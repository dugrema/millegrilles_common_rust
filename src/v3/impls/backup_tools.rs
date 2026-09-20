use crate::backup_v2::{HeaderFichierArchive, TypeArchive};
use crate::error::Error as CommonError;
use crate::v3::impls::asyncio_ciphers::{AsyncDecryptionReaderMgs4, AsyncEncryptionWriterMgs4};
use crate::v3::impls::backup_filehandling::{overwrite_backup_file_header, process_backup_file, verify_backup_file};
use crate::v3::impls::backup_producer::write_new_header;
use crate::v3::impls::security_service::digest_file;
use crate::v3::models::{BackupTransactionRow, DecryptedKey};
use async_compression::tokio::bufread::DeflateDecoder;
use async_compression::tokio::write::DeflateEncoder;
use chrono::Utc;
use chrono::format::StrftimeItems;
use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageX25519Impl, CleSecreteSerialisee};
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher, DecipherMgs4};
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::{EnveloppePrivee, parse_encrypted_private_key};
use openssl::pkey::{PKey, Private};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use bson::DateTime;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tracing::{debug, warn};
use crate::db_structs::TransactionOwned;

pub async fn load_master_key(key_path: &Path) -> Result<PKey<Private>, CommonError> {
    eprintln!("Master key path provided: {:?}", key_path);

    // rpassword::prompt_password will hide the input as the user types
    // let mut password_file = tokio::fs::File::open(password_path).await?;
    // let mut password = String::new();
    // password_file.read_to_string(&mut password).await?;
    let password = match rpassword::prompt_password("Enter master key password: ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to read password: {}", e);
            std::process::exit(1);
        }
    };
    let trimmed_password = password.trim();
    let private_key = match parse_encrypted_private_key(Path::new(&key_path), trimmed_password) {
        Ok(p) => p,
        Err(e) => {
            return Err(CommonError::String(format!("Error loading private key: {}", e)));
        }
    };

    Ok(private_key)
}

pub async fn tool_verify_backup_file(backup_file: &Path, idmg: &str, master_key_path: &Path) -> Result<(), CommonError> {
    let master_key = load_master_key(master_key_path).await.unwrap();
    let archive_info = process_backup_file(backup_file, idmg).await?;
    let (
        _key_information,
        decrypted_key
    ) = decrypt_key(&archive_info.header, &master_key)?;
    verify_backup_file(backup_file, idmg, Some(&decrypted_key)).await
}

pub async fn sort_backup_file(
    backup_file: &Path,
    idmg: &str,
    signing_key_path: &PathBuf,
    ca_path: &PathBuf,
    master_key_path: &Path,
    output_dir: &Path
) -> Result<(), CommonError> {
    let signing_key = EnveloppePrivee::from_files_combined(signing_key_path, ca_path)?;
    let master_key = load_master_key(master_key_path).await?;
    process_sort_backup_file(backup_file, idmg, &signing_key, &master_key, output_dir).await
}

/// One-off tool to take a backup file (e.g. Concatene or Final), decrypt and sort transactions and rewrite it.
async fn process_sort_backup_file(
    backup_file: &Path,
    idmg: &str,
    signing_key: &EnveloppePrivee,
    master_key: &PKey<Private>,
    output_dir: &Path
) -> Result<(), CommonError> {
    let workfile_path = output_dir.join("backup.mgbak.work");
    let outputfile_path = output_dir.join("output.jsonl");
    let mut output_writer = tokio::io::BufWriter::new(File::create(outputfile_path.clone()).await?);

    let archive_info = process_backup_file(backup_file, idmg).await?;
    let archive_type = match archive_info.header.type_archive.as_str() {
        "F" => TypeArchive::Final,
        "C" => TypeArchive::Concatene,
        "I" => TypeArchive::Incremental,
        _ => return Err(CommonError::Str("Unsupported archive type"))
    };

    // Parse all transactions and validate each decrypted entry
    let (key_information, decrypted_key) = decrypt_key(&archive_info.header, master_key)?;
    // let mut key_value: CleDechiffrageX25519Impl = key.try_into()?;
    // key_value.nonce = Some(archive_info.header.nonce.clone());
    // key_value.format = archive_info.header.format.as_str().try_into()?;
    let decipher = DecipherMgs4::new(&key_information)?;
    let mut file = File::open(archive_info.path_fichier.as_path()).await?;
    eprintln!("Processing backup file {:?}, starting at byte position {}", archive_info.path_fichier, archive_info.position_data);
    file.seek(SeekFrom::Start(archive_info.position_data as u64)).await?;

    // Set-up the streaming pipeline for decrypting/decompressing the transactions
    let decryptor = AsyncDecryptionReaderMgs4::new(file, decipher);
    let buf_reader = BufReader::new(decryptor);
    let decompressor = DeflateDecoder::new(buf_reader);
    let mut lines = BufReader::new(decompressor).lines();

    // Create streaming "compression -> encryption -> file writing" pipeline for backup file
    let mut work_file = tokio::io::BufWriter::new(File::create(&workfile_path).await?);

    // Write header first (spacing, it will be overwritten at the end
    let (_backup_header, _header_size) = write_new_header(
        &mut work_file,
        &archive_type,
        idmg,
        archive_info.header.domaine.as_str(),
        &archive_info.header.cle_id,
        &archive_info.header.cle_dechiffrage,
        signing_key.enveloppe_pub.as_ref(),
    ).await?;
    eprintln!("Header written, creating pipeline");

    let cipher = CipherMgs4::with_secret(CleSecreteCipher::CleSecrete(key_information.cle_secrete.unwrap()))?;
    let mut encryptor = AsyncEncryptionWriterMgs4::new(work_file, cipher);
    eprintln!("Creating compressor");
    let mut compressor = DeflateEncoder::new(&mut encryptor);

    // let mut transaction_list = Vec::with_capacity(2_000_000);
    let mut first_transaction = chrono::DateTime::<Utc>::MIN_UTC;
    let mut last_transaction = chrono::DateTime::<Utc>::MIN_UTC;
    let mut out_of_order = false;
    let mut count_transactions: usize = 0;
    while let Some(transaction_data) = lines.next_line().await? {
        // Output unencrypted data
        output_writer.write_all(transaction_data.as_bytes()).await?;
        output_writer.write_all(b"\n").await?;

        let mut t: TransactionOwned = match serde_json::from_str(transaction_data.as_str()) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error processing transaction: {}", transaction_data);
                Err(e)?
            }
        };

        if ! out_of_order {
            let new_transaction_time = t.processed_date();
            if first_transaction == chrono::DateTime::<Utc>::MIN_UTC {
                first_transaction = new_transaction_time.to_owned();
            } else if &first_transaction > new_transaction_time {
                warn!("Transactions are out of order - current transaction has time prior to first");
                out_of_order = true;
            }
            if &last_transaction > new_transaction_time {
                warn!("Transactions are out of order - current transaction has time prior to previous transaction");
            }
            last_transaction = new_transaction_time.to_owned();
        }
        count_transactions += 1;
        if count_transactions % 1000 == 0 {
            eprintln!("Transactions processed: {} / {}", count_transactions, archive_info.header.nombre_transactions);
        }

        t.verifier_signature()?;    // Cryptographic check of the transaction

        if let Some(processed) = t.processed.clone() {
            // This is a wrong format, convert to proper format

            let owned: MessageMilleGrillesOwned = t.into();
            let backup_ser = BackupTransactionRow { message: &owned, processed: &processed };
            compressor.write_all(&serde_json::to_vec(&backup_ser)?).await?;
        } else {
            // Just write back the exact string we read from the backup archive
            compressor.write_all(transaction_data.as_bytes()).await?;
        }

        compressor.write_all(b"\n").await?;
        compressor.flush().await?;  // Workaround, issue with stream
        // transaction_list.push(t);
    }

    // Close-out the output writer
    output_writer.shutdown().await?;
    drop(output_writer);

    // Sort list
    eprintln!("Sorting transactions in memory");
    // transaction_list.sort_by_key(|m| *m.processed_date());

    // Get updated first transaction times
    // let first_transaction = transaction_list.first().unwrap().processed_date().to_owned();
    // let last_transaction = transaction_list.last().unwrap().processed_date().to_owned();

    eprintln!("Wrting back transactions into workfile");
    // for t in transaction_list.into_iter() {
    //     compressor.write_all(&serde_json::to_vec(&t)?).await?;
    //     compressor.write_all(b"\n").await?;
    //     compressor.flush().await?;  // Workaround, issue with stream
    // }

    eprintln!("Shut-down writing pipeline");
    compressor.shutdown().await?;
    encryptor.shutdown().await?;

    let encryption_result = match encryptor.result {
        Some(result) => result,
        None => {
            return Err(CommonError::Str("Encryption results were not available for backup, aborting"));
        }
    };

    eprintln!("Updating backup header information");
    // Update the backup header with metadata including decryption information
    let mut backup_header = archive_info.header.clone();
    backup_header.timestamp = Some(Utc::now());
    backup_header.debut_backup = first_transaction.clone();
    backup_header.fin_backup = last_transaction;
    backup_header.nombre_transactions = count_transactions as u64;
    match encryption_result.cles.nonce.as_ref() {
        Some(inner) => {
            backup_header.nonce = inner.clone();
        },
        None => return Err(CommonError::Str("Nonce missing from MGS4 encryption result"))
    }

    // Apply cryptographic signature
    backup_header.content_digest = Some(encryption_result.hachage_bytes);
    eprintln!("Signing backup header");
    backup_header.sign(signing_key)?;

    eprintln!("Overwriting backup header in workfile");
    overwrite_backup_file_header(workfile_path.as_path(), &backup_header).await?;

    eprintln!("Renaming workfile with calculated digest");
    let (path_backup_file, _digest_suffix, _filesize) = rename_backup_file(
        &archive_type,
        first_transaction,
        archive_info.header.domaine.as_str(),
        output_dir,
        workfile_path.as_path(),
    ).await?;

    eprintln!("Backup file renamed to {:?}, verifying", path_backup_file);
    verify_backup_file(path_backup_file.as_path(), idmg, Some(&decrypted_key)).await?;
    eprintln!("Verified backup file, OK");

    Ok(())
}

fn decrypt_key(archive_header: &HeaderFichierArchive, master_key: &PKey<Private>) -> Result<(CleDechiffrageX25519Impl, DecryptedKey), CommonError> {
    let signature = archive_header.cle_dechiffrage.clone();
    let decrypted_key = signature.dechiffrer_ca(master_key)?;

    // // Rebuild DecryptedKey for the cache
    let cached_key = DecryptedKey {
        signature: Some(signature),
        key: CleSecreteSerialisee::from_cle_secrete(decrypted_key.clone(), Some("DUMMY".to_string()), None, None::<&str>, None::<&str>)?,
        secret: decrypted_key.clone(),
    };

    // Build DecryptedKey result
    let full_key_information = CleDechiffrageX25519Impl {
        cle_chiffree: "".to_string(),
        cle_secrete: Some(decrypted_key),
        format: archive_header.format.as_str().try_into()?,
        nonce: Some(archive_header.nonce.as_str().into()),
        verification: None,
    };

    Ok((full_key_information, cached_key))
}

pub async fn rename_backup_file(
    archive_type: &TypeArchive,
    first_transaction: chrono::DateTime<Utc>,
    domain: &str,
    backup_path: &Path,
    workfile_path: &Path
) -> Result<(PathBuf, String, u64), CommonError> {
    // Rename work file
    let date_str = first_transaction.format_with_items(StrftimeItems::new("%Y%m%d%H%M%S%3fZ"));

    // Calculer le digest du fichier (apres modification du header).
    let digest_str = digest_file(workfile_path, multihash::Code::Blake2b512, multibase::Base::Base58Btc).await?;

    let archive_type_marker = match archive_type {
        TypeArchive::Incremental => "I",
        TypeArchive::Concatene => "C",
        TypeArchive::Final => "F",
    };

    // Keep last 12 chars of digest
    let digest_suffix = digest_str[digest_str.len()-12..digest_str.len()].to_string();

    // File name example : AiLanguage_2024-09-24T21:43:07.162Z_I_KozFJz4vLFe7.mgbak
    let backup_file_name = format!(
        "{}_{}_{}_{}.mgbak",
        domain,
        date_str,
        archive_type_marker,
        &digest_suffix
    );

    debug!("rename_work_file Date {}, digest {}, filename: {}", date_str, digest_str, backup_file_name);
    let mut backup_file_path = backup_path.to_owned();
    backup_file_path.push(backup_file_name);

    let metadata = workfile_path.metadata()?;
    let filesize = metadata.len();

    // Last operation - rename. If this success
    fs::rename(workfile_path, &backup_file_path).await?;

    Ok((backup_file_path, digest_suffix, filesize))
}

// #[cfg(test)]
// mod tool_module {
//     use std::path::PathBuf;
//     use super::*;
//
//     const IDMG: &str = "zaSDqKqrvhrGJS6oC2Zo4TtFXAc5FsbsZkcf9ADPx3u1jFepxikpxxjW";
//
//     #[tokio::test]
//     async fn run_sort_file() {
//         eprintln!("Run backup file sorting");
//         let master_key = load_master_key(
//             Path::new(&format!("/home/mathieu/Documents/cles/{}.pem", IDMG)),
//             Path::new("/home/mathieu/Documents/cles/pass.txt"),
//         ).await.unwrap();
//
//         let backup_path = PathBuf::from(
//             "/home/mathieu/tas/dev/millegrilles/dev1/var/backup/domains/MaitreDesCles/MaitreDesCles_20220914184226381Z_C_kaQsFm1TFmde.mgbak"
//         );
//         sort_backup_file(backup_path.as_path(), IDMG, &master_key).await.unwrap();
//     }
//
// }

