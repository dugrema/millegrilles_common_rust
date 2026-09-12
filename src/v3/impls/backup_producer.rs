use crate::backup_v2::{FichierArchiveBackup, HeaderFichierArchive, TypeArchive, organiser_fichiers_backup};
use crate::constantes::{COMMANDE_SAUVEGARDER_CERTIFICAT, DOMAINE_PKI, NEW_LINE_BYTE, Securite};
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::messages_generiques::CommandeSauvegarderCertificat;
use crate::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::asyncio_ciphers::{AsyncDecryptionReaderMgs4, AsyncEncryptionWriterMgs4};
use crate::v3::impls::backup_encryption::{get_domain_backup_key, load_backup_keys};
use crate::v3::impls::backup_filehandling::{load_backup_file_list, overwrite_backup_file_header, prepare_backup_workfile, rename_backup_file, rotate_backup_files};
use crate::v3::models::{BackupResult, DecryptedKey, PreflightResult, TransactionProcessedRow};
use crate::v3::{ChiffrageService, ConfigService};
use async_compression::tokio::write::DeflateEncoder;
use async_compression::tokio::bufread::DeflateDecoder;
use bson::doc;
use chrono::{DateTime, TimeZone, Utc};
use millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::ClientSession;
use mongodb::options::Hint;
use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::Path;
use millegrilles_cryptographie::chiffrage_mgs4::DecipherMgs4;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

pub async fn preflight_check(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
    redolog_collection_name: &str,
    incremental: bool,
) -> Result<PreflightResult, CommonError> {
    // Check how many transactions are in the redo-log (if incremental, we need at least 1)
    let waiting_transaction_count = check_redo_log_size(mongo, redolog_collection_name).await?;
    let domain_backup_path = mongo.get_path_backup().join(domain_name);
    
    if incremental {
        if waiting_transaction_count == 0 {
            return Err(CommonError::Str("No transactions waiting in redo collection for incremental backup, aborting"));
        }
    }
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    // Check if we have existing incremental backups to concatenate
    let existing_files = load_backup_file_list(
        domain_backup_path.as_path(),
        idmg.as_str()
    ).await?;

    if waiting_transaction_count == 0 && existing_files.len() <= 1 {
        // We only have 1 backup file (Concatene) and there are no additional transactions to back-up
        return Err(CommonError::Str("All transactions are already in Final/Concatene files, aborting full backup"));
    }

    // Get encryption key for this domain
    let decryption_key = get_domain_backup_key(outbound, chiffrage, domain_name).await?;

    Ok(PreflightResult {
        domain_name: domain_name.to_string(),
        idmg: config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?,
        domain_backup_path,
        existing_files,
        redolog_count: 0,
        key: decryption_key,
    })
}

async fn check_redo_log_size(mongo: &dyn MongoDao, redolog_collection_name: &str) -> Result<u64, CommonError> {
    let collection = mongo.get_collection(redolog_collection_name)?;
    Ok(collection.count_documents(doc!{}).await?)
}

pub async fn produce_incremental_backup_file(
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    chiffrage: &dyn ChiffrageService,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
) -> Result<FichierArchiveBackup, CommonError> {
    debug!("Starting incremental backup");

    // let domain_backup_path = mongo.get_path_backup().join(domain_info.domain_name.as_str());
    let domain_backup_path = domain_info.domain_backup_path.as_path();
    let incremental_workfile_path = prepare_backup_workfile(domain_backup_path).await?;

    // Start database transaction - will commit only once the file is completely flushed.
    let mut session = mongo.get_session().await?;
    session.start_transaction().await?;

    match process_incremental_file_operations(
        outbound,
        mongo,
        chiffrage,
        domain_info,
        redolog_collection_name,
        incremental_workfile_path.as_path(),
        &mut session,
    ).await {
        Ok(backup) => {
            match session.commit_transaction().await {
                Ok(()) => Ok(backup),
                Err(e) => {
                    error!("Failed to commit transaction, we delete the incremental backup file: {:?}", e);
                    tokio::fs::remove_file(incremental_workfile_path).await.ok();
                    Err(e)?  // Raise the error again
                }
            }
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn process_incremental_file_operations(
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    chiffrage: &dyn ChiffrageService,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
    incremental_workfile_path: &Path,
    session: &mut ClientSession,
) -> Result<FichierArchiveBackup, CommonError> {
    let mut work_file = tokio::io::BufWriter::new(File::create(&incremental_workfile_path).await?);

    // Write the backup header to the file before starting the stream
    let (key_id, signature) = match (&domain_info.key.key.cle_id, &domain_info.key.signature) {
        (Some(key_id), Some(signature)) => (key_id.as_str(),signature),
        _ => return Err(CommonError::Str("No key_id/domain signature in key set")),
    };
    let (mut backup_header, header_size) = write_new_header(
        &mut work_file,
        &TypeArchive::Incremental,
        domain_info.idmg.as_str(),
        domain_info.domain_name.as_str(),
        key_id,
        signature
    ).await?;

    // Create streaming "compression -> encryption -> file writing" pipeline for backup file
    let mut encryptor = AsyncEncryptionWriterMgs4::new(
        work_file,
        chiffrage.get_cipher_mgs4(&domain_info.key)?
    );
    let mut compressor = DeflateEncoder::new(&mut encryptor);

    // Produce backup file content. This also cleans-up the redo-log table.
    let backup_result = extract_redolog_content(
        outbound,
        mongo,
        &mut compressor,
        domain_info,
        redolog_collection_name,
        session
    ).await?;

    // Wind down pipeline
    compressor.shutdown().await?;
    encryptor.shutdown().await?;

    let encryption_result = match encryptor.result {
        Some(result) => result,
        None => {
            return Err(CommonError::Str("Encryption results were not available for backup, aborting"));
        }
    };

    // Update the backup header with metadata including decryption information
    backup_header.debut_backup = backup_result.first_transaction;
    backup_header.fin_backup = backup_result.last_transaction;
    backup_header.nombre_transactions = backup_result.count;
    match encryption_result.cles.nonce.as_ref() {
        Some(inner) => {
            backup_header.nonce = inner.clone();
        },
        None => return Err(CommonError::Str("Nonce missing from MGS4 encryption result"))
    }

    let backup_path = incremental_workfile_path.parent()
        .expect("Failed to get backup parent directory").to_owned();
    overwrite_backup_file_header(backup_path.as_path(), &backup_header).await?;

    // Extract date information from header
    let first_transaction = match Utc.timestamp_millis_opt(backup_result.first_transaction as i64).single() {
        Some(timestamp) => timestamp,
        None => return Err(CommonError::Str("Unable to get time of first transaction from seconds"))
    };

    // Rename working file to final file with digest in name
    let (path_backup_file, digest_suffix, filesize) = rename_backup_file(
        chiffrage,
        &TypeArchive::Incremental,
        first_transaction,
        domain_info.domain_name.as_str(),
        backup_path.as_path(),
        incremental_workfile_path
    ).await?;

    // Position of first byte of data: 4 bytes (version u16, taille header u16) + header
    let position_data = (4 + header_size) as usize;
    let backup_result = FichierArchiveBackup {
        path_fichier: path_backup_file,
        header: backup_header,
        position_data,
        digest_suffix,
        len: filesize,
    };

    Ok(backup_result)
}

async fn extract_redolog_content<W>(
    outbound: &MessageOutboundFacade,
    mongo: &MongoDaoImpl,
    writer: &mut W,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
    session: &mut ClientSession,
) -> Result<BackupResult, CommonError>
where
    W: AsyncWrite + Unpin,
{
    let collection = mongo.get_collection_typed::<TransactionProcessedRow>(
        redolog_collection_name
    )?;

    // Make a cursor sorted by _processed time, this ensures all transactions are run in the same order.
    // Use a hard limit of 10,000 transactions per incremental file (limits DB cleanup per transaction id).
    let mut cursor = collection
        .find(doc!{})
        .hint(Hint::Name("processed".into()))
        // .sort(bson::doc!{"_processed": 1})
        .session(&mut *session)
        .batch_size(20)
        .limit(10_000)
        .await?;

    let mut transaction_ids: Vec<String> = Vec::with_capacity(domain_info.redolog_count);
    let mut last_transaction_date: DateTime<Utc> = DateTime::from_timestamp(0, 0).expect("Failed: datetime zero");
    let mut result = BackupResult {
        first_transaction: 0,
        last_transaction: 0,
        count: 0,
    };

    let new_line_slice = [NEW_LINE_BYTE; 1];

    // Read all transactions in the mongo redolog collection
    let mut unreadable_transactions = false;
    let mut already_processed_certificate_ids = HashSet::new();
    while let Some(transaction) = cursor.next(&mut *session).await {
        match transaction {
            Ok(mut transaction) => {
                // Beancounting
                if result.first_transaction == 0 {
                    result.first_transaction = transaction.processed.timestamp() as u64;
                }
                let previous_last = result.last_transaction;
                result.last_transaction = transaction.processed.timestamp() as u64;
                if previous_last > result.last_transaction {
                    return Err(CommonError::Str("Transaction processing dates are not sorted properly"));
                }
                last_transaction_date = transaction.processed;  // Keep date instance, more precise for cleanup
                result.count += 1;
                // Done beancounting

                // Ensure volatile fields are empty
                transaction.message.millegrille = None;
                transaction.message.attachements = None;

                // Extract certificate from transaction
                if let Some(certificate) = transaction.message.certificat.take() {
                    save_certificate(outbound, &certificate, &mut already_processed_certificate_ids).await?;
                }

                // Keep transaction id for cleanup at the end (delete)
                transaction_ids.push(transaction.message.id.clone());
                let transaction_str = serde_json::to_string(&transaction)?;
                writer.write_all(transaction_str.as_bytes().to_vec().as_slice()).await?;
                // Add line feed (\n) to allow file to be read as "jsonl"
                writer.write_all(&new_line_slice).await?;
            }
            Err(e) => {
                error!("Error parsing redolog content: {}, will ignore and delete transaction", e);
                unreadable_transactions = true;
            }
        }
    }

    // Delete processed transactions
    if ! transaction_ids.is_empty() {
        collection
            .delete_many(doc! {"id": {"$in": &transaction_ids}})
            .session(&mut *session)
            .await?;
        transaction_ids.clear();
    }

    // Cleanup all transactions not read properly (deserialize Err) and copy them to another collection
    if unreadable_transactions {
        // We already deleted all successfully backed-up transactions by exact id.
        // This is to remove "bad" rows that cannot be read at all with the proper structure.
        let bson_max_date = bson::DateTime::from_chrono(last_transaction_date);
        let collection = mongo.get_collection(redolog_collection_name)?;
        let collection_bad = mongo.get_collection(format!("{}_BAD", redolog_collection_name).as_str())?;
        let mut cursor = collection
            .find(doc! {"processed": {"$lt": bson_max_date}})
            .session(&mut *session)
            .await?;

        while let Some(result) = cursor.next(&mut *session).await {
            match result {
                Ok(mut doc_value) => {
                    let doc_id = doc_value.remove("_id").expect("Cannot get doc _id");
                    warn!("Transaction redo-log entry id:{} cannot be processed: {:?}", doc_id, doc_value);
                    collection_bad.insert_one(doc_value).await?;
                    transaction_ids.push(doc_id.to_string());
                },
                Err(e) => {
                    error!("Unable to read collection content for cleanup: {:?}", e);
                }
            }
        }

        // Cleanup of bad transactions
        if ! transaction_ids.is_empty() {
            collection
                .delete_many(doc! {"id": {"$in": transaction_ids}})
                .session(&mut *session)
                .await?;
        }
    }

    Ok(result)
}

/// This takes all backup files (previous concatenated and incrementals) and saves them in a new file.
async fn process_concatenated_file_operations(
    chiffrage: &dyn ChiffrageService,
    domain_info: &PreflightResult,
    keys: Vec<DecryptedKey>,
    workfile_path: &Path,
) -> Result<FichierArchiveBackup, CommonError> {
    let mut work_file = tokio::io::BufWriter::new(File::create(&workfile_path).await?);

    let (key_id, signature) = match (&domain_info.key.key.cle_id, &domain_info.key.signature) {
        (Some(key_id), Some(signature)) => (key_id.as_str(),signature),
        _ => return Err(CommonError::Str("No key_id/domain signature in key set")),
    };
    let (mut backup_header, header_size) = write_new_header(
        &mut work_file,
        &TypeArchive::Concatene,
        domain_info.idmg.as_str(),
        domain_info.domain_name.as_str(),
        key_id,
        signature
    ).await?;

    // Create streaming "compression -> encryption -> file writing" pipeline for backup file
    let mut encryptor = AsyncEncryptionWriterMgs4::new(
        work_file,
        chiffrage.get_cipher_mgs4(&domain_info.key)?
    );
    let mut compressor = DeflateEncoder::new(&mut encryptor);

    // BACKUP
    let mut keys_map = HashMap::new();
    for key in keys.into_iter() {
        let key_id = match key.key.cle_id.as_ref() {
            Some(key_id) => key_id,
            None => return Err(CommonError::Str("No key_id/domain signature in key set"))
        };
        keys_map.insert(key_id.to_string(), key);
    }
    let backup_result = extract_transactions_from_backup(domain_info, &keys_map, &mut compressor).await?;

    // Wind down pipeline
    compressor.shutdown().await?;
    encryptor.shutdown().await?;

    let encryption_result = match encryptor.result {
        Some(result) => result,
        None => {
            return Err(CommonError::Str("Encryption results were not available for backup, aborting"));
        }
    };

    // Update the backup header with metadata including decryption information
    backup_header.debut_backup = backup_result.first_transaction;
    backup_header.fin_backup = backup_result.last_transaction;
    backup_header.nombre_transactions = backup_result.count;
    match encryption_result.cles.nonce.as_ref() {
        Some(inner) => {
            backup_header.nonce = inner.clone();
        },
        None => return Err(CommonError::Str("Nonce missing from MGS4 encryption result"))
    }

    let backup_path = workfile_path.parent()
        .expect("Failed to get backup parent directory").to_owned();
    overwrite_backup_file_header(backup_path.as_path(), &backup_header).await?;

    // Extract date information from header
    let first_transaction = match Utc.timestamp_millis_opt(backup_result.first_transaction as i64).single() {
        Some(timestamp) => timestamp,
        None => return Err(CommonError::Str("Unable to get time of first transaction from seconds"))
    };

    // Rename working file to final file with digest in name
    let (path_backup_file, digest_suffix, filesize) = rename_backup_file(
        chiffrage,
        &TypeArchive::Incremental,
        first_transaction,
        domain_info.domain_name.as_str(),
        backup_path.as_path(),
        workfile_path
    ).await?;

    // Position of first byte of data: 4 bytes (version u16, taille header u16) + header
    let position_data = (4 + header_size) as usize;
    let backup_result = FichierArchiveBackup {
        path_fichier: path_backup_file,
        header: backup_header,
        position_data,
        digest_suffix,
        len: filesize,
    };

    Ok(backup_result)
}

async fn extract_transactions_from_backup<W>(
    domain_info: &PreflightResult,
    keys: &HashMap<String, DecryptedKey>,
    writer: &mut W
) -> Result<BackupResult, CommonError> where W: AsyncWrite + Unpin {

    let existing_files = &domain_info.existing_files;

    let mut first_transaction: u64 = 0;
    let mut last_transaction: u64 = 0;
    let mut transaction_count: u64 = 0;

    for backup_file in existing_files {
        if backup_file.header.type_archive == TypeArchive::Final.to_string() {
            continue  // Skip final archives, they **MUST NOT** be re-processed
        }

        let key_id = backup_file.header.cle_id.as_str();
        let decipher_key = match keys.get(&key_id.to_string()) {
            Some(key) => key,
            None => return Err(CommonError::String(format!("Key id {} not found", key_id)))
        };

        // Position the file to read from the start of encrypted data
        let mut file = File::open(backup_file.path_fichier.as_path()).await?;
        file.seek(SeekFrom::Start(backup_file.position_data as u64)).await?;

        // Set-up the streaming pipeline for decrypting/decompressing the transactions
        let decipher = DecipherMgs4::new(&decipher_key.try_into()?)
            .expect("Failed to create decipher");
        let decryptor = AsyncDecryptionReaderMgs4::new(file, decipher);
        let buf_reader = BufReader::new(decryptor);
        let decompressor = DeflateDecoder::new(buf_reader);
        let mut lines = BufReader::new(decompressor).lines();

        while let Some(transaction) = lines.next_line().await? {
            // Validate structure of transaction
            let mut t: MessageMilleGrillesOwned = serde_json::from_str(transaction.as_str())?;
            t.verifier_signature()?;  // Ensure transaction is valid through self-contained check

            // Transactions must be in order, this is enforced here. Also bean counting.
            let new_transaction_time = t.estampille.timestamp() as u64;
            if first_transaction == 0 {
                first_transaction = new_transaction_time;
            } else if first_transaction > new_transaction_time {
                return Err(CommonError::Str("Transactions are out of order - current transaction has time prior to first"))
            }
            if last_transaction > new_transaction_time {
                return Err(CommonError::Str("Transactions are out of order - current transaction has time prior to previous transaction"))
            }
            last_transaction = new_transaction_time;
            transaction_count += 1;

            // Write transaction back to new file
            writer.write_all(transaction.as_bytes()).await?;
            // Add newline for jsonl format
            writer.write_all(b"\n").await?;
        }
    }

    writer.flush().await?;

    Ok(BackupResult {
        first_transaction,
        last_transaction,
        count: transaction_count,
    })
}

async fn save_certificate(
    outbound: &MessageOutboundFacade,
    certificate: &Vec<String>,
    already_processed_ids: &mut HashSet<String>
) -> Result<(), CommonError> {
    // Ensure the certificate is saved by the CorePki domain.
    let certificate_str = certificate.join("\n");
    let certificate_instance = EnveloppeCertificat::try_from(certificate_str.as_str())?;
    let certificate_fingerprint = certificate_instance.fingerprint_pk()?;
    if ! already_processed_ids.contains(&certificate_fingerprint) {

        // Send certificate for saving
        let routing = RoutageMessageAction::builder(
            DOMAINE_PKI, COMMANDE_SAUVEGARDER_CERTIFICAT, vec![Securite::L3Protege]).build();
        let command = CommandeSauvegarderCertificat {
            chaine_pem: certificate.to_owned(),
            ca: None,
        };
        match outbound.send_command(routing, command).await {
            Ok(response) => match response {
                Some(response) => {
                    if let Ok((true, e)) = response.is_err() {
                        return Err(CommonError::String(format!("Error when saving certificate: {:?}", e)))
                    }
                },
                None => return Err(CommonError::Str("No response received when saving certificate"))
            },
            Err(e) => return Err(CommonError::String(format!("Error saving certificate {}: {:?}", certificate_fingerprint, e)))
        };

        // Save fingerprint to avoid re-sending this certificate
        already_processed_ids.insert(certificate_fingerprint);
    }
    Ok(())
}

pub async fn produce_concatenated_backup_file(
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
    domain_info: &PreflightResult
) -> Result<FichierArchiveBackup, CommonError> {
    // Preflight check - ensure at least 1 incremental file is present
    if ! domain_info.contains_incremental() {
        return Err(CommonError::Str("No incremental files found to concatenate"))
    }

    let domain_backup_path = domain_info.domain_backup_path.as_path();

    // Fetch all keys required to decrypt existing backups
    let keys = load_backup_keys(outbound, &domain_info.existing_files).await?;

    // Set-up the new concatenated workfile
    let workfile = prepare_backup_workfile(domain_backup_path).await?;
    let backup_result = process_concatenated_file_operations(
        chiffrage,
        domain_info,
        keys,
        workfile.as_path()
    ).await?;

    // Extract date information from header
    let first_transaction = match Utc.timestamp_millis_opt(backup_result.header.debut_backup as i64).single() {
        Some(timestamp) => timestamp,
        None => return Err(CommonError::Str("Unable to get time of first transaction from seconds"))
    };

    // Concatenated file done, rotate all backup folders and move *.mgbak files to backup_NOW (NOW is the date)
    rotate_backup_files(domain_backup_path).await?;

    // Rename concatenated workfile to proper value
    let (path_backup_file, digest_suffix, filesize) = rename_backup_file(
        chiffrage,
        &TypeArchive::Concatene,
        first_transaction,
        domain_info.domain_name.as_str(),
        domain_backup_path,
        workfile.as_path()
    ).await?;

    let backup_result = FichierArchiveBackup {
        path_fichier: path_backup_file,
        header: backup_result.header,
        position_data: backup_result.position_data,
        digest_suffix,
        len: filesize,
    };

    Ok(backup_result)
}

/// Generates and writes a new header. All fields are "maximized" to make space in the file.
/// This writes all file headers (version, length of header, header itself)
async fn write_new_header<W>(
    writer: &mut W,
    archive_type: &TypeArchive,
    idmg: &str,
    domain: &str,
    key_id: &str,
    key_signature: &SignatureDomaines
) -> Result<(HeaderFichierArchive, u16), CommonError> where W: AsyncWrite + Unpin {
    static FILE_VERSION: u16 = 1;
    let header = HeaderFichierArchive {
        idmg: idmg.to_string(),
        domaine: domain.to_string(),
        type_archive: archive_type.into(),
        debut_backup: u64::MAX,
        fin_backup: u64::MAX,
        nombre_transactions: u64::MAX,
        cle_id: key_id.to_string(),
        cle_dechiffrage: key_signature.to_owned(),
        nonce: "DUMMY_NONCE_HEADER_40_CHARS_____________".to_string(),
        format: "mgs4".to_string(),
        compression: Some("deflate".to_string()),
    };
    let header_str = serde_json::to_string(&header)?;
    let header_size = header_str.len() as u16;
    debug!("preparer_fichier_chiffrage Header taille initiale {}", header_size);

    writer.write(&FILE_VERSION.to_le_bytes()).await?;
    writer.write(&header_size.to_le_bytes()).await?;
    writer.write_all(header_str.as_bytes()).await?;
    writer.flush().await?;

    Ok((header, header_size))
}
