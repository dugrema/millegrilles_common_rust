use std::io::SeekFrom;
use crate::backup_v2::{organiser_fichiers_backup, FichierArchiveBackup, HeaderFichierArchive, TypeArchive};
use crate::constantes::NEW_LINE_BYTE;
use crate::error::Error as CommonError;
use crate::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::asyncio_ciphers::AsyncEncryptionWriterMgs4;
use crate::v3::impls::backup_encryption::get_domain_backup_key;
use crate::v3::models::{BackupResult, PreflightResult, TransactionProcessedRow};
use crate::v3::{ChiffrageService, ConfigService};
use async_compression::tokio::write::DeflateEncoder;
use bson::{Bson, doc, serde_helpers::datetime::FromChrono04DateTime};
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher};
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use mongodb::ClientSession;
use mongodb::options::Hint;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use millegrilles_cryptographie::maitredescles::SignatureDomaines;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::pin;
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

    let existing_files = if incremental {
        if waiting_transaction_count == 0 {
            return Err(CommonError::Str("No transactions waiting in redo collection for incremental backup, aborting"));
        }
        None
    } else {
        let domain_backup_path = mongo.get_path_backup().join(domain_name);
        let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

        // Check if we have existing incremental backups to concatenate
        let files = organiser_fichiers_backup(
            domain_backup_path.as_path(),
            idmg.as_str(),
            false
        ).await?;

        if waiting_transaction_count == 0 && files.len() <= 1 {
            // We only have 1 backup file (Concatene) and there are no additional transactions to back-up
            return Err(CommonError::Str("All transactions are already in Final/Concatene files, aborting full backup"));
        }

        Some(files)
    };

    // Get encryption key for this domain
    let decryption_key = get_domain_backup_key(outbound, chiffrage, domain_name).await?;

    Ok(PreflightResult {
        domain_name: domain_name.to_string(),
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
    mongo: &MongoDaoImpl,
    chiffrage: &dyn ChiffrageService,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
) -> Result<FichierArchiveBackup, CommonError> {
    debug!("Starting incremental backup");

    let path = PathBuf::new();

    // Start database transaction - will commit only once the file is completely flushed.
    let mut session = mongo.get_session().await?;
    session.start_transaction().await?;

    match process_incremental_file_operations(
        mongo,
        chiffrage,
        domain_info,
        redolog_collection_name,
        path.as_path(),
        &mut session,
    ).await {
        Ok(backup) => {
            session.commit_transaction().await?;
            Ok(backup)
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        }
    }
}

async fn process_incremental_file_operations(
    mongo: &MongoDaoImpl,
    chiffrage: &dyn ChiffrageService,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
    path: &Path,
    session: &mut ClientSession,
) -> Result<FichierArchiveBackup, CommonError> {
    let mut file = File::create(path).await?;

    let idmg = "DUMMY";  // TODO: Get IDMG

    // TODO Write the backup header to the file before starting the stream
    let (key_id, signature) = match (&domain_info.key.key.cle_id, &domain_info.key.signature) {
        (Some(key_id), Some(signature)) => (key_id.as_str(),signature),
        _ => return Err(CommonError::Str("No key_id/domain signature in key set")),
    };
    let (mut backup_header, header_size) = write_new_header(
        &mut file,
        &TypeArchive::Incremental,
        idmg,
        domain_info.domain_name.as_str(),
        key_id,
        signature
    ).await?;

    // Create streaming compression -> encryption -> writing pipeline for backup file
    let mut encryptor = AsyncEncryptionWriterMgs4::new(
        file,
        chiffrage.get_cipher_mgs4(&domain_info.key)?
    );
    let mut compressor = DeflateEncoder::new(&mut encryptor);

    // Produce backup file content
    let backup_result = extract_redolog_content(
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

    // TODO Update the backup header with metadata including decryption information

    backup_header.debut_backup = backup_result.first_transaction;
    backup_header.fin_backup = backup_result.last_transaction;
    backup_header.nombre_transactions = backup_result.count;
    match encryption_result.cles.nonce.as_ref() {
        Some(inner) => {
            backup_header.nonce = inner.clone();
        },
        None => return Err(CommonError::Str("Nonce missing from MGS4 encryption result"))
    }

    end_backup_file(path, &backup_header, header_size).await?;

    // Rename working file to final file with digest in name
    
    let backup_result = FichierArchiveBackup {
        path_fichier: path.to_path_buf(),
        header: backup_header,
        position_data: 0,
        digest_suffix: "".to_string(),
        len: 0,
    };

    Ok(backup_result)
}

async fn extract_redolog_content(
    mongo: &MongoDaoImpl,
    writer: &mut DeflateEncoder<&mut AsyncEncryptionWriterMgs4<File>>,
    domain_info: &PreflightResult,
    redolog_collection_name: &str,
    session: &mut ClientSession,
) -> Result<BackupResult, CommonError> {
    let collection = mongo.get_collection_typed::<TransactionProcessedRow>(
        redolog_collection_name
    )?;

    // Make a cursor sorted by _processed time, this ensures all transactions are run in the same order.
    let mut cursor = collection
        .find(doc!{})
        .hint(Hint::Name("processed".into()))
        // .sort(bson::doc!{"_processed": 1})
        .session(&mut *session)
        .batch_size(20)
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
    while let Some(transaction) = cursor.next(&mut *session).await {
        match transaction {
            Ok(transaction) => {
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

    let value = [0x0u8; 16];
    writer.write_all(value.as_slice()).await?;

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

pub async fn produce_concatene_backup_file() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

/// Generates and writes a new header. All fields are "maximized" to make space in the file.
/// This writes all file headers (version, length of header, header itself)
async fn write_new_header(
    file: &mut File,
    archive_type: &TypeArchive,
    idmg: &str,
    domain: &str,
    key_id: &str,
    key_signature: &SignatureDomaines
) -> Result<(HeaderFichierArchive, u16), CommonError> {
    static FILE_VERSION: u16 = 1;
    let mut header = HeaderFichierArchive {
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

    file.write(&FILE_VERSION.to_le_bytes()).await?;
    file.write(&header_size.to_le_bytes()).await?;
    file.write_all(header_str.as_bytes()).await?;
    file.flush().await?;

    Ok((header, header_size))
}

async fn end_backup_file(file_path: &Path, header: &HeaderFichierArchive, header_size: u16) -> Result<(), CommonError> {
    let header_str = serde_json::to_string(&header)?;
    let header_updated_size = header_str.len() as u16;
    debug!("preparer_fichier_chiffrage Header taille mise a jour {}, valeur: {}", header_updated_size, header_str);
    if header_size < header_updated_size {
        Err("backup_v2.preparer_fichier_chiffrage Header mis a jour est plus grand que l'espace reserve")?;
    }

    let mut file = File::create(file_path).await?;

    // Fix file header with missing information, keep same version and header size info (bytes 0-3)
    // The unused header portion will be padded with 0s.
    file.seek(SeekFrom::Start(4)).await?;
    file.write_all(header_str.as_bytes()).await?;
    // Truncate by filling in 0s over the remaining original header
    for _ in header_updated_size..header_size {
        file.write(&[0u8]).await?;
    }
    file.flush().await?;

    Ok(())
}
