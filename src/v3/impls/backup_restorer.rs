use crate::error::Error as CommonError;
use crate::mongo_dao::MongoDao;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::asyncio_ciphers::AsyncDecryptionReaderMgs4;
use crate::v3::impls::backup_encryption::load_backup_keys;
use crate::v3::impls::backup_filehandling::load_backup_file_list;
use crate::v3::impls::backup_producer::check_redo_log_size;
use crate::v3::models::{BackupResult, RestorePreflightResult};
use crate::v3::{ConfigService, TransactionService};
use async_compression::tokio::bufread::DeflateDecoder;
use millegrilles_cryptographie::chiffrage_cles::CleDechiffrageX25519Impl;
use millegrilles_cryptographie::chiffrage_mgs4::DecipherMgs4;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::collections::HashMap;
use std::io::SeekFrom;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWrite, BufReader};
use tracing::debug;

pub async fn restore_preflight_check(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    domain_name: &str,
    redolog_collection_name: &str,
    version: Option<&String>,
) -> Result<RestorePreflightResult, CommonError> {
    // Check how many transactions are in the redo-log (if incremental, we need at least 1)
    let path_backup_root = mongo.get_path_backup();
    let domain_backup_path = path_backup_root.join(domain_name);

    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    let file_list = match version {
        Some(version) => {
            todo!("Handle version")
        },
        None => {
            // Fetch files in *current* backup directory (*.mgbak in domain_backup_path + final/)
            load_backup_file_list(domain_backup_path.as_path(), idmg.as_str()).await?
        }
    };

    let waiting_transaction_count = check_redo_log_size(mongo, redolog_collection_name).await?;

    // Collect all keys
    let keys = load_backup_keys(outbound, &file_list).await?;
    let mut keys_map = HashMap::new();
    for key in keys.into_iter() {
        let key_id = match key.key.cle_id.as_ref() {
            Some(key_id) => key_id,
            None => Err(CommonError::Str("No key_id/domain signature in key set"))?
        };
        keys_map.insert(key_id.to_string(), key);
    }

    Ok(RestorePreflightResult {
        domain_name: domain_name.to_string(),
        idmg,
        domain_backup_path,
        files: file_list,
        redolog_count: waiting_transaction_count as usize,
        keys: keys_map,
    })
}

const CERTIFICATE_CACHE_LIMIT: usize = 250;

async fn process_transactions_from_backup<W>(
    domain_info: &RestorePreflightResult,
    outbound: &MessageOutboundFacade,
    transaction: &dyn TransactionService,
) -> Result<BackupResult, CommonError> where W: AsyncWrite + Unpin {

    let existing_files = &domain_info.files;
    debug!("Extract transactions from {} existing files", existing_files.len());

    let keys = &domain_info.keys;

    let mut first_transaction: u64 = 0;
    let mut last_transaction: u64 = 0;
    let mut transaction_count: u64 = 0;

    let mut skipping = false;  // When in resume mode, this is true and gets toggled to false when ready to resume

    // Use a cache of certificates to accelerate processing
    let mut certificate_cache:  HashMap<String, Arc<EnveloppeCertificat>> = HashMap::new();

    let mut aggregator = None;

    for backup_file in existing_files {
        debug!("Processing backup file {:?}", backup_file.path_fichier);

        let key_id = backup_file.header.cle_id.as_str();
        let decipher_key = match keys.get(&key_id.to_string()) {
            Some(key) => {
                // Inject the nonce/format from the backup file into the key
                let mut value: CleDechiffrageX25519Impl = key.try_into()?;
                value.nonce = Some(backup_file.header.nonce.clone());
                value.format = backup_file.header.format.as_str().try_into()?;
                value
            },
            None => return Err(CommonError::String(format!("Key id {} not found", key_id)))
        };

        // Position the file to read from the start of encrypted data
        let mut file = File::open(backup_file.path_fichier.as_path()).await?;
        debug!("Processing backup file {:?}, starting at byte position {}", backup_file.path_fichier, backup_file.position_data);
        file.seek(SeekFrom::Start(backup_file.position_data as u64)).await?;

        // Set-up the streaming pipeline for decrypting/decompressing the transactions
        let decipher = DecipherMgs4::new(&decipher_key)
            .expect("Failed to create decipher");
        let decryptor = AsyncDecryptionReaderMgs4::new(file, decipher);
        let buf_reader = BufReader::new(decryptor);
        let decompressor = DeflateDecoder::new(buf_reader);
        let mut lines = BufReader::new(decompressor).lines();

        while let Some(transaction_data) = lines.next_line().await? {

            // Transactions must be in order, this is enforced here. Also bean counting.
            let mut t: MessageMilleGrillesOwned = serde_json::from_str(transaction_data.as_str())?;
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

            // Check if we are skipping (resuming)
            if skipping {
                // if t.id == LAST_PROCESSED_ID { skipping = false }
                continue  // Transaction already processed
            }

            // Validate structure of transaction
            t.verifier_signature()?;  // Ensure transaction is valid through self-contained check

            // Fetch certificate
            let pubkey = &t.pubkey;
            let certificate = match certificate_cache.get(pubkey) {
                Some(certificate) => certificate.clone(),
                None => {
                    debug!("Loading certificate {}", pubkey);
                    let certificate = outbound.get_certificate(pubkey, Some(3_000)).await?;
                    if certificate_cache.len() > CERTIFICATE_CACHE_LIMIT {
                        certificate_cache.clear();
                    }
                    certificate_cache.insert(pubkey.clone(), certificate.clone());
                    certificate
                }
            };

            // Add transaction to write operations aggregator.
            aggregator = Some(transaction.route_transaction(
                t,
                certificate,
                aggregator.take()
            ).await?);

            if transaction_count % 20 == 0 {
                // Run write operations from aggregator
                if let Some(aggregator) = aggregator.take() {
                    transaction.run_aggregator(aggregator).await?;
                }
            }
        }
    }

    // Run last batch of write operations from aggregator when applicable
    if let Some(aggregator) = aggregator.take() {
        transaction.run_aggregator(aggregator).await?;
    }

    debug!("Done processing transactions");

    Ok(BackupResult {
        first_transaction,
        last_transaction,
        count: transaction_count,
    })
}
