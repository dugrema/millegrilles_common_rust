use crate::error::Error as CommonError;
use crate::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::asyncio_ciphers::AsyncDecryptionReaderMgs4;
use crate::v3::impls::backup_encryption::load_backup_keys;
use crate::v3::impls::backup_filehandling::load_backup_file_list;
use crate::v3::impls::backup_producer::check_redo_log_size;
use crate::v3::models::{RestorePreflightResult, TransactionOperationAggregator, TransactionProcessedRow};
use crate::v3::{ConfigService, TransactionService};
use async_compression::tokio::bufread::DeflateDecoder;
use bson::doc;
use futures_util::StreamExt;
use millegrilles_cryptographie::chiffrage_cles::CleDechiffrageX25519Impl;
use millegrilles_cryptographie::chiffrage_mgs4::DecipherMgs4;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::options::Hint;
use std::collections::HashMap;
use std::io::SeekFrom;
use std::sync::{Arc, Mutex};
use openssl::pkey::{PKey, Private};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tracing::{debug, error};

pub async fn restore_preflight_check<'a>(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    domain_name: &str,
    redolog_collection_name: &str,
    version: Option<&String>,
    resume: bool,
    master_key: Option<&'a PKey<Private>>,
) -> Result<RestorePreflightResult<'a>, CommonError> {
    // Check how many transactions are in the redo-log (if incremental, we need at least 1)
    let path_backup_root = mongo.get_path_backup();
    let domain_backup_path = path_backup_root.join(domain_name);

    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    let file_list = match version {
        Some(_version) => {
            todo!("Handle version")
        },
        None => {
            // Fetch files in *current* backup directory (*.mgbak in domain_backup_path + final/)
            load_backup_file_list(domain_backup_path.as_path(), idmg.as_str()).await?
        }
    };

    let waiting_transaction_count = check_redo_log_size(mongo, redolog_collection_name).await?;

    // Collect all keys
    let keys_map = if master_key.is_none() {
        let keys = load_backup_keys(outbound, &file_list).await?;
        let mut keys_map = HashMap::new();
        for key in keys.into_iter() {
            let key_id = match key.key.cle_id.as_ref() {
                Some(key_id) => key_id,
                None => Err(CommonError::Str("No key_id/domain signature in key set"))?
            };
            keys_map.insert(key_id.to_string(), key);
        }
        keys_map
    } else {
        HashMap::new()  // Return empty map, decryption will occur on the spot ands keys will get cached
    };

    if resume {
        todo!("Find last transaction by date in tracking table");
    }

    Ok(RestorePreflightResult {
        domain_name: domain_name.to_string(),
        idmg,
        domain_backup_path,
        files: file_list,
        redolog_count: waiting_transaction_count as usize,
        keys: Mutex::new(keys_map),
        last_processed_id: None,
        master_key,
    })
}

const CERTIFICATE_CACHE_LIMIT: usize = 250;

pub struct RestorationState {
    pub first_transaction: u64,
    pub last_transaction: u64,
    pub transaction_count: u64,
    skipping: bool,
    aggregator: Option<TransactionOperationAggregator>,
}

pub async fn process_transactions_from_backup<'a>(
    mongo: &MongoDaoImpl,
    domain_info: &RestorePreflightResult<'a>,
    outbound: &MessageOutboundFacade,
    transaction: &dyn TransactionService,
    redolog_collection_name: &str,
) -> Result<RestorationState, CommonError> {
    // Process all mgbak files
    let mut restoration_state = process_backup_files(domain_info, outbound, transaction).await?;

    // Process the redo-log collection
    process_redolog_collection(
        mongo,
        outbound,
        transaction,
        redolog_collection_name,
        &mut restoration_state
    ).await?;

    // Run last batch of write operations from aggregator when applicable
    if let Some(aggregator) = restoration_state.aggregator.take() {
        transaction.run_aggregator(aggregator).await?;
    }

    debug!("Done processing transactions");

    Ok(restoration_state)
}

async fn process_backup_files<'a>(
    domain_info: &RestorePreflightResult<'a>,
    outbound: &MessageOutboundFacade,
    transaction: &dyn TransactionService
) -> Result<RestorationState, CommonError> {
    let mut restoration_state = RestorationState {
        first_transaction: 0,
        last_transaction: 0,
        transaction_count: 0,
        skipping: domain_info.last_processed_id.is_some(),
        aggregator: None,
    };

    let mut certificate_cache: HashMap<String, Arc<EnveloppeCertificat>> = HashMap::new();
    debug!("Extract transactions from {} existing files", &domain_info.files.len());
    for backup_file in &domain_info.files {
        debug!("Processing backup file {:?}", backup_file.path_fichier);

        let decipher_key = domain_info.decrypt_key(&backup_file.header)?;
        // let key_id = backup_file.header.cle_id.as_str();
        // let decipher_key = match domain_info.keys.get(&key_id.to_string()) {
        //     Some(key) => {
        //         // Inject the nonce/format from the backup file into the key
        //         let mut value: CleDechiffrageX25519Impl = key.try_into()?;
        //         value.nonce = Some(backup_file.header.nonce.clone());
        //         value.format = backup_file.header.format.as_str().try_into()?;
        //         value
        //     },
        //     None => return Err(CommonError::String(format!("Key id {} not found", key_id)))
        // };

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
            if restoration_state.first_transaction == 0 {
                restoration_state.first_transaction = new_transaction_time;
            } else if restoration_state.first_transaction > new_transaction_time {
                return Err(CommonError::Str("Transactions are out of order - current transaction has time prior to first"))
            }
            if restoration_state.last_transaction > new_transaction_time {
                return Err(CommonError::Str("Transactions are out of order - current transaction has time prior to previous transaction"))
            }
            restoration_state.last_transaction = new_transaction_time;
            restoration_state.transaction_count += 1;

            // Check if we are skipping (resuming)
            if restoration_state.skipping {
                if Some(&t.id) == domain_info.last_processed_id.as_ref() {
                    debug!("Ran to last processed transaction id {}, toggling write operations", t.id);
                    restoration_state.skipping = false
                    // Note: we still skip this transaction as it is already processed
                }
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

            // Add transaction to the operations aggregator.
            restoration_state.aggregator = Some(transaction.route_transaction(
                t,
                certificate,
                restoration_state.aggregator.take()
            ).await?);

            if restoration_state.transaction_count % 20 == 0 {
                // Run write operations from aggregator
                if let Some(aggregator) = restoration_state.aggregator.take() {
                    transaction.run_aggregator(aggregator).await?;
                }
            }
        }
    }

    Ok(restoration_state)
}

pub async fn truncate_data_tables(
    mongo: &dyn MongoDao,
    data_tables: &Vec<String>,
    tracking_collection_name: Option<&str>
) -> Result<(), CommonError> {
    for table_name in data_tables {
        let collection = mongo.get_collection(table_name.as_str())?;
        collection.delete_many(doc!{}).await?;  // TODO - Truncate or drop/recreate with index
    }

    if let Some(tracking) = tracking_collection_name {
        debug!("Truncating tracking table {}", tracking);
        let collection = mongo.get_collection(tracking)?;
        collection.delete_many(doc!{}).await?;
    }

    Ok(())
}

async fn process_redolog_collection(
    mongo: &MongoDaoImpl,
    outbound: &MessageOutboundFacade,
    transaction: &dyn TransactionService,
    redolog_collection_name: &str,
    restoration_state: &mut RestorationState,
) -> Result<(), CommonError> {
    let collection = mongo.get_collection_typed::<TransactionProcessedRow>(redolog_collection_name)?;
    debug!("Opening cursor on redo-log collection: {}", redolog_collection_name);
    let mut cursor = collection
        .find(doc!{})
        .hint(Hint::Name("date_processed".into()))
        // .sort(bson::doc!{"_processed": 1})
        // .session(&mut *session)
        .batch_size(20)
        .limit(10_000)
        .await?;

    debug!("Processing entries from redo-log");
    while let Some(transaction_row) = cursor.next().await {
        match transaction_row {
            Ok(mut transaction_data) => {
                // Beancounting
                if restoration_state.first_transaction == 0 {
                    restoration_state.first_transaction = transaction_data.processed.timestamp() as u64;
                }
                let previous_last = restoration_state.last_transaction;
                restoration_state.last_transaction = transaction_data.processed.timestamp() as u64;
                if previous_last > restoration_state.last_transaction {
                    return Err(CommonError::Str("Transaction processing dates are not sorted properly"));
                }
                restoration_state.transaction_count += 1;
                // Done beancounting

                // Validate structure of transaction
                transaction_data.message.verifier_signature()?;  // Ensure transaction is valid through self-contained check

                // Parse certificate from transaction
                let certificate = if let Some(certificate_string) = transaction_data.message.certificat.as_ref() {
                    let certificate_str = certificate_string.join("\n");
                    Arc::new(EnveloppeCertificat::try_from(certificate_str.as_str())?)
                } else {
                    debug!("Fetch certificate for redo-log transaction {}", transaction_data.message.id);
                    outbound.get_certificate(transaction_data.message.pubkey.as_str(), Some(3_000)).await?
                };

                restoration_state.aggregator = Some(transaction.route_transaction(
                    transaction_data.message,
                    certificate,
                    restoration_state.aggregator.take()
                ).await?);
            }
            Err(e) => {
                error!("Error parsing redolog content: {}, will ignore transaction", e);
            }
        }
    }

    Ok(())
}
