use crate::backup_v2::{FichierArchiveBackup, HeaderFichierArchive, TypeArchive};
use crate::common_messages::ResponseRequestDechiffrageV2Cle;
use crate::error::Error as CommonError;
use crate::v3::facades::message_inbound::MessageValidated;
use base64::Engine;
use base64::engine::general_purpose;
use bson::{Bson, Document, doc, serde_helpers::datetime::FromChrono04DateTime};
use chrono::{DateTime, Utc};
use jwt_simple::prelude::Deserialize;
use millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageX25519Impl, CleSecreteSerialisee};
use millegrilles_cryptographie::maitredescles::{SignatureDomaines, generer_cle_avec_ca};
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, MessageMilleGrillesOwned};
use millegrilles_cryptographie::x25519::{CleDerivee, CleSecreteX25519};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::options::WriteModel;
use openssl::pkey::{PKey, Private};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct VerifiedResponseMessage {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
}

impl VerifiedResponseMessage {
    pub fn is_ok(&self) -> Result<bool, CommonError> {
        ErrorMessage::is_ok(&self.message)
    }
    pub fn is_err(&self) -> Result<(bool, Option<String>), CommonError> {
        ErrorMessage::is_err(&self.message)
    }
}

#[derive(Clone)]
pub struct TransactionWrapper {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
    /// Decrypted content when applicable
    pub content: Option<Value>,
}

impl From<MessageValidated> for TransactionWrapper {
    fn from(value: MessageValidated) -> Self {
        Self {
            message: value.message,
            certificate: value.certificate,
            content: value.content,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchInsertions {
    pub collection_name: String,
    pub insertions: Vec<Document>
}

impl BatchInsertions {
    pub fn new(collection_name: &str, insertions: Vec<Document>) -> Self {
        Self {
            collection_name: collection_name.to_string(),
            insertions,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowTransactionTracking {
    pub bid: Bson,
    pub ok: bool,
    pub id: String,
    #[serde(with = "FromChrono04DateTime")]
    pub processed: chrono::DateTime<Utc>,
}

impl TryFrom<&MessageMilleGrillesOwned> for RowTransactionTracking {
    type Error = CommonError;
    fn try_from(value: &MessageMilleGrillesOwned) -> Result<Self, CommonError> {
        let bid_complete = hex::decode(value.id.as_str())?;
        let bid_truncated = &bid_complete[0..16];
        let bid_truncated_base64 = general_purpose::STANDARD.encode(bid_truncated);
        let bid_truncated_bson = Bson::Binary(bson::Binary::from_base64(bid_truncated_base64, None)
            .expect("bid_truncated_bson base64"));
        Ok(Self {
            bid: bid_truncated_bson,
            ok: true,
            id: value.id.clone(),
            processed: value.estampille,
        })
    }
}

#[derive(Debug, Clone)]
/// Used to aggregate transaction operations.
/// Simplifies batching on rebuilds (redo).
pub struct TransactionOperationAggregator {
    /// List of tracking rows to add for the transaction.
    pub tracking: Option<Vec<Document>>,
    /// Insertions run first as a batch, they must not have any dependency (e.g. deletion to avoid duplicate)
    pub batch_insertions: Option<Vec<BatchInsertions>>,
    /// Operations that can run concurrently (e.g. updating/deleting entries from different collections)
    /// These operations can depend on batch_insertions because insertions always run first.
    pub unordered: Option<Vec<WriteModel>>,
    /// Operations that must be run in order, e.g. "update val=val+1" then "delete where val>10".
    /// They will always be run after the batch_insertions and unordered operations.
    pub ordered: Option<Vec<WriteModel>>,
    /// Set to true when the backup contains legacy transactions.
    /// This allows workarounds while processing older backups.
    pub legacy: bool,
}

impl TransactionOperationAggregator {
    pub fn new() -> Self {
        Self {
            tracking: None,
            batch_insertions: None,
            unordered: None,
            ordered: None,
            legacy: false,
        }
    }

    pub fn batch_insertion(&mut self, operation: BatchInsertions) -> Result<&mut Self, CommonError> {
        if self.ordered.is_some() {
            Err(CommonError::Str("Cannot use batch insertion once ordered list is used"))?
        }
        self.batch_insertions.get_or_insert(vec![]).push(operation);
        Ok(self)
    }

    pub fn add_unordered(&mut self, operation: WriteModel) -> Result<&mut Self, CommonError> {
        if self.ordered.is_some() {
            Err(CommonError::Str("Cannot use unordered operations once ordered list is used"))?
        }
        self.unordered.get_or_insert(vec![]).push(operation);
        Ok(self)
    }

    pub fn add_ordered(&mut self, operation: WriteModel) -> &mut Self {
        self.ordered.get_or_insert(vec![]).push(operation);
        self
    }

    pub fn merge(&mut self, other: Self) {
        // Pass in the legacy flag (only goes from false to true)
        self.legacy = self.legacy || other.legacy;

        // Tracking entries
        match self.tracking.as_mut() {
            Some(tracking) => {
                if let Some(other_tracking) = other.tracking {
                    tracking.extend(other_tracking);
                }
            }
            None => {
                self.tracking = other.tracking;
            }
        }

        // Presence of ordered operations determine how processing can be done
        if self.ordered.is_none() {
            match self.batch_insertions.as_mut() {
                Some(insertions) => {
                    if let Some(other_insertions) = other.batch_insertions {
                        insertions.extend(other_insertions);
                    }
                }
                None => {
                    self.batch_insertions = other.batch_insertions;
                }
            }
            match self.unordered.as_mut() {
                Some(unordered) => {
                    if let Some(other_unordered) = other.unordered {
                        unordered.extend(other_unordered);
                    }
                }
                None => {
                    self.unordered = other.unordered;
                }
            }
        } else {
            // Must add all remaining operations as ordered
            todo!()
        }

        // Always extend ordered at the end in case other operations were injected (insert, unordered)
        match self.ordered.as_mut() {
            Some(ordered) => {
                if let Some(other_ordered) = other.ordered {
                    ordered.extend(other_ordered);
                }
            }
            None => {
                self.ordered = other.ordered;
            }
        }
    }
}

#[derive(Debug)]
pub struct LockFile {
    pub file: File,
    pub path: PathBuf,
}

pub struct BackupPreflightResult {
    pub domain_name: String,
    pub idmg: String,
    pub domain_backup_path: PathBuf,
    /// List of existing backup files in order (Finals, current Concatenated then Incrementals)
    pub files: Vec<FichierArchiveBackup>,
    // Number of transactions currently in the redo-log (not backed-up yet)
    pub redolog_count: usize,
    pub key: DecryptedKey,
    /// Suffix ot the Concatene file
    pub version: Option<String>,
}

impl BackupPreflightResult {
    pub fn contains_incremental(&self) -> bool {
        if let Some(last_file) = self.files.last() {
            if last_file.header.type_archive == TypeArchive::Incremental.to_string() {
                return true
            }
        }
        false
    }
}

pub struct RestorePreflightResult<'a> {
    pub domain_name: String,
    pub idmg: String,
    pub domain_backup_path: PathBuf,
    /// List of existing backup files in order (Finals, current Concatenated then Incrementals)
    pub files: Vec<FichierArchiveBackup>,
    /// Transaction count from all file headers
    pub file_transaction_count: u64,
    /// Number of transactions currently in the redo-log (not backed-up yet)
    pub redolog_count: usize,
    pub keys: Mutex<HashMap<String, DecryptedKey>>,
    /// Used when resuming, this is the last processed transaction id in the tracking table
    pub last_processed_id: Option<String>,
    pub master_key: Option<&'a PKey<Private>>,
}

impl<'a> RestorePreflightResult<'a> {
    pub fn decrypt_key(&self, archive_header: &HeaderFichierArchive) -> Result<CleDechiffrageX25519Impl, CommonError> {
        let key_id = archive_header.cle_id.as_str();

        {
            let guard = self.keys.lock().unwrap();
            match guard.get(&key_id.to_string()) {
                Some(key) => {
                    // Inject the nonce/format from the backup file into the key
                    let mut value: CleDechiffrageX25519Impl = key.try_into()?;
                    value.nonce = Some(archive_header.nonce.clone());
                    value.format = archive_header.format.as_str().try_into()?;
                    return Ok(value)
                },
                None => {
                    if self.master_key.is_none() {
                        return Err(CommonError::String(format!("Key id {} not found", key_id)));
                    }
                }
            }
        }

        // Key not cached, but we have a decryption key
        match self.master_key.as_ref() {
            Some(master_key) => {
                // Decrypt directly
                let signature = archive_header.cle_dechiffrage.clone();
                let decrypted_key = signature.dechiffrer_ca(master_key)?;

                // Rebuild DecryptedKey for the cache
                let cached_key = DecryptedKey {
                    signature: Some(signature),
                    key: CleSecreteSerialisee::from_cle_secrete(decrypted_key.clone(), Some(key_id), None, None::<&str>, None::<&str>)?,
                    secret: decrypted_key.clone(),
                };
                {
                    // Save the key in map for reuse
                    let mut guard = self.keys.lock().unwrap();
                    guard.insert(key_id.to_string(), cached_key);
                }

                // Build DecryptedKey result
                Ok(CleDechiffrageX25519Impl {
                    cle_chiffree: "".to_string(),
                    cle_secrete: Some(decrypted_key),
                    format: archive_header.format.as_str().try_into()?,
                    nonce: Some(archive_header.nonce.as_str().into()),
                    verification: None,
                })
            },
            None => {
                // Should not happen - we already checked that we have the master key
                Err(CommonError::String(format!("Key id {} not found in cache", key_id)))
            }
        }
    }
}

#[derive(Clone)]
pub struct GeneratedSecretKey {
    pub key_id: String,
    pub secret_key: CleDerivee,
    pub signature: SignatureDomaines,
    pub encrypted_keys: HashMap<String, String>,
}

impl GeneratedSecretKey {
    /// Make the secret value obvious
    pub fn secret_key(&self) -> &CleSecreteX25519 {
        &self.secret_key.secret
    }

    pub fn generate(domains: Vec<String>, ca: &EnveloppeCertificat, public_keys: Vec<&EnveloppeCertificat>) -> Result<Self, CommonError> {
        // Generate secret key
        let (new_key, secret_key) = generer_cle_avec_ca(
            domains,
            ca,
            public_keys
        )?;

        // Convert to proper format
        Self::from_dechiffrage_key(new_key, secret_key)
    }

    pub fn from_dechiffrage_key(
        value: DechiffrageInterMillegrilleOwned,
        secret_key: CleDerivee
    ) -> Result<Self, CommonError> {
        let key_id = match value.cle_id {
            Some(inner) => inner,
            None => return Err(CommonError::Str("Key id was not generated"))
        };

        let signature = match value.signature {
            Some(inner) => inner,
            None => return Err(CommonError::Str("Key signature was not generated"))
        };

        let encrypted_keys: HashMap<String, String> = match value.cles {
            Some(inner) => inner.into_iter().collect(),
            None => return Err(CommonError::Str("Encrypted keys were not generated"))
        };

        Ok(Self {
            key_id,
            secret_key,
            signature,
            encrypted_keys,
        })
    }
}

/// Encapsulates a key response
pub struct DecryptedKey {
    pub signature: Option<SignatureDomaines>,
    pub key: CleSecreteSerialisee,
    pub secret: CleSecreteX25519,
}

impl TryFrom<ResponseRequestDechiffrageV2Cle> for DecryptedKey {
    type Error = CommonError;

    fn try_from(value: ResponseRequestDechiffrageV2Cle) -> Result<Self, Self::Error> {
        let signature = value.signature.clone();
        let key: CleSecreteSerialisee = value.try_into()?;
        let secret: CleSecreteX25519 = key.cle_secrete()?;
        Ok(Self {signature, key, secret})
    }
}

impl TryFrom<GeneratedSecretKey> for DecryptedKey {
    type Error = CommonError;

    fn try_from(value: GeneratedSecretKey) -> Result<Self, Self::Error> {
        let serialized_key = CleSecreteSerialisee::from_cle_secrete(
            value.secret_key.secret.clone(),
            Some(value.key_id.clone()),
            None, None::<&str>, None::<&str>,
        )?;
        Ok(Self {
            signature: Some(value.signature),
            key: serialized_key,
            secret: value.secret_key.secret,
        })
    }
}

impl TryInto<CleDechiffrageX25519Impl> for &DecryptedKey {
    type Error = CommonError;

    fn try_into(self) -> Result<CleDechiffrageX25519Impl, Self::Error> {
        Ok(CleDechiffrageX25519Impl {
            cle_chiffree: "N/A".to_string(),
            cle_secrete: Some(self.secret.clone()),
            format: self.key.format.clone().unwrap_or(FormatChiffrage::MGS4),
            nonce: match self.key.nonce.clone() { Some(nonce) => Some(nonce.to_string()), None => None },
            verification: match self.key.verification.clone() { Some(verif) => Some(verif.to_string()), None => None },
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct TransactionProcessedRow {
    #[serde(flatten)]
    pub message: MessageMilleGrillesOwned,
    #[serde(with="FromChrono04DateTime")]
    pub processed: chrono::DateTime<Utc>,
}

#[derive(Clone)]
pub struct BackupResult {
    /// First transaction in the backup, epoch milliseconds
    pub first_transaction: DateTime<Utc>,
    /// Last transaction in the backup, epoch milliseconds
    pub last_transaction: DateTime<Utc>,
    pub count: u64
}

/// Generic message structure, can be used for OK or Errors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub ok: bool,
    pub code: Option<u16>,
    pub err: Option<String>,
}

impl ErrorMessage {
    pub fn ok() -> Self { Self { ok: true, code: None, err: None } }
    pub fn err(msg: &str) -> Self { Self { ok: false, code: None, err: Some(msg.to_string()) } }
    pub fn err_code(code: u16, msg: &str) -> Self { Self { ok: false, code: Some(code), err: Some(msg.to_string()) } }
    pub fn is_ok(value: &MessageMilleGrillesOwned) -> Result<bool, CommonError> {
        let content: Self = value.deserialize()?;
        Ok(content.ok)
    }
    pub fn is_err(value: &MessageMilleGrillesOwned) -> Result<(bool, Option<String>), CommonError> {
        let content: Self = value.deserialize()?;
        Ok((!content.ok, content.err))
    }
}

pub enum PreflightError {
    NothingToDo,
    NotReadyForBackup,
    CommonError(CommonError),
}

impl From<CommonError> for PreflightError {
    fn from(err: CommonError) -> Self { PreflightError::CommonError(err) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateRequest {
    pub fingerprint: String
}

#[derive(Clone, Debug)]
pub struct FilehostClient {
    pub client: reqwest::Client,
    pub url: String,
    pub last_usage: DateTime<Utc>,
    pub last_test: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainPresenceEvent {
    pub instance_id: String,
    pub domaine: String,
    pub sous_domaines: Option<String>,
    pub exchanges_routing: Option<String>,
    pub primaire: bool,
    pub reclame_fuuids: bool,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct CoreTopologyBackupEvent {
//     pub uuid_rapport: String,
//     pub evenement: String,
//     pub domaine: String,
//     #[serde(with="ts_seconds")]
//     pub timestamp: DateTime<Utc>,
// }
