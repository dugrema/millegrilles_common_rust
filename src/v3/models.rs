use crate::backup_v2::{FichierArchiveBackup, TypeArchive};
use crate::common_messages::ResponseRequestDechiffrageV2Cle;
use crate::error::Error as CommonError;
use crate::v3::facades::message_inbound::MessageValidated;
use bson::{Document, doc, serde_helpers::datetime::FromChrono04DateTime};
use chrono::Utc;
use jwt_simple::prelude::Deserialize;
use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageX25519Impl, CleSecreteSerialisee};
use millegrilles_cryptographie::maitredescles::{generer_cle_avec_ca, SignatureDomaines};
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, MessageMilleGrillesOwned};
use millegrilles_cryptographie::x25519::{CleDerivee, CleSecreteX25519};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::options::WriteModel;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use millegrilles_cryptographie::chiffrage::FormatChiffrage;

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

#[derive(Debug, Clone)]
/// Used to aggregate transaction operations.
/// Simplifies batching on rebuilds (redo).
pub struct TransactionOperationAggregator {
    /// Insertions run first as a batch, they must not have any dependency (e.g. deletion to avoid duplicate)
    pub batch_insertions: Option<Vec<BatchInsertions>>,
    /// Operations that can run concurrently (e.g. updating/deleting entries from different collections)
    /// These operations can depend on batch_insertions because insertions always run first.
    pub unordered: Option<Vec<WriteModel>>,
    /// Operations that must be run in order, e.g. "update val=val+1" then "delete where val>10".
    /// They will always be run after the batch_insertions and unordered operations.
    pub ordered: Option<Vec<WriteModel>>,
}

impl TransactionOperationAggregator {
    pub fn new() -> Self {
        Self {
            batch_insertions: None,
            unordered: None,
            ordered: None
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

}

#[derive(Debug)]
pub struct LockFile {
    pub file: File,
    pub path: PathBuf,
}

pub struct PreflightResult {
    pub domain_name: String,
    pub idmg: String,
    pub domain_backup_path: PathBuf,
    /// List of existing backup files in order (Finals, current Concatenated then Incrementals)
    pub existing_files: Vec<FichierArchiveBackup>,
    // Number of transactions currently in the redo-log (not backed-up yet)
    pub redolog_count: usize,
    pub key: DecryptedKey,
}

impl PreflightResult {
    pub fn contains_incremental(&self) -> bool {
        if let Some(last_file) = self.existing_files.last() {
            if last_file.header.type_archive == TypeArchive::Incremental.to_string() {
                return true
            }
        }
        false
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
    pub first_transaction: u64,
    pub last_transaction: u64,
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
    CommonError(CommonError),
}

impl From<CommonError> for PreflightError {
    fn from(err: CommonError) -> Self { PreflightError::CommonError(err) }
}
