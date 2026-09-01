use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::sync::Arc;
use bson::Document;
use millegrilles_cryptographie::chiffrage_cles::CleSecreteSerialisee;
use millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_cryptographie::x25519::{CleDerivee, CleSecreteX25519};
use mongodb::options::WriteModel;
use serde_json::Value;
use crate::backup_v2::FichierArchiveBackup;
use crate::common_messages::ResponseRequestDechiffrageV2Cle;
use crate::error::Error as CommonError;
use crate::v3::facades::message_inbound::MessageValidated;

pub struct VerifiedResponseMessage {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
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
    /// List of existing backup files in order (Finals, current Concatenated then Incrementals)
    pub existing_files: Option<Vec<FichierArchiveBackup>>,
    // Number of transactions currently in the redo-log (not backed-up yet)
    pub redolog_count: usize,
    pub key: DecryptedKey,
}

#[derive(Clone)]
pub struct GeneratedSecretKey {
    pub key_id: String,
    secret_key: CleDerivee,
    pub signature: SignatureDomaines,
    pub encrypted_keys: HashMap<String, String>,
}

impl GeneratedSecretKey {
    /// Make the secret value obvious
    pub fn secret_key(&self) -> &CleSecreteX25519 {
        &self.secret_key.secret
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
