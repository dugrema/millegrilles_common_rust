use std::fs::File;
use std::path::PathBuf;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::sync::Arc;
use bson::Document;
use mongodb::options::WriteModel;
use serde_json::Value;
use crate::backup_v2::FichierArchiveBackup;
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

#[derive(Debug, Clone)]
pub struct PreflightResult {
    /// List of existing backup files in order (Finals, current Concatenated then Incrementals)
    pub existing_files: Option<Vec<FichierArchiveBackup>>,
    // Number of transactions currently in the redo-log (not backed-up yet)
    pub redolog_count: usize,
}
