use std::path::Path;
use crate::backup_v2::InfoTransactions;
use crate::configuration::{ConfigurationMq, ConfigurationNoeud, ConfigurationPki};
use crate::error::Error as CommonError;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::v3::impls::rabbitmq_consumer::InboundMessage;
use crate::v3::models::{DecryptedKey, GeneratedSecretKey, TransactionOperationAggregator, TransactionWrapper, VerifiedResponseMessage};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::ValidateurX509;
use mongodb::{Collection, bson::Document};
use serde_json::Value;
use std::sync::Arc;
use multibase::Base;
use multihash::Code;
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait MessagingService: Send + Sync {
    /// Emits a message, does not wait for a response (i.e. supported types are Event, Response, non-blocking Commands)
    /// This is fire and forget (no confirmation expected)
    async fn emit(&self, message: MessageMilleGrillesBufferDefault, routing: Option<RoutageMessageAction>)
                  -> Result<(), CommonError>;

    /// Sends a message and waits for a response. Used for requests and blocking commands only.
    async fn send(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageAction)
                  -> Result<VerifiedResponseMessage, CommonError>;

    /// Emits a response
    async fn respond(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageReponse)
                  -> Result<(), CommonError>;

    /// Take the message receiver from the queue registry for a named queue.
    fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<InboundMessage>, CommonError>;
}

#[async_trait]
pub trait PkiService: ValidateurX509 + Send + Sync {
    /// Loads and validates a PEm file. ca_pem is optional (only required for loading from different system)
    /// date=None means current date
    fn validate_pem(&self, pem_chain: &str, ca_pem: Option<&str>, date: Option<&DateTime<Utc>>)
        -> Result<Arc<EnveloppeCertificat>, CommonError>;

    /// Verifies all security components of the message. Returns the parsed certificate.
    /// Fails with an Error on any issue.
    async fn validate_message(&self, message: &MessageMilleGrillesOwned) -> Result<Arc<EnveloppeCertificat>, CommonError>;

    async fn validate_message_ref(&self, message: &MessageMilleGrillesRefDefault) -> Result<Arc<EnveloppeCertificat>, CommonError>;

    /// A cached public key implies the corresponding certificate has been verified and is currently valid.
    fn is_cached_pk_valid(&self, public_key: &str) -> bool;
}

#[async_trait]
pub trait ChiffrageService: Send + Sync {
    fn get_encryption_publickeys(&self) -> Vec<Arc<EnveloppeCertificat>>;
    fn encryption_key_maintenance(&self);
    fn add_encryption_publickey(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), CommonError>;
    fn decrypt_document(&self, value: EncryptedDocument) -> Result<Value, CommonError>;
    /// Fetches keys from the KeyMaster
    async fn get_keys(&self, key_ids: Vec<String>) -> Result<Vec<DecryptedKey>, CommonError>;
    /// Generates a new key that can be decrypted by the CA master key
    async fn generate_new_key(&self, domains: &Vec<String>) -> Result<GeneratedSecretKey, CommonError>;
    /// Saves the generated keys with the KeyMaster
    async fn save_keys(&self, keys: Vec<GeneratedSecretKey>) -> Result<(), CommonError>;
    async fn digest_file(&self, path: &Path, code: Code, base: Base) -> Result<String, CommonError>;
}

pub trait ConfigService: Send + Sync {
    fn get_configuration_mq(&self) -> &ConfigurationMq;
    fn get_configuration_pki(&self) -> &ConfigurationPki;
    fn get_configuration_instance(&self) -> &ConfigurationNoeud;
}

/// Message and document formatting
pub trait FormatService: Send + Sync {
    fn build_response(&self, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), CommonError>;
    fn build_encrypted_response(&self, message: Value, certificat_demandeur: &EnveloppeCertificat)
                                -> Result<(MessageMilleGrillesBufferDefault, String), CommonError>;
    fn build_action_message(&self, type_message: MessageKind, routage: &RoutageMessageAction, message: Value)
                            -> Result<(MessageMilleGrillesBufferDefault, String), CommonError>;
    fn build_encrypted_action_message(&self, type_message: MessageKind, routage: &RoutageMessageAction, 
                                      message: Value, keys: Vec<&EnveloppeCertificat>) 
        -> Result<(MessageMilleGrillesBufferDefault, String), CommonError>;
}

#[async_trait]
pub trait BackupService: Send + Sync {
    async fn backup_domain(
        &self,
        domain_name: String,
        redolog_collection_name: String,
        concatenate: bool,
        correlation_id: String,
    ) -> Result<(), CommonError>;
}

#[async_trait]
pub trait DatabaseService: Send + Sync {
    async fn get_collection(&self, name: &str) -> Result<Collection<Document>, CommonError>;
}

#[async_trait]
pub trait TransactionService: Send + Sync {
    async fn process_transaction(&self, wrapper: TransactionWrapper) -> Result<(), CommonError>;
    async fn process_value(&self, domain: &str, action: &str, value: Value) -> Result<(), CommonError>;
}

#[async_trait]
pub trait TransactionRouter: Send + Sync {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError>;
}

#[async_trait]
pub trait FilehostClient: Send + Sync {
    async fn connect() -> Result<(), CommonError>;
    async fn put_file() -> Result<(), CommonError>;
    async fn get_file() -> Result<(), CommonError>;
    async fn get_backup_list() -> Result<(), CommonError>;
    async fn get_backup_file() -> Result<(), CommonError>;
    async fn put_backup_file() -> Result<(), CommonError>;
}
