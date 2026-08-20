use crate::configuration::{ConfigurationMq, ConfigurationNoeud, ConfigurationPki};
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::ValidateurX509;
use mongodb::{Collection, bson::Document};
use serde_json::Value;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc::Receiver;

#[async_trait]
pub trait MessagingService: Send + Sync {
    /// Emits a message, does not wait for a response (i.e. supported types are Event, Response, non-blocking Commands)
    /// This is fire and forget (no confirmation expected)
    async fn emit(&self, message: MessageMilleGrillesBufferDefault, routing: Option<RoutageMessageAction>)
                  -> Result<(), Error>;

    /// Sends a message and waits for a response. Used for requests and blocking commands only.
    async fn send(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageAction)
                  -> Result<MessageMilleGrillesBufferDefault, Error>;

    /// Take the message receiver from the queue registry for a named queue.
    fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<MessageMilleGrillesBufferDefault>, Error>;
}

#[async_trait]
pub trait PkiService: ValidateurX509 + Send + Sync {
    /// Loads and validates a PEm file. ca_pem is optional (only required for loading from different system)
    /// date=None means current date
    fn validate_pem(&self, pem_chain: &str, ca_pem: Option<&str>, date: Option<&DateTime<Utc>>)
        -> Result<Arc<EnveloppeCertificat>, Error>;

    /// Verifies all security components of the message. Returns the parsed certificate.
    /// Fails with an Error on any issue.
    async fn validate_message(&self, message: &MessageMilleGrillesRefDefault) -> Result<Arc<EnveloppeCertificat>, Error>;

    /// A cached public key implies the corresponding certificate has been verified and is currently valid.
    fn is_cached_pk_valid(&self, public_key: &str) -> bool;
}

#[async_trait]
pub trait ChiffrageService: Send + Sync {
    fn get_encryption_publickeys(&self) -> Vec<Arc<EnveloppeCertificat>>;
    fn encryption_key_maintenance(&self);
    fn add_encryption_publickey(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), Error>;
}

pub trait ConfigService: Send + Sync {
    fn get_configuration_mq(&self) -> &ConfigurationMq;
    fn get_configuration_pki(&self) -> &ConfigurationPki;
    fn get_configuration_instance(&self) -> &ConfigurationNoeud;
}

/// Message and document formatting
pub trait FormatService: Send + Sync {
    fn build_response(&self, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error>;
    fn build_encrypted_response(&self, message: Value, certificat_demandeur: &EnveloppeCertificat)
                                -> Result<(MessageMilleGrillesBufferDefault, String), Error>;
    fn build_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value)
                            -> Result<(MessageMilleGrillesBufferDefault, String), Error>;
    fn build_encrypted_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value)
                                      -> Result<(MessageMilleGrillesBufferDefault, String), Error>;
}

#[async_trait]
pub trait BackupService: Send + Sync {}

#[async_trait]
pub trait DatabaseService: Send + Sync {
    async fn get_collection(&self, name: &str) -> Result<Collection<Document>, Error>;
}
