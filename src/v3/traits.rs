use crate::configuration::{ConfigurationMq, ConfigurationNoeud, ConfigurationPki};
use crate::error::Error;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::securite::Securite;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::{Collection, bson::Document};
use serde_json::Value;
use std::sync::Arc;
use millegrilles_cryptographie::x509_store::ValidateurX509;

#[async_trait]
pub trait MessagingService: Send + Sync {
    async fn emit_event(&self, routage: RoutageMessageAction, value: Value) -> Result<(), Error>;

    async fn send_request(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error>;

    // Transactions as messages should be obsolete (use command instead)
    // async fn send_transaction(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error>;

    async fn send_command(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error>;

    async fn respond(&self, routage: RoutageMessageReponse, value: Value) -> Result<(), Error>;

    /// Emettre un message en str deja serialise
    async fn emit_message(&self, type_message: TypeMessageOut, value: MessageMilleGrillesBufferDefault) -> Result<Option<TypeMessage>, Error>;

    fn mq_available(&self) -> bool;

    /// Active le mode regeneration
    fn set_regeneration(&self);

    /// Desactive le mode regeneration
    fn reset_regeneration(&self);

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_regeneration_mode(&self) -> bool;

    fn get_security(&self) -> &Securite;

    fn is_dev(&self) -> bool;
}

#[async_trait]
pub trait PkiService: ValidateurX509 + Send + Sync {}

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
