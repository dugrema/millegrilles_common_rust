use async_trait::async_trait;
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::recepteur_messages::TypeMessage;
use crate::certificats::{EnveloppeCertificat, EnveloppePrivee};
use crate::configuration::{ConfigurationMq, ConfigurationPki, ConfigurationNoeud};
use mongodb::{bson::Document, Collection};
use std::sync::Arc;

#[async_trait]
pub trait DatabaseService: Send + Sync {
    async fn get_collection(&self, name: &str) -> Result<Collection<Document>, Error>;
}

#[async_trait]
pub trait MessagingService: Send + Sync {
    async fn transmettre_requete_json(&self, routage: RoutageMessageAction, message_json: serde_json::Value) -> Result<Option<TypeMessage>, Error>;
    async fn transmettre_commande_json(&self, routage: RoutageMessageAction, message_json: serde_json::Value) -> Result<Option<TypeMessage>, Error>;
}

#[async_trait]
pub trait SecurityService: Send + Sync {
    async fn get_publickeys_chiffrage(&self) -> Vec<EnveloppeCertificat>;
}

#[async_trait]
pub trait CertificatService: Send + Sync {
    async fn emettre_certificat(&self, routage: RoutageMessageAction) -> Result<(), Error>;
}

#[async_trait]
pub trait ChiffrageService: Send + Sync {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>>;
    fn entretien_cle_chiffrage(&self);
    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), Error>;
}

#[async_trait]
pub trait ConfigService: Send + Sync {
    fn get_configuration_mq(&self) -> &ConfigurationMq;
    fn get_configuration_pki(&self) -> &ConfigurationPki;
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud;
}

pub trait FormatService: Send + Sync {
    fn get_enveloppe_signature(&self) -> EnveloppePrivee;
}

#[async_trait]
pub trait BackupService: Send + Sync {}

pub trait RedisService: crate::middleware::RedisTrait {}
