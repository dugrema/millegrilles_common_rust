use crate::configuration::{ConfigurationMq, ConfigurationNoeud, ConfigurationPki};
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use async_trait::async_trait;
use mongodb::{Collection, bson::Document};
use std::sync::Arc;
use millegrilles_cryptographie::securite::Securite;
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};

#[async_trait]
pub trait DatabaseService: Send + Sync {
    async fn get_collection(&self, name: &str) -> Result<Collection<Document>, Error>;
}

#[async_trait]
pub trait MessagingService: Send + Sync {
    async fn emettre_evenement(&self, routage: RoutageMessageAction, value: serde_json::Value) -> Result<(), Error>;

    async fn transmettre_requete(&self, routage: RoutageMessageAction, value: serde_json::Value) -> Result<Option<TypeMessage>, Error>;

    async fn soumettre_transaction(&self, routage: RoutageMessageAction, value: serde_json::Value) -> Result<Option<TypeMessage>, Error>;

    async fn transmettre_commande(&self, routage: RoutageMessageAction, value: serde_json::Value) -> Result<Option<TypeMessage>, Error>;

    async fn repondre(&self, routage: RoutageMessageAction, value: serde_json::Value) -> Result<(), Error>;

    /// Emettre un message en str deja serialise
    async fn emettre_message(&self, type_message: TypeMessageOut, value: serde_json::Value) -> Result<Option<TypeMessage>, Error>;

    fn mq_disponible(&self) -> bool;

    /// Active le mode regeneration
    fn set_regeneration(&self);

    /// Desactive le mode regeneration
    fn reset_regeneration(&self);

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_mode_regeneration(&self) -> bool;

    fn get_securite(&self) -> &Securite;

    fn is_dev(&self) -> bool;
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
