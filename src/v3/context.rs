use async_trait::async_trait;
use crate::v3::traits::*;
use crate::middleware::{MiddlewareMessage, RedisTrait};
use crate::redis_dao::RedisDao;
use crate::generateur_messages::{RoutageMessageAction, GenerateurMessages};
use crate::recepteur_messages::TypeMessage;
use crate::certificats::{EnveloppeCertificat, EnveloppePrivee};
use crate::configuration::{ConfigMessages, IsConfigNoeud};
use crate::formatteur_messages::FormatteurMessage;
use mongodb::{bson::Document, Collection};

#[async_trait]
impl DatabaseService for MiddlewareMessage {
    async fn get_collection(&self, name: &str) -> Result<Collection<Document>, crate::error::Error> {
        self.get_collection(name).await.map_err(|e| crate::error::Error::String(format!("{:?}", e)))
    }
}

#[async_trait]
impl MessagingService for MiddlewareMessage {
    async fn transmettre_requete_json(&self, routage: RoutageMessageAction, message_json: serde_json::Value) -> Result<Option<TypeMessage>, crate::error::Error> {
        self.transmettre_requete(routage, &message_json).await.map_err(|e| crate::error::Error::String(format!("{:?}", e)))
    }

    async fn transmettre_commande_json(&self, routage: RoutageMessageAction, message_json: serde_json::Value) -> Result<Option<TypeMessage>, crate::error::Error> {
        self.transmettre_commande(routage, &message_json).await.map_err(|e| crate::error::Error::String(format!("{:?}", e)))
    }
}

#[async_trait]
impl SecurityService for MiddlewareMessage {
    async fn get_publickeys_chiffrage(&self) -> Vec<EnveloppeCertificat> {
        self.get_publickeys_chiffrage().await.into_iter().map(|c| c.into()).collect()
    }
}

impl ConfigService for MiddlewareMessage {
    fn get_configuration_mq(&self) -> &crate::configuration::ConfigurationMq {
        self.ressources.configuration.get_configuration_mq()
    }
    fn get_configuration_pki(&self) -> &crate::configuration::ConfigurationPki {
        self.ressources.configuration.get_configuration_pki()
    }
    fn get_configuration_noeud(&self) -> &crate::configuration::ConfigurationNoeud {
        self.ressources.configuration.get_configuration_noeud()
    }
}

impl FormatService for MiddlewareMessage {
    fn get_enveloppe_signature(&self) -> EnveloppePrivee {
        (*self.ressources.generateur_messages.get_enveloppe_signature()).clone()
    }
}

impl BackupService for MiddlewareMessage {}

pub struct MiddlewareContext<'a> {
    pub database: &'a dyn DatabaseService,
    pub messaging: &'a dyn MessagingService,
    pub security: &'a dyn SecurityService,
    pub config: &'a dyn ConfigService,
    pub format: &'a dyn FormatService,
    pub backup: &'a dyn BackupService,
    pub redis: Option<&'a RedisDao>,
}

impl<'a> MiddlewareContext<'a> {
    pub fn new(middleware: &'a MiddlewareMessage) -> Self {
        Self {
            database: middleware,
            messaging: middleware,
            security: middleware,
            config: middleware,
            format: middleware,
            backup: middleware,
            redis: middleware.get_redis(),
        }
    }
}
