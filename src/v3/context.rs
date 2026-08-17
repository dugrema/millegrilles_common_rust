use async_trait::async_trait;
use crate::v3::traits::*;
use crate::middleware::{MiddlewareMessage, RedisTrait, IsConfigurationPki};
use crate::redis_dao::RedisDao;
use crate::generateur_messages::{RoutageMessageAction, GenerateurMessages};
use crate::recepteur_messages::TypeMessage;
use crate::certificats::{EnveloppeCertificat, EnveloppePrivee};
use crate::configuration::{ConfigMessages, IsConfigNoeud};
use crate::formatteur_messages::FormatteurMessage;
use crate::chiffrage_cle::CleChiffrageCache;
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use mongodb::{bson::Document, Collection};
use std::sync::Arc;



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
        ChiffrageService::get_publickeys_chiffrage(self).into_iter().map(|c| (*c).clone()).collect()
    }
}

#[async_trait]
impl CertificatService for MiddlewareMessage {
    async fn emettre_certificat(&self, routage: RoutageMessageAction) -> Result<(), crate::error::Error> {
        let enveloppe_privee = self.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe_pub.as_ref();
        let message = crate::middleware::formatter_message_certificat(enveloppe_certificat)?;

        if let Some(redis) = self.redis.as_ref() {
            if let Err(e) = redis.save_certificat(enveloppe_certificat).await {
                log::warn!("MiddlewareDb.emettre_certificat Erreur sauvegarde certificat local sous redis : {:?}", e);
            }
        }

        self.ressources.generateur_messages.emettre_evenement(routage, &message).await?;
        Ok(())
    }
}

#[async_trait]
impl ChiffrageService for MiddlewareMessage {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        CleChiffrageHandler::get_publickeys_chiffrage(&self.cle_chiffrage_handler)
    }

    fn entretien_cle_chiffrage(&self) {
        self.cle_chiffrage_handler.entretien_cle_chiffrage();
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), crate::error::Error> {
        self.cle_chiffrage_handler.ajouter_certificat_chiffrage(certificat).map_err(|e| crate::error::Error::String(e.to_string()))
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
    pub certificat: &'a dyn CertificatService,
    pub chiffrage: &'a dyn ChiffrageService,
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
            certificat: middleware,
            chiffrage: middleware,
            config: middleware,
            format: middleware,
            backup: middleware,
            redis: middleware.get_redis(),
        }
    }
}
