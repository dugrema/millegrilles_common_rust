use async_trait::async_trait;
use crate::v3::traits::{SecurityService, ChiffrageService, CertificatService, MessagingService};
use crate::error::Error;
use crate::configuration::ConfigMessages;
use std::sync::Arc;
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::ValidateurX509Impl;
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};
use crate::generateur_messages::RoutageMessageAction;

pub struct SecurityServiceImpl {
    validator: Arc<ValidateurX509Impl>,
    encryption_handler: CleChiffrageHandlerImpl,
    messaging: Arc<dyn MessagingService>,
    config: Arc<dyn ConfigMessages>,
}

impl SecurityServiceImpl {
    pub fn new(
        validator: Arc<ValidateurX509Impl>,
        encryption_handler: CleChiffrageHandlerImpl,
        messaging: Arc<dyn MessagingService>,
        config: Arc<dyn ConfigMessages>,
    ) -> Self {
        Self {
            validator,
            encryption_handler,
            messaging,
            config,
        }
    }
}

#[async_trait]
impl SecurityService for SecurityServiceImpl {
    async fn get_publickeys_chiffrage(&self) -> Vec<EnveloppeCertificat> {
        self.encryption_handler.get_publickeys_chiffrage()
            .into_iter()
            .map(|c| (*c).clone())
            .collect()
    }
}

#[async_trait]
impl ChiffrageService for SecurityServiceImpl {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.encryption_handler.get_publickeys_chiffrage()
    }

    fn entretien_cle_chiffrage(&self) {
        self.encryption_handler.entretien_cle_chiffrage();
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), Error> {
        self.encryption_handler.ajouter_certificat_chiffrage(certificat).map_err(|e| Error::String(e.to_string()))
    }
}

#[async_trait]
impl CertificatService for SecurityServiceImpl {
    async fn emettre_certificat(&self, routage: RoutageMessageAction) -> Result<(), Error> {
        // In a real implementation, this would format a real certificate message.
        // For the PoC, we'll send a dummy JSON to the requested routage.
        let message_json = serde_json::json!({
            "status": "certificat_emitted_dummy"
        });

        self.messaging.transmettre_commande(routage, message_json).await?;
        Ok(())
    }
}
