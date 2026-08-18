use async_trait::async_trait;
use crate::v3::traits::{SecurityService, ChiffrageService};
use crate::error::Error;
use crate::configuration::ConfigMessages;
use std::sync::Arc;
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::ValidateurX509Impl;
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};

pub struct SecurityServiceImpl {
    validator: Arc<ValidateurX509Impl>,
    encryption_handler: CleChiffrageHandlerImpl,
    config: Arc<dyn ConfigMessages>,
}

impl SecurityServiceImpl {
    pub fn new(
        validator: Arc<ValidateurX509Impl>,
        encryption_handler: CleChiffrageHandlerImpl,
        config: Arc<dyn ConfigMessages>,
    ) -> Self {
        Self {
            validator,
            encryption_handler,
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
