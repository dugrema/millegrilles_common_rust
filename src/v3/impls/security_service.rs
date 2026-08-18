use async_trait::async_trait;
use crate::v3::traits::{PkiService, ChiffrageService};
use crate::error::Error;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::{ValidateurX509, ValidateurX509Impl};
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};

pub struct SecurityServiceImpl {
    validator: Arc<ValidateurX509Impl>,
    encryption_handler: CleChiffrageHandlerImpl,
}

impl SecurityServiceImpl {
    pub fn new(
        validator: Arc<ValidateurX509Impl>,
        encryption_handler: CleChiffrageHandlerImpl,
    ) -> Self {
        Self {
            validator,
            encryption_handler,
        }
    }
}

#[async_trait]
impl ValidateurX509 for SecurityServiceImpl {
    fn valider(&self, enveloppe: &EnveloppeCertificat, date: Option<&DateTime<Utc>>) -> Result<(), millegrilles_cryptographie::error::Error> {
        todo!()
    }
}

#[async_trait]
impl PkiService for SecurityServiceImpl {}

#[async_trait]
impl ChiffrageService for SecurityServiceImpl {
    fn get_encryption_publickeys(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.encryption_handler.get_publickeys_chiffrage()
    }

    fn encryption_key_maintenance(&self) {
        self.encryption_handler.entretien_cle_chiffrage();
    }

    fn add_encryption_publickey(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), Error> {
        self.encryption_handler.ajouter_certificat_chiffrage(certificat).map_err(|e| Error::String(e.to_string()))
    }
}
