use crate::certificats::valider_pour_date;
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};
use crate::error::Error;
use crate::v3::traits::{ChiffrageService, PkiService};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::x509_store::{ValidateurX509, ValidateurX509Impl};
use openssl::x509::X509;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use x509_parser::nom::ExtendInto;

// --- Constants ---
pub const CACHE_LIMIT: usize = 50;
pub const CACHE_RESET_INTERVAL_SEC: u64 = 3600 * 3;


// --- Internal Components ---

pub struct SecurityServiceImpl {
    validator: Arc<ValidateurX509Impl>,
    encryption_handler: CleChiffrageHandlerImpl,
    /// Cache for the certificates that are already verified (local CA/current date only)
    cache_verified_pk: Mutex<HashSet<String>>,
}

impl SecurityServiceImpl {
    pub fn new(
        validator: Arc<ValidateurX509Impl>,
        encryption_handler: CleChiffrageHandlerImpl,
    ) -> Self {
        Self {
            validator,
            encryption_handler,
            cache_verified_pk: Mutex::new(HashSet::with_capacity(CACHE_LIMIT)),
        }
    }

    pub async fn run(&self, cancellation_token: CancellationToken) {
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    debug!("SecurityServiceImpl stopping");
                    break;
                }
                _ = async {
                    // Reset cache
                    self.cache_verified_pk.lock().expect("validate_pem Error locking cache").clear();
                    tokio::time::sleep(Duration::from_secs(CACHE_RESET_INTERVAL_SEC)).await;
                } => {}
            }
        }
    }
}

#[async_trait]
impl ValidateurX509 for SecurityServiceImpl {
    fn valider(&self, enveloppe: &EnveloppeCertificat, date: Option<&DateTime<Utc>>) -> Result<(), millegrilles_cryptographie::error::Error> {
        self.validator.valider(enveloppe, date)
    }
}

#[async_trait]
impl PkiService for SecurityServiceImpl {
    fn validate_pem(&self, pem_chain: &str, ca_pem: Option<&str>, date: Option<&DateTime<Utc>>) -> Result<Arc<EnveloppeCertificat>, Error> {
        let mut enveloppe = EnveloppeCertificat::try_from(pem_chain)?;
        if let Some(ca) = ca_pem {
            enveloppe.millegrille = Some(X509::from_pem(ca.as_bytes())?);
        }

        // Cache check when appropriate
        let pk = enveloppe.fingerprint_pk()?;
        if ca_pem.is_none() && date.is_none() && self.cache_verified_pk
            .lock().expect("validate_pem Error locking cache").contains(pk.as_str())
        {
            // Certificate was already checked and is valid, return immediately.
            return Ok(Arc::new(enveloppe))
        }

        // Validate the certificate - throws an Error when invalid.
        self.validator.valider(&enveloppe, date)?;

        if ca_pem.is_none() && date.is_none() {
            // Certificate is valid, cache key
            let mut guard = self.cache_verified_pk.lock().expect("validate_pem Error locking cache");
            if guard.len() >= CACHE_LIMIT {
                // Cleanup all cache, start over
                guard.clear()
            }
            guard.insert(pk);
        }

        Ok(Arc::new(enveloppe))
    }

    async fn validate_message(&self, message: &MessageMilleGrillesOwned) -> Result<Arc<EnveloppeCertificat>, Error> {
        // Internal cryptographic verification of the message must have been done already.
        // This will have checked the id with hash of content and the signature (sig) using pubkey and id.
        if message.contenu_valide != Some((true, true)) {
            return Err(Error::Str("Message internal cryptographic validation must be done before this step"))
        }

        // Retrieve the properly formatted certificate
        let pem_chain = match &message.certificat {
            Some(chain) => {
                let mut chain_string = String::with_capacity(5000);
                for cert in chain {
                    cert.extend_into(&mut chain_string);
                }
                chain_string
            },
            None => return Err(Error::Str("No certificate in message"))
        };

        // Load and validate the certificate - throws an Error when invalid.
        let enveloppe = self.validate_pem(pem_chain.as_str(), None, None)?;

        // Ensure the attached certificate matches the message's pubkey value.
        let fingerprint = enveloppe.fingerprint_pk()?;
        if message.pubkey != fingerprint {
            return Err(Error::Str("Mismatch between certificate and message pubkey"));
        }

        // We checked the certificate for current date - also ensure the message timestamp
        // overlaps the certificate's date range. Throws error if range is wrong.
        valider_pour_date(enveloppe.as_ref(), &message.estampille)?;

        Ok(enveloppe)
    }

    async fn validate_message_ref(&self, message: &MessageMilleGrillesRefDefault) -> Result<Arc<EnveloppeCertificat>, Error> {
        // Internal cryptographic verification of the message must have been done already.
        // This will have checked the id with hash of content and the signature (sig) using pubkey and id.
        if message.contenu_valide != Some((true, true)) {
            return Err(Error::Str("Message internal cryptographic validation must be done before this step"))
        }

        // Retrieve the properly formatted certificate
        let pem_chain = match &message.certificat_escaped {
            Some(chain) => {
                let mut chain_string = String::with_capacity(5000);
                for cert in chain {
                    let certificat: String = serde_json::from_str(format!("\"{}\"", cert).as_str())?;
                    certificat.extend_into(&mut chain_string);
                }
                chain_string
            },
            None => return Err(Error::Str("No certificate in message"))
        };

        // Load and validate the certificate - throws an Error when invalid.
        let enveloppe = self.validate_pem(pem_chain.as_str(), None, None)?;

        // Ensure the attached certificate matches the message's pubkey value.
        let fingerprint = enveloppe.fingerprint_pk()?;
        if message.pubkey != fingerprint {
            return Err(Error::Str("Mismatch between certificate and message pubkey"));
        }

        // We checked the certificate for current date - also ensure the message timestamp
        // overlaps the certificate's date range. Throws error if range is wrong.
        valider_pour_date(enveloppe.as_ref(), &message.estampille)?;

        Ok(enveloppe)
    }

    fn is_cached_pk_valid(&self, public_key: &str) -> bool {
        self.cache_verified_pk.lock().expect("is_cached_pk_valid Error locking HashSet").contains(public_key)
    }
}

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

