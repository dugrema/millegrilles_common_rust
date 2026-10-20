use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use jwt_simple::prelude::Serialize;
use millegrilles_cryptographie::chiffrage::CleSecreteMgs4;
use millegrilles_cryptographie::chiffrage_cles::Cipher;
use millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher};
use crate::error::Error as CommonError;
use serde::de::DeserializeOwned;
use crate::v3::{ChiffrageService, DocumentEncryptionService};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::GeneratedSecretKey;

const MAX_KEYS_CACHE: usize = 30;

pub struct DocumentEncryptionServiceImpl {
    domain: String,
    chiffrage: Arc<dyn ChiffrageService>,
    outbound: Arc<MessageOutboundFacade>,
    /// Encryption key for the current session, created lazily
    encryption_key: Mutex<Option<GeneratedSecretKey>>,
    /// Cache of keys used to decrypt content previously generated. Key is the key_id.
    key_cache: Mutex<HashMap<String, CleSecreteMgs4>>,
}

impl DocumentEncryptionServiceImpl {
    pub fn new(chiffrage: Arc<dyn ChiffrageService>, outbound: Arc<MessageOutboundFacade>, domain_name: &str) -> Self {
        Self {
            domain: domain_name.into(),
            chiffrage,
            outbound,
            encryption_key: Mutex::new(None),
            key_cache: Mutex::new(HashMap::with_capacity(MAX_KEYS_CACHE)),
        }
    }

    async fn get_key(&self) -> Result<GeneratedSecretKey, crate::error::Error> {
        {
            let guard = self.encryption_key.lock().expect("Lock poisoned");
            if let Some(guard) = guard.as_ref() {
                return Ok(guard.clone())
            }
        }

        // Generate new key
        let key = self.chiffrage.generate_new_key(&vec![self.domain.clone()]).await?;
        self.outbound.save_keys(&vec![&key], Some(5_000)).await?;

        // Keep new key in memory and return
        {
            let mut guard = self.encryption_key.lock().expect("Lock poisoned");
            *guard = Some(key.clone());
        }
        {
            let cle_mgs4: CleSecreteMgs4 = key.secret_key.secret.clone();
            let key_id = key.key_id.clone();
            let mut guard = self.key_cache.lock().expect("Lock poisoned");
            guard.insert(key_id, cle_mgs4);
        }

        Ok(key)
    }

    async fn get_key_by_id(&self, key_id: &str) -> Result<CleSecreteMgs4, crate::error::Error> {
        {
            let guard = self.key_cache.lock().expect("Lock poisoned");
            if let Some(key) = guard.get(key_id) {
                return Ok(key.clone())
            }
        }

        // Attempt to fetch key from keymaster
        let mut result = self.outbound.get_keys(self.domain.as_str(), vec![key_id.to_string()], None).await?;
        if result.is_empty() {
            return Err(crate::error::Error::Str("Key not found"))
        }

        // We are only expecting 1 key
        let secret = result.remove(0);
        let cle_mgs4: CleSecreteMgs4 = secret.secret;

        // Save key in memory
        let mut guard = self.key_cache.lock().expect("Lock poisoned");
        // Simple cleanup to avoid getting too many keys in memory
        if guard.len() > MAX_KEYS_CACHE {
            guard.clear();
        }
        guard.insert(key_id.to_string(), cle_mgs4.clone());

        Ok(cle_mgs4)
    }
}

#[async_trait]
impl DocumentEncryptionService for DocumentEncryptionServiceImpl {
    async fn encrypt<S>(&self, value: &S) -> Result<EncryptedDocument, CommonError> where S: Serialize + Sync {
        let secret_key = self.get_key().await?;
        let value = serde_json::to_vec(value)?;
        let cipher = CipherMgs4::with_secret(CleSecreteCipher::CleSecrete(secret_key.secret_key.secret))?;
        let encrypted_value = cipher.to_vec(&value)?;
        let mut encrypted_document = EncryptedDocument::try_from(encrypted_value)?;

        // Set key_id to allow decryption in the future.
        encrypted_document.cle_id = Some(secret_key.key_id);

        // Remove values saved elsewhere or not needed
        encrypted_document.cle = None;
        encrypted_document.verification = None;  // Not used

        Ok(encrypted_document)
    }

    async fn decrypt<D>(
        &self,
        value: &EncryptedDocument
    ) -> Result<D, CommonError> where D: DeserializeOwned {
        let key_id = match value.cle_id.as_ref() {
            Some(key_id) => key_id,
            None => return Err(crate::error::Error::Str("Key id not provided"))
        };
        let key = self.get_key_by_id(key_id.as_str()).await?;
        let decrypted_content = value.clone().decrypt_with_secret(&key)?;

        // Deserialize to format requested by caller
        Ok(serde_json::from_slice(decrypted_content.as_slice())?)
    }
}
