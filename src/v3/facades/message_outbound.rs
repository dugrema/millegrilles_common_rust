use crate::chiffrage_cle::CommandeAjouterCleDomaine;
use crate::common_messages::{ReponseRequeteDechiffrageV2, RequeteDechiffrage};
use crate::constantes::{Securite, COMMANDE_AJOUTER_CLE_DOMAINES, DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, PKI_DOMAINE_NOM, PKI_REQUETE_CERTIFICAT};
use crate::error::Error as CommonError;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::v3::impls::rabbitmq_consumer::DeliveryInfo;
use crate::v3::models::{CertificateRequest, DecryptedKey, GeneratedSecretKey, VerifiedResponseMessage};
use crate::v3::{ConfigService, FormatService, MessagingService};
use jwt_simple::prelude::Serialize;
use millegrilles_cryptographie::messages_structs::MessageKind;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::borrow::Cow;
use std::sync::Arc;
use chrono::{Duration, Utc};
use crate::middleware::ReponseEnveloppe;

/// Facade that exposes methods to easily send different types of messages
pub struct MessageOutboundFacade {
    config: Arc<dyn ConfigService>,
    messaging: Arc<dyn MessagingService>,
    format: Arc<dyn FormatService>,
}

impl MessageOutboundFacade {
    pub fn new(
        config: Arc<dyn ConfigService>,
        messaging: Arc<dyn MessagingService>,
        format: Arc<dyn FormatService>,
    ) -> Self {
        Self {
            config,
            messaging,
            format,
        }
    }

    pub async fn wait_ready(&self, timeout: Option<i64>) -> Result<(), CommonError> {
        let expiration = match timeout {
            Some(timeout) => {
                Some(Utc::now() + Duration::milliseconds(timeout))
            },
            None => None
        };
        loop {
            if let Some(expiration) = expiration.as_ref() {
                if expiration < &Utc::now() {
                    return Err(CommonError::Str("Timeout"))
                }
            }
            if self.messaging.is_ready().await? {
                return Ok(());
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn emit_event<R,M>(&self, routing: R, message: M)
        -> Result<(), CommonError>
    where R: Into<RoutageMessageAction>, M: Serialize
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (response, _id) = self.format.build_action_message(
            MessageKind::Evenement, &routing, value)?;
        self.messaging.emit(response, Some(routing)).await
    }

    pub async fn send_request<R,M>(&self, routing: R, message: M)
        -> Result<VerifiedResponseMessage, CommonError>
    where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let mut routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (message, id) = self.format.build_action_message(
            MessageKind::Requete, &routing, value)?;

        if routing.blocking != Some(false) && routing.correlation_id.is_none() {
            // Set message id as correlation_id to allow for a reply
            routing.correlation_id = Some(id)
        }

        self.messaging.send(message, routing).await
    }

    pub async fn send_command<R,M>(&self, routing: R, message: M)
        -> Result<Option<VerifiedResponseMessage>, CommonError>
    where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let mut routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (message, id) = self.format.build_action_message(
            MessageKind::Commande, &routing, value)?;

        // By default, a command is blocking, we use non-blocking when explicitly requested.
        let blocking = routing.blocking != Some(false);

        if blocking {
            if routing.correlation_id.is_none() {
                // Set message id as correlation_id to allow for a reply
                routing.correlation_id = Some(id)
            }
            Ok(Some(self.messaging.send(message, routing).await?))
        } else {
            self.messaging.emit(message, Some(routing)).await?;
            Ok(None)
        }
    }

    pub async fn respond<M>(&self, delivery_info: DeliveryInfo, message: M) -> Result<(), CommonError>
    where M: Serialize + Send + Sync
    {
        // Prepare routing from delivery information
        let correlation_id = match delivery_info.properties.correlation_id() {
            Some(id) => id,
            None => return Err(CommonError::Str("correlation_id missing for response")),
        };
        let reply_to = match delivery_info.properties.reply_to() {
            Some(to) => to,
            None => return Err(CommonError::Str("reply_to missing for response")),
        };
        let routing = RoutageMessageReponse::new(reply_to.as_str(), correlation_id.as_str());

        // Send
        self.respond_routed(routing, message).await
    }

    pub async fn respond_routed<R,M>(&self, routing: R, message: M)
        -> Result<(), CommonError>
    where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (response, _id) = self.format.build_response(value)?;
        self.messaging.respond(response, routing).await
    }

    pub async fn respond_encrypted<M>(
        &self,
        delivery_info: DeliveryInfo,
        message: M,
        certificate: &EnveloppeCertificat
    ) -> Result<(), CommonError> where M: Serialize + Send + Sync {
        // Prepare routing from delivery information
        let correlation_id = match delivery_info.properties.correlation_id() {
            Some(id) => id,
            None => return Err(CommonError::Str("correlation_id missing for response")),
        };
        let reply_to = match delivery_info.properties.reply_to() {
            Some(to) => to,
            None => return Err(CommonError::Str("reply_to missing for response")),
        };
        let routing = RoutageMessageReponse::new(reply_to.as_str(), correlation_id.as_str());

        // Send
        self.respond_routed_encrypted(routing, message, certificate).await
    }

    pub async fn respond_routed_encrypted<R,M>(
        &self,
        routing: R,
        message: M,
        certificate: &EnveloppeCertificat
    ) -> Result<(), CommonError> where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (response, _id) = self.format.build_encrypted_response(value, certificate)?;
        self.messaging.respond(response, routing).await
    }

    pub async fn get_keys(
        &self,
        domain: &str,
        key_ids: Vec<String>,
        include_signature: Option<bool>
    ) -> Result<Vec<DecryptedKey>, CommonError> {
        let request = RequeteDechiffrage {
            domaine: domain.to_string(),
            liste_hachage_bytes: None,
            cle_ids: Some(key_ids),
            certificat_rechiffrage: None,
            inclure_signature: include_signature,
        };

        let routing = RoutageMessageAction::builder(
            DOMAINE_NOM_MAITREDESCLES,
            MAITREDESCLES_REQUETE_DECHIFFRAGE_V2,
            vec![Securite::L3Protege]
        ).build();

        let response = self.send_request(routing, request).await?;
        if response.message.kind == MessageKind::ReponseChiffree {
            // Decrypt the response
            let enveloppe_signature = self.config.get_configuration_pki().get_enveloppe_privee();
            let reponse: ReponseRequeteDechiffrageV2 = response.message.dechiffrer(enveloppe_signature.as_ref())?;
            let keys = if reponse.ok && reponse.cles.is_some() {
                reponse.cles.expect("cles")
            } else {
                return Err(format!("chiffrage_cle.get_cles_rechiffrees_v2 Erreur reponse dechiffrage cles code: {}, err: {:?}", reponse.code, reponse.err))?
            };

            // Convert keys to decrypted keys
            let mut converted_keys: Vec<DecryptedKey> = Vec::with_capacity(keys.len());
            for key in keys.into_iter() {
                converted_keys.push(key.try_into()?);
            }

            Ok(converted_keys)
        } else {
            // This is an error
            let (is_err, e) = response.is_err()?;
            if is_err {
                Err(CommonError::String(format!("Unable to get keys: {:?}", e)))
            } else {
                Err(CommonError::Str("Unable to get keys: Response OK but no keys found"))
            }
        }
    }

    pub async fn save_keys(
        &self,
        keys: &Vec<&GeneratedSecretKey>,
        timeout: Option<u64>,
    ) -> Result<(), CommonError> {
        // Default timeout of 15 seconds
        let timeout = timeout.unwrap_or_else(|| 15_000);

        // Save each key individually
        for key in keys {
            let add_key_command = CommandeAjouterCleDomaine {
                cles: Cow::Borrowed(&key.encrypted_keys),
                signature: Cow::Borrowed(&key.signature)
            };
            let routing = RoutageMessageAction::builder(
                DOMAINE_NOM_MAITREDESCLES,
                COMMANDE_AJOUTER_CLE_DOMAINES,
                vec![Securite::L1Public])
                .timeout_blocking(timeout)
                .build();
            let response = match self.send_command(routing, add_key_command).await? {
                Some(response) => response,
                None => return Err(CommonError::Str("No response received when saving key"))
            };
            if let (true, e) = response.is_err()? {
                return Err(CommonError::String(format!("Error while saving keys: {:?}", e)));
            }
        }

        Ok(())
    }

    pub async fn get_certificate(&self, fingerprint: &str, timeout: Option<u64>) -> Result<Arc<EnveloppeCertificat>, CommonError> {
        let timeout = timeout.unwrap_or_else(|| 15_000);

        let routing = RoutageMessageAction::builder(
            PKI_DOMAINE_NOM,
            PKI_REQUETE_CERTIFICAT,
            vec![Securite::L1Public])
            .timeout_blocking(timeout)
            .build();
        let request = CertificateRequest { fingerprint: fingerprint.to_string() };
        let response = self.send_request(routing, request).await?;
        let certificate_information: ReponseEnveloppe = response.message.deserialize()?;
        let mut enveloppe = EnveloppeCertificat::try_from(
            certificate_information.chaine_pem.join("\n").as_str()
        )?;
        let ca = self.config.get_configuration_pki().get_enveloppe_privee().enveloppe_ca.certificat.clone();
        enveloppe.millegrille = Some(ca);

        Ok(Arc::new(enveloppe))
    }
}
