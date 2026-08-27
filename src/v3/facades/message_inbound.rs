use crate::error::Error as CommonError;
use crate::v3::{ConfigService, MessagingService, PkiService};
use futures::Stream;
use futures::StreamExt;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use serde_json::Value;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;

pub struct MessageValidated {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
    pub content: Option<Value>,
}

pub struct MessageInboundValidator {
    config: Arc<dyn ConfigService>,
    messaging: Arc<dyn MessagingService>,
    pki: Arc<dyn PkiService>,
}

impl MessageInboundValidator {
    pub fn new(
        config: Arc<dyn ConfigService>,
        messaging: Arc<dyn MessagingService>,
        pki: Arc<dyn PkiService>,
    ) -> Self {
        Self {
            config,
            messaging,
            pki,
        }
    }

    /// Converts a Receiver into a Stream of processed messages.
    /// The caller can use `while let Some(result) = stream.next().await` to consume it.
    pub fn consume_named_queue<'a>(&'a self, q_name: &str) -> Result<impl Stream<Item = Result<MessageValidated, CommonError>> + 'a, CommonError> {
        let rx = self.messaging.take_named_q_rx(q_name)?;

        Ok(ReceiverStream::new(rx).then(move |msg| async move {
            self.process_single_message(msg).await
        }))
    }

    /// Placeholder for the actual processing logic (validation -> decryption -> deserialization).
    async fn process_single_message(&self, mut message: MessageMilleGrillesOwned) -> Result<MessageValidated, CommonError>
    {
        // Internal validation, ensures the hash (id) matches content and the pubkey/id match the signature.
        if message.contenu_valide != Some((true, true)) {
            message.verifier_signature()?;
        }

        // Certificate validation
        let enveloppe = self.pki.validate_message(&message).await?;

        // Decrypt message when appropriate
        let decrypted_value: Option<Value> = match message.dechiffrage.as_ref() {
            Some(_inner) => {
                // Decrypt message when appropriate
                if message.dechiffrage.is_some() {
                    let enveloppe_privee = self.config.get_configuration_pki().get_enveloppe_privee();
                    Some(message.dechiffrer(enveloppe_privee.as_ref())?)
                } else {
                    None
                }
            },
            None => None
        };

        Ok(MessageValidated { message, certificate: enveloppe, content: decrypted_value })
    }
}
