use crate::error::Error as CommonError;
use crate::v3::{ConfigService, MessagingService, PkiService};
use futures::Stream;
use futures::StreamExt;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use serde_json::Value;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

pub struct MessageValidated {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
    pub content: Option<Value>,
}

pub struct MessageInboundValidator {
    config: Arc<dyn ConfigService>,
    messaging: Arc<dyn MessagingService>,
    pki: Arc<dyn PkiService>,
    shutdown_token: CancellationToken,
}

impl MessageInboundValidator {
    pub fn new(
        config: Arc<dyn ConfigService>,
        messaging: Arc<dyn MessagingService>,
        pki: Arc<dyn PkiService>,
        shutdown_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            messaging,
            pki,
            shutdown_token,
        }
    }

    /// Converts a Receiver into a Stream of processed messages.
    /// The caller can use `while let Some(result) = stream.next().await` to consume it.
    // pub fn consume_named_queue<'a>(&'a self, q_name: &str) -> Result<impl Stream<Item = Result<MessageValidated, CommonError>> + 'a, CommonError> {
    //     let rx = self.messaging.take_named_q_rx(q_name)?;
    //
    //     Ok(ReceiverStream::new(rx).then(move |msg| async move {
    //         self.process_single_message(msg).await
    //     }))
    // }
    pub fn consume_named_queue<'a>(
        &'a self,
        q_name: &str
    ) -> Result<impl Stream<Item = Result<MessageValidated, CommonError>> + 'a, CommonError> {
        let rx = self.messaging.take_named_q_rx(q_name)?;
        let shutdown_token = self.shutdown_token.clone(); // Clone the token for the stream

        let q_name_string = q_name.to_string();
        let shutdown_fut = async move {
            shutdown_token.cancelled().await;
            debug!("named_queue_thread Consumer {} cancelled, stopping", q_name_string);
        };

        Ok(ReceiverStream::new(rx)
            .then(move |msg| async move {
                // This processing is still an 'await' point.
                // If a message is being processed when the token is cancelled,
                // the 'take_until' won't stop THIS specific 'then' future from finishing.
                self.process_single_message(msg).await
            })
            .take_until(shutdown_fut)
        ) // The stream itself terminates here
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
