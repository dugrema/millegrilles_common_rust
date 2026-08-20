use crate::error::Error as CommonError;
use crate::v3::{MessagingService, PkiService};
use futures::Stream;
use futures::StreamExt;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;

pub struct MessageValidated {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
}

pub struct MessageInboundValidator {
    messaging: Arc<dyn MessagingService>,
    pki: Arc<dyn PkiService>,
}

impl MessageInboundValidator {
    pub fn new(
        messaging: Arc<dyn MessagingService>,
        pki: Arc<dyn PkiService>,
    ) -> Self {
        Self {
            messaging,
            pki,
        }
    }

    /// Converts a Receiver into a Stream of processed messages.
    /// The caller can use `while let Some(result) = stream.next().await` to consume it.
    pub fn consume_named_queue<'a, T>(&'a self, q_name: &str) -> Result<impl Stream<Item = Result<MessageValidated, CommonError>> + 'a, CommonError>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        let rx = self.messaging.take_named_q_rx(q_name)?;

        Ok(ReceiverStream::new(rx).then(move |msg| async move {
            self.process_single_message(msg).await
        }))
    }

    /// Placeholder for the actual processing logic (validation -> decryption -> deserialization).
    async fn process_single_message(&self, msg: MessageMilleGrillesBufferDefault) -> Result<MessageValidated, CommonError>
    {
        let mut message_owned: MessageMilleGrillesOwned = msg.parse_to_owned()?;

        // Internal validation, ensures the hash (id) matches content and the pubkey/id match the signature.
        message_owned.verifier_signature()?;

        // Certificate validation
        let enveloppe = self.pki.validate_message(&message_owned).await?;

        Ok(MessageValidated { message: message_owned, certificate: enveloppe })
    }
}
