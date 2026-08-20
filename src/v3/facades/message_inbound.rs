use crate::error::Error;
use std::sync::Arc;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use tokio::sync::mpsc::Receiver;
use crate::v3::MessagingService;

pub struct MessageInboundValidator {
    messaging: Arc<dyn MessagingService>,
}

impl MessageInboundValidator {
    pub fn new(
        messaging: Arc<dyn MessagingService>,
    ) -> Self {
        Self {
            messaging,
        }
    }

    pub async fn recv_validate(&self, queue_name: &str) -> Result<(), Error> {
        let mut rx = self.messaging.take_named_q_rx(queue_name)?;

        while let message = rx.recv().await {
            // Validate message

            // Send out the result to caller ...
        }

        todo!()
    }
}
