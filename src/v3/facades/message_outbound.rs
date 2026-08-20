use crate::generateur_messages::RoutageMessageAction;
use crate::v3::{FormatService, MessagingService};
use jwt_simple::prelude::Serialize;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use std::sync::Arc;
use crate::error::Error;

/// Facade that exposes methods to easily send different types of messages
pub struct MessageOutboundFacade {
    messaging: Arc<dyn MessagingService>,
    format: Arc<dyn FormatService>,
}

impl MessageOutboundFacade {
    pub fn new(
        messaging: Arc<dyn MessagingService>,
        format: Arc<dyn FormatService>,
    ) -> Self {
        Self {
            messaging,
            format,
        }
    }

    pub async fn emit_event<R,M>(&self, routing: R, message: M)
        -> Result<(), Error>
    where R: Into<RoutageMessageAction>, M: Serialize
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (response, _id) = self.format.build_action_message(
            MessageKind::Evenement, &routing, value)?;
        self.messaging.emit(response, Some(routing)).await
    }

    pub async fn send_request<R,M>(&self, routing: R, message: M)
        -> Result<MessageMilleGrillesBufferDefault, crate::error::Error>
    where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (message, _id) = self.format.build_action_message(
            MessageKind::Requete, &routing, value)?;
        self.messaging.send(message, routing).await
    }

    pub async fn send_command<R,M>(&self, routing: R, message: M)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
    where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (message, _id) = self.format.build_action_message(
            MessageKind::Commande, &routing, value)?;

        // By default, a command is blocking, we use non-blocking when explicitly requested.
        let blocking = routing.blocking != Some(false);

        if blocking {
            Ok(Some(self.messaging.send(message, routing).await?))
        } else {
            self.messaging.emit(message, Some(routing)).await?;
            Ok(None)
        }
    }

    pub async fn respond<R,M>(&self, routing: R, message: M)
        -> Result<(), crate::error::Error>
    where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let routing = routing.into();
        let value = serde_json::to_value(message)?;
        let (response, _id) = self.format.build_response(value)?;
        self.messaging.emit(response, Some(routing)).await
    }

}
