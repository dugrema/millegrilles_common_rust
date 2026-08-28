use crate::error::Error as CommonError;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::v3::{FormatService, MessagingService};
use jwt_simple::prelude::Serialize;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesOwned};
use std::sync::Arc;
use crate::v3::impls::rabbitmq_consumer::DeliveryInfo;

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
        -> Result<MessageMilleGrillesOwned, CommonError>
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
        -> Result<Option<MessageMilleGrillesOwned>, CommonError>
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

}
