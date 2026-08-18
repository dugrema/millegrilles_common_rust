use crate::error::Error;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::rabbitmq_dao::{MessageOut, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::v3::{ConfigService, FormatService};
use crate::v3::impls::rabbitmq_internal::{
    RabbitConnectionManager, RabbitConsumerManager, RabbitMessageDispatcher, RabbitQueueRegistry,
};
use crate::v3::traits::MessagingService;
use async_trait::async_trait;
use millegrilles_cryptographie::securite::Securite;
use serde_json::Value;
use std::sync::Arc;
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;

pub struct MessagingServiceImpl {
    connection_manager: RabbitConnectionManager,
    message_dispatcher: RabbitMessageDispatcher,
    consumer_manager: RabbitConsumerManager,
    queue_registry: RabbitQueueRegistry,
}

impl MessagingServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        securite: Securite,
    ) -> Self {
        let connection_manager = RabbitConnectionManager::new(config);
        let message_dispatcher = RabbitMessageDispatcher::new(securite);
        let consumer_manager = RabbitConsumerManager::new();
        let queue_registry = RabbitQueueRegistry::new();

        Self {
            connection_manager,
            message_dispatcher,
            consumer_manager,
            queue_registry,
        }
    }

    pub async fn init(&self) {
        self.connection_manager.connecter().await.ok();
        todo!("Rewrite without middleware: Arc<M>, rabbitmq: RabbitMqExecutor")
        // self.message_dispatcher.spawn_workers(rabbitmq.clone());
        // In a real implementation, we'd also spawn the consumer manager's worker here
    }
}

impl FormatService for MessagingServiceImpl {
    fn build_response(&self, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_encrypted_response(&self, message: Value, certificat_demandeur: &EnveloppeCertificat) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_encrypted_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }
}

#[async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn emit_event(&self, routage: RoutageMessageAction, value: Value) -> Result<(), Error> {
        let (message, _id) = self.build_action_message(MessageKind::Evenement, routage.clone(), value)?;
        let message = MessageOut {
            message_id: uuid::Uuid::new_v4().to_string(),
            type_message: TypeMessageOut::Evenement(routage),
            message,
            attente_expiration: None,
        };
        self.message_dispatcher.send_out(message).await.map_err(|e| Error::from(e))?;
        Ok(())
    }

    async fn send_request(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
        let (message, _id) = self.build_action_message(MessageKind::Requete, routage.clone(), value)?;
        let message = MessageOut {
            message_id: uuid::Uuid::new_v4().to_string(),
            type_message: TypeMessageOut::Requete(routage),
            message,
            attente_expiration: Some(chrono::Utc::now() + chrono::Duration::seconds(30)),
        };
        match self.message_dispatcher.send_out(message).await? {
            Some(rx) => Ok(Some(rx.await.map_err(|e| Error::from(e.to_string()))?)),
            None => Ok(None),
        }
    }

    // async fn send_transaction(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
    //     let message = MessageOut {
    //         message_id: uuid::Uuid::new_v4().to_string(),
    //         type_message: TypeMessageOut::Transaction(routage),
    //         message: value,
    //         attente_expiration: Some(chrono::Utc::now() + chrono::Duration::seconds(30)),
    //     };
    //     match self.message_dispatcher.send_out(message).await? {
    //         Some(rx) => Ok(Some(rx.await.map_err(|e| Error::from(e.to_string()))?)),
    //         None => Ok(None),
    //     }
    // }

    async fn send_command(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
        let (message, _id) = self.build_action_message(MessageKind::Commande, routage.clone(), value)?;
        let message = MessageOut {
            message_id: uuid::Uuid::new_v4().to_string(),
            type_message: TypeMessageOut::Commande(routage),
            message,
            attente_expiration: Some(chrono::Utc::now() + chrono::Duration::seconds(30)),
        };
        match self.message_dispatcher.send_out(message).await? {
            Some(rx) => Ok(Some(rx.await.map_err(|e| Error::from(e.to_string()))?)),
            None => Ok(None),
        }
    }

    async fn respond(&self, routage: RoutageMessageReponse, value: Value) -> Result<(), Error> {
        let (message, _id) = self.build_response(value)?;
        let message = MessageOut {
            message_id: uuid::Uuid::new_v4().to_string(),
            type_message: TypeMessageOut::Reponse(routage),
            message,
            attente_expiration: None,
        };
        self.message_dispatcher.send_out(message).await.map_err(|e| Error::from(e))?;
        Ok(())
    }

    async fn emit_message(&self, type_message: TypeMessageOut, value: MessageMilleGrillesBufferDefault) -> Result<Option<TypeMessage>, Error> {
        let message = MessageOut {
            message_id: uuid::Uuid::new_v4().to_string(),
            type_message,
            message: value,
            attente_expiration: None,
        };
        match self.message_dispatcher.send_out(message).await? {
            Some(rx) => Ok(Some(rx.await.map_err(|e| Error::from(e.to_string()))?)),
            None => Ok(None),
        }
    }

    fn mq_available(&self) -> bool {
        // In a real implementation, this would check the connection manager's state
        true
    }

    fn set_regeneration(&self) {
        // Implementation would depend on the rest of the system
    }

    fn reset_regeneration(&self) {
        // Implementation would depend on the rest of the system
    }

    fn get_regeneration_mode(&self) -> bool {
        false
    }

    fn get_security(&self) -> &Securite {
        &self.message_dispatcher.securite
    }

    fn is_dev(&self) -> bool {
        false
    }
}
