use crate::error::Error;
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::v3::impls::rabbitmq_internal::{
    RabbitConnectionManager, RabbitConsumerManager, RabbitMessageDispatcher, RabbitQueueRegistry,
};
use crate::v3::traits::MessagingService;
use crate::v3::ConfigService;
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use std::sync::Arc;
use millegrilles_cryptographie::securite::Securite;
use tokio::sync::mpsc::Receiver;
use crate::rabbitmq_dao::ConfigQueue;

pub struct MessagingServiceImpl {
    connection_manager: Arc<RabbitConnectionManager>,
    queue_registry: Arc<RabbitQueueRegistry>,
    consumer_manager: Arc<RabbitConsumerManager>,
    message_dispatcher: RabbitMessageDispatcher,
}

impl MessagingServiceImpl {

    /// Creates a new messaging service.
    /// Note: app_name must either be in the Domaines or Roles of the certificate or the server will reject the connection.
    pub fn new(
        app_name: &str,
        config: Arc<dyn ConfigService>,
    ) -> Self {
        // Extract security level from certificate
        let securite_str = config.get_configuration_pki().get_enveloppe_privee()
            .enveloppe_pub.extensions().expect("MessagingServiceImpl: No extensions found on Certificate")
            .exchanges.expect("MessagingServiceImpl: No exchanges found on certificate")[0].clone();
        let security_level: Securite = securite_str.as_str().try_into().expect("MessagingServiceImpl: Security not supported");

        let connection_manager = Arc::new(RabbitConnectionManager::new(config));
        let queue_registry = Arc::new(RabbitQueueRegistry::new(app_name));
        let consumer_manager = Arc::new(RabbitConsumerManager::new(queue_registry.clone()));
        let message_dispatcher = RabbitMessageDispatcher::new(connection_manager.clone(), queue_registry.clone(), consumer_manager.clone(), security_level);

        Self {
            connection_manager,
            queue_registry,
            consumer_manager,
            message_dispatcher,
        }
    }

    /// Allows dynamically adding a named queue configuration. Does not start processing.
    pub fn add_named_queue(&self, queue: ConfigQueue) -> Result<(), CommonError> {
        self.queue_registry.add_named_queue(queue)
    }

    /// Starts the messaging service background threads including the connection to the server.
    pub async fn start(&self) {
        self.connection_manager.connecter().await.ok();
        todo!("Rewrite without middleware: Arc<M>, rabbitmq: RabbitMqExecutor")
        // self.message_dispatcher.spawn_workers(rabbitmq.clone());
        // In a real implementation, we'd also spawn the consumer manager's worker here
    }
}

#[async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn emit(&self, message: MessageMilleGrillesBufferDefault, routing: Option<RoutageMessageAction>) -> Result<(), Error> {
        if let Some(_rx) = self.message_dispatcher.send_message(message, routing).await? {
            return Err(CommonError::Str("MessagingServiceImpl Unexpected waiter produced on emit message"))
        }
        Ok(())
    }

    async fn send(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageAction) -> Result<MessageMilleGrillesBufferDefault, Error> {
        match self.message_dispatcher.send_message(message, Some(routing)).await? {
            Some(rx) => {
                let val = rx.await
                    .map_err(|e| CommonError::String(format!("MessagingServiceImpl Waiting for response: {:?}", e)))?;
                val
            },
            None => Err(CommonError::Str("No message waiter was generated"))
        }
    }

    fn get_reply_q_name(&self) -> Option<String> {
        self.queue_registry.get_reply_q_name()
    }

    fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<MessageMilleGrillesBufferDefault>, CommonError> {
        self.queue_registry.take_named_q_rx(q_name)
    }

    fn take_trigger_q_rx(&self) -> Result<Receiver<MessageMilleGrillesBufferDefault>, CommonError> {
        self.queue_registry.take_trigger_rx()
    }

    fn is_paused(&self) -> bool {
        todo!()
    }

    async fn wait_for_resume(&self, timeout: Option<u32>) -> Result<(), Error> {
        todo!()
    }
}
