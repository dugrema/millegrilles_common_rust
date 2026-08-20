use crate::error::Error;
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::rabbitmq_dao::ConfigQueue;
use crate::v3::ConfigService;
use crate::v3::impls::rabbitmq_connection::RabbitConnectionManager;
use crate::v3::impls::rabbitmq_consumer::RabbitConsumerManager;
use crate::v3::impls::rabbitmq_dispatcher::RabbitMessageDispatcher;
use crate::v3::impls::rabbitmq_registry::RabbitQueueRegistry;
use crate::v3::traits::MessagingService;
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;

pub struct MessagingServiceImpl {
    connection_manager: Arc<RabbitConnectionManager>,
    queue_registry: Arc<RabbitQueueRegistry>,
    consumer_manager: Arc<RabbitConsumerManager>,
    message_dispatcher: Arc<RabbitMessageDispatcher>,
}

impl MessagingServiceImpl {

    /// Creates a new messaging service.
    /// Note: app_name must either be in the Domaines or Roles of the certificate or the server will reject the connection.
    pub fn new(
        config: Arc<dyn ConfigService>,
    ) -> Self {
        let connection_manager = Arc::new(RabbitConnectionManager::new(config));
        let queue_registry = Arc::new(RabbitQueueRegistry::new());
        let consumer_manager = Arc::new(RabbitConsumerManager::new(connection_manager.clone(), queue_registry.clone()));
        let message_dispatcher = Arc::new(RabbitMessageDispatcher::new(connection_manager.clone(), queue_registry.clone(), consumer_manager.clone()));

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
    pub async fn run(&self) {
        // Connect synchronously, the application should fail fast if a working connection cannot be made.
        self.connection_manager.connect().await.expect("Error connection to RabbitMQ server");

        // Start all other threads
        let connection_clone = self.connection_manager.clone();
        tokio::spawn(async move { connection_clone.run().await });
        let consumer_clone = self.consumer_manager.clone();
        tokio::spawn(async move { consumer_clone.run().await });
        let dispatcher_clone = self.message_dispatcher.clone();
        tokio::spawn(async move { dispatcher_clone.run().await });
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

    fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<MessageMilleGrillesBufferDefault>, CommonError> {
        self.queue_registry.take_named_q_rx(q_name)
    }
}
