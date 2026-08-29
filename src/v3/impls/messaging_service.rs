use crate::certificats::VerificateurPermissions;
use crate::error::Error as CommonError;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::rabbitmq_dao::ConfigQueue;
use crate::v3::impls::rabbitmq_connection::RabbitConnectionManager;
use crate::v3::impls::rabbitmq_consumer::{InboundMessage, RabbitConsumerManager};
use crate::v3::impls::rabbitmq_dispatcher::{MessageRoutingEnum, RabbitMessageDispatcher};
use crate::v3::impls::rabbitmq_registry::RabbitQueueRegistry;
use crate::v3::models::VerifiedResponseMessage;
use crate::v3::traits::MessagingService;
use crate::v3::{ConfigService, PkiService};
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub struct MessagingServiceImpl {
    connection_manager: Arc<RabbitConnectionManager>,
    queue_registry: Arc<RabbitQueueRegistry>,
    consumer_manager: Arc<RabbitConsumerManager>,
    message_dispatcher: Arc<RabbitMessageDispatcher>,
    pki: Arc<dyn PkiService>,
}

impl MessagingServiceImpl {

    /// Creates a new messaging service.
    /// Note: app_name must either be in the Domaines or Roles of the certificate or the server will reject the connection.
    pub fn new(
        config: Arc<dyn ConfigService>,
        pki: Arc<dyn PkiService>,
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
            pki,
        }
    }

    /// Allows dynamically adding a named queue configuration. Does not start processing.
    pub fn add_named_queue(&self, queue: ConfigQueue) -> Result<(), CommonError> {
        self.queue_registry.add_named_queue(queue)
    }

    /// Starts the messaging service background threads including the connection to the server.
    /// Returns when all threads have been started
    pub async fn start(&self, join_set: &mut JoinSet<()>, cancellation_token: CancellationToken) -> Result<(), CommonError> {
        // Connect synchronously, the application should fail fast if a working connection cannot be made.
        self.connection_manager.connect().await?;

        // Start all other threads
        let connection_clone = self.connection_manager.clone();
        let token_clone = cancellation_token.clone();
        join_set.spawn(async move { connection_clone.run(token_clone).await });
        
        let consumer_clone = self.consumer_manager.clone();
        consumer_clone.run(join_set, cancellation_token.clone()).await;
        
        let dispatcher_clone = self.message_dispatcher.clone();
        let token_clone = cancellation_token.clone();
        join_set.spawn(async move { dispatcher_clone.run(token_clone).await });

        Ok(())
    }
}

#[async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn emit(&self, message: MessageMilleGrillesBufferDefault, routing: Option<RoutageMessageAction>) -> Result<(), CommonError> {
        let routing = match routing {
            Some(r) => MessageRoutingEnum::Action(r),
            None => MessageRoutingEnum::None,
        };
        if let Some(_rx) = self.message_dispatcher.send_message(message, routing).await? {
            return Err(CommonError::Str("MessagingServiceImpl Unexpected waiter produced on emit message"))
        }
        Ok(())
    }

    async fn send(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageAction) -> Result<VerifiedResponseMessage, CommonError> {
        // Check requirements to produce a waiter
        if routing.blocking == Some(false) || routing.correlation_id.is_none() {
            return Err(CommonError::Str("MessagingService.send Unable to wait for reply, needs a correlation_id and blocking != false"));
        }

        let routing = MessageRoutingEnum::Action(routing);
        match self.message_dispatcher.send_message(message, routing).await? {
            Some(rx) => {
                match rx.await {
                    Ok(Ok(response)) => {
                        // Validate response certificate and apply validation rules
                        let certificate = self.pki.validate_message(&response.message).await?;

                        // Apply validation rules for certificate response
                        if let Some(security) = response.security {
                            if ! certificate.verifier_exchanges(security)? {
                                return Err(CommonError::Str("MessagingServiceImpl Invalid response security (exchanges)"))
                            }
                        }

                        if let Some(domains) = response.domains {
                            if ! certificate.verifier_domaines(domains)? {
                                return Err(CommonError::Str("MessagingServiceImpl Invalid response domains"))
                            }
                        }

                        if let Some(roles) = response.roles {
                            if ! certificate.verifier_roles_string(roles)? {
                                return Err(CommonError::Str("MessagingServiceImpl Invalid response roles"))
                            }
                        }

                        Ok(VerifiedResponseMessage { message: response.message, certificate })
                    }
                    Ok(Err(e)) => Err(CommonError::String(format!("MessagingServiceImpl Error response received : {:?}", e))),
                    Err(e) => Err(CommonError::String(format!("MessagingServiceImpl Error when receiving responses : {:?}", e)))
                }
            },
            None => Err(CommonError::Str("No message waiter was generated"))
        }
    }

    async fn respond(&self, message: MessageMilleGrillesBufferDefault, routing: RoutageMessageReponse) -> Result<(), CommonError> {
        let routing = MessageRoutingEnum::Response(routing);
        if let Some(_rx) = self.message_dispatcher.send_message(message, routing).await? {
            return Err(CommonError::Str("MessagingServiceImpl Unexpected waiter produced on respond to message"))
        }
        Ok(())
    }

    fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<InboundMessage>, CommonError> {
        self.queue_registry.take_named_q_rx(q_name)
    }
}

