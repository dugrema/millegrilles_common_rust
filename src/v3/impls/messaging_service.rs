use crate::error::Error;
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

pub struct MessagingServiceImpl {
    connection_manager: RabbitConnectionManager,
    message_dispatcher: RabbitMessageDispatcher,
    consumer_manager: RabbitConsumerManager,
    queue_registry: RabbitQueueRegistry,
}

impl MessagingServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
    ) -> Self {
        // Extract security level from certificate
        let securite_str = config.get_configuration_pki().get_enveloppe_privee()
            .enveloppe_pub.extensions().expect("MessagingServiceImpl: No extensions found on Certificate")
            .exchanges.expect("MessagingServiceImpl: No exchanges found on certificate")[0].clone();
        let security_level: Securite = securite_str.as_str().try_into().expect("MessagingServiceImpl: Security not supported");

        let connection_manager = RabbitConnectionManager::new(config);
        let message_dispatcher = RabbitMessageDispatcher::new(security_level);
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

#[async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn emit(&self, message: MessageMilleGrillesBufferDefault, routage: Option<RoutageMessageAction>) -> Result<(), Error> {
        todo!()
    }

    async fn send(&self, message: MessageMilleGrillesBufferDefault, routage: Option<RoutageMessageAction>) -> Result<MessageMilleGrillesBufferDefault, Error> {
        todo!()
    }

    async fn take_named_q_rx(&self, q_name: &str) -> Receiver<MessageMilleGrillesBufferDefault> {
        todo!()
    }

    async fn take_trigger_q_rx(&self, trigger_name: &str) -> Receiver<MessageMilleGrillesBufferDefault> {
        todo!()
    }

    fn is_paused(&self) -> bool {
        todo!()
    }

    async fn wait_for_resume(&self, timeout: Option<u32>) -> Result<(), Error> {
        todo!()
    }
}
