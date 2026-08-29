use crate::constantes::{SECURITE_1_PUBLIC, Securite};
use crate::error::Error as CommonError;
use crate::rabbitmq_dao::ConfigQueue;
use crate::v3::impls::rabbitmq_connection::RabbitConnectionManager;
use crate::v3::impls::rabbitmq_registry::RabbitQueueRegistry;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicQosOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::{DeliveryTag, FieldTable, ShortString};
use lapin::{BasicProperties, Channel, Consumer, Queue};
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const INTERVALLE_ENTRETIEN_ATTENTE: Duration = Duration::from_millis(1500);
const FLAG_TTL: &str = "x-message-ttl";
const DEFAULT_TTL: u64 = 300_000;

// --- Internal Types ---

struct RabbitMqConsumer {
    channel: Channel,
    queue: Queue,
    consumer: Consumer,
}

#[derive(Clone)]
pub struct DeliveryInfo {
    pub delivery_tag: DeliveryTag,
    pub exchange: ShortString,
    pub routing_key: ShortString,
    pub properties: BasicProperties,
}

#[derive(Clone)]
pub struct InboundMessage {
    pub delivery: DeliveryInfo,
    pub parsed: MessageMilleGrillesOwned,
}

#[derive(Clone)]
pub struct ResponseMessage {
    pub message: MessageMilleGrillesOwned,
    /// Acceptable exchanges for the response certificate
    pub security: Option<Vec<Securite>>,
    /// Acceptable domains for the response certificate
    pub domains: Option<Vec<String>>,
    /// Acceptable roles for the response certificate
    pub roles: Option<Vec<String>>,
}

pub struct ResponseWaiter {
    sender: oneshot::Sender<Result<ResponseMessage, CommonError>>,
    expiration: DateTime<Utc>,

    // Response check options - RabbitMQ response queues are named exclusive queues.
    // Anyone connected to the server can reply on the queue just by knowing the name.
    // The following values allow a check on where the response came from.
    /// Acceptable security levels for the response certificate
    security: Option<Vec<Securite>>,
    /// Acceptable domains for the response certificate
    domains: Option<Vec<String>>,
    /// Acceptable roles for the response certificate
    roles: Option<Vec<String>>,
}

impl ResponseWaiter {
    pub fn new(
        sender: oneshot::Sender<Result<ResponseMessage, CommonError>>,
        expiration: DateTime<Utc>,
        security: Option<Vec<Securite>>,
        domains: Option<Vec<String>>,
        roles: Option<Vec<String>>,
    ) -> Self {
        Self { sender, expiration, security, domains, roles }
    }
}


pub struct RabbitConsumerManager {
    connection: Arc<RabbitConnectionManager>,
    queue_registry: Arc<RabbitQueueRegistry>,
    // notify_queues_changed: Arc<Notify>,
    /// Responses waiting by correlation id
    waiting_responses: Mutex<HashMap<String, ResponseWaiter>>,
}

impl RabbitConsumerManager {
    pub fn new(connection: Arc<RabbitConnectionManager>, queue_registry: Arc<RabbitQueueRegistry>) -> Self {
        Self {
            connection,
            queue_registry,
            // notify_queues_changed: Arc::new(Notify::new()),
            waiting_responses: Mutex::new(HashMap::with_capacity(50)),
        }
    }

    pub fn add_response(&self, correlation_id: String, waiter: ResponseWaiter) -> Result<(), crate::error::Error> {
        let mut guard = self.waiting_responses.lock()
            .expect("RabbitConsumerManager.add_correlation Error locking mutex");
        guard.insert(correlation_id, waiter);
        Ok(())
    }

    pub async fn run(self: Arc<Self>, join_set: &mut JoinSet<()>, cancellation_token: CancellationToken) {
        let self_clone = self.clone();
        self_clone.start_named_queue_threads(join_set, cancellation_token.clone()).await.expect("Error starting queue threads");
        let self_clone = self.clone();
        let cancellation_token_clone = cancellation_token.clone();
        join_set.spawn(async move { self_clone.reply_q_thread(cancellation_token_clone).await });
        let self_clone = self.clone();
        let cancellation_token_clone = cancellation_token.clone();
        join_set.spawn(async move { self_clone.maintenance_thread(cancellation_token_clone).await });
    }

    async fn start_named_queue_threads(self: Arc<Self>, join_set: &mut JoinSet<()>, cancellation_token: CancellationToken) -> Result<(), crate::error::Error> {
        let queue_names = self.queue_registry.get_queue_names();
        for q_name in queue_names {
            let self_clone = self.clone();
            let cancellation_token_clone = cancellation_token.clone();
            join_set.spawn(async move { self_clone.named_queue_thread(q_name, cancellation_token_clone).await });
        }
        Ok(())
    }

    async fn named_queue_thread(self: Arc<Self>, q_name: String, cancellation_token: CancellationToken) -> () {
        // Get queue config and Sender
        let (config, tx) = self.queue_registry
            .get_named_queue(q_name.as_str()).expect("unknown queue name");
        
        loop {
            // RabbitMQ struct holder for this thread
            let mut consumer_holder: Option<RabbitMqConsumer> = None;

            while consumer_holder.is_none() {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        return;
                    }
                    _ = async {
                        match self.connection.get_channel().await {
                            Ok(channel_inner) => {
                                let qos_options_reponses = BasicQosOptions { global: false };
                                if let Err(e) = channel_inner.basic_qos(1, qos_options_reponses).await {
                                    error!("named_queue_consume Error configuring channel for queue {:?}, {:?}", q_name, e);
                                } else {
                                    match create_named_queue(&channel_inner, &config).await {
                                        Ok((q, consumer)) => {
                                            consumer_holder = Some(RabbitMqConsumer { queue: q, channel: channel_inner, consumer });
                                        },
                                        Err(e) => error!("named_queue_thread Error creating reply queue: {:?}", e)
                                    }
                                }
                            },
                            Err(e) => error!("named_queue_thread Error getting channel, will sleep: {}", e)
                        }
                    } => {}
                }
                if consumer_holder.is_none() {
                    tokio::time::sleep(ATTENTE_RECONNEXION).await;
                }
            }
            let mut consumer_holder = consumer_holder.expect("named_queue_thread Error getting consumer struct");

            loop {
                // The select! block ONLY handles the "waiting" for either a signal OR a message.
                let maybe_delivery = tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        consumer_holder.channel.close(200, "Closing").await.ok();
                        debug!("named_queue_thread Consumer {} cancelled, stopping", q_name);
                        return; // Exit loop gracefully
                    }
                    delivery_res = consumer_holder.consumer.next() => {
                        delivery_res // Return the delivery result to the local variable
                    }
                };

                let delivery = match maybe_delivery {
                    Some(Ok(r)) => r,
                    Some(Err(e)) => {
                        error!("named_queue_thread Error message delivery : {:?}", e);
                        break;
                    }
                    None => break,
                };

                let reply_q_name = consumer_holder.queue.name().as_str();
                debug!("named_queue_thread({}): Reception nouveau message {}", reply_q_name, reply_q_name);

                // Take the buffer into MilleGrilles message structure (no parsing yet)
                let message: MessageMilleGrillesBufferDefault = delivery.data.into();

                // Do basic message internal validation for quick rejection (no certificate check)
                // Verify structure
                let message = match message.parse_to_owned() {
                    Ok(mut m) => {
                        // Structure ok, verify signature
                        if let Err(e) = m.verifier_signature() {
                            error!("named_queue_thread Invalid signature in received message : {:?}", e);
                            None
                        } else {
                            // The message has a valid signature
                            Some(m)
                        }
                    }
                    Err(e) => {
                        error!("named_queue_thread Invalid message received : {:?}", e);
                        None
                    }
                };

                if let Some(message) = message {
                    // Send message for further processing
                    let delivery_info = DeliveryInfo {
                        delivery_tag: delivery.delivery_tag.clone(),
                        exchange: delivery.exchange.clone(),
                        routing_key: delivery.routing_key.clone(),
                        properties: delivery.properties.clone(),
                    };
                    let inbound_message = InboundMessage { delivery: delivery_info, parsed: message };

                    if let Err(e) = tx.send(inbound_message).await {
                        error!("named_queue_thread Error message delivery : {:?}", e);
                    }
                }

                // Always send ack
                delivery.acker.ack(BasicAckOptions::default()).await.ok();
            }

            // Exclusive reply queue is lost with the connection being closed
            consumer_holder.channel.close(200, "Closing").await.ok();
            self.queue_registry.set_reply_q_name(None);
        }
    }

    async fn reply_q_thread(self: Arc<Self>, cancellation_token: CancellationToken) -> () {
        loop {
            // RabbitMQ struct holder for this thread
            let mut consumer_holder: Option<RabbitMqConsumer> = None;

            while consumer_holder.is_none() {
                match self.connection.get_channel().await {
                    Ok(channel_inner) => {
                        match create_reply_queue(self.queue_registry.as_ref(), &channel_inner).await {
                            Ok((q, consumer)) => {
                                // Create consumer
                                debug!("task_traitement_reponses consumer pret {}", q.name());
                                consumer_holder = Some(RabbitMqConsumer {queue: q, channel: channel_inner, consumer});
                                break
                            },
                            Err(e) => error!("Error creating reply queue: {:?}", e)
                        }
                    },
                    Err(e) => error!("Error getting channel, will sleep: {}", e)
                }
                tokio::time::sleep(ATTENTE_RECONNEXION).await;
            }
            let mut consumer_holder = consumer_holder.expect("reply_q_thread Error getting consumer struct");

            loop {
                // The select! block ONLY handles the "waiting" for either a signal OR a message.
                let maybe_delivery = tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        consumer_holder.channel.close(200, "Closing").await.ok();
                        debug!("reply_q_thread Consumer cancelled, stopping");
                        return; // Exit loop gracefully
                    }
                    delivery_res = consumer_holder.consumer.next() => {
                        delivery_res // Return the delivery result to the local variable
                    }
                };

                let delivery = match maybe_delivery {
                    Some(Ok(r)) => r,
                    Some(Err(e)) => {
                        error!("reply_q_thread Error message delivery : {:?}", e);
                        break;
                    }
                    None => break,
                };

                // Find correlation for message
                let correlation_id = match delivery.properties.correlation_id() {
                    Some(correlation_id) => correlation_id.to_string(),
                    None => {
                        // No correlation_id at all - ACK and move on
                        debug!("Received uncorrelated message on reply_q, dropping");
                        delivery.acker.ack(BasicAckOptions::default()).await.ok();
                        continue;
                    }
                };

                // Retrieve the response waiter
                let response_waiter = self.waiting_responses
                    .lock().expect("reply_q_thread Error locking waiters")
                    .remove(&correlation_id);

                let response_waiter = match response_waiter {
                    Some(waiter) => waiter,
                    None => {
                        // No matching correlation_id - ACK and move on
                        debug!("Received uncorrelated message on reply_q, dropping: correlation_id = {}", correlation_id);
                        delivery.acker.ack(BasicAckOptions::default()).await.ok();
                        continue;
                    }
                };

                // Something is waiting for this message - continue processing
                // Take the buffer into MilleGrilles message structure (no parsing yet)
                let message: MessageMilleGrillesBufferDefault = delivery.data.into();

                // Do basic message internal validation for quick rejection (no certificate check)
                // let mut valid = false;
                // Verify structure
                // match message.parse() {
                let message: Option<MessageMilleGrillesOwned> = match message.parse_to_owned() {
                    Ok(mut inner) => {
                        // Structure ok, verify signature
                        if let Err(e) = inner.verifier_signature() {
                            error!("reply_q_thread Invalid signature in received message : {:?}", e);
                            None
                        } else {
                            Some(inner)
                        }
                    },
                    Err(e) => {
                        error!("reply_q_thread Invalid message received : {:?}", e);
                        None
                    }
                };

                if let Some(message) = message {
                    let message_id = message.id.clone();

                    let reponse_message = ResponseMessage {
                        message,
                        security: response_waiter.security,
                        domains: response_waiter.domains,
                        roles: response_waiter.roles,
                    };

                    // Send message for further processing
                    if let Err(e) = response_waiter.sender.send(Ok(reponse_message)) {
                        if let Err(e) = e {
                            error!("reply_q_thread Error tx message delivery on correlation id {} : {:?}", message_id, e);
                        } else {
                            error!("Message could not be processed, id: {}", message_id);
                        }
                    }
                } else {
                    if let Err(e) = response_waiter.sender
                        .send(Err(crate::error::Error::Str("The response to this message was invalid (structure/signature)")))
                    {
                        if let Err(e) = e {
                            error!("reply_q_thread Error delivery or invalid message response : {:?}", e);
                        } else {
                            error!("reply_q_thread Error on delivery of response message");
                        }
                    }
                }

                // Always send ack
                delivery.acker.ack(BasicAckOptions::default()).await.ok();
            }

            // Exclusive reply queue is lost with the connection being closed
            consumer_holder.channel.close(200, "Closing").await.ok();
            self.queue_registry.set_reply_q_name(None);
        }
    }

    async fn maintenance_thread(&self, cancellation_token: CancellationToken) {
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    break;
                }
                _ = tokio::time::sleep(INTERVALLE_ENTRETIEN_ATTENTE) => {
                    self.cleanup_waiters();
                }
            }
        }
    }

    fn cleanup_waiters(&self) {
        let date_now = Utc::now();
        let mut expired_senders = Vec::new();

        {
            let mut guard = self.waiting_responses.lock()
                .expect("RabbitConsumerManager.cleanup_waiters Error locking mutex");

            if guard.is_empty() {
                return;
            }

            // Collect keys of expired waiters to avoid borrow checker issues while removing
            let expired_keys: Vec<String> = guard.iter()
                .filter(|(_, attente)| attente.expiration <= date_now)
                .map(|(k, _)| k.clone())
                .collect();

            for key in expired_keys {
                if let Some(waiter) = guard.remove(&key) {
                    expired_senders.push(waiter.sender);
                }
            }
        }

        // Send the error responses after dropping the lock to minimize contention
        for sender in expired_senders {
            let _ = sender.send(Err(crate::error::Error::Str("Timeout")));
        }
    }
}

async fn create_named_queue(channel: &Channel, config: &ConfigQueue) -> Result<(Queue, Consumer), CommonError> {
    let options = QueueDeclareOptions {
        passive: false,
        durable: config.durable,
        exclusive: ! config.durable,
        auto_delete: config.autodelete,
        nowait: false,
    };

    let mut params = FieldTable::default();
    let ttl = config.ttl.unwrap_or_else(|| DEFAULT_TTL as u32);
    params.insert(FLAG_TTL.into(), ttl.into());

    let queue_name = config.nom_queue.as_str();
    let named_queue = channel.queue_declare(queue_name, options, params).await?;
    info!("create_named_queue Created named Q: {}", queue_name);

    for rk in &config.routing_keys {
        let routing_key = rk.routing_key.as_str();
        let exchange = rk.exchange.get_str();
        debug!("named_queue_thread queue_bind rk {} on queue {}, exchange {}", routing_key, queue_name, exchange);
        channel.queue_bind(
            queue_name,
            exchange,
            routing_key,
            QueueBindOptions::default(),
            FieldTable::default()
        ).await?;
    }

    // Create consumer
    let consumer = channel
        .basic_consume(queue_name, "".into(), BasicConsumeOptions::default(), FieldTable::default()).await?;

    Ok((named_queue, consumer))
}

async fn create_reply_queue(queue_registry: &RabbitQueueRegistry, channel: &Channel)
                            -> Result<(Queue, Consumer), CommonError> {
    let options = QueueDeclareOptions {
        passive: false,
        durable: false,
        exclusive: true,
        auto_delete: true,
        nowait: false,
    };

    let mut params = FieldTable::default();
    params.insert(FLAG_TTL.into(), (DEFAULT_TTL as u32).into());

    let reply_queue = channel.queue_declare("", options, params).await?;

    let queue_name = reply_queue.name().as_str();
    info!("create_reply_queue Setting reply Q name: {}", queue_name);
    queue_registry.set_reply_q_name(Some(queue_name.to_owned()));

    let exchanges: Vec<&str> = vec![SECURITE_1_PUBLIC];
    debug!("create_reply_queue Binding on exchanges : {:?}", exchanges);

    let consumer = channel
        .basic_consume(
            queue_name,
            "".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        ).await?;

    Ok((reply_queue, consumer))
}
