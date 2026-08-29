use crate::constantes::DEFAULT_MESSAGE_TIMEOUT;
use crate::error::Error as CommonError;
use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use crate::v3::impls::rabbitmq_connection::RabbitConnectionManager;
use crate::v3::impls::rabbitmq_consumer::{RabbitConsumerManager, ResponseMessage, ResponseWaiter};
use crate::v3::impls::rabbitmq_registry::RabbitQueueRegistry;
use chrono::Utc;
use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel};
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);


// --- Internal Components ---

struct OutgoingMessage {
    message_kind: MessageKind,
    routing: MessageRoutingEnum,
    message: MessageMilleGrillesBufferDefault,
}

pub struct RabbitMessageDispatcher {
    connection: Arc<RabbitConnectionManager>,
    registry: Arc<RabbitQueueRegistry>,
    consumer: Arc<RabbitConsumerManager>,
    tx_out: Sender<OutgoingMessage>,
    rx_out: Mutex<Option<Receiver<OutgoingMessage>>>,
    // securite: Securite,
}

pub enum MessageRoutingEnum {
    None,
    Action(RoutageMessageAction),
    Response(RoutageMessageReponse),
}

impl RabbitMessageDispatcher {
    pub fn new(connection: Arc<RabbitConnectionManager>, registry: Arc<RabbitQueueRegistry>, consumer: Arc<RabbitConsumerManager>) -> Self {
        let (tx_out, rx_out) = mpsc::channel(5);
        Self {
            connection,
            registry,
            consumer,
            tx_out,
            rx_out: Mutex::new(Some(rx_out)),
        }
    }

    pub async fn send_message(&self, message: MessageMilleGrillesBufferDefault, routing: MessageRoutingEnum)
        -> Result<Option<oneshot::Receiver<Result<ResponseMessage, CommonError>>>, CommonError> {
        let message_kind = {
            let message_ref = message.parse()?;
            message_ref.kind
        };

        // Ensure the proper information for routing is available
        match message_kind {
            MessageKind::Requete | MessageKind::Commande | MessageKind::Evenement => {
                match routing {
                    MessageRoutingEnum::None => {
                        return Err(CommonError::Str("Message types requete, commande and evenement require routing information for the exchanges"))
                    },
                    MessageRoutingEnum::Action(_) => {}
                    MessageRoutingEnum::Response(_) => {}
                }
            }
            _ => ()
        }

        let outgoing_message = OutgoingMessage {
            message_kind,
            routing,
            message
        };
        self.send_out(outgoing_message).await
    }

    async fn send_out(&self, message: OutgoingMessage)
        -> Result<Option<oneshot::Receiver<Result<ResponseMessage, CommonError>>>, CommonError> {
        let (
            correlation_id,
            timeout_blocking,
            domains,
            exchanges
        ) = match &message.routing {
            MessageRoutingEnum::None => {(None, None, None, None)}
            MessageRoutingEnum::Action(r) => {(
                r.correlation_id.clone(),
                r.timeout_blocking.clone(),
                Some(vec![r.domaine.clone()]),
                Some(r.exchanges.clone())
            )}
            MessageRoutingEnum::Response(_) => {(None, None, None, None)}
        };
        let receiver = match correlation_id {
            Some(correlation_id) => {
                // We have a message with correlation, add expiration information
                let timeout_messages = timeout_blocking.unwrap_or_else(|| DEFAULT_MESSAGE_TIMEOUT);
                let expiration = Utc::now() + chrono::Duration::milliseconds(timeout_messages as i64);

                // Create correlation waiter for the response (to be put on the tx)
                let (tx, rx) = oneshot::channel();
                let response_waiter = ResponseWaiter::new(tx, expiration, exchanges, domains, None);
                self.consumer.add_response(correlation_id.to_owned(), response_waiter)?;

                // Return receiver
                Some(rx)
            },
            None => None
        };

        self.tx_out.send(message).await?;

        Ok(receiver)
    }

    pub async fn run(&self, cancellation_token: CancellationToken) {
        // Extract the receiver
        let mut rx = self.rx_out.lock().unwrap().take().unwrap();

        // Channel holder for this thread
        let mut channel: Option<Channel> = None;

        // Loop while the receiver does not return None and cancellation_token is not cancelled.
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    debug!("RabbitMessageDispatcher Stopping");
                    return;
                }
                maybe_message = rx.recv() => {
                    let message = match maybe_message {
                        Some(m) => m,
                        None => break,
                    };

                    // Channel maintenance
                    if let Some(channel_inner) = &channel {
                        if ! channel_inner.status().connected() {
                            channel = None;
                        }
                    }

                    while channel.is_none() {
                        match self.connection.get_channel().await {
                            Ok(channel_inner) => {
                                channel = Some(channel_inner);
                            },
                            Err(e) => {
                                error!("Error getting channel, will sleep: {}", e);
                                tokio::time::sleep(ATTENTE_RECONNEXION).await;
                            },
                        }
                    }

                    let channel_inner = channel.as_ref().expect("Unable to get channel");
                    let reply_q_name = self.registry.get_reply_q_name();
                    if let Err(e) = publish_message(channel_inner, message, reply_q_name).await {
                        error!("Error publishing message: {:?}", e);
                    }
                }
            }
        }
    }
}

async fn publish_message(channel: &Channel, message: OutgoingMessage, reply_q: Option<String>) -> Result<(), CommonError> {
    let options = BasicPublishOptions::default();
    let payload = message.message.buffer;
    let (correlation_id, reply_to) = match &message.routing {
        MessageRoutingEnum::None => {(None, None)}
        MessageRoutingEnum::Action(r) => {(r.correlation_id.clone(), r.reply_to.clone())}
        MessageRoutingEnum::Response(r) => {(Some(r.correlation_id.clone()), Some(r.reply_to.clone()))}
    };

    let (properties, reply_to) = {
        let mut properties = BasicProperties::default();
        if let Some(correlation_id) = correlation_id.clone() {
            properties = properties.with_correlation_id(correlation_id.into());
        }

        let reply_to = match message.message_kind {
            MessageKind::Requete | MessageKind::Commande => {
                let reply_to = match reply_to {
                    Some(reply_to) => reply_to,
                    None => match reply_q {
                        Some(q) => q.to_owned(),
                        None => return Err(CommonError::Str("No reply_q provided for response"))
                    }
                };
                debug!("task_emettre_messages Emission message, reply_q en parametre : {:?}", reply_to);
                properties = properties.with_reply_to(reply_to.as_str().into());

                Some(reply_to)
            },
            MessageKind::Reponse | MessageKind::ReponseChiffree => reply_to,
            _ => None
        };

        (properties, reply_to)
    };

    match message.message_kind {
        MessageKind::Reponse | MessageKind::ReponseChiffree => {
            let reply_to_inner = match reply_to {
                Some(reply_to) => reply_to,
                None => return Err(CommonError::Str("No reply_q provided for response"))
            };
            debug!("publish_message Replying to reply_q {} with correlation_id {:?}", reply_to_inner, correlation_id);

            let resultat = channel.basic_publish(
                "",
                reply_to_inner.as_str(),
                options,
                payload.to_vec().as_slice(),
                properties
            ).await;
            if resultat.is_err() {
                error!("publish_message Error emitting message {:?}", resultat);
                return Err(CommonError::Str("No reply_q provided for response"))
            } else {
                debug!("publish_message Response {:?} to {:?} sent", correlation_id, reply_to_inner);
            }
        },
        MessageKind::Requete | MessageKind::Commande | MessageKind::Evenement => {
            let routing = match message.routing {
                MessageRoutingEnum::Action(r) => r,
                _ => return Err(CommonError::Str("No routing provided for requete/commande/evenement"))
            };
            let routing_key = concatenate_routing_key(message.message_kind, Some(&routing))?;

            for exchange in routing.exchanges {
                let resultat = channel.basic_publish(
                    exchange.get_str(),
                    &routing_key,
                    options,
                    payload.clone().as_slice(),
                    properties.clone()
                ).await;
                match resultat {
                    Ok(_) => debug!("task_emettre_messages Message {}/{:?} emis sur {:?}", routing_key, properties, exchange),
                    Err(e) => error!("task_emettre_messages Erreur emission message {:?}", e)
                }
            }
        }
        _ => return Err(CommonError::String(format!("Kind not supported: {:?}", message.message_kind))),
    }

    Ok(())
}

fn concatenate_routing_key_action_message(kind: &str, routage: &RoutageMessageAction) -> String {
    let mut vec_rk = vec![kind];
    vec_rk.push(routage.domaine.as_str());
    if let Some(partition) = routage.partition.as_ref() {
        vec_rk.push(partition.as_str());
    }
    vec_rk.push(routage.action.as_str());
    vec_rk.join(".")
}

fn concatenate_routing_key(message_kind: MessageKind, routing: Option<&RoutageMessageAction>) -> Result<String, CommonError> {
    let routing = match routing {
        Some(r) => r,
        None => return Err(CommonError::Str("concatenate_routing_key No routing information provided"))
    };
    match message_kind {
        MessageKind::Requete => Ok(concatenate_routing_key_action_message("requete", routing)),
        MessageKind::Commande => Ok(concatenate_routing_key_action_message("commande", routing)),
        MessageKind::Evenement => Ok(concatenate_routing_key_action_message("evenement", routing)),
        MessageKind::Reponse |
        MessageKind::ReponseChiffree |
        MessageKind::Document |
        MessageKind::Transaction |
        MessageKind::TransactionMigree |
        MessageKind::CommandeInterMillegrille => Err(CommonError::Str("Unsupported OutgoingMessage type"))
    }
}
