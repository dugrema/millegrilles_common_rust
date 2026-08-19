use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigurationMq, ConfigurationPki};
use crate::error::Error as CommonError;
use crate::rabbitmq_dao::{ConfigQueue, MessageInterne, MessageOut, TypeMessageOut};
use crate::v3::{ConfigService, MessagingService};
use chrono::{DateTime, Utc};
use lapin::{tcp::OwnedIdentity, tcp::OwnedTLSConfig, BasicProperties, Channel, Connection, ConnectionProperties};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::securite::Securite;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use lapin::options::BasicPublishOptions;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{sync::{Notify, mpsc, oneshot}, task::{self}};
use url::Url;
use crate::constantes::DEFAULT_MESSAGE_TIMEOUT;
use crate::generateur_messages::RoutageMessageAction;
use crate::recepteur_messages::TypeMessage;
// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const INTERVALLE_ENTRETIEN_ATTENTE: Duration = Duration::from_millis(1500);
const FLAG_TTL: &str = "x-message-ttl";

// --- Internal Types ---

#[derive(Debug)]
struct ResponseWaiter {
    correlation: String,
    sender: oneshot::Sender<Result<MessageMilleGrillesBufferDefault, CommonError>>,
    expiration: DateTime<Utc>,
}

// --- Internal Components ---

pub struct RabbitConnectionManager {
    connexion: Mutex<Option<Arc<Connection>>>,
    notify_connexion_ready: Arc<Notify>,
    config: Arc<dyn ConfigService>,
}

impl RabbitConnectionManager {
    pub fn new(config: Arc<dyn ConfigService>) -> Self {
        Self {
            connexion: Mutex::new(None),
            notify_connexion_ready: Arc::new(Notify::new()),
            config,
        }
    }

    pub async fn connecter(&self) -> Result<Arc<Connection>, Box<dyn StdError>> {
        let config_mq = self.config.get_configuration_mq();
        let idmg = self.config.get_configuration_pki().get_validateur().idmg().to_owned();
        let addr = format!(
            "amqps://{}:{}/{}?auth_mechanism=external",
            config_mq.host,
            config_mq.port,
            idmg
        );

        let tls_config = self.get_tls_config();
        let resultat = Connection::connect_with_config(&addr, ConnectionProperties::default(), tls_config).await;
        if let Ok(c) = resultat {
            let conn = Arc::new(c);
            let mut guard = self.connexion.lock().unwrap();
            *guard = Some(conn.clone());

            let attente = match emettre_certificat_compte_internal(self.config.get_configuration_mq(), self.config.get_configuration_pki()).await {
                Ok(()) => true,
                Err(e) => {
                    error!("Erreur creation compte MQ: {:?}", e);
                    false
                }
            };

            if attente {
                tokio::time::sleep(ATTENTE_RECONNEXION).await;
            }

            Ok(conn)
        } else {
            Err(format!("Erreur de connexion MQ après tentative: {:?}", resultat).into())
        }
    }

    fn get_tls_config(&self) -> OwnedTLSConfig {
        let mq_config = self.config.get_configuration_mq();

        let cert_chain = self.config.get_configuration_pki().get_validateur().ca_pem().to_owned();
        let der = mq_config.p12_keycert.clone();
        let password = mq_config.p12_password.clone();

        OwnedTLSConfig {
            identity: Some(OwnedIdentity {
                der,
                password,
            }),
            cert_chain: Some(cert_chain),
        }
    }

    async fn get_channel(&self) -> Result<Channel, String> {
        let connexion = self.get_connexion().await.ok_or_else(|| "Aucune connexion établie".to_string())?;
        connexion.create_channel().await.map_err(|e| format!("Erreur création channel: {:?}", e))
    }

    async fn get_connexion(&self) -> Option<Arc<Connection>> {
        let guard = self.connexion.lock().unwrap();
        guard.clone()
    }

    fn notify_ready(&self) {
        self.notify_connexion_ready.notify_waiters();
    }

    async fn wait_for_ready(&self) {
        self.notify_connexion_ready.notified().await;
    }

    fn cleanup(&self) {
        let mut guard = self.connexion.lock().unwrap();
        *guard = None;
    }
}

async fn emettre_certificat_compte_internal(
    mq: &ConfigurationMq,
    pki: &ConfigurationPki,
) -> Result<(), Box<dyn StdError>> {
    const MTLS_PORT: u16 = 444;
    const COMMANDE: &str = "administration/ajouterCompte";

    let mut hosts = Vec::new();
    hosts.push(Url::parse("https://midcompte:2444")?);
    hosts.push(Url::parse(format!("https://{}:{}", mq.host, MTLS_PORT).as_str())?);
    hosts.push(Url::parse(format!("https://nginx:{}", MTLS_PORT).as_str())?);

    debug!("Tenter creer compte MQ avec hosts {:?}", hosts);

    let enveloppe = pki.get_enveloppe_privee().clone();
    let ca_cert_pem = enveloppe.ca_pem.as_str();
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;

    for host in hosts {
        debug!("Creation compte MQ avec host : {}", host);

        let pem_cert = enveloppe.chaine_pem.join("\n");
        let pem_cle = enveloppe.cle_privee_pem.as_str();
        let clecert_pem = format!("{}\n{}", pem_cle, pem_cert);
        let identity = reqwest::Identity::from_pem(clecert_pem.as_bytes())?;

        let client = reqwest::Client::builder()
            .add_root_certificate(root_ca.clone())
            .identity(identity)
            .https_only(true)
            .use_rustls_tls()
            .timeout(core::time::Duration::new(5, 0))
            .danger_accept_invalid_certs(true)
            .build()?;

        let url = format!("{}{}", host, COMMANDE);
        info!("Utiliser URL de creation de compte MQ : {:?}", url);
        match client.post(url).send().await {
            Ok(r) => {
                let status_code = r.status().as_u16();
                if r.status().is_success() {
                    if status_code == 201 {
                        debug!("emettre_certificat_compte Reponse OK : {:?}", r);
                        return Ok(())
                    } else {
                        info!("Compte cree (reponse {}), on poursuit", status_code);
                    }
                }
                warn!("emettre_certificat_compte Response creation compte MQ status {:?} error : {:?}", r.status(), r);
            },
            Err(e) => {
                warn!("emettre_certificat_compte Response creation compte MQ error : {:?}", e);
            }
        }
    }

    Err("Echec creation de compte avec certificat sur MQ".into())
}

struct OutgoingMessage {
    message_kind: MessageKind,
    routing: Option<RoutageMessageAction>,
    message: MessageMilleGrillesBufferDefault,
}

pub struct RabbitMessageDispatcher {
    connection: Arc<RabbitConnectionManager>,
    registry: Arc<RabbitQueueRegistry>,
    consumer: Arc<RabbitConsumerManager>,
    tx_out: Sender<OutgoingMessage>,
    rx_out: Mutex<Option<Receiver<OutgoingMessage>>>,
    securite: Securite,
}

impl RabbitMessageDispatcher {
    pub fn new(connection: Arc<RabbitConnectionManager>, registry: Arc<RabbitQueueRegistry>, consumer: Arc<RabbitConsumerManager>, securite: Securite) -> Self {
        let (tx_out, rx_out) = mpsc::channel(5);
        Self {
            connection,
            registry,
            consumer,
            tx_out,
            rx_out: Mutex::new(Some(rx_out)),
            securite,
        }
    }

    pub async fn send_message(&self, message: MessageMilleGrillesBufferDefault, routing: Option<RoutageMessageAction>) -> Result<Option<oneshot::Receiver<Result<MessageMilleGrillesBufferDefault, CommonError>>>, CommonError> {
        let message_kind = {
            let message_ref = message.parse()?;
            message_ref.kind
        };

        // Ensure the proper information for routing is available
        match message_kind {
            MessageKind::Requete | MessageKind::Commande | MessageKind::Evenement => {
                if routing.is_none() {
                    return Err(CommonError::Str("Message types requete, commande and evenement require routing information for the exchanges"))
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
        -> Result<Option<oneshot::Receiver<Result<MessageMilleGrillesBufferDefault, CommonError>>>, CommonError> {
        let (correlation_id, timeout_blocking) = match message.routing.as_ref() {
            Some(r) => (r.correlation_id.as_ref(), r.timeout_blocking.clone()),
            None => (None, None)
        };
        let receiver = match correlation_id {
            Some(correlation_id) => {
                // We have a message with correlation, add expiration information
                let timeout_messages = timeout_blocking.unwrap_or_else(|| DEFAULT_MESSAGE_TIMEOUT);
                let expiration = Utc::now() + chrono::Duration::milliseconds(timeout_messages as i64);

                // Create correlation waiter for the response (to be put on the tx)
                let (tx, rx) = oneshot::channel();
                let response_waiter = ResponseWaiter {
                    correlation: correlation_id.clone().into(),
                    sender: tx,
                    expiration,
                };
                self.consumer.add_response(correlation_id.to_owned(), response_waiter)?;

                // Return receiver
                Some(rx)
            },
            None => None
        };

        self.tx_out.send(message).await?;

        Ok(receiver)
    }

    pub async fn run(&self) {
        // Extract the receiver
        let mut rx = self.rx_out.lock().unwrap().take().unwrap();

        // Channel holder for this thread
        let mut channel: Option<Channel> = None;

        loop {
            let message = match rx.recv().await {
                Some(message) => message,
                None => return  // Stopping
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
                        if channel_inner.status().connected() {
                            channel = Some(channel_inner);
                        }
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

async fn publish_message(channel: &Channel, message: OutgoingMessage, reply_q: Option<String>) -> Result<(), CommonError> {
    let options = BasicPublishOptions::default();
    let payload = message.message.buffer;
    let (correlation_id, reply_to) = match message.routing.as_ref() {
        Some(r) => (r.correlation_id.clone(), r.reply_to.clone()),
        None => (None, None)
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
            let routing_key = concatenate_routing_key(message.message_kind, message.routing.as_ref())?;
            let routing = match message.routing {
                Some(r) => r,
                None => return Err(CommonError::Str("No routing provided for requete/commande/evenement"))
            };

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

pub struct RabbitConsumerManager {
    queue_registry: Arc<RabbitQueueRegistry>,
    notify_queues_changed: Arc<Notify>,
    /// Responses waiting by correlation id
    waiting_responses: Mutex<HashMap<String, ResponseWaiter>>,
}

impl RabbitConsumerManager {
    pub fn new(queue_registry: Arc<RabbitQueueRegistry>) -> Self {
        Self {
            queue_registry,
            notify_queues_changed: Arc::new(Notify::new()),
            waiting_responses: Mutex::new(HashMap::with_capacity(50)),
        }
    }

    fn add_response(&self, correlation_id: String, waiter: ResponseWaiter) -> Result<(), CommonError> {
        let mut guard = self.waiting_responses.lock()
            .expect("RabbitConsumerManager.add_correlation Error locking mutex");
        guard.insert(correlation_id, waiter);
        Ok(())
    }

    async fn run(&self) {
        loop {
            self.cleanup_waiters();
            // For now, we just wait for the next notification.
            tokio::time::sleep(INTERVALLE_ENTRETIEN_ATTENTE).await;
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
            let _ = sender.send(Err(CommonError::Str("Timeout")));
        }
    }
}

/// Named queue for the registry
struct NamedQueue {
    queue: ConfigQueue,
    tx: Sender<MessageMilleGrillesBufferDefault>,
    /// Holds rx until a consumer process takes it
    rx: Option<Receiver<MessageMilleGrillesBufferDefault>>,
}

impl NamedQueue {
    fn new(config: ConfigQueue) -> Self {
        let (tx, rx) = mpsc::channel(1);
        Self {
            queue: config,
            tx,
            rx: Some(rx),
        }
    }
}

/// Single hard-coded queue (by domain name). Receives standard MilleGrille triggers, can be
/// consumed by application when applicable (optional).
struct TriggerQueue {
    q_name: String,
    tx: Sender<MessageMilleGrillesBufferDefault>,
    /// Holds rx until a consumer process takes it
    rx: Mutex<Option<Receiver<MessageMilleGrillesBufferDefault>>>,
}

impl TriggerQueue {
    fn new(app_name: &str) -> Self {
        let q_name = format!("{}/triggers", app_name);
        let (tx, rx) = mpsc::channel(5);
        Self {
            q_name,
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }
}

/// Internal queue, correlation is done with the messages that used send().
struct ReplyQueue {
    /// The reply_q name is re-generated on each connection
    q_name: Mutex<Option<String>>,
    tx: Sender<Result<MessageMilleGrillesBufferDefault, CommonError>>,
    /// Holds rx until a consumer process takes it
    rx: Mutex<Option<Receiver<Result<MessageMilleGrillesBufferDefault, CommonError>>>>,
}

impl ReplyQueue {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(2);
        Self {
            q_name: Mutex::new(None),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }
}

pub struct RabbitQueueRegistry {
    named_queues: Mutex<HashMap<String, NamedQueue>>,
    triggers: TriggerQueue,
    reply_queue: ReplyQueue,
}

impl RabbitQueueRegistry {
    pub fn new(app_name: &str) -> Self {
        Self {
            named_queues: Mutex::new(HashMap::new()),
            triggers: TriggerQueue::new(app_name),
            reply_queue: ReplyQueue::new(),
        }
    }

    pub fn add_named_queue(&self, config: ConfigQueue) -> Result<(), CommonError> {
        let queue = NamedQueue::new(config);
        let q_name = queue.queue.nom_queue.clone();

        let mut guard = self.named_queues.lock()
            .expect("RabbitQueueRegistry.add_named_queue Lock failed");
        if guard.contains_key(q_name.as_str()) {
            return Err(CommonError::String(format!("RabbitQueueRegistry.add_named_queue Name {} already exists", q_name)));
        }
        guard.insert(q_name, queue);
        Ok(())
    }

    fn set_reply_q_name(&self, q_name: Option<String>) {
        let mut guard = self.reply_queue.q_name.lock()
            .expect("RabbitQueueRegistry.get_reply_q_name Lock failed");
        *guard = q_name;
    }

    pub fn get_reply_q_name(&self) -> Option<String> {
        self.reply_queue.q_name.lock().expect("RabbitQueueRegistry.get_reply_q_name Lock failed").clone()
    }

    pub fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<MessageMilleGrillesBufferDefault>, CommonError> {
        let mut guard = self.named_queues.lock()
            .expect("RabbitQueueRegistry.add_named_queue Lock failed");

        let mut named_queue = match guard.get_mut(q_name) {
            Some(named_queue) => named_queue,
            None => {
                return Err(CommonError::String(format!("RabbitQueueRegistry.take_named_q_rx Name {} unknown", q_name)));
            }
        };

        match named_queue.rx.take() {
            Some(rx) => Ok(rx),
            None => Err(CommonError::String(format!("RabbitQueueRegistry.take_named_q_rx Receiver for name {} already taken", q_name)))
        }
    }

    pub fn take_trigger_rx(&self) -> Result<Receiver<MessageMilleGrillesBufferDefault>, CommonError> {
        let mut guard = self.triggers.rx.lock()
            .expect("RabbitQueueRegistry.take_trigger_rx Lock failed");
        match guard.take() {
            Some(rx) => Ok(rx),
            None => Err(CommonError::Str("RabbitQueueRegistry.take_named_q_rx Trigger receiver already taken"))
        }
    }
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
