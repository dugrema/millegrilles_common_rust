use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigurationMq, ConfigurationPki};
use crate::error::Error as CommonError;
use crate::rabbitmq_dao::{ConfigQueue, MessageInterne, MessageOut, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::v3::{ConfigService, MessagingService};
use chrono::{DateTime, Utc};
use lapin::{Channel, Connection, ConnectionProperties, tcp::OwnedIdentity,
            tcp::OwnedTLSConfig,
};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_cryptographie::securite::Securite;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{sync::{Notify, mpsc, oneshot}, task::{self}};
use url::Url;

// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const INTERVALLE_ENTRETIEN_ATTENTE: Duration = Duration::from_millis(400);
const FLAG_TTL: &str = "x-message-ttl";

// --- Internal Types ---

#[derive(Debug)]
struct ResponseWaiter {
    correlation: String,
    sender: oneshot::Sender<TypeMessage>,
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

pub struct RabbitMessageDispatcher {
    tx_out: mpsc::Sender<MessageOut>,
    rx_out: Mutex<Option<mpsc::Receiver<MessageOut>>>,
    tx_reply: mpsc::Sender<MessageInterne>,
    rx_reply: Mutex<Option<mpsc::Receiver<MessageInterne>>>,
    reply_correlation_map: Mutex<HashMap<String, ResponseWaiter>>,
    reply_q: Arc<Mutex<Option<String>>>,
    securite: Securite,
}

impl RabbitMessageDispatcher {
    pub fn new(securite: Securite) -> Self {
        let (tx_out, rx_out) = mpsc::channel(3);
        let (tx_reply, rx_reply) = mpsc::channel(1);
        Self {
            tx_out,
            rx_out: Mutex::new(Some(rx_out)),
            tx_reply,
            rx_reply: Mutex::new(Some(rx_reply)),
            reply_correlation_map: Mutex::new(HashMap::new()),
            reply_q: Arc::new(Mutex::new(None)),
            securite,
        }
    }

    async fn send_out(&self, message: MessageOut) -> Result<Option<oneshot::Receiver<TypeMessage>>, String> {
        let sender = self.tx_out.clone();
        let attente_correlation_id = match &message.type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) => {
                match &r.correlation_id {
                    Some(c) => Some(c.clone()),
                    None => Some(message.message_id.clone())
                }
            }
            TypeMessageOut::Reponse(_) => { None }
            TypeMessageOut::Evenement(_) => { None }
        };

        let attente_expiration = message.attente_expiration.clone();
        match sender.send(message).await {
            Ok(_) => {
                if let Some(expiration) = attente_expiration {
                    if let Some(c) = attente_correlation_id {
                        let (tx, rx) = oneshot::channel();
                        let attente = ResponseWaiter {
                            correlation: c.clone().into(),
                            sender: tx,
                            expiration: expiration.to_owned(),
                        };
                        let mut guard = self.reply_correlation_map.lock().unwrap();
                        guard.insert(c, attente);
                        Ok(Some(rx))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            },
            Err(e) => Err(format!("Erreur send {:?}", e)),
        }
    }

    fn get_reqly_q_name(&self) -> Option<String> {
        self.reply_q.lock().unwrap().clone()
    }

    pub fn spawn_workers(
        self: Arc<Self>,
        connection_manager: Arc<RabbitConnectionManager>,
        messaging_service: Arc<dyn MessagingService>,
    ) {
        // Outbound worker: Sends messages from the dispatcher channel to RabbitMQ
        let dispatcher_out = self.clone();
        let conn_manager_out = connection_manager.clone();
        task::spawn(async move {
            let mut rx = {
                let mut guard = dispatcher_out.rx_out.lock().unwrap();
                guard.take().expect("Dispatcher rx_out not available")
            };

            while let Some(message) = rx.recv().await {
                match conn_manager_out.get_channel().await {
                    Ok(_channel) => {
                        // TODO: Implement actual AMQP publish logic here using the channel
                        info!("Dispatcher task_emettre_messages: processing message");
                        drop(_channel);
                    }
                    Err(e) => {
                        error!("Dispatcher task_emettre_messages Erreur creation channel: {:?}", e);
                    }
                }
            }
        });

        // Inbound worker: Receives replies and handles correlation/interception
        let dispatcher_in = self.clone();

        // Expiration worker: Cleans up expired correlation requests
        let dispatcher_exp = self.clone();
        task::spawn(async move {
            loop {
                tokio::time::sleep(INTERVALLE_ENTRETIEN_ATTENTE).await;
                let mut guard = dispatcher_exp.reply_correlation_map.lock().unwrap();
                if guard.is_empty() {
                    continue;
                }
                let date_now = Utc::now();
                debug!("Attentes de reponse pre-cleanup: {}", guard.len());
                guard.retain(|_, attente| attente.expiration > date_now);
                debug!("Attentes de reponse post-cleanup: {}", guard.len());
            }
        });
    }

}

pub struct RabbitConsumerManager {
    notify_queues_changed: Arc<Notify>,
}

impl RabbitConsumerManager {
    pub fn new() -> Self {
        Self {
            notify_queues_changed: Arc::new(Notify::new()),
        }
    }

    pub async fn run(
        self: Arc<Self>,
        notify: Arc<Notify>,
    ) {
        loop {
            notify.notified().await;
            // In a real implementation, we would manage the lifecycle of consumers here.

            // Old code in rabbitmq_executor: guard.retain(|_, attente| attente.expiration > date_now);

            // For now, we just wait for the next notification.
            tokio::time::sleep(Duration::from_secs(5)).await;
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
        let (tx, rx) = mpsc::channel(3);
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
        let (tx, rx) = mpsc::channel(3);
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
    tx: Sender<MessageMilleGrillesBufferDefault>,
    /// Holds rx until a consumer process takes it
    rx: Mutex<Option<Receiver<MessageMilleGrillesBufferDefault>>>,
}

impl ReplyQueue {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(3);
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
