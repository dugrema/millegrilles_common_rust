use crate::configuration::{ConfigurationMq, ConfigurationPki, ConfigMessages};
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::rabbitmq_dao::{MessageInterne, MessageOut, TypeMessageOut, NamedQueue, QueueType, ConfigRoutingExchange, ConfigQueue, ReplyQueue};
use crate::recepteur_messages::{intercepter_message, traiter_delivery, TypeMessage};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lapin::{
    message::Delivery,
    options::*,
    protocol::{AMQPErrorKind, AMQPSoftError},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties, Queue, tcp::OwnedIdentity,
    tcp::OwnedTLSConfig,
};
use log::{debug, error, info, log_enabled, trace, warn};
use millegrilles_cryptographie::securite::Securite;
use millegrilles_cryptographie::x509::EnveloppePrivee;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{sync::{mpsc, Notify, oneshot}, task::{self, JoinHandle}};
use tokio_stream::StreamExt;
use url::Url;
use crate::certificats::ValidateurX509;
use crate::v3::ConfigService;
// --- Constants ---

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const INTERVALLE_ENTRETIEN_ATTENTE: Duration = Duration::from_millis(400);
const FLAG_TTL: &str = "x-message-ttl";

// --- Internal Types ---

#[derive(Debug)]
pub struct AttenteReponse {
    pub correlation: String,
    pub sender: oneshot::Sender<TypeMessage>,
    pub expiration: DateTime<Utc>,
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

    pub async fn get_channel(&self) -> Result<Channel, String> {
        let connexion = self.get_connexion().await.ok_or_else(|| "Aucune connexion établie".to_string())?;
        connexion.create_channel().await.map_err(|e| format!("Erreur création channel: {:?}", e))
    }

    pub async fn get_connexion(&self) -> Option<Arc<Connection>> {
        let guard = self.connexion.lock().unwrap();
        guard.clone()
    }

    pub fn notify_ready(&self) {
        self.notify_connexion_ready.notify_waiters();
    }

    pub async fn wait_for_ready(&self) {
        self.notify_connexion_ready.notified().await;
    }

    pub fn cleanup(&self) {
        let mut guard = self.connexion.lock().unwrap();
        *guard = None;
    }
}

async fn emettre_certificat_compte_internal(
    mq: &crate::configuration::ConfigurationMq,
    pki: &crate::configuration::ConfigurationPki,
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
    pub tx_out: mpsc::Sender<MessageOut>,
    pub rx_out: Mutex<Option<mpsc::Receiver<MessageOut>>>,
    pub tx_reply: mpsc::Sender<MessageInterne>,
    pub rx_reply: Mutex<Option<mpsc::Receiver<MessageInterne>>>,
    pub map_attente: Mutex<HashMap<String, AttenteReponse>>,
    pub reply_q: Arc<Mutex<Option<String>>>,
    pub securite: Securite,
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
            map_attente: Mutex::new(HashMap::new()),
            reply_q: Arc::new(Mutex::new(None)),
            securite,
        }
    }

    pub async fn send_out(&self, message: MessageOut) -> Result<Option<oneshot::Receiver<TypeMessage>>, String> {
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
                        let attente = AttenteReponse {
                            correlation: c.clone().into(),
                            sender: tx,
                            expiration: expiration.to_owned(),
                        };
                        let mut guard = self.map_attente.lock().unwrap();
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

    pub fn get_reqly_q_name(&self) -> Option<String> {
        self.reply_q.lock().unwrap().clone()
    }

    pub fn spawn_workers(&self) {
        todo!("Rewrite without rabbitmq: RabbitMqExecutor")

        // let rabbitmq_out = rabbitmq.clone();
        // let tx_reply = self.tx_reply.clone();
        // task::spawn(async move {
        //     let mut rx = {
        //         let mut guard = rabbitmq_out.rx_out.lock().unwrap();
        //         match guard.take() {
        //             Some(rx) => rx,
        //             None => panic!("RabbitMessageDispatcher rx_out not available")
        //         }
        //     };
        //
        //     loop {
        //         if let Some(message) = rx.recv().await {
        //             let channel = match rabbitmq_out.create_channel().await {
        //                 Ok(c) => c,
        //                 Err(e) => {
        //                     error!("Dispatcher task_emettre_messages Erreur creation channel: {:?}", e);
        //                     continue;
        //                 }
        //             };
        //
        //             info!("Dispatcher task_emettre_messages: processing message");
        //             drop(channel);
        //         } else {
        //             break;
        //         }
        //     }
        // });
        //
        // let rabbitmq_reply = rabbitmq.clone();
        // let mut futures = FuturesUnordered::new();
        // futures.push(task::spawn(thread_traiter_reply_q(rabbitmq_reply.clone(), rabbitmq.clone())));
        // futures.push(task::spawn(thread_entretien_attente(rabbitmq.clone())));
    }
}

pub struct RabbitConsumerManager {
    pub notify_queues_changed: Arc<Notify>,
}

impl RabbitConsumerManager {
    pub fn new() -> Self {
        Self {
            notify_queues_changed: Arc::new(Notify::new()),
        }
    }

    pub async fn run(&self) {
        todo!("Rewrite without middleware: Arc<M>, rabbitmq: RabbitMqExecutor")

        // let mut futures = FuturesUnordered::new();
        // loop {
        //     {
        //         let named_queues = rabbitmq.as_ref().named_queues.lock().expect("lock");
        //         for (_, named_queue) in named_queues.iter() {
        //             if ! named_queue.is_running() {
        //                 if let Ok(f_nq) = named_queue.get_futures(middleware.clone(), rabbitmq.clone()) {
        //                     futures.extend(f_nq);
        //                 }
        //             }
        //         }
        //     }
        //
        //     futures.push(task::spawn(notify_wait_thread(rabbitmq.clone())));
        //
        //     if let Some(result) = futures.next().await {
        //         if let Err(e) = result {
        //             error!("Error in named queue consumer task: {:?}", e);
        //         }
        //     }
        // }
    }
}

pub struct RabbitQueueRegistry {
    // Placeholder
}

impl RabbitQueueRegistry {
    pub fn new() -> Self {
        Self {}
    }
}

// --- Utility Functions (from RabbitMqExecutor) ---

pub async fn notify_wait_thread(notify: Arc<Notify>) {
    let notify = notify.clone();
    notify.notified().await;
}

async fn thread_traiter_reply_q() {
    todo!("Rewrite without middleware: Arc<M>, rabbitmq: RabbitMqExecutor")

    // let mut rx = {
    //     let mut guard = rabbitmq.rx_reply.lock().expect("lock");
    //     match guard.take() {
    //         Some(rx) => rx,
    //         None => panic!("thread_traiter_reply_q rx reply non disponible")
    //     }
    // };
    //
    // while let Some(message) = rx.recv().await {
    //     let resultat = match message {
    //         MessageInterne::Delivery(delivery, _routing) => {
    //             let nom_queue = match rabbitmq.reply_q.lock().expect("lock").clone() {
    //                 Some(q) => q,
    //                 None => "_reply".into()
    //             };
    //             match traiter_delivery(
    //                 middleware.as_ref(),
    //                 nom_queue.as_str(),
    //                 delivery
    //             ).await {
    //                 Ok(m) => m,
    //                 Err(e) => {
    //                     error!("thread_traiter_reply_q Erreur traitement message : {:?}", e);
    //                     None
    //                 }
    //             }
    //         },
    //         _ => {
    //             debug!("thread_traiter_reply_q Type de message non-supporte, on l'ignore");
    //             None
    //         }
    //     };
    //
    //     if let Some(message_traite) = resultat {
    //         let attente_reponse = match &message_traite {
    //             TypeMessage::Valide(message) => {
    //                 match &message.type_message {
    //                     TypeMessageOut::Reponse(r) => {
    //                         let correlation_id = r.correlation_id.as_str();
    //                         let mut guard = rabbitmq.map_attente.lock().expect("lock");
    //                         if let Some(attente_reponse) = guard.remove(correlation_id) {
    //                             debug!("thread_traiter_reply_q Reponse pour correlation_id {} recue, traiter", correlation_id);
    //                             Some(attente_reponse)
    //                         } else {
    //                             info!("thread_traiter_reply_q Message recu sans attente sur correlation_id {}, skip", correlation_id);
    //                             None
    //                         }
    //                     },
    //                     _ => None
    //                 }
    //             },
    //             _ => None
    //         };
    //
    //         match attente_reponse {
    //             Some(a) => {
    //                 debug!("thread_traiter_reply_q Traiter reponse correlation_id: {}", a.correlation);
    //                 if let Err(e) = a.sender.send(message_traite) {
    //                     error!("thread_traiter_reply_q Erreur transmission reponse attente correlation {} : {:?}", a.correlation, e);
    //                 }
    //             },
    //             None => {
    //                 if intercepter_message(middleware.as_ref(), &message_traite).await == false {
    //                     info!("Message sur reply_q sans attente et non intercepte, on skip");
    //                 }
    //             }
    //         }
    //     }
    // }
    //
    // info!("thread_consumer_reply_queue Fin thread");
}

async fn thread_entretien_attente() {
    todo!("Rewrite without rabbitmq: RabbitMqExecutor")
    // loop {
    //     tokio::time::sleep(INTERVALLE_ENTRETIEN_ATTENTE).await;
    //     let mut guard = rabbitmq.map_attente.lock().expect("lock");
    //     if guard.is_empty() {
    //         continue;
    //     }
    //     let date_now = Utc::now();
    //     debug!("Attentes de reponse pre-cleanup: {}", guard.len());
    //     guard.retain(|_, attente| attente.expiration > date_now);
    //     debug!("Attentes de reponse post-cleanup: {}", guard.len());
    // }
}
