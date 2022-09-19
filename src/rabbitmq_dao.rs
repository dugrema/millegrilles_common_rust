use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, options::*, Queue, tcp::{OwnedIdentity, OwnedTLSConfig}, types::FieldTable};
use lapin::message::Delivery;
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
use log::{debug, error, info, warn};
use tokio::task;
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}, Notify, oneshot::Sender as SenderOneshot};
use tokio::task::JoinHandle;
use tokio_amqp::*;
use tokio_stream::StreamExt;

use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigMessages, ConfigurationMq, ConfigurationPki};
use crate::constantes::*;
use crate::formatteur_messages::MessageSerialise;
use crate::formatteur_messages::MessageMilleGrille;
use crate::recepteur_messages::TypeMessage;

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const FLAG_TTL: &str = "x-message-ttl";

// pub struct RabbitMq {
//     pub connexion: Connection,
// }
// impl RabbitMq {
// }

#[derive(Clone, Debug)]
pub struct ConfigRoutingExchange {
    pub routing_key: String,
    pub exchange: Securite,
}

#[derive(Clone, Debug)]
pub struct ConfigQueue {
    pub nom_queue: String,
    pub routing_keys: Vec<ConfigRoutingExchange>,
    pub ttl: Option<u32>,
    pub durable: bool,
}

#[derive(Clone, Debug)]
pub struct ReplyQueue {
    pub fingerprint_certificat: String,
    pub securite: Securite,
    pub ttl: Option<u32>,
    pub reply_q_name: Arc<Mutex<Option<String>>>,
}

#[derive(Clone, Debug)]
pub enum QueueType {
    ExchangeQueue(ConfigQueue),
    ReplyQueue(ReplyQueue),
    Triggers(String, Securite),
}

// pub async fn initialiser(configuration: &impl ConfigMessages) -> Result<RabbitMq, lapin::Error> {
//
//     let connexion = connecter(configuration).await?;
//
//     Ok(RabbitMq{
//         connexion,
//     })
// }

pub async fn connecter<C>(configuration: &C) -> Result<Connection, lapin::Error>
    where C: ConfigMessages
{
    let pki = configuration.get_configuration_pki();
    let mq = configuration.get_configuration_mq();

    let tls_config = get_tls_config(pki, mq);
    let idmg = pki.get_validateur().idmg().to_owned();
    let addr = format!("amqps://{}:{}/{}?auth_mechanism=external", mq.host, mq.port, idmg);

    {
        let resultat = Connection::connect_with_config(
            &addr,
            ConnectionProperties::default().with_tokio(),
            tls_config.as_ref(),
        ).await;

        if let Ok(c) = resultat {
            return Ok(c)
        } else {
            match &resultat {
                Ok(_) => panic!("resultat"),  // Ne doit pas arriver
                Err(e) => {
                    info!("Erreur de connexion MQ : {:?}", e);
                    // Tenter de determiner le type d'erreur, voir si on doit creer le compte usager
                    match e {
                        lapin::Error::ProtocolError(e) => {
                            match e.kind() {
                                AMQPErrorKind::Soft(s) => {
                                    match s {
                                        AMQPSoftError::ACCESSREFUSED => {
                                            info!("MQ Erreur access refused, emettre certificat vers monitor");
                                        },
                                        _ => {
                                            error!("rabbitmq_dao.connecter AMQPSoftError {:?}", resultat);
                                            resultat?;
                                        }  // Erreur non geree
                                    }
                                },
                                _ => {
                                    error!("rabbitmq_dao.connecter ProtocolError {:?}", resultat);
                                    resultat?;
                                }  // Erreur non geree
                            }
                        },
                        _ => {
                            error!("rabbitmq_dao.connecter Erreur generique {:?}", resultat);
                            resultat?;
                        }  // Erreur non geree
                    }
                }
            };
        }
    }

    let attente = match emettre_certificat_compte(configuration).await {
        Ok(()) => true,
        Err(e) => {
            error!("Erreur creation compte MQ: {:?}", e);
            false
        }
    };

    if attente {
        // Attendre 5 secondes et reessayer la connexion
        tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
    }

    // Reessayer la connexion (meme si erreur - regenerer l'erreur d'auth)
    Connection::connect_with_config(
        &addr,
        ConnectionProperties::default().with_tokio(),
        tls_config.as_ref(),
    ).await
}

async fn emettre_certificat_compte<C>(configuration: &C) -> Result<(), Box<dyn Error>>
    where C: ConfigMessages
{
    const PORT: u16 = 444;
    const COMMANDE: &str = "administration/ajouterCompte";

    let config_mq = configuration.get_configuration_mq();
    let hosts = vec!["nginx", config_mq.host.as_str()];
    debug!("Tenter creer compte MQ avec hosts {:?}", hosts);

    let config_pki = configuration.get_configuration_pki();
    // let certfile = config_pki.certfile.as_path();

    // Preparer certificat pour auth SSL
    let enveloppe = config_pki.get_enveloppe_privee().clone();
    let ca_cert_pem = enveloppe.chaine_pem().last().expect("last").as_str();
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;

    // Essayer d'emettre le certificat vers les hosts, en ordre
    for host in hosts {
        debug!("Creation compte MQ avec host : {}", host);

        let identity = reqwest::Identity::from_pem(enveloppe.clecert_pem.as_bytes())?;

        let client = reqwest::Client::builder()
            .add_root_certificate(root_ca.clone())
            .identity(identity)
            .https_only(true)
            .use_rustls_tls()
            .timeout(core::time::Duration::new(5, 0))

            // Accepter serveur sans certs/mauvais hosts - on s'inscrit avec cle publique, c'est safe
            .danger_accept_invalid_certs(true)
            //.danger_accept_invalid_hostnames(true)

            .build()?;

        let url = format!("https://{}:{}/{}", host, PORT, COMMANDE);
        info!("Utiliser URL de creation de compte MQ : {:?}", url);
        match client.post(url).send().await {
            Ok(r) => {
                if r.status().is_success() {
                    debug!("emettre_certificat_compte Reponse OK : {:?}", r);
                    return Ok(())
                }
                warn!("emettre_certificat_compte Response creation compte MQ status error : {:?}", r);
            },
            Err(e) => {
                warn!("emettre_certificat_compte Response creation compte MQ error : {:?}", e);
            }
        };
    }

    Err("Echec creation de compte avec certificat sur MQ")?
}

fn get_tls_config(pki: &ConfigurationPki, mq: &ConfigurationMq) -> OwnedTLSConfig {
    let cert_chain: String = pki.get_validateur().ca_pem().to_owned();

    let der: &Vec<u8> = &mq.p12_keycert;
    let password: &String = &mq.p12_password;

    OwnedTLSConfig {
        identity: Some(OwnedIdentity {der: der.to_owned(), password: password.to_owned()}),
        cert_chain: Some(cert_chain.to_owned()),
    }
}

// pub fn executer_mq<'a>(
//     configuration: Arc<impl ConfigMessages + 'static>,
//     queues: Option<Vec<QueueType>>,
//     listeners: Option<Mutex<Callback<'static, EventMq>>>,
//     securite: Securite
// ) -> Result<RabbitMqExecutorConfig, String> {
//
//     // Creer le channel utilise pour recevoir et traiter les messages mis sur les Q
//     let (tx_traiter_message, rx_traiter_message) = mpsc::channel(1);
//     let (tx_traiter_reply, rx_traiter_reply) = mpsc::channel(1);
//     let (tx_traiter_trigger, rx_traiter_trigger) = mpsc::channel(1);
//
//     // Preparer recepteur de tx_message_out pour emettre des messages vers MQ (cree dans la boucle)
//     let tx_message_out = Arc::new(Mutex::new(None));
//
//     let reply_q =  Arc::new(Mutex::new(None));
//
//     // let boucle_execution = tokio::spawn(
//     //     boucle_execution(
//     //         configuration,
//     //         queues,
//     //         tx_traiter_message.clone(),
//     //         tx_traiter_reply.clone(),
//     //         tx_traiter_trigger.clone(),
//     //         tx_message_out.clone(),
//     //         listeners,
//     //         reply_q.clone(),
//     //         securite.clone(),
//     //     )
//     // );
//
//     let executor = RabbitMqExecutor {
//         tx_out: tx_message_out.clone(),
//         tx_reply: tx_traiter_reply.clone(),
//         reply_q,
//         securite: securite.clone()
//     };
//
//     let mut rx_named_queues = HashMap::new();
//     // todo Configuration Queues deja fournies
//
//     let rx_queues = RabbitMqExecutorRx {
//         rx_messages: rx_traiter_message,
//         rx_reply: rx_traiter_reply,
//         rx_triggers: rx_traiter_trigger,
//     };
//
//     Ok(RabbitMqExecutorConfig {
//         executor,
//         rx_queues,
//         securite: securite.clone(),
//         rx_named_queues: Mutex::new(rx_named_queues),
//     })
// }

#[async_trait]
pub trait MqMessageSendInformation {
    async fn send_out(&self, message: MessageOut) -> Result<(), String>;
    fn get_reqly_q_name(&self) -> Option<String>;
}

// pub struct RabbitMqExecutorConfig {
//     pub executor: RabbitMqExecutor,
//     pub securite: Securite,
// }

pub struct RabbitMqExecutor {
    connexion: Mutex<Option<Arc<Connection>>>,
    named_queues: Mutex<HashMap<String, NamedQueue>>,
    notify_queues_changed: Arc<Notify>,
    pub reply_q: Arc<Mutex<Option<String>>>,
    pub securite: Securite,

    // TX
    pub tx_out: Sender<MessageOut>,
    pub tx_reply: Sender<MessageInterne>,
    pub tx_trigger: Sender<MessageInterne>,

    // RX holder
    rx_out: Mutex<Option<Receiver<MessageOut>>>,
    rx_reply: Mutex<Option<Receiver<MessageInterne>>>,
    rx_trigger: Mutex<Option<Receiver<MessageInterne>>>,
}

impl RabbitMqExecutor {

    pub fn new(securite: Option<Securite>) -> Self {

        // Creer channels communication mpsc
        let (tx_out, rx_out) = mpsc::channel(3);
        let (tx_reply, rx_reply) = mpsc::channel(1);
        let (tx_trigger, rx_trigger) = mpsc::channel(1);

        // Securite default = 1.public
        let securite = match securite {
            Some(s) => s,
            None => Securite::L1Public
        };

        Self {
            connexion: Mutex::new(None),
            named_queues: Mutex::new(Default::default()),
            notify_queues_changed: Default::default(),
            reply_q: Arc::new(Mutex::new(None)),
            securite,

            // TX
            tx_out,
            tx_reply,
            tx_trigger,

            // RX
            rx_out: Mutex::new(Some(rx_out)),
            rx_reply: Mutex::new(Some(rx_reply)),
            rx_trigger: Mutex::new(Some(rx_trigger)),
        }
    }

    pub async fn create_channel(&self) -> Result<Channel, String> {
        // Get connexion MQ
        let connexion = {
            let guard = self.connexion.lock().expect("lock");
            match guard.as_ref() {
                Some(c) => c.clone(),
                None => Err(format!("create_channel Aucune connexion"))?
            }
        };

        // Creer channel
        match connexion.create_channel().await {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("create_channel Erreur creation channel : {:?}", e))
        }
    }

    fn cleanup_connexion(&self) {
        // Retirer objet connexion
        {
            let mut guard = self.connexion.lock().expect("lock");
            *guard = None;
        }

        // Retirer Q reply
        {
            let mut guard = self.reply_q.lock().expect("lock");
            *guard = None;
        }
    }

    pub fn ajouter_named_queue<S>(&self, queue_name: S, named_queue: NamedQueue)
        where S: Into<String>
    {
        let queue_name_str = queue_name.into();
        debug!("ajouter_named_queue {}", queue_name_str);

        let mut guard = self.named_queues.lock().expect("lock named_queues");
        guard.insert(queue_name_str, named_queue);

        // Trigger q reload
        self.notify_queues_changed.notify_waiters();
    }

}

pub async fn notify_wait_thread(rabbitmq: Arc<RabbitMqExecutor>) {
    let notify = rabbitmq.notify_queues_changed.clone();
    notify.notified().await;
}

pub async fn run_rabbitmq<C>(rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where C: ConfigMessages + 'static
{
    let mut futures = FuturesUnordered::new();
    futures.push(task::spawn(thread_connexion(rabbitmq.clone(), config.clone())));
    futures.push(task::spawn(thread_consumer_replyq(rabbitmq.clone(), config.clone())));
    futures.push(task::spawn(task_emettre_messages(rabbitmq.clone())));
    futures.push(task::spawn(thread_consumers_named_queues(rabbitmq.clone())));

    // Run, quit sur premier echec/thread complete
    futures.next().await.expect("futures next").expect("futures result");
}

/// Thread qui run une connexion MQ, reconnecte au besoin
async fn thread_connexion<C>(rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where C: ConfigMessages
{
    loop {
        info!("Demarrage thread connexion MQ");
        let config_ref = &**config.as_ref();
        let connexion = match connecter(config_ref).await {
            Ok(c) => {
                let connexion = Arc::new(c);
                let mut guard = rabbitmq.connexion.lock().expect("lock");
                *guard = Some(connexion.clone());
                connexion
            },
            Err(e) => {
                error!("thread_connexion Erreur connexion : {:?}", e);
                tokio::time::sleep(tokio::time::Duration::new(30, 0)).await;
                continue;
            }
        };

        // Verifier etat connexion aux 5 secondes - to be fixed, utiliser channel/methode instantannee
        while connexion.status().connected() == true {
            debug!("Connexion OK");
            tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
        }

        warn!("rabbit mq deconnecte, reconnexion dans 30 secondes");
        rabbitmq.cleanup_connexion();
        tokio::time::sleep(tokio::time::Duration::new(30, 0)).await;
    }
}

async fn thread_consumer_replyq<C>(rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where C: ConfigMessages
{
    let mut first_run = true;
    loop {
        if first_run {
            first_run = false;
        } else {
            tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
        }

        let connexion = {
            let guard = rabbitmq.connexion.lock().expect("lock");
            match guard.as_ref() {
                Some(c) => c.clone(),
                None => {
                    warn!("thread_consumers_statiques mq deconnecte, reconnexion dans 5 secondes");
                    continue;
                }
            }
        };

        // Setup channels MQ
        let mut futures = FuturesUnordered::new();

        // Reply Q
        {
            let configuration = &**config.as_ref();

            let qos_options_reponses = BasicQosOptions { global: false };
            let channel = connexion.create_channel().await.expect("channel_reponses");
            channel.basic_qos(20, qos_options_reponses).await.expect("channel_reponses basic_qos");

            let pki = configuration.get_configuration_pki();
            let reply_q = ReplyQueue {
                fingerprint_certificat: pki.get_enveloppe_privee().fingerprint().to_owned(),
                securite: rabbitmq.securite.clone(),
                ttl: Some(300000),
                reply_q_name: Arc::new(Mutex::new(None)),  // Permet de maj le nom de la reply_q globalement
            };

            let tx_reply: Sender<MessageInterne> = rabbitmq.tx_reply.clone();
            futures.push(task::spawn(ecouter_consumer(
                channel,
                QueueType::ReplyQueue(reply_q),
                tx_reply
            )));
        }

        futures.next().await.expect("futures").expect("reponse");

        warn!("channel/consumer statiques deconnecte, reconnexion dans 15 secondes");
    }
}

async fn thread_consumers_named_queues(rabbitmq: Arc<RabbitMqExecutor>) {

    let mut futures = FuturesUnordered::new();
    loop {
        {
            let named_queues = rabbitmq.as_ref().named_queues.lock().expect("lock");
            for (_, named_queue) in named_queues.iter() {
                if ! named_queue.is_running() {
                    // Creer nouvelle thread
                    let futures_nq = named_queue.get_futures(rabbitmq.clone()).expect("futures named_queues");
                    futures.extend(futures_nq);
                }
            }
        }

        // Ajout task wait notify
        futures.push(task::spawn(notify_wait_thread(rabbitmq.clone())));

        match futures.next().await {
            Some(result) => {
                info!("thread_consumers_named_queues Result thread : {:?}", result);
            },
            None => ()
        };

    }
}

#[async_trait]
impl MqMessageSendInformation for RabbitMqExecutor {
    async fn send_out(&self, message: MessageOut) -> Result<(), String> {
        let sender = self.tx_out.clone();
        match sender.send(message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur send {:?}", e)),
        }
    }

    fn get_reqly_q_name(&self) -> Option<String> {
        self.reply_q.lock().expect("lock").clone()
    }
}

pub struct NamedQueue {
    pub queue: QueueType,
    pub tx: Sender<MessageInterne>,
    rx: Mutex<Option<Receiver<MessageInterne>>>,  // Conserve rx jusqu'au demarrage de la thread
}

impl NamedQueue {
    pub fn new(queue: QueueType, buffer_size: Option<usize>) -> Self {
        let buffer = match buffer_size {
            Some(b) => b,
            None => 1
        };
        let (tx, rx) = mpsc::channel(buffer);
        Self { queue, tx, rx: Mutex::new(Some(rx)) }
    }

    fn is_running(&self) -> bool {
        let mut guard = self.rx.lock().expect("lock");
        guard.is_none()  // Si rx est None, la thread est running
    }

    fn get_futures(&self, rabbitmq: Arc<RabbitMqExecutor>) -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>> {
        info!("Demarrage thread named queue {:?}", self.queue);
        let mut futures = FuturesUnordered::new();

        // Extraire le receiver
        let mut rx = {
            let mut guard = self.rx.lock().expect("lock");
            let rx = match guard.take() {
                Some(rx) => rx,
                None => Err(format!("NamedQueue rx n'est pas disponible, abort"))?
            };
            rx
        };

        futures.push(task::spawn(named_queue_consume(rabbitmq, self.tx.clone(), self.queue.clone())));
        futures.push(task::spawn(named_queue_traiter_messages(rx, self.queue.clone())));

        // futures.next().await.expect("run await").expect("run await resultat");
        Ok(futures)
    }
}

pub async fn named_queue_consume(rabbitmq: Arc<RabbitMqExecutor>, tx: Sender<MessageInterne>, queue: QueueType) {
    debug!("named_queue_consume Demarrage pour {:?}", queue);
    let mut first_run = true;

    loop {
        if ! first_run {
            tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
        } else {
            first_run = false;
        }

        // Creer channel
        let channel = match rabbitmq.create_channel().await {
            Ok(c) => c,
            Err(e) => {
                error!("named_queue_consume Erreur ouverture channel pour Q {:?}, {:?}", queue, e);
                continue
            }
        };

        {
            let qos_options_reponses = BasicQosOptions { global: false };
            if let Err(e) = channel.basic_qos(1, qos_options_reponses).await {
                error!("named_queue_consume Erreur configuration channel pour Q {:?}, {:?}", queue, e);
                continue
            }
        }

        let tx_consumer = tx.clone();
        // Demarrer consumer (va creer Q si necessaire)
        ecouter_consumer(channel, queue.clone(), tx_consumer).await;

        // Boucler, le sleep est au debut
        warn!("channel/consumer {:?} deconnecte, reconnexion dans 15 secondes", queue);
    }
}

pub async fn named_queue_traiter_messages(mut rx: Receiver<MessageInterne>, queue: QueueType) {
    debug!("named_queue_traiter_messages Demarrage queue {:?}", queue);

    // Demarrer ecoute de messages
    while let Some(message) = rx.recv().await {
        debug!("NamedQueue.run Message recu : {:?}", message);
        match message {
            MessageInterne::Delivery(delivery, routing) => {
                todo!("Traiter message Delivery")
            },
            _ => {
                debug!("Type de message non-supporte, on l'ignore");
            }
        }
    }

    info!("named_queue_traiter_messages Fermeture queue {:?}", queue);
}

// pub struct RabbitMqExecutorRx {
//     // pub rx_messages: Receiver<MessageInterne>,
//     pub rx_reply: Receiver<MessageInterne>,
//     pub rx_triggers: Receiver<MessageInterne>,
// }

// async fn boucle_execution<C>(
//     configuration: Arc<C>,
//     queues: Option<Vec<QueueType>>,
//     tx_traiter_delivery: Sender<MessageInterne>,
//     tx_traiter_reply: Sender<MessageInterne>,
//     tx_traiter_trigger: Sender<MessageInterne>,
//     tx_message_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
//     listeners: Option<Mutex<Callback<'_, EventMq>>>,
//     reply_q: Arc<Mutex<Option<String>>>,
//     securite: Securite
// )
//     where C: ConfigMessages
// {
//     let vec_queues = match queues {
//         Some(v) => v,
//         None => Vec::new(),
//     };
//
//     // let mq: RabbitMq = initialiser(configuration.as_ref()).await.expect("Erreur connexion RabbitMq");
//     let connexion = connecter(configuration.as_ref()).await?;
//
//     // Setup channels MQ
//     let channel_reponses = connexion.create_channel().await.unwrap();
//     let channel_out = connexion.create_channel().await.unwrap();
//     let qos_options_reponses = BasicQosOptions { global: false };
//     channel_reponses.basic_qos(20, qos_options_reponses).await.expect("channel_reponses basic_qos");
//     let qos_options_out = BasicQosOptions { global: false };
//     channel_out.basic_qos(20, qos_options_out).await.expect("channel_out basic_qos");
//
//     // Setup mpsc
//     // let (tx_delivery, rx_delivery) = mpsc::channel(5);
//     let (tx_out, rx_out) = mpsc::channel(3);
//
//     // Injecter tx_out dans tx_message_arc
//     {
//         let mut guard = tx_message_out.as_ref().lock().expect("Erreur injection tx_message");
//         *guard = Some(tx_out);
//     }
//
//     let mut futures = FuturesUnordered::new();
//
//     // Demarrer tasks de Q
//     {
//         let pki = configuration.get_configuration_pki();
//         let reply_q = ReplyQueue {
//             fingerprint_certificat: pki.get_enveloppe_privee().fingerprint().to_owned(),
//             securite: securite.clone(),
//             ttl: Some(300000),
//             reply_q_name: reply_q.clone(),  // Permet de maj le nom de la reply_q globalement
//         };
//         futures.push(task::spawn(ecouter_consumer(
//             channel_reponses,
//             QueueType::ReplyQueue(reply_q),
//             tx_traiter_reply.clone()
//         )));
//     }
//
//     for config_q in &vec_queues {
//         let channel_main = conn.create_channel().await.expect("main_channel create_channel");
//         let qos_options = BasicQosOptions { global: false };
//         channel_main.basic_qos(1, qos_options).await.expect("main_channel basic_qos");
//
//         let sender = match &config_q {
//             QueueType::ExchangeQueue(_) => tx_traiter_delivery.clone(),
//             QueueType::ReplyQueue(_) => tx_traiter_reply.clone(),
//             QueueType::Triggers(_q,_s) => tx_traiter_trigger.clone(),
//         };
//
//         futures.push(task::spawn(
//             ecouter_consumer(channel_main,config_q.clone(),sender)
//         ));
//     }
//
//     // Demarrer tasks de traitement de messages
//     futures.push(task::spawn(
//         task_emettre_messages(configuration.clone(), channel_out, securite.clone(), rx_out, reply_q.clone())
//     ));
//
//     // Thread pour verifier etat connexion
//     futures.push(task::spawn(entretien_connexion(arc_mq.clone())));
//
//     // Emettre message connexion completee
//     match &listeners {
//         Some(inner) => {
//             debug!("MQ Connecte, appel les listeners");
//             inner.lock().expect("callback").call(EventMq::Connecte);
//         },
//         None => {
//             debug!("MQ Connecte, aucuns listeners");
//         }
//     }
//
//     // Executer threads. Des qu'une thread se termine, on abandonne la connexion
//     info!("Debut execution consumers MQ");
//     let resultat = futures.next().await;
//
//     info!("Fin execution consumers MQ/deconnexion, resultat : {:?}", resultat);
//
//     // Vider sender immediatement
//     {
//         let mut guard = tx_message_out.as_ref().lock()
//             .expect("Erreur nettoyage tx_message");
//         *guard = None;
//     }
//
//     // Emettre message connexion perdue
//     match &listeners {
//         Some(inner) => {
//             debug!("MQ Connecte, appel les listeners");
//             inner.lock().expect("callback").call(EventMq::Deconnecte);
//         },
//         None => {
//             debug!("MQ Connecte, aucuns listeners");
//         }
//     }
//
// }

/// Thread de verification de l'etat de connexion. Va se terminer si la connexion est fermee.
async fn entretien_connexion(mq: Arc<RabbitMqExecutor>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
        todo!("Fix me")
        // let status = mq.connexion.status();
        // debug!("Verification etat connexion MQ : {:?}", status);
        // if ! status.connected() {
        //     break
        // }
        // if status.errored() || status.closed() {
        //     warn!("Connexion MQ en erreur/fermee - note: indique erreur detection _connected_");
        //     break
        // }
        // if status.blocked() {
        //     warn!("Connexion MQ bloquee (recoverable)");
        //     break  // TODO - mettre compteur pour decider de fermer la connexion
        // }
    }
    warn!("Connexion MQ perdue, on va se reconnecter");
}

async fn creer_reply_q(channel: &Channel, rq: &ReplyQueue) -> Queue {
    let options = QueueDeclareOptions {
        passive: false,
        durable: false,
        exclusive: true,
        auto_delete: true,
        nowait: false,
    };

    let mut params = FieldTable::default();
    match rq.ttl {
        Some(v) => params.insert(FLAG_TTL.into(), v.into()),
        None => ()
    }

    let reply_queue = channel
        .queue_declare(
            "",
            options,
            params,
        ).await.unwrap();

    // Ajouter routing keys pour ecouter evenements certificats, requete cert local
    let rk_fingerprint = format!("requete.certificat.{}", rq.fingerprint_certificat);
    let routing_keys = vec!(
        "evenement.certificat.infoCertificat".into(),  // Ecouter les evenements de tiers qui emettent leur certificat
        rk_fingerprint,  // Ecouter les requetes pour notre certificat
    );

    let exchanges: Vec<String> = securite_cascade_public(&rq.securite).iter().map(|s| s.get_str().to_owned()).collect();
    debug!("creer_reply_q Binding sur exchanges : {:?}", exchanges);

    let nom_queue = reply_queue.name().as_str();
    for rk in routing_keys {
        for exchange in &exchanges {
            debug!("creer_reply_q Mapping rk {} sur reply-Q {} exchange {}", rk, nom_queue, exchange);
            let _ = channel.queue_bind(
                nom_queue,
                &exchange,
                &rk,
                QueueBindOptions::default(),
                FieldTable::default()
            ).await.expect("Binding routing key");
        }
    }

    debug!("Creation reply-Q exclusive {:?}", reply_queue);

    {
        // Conserver le nom de la Q globalement
        let mut ql = rq.reply_q_name.lock().expect("lock");
        *ql = Some(reply_queue.name().as_str().into());
    }

    reply_queue
}

/// Q interne utilisee pour recevoir les triggers et autre evenements sur exchange 4.secure
async fn creer_internal_q(nom_domaine: String, channel: &Channel, securite: &Securite) -> Queue {
    let mut params = FieldTable::default();
    params.insert(FLAG_TTL.into(), 300000.into());  // 5 minutes max pour traitement events

    let domaine_split = nom_domaine.replace(".", "/");
    let nom_queue = format!("{}/triggers", domaine_split);

    let trigger_queue = channel
        .queue_declare(
            nom_queue.as_str(),
            QueueDeclareOptions::default(),
            params,
        ).await.unwrap();

    let nom_queue = trigger_queue.name().as_str();

    // Ajouter routing keys pour ecouter evenements triggers secure
    let rank_securite = securite.get_rank();
    // Ajouter routing keys pour ecouter evenements certificats, requete cert local
    if rank_securite >= 3 {

        // Note : 4.secure, utilise sur module back-end
        //        Trouver meilleure facon de representer
        let routing_keys_secure = vec!(
            // Ecouter les evenements internes pour le domaine
            String::from(format!("evenement.{}.{}", nom_domaine, EVENEMENT_TRANSACTION_PERSISTEE)),
            // String::from(EVENEMENT_GLOBAL_CEDULE),
        );
        for rk in routing_keys_secure {
            let _ = channel.queue_bind(
                nom_queue,
                SECURITE_4_SECURE,
                &rk,
                QueueBindOptions::default(),
                FieldTable::default()
            ).await.expect("Binding routing key");
        }

        let routing_keys_protege = vec!(
            // Ecouter les evenements pour le domaine
            String::from(format!("commande.{}.{}", nom_domaine, COMMANDE_BACKUP_HORAIRE)),
            String::from(format!("commande.{}.{}", nom_domaine, COMMANDE_RESTAURER_TRANSACTION)),
            String::from(format!("commande.{}.{}", nom_domaine, COMMANDE_RESTAURER_TRANSACTIONS)),
            String::from(format!("commande.{}.{}", nom_domaine, COMMANDE_RESET_BACKUP)),
            String::from(format!("commande.{}.{}", nom_domaine, COMMANDE_REGENERER)),

            // Evenement globaux
            // String::from(EVENEMENT_GLOBAL_CEDULE),
            String::from(COMMANDE_GLOBAL_BACKUP_HORAIRE),
            String::from(COMMANDE_GLOBAL_RESTAURER_TRANSACTIONS),
            String::from(COMMANDE_GLOBAL_RESET_BACKUP),
            String::from(COMMANDE_GLOBAL_REGENERER),
        );
        for rk in routing_keys_protege {
            let _ = channel.queue_bind(
                nom_queue,
                SECURITE_3_PROTEGE,
                &rk,
                QueueBindOptions::default(),
                FieldTable::default()
            ).await.expect("Binding routing key");
        }

        let routing_keys_prive = vec!(
            // Ecouter les evenements pour le domaine
            String::from(format!("evenement.{}.{}", DOMAINE_FICHIERS, EVENEMENT_BACKUP_DECLENCHER)),
        );
        for rk in routing_keys_prive {
            let _ = channel.queue_bind(
                nom_queue,
                SECURITE_2_PRIVE,
                &rk,
                QueueBindOptions::default(),
                FieldTable::default()
            ).await.expect("Binding routing key");
        }
    }

    // RK au meme niveau de securite que le module
    let routing_keys_secure = vec!(
        // Ecouter les evenements internes pour le domaine
        String::from(EVENEMENT_GLOBAL_CEDULE),
    );
    for rk in routing_keys_secure {
        let _ = channel.queue_bind(
            nom_queue,
            securite.get_str(),
            &rk,
            QueueBindOptions::default(),
            FieldTable::default()
        ).await.expect("Binding routing key");
    }

    debug!("Creation trigger-Q {:?}", trigger_queue);
    trigger_queue
}


async fn ecouter_consumer(channel: Channel, queue_type: QueueType, tx: Sender<MessageInterne>) {

    debug!("Ouvrir queue {:?}", queue_type);

    let queue = match &queue_type {
        QueueType::ExchangeQueue(c) => {
            let nom_queue = &c.nom_queue;

            let options = QueueDeclareOptions {
                passive: false,
                durable: c.durable,
                exclusive: false,
                auto_delete: false,
                nowait: false,
            };

            let mut params = FieldTable::default();
            match c.ttl {
                Some(v) => params.insert(FLAG_TTL.into(), v.into()),
                None => ()
            }

            let queue = channel.queue_declare(&nom_queue, options, params).await.unwrap();

            // Ajouter tous les routing keys a la Q
            for rk in &c.routing_keys {
                let routing_key = rk.routing_key.as_str();
                let exchange = rk.exchange.get_str();
                debug!("ecouter_consumer queue_bind rk {} sur queue {}, exchange {}", routing_key, nom_queue, exchange);
                let _ = channel.queue_bind(
                    nom_queue,
                    exchange,
                    routing_key,
                    QueueBindOptions::default(),
                    FieldTable::default()
                ).await.unwrap();
            }

            queue
        },
        QueueType::ReplyQueue(rq) => {
            creer_reply_q(&channel, &rq).await
        },
        QueueType::Triggers(nom_domaine, securite) => {
            creer_internal_q(nom_domaine.to_owned(), &channel, securite).await
        }
    };
    debug!("Declared queue {:?}", queue);

    let nom_queue = queue.name().as_str();

    let consumer = channel
        .basic_consume(
            nom_queue,
            "".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        );
    debug!("Creation consumer {}", nom_queue);
    let mut consumer = consumer.await.unwrap();
    debug!("task_traitement_reponses consumer pret {}", nom_queue);

    while let Some(delivery) = consumer.next().await {
        debug!("ecouter_consumer({}): Reception nouveau message {}: {:?}", &nom_queue, &nom_queue, &delivery);

        let (channel, delivery) = delivery.expect("error in consumer");
        if ! channel.status().connected() {
            warn!("ecouter_consumer Channel closed, on ferme la connexion");
            break
        }

        let acker = delivery.acker.clone();

        let message_interne = match &queue_type {
            QueueType::ExchangeQueue(q) => {
                let nom_queue = q.nom_queue.to_owned();
                MessageInterne::Delivery(delivery, nom_queue)
            },
            QueueType::ReplyQueue(q) => {
                let mutex = q.reply_q_name.lock().expect("lock");
                let nom_queue = match mutex.as_ref() {
                    Some(n) => n.to_owned(),
                    None => nom_queue.to_owned(),  // Q globale en attendant le nom de la Q reponse
                };
                MessageInterne::Delivery(delivery, nom_queue)
            },
            QueueType::Triggers(_q, _s) => MessageInterne::Trigger(delivery, nom_queue.to_owned()),
        };

        // Ajouter message sur Q interne
        match tx.send(message_interne).await {
            Ok(()) => {
                // Emettre le Ack
                match acker.ack(BasicAckOptions::default()).await {
                    Ok(_d) => (),
                    Err(e) => {
                        warn!("Erreur ACK message, on ferme le consumer : {:?}", e);
                        break
                    }
                }
            },
            Err(e) => {
                // Erreur de queuing interne, emettre un nack (remet message sur la Q)
                debug!("Erreur Q interne, NACK : {:?}", e);
                match acker.nack(BasicNackOptions::default()).await {
                    Ok(_d) => (),
                    Err(e) => {
                        warn!("Erreur NACK message, on ferme le consumer : {:?}", e);
                        break
                    }
                }
            }
        }
    }

    info!("rabbitmq_dao.ecouter_consumer Fermeture consumer (Q {:?})", queue_type);
}

fn concatener_rk(message: &MessageOut) -> Result<String, String> {
    let domaine = match &message.domaine {
        Some(d) => d.as_str(),
        None => Err("Domaine manquant")?,
    };

    let mut vec_rk = Vec::new();

    vec_rk.push(domaine);
    if let Some(partition) = message.partition.as_ref() {
        vec_rk.push(partition.as_str());
    }

    if let Some(action) = message.action.as_ref() {
        vec_rk.push(action.as_str());
    }

    let routing_key: String = vec_rk.join(".").into();

    Ok(routing_key)
}

async fn task_emettre_messages(rabbitmq: Arc<RabbitMqExecutor>) {
    let mut compteur: usize = 0;
    let exchange_defaut = rabbitmq.securite.get_str();
    debug!("task_emettre_messages : Demarrage thread, exchange defaut {}", exchange_defaut);

    let mut rx = {
        let mut guard = rabbitmq.rx_out.lock().expect("lock");
        match guard.take() {
            Some(rx) => rx,
            None => panic!("rabbitmq_dao.task_emettre_messages Erreur extraction rx_out")
        }
    };

    let mut channel_opt: Option<Channel> = None;

    while let Some(message) = rx.recv().await {
        compteur += 1;
        debug!("task_emettre_messages Emettre_message {}, On a recu de quoi", compteur);
        let contenu = &message.message;

        // Verifier etat du channel (doit etre connecte)
        let connecte = match channel_opt.as_ref() {
            Some(channel) => {
                if channel.status().connected() {
                    true
                } else {
                    warn!("task_emettre_messages Channel OUT est ferme, tenter de reouvrir channel");
                    false
                }
            },
            None => false
        };

        if ! connecte {
            // Tenter de recreer un channel
            channel_opt = None;
            let connexion = {
                let guard = rabbitmq.connexion.lock().expect("lock");
                match guard.as_ref() {
                    Some(c) => c.clone(),
                    None => {
                        warn!("Connexion fermee, reessayer plus tard");
                        continue
                    }
                }
            };
            match connexion.create_channel().await {
                Ok(c) => {
                    channel_opt = Some(c);
                },
                Err(e) => {
                    warn!("Erreur ouverture channel, reessayer plus tard");
                    continue
                }
            }
        };

        let channel = channel_opt.as_ref().expect("channel");

        let entete = &contenu.entete;
        debug!("Emettre_message {:?}", entete);

        let correlation_id = match &message.correlation_id {
            Some(c) => c.to_owned(),
            None => entete.uuid_transaction.to_owned()
        };

        let exchanges = match &message.exchanges {
            Some(e) => Some(e.clone()),
            None => {
                let securite = rabbitmq.securite.clone();
                match message.type_message {
                    TypeMessageOut::Reponse => None,  // Aucun exchange pour une reponse
                    _ => Some(vec![securite])  // Toutes les autre reponses, prendre exchange defaut
                }
            }
        };

        let routing_key = match &message.domaine {
            Some(_) => {
                let rk = match concatener_rk(&message) {
                    Ok(rk) => rk,
                    Err(e) => {
                        error!("task_emettre_messages Erreur preparation routing key {:?}", e);
                        continue
                    }
                };

                match &message.type_message {
                    TypeMessageOut::Requete => format!("requete.{}", rk),
                    TypeMessageOut::Commande => format!("commande.{}", rk),
                    TypeMessageOut::Transaction => format!("transaction.{}", rk),
                    TypeMessageOut::Reponse => panic!("Reponse avec domaine non supportee"),
                    TypeMessageOut::Evenement => format!("evenement.{}", rk),
                }
            },
            None => String::from(""),
        };

        let message_serialise = match MessageSerialise::from_parsed(message.message) {
            Ok(m) => m,
            Err(e) => {
                error!("task_emettre_messages Erreur traitement message, on drop : {:?}", e);
                continue;
            },
        };

        let options = BasicPublishOptions::default();
        let payload = message_serialise.get_str().as_bytes().to_vec();

        let properties = {
            let mut properties = BasicProperties::default()
                .with_correlation_id(correlation_id.clone().into());

            match &message.replying_to {
                Some(r) => {
                    debug!("task_emettre_messages Emission message, reply_q en parametre : {:?}", r);
                    properties = properties.with_reply_to(r.as_str().into());
                },
                None => {
                    let lock_reply_q = rabbitmq.reply_q.lock().expect("lock");
                    debug!("task_emettre_messages Emission message, reply_q locale : {:?}", lock_reply_q);
                    match lock_reply_q.as_ref() {
                        Some(qs) => {
                            properties = properties.with_reply_to(qs.as_str().into());
                        },
                        None => ()
                    };
                }
            }

            properties
        };

        match exchanges {
            Some(inner) => {
                for exchange in inner {
                    let resultat = channel.basic_publish(
                        exchange.get_str(),
                        &routing_key,
                        options,
                        payload.clone(),
                        properties.clone()
                    ).await;
                    if resultat.is_err() {
                        error!("task_emettre_messages Erreur emission message {:?}", resultat)
                    } else {
                        debug!("task_emettre_messages Message {} emis sur {:?}", routing_key, exchange)
                    }
                }
            },
            None => {
                // Reply
                let reply_to = message.replying_to.expect("reply_q");
                debug!("task_emettre_messages Emission message vers reply_q {} avec correlation_id {}", reply_to, correlation_id);

                // C'est une reponse (message direct)
                let resultat = channel.basic_publish(
                    "",
                    &reply_to,
                    options,
                    payload.to_vec(),
                    properties
                ).await;
                if resultat.is_err() {
                    error!("task_emettre_messages Erreur emission message {:?}", resultat);
                } else {
                    debug!("task_emettre_messages Reponse {} emise vers {:?}", correlation_id, reply_to);
                }
            }
        }
    };

    info!("emettre_message : Fin thread");
}

#[derive(Debug)]
pub struct AttenteReponse {
    pub correlation: String,
    pub sender: SenderOneshot<TypeMessage>,
}

#[derive(Debug)]
pub enum MessageInterne {
    Delivery(Delivery, String),
    Trigger(Delivery, String),
    AttenteReponse(AttenteReponse),
    CancelDemandeReponse(String),
}

#[derive(Clone, Debug)]
pub struct MessageOut {
    pub message: MessageMilleGrille,
    type_message: TypeMessageOut,
    domaine: Option<String>,
    action: Option<String>,
    partition: Option<String>,
    exchanges: Option<Vec<Securite>>,     // Utilise pour emission de message avec domaine_action
    pub correlation_id: Option<String>,
    pub replying_to: Option<String>,    // Utilise pour une reponse
}

impl MessageOut {
    pub fn new<S>(
        domaine: S,
        action: S,
        partition: Option<S>,
        message: MessageMilleGrille,
        type_message: TypeMessageOut,
        exchanges: Option<Vec<Securite>>,
        replying_to: Option<S>,
        correlation_id: Option<S>
    )
        -> MessageOut
        where S: Into<String>
    {
        if type_message == TypeMessageOut::Reponse {
            panic!("Reponse non supportee, utiliser MessageOut::new_reply()");
        }

        let corr_id = match correlation_id {
            Some(c) => c.into(),
            None => {
                let entete = &message.entete;
                entete.uuid_transaction.clone()
            }
        };

        let rep_to = match replying_to {
            Some(r) => Some(r.into()),
            None => None,
        };

        let exchange_effectif = match exchanges {
            Some(e) => Some(e),
            None => None,  // vec!(Securite::L3Protege),
        };

        let partition_owned = match partition {
            Some(p) => Some(p.into()),
            None => None,
        };

        MessageOut {
            message,
            type_message,
            domaine: Some(domaine.into()),
            action: Some(action.into()),
            partition: partition_owned,
            exchanges: exchange_effectif,
            correlation_id: Some(corr_id),
            replying_to: rep_to,
        }
    }

    pub fn new_reply(message: MessageMilleGrille, correlation_id: &str, replying_to: &str) -> MessageOut {
        MessageOut {
            message,
            type_message: TypeMessageOut::Reponse,
            domaine: None,
            action: None,
            partition: None,
            exchanges: None,
            correlation_id: Some(correlation_id.to_owned()),
            replying_to: Some(replying_to.to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeMessageOut {
    Requete,
    Commande,
    Transaction,
    Reponse,
    Evenement,
}

// https://users.rust-lang.org/t/callback-with-generic/52426
// https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=f8a5ecf9873f6463ee29066465a0d5c8
// use std::marker::PhantomData;

#[derive(Clone, Debug, Copy)]
pub enum EventMq {
    Connecte,
    Deconnecte,
}

pub struct Callback<'a, T> {
    callbacks: Vec<Box<dyn FnMut(T) + Send + 'a>>,
}

impl<'a, T> Callback<'a, T> {
    pub fn new() -> Self {
        Callback {
            callbacks: Vec::new(),
        }
    }
    pub fn register<F>(&mut self, callback: F)
    where
        F: FnMut(T) + Send + 'a,
    {
        self.callbacks.push(Box::new(callback));
    }

    pub fn call(&mut self, val: T)
    where T: Copy,
    {
        let repeat = "*".repeat(20);
        debug!("{} Begin {}", repeat, repeat);
        for callback in self.callbacks.iter_mut() {
            // val is move to closure, we need T: Copy
            callback(val);
            // or
            // (&mut *callback)(val);
        }
        debug!("{} End   {}", repeat, repeat);
    }
}

// #[cfg(test)]
// mod rabbitmq_integration_test {
//     use crate::configuration::charger_configuration;
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn connecter_mq() {
//         setup("connecter");
//         debug!("Connecter");
//
//         let config = charger_configuration().expect("config");
//         let connexion = connecter(&config).await.expect("connexion");
//
//         // debug!("Sleep 5 secondes");
//         // tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
//
//         let status = connexion.status();
//         debug!("Connexion status : {:?}", status);
//         assert_eq!(status.connected(), true);
//     }
// }