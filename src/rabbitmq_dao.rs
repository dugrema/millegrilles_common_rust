use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::stream::FuturesUnordered;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, options::*, Queue, tcp::{OwnedIdentity, OwnedTLSConfig}, types::FieldTable};
use lapin::message::Delivery;
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use tokio::{sync, task};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}, Notify, oneshot::Sender as SenderOneshot};
use tokio::task::JoinHandle;
use tokio_amqp::*;
use tokio_stream::StreamExt;

use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigMessages, ConfigurationMq, ConfigurationPki};
use crate::constantes::*;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{ChiffrageFactoryTrait, IsConfigurationPki};
use crate::recepteur_messages::{intercepter_message, traiter_delivery, TypeMessage};

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);
const INTERVALLE_ENTRETIEN_ATTENTE: Duration = Duration::from_millis(400);
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
    pub autodelete: bool,
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
        tokio::time::sleep(ATTENTE_RECONNEXION).await;
    }

    // Reessayer la connexion (meme si erreur - regenerer l'erreur d'auth)
    Connection::connect_with_config(
        &addr,
        ConnectionProperties::default().with_tokio(),
        tls_config.as_ref(),
    ).await
}

pub async fn emettre_certificat_compte<C>(configuration: &C) -> Result<(), Box<dyn Error>>
    where C: ConfigMessages
{
    const PORT: u16 = 444;
    const COMMANDE: &str = "administration/ajouterCompte";

    let config_mq = configuration.get_configuration_mq();
    let mut hosts = Vec::new();
    if let Some(midcompte) = configuration.get_configuration_noeud().midcompte_url.as_ref() {
        hosts.push(midcompte.clone());
    }
    hosts.push(Url::parse(format!("https://nginx:{}", PORT).as_str())?);
    hosts.push(Url::parse(format!("https://{}:{}", config_mq.host.as_str(), PORT).as_str())?);

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
    async fn send_out(&self, message: MessageOut) -> Result<Option<sync::oneshot::Receiver<TypeMessage>>, String>;
    fn get_reqly_q_name(&self) -> Option<String>;
}

// pub trait MqRequeteCertificat {
//     async fn request_certificat<M,S>(&self, middleware: &M, fingerprint: S) -> Result<EnveloppeCertificat, String>
//         where
//             S: Into<String>,
//             M: GenerateurMessages + ValidateurX509;
// }

// pub struct RabbitMqExecutorConfig {
//     pub executor: RabbitMqExecutor,
//     pub securite: Securite,
// }

pub struct RabbitMqExecutor {
    connexion: Mutex<Option<Arc<Connection>>>,
    named_queues: Mutex<HashMap<String, NamedQueue>>,
    notify_connexion_ready: Arc<Notify>,
    notify_queues_changed: Arc<Notify>,
    map_attente: Mutex<HashMap<String, AttenteReponse>>,
    pub reply_q: Arc<Mutex<Option<String>>>,
    pub securite: Securite,

    // TX
    pub tx_out: Sender<MessageOut>,
    pub tx_reply: Sender<MessageInterne>,

    // RX holder
    rx_out: Mutex<Option<Receiver<MessageOut>>>,
    rx_reply: Mutex<Option<Receiver<MessageInterne>>>,
}

impl RabbitMqExecutor {

    pub fn new(securite: Option<Securite>) -> Self {

        // Creer channels communication mpsc
        let (tx_out, rx_out) = mpsc::channel(3);
        let (tx_reply, rx_reply) = mpsc::channel(1);

        // Securite default = 1.public
        let securite = match securite {
            Some(s) => s,
            None => Securite::L1Public
        };

        Self {
            connexion: Mutex::new(None),
            named_queues: Mutex::new(Default::default()),
            notify_connexion_ready: Arc::new(Default::default()),
            notify_queues_changed: Default::default(),
            map_attente: Mutex::new(Default::default()),
            reply_q: Arc::new(Mutex::new(None)),
            securite,

            // TX
            tx_out,
            tx_reply,

            // RX
            rx_out: Mutex::new(Some(rx_out)),
            rx_reply: Mutex::new(Some(rx_reply)),
        }
    }

    pub async fn create_channel(&self) -> Result<Channel, String> {
        // Get connexion MQ
        let notify = self.notify_connexion_ready.clone();
        notify.notified().await;

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

    /// Retourne true si la connexion MQ est etablie et active
    pub fn est_connecte(&self) -> bool {
        let guard = self.connexion.lock().expect("lock");
        match &*guard {
            Some(c) => c.status().connected(),
            None => false
        }
    }

    pub fn notify_attendre_connexion(&self)-> Arc<Notify> { self.notify_connexion_ready.clone() }

    /// Methode d'attente de connexion
    pub async fn attendre_connexion(&self) { self.notify_connexion_ready.clone().notified().await }

}

pub async fn notify_wait_thread(rabbitmq: Arc<RabbitMqExecutor>) {
    let notify = rabbitmq.notify_queues_changed.clone();
    notify.notified().await;
}

pub async fn run_rabbitmq<C,M>(middleware: Arc<M>, rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where
        C: ConfigMessages + 'static,
        M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
{
    let mut futures = FuturesUnordered::new();
    futures.push(task::spawn(thread_connexion(rabbitmq.clone(), config.clone())));
    futures.push(task::spawn(thread_reply_q(middleware.clone(), rabbitmq.clone(), config.clone())));
    futures.push(task::spawn(task_emettre_messages(rabbitmq.clone())));
    futures.push(task::spawn(thread_consumers_named_queues(middleware, rabbitmq.clone())));

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
                tokio::time::sleep(ATTENTE_RECONNEXION).await;
                continue;
            }
        };

        // Verifier etat connexion aux 5 secondes - to be fixed, utiliser channel/methode instantannee
        while connexion.status().connected() == true {
            debug!("Connexion OK");
            rabbitmq.notify_connexion_ready.notify_waiters();  // Notify waiters a chaque fois
            tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
        }

        warn!("rabbit mq deconnecte, reconnexion dans 30 secondes");
        rabbitmq.cleanup_connexion();
        tokio::time::sleep(ATTENTE_RECONNEXION).await;
    }
}

async fn thread_reply_q<M, C>(middleware: Arc<M>, rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where
        M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
        C: ConfigMessages + 'static
{
    let mut futures = FuturesUnordered::new();
    futures.push(task::spawn(thread_consumer_replyq(rabbitmq.clone(), config.clone())));
    futures.push(task::spawn(thread_traiter_reply_q(middleware.clone(), rabbitmq.clone())));
    futures.push(task::spawn(thread_entretien_attente(rabbitmq.clone())));

    // Run, quit sur premier echec/thread complete
    futures.next().await.expect("thread_reply_q futures next").expect("thread_reply_q futures result");
}

/// Retire les "attentes" de reply expirees
async fn thread_entretien_attente(rabbitmq: Arc<RabbitMqExecutor>) {
    loop {
        tokio::time::sleep(INTERVALLE_ENTRETIEN_ATTENTE).await;
        {
            // Purger toutes les attentes expirees
            let mut guard = rabbitmq.map_attente.lock().expect("lock");
            if guard.len() == 0 {
                continue;  // Rien a faire
            }
            let date_now = Utc::now();
            debug!("Attentes de reponse pre-cleanup: {}", guard.len());
            guard.retain(|_, attente| attente.expiration > date_now);
            debug!("Attentes de reponse post-cleanup: {}", guard.len());
        }
    }
}

async fn thread_consumer_replyq<C>(rabbitmq: Arc<RabbitMqExecutor>, config: Arc<Box<C>>)
    where C: ConfigMessages
{
    let mut first_run = true;

    let reply_q = {
        let pki = config.get_configuration_pki();
        ReplyQueue {
            fingerprint_certificat: pki.get_enveloppe_privee().fingerprint().to_owned(),
            securite: rabbitmq.securite.clone(),
            ttl: Some(300000),
            reply_q_name: Arc::new(Mutex::new(None)),  // Permet de maj le nom de la reply_q globalement
        }
    };

    loop {
        if first_run {
            first_run = false;
        } else {
            tokio::time::sleep(ATTENTE_RECONNEXION).await;
        }

        // Reply Q
        let channel = match rabbitmq.create_channel().await {
            Ok(c) => c,
            Err(e) => {
                error!("Erreur ouverture channel, reessayer plus tard : {:?}", e);
                continue
            }
        };
        let qos_options_reponses = BasicQosOptions { global: false };
        channel.basic_qos(20, qos_options_reponses).await.expect("channel_reponses basic_qos");

        let tx_reply: Sender<MessageInterne> = rabbitmq.tx_reply.clone();
        if let Err(e) = ecouter_consumer(
            rabbitmq.clone(),
            channel,
            QueueType::ReplyQueue(reply_q.clone()),
            tx_reply
        ).await {
            error!("thread_consumer_replyq Erreur ecouter consumer : {:?}", e);
        }

        warn!("channel/consumer statiques deconnecte, reconnexion dans 15 secondes");
    }
}

async fn thread_traiter_reply_q<M>(middleware: Arc<M>, rabbitmq: Arc<RabbitMqExecutor>)
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
{
    let mut rx = {
        let mut guard = rabbitmq.rx_reply.lock().expect("lock");
        match guard.take() {
            Some(rx) => rx,
            None => panic!("thread_traiter_reply_q rx reply non disponible")
        }
    };

    while let Some(message) = rx.recv().await {
        debug!("Message reply q : {:?}", message);
        let resultat = match message {
            MessageInterne::Delivery(delivery, _routing) => {
                let nom_queue = match rabbitmq.reply_q.lock().expect("lock").clone() {
                    Some(q) => q,
                    None => "_reply".into()
                };
                match traiter_delivery(
                    middleware.as_ref(),
                    nom_queue.as_str(),
                    delivery
                ).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("thread_traiter_reply_q Erreur traitement message : {:?}", e);
                        None
                    }
                }
            },
            _ => {
                debug!("thread_traiter_reply_q Type de message non-supporte, on l'ignore");
                None
            }
        };

        if let Some(message_traite) = resultat {
            let attente_reponse = match &message_traite {
                TypeMessage::Valide(message) => {
                    match &message.type_message {
                        TypeMessageOut::Reponse(r) => {
                            // Reponse valide, retransmettre sur la correlation appropriee
                            let correlation_id = r.correlation_id.as_str();
                            let mut guard = rabbitmq.map_attente.lock().expect("lock");
                            if let Some(attente_reponse) = guard.remove(correlation_id) {
                                Some(attente_reponse)
                            } else {
                                info!("thread_traiter_reply_q Message recu sans attente sur correlation_id {}, skip", correlation_id);
                                None
                            }
                        },
                        _ => None
                    }
                    // if let Some(correlation_id) = message.type_message.as_ref() {
                    //     let mut guard = rabbitmq.map_attente.lock().expect("lock");
                    //     if let Some(attente_reponse) = guard.remove(correlation_id) {
                    //         Some(attente_reponse)
                    //     } else {
                    //         info!("thread_traiter_reply_q Message recu sans attente sur correlation_id {}, skip", correlation_id);
                    //         None
                    //     }
                    // } else {
                    //     None
                    // }
                },
                // TypeMessage::ValideAction(message) => {
                //     if message.action.as_str() == PKI_REQUETE_CERTIFICAT {
                //         if let Some(cert) = message.message.certificat.as_ref() {
                //             debug!("Certificat recu - {}", cert.fingerprint)
                //         }
                //     } else {
                //         warn!("thread_traiter_reply_q Recu message ValideAction, ignorer : {:?}", message);
                //     }
                //     None
                // },
                TypeMessage::Certificat(certificat) => {
                    warn!("thread_traiter_reply_q Recu MessageCertificat (deja traite) sur thread consommation, skip : {:?}", certificat);
                    None
                },
                TypeMessage::Regeneration => None  // Ignorer
            };

            match attente_reponse {
                Some(a) => {
                    // On a une correlation, rediriger le message en attente
                    if let Err(e) = a.sender.send(message_traite) {
                        error!("thread_traiter_reply_q Erreur transmission reponse attente correlation {} : {:?}", a.correlation, e);
                    }
                },
                None => {
                    // Aucune correlation (message non sollicite). Voir si on intercepte le message
                    // pour le passer a une chaine de traitement differente.
                    if intercepter_message(middleware.as_ref(), &message_traite).await == false {
                        info!("Message sur reply_q sans attente et non intercepte, on skip : {:?}", message_traite);
                    }
                }
            }
        }
    }

    info!("thread_consumer_reply_queue Fin thread");
}

async fn thread_consumers_named_queues<M>(middleware: Arc<M>, rabbitmq: Arc<RabbitMqExecutor>)
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
{

    let mut futures = FuturesUnordered::new();
    loop {
        {
            let named_queues = rabbitmq.as_ref().named_queues.lock().expect("lock");
            for (_, named_queue) in named_queues.iter() {
                if ! named_queue.is_running() {
                    // Creer nouvelle thread
                    let futures_nq = named_queue.get_futures(middleware.clone(), rabbitmq.clone()).expect("futures named_queues");
                    futures.extend(futures_nq);
                }
            }
        }

        // Ajout task wait notify
        futures.push(task::spawn(notify_wait_thread(rabbitmq.clone())));

        match futures.next().await {
            Some(result) => match result {
                Ok(()) => info!("thread_consumers_named_queues Interruption pour changer named queues"),
                Err(e) => panic!("thread_consumers_named_queues Erreur dans Q, abort : {:?}", e)
            },
            None => panic!("thread_consumers_named_queues Erreur dans Q (aucun resultat execution), abort")
        };

    }
}

#[async_trait]
impl MqMessageSendInformation for RabbitMqExecutor {
    async fn send_out(&self, message: MessageOut) -> Result<Option<sync::oneshot::Receiver<TypeMessage>>, String> {
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
                // Ajouter message attente
                if let Some(expiration) = attente_expiration {
                    if let Some(c) = attente_correlation_id {
                        // Creer channel de reception one-shot
                        let (tx, rx) = sync::oneshot::channel();

                        debug!("send_out Attente pour correlation {} timeout {:?}", c, expiration);

                        // Ajouter attente pour correlation
                        let attente = AttenteReponse {
                            correlation: c.clone().into(),
                            sender: tx,
                            expiration: expiration.to_owned(),
                        };

                        let mut guard = self.map_attente.lock().expect("lock");
                        guard.insert(c, attente);

                        Ok(Some(rx))
                    } else {
                        // Aucune correlation
                        Ok(None)
                    }
                } else {
                    // Type de message qui ne supporte pas de reponse
                    Ok(None)
                }
            },
            Err(e) => Err(format!("Erreur send {:?}", e)),
        }
    }

    fn get_reqly_q_name(&self) -> Option<String> {
        self.reply_q.lock().expect("lock").clone()
    }
}

// impl MqRequeteCertificat for RabbitMqExecutor {
//
//     async fn request_certificat<M, S>(&self, middleware: &M, fingerprint: S) -> Result<EnveloppeCertificat, String>
//         where S: AsRef<str>, M: GenerateurMessages + ValidateurX509
//     {
//         let routage = RoutageMessageAction::builder(DOMAINE_PKI.into(), PKI_REQUETE_CERTIFICAT.into())
//             .timeout_blocking(3000)
//             .build();
//         let fp = fingerprint.as_ref();
//         let requete = json!("fingerprint": fp);
//         let reponse = middleware.transmettre_requete(routage, &requete).await?;
//     }
//
// }

pub struct NamedQueue {
    pub queue: QueueType,
    pub tx: Sender<MessageInterne>,
    rx: Mutex<Option<Receiver<MessageInterne>>>,  // Conserve rx jusqu'au demarrage de la thread
    tx_traite: Sender<TypeMessage>, // Receiver message traite
    support_threads: Mutex<Option<FuturesUnordered<JoinHandle<()>>>>,
}

impl NamedQueue {
    pub fn new(queue: QueueType, tx: Sender<TypeMessage>, buffer_size: Option<usize>, consumers: Option<FuturesUnordered<JoinHandle<()>>>)
        -> Self
    {
        let buffer = match buffer_size {
            Some(b) => b,
            None => 1
        };
        let (tx_interne, rx_interne) = mpsc::channel(buffer);
        Self { queue, tx: tx_interne, rx: Mutex::new(Some(rx_interne)), tx_traite: tx, support_threads: Mutex::new(consumers) }
    }

    fn is_running(&self) -> bool {
        self.rx.lock().expect("lock").is_none()  // Si rx est None, la thread est running
    }

    fn get_futures<M>(&self, middleware: Arc<M>, rabbitmq: Arc<RabbitMqExecutor>) -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
        where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
    {
        info!("Demarrage thread named queue {:?}", self.queue);
        let mut futures = FuturesUnordered::new();

        // Extraire le receiver
        let rx = {
            let mut guard = self.rx.lock().expect("lock");
            let rx = match guard.take() {
                Some(rx) => rx,
                None => Err(format!("NamedQueue rx n'est pas disponible, abort"))?
            };
            rx
        };

        // Ajouter consumers si presents
        {
            let mut guard = self.support_threads.lock().expect("lock");
            let consumers_option = guard.take();
            if let Some(consumers) = consumers_option {
                futures.extend(consumers)
            }
        }

        let tx_traitement = self.tx_traite.clone();

        futures.push(task::spawn(named_queue_consume(rabbitmq.clone(), self.tx.clone(), self.queue.clone())));
        futures.push(task::spawn(named_queue_traiter_messages(middleware, rx, self.queue.clone(), tx_traitement)));

        // futures.next().await.expect("run await").expect("run await resultat");
        Ok(futures)
    }
}

pub async fn named_queue_consume(rabbitmq: Arc<RabbitMqExecutor>, tx: Sender<MessageInterne>, queue: QueueType) {
    debug!("named_queue_consume Demarrage pour {:?}", queue);
    let mut first_run = true;

    loop {
        if ! first_run {
            tokio::time::sleep(ATTENTE_RECONNEXION).await;
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
        match ecouter_consumer(rabbitmq.clone(), channel, queue.clone(), tx_consumer).await {
            Ok(()) => (),
            Err(e) => {
                error!("named_queue_consume ecouter_consumer Error : {:?}", e);
            }
        }

        // Boucler, le sleep est au debut
        warn!("channel/consumer {:?} deconnecte, reconnexion dans 15 secondes", queue);
    }
}

async fn named_queue_traiter_messages<M>(
    middleware: Arc<M>,
    mut rx: Receiver<MessageInterne>,
    queue: QueueType,
    tx_traite: Sender<TypeMessage>
)
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages + 'static,
{
    let nom_queue = match queue {
        QueueType::ExchangeQueue(config) => config.nom_queue.clone(),
        QueueType::Triggers(nom, _securite) => nom,
        _ => panic!("named_queue_traiter_messages Type de queue non supporte")
    };
    debug!("named_queue_traiter_messages Demarrage queue {}", nom_queue);

    // Demarrer ecoute de messages
    while let Some(message) = rx.recv().await {
        debug!("NamedQueue.run Message recu : {:?}", message);
        let resultat = match message {
            MessageInterne::Delivery(delivery, _routing) => {
                match traiter_delivery(
                    middleware.as_ref(),
                    nom_queue.as_str(),
                    delivery
                ).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("named_queue_traiter_messages Erreur traitement message : {:?}", e);
                        None
                    }
                }
            },
            MessageInterne::Trigger(delivery, nom_queue) => {
                match traiter_delivery(
                    middleware.as_ref(),
                    nom_queue.as_str(),
                    delivery
                ).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("named_queue_traiter_messages Erreur traitement trigger : {:?}", e);
                        None
                    }
                }
            },
            _ => {
                debug!("named_queue_traiter_messages Type de message non-supporte, on l'ignore");
                None
            }
        };

        if let Some(message_traite) = resultat {
            if let Err(e) = tx_traite.send(message_traite).await {
                error!("named_queue_traiter_messages Erreur send message interne : {:?}", e);
            }
        }
    }

    info!("named_queue_traiter_messages Fermeture queue {:?}", nom_queue);
}

async fn creer_reply_q(rabbitmq: Arc<RabbitMqExecutor>, channel: &Channel, rq: &ReplyQueue) -> Queue {
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

    let queue_name = reply_queue.name().as_str();
    debug!("creer_reply_q Reply Q {}", queue_name);
    {
        let mut guard = rabbitmq.reply_q.lock().expect("lock");
        *guard = Some(queue_name.to_string());
    }

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

    let options = QueueDeclareOptions {
        passive: false,
        durable: false,
        exclusive: false,
        auto_delete: true,
        nowait: false,
    };

    let trigger_queue = channel
        .queue_declare(
            nom_queue.as_str(),
            options,
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
            String::from(format!("evenement.{}.{}", DOMAINE_NOM_MAITREDESCLES, COMMANDE_CERT_MAITREDESCLES)),
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
            // String::from(format!("evenement.{}.{}", DOMAINE_BACKUP, EVENEMENT_BACKUP_DECLENCHER)),
            String::from(format!("requete.{}.{}", nom_domaine, REQUETE_NOMBRE_TRANSACTIONS)),
            String::from(format!("commande.{}.{}", nom_domaine, EVENEMENT_BACKUP_DECLENCHER)),
            String::from(format!("evenement.backup.{}", EVENEMENT_BACKUP_DECLENCHER)),
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


async fn ecouter_consumer(rabbitmq: Arc<RabbitMqExecutor>, channel: Channel, queue_type: QueueType, tx: Sender<MessageInterne>) -> Result<(), String> {

    debug!("Ouvrir queue {:?}", queue_type);

    let queue = match &queue_type {
        QueueType::ExchangeQueue(c) => {
            let nom_queue = &c.nom_queue;

            let options = QueueDeclareOptions {
                passive: false,
                durable: c.durable,
                exclusive: false,
                auto_delete: c.autodelete,
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
            creer_reply_q(rabbitmq.clone(), &channel, &rq).await
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

        let (channel, delivery) = match delivery {
            Ok(r) => r,
            Err(e) => Err(format!("Erreur delivery message : {:?}", e))?
        };
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
    Ok(())
}

fn concatener_rk(message: &MessageOut) -> Result<String, String> {
    match &message.type_message {
        TypeMessageOut::Requete(r) |
        TypeMessageOut::Commande(r) |
        TypeMessageOut::Transaction(r) |
        TypeMessageOut::Evenement(r) => {
            let mut vec_rk = Vec::new();
            vec_rk.push(r.domaine.clone());
            if let Some(partition) = r.partition.as_ref() {
                vec_rk.push(partition.clone());
            }
            vec_rk.push(r.action.clone());
            Ok(vec_rk.join(".").into())
        }
        TypeMessageOut::Reponse(_) => Err(String::from("concatener_rk Type reponse non supporte"))
    }
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
        debug!("task_emettre_messages Emettre_message {}", compteur);

        // Extraire metadata de routage
        let (correlation_id, routing_key, exchanges) = match &message.type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) |
            TypeMessageOut::Evenement(r) => {
                let correlation_id = match r.correlation_id.as_ref() {
                    Some(inner) => inner,
                    None => &message.message_id
                };

                let routing_key = match concatener_rk(&message) {
                    Ok(inner) => inner,
                    Err(e) => {
                        error!("task_emettre_messages Erreur preparation routing key {:?}", e);
                        continue
                    }
                };

                (correlation_id, routing_key, Some(&r.exchanges))
            }
            TypeMessageOut::Reponse(r) => {
                (&r.correlation_id, String::from(""), None)
            }
        };

        // let routing_key = match &message.domaine {
        //     Some(_) => {
        //         let rk = match concatener_rk(&message) {
        //             Ok(rk) => rk,
        //             Err(e) => {
        //                 error!("task_emettre_messages Erreur preparation routing key {:?}", e);
        //                 continue
        //             }
        //         };
        //
        //         match &message.type_message {
        //             TypeMessageOut::Requete(_) => format!("requete.{}", rk),
        //             TypeMessageOut::Commande(_) => format!("commande.{}", rk),
        //             TypeMessageOut::Transaction(_) => format!("transaction.{}", rk),
        //             TypeMessageOut::Reponse(_) => {
        //                 error!("Reponse avec domaine non supportee");
        //                 continue;
        //             },
        //             TypeMessageOut::Evenement => format!("evenement.{}", rk),
        //         }
        //     },
        //     None => String::from(""),
        // };

        // let message_serialise = match MessageSerialise::from_parsed(message.message) {
        //     Ok(m) => m,
        //     Err(e) => {
        //         error!("task_emettre_messages Erreur traitement message, on drop : {:?}", e);
        //         continue;
        //     },
        // };
        // let contenu = &message_serialise.parsed;

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
                    warn!("Erreur ouverture channel, reessayer plus tard : {:?}", e);
                    continue
                }
            }
        };

        let channel = channel_opt.as_ref().expect("channel");

        // let correlation_id = contenu.id.as_str();
        // let correlation_id = match message.correlation_id.as_ref() {
        //     Some(inner) => inner.as_str(),
        //     None => contenu.id.as_str()
        // };
        debug!("Emettre_message id {} (correlation {})", message.message_id, correlation_id);

        // let exchanges = match &message.exchanges {
        //     Some(e) => Some(e.clone()),
        //     None => {
        //         let securite = rabbitmq.securite.clone();
        //         match message.type_message {
        //             TypeMessageOut::Reponse => None,  // Aucun exchange pour une reponse
        //             _ => Some(vec![securite])  // Toutes les autre reponses, prendre exchange defaut
        //         }
        //     }
        // };

        let options = BasicPublishOptions::default();
        // let payload = message_serialise.get_str().as_bytes().to_vec();
        let payload = message.message.buffer;

        let properties = {
            let mut properties = BasicProperties::default()
                .with_correlation_id(correlation_id.clone().into());

            match &message.type_message {
                TypeMessageOut::Reponse(r) => {
                    // Repondre vers une Q
                    let reply_to = r.reply_to.as_str();
                    debug!("task_emettre_messages Emission message, reply_q en parametre : {:?}", r);
                    properties = properties.with_reply_to(reply_to.into());
                },
                _ => {
                    // Donner le reply_q local pour recevoir une reponse
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

            // match &message.replying_to {
            //     Some(r) => {
            //         debug!("task_emettre_messages Emission message, reply_q en parametre : {:?}", r);
            //         properties = properties.with_reply_to(r.as_str().into());
            //     },
            //     None => {
            //         let lock_reply_q = rabbitmq.reply_q.lock().expect("lock");
            //         debug!("task_emettre_messages Emission message, reply_q locale : {:?}", lock_reply_q);
            //         match lock_reply_q.as_ref() {
            //             Some(qs) => {
            //                 properties = properties.with_reply_to(qs.as_str().into());
            //             },
            //             None => ()
            //         };
            //     }
            // }

            properties
        };

        match &message.type_message {
            TypeMessageOut::Reponse(r) => {
                // Reply
                // let reply_to = message.replying_to.expect("reply_q");
                let reply_to = r.reply_to.as_str();
                debug!("task_emettre_messages Emission message vers reply_q {} avec correlation_id {}", reply_to, correlation_id);

                // C'est une reponse (message direct)
                let resultat = channel.basic_publish(
                    "",
                    reply_to,
                    options,
                    payload.to_vec(),
                    properties
                ).await;
                if resultat.is_err() {
                    error!("task_emettre_messages Erreur emission message {:?}", resultat);
                } else {
                    debug!("task_emettre_messages Reponse {} emise vers {:?}", correlation_id, reply_to);
                }
            },
            _ => {
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
                            match resultat {
                                Ok(_) => {
                                    debug!("task_emettre_messages Message {} emis sur {:?}", routing_key, exchange)
                                },
                                Err(e) => {
                                    error!("task_emettre_messages Erreur emission message {:?}", e)
                                }
                            }
                        }
                    },
                    None => warn!("Message {} sans exchanges - SKIP", message.message_id)
                }
            }
        }

        // match exchanges {
        //     Some(inner) => {
        //         for exchange in inner {
        //             let resultat = channel.basic_publish(
        //                 exchange.get_str(),
        //                 &routing_key,
        //                 options,
        //                 payload.clone(),
        //                 properties.clone()
        //             ).await;
        //             match resultat {
        //                 Ok(()) => {
        //                     debug!("task_emettre_messages Message {} emis sur {:?}", routing_key, exchange)
        //                 },
        //                 Err(e) => {
        //                     error!("task_emettre_messages Erreur emission message {:?} : {:?}", resultat, e)
        //                 }
        //             }
        //         }
        //     },
        //     None => {
        //         // Reply
        //         let reply_to = message.replying_to.expect("reply_q");
        //         debug!("task_emettre_messages Emission message vers reply_q {} avec correlation_id {}", reply_to, correlation_id);
        //
        //         // C'est une reponse (message direct)
        //         let resultat = channel.basic_publish(
        //             "",
        //             &reply_to,
        //             options,
        //             payload.to_vec(),
        //             properties
        //         ).await;
        //         if resultat.is_err() {
        //             error!("task_emettre_messages Erreur emission message {:?}", resultat);
        //         } else {
        //             debug!("task_emettre_messages Reponse {} emise vers {:?}", correlation_id, reply_to);
        //         }
        //     }
        // }
    };

    info!("emettre_message : Fin thread");
}

#[derive(Debug)]
pub struct AttenteReponse {
    pub correlation: String,
    pub sender: SenderOneshot<TypeMessage>,
    pub expiration: DateTime<Utc>,
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
    pub message: MessageMilleGrillesBufferDefault,
    message_id: String,
    type_message: TypeMessageOut,
    attente_expiration: Option<DateTime<Utc>>,
}

impl MessageOut {
    pub fn new<M,S>(
        type_message: TypeMessageOut,
        message_id: S,
        message: M,
        attente_expiration: Option<DateTime<Utc>>
    ) -> Self
        where
            M: Into<MessageMilleGrillesBufferDefault>,
            S: Into<String>
    {
        let message = message.into();
        Self {
            message,
            message_id: message_id.into(),
            type_message,
            attente_expiration,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeMessageOut {
    Requete(RoutageMessageAction),
    Commande(RoutageMessageAction),
    Transaction(RoutageMessageAction),
    Reponse(RoutageMessageReponse),
    Evenement(RoutageMessageAction),
}

impl From<MessageKind> for TypeMessageOut {
    fn from(value: MessageKind) -> Self {
        value.into()
    }
}

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
