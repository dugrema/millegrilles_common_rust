use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::sync::mpsc::SendError;
use std::thread::sleep;
use std::time::Duration;

use async_trait::async_trait;
use futures::Future;
use futures::stream::FuturesUnordered;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, options::*, publisher_confirm::Confirmation, Queue, Result as ResultLapin, tcp::{OwnedIdentity, OwnedTLSConfig}, types::FieldTable};
use lapin::message::Delivery;
use log::{debug, error, info};
use serde_json::Value;
use tokio::{task, try_join};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}, oneshot::Sender as SenderOneshot};
use tokio::task::JoinHandle;
use tokio_amqp::*;
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppePrivee, ValidateurX509};
use crate::configuration::{ConfigMessages, ConfigurationMq, ConfigurationPki};
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageSerialise};

use crate::recepteur_messages::TypeMessage;

const ATTENTE_RECONNEXION: Duration = Duration::from_millis(15_000);

pub struct RabbitMq {
    pub connexion: Connection,
}

impl RabbitMq {
}

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
}

#[derive(Clone, Debug)]
pub enum QueueType {
    ExchangeQueue(ConfigQueue),
    ReplyQueue(ReplyQueue),
    Triggers(String),
}

pub async fn initialiser(configuration: &impl ConfigMessages) -> Result<RabbitMq, String> {

    let connexion = connecter(configuration).await;

    Ok(RabbitMq{
        connexion,
    })
}

async fn connecter(configuration: &impl ConfigMessages) -> Connection {
    let pki = configuration.get_configuration_pki();
    let mq = configuration.get_configuration_mq();

    let tls_config = get_tls_config(pki, mq);
    let idmg = pki.get_validateur().idmg().to_owned();
    let addr = format!("amqps://{}:{}/{}?auth_mechanism=external", mq.host, mq.port, idmg);

    let connexion = Connection::connect_with_config(
        &addr,
        ConnectionProperties::default().with_tokio(),
        tls_config.as_ref(),
    ).await.expect("Connecte a RabbitMQ");
    connexion
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

pub fn executer_mq<'a>(
    configuration: Arc<impl ConfigMessages + 'static>,
    queues: Option<Vec<QueueType>>,
    formatteur: Arc<FormatteurMessage>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>,
) -> Result<RabbitMqExecutor, String> {

    // Creer le channel utilise pour recevoir et traiter les messages mis sur les Q
    let (tx_traiter_message, rx_traiter_message) = mpsc::channel(5);
    let (tx_traiter_trigger, rx_traiter_trigger) = mpsc::channel(5);

    // Preparer recepteur de tx_message_out pour emettre des messages vers MQ (cree dans la boucle)
    let tx_message_out = Arc::new(Mutex::new(None));

    let boucle_execution = tokio::spawn(
        boucle_execution(
            configuration,
            queues,
            tx_traiter_message.clone(),
            tx_traiter_trigger.clone(),
            tx_message_out.clone(),
            listeners,
        )
    );

    Ok(RabbitMqExecutor {
        handle: boucle_execution,
        formatteur,
        rx_messages: rx_traiter_message,
        rx_triggers: rx_traiter_trigger,
        tx_out: tx_message_out.clone(),
        tx_interne: tx_traiter_message.clone(),
        reply_q: Arc::new(Mutex::new(None)),
    })
}

#[async_trait]
pub trait MqMessageSendInformation {
    async fn send_out(&self, message: MessageOut) -> Result<(), String>;
    fn get_reqly_q_name(&self) -> Option<String>;
}

pub struct RabbitMqExecutor {
    handle: JoinHandle<()>,
    pub formatteur: Arc<FormatteurMessage>,
    pub rx_messages: Receiver<MessageInterne>,
    pub rx_triggers: Receiver<MessageInterne>,
    pub tx_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    pub tx_interne: Sender<MessageInterne>,
    pub reply_q: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl MqMessageSendInformation for RabbitMqExecutor {
    async fn send_out(&self, message: MessageOut) -> Result<(), String> {
        let sender = {
            let sender = self.tx_out.lock().expect("lock");
            match sender.as_ref() {
                Some(inner) => Ok(inner.clone()),
                None => Err(String::from("Sender pas pret")),
            }
        }?;

        match sender.send(message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur send {:?}", e)),
        }
    }

    fn get_reqly_q_name(&self) -> Option<String> {
        self.reply_q.lock().expect("lock").clone()
    }
}

async fn boucle_execution(
    configuration: Arc<impl ConfigMessages + 'static>,
    queues: Option<Vec<QueueType>>,
    tx_traiter_delivery: Sender<MessageInterne>,
    tx_traiter_trigger: Sender<MessageInterne>,
    tx_message_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    listeners: Option<Mutex<Callback<'_, EventMq>>>
) {

    let vec_queues = match queues {
        Some(v) => v,
        None => Vec::new(),
    };

    loop {
        let resultat = {
            let mq: RabbitMq = initialiser(configuration.as_ref()).await.expect("Erreur connexion RabbitMq");
            let conn = &mq.connexion;

            // Setup channels MQ
            let channel_reponses = conn.create_channel().await.unwrap();
            let channel_out = conn.create_channel().await.unwrap();

            // Setup mpsc
            // let (tx_delivery, rx_delivery) = mpsc::channel(5);
            let (tx_out, rx_out) = mpsc::channel(3);

            // Injecter tx_out dans tx_message_arc
            {
                let mut guard = tx_message_out.as_ref().lock().expect("Erreur injection tx_message");
                *guard = Some(tx_out);
            }

            let mut futures = FuturesUnordered::new();

            // Demarrer tasks de Q
            {
                let pki = configuration.get_configuration_pki();
                // let pki = match configuration.as_ref() {
                //     TypeConfiguration::ConfigurationMessages {mq: _mq, pki} => pki,
                //     TypeConfiguration::ConfigurationMessagesDb {mq: _mq, mongo: _mongo, pki} => pki,
                // };

                let reply_q = ReplyQueue {
                    fingerprint_certificat: pki.get_enveloppe_privee().fingerprint().to_owned(),
                    securite: Securite::L3Protege,
                    ttl: Some(300000),
                };
                futures.push(task::spawn(ecouter_consumer(
                    channel_reponses,
                    QueueType::ReplyQueue(reply_q),
                    tx_traiter_delivery.clone()
                )));
            }

            for config_q in &vec_queues {
                let channel_main = conn.create_channel().await.unwrap();

                let sender = match &config_q {
                    QueueType::ExchangeQueue(_) => tx_traiter_delivery.clone(),
                    QueueType::ReplyQueue(_) => tx_traiter_delivery.clone(),
                    QueueType::Triggers(_) => tx_traiter_trigger.clone(),
                };

                futures.push(task::spawn(
                    ecouter_consumer(channel_main,config_q.clone(),sender)
                ));
            }

            // Demarrer tasks de traitement de messages
            // futures.push(task::spawn(task_pretraiter_messages(rx_delivery, tx_traiter_message.clone())));
            futures.push(task::spawn(task_emettre_messages(configuration.clone(), channel_out, rx_out)));

            // Emettre message connexion completee
            match &listeners {
                Some(inner) => {
                    debug!("MQ Connecte, appel les listeners");
                    inner.lock().expect("callback").call(EventMq::Connecte);
                },
                None => {
                    debug!("MQ Connecte, aucuns listeners");
                }
            }

            info!("Debut execution consumers MQ");
            let arret = futures.next().await;

            arret
        };

        info!("Fin execution consumers MQ/deconnexion, resultat : {:?}", resultat);

        // S'assurer de vider sender immediatement
        {
            let mut guard = tx_message_out.as_ref().lock().expect("Erreur nettoyage tx_message");
            *guard = None;
        }

        // Emettre message connexion perdue
        match &listeners {
            Some(inner) => {
                debug!("MQ Connecte, appel les listeners");
                inner.lock().expect("callback").call(EventMq::Deconnecte);
            },
            None => {
                debug!("MQ Connecte, aucuns listeners");
            }
        }

        // Attendre et redemarrer la connexion MQ
        sleep(ATTENTE_RECONNEXION);
        continue;
    }
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
        Some(v) => params.insert("ttl".into(), v.into()),
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
        // Ecouter les evenements de tiers qui emettent leur certificat
        "evenement.certificat.infoCertificat".into(),
        // Ecouter les requetes pour notre certificat
        rk_fingerprint,
    );
    let exchanges: Vec<String> = vec!("3.protege".into(), "2.prive".into(), "1.public".into());

    let nom_queue = reply_queue.name().as_str();
    for rk in routing_keys {
        for exchange in &exchanges {
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

    reply_queue
}

async fn creer_internal_q(nom_domaine: String, channel: &Channel) -> Queue {
    let mut params = FieldTable::default();
    params.insert("ttl".into(), 300000.into());  // 5 minutes max pour traitement events

    let nom_queue = format!("{}/triggers", nom_domaine);

    let trigger_queue = channel
        .queue_declare(
            nom_queue.as_str(),
            QueueDeclareOptions::default(),
            params,
        ).await.unwrap();

    // Ajouter routing keys pour ecouter evenements certificats, requete cert local
    let routing_keys = vec!(
        // Ecouter les evenements internes
        String::from(format!("evenement.{}.transaction_persistee", nom_domaine)),
    );
    let exchanges: Vec<String> = vec!("4.secure".into());

    let nom_queue = trigger_queue.name().as_str();
    for rk in routing_keys {
        for exchange in &exchanges {
            let _ = channel.queue_bind(
                nom_queue,
                &exchange,
                &rk,
                QueueBindOptions::default(),
                FieldTable::default()
            ).await.expect("Binding routing key");
        }
    }

    debug!("Creation trigger-Q secure {:?}", trigger_queue);

    trigger_queue
}


async fn ecouter_consumer(channel: Channel, queue_type: QueueType, mut tx: Sender<MessageInterne>) {

    debug!("Ouvrir queue {:?}", queue_type);

    let queue = match &queue_type {
        QueueType::ExchangeQueue(c) => {
            let nom_queue = &c.nom_queue;

            let mut options = QueueDeclareOptions {
                passive: false,
                durable: c.durable,
                exclusive: false,
                auto_delete: false,
                nowait: false,
            };

            let mut params = FieldTable::default();
            match c.ttl {
                Some(v) => params.insert("ttl".into(), v.into()),
                None => ()
            }

            let queue = channel.queue_declare(&nom_queue, options, params).await.unwrap();

            // Ajouter tous les routing keys a la Q
            for rk in &c.routing_keys {
                let routing_key = rk.routing_key.as_str();
                let exchange = securite_str(&rk.exchange);
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
        QueueType::Triggers(nom_domaine) => {
            creer_internal_q(nom_domaine.to_owned(), &channel).await
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

        let (_, delivery) = delivery.expect("error in consumer");

        let acker = delivery.acker.clone();

        let message_interne = match &queue_type {
            QueueType::ExchangeQueue(_q) => MessageInterne::Delivery(delivery),
            QueueType::ReplyQueue(_q) => MessageInterne::Delivery(delivery),
            QueueType::Triggers(_q) => MessageInterne::Trigger(delivery),
        };

        // Ajouter message sur Q interne
        match tx.send(message_interne).await {
            Ok(()) => {
                // Emettre le Ack
                acker.ack(BasicAckOptions::default())
                    .await
                    .expect("ack");
            },
            Err(e) => {
                // Erreur de queuing interne, emettre un nack (remet message sur la Q)
                debug!("Erreur Q interne, NACK : {:?}", e);
                acker.nack(BasicNackOptions::default())
                    .await
                    .expect("ack");
            }
        }
    }
}

async fn task_emettre_messages(configuration: Arc<impl ConfigMessages>, channel: Channel, mut rx: Receiver<MessageOut>) {
    let mut compteur: u64 = 0;
    let mq = configuration.get_configuration_mq();
    // let mq = match configuration.as_ref() {
    //     TypeConfiguration::ConfigurationMessages {mq, pki} => mq,
    //     TypeConfiguration::ConfigurationMessagesDb {mq, mongo, pki} => mq,
    // };
    let exchange_defaut = &mq.exchange_default;
    debug!("rabbitmq_dao.emettre_message : Demarrage thread, exchange defaut {}", exchange_defaut);

    while let Some(message) = rx.recv().await {
        compteur += 1;
        debug!("Emettre_message {}, On a recu de quoi", compteur);
        let contenu = message.message;

        let entete = &contenu.entete;
        debug!("Emettre_message {:?}", entete);

        let correlation_id = match &message.correlation_id {
            Some(c) => c.as_str(),
            None => &entete.uuid_transaction.as_str()
        };

        let routing_key = match &message.domaine_action {
            Some(rk) => rk.as_str(),
            None => "",
        };
        let options = BasicPublishOptions::default();
        let payload = contenu.message.as_bytes().to_vec();
        let mut properties = BasicProperties::default()
            .with_correlation_id(correlation_id.into());

        // if let Some(reply_q) = message.replying_to {
        //     debug!("Emission message vers reply_q {} avec correlation_id {}", reply_q, correlation_id);
        //     properties = properties.with_reply_to(reply_q.into());
        // }

        match message.exchanges {
            Some(inner) => {
                for exchange in inner {
                    let resultat = channel.basic_publish(
                        securite_str(&exchange),
                        routing_key,
                        options,
                        payload.clone(),
                        properties.clone()
                    ).wait();
                    if resultat.is_err() {
                        error!("Erreur emission message {:?}", resultat)
                    } else {
                        debug!("Message {} emis sur {:?}", routing_key, exchange)
                    }
                }
            },
            None => {
                let reply_to = message.replying_to.expect("reply_q");
                debug!("Emission message vers reply_q {} avec correlation_id {}", reply_to, correlation_id);

                // C'est une reponse (message direct)
                let resultat = channel.basic_publish(
                    "",
                    &reply_to,
                    options,
                    payload.to_vec(),
                    properties
                ).wait();
                if resultat.is_err() {
                    error!("Erreur emission message {:?}", resultat);
                } else {
                    debug!("Message {} emis sur {:?}", routing_key, exchange_defaut);
                }
            }
        }
    };

    debug!("rabbitmq_dao.emettre_message : Fin thread");
}

#[derive(Debug)]
pub struct AttenteReponse {
    pub correlation: String,
    pub sender: SenderOneshot<TypeMessage>,
}

#[derive(Debug)]
pub enum MessageInterne {
    Delivery(Delivery),
    Trigger(Delivery),
    AttenteReponse(AttenteReponse),
    CancelDemandeReponse(String),
}

#[derive(Clone, Debug)]
pub struct MessageOut {
    pub message: MessageSerialise,
    type_message: TypeMessageOut,
    domaine_action: Option<String>,
    exchanges: Option<Vec<Securite>>,     // Utilise pour emission de message avec domaine_action
    correlation_id: Option<String>,
    replying_to: Option<String>,    // Utilise pour une reponse
}

impl MessageOut {
    pub fn new(domaine_action: &str, message: MessageSerialise, type_message: TypeMessageOut, exchanges: Option<Vec<Securite>>) -> MessageOut {
        if type_message == TypeMessageOut::Reponse {
            panic!("Reponse non supportee, utiliser MessageOut::new_reply()");
        }

        let uuid_transaction = {
            let entete = &message.entete;
            entete.uuid_transaction.clone()
        };

        let exchange_effectif = match exchanges {
            Some(e) => e,
            None => vec!(Securite::L3Protege),
        };

        MessageOut {
            message,
            type_message,
            domaine_action: Some(domaine_action.to_owned()),
            exchanges: Some(exchange_effectif),
            correlation_id: Some(uuid_transaction),
            replying_to: None,
        }
    }

    pub fn new_reply(message: MessageSerialise, correlation_id: &str, replying_to: &str) -> MessageOut {
        MessageOut {
            message,
            type_message: TypeMessageOut::Reponse,
            domaine_action: None,
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

