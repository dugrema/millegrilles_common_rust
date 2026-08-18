
use std::marker::Send;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::debug;


use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, RoutageMessage};
use millegrilles_cryptographie::x509::EnveloppePrivee;
use serde::Serialize;



// use crate::chiffrage_cle::CommandeSauvegarderCle;

use crate::configuration::ConfigurationPki;
use crate::constantes::*;
use crate::formatteur_messages::{build_message_action, build_reponse, FormatteurMessage};

use crate::rabbitmq_dao::{MessageOut, MqMessageSendInformation, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;

/// Conserve l'information de routage in/out d'un message
#[derive(Clone, Debug, PartialEq)]
pub struct RoutageMessageAction {
    pub domaine: String,
    pub action: String,
    pub user_id: Option<String>,
    pub partition: Option<String>,
    pub exchanges: Vec<Securite>,
    pub reply_to: Option<String>,
    pub correlation_id: Option<String>,
    pub ajouter_reply_q: bool,
    pub blocking: Option<bool>,
    pub ajouter_ca: bool,
    pub timeout_blocking: Option<u64>,
    pub queue_reception: Option<String>,
}
impl RoutageMessageAction {

    pub fn new<S,T,V>(domaine: S, action: T, exchanges: V) -> Self
        where S: Into<String>, T: Into<String>, V: Into<Vec<Securite>>
    {
        RoutageMessageAction {
            domaine: domaine.into(),
            action: action.into(),
            user_id: None,
            partition: None, exchanges: exchanges.into(), reply_to: None, correlation_id: None,
            ajouter_reply_q: false, blocking: None, ajouter_ca: false, timeout_blocking: None,
            queue_reception: None
        }
    }

    pub fn builder<S,T,V>(domaine: S, action: T, exchanges: V) -> RoutageMessageActionBuilder
        where S: Into<String>, T: Into<String>, V: Into<Vec<Securite>>
    {
        RoutageMessageActionBuilder::new(domaine, action, exchanges)
    }

}

impl<'a> Into<RoutageMessage<'a>> for &'a RoutageMessageAction {
    fn into(self) -> RoutageMessage<'a> {
        RoutageMessage {
            action: Some(self.action.as_str()),
            domaine: Some(self.domaine.as_str()),
            user_id: match self.user_id.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            partition: match self.partition.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
        }
    }
}

pub struct RoutageMessageActionBuilder {
    domaine: String,
    action: String,
    user_id: Option<String>,
    partition: Option<String>,
    exchanges: Vec<Securite>,
    reply_to: Option<String>,
    correlation_id: Option<String>,
    ajouter_reply_q: bool,
    blocking: Option<bool>,
    ajouter_ca: bool,
    timeout_blocking: Option<u64>,
    queue_reception: Option<String>,
}
impl RoutageMessageActionBuilder {
    pub fn new<S,T,V>(domaine: S, action: T, exchanges: V) -> Self
        where S: Into<String>, T: Into<String>, V: Into<Vec<Securite>>
    {
        RoutageMessageActionBuilder {
            domaine: domaine.into(),
            action: action.into(),
            user_id: None,
            partition: None, exchanges: exchanges.into(), reply_to: None, correlation_id: None,
            ajouter_reply_q: false, blocking: None, ajouter_ca: false, timeout_blocking: None,
            queue_reception: None,
        }
    }

    pub fn user_id<S>(mut self, user_id: S) -> Self
        where S: Into<String>
    {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn partition<S>(mut self, partition: S) -> Self
        where S: Into<String>
    {
        self.partition = Some(partition.into());
        self
    }

    pub fn reply_to<S>(mut self, reply_to: S) -> Self
        where S: Into<String>
    {
        self.reply_to = Some(reply_to.into());
        self
    }

    pub fn correlation_id<S>(mut self, correlation_id: S) -> Self
        where S: Into<String>
    {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    pub fn ajouter_reply_q(mut self, flag: bool) -> Self
    {
        self.ajouter_reply_q = flag;
        self
    }

    pub fn blocking(mut self, flag: bool) -> Self
    {
        self.blocking = Some(flag);
        self
    }

    pub fn ajouter_ca(mut self, flag: bool) -> Self
    {
        self.ajouter_ca = flag;
        self
    }

    pub fn timeout_blocking(mut self, timeout_blocking: u64) -> Self {
        self.timeout_blocking = Some(timeout_blocking);
        self
    }

    pub fn queue_reception<S>(mut self, queue_reception: S) -> Self
        where S: Into<String>
    {
        self.queue_reception = Some(queue_reception.into());
        self
    }

    pub fn build(self) -> RoutageMessageAction {
        RoutageMessageAction {
            domaine: self.domaine,
            action: self.action,
            user_id: self.user_id,
            partition: self.partition,
            exchanges: self.exchanges.into(),
            reply_to: self.reply_to,
            correlation_id: self.correlation_id,
            ajouter_reply_q: self.ajouter_reply_q,
            blocking: self.blocking,
            ajouter_ca: self.ajouter_ca,
            timeout_blocking: self.timeout_blocking,
            queue_reception: self.queue_reception,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoutageMessageReponse {
    pub reply_to: String,
    pub correlation_id: String,
}
impl RoutageMessageReponse {
    pub fn new<S, T>(reply_to: S, correlation_id: T) -> Self
        where S: Into<String>, T: Into<String>
    {
        RoutageMessageReponse {
            reply_to: reply_to.into(),
            correlation_id: correlation_id.into(),
        }
    }
}

#[async_trait]
pub trait GenerateurMessages: FormatteurMessage + Send + Sync {
    async fn emettre_evenement<R,M>(&self, routage: R, message: M)
        -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync;

    async fn transmettre_requete<R,M>(&self, routage: R, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync;

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync;

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync;

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync;

    /// Emettre un message en str deja serialise
    async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where M: Into<MessageMilleGrillesBufferDefault> + Send;

    fn mq_disponible(&self) -> bool;

    /// Active le mode regeneration
    fn set_regeneration(&self);

    /// Desactive le mode regeneration
    fn reset_regeneration(&self);

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_mode_regeneration(&self) -> bool;

    fn get_securite(&self) -> &Securite;

    fn is_dev(&self) -> bool;
}

pub struct GenerateurMessagesImpl {
    // tx_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    // tx_reply: Sender<MessageInterne>,
    rabbitmq: Arc<RabbitMqExecutor>,
    enveloppe_privee: Mutex<Arc<EnveloppePrivee>>,
    mode_regeneration: Mutex<bool>,
    securite: Securite,
    dev: bool,
}

impl GenerateurMessagesImpl {

    pub fn new(config: &ConfigurationPki, rabbitmq: Arc<RabbitMqExecutor>, dev: bool) -> Self {
        let securite = rabbitmq.securite.clone();
        Self {
            rabbitmq,
            enveloppe_privee: Mutex::new(config.get_enveloppe_privee()),
            mode_regeneration: Mutex::new(false),
            securite,
            dev,
        }
    }
}

#[async_trait]
impl GenerateurMessages for GenerateurMessagesImpl {

    async fn emettre_evenement<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        // if self.get_mode_regeneration() {  // Rien a faire
        //     return Ok(())
        // }

        let mut routage = routage.into();

        // Batir message
        let (message, message_id) = {
            let guard_enveloppe_privee = self.enveloppe_privee.lock().expect("lock");
            build_message_action(millegrilles_cryptographie::messages_structs::MessageKind::Evenement,
                                 routage.clone(), message, guard_enveloppe_privee.as_ref())?
        };

        // Completer routage avec nouveau correlation_id
        if routage.correlation_id.is_none() {
            routage.correlation_id = Some(message_id);
        }
        let type_message = TypeMessageOut::Evenement(routage);

        self.emettre_message(type_message, message).await?;

        Ok(())
    }

    async fn transmettre_requete<R,M>(&self, routage: R, message: M) -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let mut routage = routage.into();

        let blocking = routage.blocking.clone().unwrap_or_else(|| true);

        let (message, message_id) = {
            let guard_enveloppe_privee = self.enveloppe_privee.lock().expect("lock");
            build_message_action(millegrilles_cryptographie::messages_structs::MessageKind::Requete,
                                 routage.clone(), message, guard_enveloppe_privee.as_ref())?
        };
        if routage.correlation_id.is_none() {
            routage.correlation_id = Some(message_id);
        }
        let type_message = TypeMessageOut::Requete(routage);

        match self.emettre_message(type_message, message).await? {
            Some(inner) => Ok(Some(inner)),
            None => {
                if blocking {
                    Err(String::from("Aucune reponse"))?
                } else {
                    Ok(None)
                }
            },
        }
    }

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M) -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let mut routage = routage.into();

        let (message, message_id) = {
            let guard_enveloppe_privee = self.enveloppe_privee.lock().expect("lock");
            build_message_action(millegrilles_cryptographie::messages_structs::MessageKind::Transaction,
                                 routage.clone(), message, guard_enveloppe_privee.as_ref())?
        };
        if routage.correlation_id.is_none() {
            routage.correlation_id = Some(message_id);
        }
        let type_message = TypeMessageOut::Transaction(routage);

        self.emettre_message(type_message, message).await
    }

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        let mut routage = routage.into();

        let (message, message_id) = {
            let guard_enveloppe_privee = self.enveloppe_privee.lock().expect("lock");
            build_message_action(millegrilles_cryptographie::messages_structs::MessageKind::Commande,
                                 routage.clone(), message, guard_enveloppe_privee.as_ref())?
        };
        if routage.correlation_id.is_none() {
            routage.correlation_id = Some(message_id);
        }
        let type_message = TypeMessageOut::Commande(routage);

        self.emettre_message(type_message, message).await
    }

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync
    {
        let (message, _message_id) = {
            let guard_enveloppe_privee = self.enveloppe_privee.lock().expect("lock");
            build_reponse(message, guard_enveloppe_privee.as_ref())?
        };
        let type_message = TypeMessageOut::Reponse(routage.into());

        self.emettre_message(type_message, message).await?;

        Ok(())
    }

    async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M)
                                -> Result<Option<TypeMessage>, crate::error::Error>
        where M: Into<MessageMilleGrillesBufferDefault> + Send
    {
        let message = message.into();

        let (attendre, timeout_blocking, correlation_id) = match &type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) => {
                let correlation_id = match r.correlation_id.as_ref() {
                    Some(inner) => inner.as_str(),
                    None => Err(String::from("emettre_message Correlation_id manquant"))?,
                };
                let attendre = r.blocking.unwrap_or_else(|| true);
                (attendre, r.timeout_blocking.clone(), correlation_id.to_string())
            }
            TypeMessageOut::Reponse(r) => {
                (false, None, r.correlation_id.clone())
            }
            TypeMessageOut::Evenement(r) => {
                let correlation_id = match r.correlation_id.as_ref() {
                    Some(inner) => inner.as_str(),
                    None => Err(String::from("emettre_message Correlation_id manquant"))?,
                };
                (false, None, correlation_id.to_string())
            }
        };

        let attente_expiration = match attendre {
            true => {
                let timeout_messages = timeout_blocking.unwrap_or_else(|| 15_000);
                let expiration: DateTime<Utc> = Utc::now() + chrono::Duration::milliseconds(timeout_messages as i64);
                Some(expiration)
            },
            false => {
                None
            }
        };

        let message_out = MessageOut::new(type_message, &correlation_id, message, attente_expiration);

        // Emettre la requete sur MQ
        debug!("emettre_message_millegrille Emettre requete correlation {}", correlation_id);
        if let Some(rx) = self.rabbitmq.send_out(message_out).await? {
            match rx.await {
                Ok(r) => Ok(Some(r)),
                Err(e) => {
                    Err(format!("generateur_messages.emettre_message_millegrille Erreur reception reponse {} : {:?}", correlation_id, e))?
                }
            }
        } else {
            Ok(None)
        }
    }

    fn mq_disponible(&self) -> bool {
        self.rabbitmq.est_connecte()
    }

    fn set_regeneration(&self) {
        let mode = &self.mode_regeneration;
        let mut guard = mode.lock().expect("guard");
        *guard = true;
    }

    /// Desactive le mode regeneration
    fn reset_regeneration(&self) {
        let mode = &self.mode_regeneration;
        let mut guard = mode.lock().expect("guard");
        *guard = false;
    }

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_mode_regeneration(&self) -> bool {
        let mode = &self.mode_regeneration;
        *mode.lock().expect("lock")
    }

    fn get_securite(&self) -> &Securite {
        &self.securite
    }

    fn is_dev(&self) -> bool {
        self.dev
    }
}

impl FormatteurMessage for GenerateurMessagesImpl {
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
        self.enveloppe_privee.lock().expect("enveloppe").clone()
    }

    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
        let mut guard = self.enveloppe_privee.lock().expect("lock");
        *guard = enveloppe;
    }
}
