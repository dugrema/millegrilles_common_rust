use std::marker::Send;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::debug;
use serde::Serialize;
use tokio::sync;

use crate::certificats::EnveloppePrivee;
use crate::configuration::ConfigurationPki;
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::middleware::IsConfigurationPki;
use crate::rabbitmq_dao::{MessageOut, MqMessageSendInformation, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;

/// Conserve l'information de routage in/out d'un message
#[derive(Clone, Debug)]
pub struct RoutageMessageAction {
    domaine: String,
    action: String,
    partition: Option<String>,
    exchanges: Option<Vec<Securite>>,
    reply_to: Option<String>,
    correlation_id: Option<String>,
    ajouter_reply_q: bool,
    blocking: Option<bool>,
    ajouter_ca: bool,
    timeout_blocking: Option<u64>,
}
impl RoutageMessageAction {

    pub fn new<S>(domaine: S, action: S) -> Self
        where S: Into<String>
    {
        RoutageMessageAction {
            domaine: domaine.into(),
            action: action.into(),
            partition: None, exchanges: None, reply_to: None, correlation_id: None,
            ajouter_reply_q: false, blocking: None, ajouter_ca: false, timeout_blocking: None,
        }
    }

    pub fn builder<S>(domaine: S, action: S) -> RoutageMessageActionBuilder
        where S: Into<String>
    {
        RoutageMessageActionBuilder::new(domaine, action)
    }

}

pub struct RoutageMessageActionBuilder {
    domaine: String,
    action: String,
    partition: Option<String>,
    exchanges: Option<Vec<Securite>>,
    reply_to: Option<String>,
    correlation_id: Option<String>,
    ajouter_reply_q: bool,
    blocking: Option<bool>,
    ajouter_ca: bool,
    timeout_blocking: Option<u64>,
}
impl RoutageMessageActionBuilder {
    pub fn new<S>(domaine: S, action: S) -> Self
        where S: Into<String>
    {
        RoutageMessageActionBuilder {
            domaine: domaine.into(),
            action: action.into(),
            partition: None, exchanges: None, reply_to: None, correlation_id: None,
            ajouter_reply_q: false, blocking: None, ajouter_ca: false, timeout_blocking: None,
        }
    }

    pub fn partition<S>(mut self, partition: S) -> Self
        where S: Into<String>
    {
        self.partition = Some(partition.into());
        self
    }

    pub fn exchanges<V>(mut self, exchanges: V) -> Self
        where V: AsRef<Vec<Securite>>
    {
        self.exchanges = Some(exchanges.as_ref().to_owned());
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

    pub fn build(self) -> RoutageMessageAction {
        RoutageMessageAction {
            domaine: self.domaine,
            action: self.action,
            partition: self.partition,
            exchanges: self.exchanges,
            reply_to: self.reply_to,
            correlation_id: self.correlation_id,
            ajouter_reply_q: self.ajouter_reply_q,
            blocking: self.blocking,
            ajouter_ca: self.ajouter_ca,
            timeout_blocking: self.timeout_blocking,
        }
    }
}

#[derive(Clone, Debug)]
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
    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync;

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync;

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync;

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync;

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String>;

    /// Emettre un message en str deja serialise
    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>;

    /// Emettre un message MilleGrille deja signe
    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>;

    fn mq_disponible(&self) -> bool;

    /// Active le mode regeneration
    fn set_regeneration(&self);

    /// Desactive le mode regeneration
    fn reset_regeneration(&self);

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_mode_regeneration(&self) -> bool;

    fn get_securite(&self) -> &Securite;
}

pub struct GenerateurMessagesImpl {
    // tx_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    // tx_reply: Sender<MessageInterne>,
    rabbitmq: Arc<RabbitMqExecutor>,
    enveloppe_privee: Mutex<Arc<EnveloppePrivee>>,
    mode_regeneration: Mutex<bool>,
    securite: Securite,
}

impl GenerateurMessagesImpl {

    pub fn new(config: &ConfigurationPki, rabbitmq: Arc<RabbitMqExecutor>) -> Self {
        let securite = rabbitmq.securite.clone();
        Self {
            rabbitmq,
            enveloppe_privee: Mutex::new(config.get_enveloppe_privee()),
            mode_regeneration: Mutex::new(false),
            securite,
        }
    }

    async fn emettre_message_serializable<M>(
        &self,
        routage: RoutageMessageAction,
        message: &M,
        blocking: bool,
        type_message_out: TypeMessageOut
    ) -> Result<Option<TypeMessage>, String>
    where
        M: Serialize + Send + Sync,
    {
        let partition = match &routage.partition {
            Some(p) => Some(p.as_str()),
            None => None
        };
        let message_signe = match self.formatter_message(
            message,
            Some(routage.domaine.as_str()),
            Some(routage.action.as_str()),
            partition,
            None,
            routage.ajouter_ca
        ) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur soumission transaction : {:?}", e))?,
        };

        self.emettre_message_millegrille(routage, blocking, type_message_out, message_signe).await
    }

    async fn emettre(&self, message: MessageOut) -> Result<Option<sync::oneshot::Receiver<TypeMessage>>, String> {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(None)
        }

        self.rabbitmq.send_out(message).await
    }
}

#[async_trait]
impl GenerateurMessages for GenerateurMessagesImpl {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        let message_signe = match self.formatter_message(
            message,
            Some(&routage.domaine),
            Some(&routage.action),
            routage.partition.as_ref(),
            None,
            routage.ajouter_ca
        ) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur formattage message {:?}", e))?
        };

        let exchanges_effectifs = match routage.exchanges {
            Some(e) => Some(e),
            None => Some(vec!(self.securite.clone()))
        };

        let message_out = MessageOut::new(
            routage.domaine,
            routage.action,
            routage.partition,
            message_signe,
            TypeMessageOut::Evenement,
            exchanges_effectifs,
            routage.reply_to,
            routage.correlation_id,
            None,
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(TypeMessage::Regeneration)
        }

        // Blocking, true par defaut pour requete
        let blocking = match routage.blocking {
            Some(b) => b,
            None => true,
        };

        match self.emettre_message_serializable(routage, message, blocking, TypeMessageOut::Requete).await {
            Ok(r) => match r {
                Some(m) => Ok(m),
                None => Err(String::from("Aucune reponse")),
            },
            Err(e) => Err(e),
        }
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

        self.emettre_message_serializable(routage, message, blocking, TypeMessageOut::Transaction).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

        self.emettre_message_serializable(routage, message, blocking, TypeMessageOut::Commande).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        let message_out = MessageOut::new_reply(
            message,
            routage.correlation_id.as_str(),
            routage.reply_to.as_str()
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        let message_millegrille = match MessageSerialise::from_str(message) {
            Ok(m) => m.parsed,
            Err(e) => Err(format!("Erreur formattage message : {:?}", e))?,
        };
        self.emettre_message_millegrille(
            routage,
            blocking,
            type_message,
            message_millegrille
        ).await
    }

    async fn emettre_message_millegrille(
        &self, routage: RoutageMessageAction, blocking: bool, type_message_out: TypeMessageOut, message_signe: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        let attendre = match &type_message_out {
            TypeMessageOut::Requete => match routage.blocking {Some(b) => b || blocking, None => blocking},
            TypeMessageOut::Commande => match routage.blocking {Some(b) => b || blocking, None => blocking},
            TypeMessageOut::Transaction => match routage.blocking {Some(b) => b || blocking, None => blocking},
            TypeMessageOut::Reponse => false,
            TypeMessageOut::Evenement => false,
        };

        let attente_expiration = match attendre {
            true => {
                let timeout_messages = match routage.timeout_blocking {
                    Some(t) => t,
                    None => 15_000
                };
                let expiration: DateTime<Utc> = Utc::now() + chrono::Duration::milliseconds(timeout_messages as i64);
                Some(expiration)
            },
            false => {
                None
            }
        };

        let replying_to = if routage.ajouter_reply_q {
            self.rabbitmq.reply_q.lock().expect("lock").clone()
        } else {
            routage.reply_to
        };

        let message_out = MessageOut::new(
            routage.domaine,
            routage.action,
            routage.partition,
            message_signe,
            type_message_out,
            routage.exchanges,
            replying_to,
            routage.correlation_id,
            attente_expiration.clone(),
        );

        // Emettre la requete sur MQ
        let correlation = match &message_out.correlation_id {Some(c) => c.clone(), None => "placeholder".into()};
        debug!("emettre_message_millegrille Emettre requete correlation {:?}", message_out.correlation_id);
        if let Some(rx) = self.emettre(message_out).await? {
            match rx.await {
                Ok(r) => Ok(Some(r)),
                Err(e) => {
                    Err(format!("generateur_messages.emettre_message_millegrille Erreur reception reponse {} : {:?}", correlation, e))?
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

// impl IsConfigurationPki for GenerateurMessagesImpl {
//     fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
//         self.enveloppe_privee.clone()
//     }
// }
