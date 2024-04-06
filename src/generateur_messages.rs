use std::error::Error;
use std::marker::Send;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::{debug, error};
use millegrilles_cryptographie::ed25519_dalek::{SecretKey, SigningKey};
use millegrilles_cryptographie::heapless;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferAlloc, MessageMilleGrillesBufferDefault, RoutageMessage, MessageMilleGrillesBuilderDefault};
use millegrilles_cryptographie::x509::EnveloppePrivee;
use serde::Serialize;
use tokio::sync;
use serde_json::{json, Value};
use x509_parser::nom::AsBytes;

use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::common_messages::MessageReponse;
use crate::configuration::ConfigurationPki;
use crate::constantes::*;
use crate::formatteur_messages::{build_message_action, build_reponse, FormatteurMessage};
use crate::middleware::IsConfigurationPki;
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
        -> Result<TypeMessage, crate::error::Error>
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

    // async fn emettre_message_serializable<M>(
    //     &self,
    //     routage: RoutageMessageAction,
    //     message: &M,
    //     blocking: bool,
    //     type_message_out: TypeMessageOut
    // ) -> Result<Option<TypeMessage>, String>
    // where
    //     M: Serialize + Send + Sync,
    // {
    //     let partition = match &routage.partition {
    //         Some(p) => Some(p.as_str()),
    //         None => None
    //     };
    //     let user_id = match &routage.user_id {
    //         Some(p) => Some(p.as_str()),
    //         None => None
    //     };
    //     let message_signe = match self.formatter_message(
    //         type_message_out.clone().into(),
    //         message,
    //         Some(routage.domaine.as_str()),
    //         Some(routage.action.as_str()),
    //         partition,
    //         user_id,
    //         None,
    //         routage.ajouter_ca.clone()
    //     ) {
    //         Ok(m) => m,
    //         Err(e) => Err(format!("Erreur soumission transaction : {:?}", e))?,
    //     };
    //
    //     self.emettre_message_millegrille(routage, blocking, type_message_out, message_signe).await
    // }

    // async fn emettre(&self, message: MessageOut) -> Result<Option<sync::oneshot::Receiver<TypeMessage>>, String> {
    //
    //     if self.get_mode_regeneration() {
    //         // Rien a faire
    //         return Ok(None)
    //     }
    //
    //     self.rabbitmq.send_out(message).await
    // }
}

// pub fn build_message_action<R,M>(routage: R, message: M, enveloppe_privee: &EnveloppePrivee)
//     -> Result<(MessageMilleGrillesBufferDefault, String), String>
//     where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync
// {
//     let routage = routage.into();
//     let contenu = match serde_json::to_string(&message) {
//         Ok(inner) => inner,
//         Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
//     };
//
//     let estampille = Utc::now();
//
//     let routage_message: RoutageMessage = routage.clone().into();
//
//     let mut cle_privee_u8 = SecretKey::default();
//     match enveloppe_privee.cle_privee().raw_private_key() {
//         Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
//         Err(e) => Err(format!("build_message_action Erreur raw_private_key {:?}", e))?
//     };
//     let signing_key = SigningKey::from_bytes(&cle_privee_u8);
//
//     let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
//     let pem_vec = enveloppe_privee.enveloppe.get_pem_vec_extracted();
//     certificat.extend(pem_vec.iter().map(|s| s.as_str()));
//
//     let generateur = MessageMilleGrillesBuilderDefault::new(
//         millegrilles_cryptographie::messages_structs::MessageKind::Commande, contenu.as_str(), estampille, &signing_key)
//         .routage(routage_message)
//         .certificat(certificat);
//
//     // Allouer un Vec et serialiser le message signe.
//     let mut buffer = Vec::new();
//     let message_ref = generateur.build_into_alloc(&mut buffer)?;
//
//     // Retourner le nouveau message
//     Ok((MessageMilleGrillesBufferDefault::from(buffer), message_ref.id.to_owned()))
// }
//
// pub fn build_reponse<M>(message: M, enveloppe_privee: &EnveloppePrivee)
//                         -> Result<(MessageMilleGrillesBufferDefault, String), String>
//     where M: Serialize + Send + Sync
// {
//     let contenu = match serde_json::to_string(&message) {
//         Ok(inner) => inner,
//         Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
//     };
//
//     let estampille = Utc::now();
//
//     let mut cle_privee_u8 = SecretKey::default();
//     match enveloppe_privee.cle_privee().raw_private_key() {
//         Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
//         Err(e) => Err(format!("build_reponse Erreur raw_private_key {:?}", e))?
//     };
//     let signing_key = SigningKey::from_bytes(&cle_privee_u8);
//
//     let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
//     let pem_vec = enveloppe_privee.enveloppe.get_pem_vec_extracted();
//     certificat.extend(pem_vec.iter().map(|s| s.as_str()));
//
//     let generateur = MessageMilleGrillesBuilderDefault::new(
//         millegrilles_cryptographie::messages_structs::MessageKind::Commande, contenu.as_str(), estampille, &signing_key)
//         .certificat(certificat);
//
//     // Allouer un Vec et serialiser le message signe.
//     let mut buffer = Vec::new();
//     let message_ref = generateur.build_into_alloc(&mut buffer)?;
//
//     // Retourner le nouveau message
//     Ok((MessageMilleGrillesBufferDefault::from(buffer), message_ref.id.to_owned()))
// }

#[async_trait]
impl GenerateurMessages for GenerateurMessagesImpl {

    async fn emettre_evenement<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {  // Rien a faire
            return Ok(())
        }

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

    async fn transmettre_requete<R,M>(&self, routage: R, message: M) -> Result<TypeMessage, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {  // Rien a faire
            return Ok(TypeMessage::Regeneration)
        }

        let mut routage = routage.into();

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
            Some(inner) => Ok(inner),
            None => Err(String::from("Aucune reponse"))?,
        }

        // match self.emettre_message_serializable(routage, message, TypeMessageOut::Requete).await {
        //     Ok(r) => match r {
        //         Some(m) => Ok(m),
        //         None => Err(String::from("Aucune reponse")),
        //     },
        //     Err(e) => Err(e),
        // }
    }

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M) -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {

        if self.get_mode_regeneration() {  // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

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

        // self.emettre_message_serializable(routage, message, blocking, TypeMessageOut::Transaction).await
    }

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {  // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

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

        // self.emettre_message_serializable(routage, message, blocking, TypeMessageOut::Commande).await
    }

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync
    {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        // let routage = routage.into();
        //
        // let message_out = MessageOut::new_reply(
        //     message,
        //     routage.correlation_id.as_str(),
        //     routage.reply_to.as_str()
        // );
        //
        // self.rabbitmq.send_out(message_out).await?;
        //
        // Ok(())

        let (message, message_id) = {
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

        // let attendre = match type_message_out {
        //     TypeMessageOut::Requete => match routage.blocking {Some(b) => b || blocking, None => blocking},
        //     TypeMessageOut::Commande => match routage.blocking {Some(b) => b || blocking, None => blocking},
        //     TypeMessageOut::Transaction => match routage.blocking {Some(b) => b || blocking, None => blocking},
        //     TypeMessageOut::Reponse => false,
        //     TypeMessageOut::Evenement => false,
        // };

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

        // let replying_to = if routage.ajouter_reply_q {
        //     self.rabbitmq.reply_q.lock().expect("lock").clone()
        // } else {
        //     routage.reply_to
        // };

        let message_out = MessageOut::new(type_message, &correlation_id, message, attente_expiration);

        // let message_out = MessageOut::new(
        //     routage,
        //     message,
        //     type_message_out,
        //     replying_to,
        //     attente_expiration.clone(),
        // );

        // Emettre la requete sur MQ
        // let correlation = match &message_out.correlation_id {Some(c) => c.clone(), None => "placeholder".into()};
        debug!("emettre_message_millegrille Emettre requete correlation {}", correlation_id);
        // if let Some(rx) = self.emettre(message_out).await? {
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

// pub async fn transmettre_cle_attachee<M,V>(middleware: &M, cle: V) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages,
//           V: Serialize
// {
//     let ser_value = serde_json::to_value(cle)?;
//     debug!("Reception commande MaitreDesCles : {:?}", ser_value);
//     let mut message_cle = MessageSerialise::from_serializable(ser_value)?;
//
//     // Extraire partition pour le routage
//     let routage = match message_cle.parsed.attachements.take() {
//         Some(mut attachments_cle) => match attachments_cle.remove("partition") {
//             Some(partition) => match partition.as_str() {
//                 Some(partition) => {
//                     RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
//                         .exchanges(vec![Securite::L3Protege])
//                         .partition(partition)
//                         .build()
//                 },
//                 None => {
//                     error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : partition n'est pas str");
//                     return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (1)"}), None)?));
//                 }
//             },
//             None => {
//                 error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : partition manquante");
//                 return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (2)"}), None)?));
//             }
//         },
//         None => {
//             error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : attachements.partition manquant");
//             return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (3)"}), None)?));
//         }
//     };
//
//     // match middleware.transmettre_commande(routage, &message_cle.parsed, true).await {
//     match middleware.emettre_message_millegrille(routage, true, TypeMessageOut::Commande, message_cle.parsed).await {
//         Ok(inner) => {
//             if let Some(TypeMessage::Valide(reponse)) = inner {
//                 let reponse_contenu: MessageReponse = reponse.message.parsed.map_contenu()?;
//                 if let Some(true) = reponse_contenu.ok {
//                     debug!("Cle sauvegardee OK");
//                 } else {
//                     error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : reponse ok == false");
//                     return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (4)"}), None)?));
//                 }
//             } else {
//                 error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : mauvais type reponse");
//                 return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (5)"}), None)?));
//             }
//         },
//         Err(e) => {
//             error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", e);
//             return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Erreur sauvegarde cle (6)"}), None)?));
//         }
//     }
//
//     Ok(None)
// }

// pub async fn sauvegarde_attachement_cle<M>(middleware: &M, cle: Value) -> Result<(), Box<dyn Error>>
//     where M: GenerateurMessages
// {
//     match serde_json::from_value::<MessageMilleGrille>(cle) {
//         Ok(mut commande) => {
//             // Extraire champ partition en attachement
//             let partition = match commande.attachements.take() {
//                 Some(mut attachements) => {
//                     match attachements.remove("partition") {
//                         Some(partition) => match partition.as_str() {
//                             Some(partition) => partition.to_owned(),
//                             None => Err(format!("generateur_messages.sauvegarde_attachement_cle Sauvegarder cle : Partition absente (1)"))?
//                         },
//                         None => Err(format!("generateur_messages.sauvegarde_attachement_cle Sauvegarder cle : Partition absente (2)"))?
//                     }
//                 },
//                 None => Err(format!("generateur_messages.sauvegarde_attachement_cle Sauvegarder cle : Partition absente (3)"))?
//             };
//
//             // Convertir la cle
//             let cle: CommandeSauvegarderCle = commande.map_contenu()?;
//             debug!("commande_conserver_configuration_notifications Sauvegarder cle SMTP : {:?}", cle);
//             let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
//                 .exchanges(vec![Securite::L3Protege])
//                 .partition(partition)
//                 .build();
//
//             // Emettre la cle, verifier reponse (doit etre ok: true)
//             match middleware.emettre_message_millegrille(routage, true , TypeMessageOut::Commande, commande).await? {
//                 Some(TypeMessage::Valide(m)) => {
//                     let reponse: MessageReponse = m.message.parsed.map_contenu()?;
//                     if let Some(true) = reponse.ok {
//                         // Ok
//                     } else {
//                         Err(format!("generateur_messages.sauvegarde_attachement_cle Sauvegarder cle SMTP : Reponse ok != true"))?
//                     }
//                 },
//                 _ => Err(format!("generateur_messages.sauvegarde_attachement_cle Sauvegarder cle SMTP : Mauvais type reponse"))?
//             }
//         },
//         Err(e) => Err(format!("generateur_messages.sauvegarde_attachement_cle Erreur mapping commande cle : {:?}", e))?
//     }
//
//     Ok(())
// }
