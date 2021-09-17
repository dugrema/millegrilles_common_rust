use std::sync::{Arc, Mutex};
use std::marker::Send;

use async_trait::async_trait;
use log::{debug, error, info};
use serde_json::{Map, Value};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}, oneshot};
use tokio::time::{Duration, timeout};
use tokio::time::error::Elapsed;

use lapin::message::Delivery;

use crate::constantes::*;
use crate::formatteur_messages::MessageSerialise;
use crate::rabbitmq_dao::{AttenteReponse, MessageInterne, MessageOut, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::formatteur_messages::MessageMilleGrille;
use std::error::Error;
use crate::{FormatteurMessage, EnveloppePrivee, ConfigurationPki, IsConfigurationPki};
use serde::Serialize;

#[async_trait]
pub trait GenerateurMessages: FormatteurMessage + Send + Sync {
    async fn emettre_evenement(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize+Send+Sync), exchanges: Option<Vec<Securite>>) -> Result<(), String>;

    async fn transmettre_requete<M>(&self, domaine: &str, action: &str, partition: Option<&str>, message: &M, exchange: Option<Securite>) -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync;

    async fn soumettre_transaction(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize+Send+Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String>;
    async fn transmettre_commande(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize+Send+Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String>;
    async fn repondre(&self, message: MessageMilleGrille, reply_q: &str, correlation_id: &str) -> Result<(), String>;

    /// Emettre un message en str deja formatte
    async fn emettre_message(&self, domaine: &str, action: &str, partition: Option<&str>,
                             type_message: TypeMessageOut, message: &str, exchange: Option<Securite>, blocking: bool
    ) -> Result<Option<TypeMessage>, String>;

    async fn emettre_message_millegrille(&self, domaine: &str, action: &str, partition: Option<&str>,
                             exchange: Option<Securite>, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille
    ) -> Result<Option<TypeMessage>, String>;

    fn mq_disponible(&self) -> bool;

    /// Active le mode regeneration
    fn set_regeneration(&self);

    /// Desactive le mode regeneration
    fn reset_regeneration(&self);

    /// Retourne l'etat du mode regeneration (true = actif)
    fn get_mode_regeneration(&self) -> bool;
}

pub struct GenerateurMessagesImpl {
    tx_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    tx_interne: Sender<MessageInterne>,
    enveloppe_privee: Arc<EnveloppePrivee>,
    mode_regeneration: Mutex<bool>,
}

impl GenerateurMessagesImpl {

    pub fn new(config: &ConfigurationPki, mq: &RabbitMqExecutor) -> GenerateurMessagesImpl {
        GenerateurMessagesImpl {
            tx_out: mq.tx_out.clone(),
            tx_interne: mq.tx_interne.clone(),
            enveloppe_privee: config.get_enveloppe_privee(),
            mode_regeneration: Mutex::new(false),
        }
    }

    async fn emettre_message_serializable<M>(
        &self,
        domaine: &str,
        action: &str,
        partition: Option<&str>,
        message: &M,
        exchange: Option<Securite>,
        blocking: bool,
        type_message_out: TypeMessageOut
    ) -> Result<Option<TypeMessage>, String>
    where
        M: Serialize + Send + Sync,
    {
        let message_signe = match self.formatter_message(message, Some(domaine), Some(action), partition, None) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur soumission transaction : {:?}", e))?,
        };

        self.emettre_message_millegrille(domaine, action, partition, exchange, blocking, type_message_out, message_signe).await
    }

    async fn emettre(&self, message: MessageOut) -> Result<(), String> {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        // Faire un clone du sender
        let mut sender = {
            match self.tx_out.lock().unwrap().as_ref() {
                Some(sender_ref) => Some(sender_ref.clone()),
                None => None,
            }
        };

        match sender {
            Some(mut s) => {
                debug!("Emettre message out : {:?}", &message);
                let resultat = s.send(message).await;
                match resultat {
                    Ok(()) => {
                        debug!("Message emis");
                        Ok(())
                    },
                    Err(e) => {
                        Err(format!("Erreur send message {:?}", e.to_string()))
                    }
                }
            },
            None => Err("Err, MQ n'est pas pret a emettre des messages".into())
        }
    }
}

#[async_trait]
impl GenerateurMessages for GenerateurMessagesImpl {

    async fn emettre_evenement(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchanges: Option<Vec<Securite>>) -> Result<(), String> {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        let message_signe = match self.formatter_message(
            message,
            Some(domaine),
            Some(action),
            partition,
            None
        ) {
            Ok(m) => m,
            Err(e) => Err(format!("Erreur formattage message {:?}", e))?
        };

        let exchanges_effectifs = match exchanges {
            Some(e) => Some(e),
            None => Some(vec!(Securite::L3Protege))
        };

        let message_out = MessageOut::new(
            domaine,
            action,
            partition,
            message_signe,
            TypeMessageOut::Evenement,
            exchanges_effectifs
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    async fn transmettre_requete<M>(&self, domaine: &str, action: &str, partition: Option<&str>, message: &M, exchange: Option<Securite>) -> Result<TypeMessage, String>
    where
        M: Serialize + Send + Sync,
    {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(TypeMessage::Regeneration)
        }

        match self.emettre_message_serializable(domaine, action, partition, message, exchange, true, TypeMessageOut::Requete).await {
            Ok(r) => match r {
                Some(m) => Ok(m),
                None => Err(String::from("Aucune reponse")),
            },
            Err(e) => Err(e),
        }

        // let message_signe = match self.formatter_message(message, Some(domaine), None) {
        //     Ok(m) => m,
        //     Err(e) => Err(format!("Erreur transmission requete : {:?}", e))?
        // };
        //
        // let exchanges = match exchange {
        //     Some(inner) => Some(vec!(inner)),
        //     None => Some(vec!(Securite::L3Protege)),
        // };
        //
        // let message_out = MessageOut::new(
        //     domaine,
        //     message_signe,
        //     TypeMessageOut::Requete,
        //     exchanges
        // );
        //
        // let entete = &message_out.message.entete;
        // let correlation_id = entete.uuid_transaction.clone();
        //
        // let (tx_delivery, mut rx_delivery) = oneshot::channel();
        // let demande = MessageInterne::AttenteReponse(AttenteReponse {
        //     correlation: correlation_id.clone(),
        //     sender: tx_delivery,
        // });
        //
        // // Ajouter un hook pour la nouvelle correlation, permet de recevoir la reponse
        // self.tx_interne.send(demande).await.expect("Erreur emission message interne");
        //
        // // Emettre la requete sur MQ
        // debug!("Emettre requete correlation {}", correlation_id);
        // let _ = self.emettre(message_out).await?;
        //
        // // Retourner le channel pour attendre la reponse
        // let reponse= timeout(Duration::from_millis(15_000), rx_delivery).await;
        // match reponse {
        //     Ok(inner) => {
        //         match inner {
        //             Ok(inner2) => Ok(inner2),
        //             Err(e) => Err(format!("Erreur channel reponse {} : {:?}", correlation_id, e))?,
        //         }
        //     },
        //     Err(t) => Err(format!("Timeout reponse {}", correlation_id))?,
        // }
    }

    async fn soumettre_transaction(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {

        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

        self.emettre_message_serializable(domaine, action, partition, message, exchange, blocking, TypeMessageOut::Transaction).await
    }

    async fn transmettre_commande(&self, domaine: &str, action: &str, partition: Option<&str>, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(Some(TypeMessage::Regeneration))
        }

        self.emettre_message_serializable(domaine, action, partition, message, exchange, blocking, TypeMessageOut::Commande).await
    }

    async fn repondre(&self, message: MessageMilleGrille, reply_q: &str, correlation_id: &str) -> Result<(), String> {
        if self.get_mode_regeneration() {
            // Rien a faire
            return Ok(())
        }

        // let message_signe = match self.formatter_message(message, None, None, None, None) {
        //     Ok(m) => m,
        //     Err(e) => Err(format!("Erreur soumission transaction : {:?}", e))?,
        // };

        let message_out = MessageOut::new_reply(
            message,
            correlation_id,
            reply_q
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    async fn emettre_message(&self, domaine: &str, action: &str, partition: Option<&str>,
                             type_message: TypeMessageOut, message: &str, exchange: Option<Securite>, blocking: bool
    ) -> Result<Option<TypeMessage>, String>
    {
        let message_millegrille = match MessageSerialise::from_str(message) {
            Ok(m) => m.parsed,
            Err(e) => Err(format!("Erreur formattage message : {:?}", e))?,
        };
        self.emettre_message_millegrille(
            domaine,
            action,
            partition,
            exchange,
            blocking,
            type_message,
            message_millegrille
        ).await
    }

    async fn emettre_message_millegrille(
        &self, domaine: &str, action: &str, partition: Option<&str>, exchange: Option<Securite>,
        blocking: bool, type_message_out: TypeMessageOut, message_signe: MessageMilleGrille
    ) -> Result<Option<TypeMessage>, String> {
        let exchanges = match exchange {
            Some(inner) => Some(vec!(inner)),
            None => Some(vec!(Securite::L3Protege)),
        };

        let message_out = MessageOut::new(
            domaine,
            action,
            partition,
            message_signe,
            type_message_out,
            exchanges
        );

        let (tx_delivery, mut rx_delivery) = oneshot::channel();

        let correlation_id = {
            let entete = &message_out.message.entete;
            entete.uuid_transaction.clone()
        };

        if blocking {
            let demande = MessageInterne::AttenteReponse(AttenteReponse {
                correlation: correlation_id.clone(),
                sender: tx_delivery,
            });

            // Ajouter un hook pour la nouvelle correlation, permet de recevoir la reponse
            self.tx_interne.send(demande).await.expect("Erreur emission message interne");
        }

        // Emettre la requete sur MQ
        debug!("Emettre requete correlation {}", correlation_id);
        let _ = self.emettre(message_out).await?;

        // Retourner le channel pour attendre la reponse
        if blocking {
            let reponse = timeout(Duration::from_millis(15_000), rx_delivery).await;
            match reponse {
                Ok(inner) => {
                    match inner {
                        Ok(inner2) => Ok(Some(inner2)),
                        Err(e) => Err(format!("Erreur channel reponse {} : {:?}", correlation_id, e))?,
                    }
                },
                Err(t) => Err(format!("Timeout reponse {}", correlation_id))?,
            }
        } else {
            // Non-blocking, emission simple et on n'attend pas
            Ok(None)
        }
    }

    fn mq_disponible(&self) -> bool {
        let guard = self.tx_out.lock().expect("mutex");
        match guard.as_ref() {
            Some(_) => true,
            None => false,
        }
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

}

impl FormatteurMessage for GenerateurMessagesImpl {
}

impl IsConfigurationPki for GenerateurMessagesImpl {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.enveloppe_privee.clone()
    }
}
