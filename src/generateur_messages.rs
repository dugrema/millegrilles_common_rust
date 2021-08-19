use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::{debug, error, info};
use serde_json::{Map, Value};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}, oneshot};
use tokio::time::{Duration, timeout};
use tokio::time::error::Elapsed;

use lapin::message::Delivery;

use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageJson, MessageSigne};
use crate::rabbitmq_dao::{AttenteReponse, MessageInterne, MessageOut, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;

#[async_trait]
pub trait GenerateurMessages: Send + Sync {
    async fn soumettre_transaction(&self, domaine: &str, message: &MessageJson, exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String>;
    async fn transmettre_requete(&self, domaine: &str, message: &MessageJson, exchange: Option<Securite>) -> Result<TypeMessage, String>;
    async fn emettre_evenement(&self, domaine: &str, message: &MessageJson, exchanges: Option<Vec<Securite>>) -> Result<(), String>;
    async fn repondre(&self, message: &MessageJson, reply_q: &str, correlation_id: &str) -> Result<(), String>;
    fn mq_disponible(&self) -> bool;
}

pub struct GenerateurMessagesImpl {
    tx_out: Arc<Mutex<Option<Sender<MessageOut>>>>,
    tx_interne: Sender<MessageInterne>,
    formatteur: Arc<FormatteurMessage>,
}

impl GenerateurMessagesImpl {

    pub fn new(mq: &RabbitMqExecutor) -> GenerateurMessagesImpl {
        GenerateurMessagesImpl {
            tx_out: mq.tx_out.clone(),
            tx_interne: mq.tx_interne.clone(),
            formatteur: mq.formatteur.clone(),
        }
    }

    async fn emettre(&self, message: MessageOut) -> Result<(), String> {

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
impl<'a> GenerateurMessages for GenerateurMessagesImpl {

    async fn soumettre_transaction(&self, domaine: &str, message: &MessageJson, exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        let message_signe = self.signer(Some(domaine), message);

        let exchanges = match exchange {
            Some(inner) => Some(vec!(inner)),
            None => Some(vec!(Securite::L3Protege)),
        };

        let domaine_action = format!("transaction.{}", domaine);

        let message_out = MessageOut::new(
            &domaine_action,
            message_signe?,
            TypeMessageOut::Transaction,
            exchanges
        );

        let (tx_delivery, mut rx_delivery) = oneshot::channel();
        let entete = &message_out.message.entete;
        let correlation_id = entete.get("uuid_transaction").expect("uuid_transaction").as_str().expect("correlation_id").to_owned();

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
            let reponse= timeout(Duration::from_millis(15_000), rx_delivery).await;
            match reponse {
                Ok(inner) => {
                    match inner {
                        Ok(inner2) => Ok(Some(inner2)),
                        Err(e) => Err(format!("Erreur channel reponse {} : {:?}", correlation_id, e)),
                    }
                },
                Err(t) => Err(format!("Timeout reponse {}", correlation_id)),
            }
        } else {
            // Non-blocking, emission simple et on n'attend pas
            Ok(None)
        }
    }

    async fn transmettre_requete(&self, domaine: &str, message: &MessageJson, exchange: Option<Securite>) -> Result<TypeMessage, String> {

        let message_signe = self.signer(Some(domaine), message);

        let exchanges = match exchange {
            Some(inner) => Some(vec!(inner)),
            None => Some(vec!(Securite::L3Protege)),
        };

        let message_out = MessageOut::new(
            domaine,
            message_signe?,
            TypeMessageOut::Requete,
            exchanges
        );

        let entete = &message_out.message.entete;
        let correlation_id = entete.get("uuid_transaction").expect("uuid_transaction").as_str().expect("correlation_id").to_owned();

        let (tx_delivery, mut rx_delivery) = oneshot::channel();
        let demande = MessageInterne::AttenteReponse(AttenteReponse {
            correlation: correlation_id.clone(),
            sender: tx_delivery,
        });

        // Ajouter un hook pour la nouvelle correlation, permet de recevoir la reponse
        self.tx_interne.send(demande).await.expect("Erreur emission message interne");

        // Emettre la requete sur MQ
        debug!("Emettre requete correlation {}", correlation_id);
        let _ = self.emettre(message_out).await?;

        // Retourner le channel pour attendre la reponse
        let reponse= timeout(Duration::from_millis(15_000), rx_delivery).await;
        match reponse {
            Ok(inner) => {
                match inner {
                    Ok(inner2) => Ok(inner2),
                    Err(e) => Err(format!("Erreur channel reponse {} : {:?}", correlation_id, e)),
                }
            },
            Err(t) => Err(format!("Timeout reponse {}", correlation_id)),
        }
    }

    async fn emettre_evenement(&self, domaine: &str, message: &MessageJson, exchanges: Option<Vec<Securite>>) -> Result<(), String> {

        let message_signe = self.signer(Some(domaine), message);

        let exchanges_effectifs = match exchanges {
            Some(e) => Some(e),
            None => Some(vec!(Securite::L3Protege))
        };

        let message_out = MessageOut::new(
            domaine,
            message_signe?,
            TypeMessageOut::Evenement,
            exchanges_effectifs
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    async fn repondre(&self, message: &MessageJson, reply_q: &str, correlation_id: &str) -> Result<(), String> {
        let message_signe = self.signer(None, message);

        let message_out = MessageOut::new_reply(
            message_signe?,
            correlation_id,
            reply_q
        );

        let _ = self.emettre(message_out).await?;

        Ok(())
    }

    fn mq_disponible(&self) -> bool {
        let guard = self.tx_out.lock().expect("mutex");
        match guard.as_ref() {
            Some(_) => true,
            None => false,
        }
    }
}

impl GenerateurMessagesImpl {
    fn signer(&self, domaine: Option<&str>, message: &MessageJson) -> Result<MessageSigne, String> {
        let message_signe = self.formatteur.formatter_value(message, domaine);
        let message_signe = match message_signe {
            Ok(m) => Ok(m),
            Err(e) => Err(String::from("Erreur emission evenement sur signature message")),
        }?;
        Ok(message_signe)
    }
}
