use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::from_utf8;
use std::sync::Arc;
use chrono::Utc;

use lapin::message::Delivery;
use log::{debug, error, info, trace, warn};
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesRef, MessageValidable};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use TypeMessageOut as TypeMessageIn;

use crate::certificats::{MessageInfoCertificat, ValidateurX509};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{formatter_message_certificat, IsConfigurationPki};
use crate::rabbitmq_dao::TypeMessageOut;

/// Traitement d'un message Delivery. Convertit en MessageMillegrille, valide le certificat
pub async fn traiter_delivery<M,S>(
    middleware: &M,
    nom_queue: S,
    delivery: Delivery,
)
    -> Result<Option<TypeMessage>, Box<dyn Error>>
    where
        M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ConfigMessages,
        S: AsRef<str>
{
    let nom_q = nom_queue.as_ref();
    debug!("recepteur_messages.traiter_delivery sur Q {}", nom_q);

    // Transferer le Vec<u8> du delivery vers un buffer de message et
    // faire le parsing (validation structure).
    let message: MessageMilleGrillesBufferDefault = delivery.data.into();
    let (type_message, certificat) = {
        let mut message_ref = message.parse()?;
        debug!("traiter_delivery Recu message {:?}", message_ref.routage);

        // Verifier la signature du message. Lance une Err si le message est invalide.
        if let Err(e) = message_ref.verifier_signature() {
            info!("Erreur verification signature:\n{}", from_utf8(message.buffer.as_slice())?);
            Err(e)?
        }
        let correlation_id = match delivery.properties.correlation_id() {
            Some(inner) => inner.as_str(),
            None => message_ref.id
        };
        debug!("traiter_delivery Traiter message {:?}", correlation_id);

        // Determiner le type de message (reponse ou action)
        let rk = delivery.routing_key.as_str();
        let ex = delivery.exchange.as_str();

        let type_message = if ex == "" {
            // On a une reponse
            let correlation_delivery = match delivery.properties.correlation_id() {
                Some(inner) => inner.as_str(),
                None => Err(String::from("traiter_delivery Reponse recue sans correlation_id - SKIP"))?
            };
            let routage = RoutageMessageReponse {
                reply_to: nom_q.into(),
                correlation_id: correlation_delivery.into(),
            };
            TypeMessageIn::Reponse(routage)
        } else {
            // Message action
            let mut rk_split = rk.split(".");
            let type_message_string = match rk_split.next() {
                Some(inner) => inner.to_ascii_lowercase(),
                None => Err(String::from("traiter_delivery Message d'action avec routing_key vide - SKIP"))?
            };

            let message_routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("traiter_delivery Message action sans routage dans le contenu - SKIP"))?
            };

            let domaine = match message_routage.domaine {
                Some(inner) => inner.to_owned(),
                None => Err(String::from("traiter_delivery Message d'action sans domaine"))?
            };
            let action = match message_routage.action {
                Some(inner) => inner.to_owned(),
                None => Err(String::from("traiter_delivery Message d'action sans action"))?
            };
            let user_id = match message_routage.user_id {
                Some(inner) => Some(inner.to_owned()),
                None => None
            };
            let partition = match message_routage.partition {
                Some(inner) => Some(inner.to_owned()),
                None => None
            };
            let reply_to = match delivery.properties.reply_to() {
                Some(inner) => Some(inner.as_str().to_owned()),
                None => None
            };

            let routage = RoutageMessageAction {
                domaine,
                action,
                user_id,
                partition,
                exchanges: vec![Securite::try_from(ex)?],
                reply_to,
                correlation_id: Some(correlation_id.to_owned()),
                ajouter_reply_q: false,
                blocking: None,
                ajouter_ca: false,
                timeout_blocking: None,
                queue_reception: Some(nom_q.to_string())
            };

            match type_message_string.as_str() {
                "requete" => TypeMessageIn::Requete(routage),
                "evenement" => TypeMessageIn::Evenement(routage),
                "commande" => TypeMessageIn::Commande(routage),
                "transaction" => TypeMessageIn::Transaction(routage),
                _ => Err(format!("traiter_delivery Type message action non supporte : {}", type_message_string))?
            }
        };

        // Valider le message. Lance une Err si le certificat est invalide ou inconnu.
        let certificat = middleware.valider_certificat_message(
            &message_ref, true).await?;
        // if ! middleware.valider_pour_date(certificat.as_ref(), &Utc::now())? {
        //     Err(String::from("Le certificat d'un message recu n'est pas presentement valide"))?
        // }

        debug!("Message valide {}", correlation_id);
        (type_message, certificat)
    };
    Ok(Some(TypeMessage::Valide(MessageValide { message, type_message, certificat })))
}

pub async fn intercepter_message<M>(middleware: &M, message: &TypeMessage) -> bool
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ConfigMessages
{
    // Intercepter reponses et requetes de certificat
    match &message {
        TypeMessage::Valide(message_valide) => {
            match &message_valide.type_message {
                TypeMessageOut::Evenement(r) => {
                    match r.action.as_str() {
                        COMMANDE_CERT_MAITREDESCLES => {
                            error!("intercepter_messageEvenement certificat maitre des cles recus - !!disabled, FIX ME!!");
                            false
                            // match middleware.recevoir_certificat_chiffrage(middleware, message).await {
                            //     Ok(_) => true,
                            //     Err(e) => {
                            //         error!("Erreur interception certificat maitre des cles : {:?}", e);
                            //         false
                            //     }
                            // }
                        },
                        _ => false,
                    }
                },
                _ => false
            }
        },
        TypeMessage::Certificat(_inner) => {
            // Rien a faire, le certificat a deja ete intercepte par ValidateurX509
            debug!("Message evenement certificat, message intercepte");
            true
        },
        TypeMessage::Regeneration => true,  // Rien a faire
    }
}

#[derive(Clone, Debug)]
pub struct MessageValide {
    pub message: MessageMilleGrillesBufferDefault,
    pub type_message: TypeMessageIn,
    pub certificat: Arc<EnveloppeCertificat>,
}

#[derive(Clone, Debug)]
pub struct MessageCertificat {
    pub enveloppe_certificat: EnveloppeCertificat,
}

#[derive(Clone, Debug)]
pub enum TypeMessage {
    Valide(MessageValide),
    Certificat(MessageCertificat),
    Regeneration,
}

#[derive(Debug)]
pub struct ErreurValidation {
    pub verification: ErreurVerification,
}

impl ErreurValidation {
    pub fn new(verification: ErreurVerification) -> Self {
        Self {
            verification
        }
    }
}

impl Display for ErreurValidation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("ErreurValidation dans verification {:?}", self.verification).as_str())
    }
}

impl Error for ErreurValidation {}

#[derive(Clone, Debug)]
pub enum ErreurVerification {
    HachageInvalide,
    SignatureInvalide,
    CertificatInconnu(String),
    CertificatInvalide,
    EnteteManquante,
    ErreurGenerique,
}
