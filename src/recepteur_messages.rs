use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::from_utf8;
use std::sync::Arc;
use chrono::Utc;

use lapin::message::Delivery;
use log::{debug, error, info, trace, warn};
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesRef};
use TypeMessageOut as TypeMessageIn;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille, MessageInfoCertificat, ValidateurX509, VerificateurPermissions};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{ChiffrageFactoryTrait, formatter_message_certificat, IsConfigurationPki};
use crate::rabbitmq_dao::TypeMessageOut;
// use crate::verificateur::verifier_message;

/// Traitement d'un message Delivery. Convertit en MessageMillegrille, valide le certificat
pub async fn traiter_delivery<M,S>(
    middleware: &M,
    nom_queue: S,
    delivery: Delivery,
)
    -> Result<Option<TypeMessage>, Box<dyn Error>>
    where
        M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages,
        S: AsRef<str>
{
    let nom_q = nom_queue.as_ref();
    debug!("recepteur_messages.traiter_delivery sur Q {}", nom_q);

    // Transferer le Vec<u8> du delivery vers un buffer de message et
    // faire le parsing (validation structure).
    let message: MessageMilleGrillesBufferDefault = delivery.data.into();
    debug!("traiter_delivery Recu message\n{}", from_utf8(message.buffer.as_slice())?);
    let (type_message, certificat) = {
        let mut message_ref = message.parse()?;

        // Verifier la signature du message. Lance une Err si le message est invalide.
        message_ref.verifier_signature()?;

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
        let certificat = middleware.valider_certificat_message(&message_ref).await?;
        if ! middleware.valider_pour_date(certificat.as_ref(), &Utc::now())? {
            Err(String::from("Le certificat d'un message recu n'est pas presentement valide"))?
        }

        debug!("Message valide {}", correlation_id);
        (type_message, certificat)
    };
    Ok(Some(TypeMessage::Valide(MessageValide { message, type_message, certificat })))
}

pub async fn intercepter_message<M>(middleware: &M, message: &TypeMessage) -> bool
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + ChiffrageFactoryTrait + ConfigMessages
{
    // Intercepter reponses et requetes de certificat
    match &message {
        TypeMessage::Valide(message_valide) => {
            match &message_valide.type_message {
                TypeMessageOut::Evenement(r) => {
                    match r.action.as_str() {
                        // PKI_REQUETE_CERTIFICAT => {
                        //     info!("intercepter_messageEvenement certificat intercepte");
                        //     traiter_certificatintercepter_message(middleware, message).await;
                        //     true  // Intercepte
                        // },
                        COMMANDE_CERT_MAITREDESCLES => {
                            info!("intercepter_messageEvenement certificat maitre des cles recus");
                            match middleware.recevoir_certificat_chiffrage(middleware, message).await {
                                Ok(_) => true,
                                Err(e) => {
                                    error!("Erreur interception certificat maitre des cles : {:?}", e);
                                    false
                                }
                            }
                        },
                        _ => false,
                    }
                },
                _ => false
            }

            // match &inner.correlation_id {
            //     Some(correlation_id) => {
            //         match correlation_id.as_str() {
            //             COMMANDE_CERT_MAITREDESCLES => {
            //                 info!("intercepter_message Reponse certificat maitre des cles recus : {:?}", inner);
            //                 match middleware.recevoir_certificat_chiffrage(middleware, &inner.message).await {
            //                     Ok(_) => true,
            //                     Err(e) => {
            //                         error!("intercepter_message Erreur interception certificat maitre des cles : {:?}", e);
            //                         false
            //                     }
            //                 }
            //             },
            //             _ => false
            //         }
            //     },
            //     None => false
            // }
        },
        // TypeMessage::ValideAction(inner) => {
        //     match inner.type_message {
        //         TypeMessageIn::Evenement => {
        //             match inner.action.as_str() {
        //                 PKI_REQUETE_CERTIFICAT => {
        //                     info!("intercepter_messageEvenement certificat {}, message intercepte", inner.routing_key);
        //                     traiter_certificatintercepter_message(middleware, inner).await;
        //                     true  // Intercepte
        //                 },
        //                 COMMANDE_CERT_MAITREDESCLES => {
        //                     info!("intercepter_messageEvenement certificat maitre des cles recus : {:?}", inner);
        //                     match middleware.recevoir_certificat_chiffrage(middleware, &inner.message).await {
        //                         Ok(_) => true,
        //                         Err(e) => {
        //                             error!("Erreur interception certificat maitre des cles : {:?}", e);
        //                             false
        //                         }
        //                     }
        //                 },
        //                 _ => false,
        //             }
        //         },
        //         TypeMessageIn::Requete => {
        //             match inner.domaine.as_str() {
        //                 "certificat" => {
        //                     emettre_certificat(middleware, message, inner).await;
        //                     true
        //                 },
        //                 _ => false,
        //             }
        //         },
        //         _ => {
        //             false // pas intercepte
        //         }
        //     }
        // },
        TypeMessage::Certificat(_inner) => {
            // Rien a faire, le certificat a deja ete intercepte par ValidateurX509
            debug!("Message evenement certificat, message intercepte");
            true
        },
        TypeMessage::Regeneration => true,  // Rien a faire
    }
}

// async fn emettre_certificat<M>(middleware: &M, type_message: &TypeMessage, message: &MessageMilleGrillesBufferDefault)
//     where M: GenerateurMessages
// {
//     let enveloppe_privee = middleware.get_enveloppe_signature();
//     let fingerprint = enveloppe_privee.fingerprint();
//
//     // Determiner si le message correspond a notre certificat (return immediatement sinon)
//     if fingerprint.as_str() != inner.action.as_str() { return }
//     let reply_q = match &inner.reply_q { Some(inner) => inner.as_str(), None => return};
//     let correlation_id = match &inner.correlation_id { Some(inner) => inner.as_str(), None => return};
//     debug!("Emettre certificat a demandeur sous correlation_id {}", correlation_id);
//
//     match preparer_reponse_certificats(
//         middleware,
//         message,
//         enveloppe_privee.as_ref(),
//         reply_q,
//         correlation_id
//     ).await {
//         Ok(()) => (),
//         Err(e) => error!("intercepter_message: Erreur emission reponse : {:?}", e)
//     }
//
// }

// async fn traiter_certificatintercepter_message<M>(middleware: &M, inner: &MessageValideAction)
//     where M: ValidateurX509
// {
//     // Message deja intercepte par ValidateurX509, plus rien a faire.
//     debug!("Evenement certificat {}, message intercepte", inner.routing_key);
//
//     // Charger / mettre certificat en cache au besoin.
//     let m: MessageInfoCertificat = match inner.message.get_msg().map_contenu() {
//         Ok(m) => m,
//         Err(e) => {
//             info!("Erreur lecture message infoCertificat : {:?}", e);
//             return
//         }
//     };
//
//     match m.chaine_pem {
//         Some(chaine_pem) => {
//             let fingerprint = match m.fingerprint.as_ref() {
//                 Some(f) => Some(f.as_str()),
//                 None => None,
//             };
//             match middleware.charger_enveloppe(&chaine_pem, fingerprint, None).await {
//                 Ok(e) => {
//                     debug!("traiter_certificatintercepter_message Certificat intercepte {}", e.fingerprint);
//                 },
//                 Err(e) => info!("Erreur chargement message certificat.infoCertificat : {:?}", e)
//             }
//         },
//         None => (),
//     }
//
// }

// async fn preparer_reponse_certificats<M>(
//     middleware: &M,
//     _message: &TypeMessage,
//     enveloppe_privee: &EnveloppePrivee,
//     reply_q: &str,
//     correlation_id: &str
// ) -> Result<(), Box<dyn Error>>
//     where M:  GenerateurMessages
// {
//     let message_value = formatter_message_certificat(enveloppe_privee.enveloppe.as_ref())?;
//     let message = middleware.formatter_reponse(message_value, None)?;
//     let routage = RoutageMessageReponse::new(reply_q, correlation_id);
//     Ok(middleware.repondre(routage, message).await?)
// }

// async fn traiter_certificat_attache(validateur: &impl ValidateurX509, certificat: &Value, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
//     debug!("Recu certficat attache {:?}", certificat);
//
//     // Batir l'enveloppe pour calculer le fingerprint - va permettre de verifier le cache
//     let enveloppe = match certificat.as_array() {
//         Some(certs) => {
//             let mut vec_strings : Vec<String> = Vec::new();
//             for v in certs {
//                 match v.as_str() {
//                     Some(c_string) => vec_strings.push(String::from(c_string)),
//                     None => return Err("Valeur invalide sous _certificat".into())
//                 }
//             }
//             validateur.charger_enveloppe(&vec_strings, fingerprint).await
//         },
//         None => Err("Contenu de _certificat est vide".into())
//     }?;
//
//     debug!("Enveloppe du certificat attache est charge : {:?}", &enveloppe.fingerprint());
//
//     Ok(enveloppe)
// }

// fn parse<'a, D>(data: D) -> Result<(MessageMilleGrillesBufferDefault, MessageMilleGrillesRef<'a, 4>), String>
//     where D: Into<Vec<u8>>
// {
//     let message: MessageMilleGrillesBufferDefault = data.into().into();
//     let message_parsed = match message.parse() {
//         Ok(inner) => inner,
//         Err(e) => Err(e.to_string())?
//     };
//
//     Ok((message, message_parsed))
//
//     // Valider la structure du message
//
//     // let data = match String::from_utf8(data.into()) {
//     //     Ok(data) => data,
//     //     Err(e) => {
//     //         return Err(format!("Erreur message n'est pas UTF-8 : {:?}", e))
//     //     }
//     // };
//     //
//     // let message_serialise = match MessageSerialise::try_from(data) {
//     //     Ok(m) => m,
//     //     Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}", e))?,
//     // };
//     //
//     // Ok(message_serialise)
// }

#[derive(Clone, Debug)]
pub struct MessageValide {
    pub message: MessageMilleGrillesBufferDefault,
    pub type_message: TypeMessageIn,
    pub certificat: Arc<EnveloppeCertificat>,
}

// #[derive(Clone, Debug)]
// pub struct MessageValideAction {
//     pub message: MessageMilleGrillesBufferDefault,
//     // pub q: String,
//     // pub reply_q: Option<String>,
//     // pub correlation_id: Option<String>,
//     // pub routing_key: String,
//     // pub domaine: String,
//     // pub action: String,
//     // pub exchange: Option<String>,
//     pub type_message: TypeMessageIn,
// }
// impl MessageValideAction {
//     pub fn new<'a,S>(message: MessageSerialise, q: S, routing_key: S, domaine: S, action: S, type_message: TypeMessageIn)
//         -> Self
//         where S: Into<String>
//     {
//         MessageValideAction {
//             message,
//             q: q.into(),
//             reply_q: None,
//             correlation_id: None,
//             routing_key: routing_key.into(),
//             domaine: domaine.into(),
//             action: action.into(),
//             exchange: None,
//             type_message,
//         }
//     }
//
//     pub fn from_message_millegrille(message: MessageMilleGrille, type_message: TypeMessageIn) -> Result<Self, Box<dyn Error>> {
//         let (domaine, action) = match message.routage.as_ref() {
//             Some(inner) => {
//                 if inner.domaine.is_none() {
//                     Err(format!("MessageValideAction.from_message_millegrille Domaine None"))?;
//                 }
//                 if inner.action.is_none() {
//                     Err(format!("MessageValideAction.from_message_millegrille Action None"))?;
//                 }
//                 (inner.domaine.as_ref().expect("domaine").to_owned(), inner.action.as_ref().expect("action").to_owned())
//             },
//             None => Err(format!("MessageValideAction.from_message_millegrille Routage absent"))?
//         };
//
//         let message_serialize = MessageSerialise::from_parsed(message)?;
//
//         Ok(Self::new(message_serialize, "interne", "interne",
//                      domaine.as_str(), action.as_str(), type_message))
//     }
//
//     pub fn get_reply_info(&self) -> Result<(String, String), String> {
//         let reply_q = match &self.reply_q {
//             Some(r) => r.to_owned(),
//             None => Err(format!("Reply Q manquante"))?
//         };
//         let correlation_id = match &self.correlation_id {
//             Some(r) => r.to_owned(),
//             None => Err(format!("Correlation id manquant"))?
//         };
//
//         Ok((reply_q, correlation_id))
//     }
//
//     pub fn get_partition(&self) -> Option<&str> {
//         let routing_key: Vec<&str> = self.routing_key.split(".").collect();
//         if routing_key.len() == 4 {
//             Some(*routing_key.get(2).expect("get"))
//         } else {
//             None
//         }
//     }
//
// }
// impl TryInto<TransactionImpl> for MessageValideAction {
//     type Error = Box<dyn Error>;
//
//     fn try_into(self) -> Result<TransactionImpl, Self::Error> {
//         TransactionImpl::try_from(self.message)
//     }
// }

// #[derive(Debug)]
// pub struct MessageTrigger {
//     pub message: MessageMilleGrille,
//     pub enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
//     pub reply_q: Option<String>,
//     pub correlation_id: Option<String>,
//     pub routing_key: Option<String>,
//     pub domaine: Option<String>,
//     pub exchange: Option<String>,
//     pub type_message: Option<TypeMessageIn>,
// }

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

// impl VerificateurPermissions for MessageValide {
//     fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
//         self.message.get_extensions()
//     }
// }

// /// Valide le certificat de MilleGrillesRef pour le message.
// pub async fn valider_certificat<'a, M, const C: usize>(
//     middleware: &M,
//     message: &mut MessageMilleGrillesRef<'a, C>
// )
//     -> Result<Arc<EnveloppeCertificat>, ErreurValidation>
//     where M: ValidateurX509 + GenerateurMessages
// {
//     // Verifier la signature du message. Lance une Err si invalide.
//     if let Err(_) = message.verifier_signature() {
//         Err(ErreurValidation::new(ErreurVerification::SignatureInvalide))?
//     }
//
//     // Recuperer le certificat du message.
//     let pubkey = message.pubkey;
//     let certificat_pem = message.certificat.as_ref();
//
//     let enveloppe = if middleware.est_cache(pubkey) || certificat_pem.is_none() {
//         // Utiliser le middleware pour recuperer le certificat
//         match middleware.get_certificat(pubkey).await {
//             Some(inner) => inner,
//             None => Err(ErreurValidation::new(ErreurVerification::CertificatInconnu(pubkey.into())))?
//         }
//     } else {
//         // Charger le certificat recu avec le message
//         let vec_pem: Vec<String> = certificat_pem.unwrap().iter().map(|s| s.to_string()).collect();
//         match middleware.charger_enveloppe(&vec_pem, Some(pubkey), message.millegrille).await {
//             Ok(inner) => inner,
//             Err(_) => Err(ErreurValidation::new(ErreurVerification::CertificatInvalide))?
//         }
//     };
//
//     match middleware.valider_pour_date(enveloppe.as_ref(), &message.estampille) {
//         Ok(inner) => match inner {
//             true => Ok(enveloppe),
//             false => Err(ErreurValidation::new(ErreurVerification::CertificatInvalide))
//         },
//         Err(e) => Err(ErreurValidation::new(ErreurVerification::CertificatInvalide))
//     }
// }
