use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::stream::FuturesUnordered;
use lapin::message::Delivery;
use log::{debug, error, info, trace, warn};
use serde_json::{json, Map, Value};
use tokio::{join, sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, sleep, timeout}, try_join};
use tokio_stream::StreamExt;
use TypeMessageOut as TypeMessageIn;

use crate::bson::Document;
use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille, MessageInfoCertificat, ValidateurX509, VerificateurPermissions};
use crate::chiffrage::Chiffreur;
use crate::configuration::charger_configuration_avec_db;
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{formatter_message_certificat, IsConfigurationPki};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};
use crate::rabbitmq_dao::{AttenteReponse, ConfigQueue, ConfigRoutingExchange, executer_mq, MessageInterne, MessageOut, QueueType, TypeMessageOut};
use crate::serde::de::DeserializeOwned;
use crate::transactions::{Transaction, TransactionImpl};
use crate::verificateur::verifier_message;

/// Thread de traitement des messages
pub async fn recevoir_messages<M>(
    middleware: Arc<M>,
    mut rx: Receiver<MessageInterne>,
    mut tx_verifie: Sender<TypeMessage>,
    mut tx_certificats_manquants: Sender<RequeteCertificatInterne>
)
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + Chiffreur
{
    debug!("recepteur_messages.recevoir_messages : Debut thread traiter_messages");

    let mut map_attente: HashMap<String, AttenteReponse> = HashMap::new();

    while let Some(mi) = rx.recv().await {
        debug!("traiter_messages: Message recu : {:?}", mi);

        let (delivery, nom_q, tx) = match mi {
            MessageInterne::Delivery(d, q) => (d, q, &tx_verifie),
            MessageInterne::AttenteReponse(a) => {
                map_attente.insert(a.correlation.clone(), a);
                continue
            },
            MessageInterne::CancelDemandeReponse(fp) => {
                map_attente.remove(&fp);
                continue
            },
            MessageInterne::Trigger(d, q) => (d, q, &tx_verifie),
        };

        // Extraire le contenu du message
        let mut contenu = match parse(&delivery.data) {
            Ok(c) => c,
            Err(e) => {
                error!("Erreur parsing message : {:?}", e);
                continue
            }
        };

        let entete = contenu.get_entete().clone();
        let fingerprint_certificat = entete.fingerprint_certificat.as_str();
        debug!("Traiter message {:?}", entete);

        // Extraire routing key pour gerer messages qui ne requierent pas de validation
        let (mut routing_key, type_message, domaine, action) = {
            let rk = delivery.routing_key.as_str();
            let ex = delivery.exchange.as_str();
            if ex == "" {
                (None, Some(TypeMessageIn::Reponse), None, None)
            } else {
                let copie_rk = rk.to_owned();
                let mut rk_split = copie_rk.split(".");
                let type_str = rk_split.next().expect("Type message manquant de la RK");
                let domaine: Option<String> = Some(rk_split.next().expect("Domaine manquant de la RK").into());
                let action: Option<String> = Some(rk_split.last().expect("Action manquante de la RK").into());
                let type_message = match type_str {
                    "requete" => Some(TypeMessageIn::Requete),
                    "evenement" => Some(TypeMessageIn::Evenement),
                    "commande" => Some(TypeMessageIn::Commande),
                    "transaction" => Some(TypeMessageIn::Transaction),
                    _ => None
                };

                (Some(String::from(rk)), type_message, domaine, action)
            }
        };

        // Valider le message. Si on a deja le certificat, on fait juste l'extraire du Option.
        match valider_message(middleware.as_ref(), &mut contenu).await {
            Ok(t) => t,
            Err(e) => {
                debug!("Message invalide, faire traitements divers, erreur : {:?}", e);
                // NOTE : le message de certificat est intercepte par le ValidateurX509 et mis en
                //        cache directement. Aucun traitement explicite n'est requis.

                if let ErreurVerification::CertificatInconnu(fingerprint) = e {
                    // Verifier si le message contient le certificat (vieille approche)
                    if let Some(chaine_pem) = contenu.get_msg().contenu.get("chaine_pem") {
                        if let Some(fingerprint_dans_message) = contenu.get_msg().contenu.get("fingerprint") {
                            let chaine_pem_vec = match chaine_pem.as_array() {
                                Some(chaine_values) => {
                                    let mut vec = Vec::new();
                                    for v in chaine_values {
                                        vec.push(String::from(v.as_str().expect("vec pem")));
                                    }
                                    Ok(vec)
                                },
                                None => Err("Chaine pem n'est pas un array")
                            }.expect("Chaine pem n'est pas un array");
                            debug!("Certificat inconnu, message invalide mais contient chaine_pem, on l'extrait");
                            match middleware.charger_enveloppe(&chaine_pem_vec, Some(fingerprint_dans_message.as_str().expect("fingerprint"))).await {
                                Ok(enveloppe) => (),
                                Err(e) => error!("Erreur chargemnet certificat dans (message est aussi invalide) : {:?}", e),
                            };
                        }
                    } else {
                        tx_certificats_manquants.send(RequeteCertificatInterne { fingerprint: fingerprint.clone(), delivery })
                            .await.unwrap_or_else(
                            |e| error!("Erreur emission requete cert pour {}", fingerprint)
                        );
                    }
                }

                // Il n'y a plus rien a faire pour recuperer le message, on l'abandonne.
                continue
            },
        }

        let mut exchange = {
            let ex = delivery.exchange.as_str();
            if ex == "" {
                None
            } else {
                Some(String::from(ex))
            }
        };
        let properties = delivery.properties;
        let correlation_id = match properties.correlation_id() {
            Some(c) => Some(String::from(c.as_str())),
            None => None,
        };
        let reply_q = match properties.reply_to() {
            Some(q) => Some(String::from(q.as_str())),
            None => None,
        };

        debug!("Message valide {:?}, passer a la prochaine etape (correlation: {:?})", &entete, correlation_id);
        let message = match action {
            Some(inner_action) => {
                TypeMessage::ValideAction(MessageValideAction {
                    message: contenu,
                    q: nom_q,
                    reply_q,
                    correlation_id: correlation_id.clone(),
                    routing_key: routing_key.expect("routing key inconnue"),
                    domaine: domaine.expect("domaine inconnu"),
                    action: inner_action,
                    exchange,
                    type_message: type_message.clone().expect("type message inconnu"),
                })
            },
            None => {
                TypeMessage::Valide(MessageValide {
                    message: contenu,
                    q: nom_q,
                    reply_q,
                    correlation_id: correlation_id.clone(),
                    routing_key,
                    domaine,
                    exchange,
                    type_message: type_message.clone(),
                })
            }
        };

        // Verifier si le message est une reponse a une requete connue
        if let Some(tm) = type_message {
            if tm == TypeMessageOut::Reponse {
                if let Some(cid) = &correlation_id {
                    debug!("Recu type message valide ... c'est une reponse? {}", cid);
                    if let Some(ma) = map_attente.remove(cid) {
                        debug!("Recu reponse pour message en attente sur {}", cid);
                        ma.sender.send(message).unwrap_or_else(|e| error!("Erreur traitement reponse"));
                        continue
                    }
                }
            }
        }

        // Voir si on intercepte le message pour le passer a une chaine de traitement
        // differente.
        let intercepte = intercepter_message(middleware.as_ref(), &message).await;

        // Passer le message pour traitement habituel
        if intercepte == false {
            debug!("Message valide, soumettre a tx_verifie : {:?}", &entete);
            tx.send(message).await.expect("tx_verifie");
        } else {
            debug!("Message valide et intercepte, pas soumis a tx_verifie : {:?}", &entete);
        }

    }
    info!("recepteur_messages.recevoir_messages : Fin thread traiter_messages");
}

pub struct RequeteCertificatInterne {
    delivery: Delivery,
    fingerprint: String,
}

/// Task de requete et attente de reception de certificat
pub async fn task_requetes_certificats(middleware: Arc<impl GenerateurMessages>, mut rx: Receiver<RequeteCertificatInterne>, tx: Sender<MessageInterne>, skip_requete: bool) {
    info!("recepteur_messages.task_requetes_certificats : Demarrage thread");
    while let Some(req_cert) = rx.recv().await {
        let delivery = req_cert.delivery;
        let fingerprint = req_cert.fingerprint;

        // todo Verifier dans redis si le certificat est deja en cache


        if !skip_requete {
            debug!("Faire une requete pour charger le certificat {}", fingerprint);
            let requete = json!({"fingerprint": fingerprint});
            let domaine_action = format!("certificat.{}", fingerprint);
            // let message = MessageJson::new(requete);
            let routage = RoutageMessageAction::new("certificat", fingerprint.as_str());
            match middleware.transmettre_requete(routage, &requete).await {
                Ok(r) => {
                    tx.send(MessageInterne::Delivery(delivery, String::from("reponse")))
                        .await.expect("resend delivery avec certificat");
                    continue  // Ok
                },
                Err(e) => {
                    error!("Erreur / timeout sur demande certificat {} : {}", fingerprint, e);
                }
            }
        }

        // Certificat inconnu
        tx.send(MessageInterne::CancelDemandeReponse(fingerprint))
            .await.expect("cancel demande certificat sur timeout");
    }

    info!("recepteur_messages.task_requetes_certificats : Fin thread");
}

pub async fn intercepter_message<M>(middleware: &M, message: &TypeMessage) -> bool
    where M: ValidateurX509 + GenerateurMessages + IsConfigurationPki + Chiffreur
{
    // Intercepter reponses et requetes de certificat
    match &message {
        TypeMessage::Valide(inner) => {
            match &inner.correlation_id {
                Some(correlation_id) => {
                    match correlation_id.as_str() {
                        COMMANDE_CERT_MAITREDESCLES => {
                            debug!("intercepter_message Reponse certificat maitre des cles recus : {:?}", inner);
                            match middleware.recevoir_certificat_chiffrage(&inner.message).await {
                                Ok(_) => true,
                                Err(e) => {
                                    error!("intercepter_message Erreur interception certificat maitre des cles : {:?}", e);
                                    false
                                }
                            }
                        },
                        _ => false
                    }
                },
                None => false
            }
        },
        TypeMessage::ValideAction(inner) => {
            match inner.type_message {
                TypeMessageIn::Evenement => {
                    match inner.action.as_str() {
                        "infoCertificat" => {
                            debug!("intercepter_messageEvenement certificat {}, message intercepte", inner.routing_key);
                            traiter_certificatintercepter_message(middleware, inner).await;
                            true  // Intercepte
                        },
                        COMMANDE_CERT_MAITREDESCLES => {
                            debug!("intercepter_messageEvenement certificat maitre des cles recus : {:?}", inner);
                            match middleware.recevoir_certificat_chiffrage(&inner.message).await {
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
                TypeMessageIn::Requete => {
                    match inner.domaine.as_str() {
                        "certificat" => {
                            emettre_certificat(middleware, message, inner).await;
                            true
                        },
                        _ => false,
                    }
                },
                _ => {
                    false // pas intercepte
                }
            }
            // if inner.type_message == TypeMessageIn::Evenement && inner.action == "infoCertificat" {
            //     // Message deja intercepte par ValidateurX509, plus rien a faire.
            //     debug!("Evenement certificat {}, message intercepte", inner.routing_key);
            //     traiter_certificatintercepter_message(middleware, inner).await;
            //     true  // Intercepte
            // } else if inner.type_message == TypeMessageIn::Requete && inner.domaine == "certificat" {
            //     // Requete pour notre certificat, on l'emet
            //     emettre_certificat(middleware, message, inner).await;
            //     true
            // } else {
            //     false  // Pas intercepte
            // }
        },
        TypeMessage::Certificat(inner) => {
            // Rien a faire, le certificat a deja ete intercepte par ValidateurX509
            debug!("Message evenement certificat, message intercepte");
            true
        },
        TypeMessage::Regeneration => true,  // Rien a faire
    }
}

async fn emettre_certificat<M>(middleware: &M, message: &TypeMessage, inner: &MessageValideAction)
    where M: GenerateurMessages
{
    let enveloppe_privee = middleware.get_enveloppe_privee();
    let fingerprint = enveloppe_privee.fingerprint();

    // Determiner si le message correspond a notre certificat (return immediatement sinon)
    if fingerprint.as_str() != inner.action.as_str() { return }
    let reply_q = match &inner.reply_q { Some(inner) => inner.as_str(), None => return};
    let correlation_id = match &inner.correlation_id { Some(inner) => inner.as_str(), None => return};
    debug!("Emettre certificat a demandeur sous correlation_id {}", correlation_id);

    match preparer_reponse_certificats(
        middleware,
        message,
        enveloppe_privee.as_ref(),
        reply_q,
        correlation_id
    ).await {
        Ok(()) => (),
        Err(e) => error!("intercepter_message: Erreur emission reponse : {:?}", e)
    }

}

async fn traiter_certificatintercepter_message<M>(middleware: &M, inner: &MessageValideAction)
    where M: ValidateurX509
{
    // Message deja intercepte par ValidateurX509, plus rien a faire.
    debug!("Evenement certificat {}, message intercepte", inner.routing_key);

    // Charger / mettre certificat en cache au besoin.
    let m: MessageInfoCertificat = match inner.message.get_msg().map_contenu::<MessageInfoCertificat>(None) {
        Ok(m) => m,
        Err(e) => {
            info!("Erreur lecture message infoCertificat : {:?}", e);
            return
        }
    };

    match m.chaine_pem {
        Some(chaine_pem) => {
            let fingerprint = match m.fingerprint.as_ref() {
                Some(f) => Some(f.as_str()),
                None => None,
            };
            match middleware.charger_enveloppe(&chaine_pem, fingerprint).await {
                Ok(_) => (),
                Err(e) => info!("Erreur chargement message certificat.infoCertificat : {:?}", e)
            }
        },
        None => (),
    }

}

async fn preparer_reponse_certificats<M>(
    middleware: &M,
    message: &TypeMessage,
    enveloppe_privee: &EnveloppePrivee,
    reply_q: &str,
    correlation_id: &str
) -> Result<(), Box<dyn Error>>
    where M:  GenerateurMessages
{
    let message_value = formatter_message_certificat(enveloppe_privee.enveloppe.as_ref());
    let message = middleware.formatter_reponse(message_value, None)?;
    let routage = RoutageMessageReponse::new(reply_q, correlation_id);
    Ok(middleware.repondre(routage, message).await?)
}

async fn traiter_certificat_attache(validateur: &impl ValidateurX509, certificat: &Value, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
    debug!("Recu certficat attache {:?}", certificat);

    // Batir l'enveloppe pour calculer le fingerprint - va permettre de verifier le cache
    let enveloppe = match certificat.as_array() {
        Some(certs) => {
            let mut vec_strings : Vec<String> = Vec::new();
            for v in certs {
                match v.as_str() {
                    Some(c_string) => vec_strings.push(String::from(c_string)),
                    None => return Err("Valeur invalide sous _certificat".into())
                }
            }
            validateur.charger_enveloppe(&vec_strings, fingerprint).await
        },
        None => Err("Contenu de _certificat est vide".into())
    }?;

    debug!("Enveloppe du certificat attache est charge : {:?}", &enveloppe.fingerprint());

    Ok(enveloppe)
}

fn parse(data: &Vec<u8>) -> Result<MessageSerialise, String> {
    let data = match String::from_utf8(data.to_owned()) {
        Ok(data) => data,
        Err(e) => {
            return Err(format!("Erreur message n'est pas UTF-8 : {:?}", e))
        }
    };

    let message_serialise = match MessageSerialise::from_str(data.as_str()) {
        Ok(m) => m,
        Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}\n{}", e, data))?,
    };

    // let map_doc: serde_json::Result<Value> = serde_json::from_str(data.as_str());
    // let contenu = match map_doc {
    //     Ok(v) => Ok(MessageJson::new(v)),
    //     Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}\n{}", e, data)),
    // }?;

    Ok(message_serialise)
}

#[derive(Clone, Debug)]
pub struct MessageValide {
    pub message: MessageSerialise,
    pub q: String,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: Option<String>,
    pub domaine: Option<String>,
    pub exchange: Option<String>,
    pub type_message: Option<TypeMessageIn>,
}

#[derive(Clone, Debug)]
pub struct MessageValideAction {
    pub message: MessageSerialise,
    pub q: String,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: String,
    pub domaine: String,
    pub action: String,
    pub exchange: Option<String>,
    pub type_message: TypeMessageIn,
}
impl MessageValideAction {
    pub fn new<S>(message: MessageSerialise, q: S, routing_key: S, domaine: S, action: S, type_message: TypeMessageIn)
        -> Self
        where S: Into<String>
    {
        MessageValideAction {
            message,
            q: q.into(),
            reply_q: None,
            correlation_id: None,
            routing_key: routing_key.into(),
            domaine: domaine.into(),
            action: action.into(),
            exchange: None,
            type_message,
        }
    }

    pub fn get_reply_info(&self) -> Result<(String, String), String> {
        let reply_q = match &self.reply_q {
            Some(r) => r.to_owned(),
            None => Err(format!("Reply Q manquante"))?
        };
        let correlation_id = match &self.correlation_id {
            Some(r) => r.to_owned(),
            None => Err(format!("Correlation id manquant"))?
        };

        Ok((reply_q, correlation_id))
    }
}
impl TryInto<TransactionImpl> for MessageValideAction {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<TransactionImpl, Self::Error> {
        TransactionImpl::try_from(self.message)
    }
}

#[derive(Debug)]
pub struct MessageTrigger {
    pub message: MessageMilleGrille,
    pub enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: Option<String>,
    pub domaine: Option<String>,
    pub exchange: Option<String>,
    pub type_message: Option<TypeMessageIn>,
}

#[derive(Clone, Debug)]
pub struct MessageCertificat {
    enveloppe_certificat: EnveloppeCertificat,
}

#[derive(Clone, Debug)]
pub enum TypeMessage {
    Valide(MessageValide),
    ValideAction(MessageValideAction),
    Certificat(MessageCertificat),
    Regeneration,
}

#[derive(Clone, Debug)]
pub enum ErreurVerification {
    HachageInvalide,
    SignatureInvalide,
    CertificatInconnu(String),
    CertificatInvalide,
    EnteteManquante,
    ErreurGenerique,
}

impl VerificateurPermissions for MessageValideAction {
    fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
        self.message.get_extensions()
    }
}

pub async fn valider_message<M>(
    middleware: &M,
    message: &mut MessageSerialise
) -> Result<(), ErreurVerification>
where
    M: ValidateurX509 + GenerateurMessages + IsConfigurationPki,
{

    match &message.certificat {
        Some(e) => (),
        None => {
            let entete = message.get_entete();
            let fingerprint = entete.fingerprint_certificat.as_str();
            let certificat = match &message.get_msg().certificat {
                Some(c) => {
                    // Utiliser certificat attache au besoin
                    match middleware.charger_enveloppe(&c, Some(fingerprint)).await {
                        Ok(e) => {
                            // Set le certificat dans le message
                            Ok(e)
                        },
                        Err(e) => {
                            error!("Erreur chargement certificat {:?}", e);
                            Err(ErreurVerification::ErreurGenerique)?
                        }
                    }
                },
                None => {
                    match middleware.get_certificat(fingerprint).await {
                        Some(e) => {
                            Ok(e)
                        },
                        None => Err(ErreurVerification::CertificatInconnu(fingerprint.into()))?,
                    }
                }
            }?;
            message.set_certificat(certificat);
        }
    };

    match verifier_message(message, middleware, None) {
        Ok(v) => {
            if v.valide() == true {
                Ok(())
            } else if v.signature_valide == false {
                Err(ErreurVerification::SignatureInvalide)
            } else if v.certificat_valide == false {
                Err(ErreurVerification::CertificatInvalide)
            } else if let Some(hachage_valide) = v.hachage_valide {
                if hachage_valide == false {
                    Err(ErreurVerification::HachageInvalide)
                } else {
                    Err(ErreurVerification::SignatureInvalide)
                }
            } else {
                Err(ErreurVerification::ErreurGenerique)
            }
        },
        Err(e) => {
            warn!("Validation message est invalide : {:?}", e);
            Err(ErreurVerification::ErreurGenerique)
        },
    }

}
