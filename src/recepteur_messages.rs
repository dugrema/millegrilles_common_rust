use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use lapin::message::Delivery;
use log::{debug, error, info, warn};
use serde_json::{json, Map, Value};
use tokio::{join, sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, sleep, timeout}, try_join};
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509};
use crate::configuration::charger_configuration_avec_db;
use crate::formatteur_messages::{FormatteurMessage, MessageJson};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};
use TypeMessageOut as TypeMessageIn;

use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl};
use crate::middleware::{formatter_message_certificat, formatter_message_enveloppe_privee, IsConfigurationPki, MiddlewareDbPki, ValidateurX509Database};
use crate::rabbitmq_dao::{AttenteReponse, ConfigQueue, ConfigRoutingExchange, executer_mq, MessageInterne, MessageOut, QueueType, TypeMessageOut};
use crate::verificateur::{verifier_hachage, verifier_message, verifier_signature};

/// Thread de traitement des messages
pub async fn recevoir_messages(
    middleware: Arc<impl ValidateurX509 + GenerateurMessages + IsConfigurationPki>,
    mut rx: Receiver<MessageInterne>,
    mut tx_verifie: Sender<TypeMessage>,
    mut tx_certificats_manquants: Sender<RequeteCertificatInterne>
) {
    debug!("MAIN : Debut thread traiter_messages");

    let mut map_attente: HashMap<String, AttenteReponse> = HashMap::new();

    while let Some(mi) = rx.recv().await {
        debug!("traiter_messages: Message recu : {:?}", mi);

        let (delivery, tx) = match mi {
            MessageInterne::Delivery(d) => (d, &tx_verifie),
            MessageInterne::AttenteReponse(a) => {
                map_attente.insert(a.correlation.clone(), a);
                continue
            },
            MessageInterne::CancelDemandeReponse(fp) => {
                map_attente.remove(&fp);
                continue
            },
            MessageInterne::Trigger(d) => (d, &tx_verifie),
        };

        // Extraire le contenu du message
        let contenu = match parse(&delivery.data) {
            Ok(c) => c,
            Err(e) => {
                debug!("Erreur parsing message : {:?}", e);
                continue
            }
        };

        let entete = contenu.get_message().get("en-tete");
        let fingerprint_certificat = match entete {
            Some(e) => {
                match e.get("fingerprint_certificat") {
                    Some(fp) => fp.as_str(),
                    None => None,
                }
            },
            None => None,
        };

        // Extraire routing key pour gerer messages qui ne requierent pas de validation
        let (mut routing_key, type_message, domaine, action) = {
            let rk = delivery.routing_key.as_str();
            if rk == "" {
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

        // Verifier s'il y a un certificat attache. S'assurer qu'il est dans le cache local.
        let enveloppe_certificat = match contenu.get_message().get("_certificat") {
            Some(c) => {
                match traiter_certificat_attache(middleware.as_ref(), c, fingerprint_certificat).await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        debug!("Erreur chargement certificat attache\n{:?}", e);
                        None
                    },
                }
            },
            None => None,
        };

        // Valider le message. Si on a deja le certificat, on fait juste l'extraire du Option.
        let enveloppe_certificat = match valider_message(middleware.as_ref(), &contenu, enveloppe_certificat).await {
            Ok(t) => t,
            Err(e) => {
                debug!("Message invalide, faire traitements divers, erreur : {:?}", e);
                // NOTE : le message de certificat est intercepte par le ValidateurX509 et mis en
                //        cache directement. Aucun traitement explicite n'est requis.

                if let ErreurVerification::CertificatInconnu(fingerprint) = e {
                    // Verifier si le message contient le certificat (vieille approche)
                    if let Some(chaine_pem) = contenu.get_message().get("chaine_pem") {
                        if let Some(fingerprint_dans_message) = contenu.get_message().get("fingerprint") {
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
        };

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

        debug!("Message valide, passer a la prochaine etape (correlation: {:?})", correlation_id);
        let message = match action {
            Some(inner_action) => {
                TypeMessage::ValideAction(MessageValideAction {
                    message: contenu,
                    enveloppe_certificat: Some(enveloppe_certificat.clone()),
                    reply_q,
                    correlation_id: correlation_id.clone(),
                    routing_key: routing_key.expect("routing key inconnue"),
                    domaine: domaine.expect("domaine inconnu"),
                    action: inner_action,
                    exchange,
                    type_message: type_message.expect("type message inconnu"),
                })
            },
            None => {
                TypeMessage::Valide(MessageValide {
                    message: contenu,
                    enveloppe_certificat: Some(enveloppe_certificat.clone()),
                    reply_q,
                    correlation_id: correlation_id.clone(),
                    routing_key,
                    domaine,
                    exchange,
                    type_message,
                })
            }
        };

        // Verifier si le message est une reponse a une requete connue
        if let Some(cid) = &correlation_id {
            debug!("Recu type message valide ... c'est une reponse? {}", cid);
            if let Some(ma) = map_attente.remove(cid) {
                debug!("Recu reponse pour message en attente sur {}", cid);
                ma.sender.send(message).unwrap_or_else(|e| error!("Erreur traitement reponse"));
                continue
            }
        }

        // Voir si on intercepte le message pour le passer a une chaine de traitement
        // differente.
        let intercepte = intercepter_message(middleware.as_ref(), &message).await;

        // Passer le message pour traitement habituel
        if intercepte == false {
            debug!("Message valide, soumettre a tx_verifie");
            tx.send(message).await.expect("tx_verifie");
        } else {
            debug!("Message valide et intercepte, pas soumis a tx_verifie");
        }

    }
    debug!("MAIN : Fin thread traiter_messages");
}

pub struct RequeteCertificatInterne {
    delivery: Delivery,
    fingerprint: String,
}

/// Task de requete et attente de reception de certificat
pub async fn task_requetes_certificats(middleware: Arc<dyn GenerateurMessages>, mut rx: Receiver<RequeteCertificatInterne>, tx: Sender<MessageInterne>) {
    while let Some(req_cert) = rx.recv().await {
        let delivery = req_cert.delivery;
        let fingerprint = req_cert.fingerprint;

        debug!("Faire une requete pour charger le certificat {}", fingerprint);
        let requete = json!({"fingerprint": fingerprint});
        let domaine_action = format!("requete.certificat.{}", fingerprint);
        let message = MessageJson::new(requete);
        let reponse = middleware.transmettre_requete(&domaine_action, &message, None)
            .await;
        debug!("Reponse de ma requete!!!");

        // Re-send
        match reponse {
            Ok(r) => {
                tx.send(MessageInterne::Delivery(delivery))
                    .await.expect("resend delivery avec certificat");
            },
            Err(e) => {
                error!("Erreur / timeout sur demande certificat {} : {}", fingerprint, e);
                tx.send(MessageInterne::CancelDemandeReponse(fingerprint))
                    .await.expect("cancel demande certificat sur timeout");
            }
        }
    }
}

pub async fn intercepter_message(middleware: &(impl GenerateurMessages + IsConfigurationPki), message: &TypeMessage) -> bool {
    // Intercepter reponses et requetes de certificat
    match &message {
        TypeMessage::Valide(inner) => {
            false
        },
        TypeMessage::ValideAction(inner) => {
            if inner.type_message == TypeMessageIn::Evenement && inner.action == "infoCertificat" {
                // Message deja intercepte par ValidateurX509, plus rien a faire.
                debug!("Evenement certificat {}, message intercepte", inner.routing_key);
                true  // Intercepte
            } else if inner.type_message == TypeMessageIn::Requete && inner.domaine == "certificat" {
                // Requete pour notre certificat, on l'emet
                let enveloppe_privee = middleware.get_enveloppe_privee();
                let fingerprint = enveloppe_privee.fingerprint();
                if fingerprint.as_str() == inner.action.as_str() {
                    let message = formatter_message_enveloppe_privee(enveloppe_privee.as_ref());
                    if let Some(reply_q) = &inner.reply_q {
                        if let Some(correlation_id) = &inner.correlation_id {
                            debug!("Emettre certificat a demandeur sous correlation_id {}", correlation_id);
                            middleware.repondre(&message, reply_q, correlation_id).await.expect("repondre requete certificat");
                            true  // Intercepte
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false  // Pas intercepte
            }
        },
        TypeMessage::Certificat(inner) => {
            // Rien a faire, le certificat a deja ete intercepte par ValidateurX509
            debug!("Message evenement certificat, message intercepte");
            true
        },
    }
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

fn parse(data: &Vec<u8>) -> Result<MessageJson, String> {
    let data = match String::from_utf8(data.to_owned()) {
        Ok(data) => data,
        Err(e) => {
            return Err(format!("Erreur message n'est pas UTF-8 : {:?}", e))
        }
    };

    let map_doc: serde_json::Result<Value> = serde_json::from_str(data.as_str());
    let contenu = match map_doc {
        Ok(v) => Ok(MessageJson::new(v)),
        Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}\n{}", e, data)),
    }?;

    Ok(contenu)
}

#[derive(Debug)]
pub struct MessageValide {
    pub message: MessageJson,
    pub enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: Option<String>,
    pub domaine: Option<String>,
    pub exchange: Option<String>,
    pub type_message: Option<TypeMessageIn>,
}

#[derive(Debug)]
pub struct MessageValideAction {
    pub message: MessageJson,
    pub enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: String,
    pub domaine: String,
    pub action: String,
    pub exchange: Option<String>,
    pub type_message: TypeMessageIn,
}

#[derive(Debug)]
pub struct MessageTrigger {
    pub message: MessageJson,
    pub enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
    pub reply_q: Option<String>,
    pub correlation_id: Option<String>,
    pub routing_key: Option<String>,
    pub domaine: Option<String>,
    pub exchange: Option<String>,
    pub type_message: Option<TypeMessageIn>,
}

#[derive(Debug)]
pub struct MessageCertificat {
    enveloppe_certificat: EnveloppeCertificat,
}

#[derive(Debug)]
pub enum TypeMessage {
    Valide(MessageValide),
    ValideAction(MessageValideAction),
    Certificat(MessageCertificat),
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

async fn valider_message(
    middleware: &(impl ValidateurX509 + GenerateurMessages + IsConfigurationPki),
    message: &MessageJson,
    enveloppe_certificat: Option<Arc<EnveloppeCertificat>>
) -> Result<Arc<EnveloppeCertificat>, ErreurVerification> {

    let enveloppe = match enveloppe_certificat {
        Some(e) => Ok(e),
        None => {
            let entete = match message.get_message().get("en-tete") {
                Some(e) => Ok(e),
                None => Err(ErreurVerification::EnteteManquante),
            }?;
            let fingerprint = entete.get("fingerprint_certificat").expect("fingerprint");
            let fp_str = fingerprint.as_str().expect("fingerprint str");
            // Tenter de charger l'enveloppe a partir du validateur (cache, db, etc.)
            match middleware.get_certificat(fp_str).await {
                Some(e) => Ok(e),
                None => Err(ErreurVerification::CertificatInconnu(fp_str.into())),
            }
        }
    }?;

    match verifier_message(message, enveloppe.as_ref(), middleware.idmg(), None) {
        Ok(v) => {
            if v.valide() == true {
                Ok(enveloppe)
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