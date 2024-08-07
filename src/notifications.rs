use std::collections::HashMap;
use std::error::Error;
use std::sync::Mutex;
use log::{debug, error, warn};
use serde::{Serialize, Deserialize};
use serde_json::{json, Map, Value};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io;
use std::io::prelude::*;
use std::str::from_utf8;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::chiffrage_mgs4::CleSecreteCipher;
use millegrilles_cryptographie::ed25519_dalek::{SecretKey, SigningKey};
use millegrilles_cryptographie::heapless;
use millegrilles_cryptographie::messages_structs::{optionepochseconds, DechiffrageInterMillegrilleOwned, MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesBuilderDefault, RoutageMessage, MessageMilleGrilleBufferContenu};
use millegrilles_cryptographie::x25519::{CleDerivee, deriver_asymetrique_ed25519};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use multibase::{Base, encode};

use crate::certificats::ValidateurX509;

use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::common_messages::{MessageReponse, verifier_reponse_ok, verifier_reponse_ok_option};
use crate::constantes::*;
use crate::formatteur_messages::build_message_action;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;

/// Contenu chiffre du message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationMessageInterne {
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub content: String,
    pub version: i32,
    pub format: String,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct NotificationMessageUsager {
//     pub user_id: String,
//     pub from: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub subject: Option<String>,
//     pub content: String,
//     pub version: i32,
//     pub format: String,
// }
/// Enveloppe du message de notification
// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct NotificationContenu {
//     niveau: String,
//     ref_hachage_bytes: String,
//     format: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     header: Option<String>,
//     message_chiffre: String,
// }

/// Enveloppe de la notification, routage
#[derive(Clone, Serialize, Deserialize)]
struct Notification {
    message: MessageMilleGrillesOwned,
    #[serde(skip_serializing_if = "Option::is_none")]
    destinataires: Option<Vec<String>>,
    #[serde(with = "optionepochseconds", skip_serializing_if = "Option::is_none")]
    expiration: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    niveau: Option<String>,
    // message: NotificationContenu,
    // #[serde(rename = "_cle", skip_serializing_if = "Option::is_none")]
    // cle: Option<MessageMilleGrille>,
}

pub struct EmetteurNotifications {
    from: Option<String>,
    cle_derivee_proprietaire: CleSecreteCipher,
    commande_cle_proprietaire: Mutex<Option<MessageMilleGrillesBufferDefault>>,
    commande_cle_transmise: Mutex<bool>,
    ref_hachage_bytes: Mutex<Option<String>>,
}

#[derive(Clone, Deserialize)]
pub struct MessageCertificat {
    certificat: Vec<String>
}

impl EmetteurNotifications {

    pub fn new(enveloppe_ca: &EnveloppeCertificat, champ_from: Option<String>) -> Result<Self, crate::error::Error> {

        let cle_millegrille_public = &enveloppe_ca.certificat.public_key()?;
        let fingerprint_ca = enveloppe_ca.fingerprint()?;
        let cle_derivee_proprietaire = deriver_asymetrique_ed25519(cle_millegrille_public)?;
        let cle_cipher = CleSecreteCipher::CleDerivee((fingerprint_ca, cle_derivee_proprietaire));

        Ok(EmetteurNotifications {
            from: champ_from,
            cle_derivee_proprietaire: cle_cipher,
            commande_cle_proprietaire: Mutex::new(None::<MessageMilleGrillesBufferDefault>),
            commande_cle_transmise: Mutex::new(false),
            ref_hachage_bytes: Mutex::new(None),
        })
    }

    pub async fn emettre_notification_proprietaire<M>(
        &self,
        middleware: &M,
        contenu: NotificationMessageInterne,
        niveau: &str,
        expiration: Option<i64>,
        destinataires: Option<Vec<String>>
    ) -> Result<(), crate::error::Error>
    where M: GenerateurMessages + ValidateurX509 + CleChiffrageHandler
    {
        let commande_transmise = self.commande_cle_transmise.lock().expect("lock").clone();
        let enveloppe_signature = middleware.get_enveloppe_signature();
        let cles_chiffrage = middleware.get_publickeys_chiffrage();

        // Generer le message
        let cle_proprietaire = &self.cle_derivee_proprietaire;
        let cipher = millegrilles_cryptographie::chiffrage_mgs4::CipherMgs4::with_secret(cle_proprietaire.to_owned())?;
        let origine = enveloppe_signature.enveloppe_pub.idmg()?;
        let mut generateur = MessageMilleGrillesBuilderDefault::from_serializable(
            millegrilles_cryptographie::messages_structs::MessageKind::CommandeInterMillegrille,
            &contenu
        )?
            .enveloppe_signature(enveloppe_signature.as_ref())?
            .routage(RoutageMessage::for_action(DOMAINE_NOM_MESSAGERIE, "nouveauMessage"))
            .origine(origine.as_str())
            .cles_chiffrage(cles_chiffrage.iter().map(|c| c.as_ref()).collect());

        // Injecter l'identificateur de la cle, retirer certificats

        generateur.certificat = None;  // Retirer le certificat (redondant)

        let mut buffer = Vec::new();
        let message_signe_ref = generateur.encrypt_into_alloc(&mut buffer, cipher)?;
        let mut message_signe: MessageMilleGrillesOwned = message_signe_ref.try_into()?;

        error!("notifications.emettre_notification_proprietaire **FIX ME**\n{}\nCles: {:?}", serde_json::to_string(&message_signe)?, cles_chiffrage);

        let (cle, cle_id) = match commande_transmise {
            true => {
                // Remplacer ref_hachage_bytes
                let cle_id = match (*self.ref_hachage_bytes.lock().expect("lock")).as_ref() {
                    Some(c) => c.clone(),
                    None => panic!("emettre_notification_proprietaire commande_transmise == true, ref_hachage_bytes None")
                };
                (None, cle_id)
            },
            false => {
                debug!("emettre_notification_proprietaire Emettre commande cle");
                let mut cle_id = message_signe.dechiffrage.as_ref().expect("dechiffrage").cle_id.as_ref().expect("cle_id").clone();

                let (mut commande_outer, cle_id) = match (*self.commande_cle_proprietaire.lock().expect("lock")).as_ref() {
                    Some(c) => {
                        let message_ref = c.parse()?;
                        let cle_id = match message_ref.dechiffrage {
                            Some(inner) => match inner.cle_id {
                                Some(inner) => inner.to_string(),
                                None => Err(crate::error::Error::Str("emettre_notification_proprietaire Erreur dechiffrage cle_id vide"))?
                            },
                            None => Err(crate::error::Error::Str("emettre_notification_proprietaire Erreur dechiffrage cle vide"))?
                        };
                        (Some(c.clone()), cle_id)
                    },
                    None => (None, cle_id)
                };

                if commande_outer.is_none() {
                    debug!("emettre_notification_proprietaire Generer la commande MaitreDesCles");

                    let mut identificateurs_document = HashMap::new();
                    identificateurs_document.insert("notification".to_string(), "true".to_string());

                    let commande = CommandeSauvegarderCle::from_message_chiffre(&message_signe, identificateurs_document)?;

                    // Signer commande
                    let mut routage_builder = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege]);
                    let mut partition = None;
                    if let Some(inner) = commande.partition.as_ref() {
                        partition = Some(inner.clone());
                        routage_builder = routage_builder.partition(inner);
                    }
                    let routage = routage_builder.build();

                    let (commande_signee, message_id) = middleware.build_message_action(
                        millegrilles_cryptographie::messages_structs::MessageKind::Commande, routage, &commande)?;

                    error!("Commande cle notifications signee\n{}", from_utf8(commande_signee.buffer.as_slice()).expect("from_utf8"));

                    let commande_signee_ref = commande_signee.parse()?;
                    let mut commande_signee: MessageMilleGrillesOwned = commande_signee_ref.try_into()?;
                    if let Some(partition) = partition {
                        commande_signee.ajouter_attachement("partition", partition)?;
                    }
                    let commande_signee: MessageMilleGrillesBufferDefault = commande_signee.try_into()?;

                    error!("Commande cle avec attachement\n{}", from_utf8(commande_signee.buffer.as_slice()).expect("from_utf8"));

                    {
                        // Conserver message_id
                        let mut guard = self.ref_hachage_bytes.lock().expect("lock");
                        guard.replace(message_id);
                    }

                    // Conserver commande signee
                    let mut guard = self.commande_cle_proprietaire.lock().expect("lock");
                    guard.replace(commande_signee.clone());

                    // Retourner commande signee
                    commande_outer = Some(commande_signee);
                }

                // Retirer les cles de chiffrage - conservees avec commande_outer
                message_signe.dechiffrage.as_mut().expect("dechiffrage").cles.take();

                (commande_outer, cle_id)
            }
        };

        // Retirer les cles de chiffrage, ajuster le cle_id
        let mut dechiffrage = message_signe.dechiffrage.as_mut().expect("dechiffrage");
        dechiffrage.cles = None;
        dechiffrage.cle_id = Some(cle_id.clone());

        // let message_a_signer = MessageInterMillegrille {
        //     contenu: message_contenu,
        //     origine: middleware.idmg().to_owned(),
        //     dechiffrage: DechiffrageInterMillegrilleOwned {
        //         hachage: None,
        //         cle_id: Some(cle_id),
        //         format: "mgs4".to_owned(),
        //         header: Some(cipher.get_header().to_owned()),
        //         nonce: None,
        //         cles: None,
        //         verification: None,
        //     }
        // };
        //
        // let mut message_signe = middleware.formatter_message(
        //     MessageKind::CommandeInterMillegrille, &message_a_signer,
        //     Some(DOMAINE_NOM_MESSAGERIE), Some("nouveauMessage"), None::<&str>,
        //     None::<&str>, Some(1), false)?;
        // message_signe.retirer_certificats();  // Retirer certificat, redondant

        // Convertir contenu en message de notification
        let expiration = match expiration {
            // Some(e) => Some(DateEpochSeconds::from_i64(e)),
            Some(e) => DateTime::from_timestamp(e as i64, 0),
            None => None
        };

        // let message_signe_buffer: MessageMilleGrillesBufferDefault = message_signe.try_into()?;

        let mut notification = Notification {
            message: message_signe,  // from_utf8(message_signe_buffer.buffer.as_slice())?.to_string(),
            destinataires,
            expiration,
            niveau: Some(niveau.to_owned()),
        };

        debug!("emettre_notification_proprietaire Notification a transmettre a {:?}", notification.destinataires);

        error!("notifications Objet Notification\n{}", serde_json::to_string(&notification)?);

        let mut routage = RoutageMessageAction::builder(
            DOMAINE_NOM_MESSAGERIE, ACTION_NOTIFIER, vec![Securite::L1Public]
        ).build();

        let (message_notification, notification_id) = middleware.build_message_action(
            millegrilles_cryptographie::messages_structs::MessageKind::Commande,
            routage.clone(), &notification
        )?;
        routage.correlation_id = Some(notification_id);

        let mut message_notification: MessageMilleGrillesOwned = message_notification.parse()?.try_into()?;
        if let Some(cle) = cle {
            debug!("notifications Message notification cle buffer\n{}", from_utf8(cle.buffer.as_slice()).expect("from_utf8"));
            let cle_owned: MessageMilleGrillesOwned = cle.parse_to_owned()?;
            message_notification.ajouter_attachement("cle", serde_json::to_value(cle_owned)?)?;
        }

        // let reponse = middleware.transmettre_commande(routage, notification).await?;
        let type_message = TypeMessageOut::Commande(routage);
        let message_notification: MessageMilleGrillesBufferDefault = message_notification.try_into()?;
        let reponse = middleware.emettre_message(type_message, message_notification).await?;

        match reponse {
            Some(r) => match r {
                TypeMessage::Valide(m) => {
                    let message_ref = m.message.parse()?;
                    let message_ok: MessageReponse = message_ref.contenu()?.deserialize()?; //serde_json::from_str(message_ref.contenu)?;
                    if let Some(true) = message_ok.ok {
                        // Marquer cle comme transmise
                        let mut guard = self.commande_cle_transmise.lock().expect("lock");
                        *guard = true;
                    }
                },
                _ => Err(format!("notifications.emettre_notification_proprietaire Mauvais type de reponse sur notification"))?
            },
            None => warn!("emettre_notification_proprietaire Aucune reponse")
        }

        Ok(())
    }

    // fn chiffrer_contenu_notification<S>(contenu: &S, cipher: &mut CipherMgs4)
    //     -> Result<String, Box<dyn Error>>
    //     where S: Serialize
    // {
    //     let contenu = serde_json::to_string(contenu)?;
    //     let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    //     encoder.write_all(contenu.as_bytes())?;
    //     let contenu = encoder.finish()?;
    //
    //     let mut output_buffer = [0u8; 128 * 1024];
    //     let mut position = cipher.update(contenu.as_slice(), &mut output_buffer[..])?;
    //     position += cipher.finalize_keep(&mut output_buffer[position..])?;
    //
    //     let contenu = encode(Base::Base64, &output_buffer[..position]);
    //
    //     // Retirer premier caracter (mulibase base64 'm')
    //     Ok(contenu[1..].to_string())
    // }

    // pub async fn emettre_notification_usager<M,D,S,N>(
    //     &self,
    //     middleware: &M,
    //     user_id: S,
    //     contenu: NotificationMessageInterne,
    //     niveau: N,
    //     domaine: D,
    //     expiration: Option<i64>,
    //     cle_dechiffree: Option<CleDechiffree>
    // ) -> Result<String, crate::error::Error>
    //     where
    //         M: GenerateurMessages + ValidateurX509 + ChiffrageFactoryTrait,
    //         D: AsRef<str>, S: AsRef<str>, N: AsRef<str>
    // {
    //     let user_id = user_id.as_ref();
    //     let niveau = niveau.as_ref();
    //     let domaine = domaine.as_ref();
    //
    //     let cle_deja_sauvegardee = cle_dechiffree.is_some();
    //
    //     todo!("messages inter-millegrilles fix-me")
    //     // let (cle_derivee, cle_id) = match cle_dechiffree {
    //     //     Some(inner) => {
    //     //         let public_peer = [0u8; 32]; // Dummy vide
    //     //         let cle_derivee = CleDerivee { secret: inner.cle_secrete, public_peer };
    //     //         (cle_derivee, Some(inner.hachage_bytes))
    //     //     },
    //     //     None => {
    //     //         debug!("emettre_notification_usager Generer une nouvelle cle secrete pour notifications de l'usager");
    //     //         let cle_privee = middleware.get_enveloppe_signature();
    //     //         let cle_millegrille_public = &cle_privee.enveloppe_ca.cle_publique;
    //     //         let cle_derivee_proprietaire = deriver_asymetrique_ed25519(cle_millegrille_public)?;
    //     //         (cle_derivee_proprietaire, None)
    //     //     }
    //     // };
    //     //
    //     // let mut cipher = CipherMgs4::new_avec_secret(&cle_derivee)?;
    //     // // Serialiser, compresser (gzip) et chiffrer le contenu de la notification.
    //     // let message_contenu = Self::chiffrer_contenu_notification(&contenu, &mut cipher)?;
    //     // let hachage_contenu = cipher.get_hachage().expect("get_hachage").to_owned();
    //     // // Convertir contenu en message de notification
    //     // let expiration = match expiration {
    //     //     // Some(e) => Some(DateEpochSeconds::from_i64(e)),
    //     //     Some(e) => DateTime::from_timestamp(e as i64, 0),
    //     //     None => None
    //     // };
    //     // let mut cle_id = match cle_id {
    //     //     Some(inner) => inner,
    //     //     None => cipher.get_hachage().expect("get_hachage").to_owned()
    //     // };
    //     //
    //     // let commande_cles_messagerie = if cle_deja_sauvegardee == false {
    //     //     debug!("emettre_notification_usager Generer commande maitre des cles");
    //     //     let mut identificateurs_document = HashMap::new();
    //     //     identificateurs_document.insert("notification".to_string(), "true".to_string());
    //     //     identificateurs_document.insert("user_id".to_string(), user_id.to_string());
    //     //
    //     //     // let cle_privee = middleware.get_enveloppe_signature();
    //     //     // let cle_ca = cle_privee.enveloppe_ca.as_ref();
    //     //
    //     //     let mut public_keys = middleware.get_publickeys_chiffrage();
    //     //
    //     //     if public_keys.len() == 0 {
    //     //         debug!("emettre_notification_usager Il manque les certificats de chiffrage - charger");
    //     //         middleware.charger_certificats_chiffrage(middleware).await?;
    //     //         public_keys = middleware.get_publickeys_chiffrage();
    //     //         if public_keys.len() == 1 {
    //     //             Err(format!("Erreur chargement certificats maitre des cles - non recus"))?;
    //     //         }
    //     //     }
    //     //
    //     //     // public_keys.push(FingerprintCertPublicKey::new(
    //     //     //     cle_ca.fingerprint.clone(), cle_ca.cle_publique.clone(), true));
    //     //     debug!("emettre_notification_usager Public keys chiffrage {:?}", public_keys);
    //     //     let cipher_keys = cipher.get_cipher_keys(&public_keys)?;
    //     //
    //     //     let mut partition = "dummy".to_string();
    //     //     for k in &public_keys {
    //     //         if k.est_cle_millegrille == false {
    //     //             partition = k.fingerprint.clone();
    //     //             break;
    //     //         }
    //     //     }
    //     //
    //     //     let commande_cles_messagerie = cipher_keys.get_commande_sauvegarder_cles(
    //     //         "Messagerie", None, identificateurs_document)?;
    //     //
    //     //     // Emettre la commande de cles messagerie en premier - il faut eviter que la commande
    //     //     // de cle pour le domaine soit acceptee avant la cle de Messagerie
    //     //     let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
    //     //         .partition(partition.as_str())
    //     //         .build();
    //     //     debug!("emettre_notification_usager Transmettre commande maitre des cles messagerie : {:?}", commande_cles_messagerie);
    //     //     let reponse_cles = middleware.transmettre_commande(routage, &commande_cles_messagerie).await?;
    //     //     debug!("emettre_notification_usager Reponse commande maitre des cles : {:?}", reponse_cles);
    //     //     if verifier_reponse_ok_option(&reponse_cles) == false {
    //     //         Err(format!("Erreur sauvegarde cle notification Messagerie : {:?}", reponse_cles))?;
    //     //     }
    //     //
    //     //     // Emettre cle pour le domaine immediatement - sert a reutiliser la cle
    //     //     let mut commande_cles_domaine = commande_cles_messagerie.clone();
    //     //     commande_cles_domaine.domaine = domaine.to_owned();
    //     //
    //     //     let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE, vec![Securite::L3Protege])
    //     //         .partition(partition.as_str())
    //     //         .build();
    //     //     debug!("emettre_notification_usager Transmettre commande maitre des cles domaine {} : {:?}", domaine, commande_cles_domaine);
    //     //     let reponse_domaine = middleware.transmettre_commande(routage, &commande_cles_domaine).await?;
    //     //     debug!("emettre_notification_usager Reponse commande maitre des cles : {:?}", reponse_domaine);
    //     //     if verifier_reponse_ok_option(&reponse_domaine) == false {
    //     //         Err(format!("Erreur sauvegarde cle domaine {} : {:?}", domaine, reponse_domaine))?;
    //     //     }
    //     //
    //     //     todo!("messages inter-millegrilles fix-me")
    //     //     // let commande_maitredescles = middleware.formatter_message(
    //     //     //     MessageKind::Commande, &commande_cles_messagerie,
    //     //     //     Some(DOMAINE_NOM_MESSAGERIE), Some(ACTION_NOTIFIER), Some(partition.as_str()),
    //     //     //     None::<&str>, None, false)?;
    //     //     //
    //     //     // Some(commande_maitredescles)
    //     // } else {
    //     //     None  // Cle existe deja dans maitre des cles
    //     // };
    //     //
    //     // let message_a_signer = MessageInterMillegrille {
    //     //     contenu: message_contenu,
    //     //     origine: middleware.idmg().to_owned(),
    //     //     dechiffrage: DechiffrageInterMillegrilleOwned {
    //     //         hachage: None,
    //     //         cle_id: Some(cle_id.clone()),
    //     //         format: "mgs4".to_owned(),
    //     //         header: Some(cipher.get_header().to_owned()),
    //     //         cles: None,
    //     //     }
    //     // };
    //     //
    //     // let mut message_signe = middleware.formatter_message(
    //     //     MessageKind::CommandeInterMillegrille, &message_a_signer,
    //     //     Some(DOMAINE_NOM_MESSAGERIE), Some("nouveauMessage"), None::<&str>,
    //     //     None::<&str>, Some(1), false)?;
    //     // message_signe.retirer_certificats();  // Retirer certificat, redondant
    //     //
    //     // let mut notification = Notification {
    //     //     message: message_signe,
    //     //     destinataires: Some(vec![user_id.to_string()]),
    //     //     expiration,
    //     //     niveau: Some(niveau.to_owned()),
    //     // };
    //     //
    //     // debug!("emettre_notification_usager Notification a transmettre a {:?}", notification.destinataires);
    //     //
    //     // let routage = RoutageMessageAction::builder(DOMAINE_NOM_MESSAGERIE, ACTION_NOTIFIER, vec![Securite::L1Public])
    //     //     .build();
    //     //
    //     // // let mut commande = middleware.formatter_message(
    //     // //     MessageKind::Commande, &notification,
    //     // //     Some(DOMAINE_NOM_MESSAGERIE), Some(ACTION_NOTIFIER), None::<&str>,
    //     // //     None::<&str>, None, false)?;
    //     // //
    //     // // // Ajouter cle en attachement au besoin
    //     // // if let Some(inner) = commande_cles_messagerie {
    //     // //     debug!("Emettre commande cle messagerie : {:?}", inner);
    //     // //     //commande.ajouter_attachement("cle", serde_json::to_value(inner)?);
    //     // // }
    //     // //
    //     // // let reponse = middleware.emettre_message_millegrille(
    //     // //     routage, true, TypeMessageOut::Commande, commande).await?;
    //     //
    //     // let reponse = middleware.transmettre_commande(routage, notification).await?;
    //     //
    //     // if verifier_reponse_ok_option(&reponse) == false {
    //     //     error!("emettre_notification_usager Erreur transmission notification, messagerie reponse : {:?}", reponse);
    //     // }
    //     //
    //     // Ok(cle_id)
    // }
}

// #[cfg(test)]
// mod test {
//     use std::path::PathBuf;
//     use std::sync::Arc;
//     use log::debug;
//     use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
//     use openssl::x509::store::X509Store;
//     use openssl::x509::X509;
//     use tokio;
//
//     use crate::certificats::{build_store_path, charger_enveloppe, charger_enveloppe_privee, EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
//     use crate::constantes::Securite;
//     use crate::formatteur_messages::FormatteurMessage;
//     use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
//     use crate::rabbitmq_dao::TypeMessageOut;
//     use crate::recepteur_messages::{MessageValide, TypeMessage};
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     #[tokio::test]
//     async fn test_notification() -> Result<(), Box<dyn Error>> {
//         setup("test_notification");
//
//         let generateur = preparer_generateur_dummy()?;
//
//         // Test
//         let emetteur = EmetteurNotifications::new(generateur.enveloppe_ca.as_ref(), None)?;
//
//         let notification_interne = NotificationMessageInterne {
//             from: "".to_string(),
//             subject: None,
//             content: "".to_string(),
//             version: 0,
//             format: "".to_string(),
//         };
//
//         emetteur.emettre_notification_proprietaire(
//             &generateur,
//             notification_interne,
//             "info",
//             None,
//             None
//         ).await?;
//
//         Ok(())
//     }
//
//     #[tokio::test]
//     async fn test_2_notifications() -> Result<(), Box<dyn Error>> {
//         setup("test_2_notifications");
//
//         let generateur = preparer_generateur_dummy()?;
//
//         // Test
//         let emetteur = EmetteurNotifications::new(generateur.enveloppe_ca.as_ref(), None)?;
//
//         let notification_interne = NotificationMessageInterne {
//             from: "".to_string(),
//             subject: None,
//             content: "".to_string(),
//             version: 0,
//             format: "".to_string(),
//         };
//
//         emetteur.emettre_notification_proprietaire(&generateur, notification_interne.clone(), "info", None, None).await?;
//         emetteur.emettre_notification_proprietaire(&generateur, notification_interne, "info", None, None).await?;
//
//         Ok(())
//     }
//
//     struct DummyGenerateurMessages {
//         validateur: Arc<ValidateurX509Impl>,
//         enveloppe_privee: Arc<EnveloppePrivee>,
//         enveloppe_ca: Arc<EnveloppeCertificat>,
//     }
//
//     impl FormatteurMessage for DummyGenerateurMessages {
//         fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
//             self.enveloppe_privee.clone()
//         }
//
//         fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
//             todo!()
//         }
//     }
//
//     #[async_trait]
//     impl ValidateurX509 for DummyGenerateurMessages {
//         async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
//             -> Result<Arc<EnveloppeCertificat>, crate::error::Error>
//         {
//             self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await
//         }
//
//         async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
//             todo!()
//         }
//
//         fn set_flag_persiste(&self, fingerprint: &str) {
//             todo!()
//         }
//
//         async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
//             todo!()
//         }
//
//         fn est_cache(&self, fingerprint: &str) -> bool {
//             todo!()
//         }
//
//         fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
//             todo!()
//         }
//
//         fn idmg(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_pem(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_cert(&self) -> &X509 {
//             todo!()
//         }
//
//         fn store(&self) -> &X509Store {
//             todo!()
//         }
//
//         fn store_notime(&self) -> &X509Store {
//             todo!()
//         }
//
//         async fn entretien_validateur(&self) {
//             todo!()
//         }
//     }
//
//     #[async_trait]
//     impl GenerateurMessages for DummyGenerateurMessages {
//         async fn emettre_evenement<R, M>(&self, routage: R, message: &M) -> Result<(), String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn transmettre_requete<R, M>(&self, routage: R, message: &M) -> Result<TypeMessage, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn soumettre_transaction<R, M>(&self, routage: R, message: &M) -> Result<Option<TypeMessage>, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn transmettre_commande<R, M>(&self, routage: R, message: &M) -> Result<Option<TypeMessage>, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn repondre<R, M>(&self, routage: R, message: M) -> Result<(), String> where R: Into<RoutageMessageReponse>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M) -> Result<Option<TypeMessage>, String> where M: Into<MessageMilleGrillesBufferDefault> {
//             todo!()
//         }
//
//         fn mq_disponible(&self) -> bool {
//             todo!()
//         }
//
//         fn set_regeneration(&self) {
//             todo!()
//         }
//
//         fn reset_regeneration(&self) {
//             todo!()
//         }
//
//         fn get_mode_regeneration(&self) -> bool {
//             todo!()
//         }
//
//         fn get_securite(&self) -> &Securite {
//             todo!()
//         }
//     }
//
//     fn preparer_generateur_dummy() -> Result<DummyGenerateurMessages, Box<dyn Error>> {
//         // Setup
//         let ca_certfile = PathBuf::from(std::env::var("CERTFILE").unwrap_or_else(|_| "/var/opt/millegrilles/configuration/pki.millegrille.cert".into()));
//         let validateur: Arc<ValidateurX509Impl> = Arc::new(build_store_path(ca_certfile.as_path()).expect("Erreur chargement store X509"));
//
//         let keyfile = PathBuf::from(std::env::var("KEYFILE").unwrap_or_else(|_| "/var/opt/millegrilles/secrets/pki.maitrecomptes.cle".into()));
//         let certfile = PathBuf::from(std::env::var("CERTFILE").unwrap_or_else(|_| "/var/opt/millegrilles/secrets/pki.maitredescles.cert".into()));
//
//         // Preparer enveloppe privee
//         let enveloppe_privee = Arc::new(
//             charger_enveloppe_privee(
//                 certfile.as_path(),
//                 keyfile.as_path(),
//                 validateur.clone()
//             ).expect("Erreur chargement cle ou certificat")
//         );
//         let enveloppe_ca = enveloppe_privee.enveloppe_ca.clone();
//
//         Ok(DummyGenerateurMessages { validateur, enveloppe_privee, enveloppe_ca })
//     }
//
// }
