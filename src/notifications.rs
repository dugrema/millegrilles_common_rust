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

use async_trait::async_trait;
use multibase::{Base, encode};

use crate::certificats::{EnveloppeCertificat, FingerprintCertPublicKey, ValidateurX509};

use crate::chiffrage::{CipherMgs, CleSecrete, MgsCipherKeys};
use crate::chiffrage_cle::{CleDechiffree, CommandeSauvegarderCle};
use crate::chiffrage_ed25519::{CleDerivee, deriver_asymetrique_ed25519};
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::common_messages::{MessageReponse, verifier_reponse_ok, verifier_reponse_ok_option};
use crate::constantes::*;
use crate::formatteur_messages::{DateEpochSeconds, DechiffrageInterMillegrille, MessageInterMillegrille, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::middleware::ChiffrageFactoryTrait;
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
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Notification {
    message: MessageMilleGrille,
    #[serde(skip_serializing_if = "Option::is_none")]
    destinataires: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<DateEpochSeconds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    niveau: Option<String>,
    // message: NotificationContenu,
    // #[serde(rename = "_cle", skip_serializing_if = "Option::is_none")]
    // cle: Option<MessageMilleGrille>,
}

pub struct EmetteurNotifications {
    from: Option<String>,
    cle_derivee_proprietaire: CleDerivee,
    commande_cle_proprietaire: Mutex<Option<MessageMilleGrille>>,
    commande_cle_transmise: Mutex<bool>,
    ref_hachage_bytes: Mutex<Option<String>>,
}

#[derive(Clone, Deserialize)]
pub struct MessageCertificat {
    certificat: Vec<String>
}

impl EmetteurNotifications {

    pub fn new(enveloppe_ca: &EnveloppeCertificat, champ_from: Option<String>) -> Result<Self, Box<dyn Error>> {

        let cle_millegrille_public = &enveloppe_ca.cle_publique;
        let cle_derivee_proprietaire = deriver_asymetrique_ed25519(cle_millegrille_public)?;

        Ok(EmetteurNotifications {
            from: champ_from,
            cle_derivee_proprietaire,
            commande_cle_proprietaire: Mutex::new(None::<MessageMilleGrille>),
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
    ) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509
    {
        let commande_transmise = self.commande_cle_transmise.lock().expect("lock").clone();

        // Creer cipher pour chiffrer contenu du message, utiliser la cle secrete connue
        let mut cipher = CipherMgs4::new_avec_secret(&self.cle_derivee_proprietaire)?;
        // Serialiser, compresser (gzip) et chiffrer le contenu de la notification.
        let message_contenu = Self::chiffrer_contenu_notification(&contenu, &mut cipher)?;
        let hachage_contenu = cipher.get_hachage().expect("get_hachage").to_owned();

        // Convertir contenu en message de notification
        let expiration = match expiration {
            Some(e) => Some(DateEpochSeconds::from_i64(e)),
            None => None
        };

        let mut cle_id = cipher.get_hachage().expect("get_hachage").to_owned();

        let cle = match commande_transmise {
            true => {
                // Remplacer ref_hachage_bytes
                match (*self.ref_hachage_bytes.lock().expect("lock")).as_ref() {
                    Some(c) => {
                        cle_id = c.clone();
                    },
                    None => panic!("emettre_notification_proprietaire commande_transmise == true, ref_hachage_bytes None")
                };
                None
            },
            false => {
                debug!("emettre_notification_proprietaire Emettre commande cle");
                let mut commande_outer = match (*self.commande_cle_proprietaire.lock().expect("lock")).as_ref() {
                    Some(c) => Some(c.clone()),
                    None => None
                };

                if commande_outer.is_none() {
                    debug!("emettre_notification_proprietaire Generer la commande MaitreDesCles");
                    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, REQUETE_CERT_MAITREDESCLES)
                        .exchanges(vec![Securite::L1Public])
                        .build();

                    let (public_keys, partition) = {
                        let enveloppe_maitredescles = match middleware.transmettre_requete(routage, &json!({})).await? {
                            TypeMessage::Valide(m) => {
                                let certificat_message: MessageCertificat = m.message.parsed.map_contenu()?;
                                // let certificat_pem: Vec<String> = m.message.parsed.map_contenu(Some("certificat"))?;
                                let certificat_pem = certificat_message.certificat;
                                debug!("emettre_notification_proprietaire Certificat maitre des cles {:?}", certificat_pem);
                                middleware.charger_enveloppe(&certificat_pem, None, None).await?
                            },
                            _ => Err(format!("notifications.emettre_notification_proprietaire Erreur reception certificat maitre des cles (mauvais type reponse)"))?
                        };

                        // &Vec<FingerprintCertPublicKey>
                        let enveloppe_ca = middleware.get_enveloppe_signature().enveloppe_ca.clone();
                        let mut fpkeys = Vec::new();
                        fpkeys.push(FingerprintCertPublicKey {
                            fingerprint: enveloppe_ca.fingerprint.clone(),
                            public_key: enveloppe_ca.cle_publique.clone(),
                            est_cle_millegrille: true,
                        });
                        fpkeys.push(FingerprintCertPublicKey {
                            fingerprint: enveloppe_maitredescles.fingerprint.clone(),
                            public_key: enveloppe_maitredescles.cle_publique.clone(),
                            est_cle_millegrille: false,
                        });

                        (fpkeys, enveloppe_maitredescles.fingerprint.clone())
                    };

                    let mut identificateurs_document = HashMap::new();
                    identificateurs_document.insert("notification".to_string(), "true".to_string());
                    let cles_rechiffrees = cipher.get_cipher_keys(&public_keys)?;
                    let commande = cles_rechiffrees.get_commande_sauvegarder_cles(
                        "Messagerie", None, identificateurs_document)?;

                    // Signer commande
                    let mut commande_signee = middleware.formatter_message(
                        MessageKind::Commande, &commande,
                        Some(DOMAINE_NOM_MAITREDESCLES), Some(COMMANDE_SAUVEGARDER_CLE),
                        Some(partition.as_str()), None, false)?;

                    commande_signee.ajouter_attachement("partition", partition);

                    {
                        // Conserver ref_hachage_bytes
                        let mut guard = self.ref_hachage_bytes.lock().expect("lock");
                        guard.replace(commande.hachage_bytes.clone());
                    }

                    // Conserver commande signee
                    let mut guard = self.commande_cle_proprietaire.lock().expect("lock");
                    guard.replace(commande_signee.clone());

                    // Retourner commande signee
                    commande_outer = Some(commande_signee);
                }

                commande_outer
            }
        };

        // let mut commande = NotificationContenu {
        //     niveau: niveau.to_owned(),
        //     message: message_contenu,
        //     // ref_hachage_bytes: cipher.get_hachage().expect("get_hachage").to_owned(),
        //     // format: "mgs4".into(),
        //     // header: Some(cipher.get_header().to_owned()),
        //     // message_chiffre,
        // };

        let message_a_signer = MessageInterMillegrille {
            contenu: message_contenu,
            origine: middleware.idmg().to_owned(),
            dechiffrage: DechiffrageInterMillegrille {
                hachage: None,
                cle_id: Some(cle_id),
                format: "mgs4".to_owned(),
                header: Some(cipher.get_header().to_owned()),
                cles: None,
            }
        };

        let mut message_signe = middleware.formatter_message(
            MessageKind::CommandeInterMillegrille, &message_a_signer,
            Some(DOMAINE_NOM_MESSAGERIE), Some("nouveauMessage"), None::<&str>,
            Some(1), false)?;
        message_signe.retirer_certificats();  // Retirer certificat, redondant

        let mut notification = Notification {
            message: message_signe,
            destinataires,
            expiration,
            niveau: Some(niveau.to_owned()),
        };

        debug!("emettre_notification_proprietaire Notification a transmettre {:?}", notification);

        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MESSAGERIE, ACTION_NOTIFIER)
            .exchanges(vec![Securite::L1Public])
            .build();

        let mut commande = middleware.formatter_message(
            MessageKind::Commande, &notification,
            Some(DOMAINE_NOM_MESSAGERIE), Some(ACTION_NOTIFIER), None,
            None, false)?;
        // Ajouter cle en attachement au besoin
        if let Some(inner) = cle {
            commande.ajouter_attachement("cle", serde_json::to_value(inner)?);
        }

        // let reponse = middleware.transmettre_commande(routage, &notification, true).await?;
        let reponse = middleware.emettre_message_millegrille(
            routage, true, TypeMessageOut::Commande, commande).await?;

        match reponse {
            Some(r) => match r {
                TypeMessage::Valide(m) => {
                    let message_ok: MessageReponse = m.message.parsed.map_contenu()?;
                    // let ok: bool = m.message.parsed.map_contenu(Some("ok"))?;
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

    fn chiffrer_contenu_notification<S>(contenu: &S, cipher: &mut CipherMgs4)
        -> Result<String, Box<dyn Error>>
        where S: Serialize
    {
        let contenu = serde_json::to_string(contenu)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(contenu.as_bytes())?;
        let contenu = encoder.finish()?;

        let mut output_buffer = [0u8; 128 * 1024];
        let mut position = cipher.update(contenu.as_slice(), &mut output_buffer[..])?;
        position += cipher.finalize_keep(&mut output_buffer[position..])?;

        let contenu = encode(Base::Base64, &output_buffer[..position]);

        // Retirer premier caracter (mulibase base64 'm')
        Ok(contenu[1..].to_string())
    }

    pub async fn emettre_notification_usager<M,D,S,N>(
        &self,
        middleware: &M,
        user_id: S,
        contenu: NotificationMessageInterne,
        niveau: N,
        domaine: D,
        expiration: Option<i64>,
        cle_dechiffree: Option<CleDechiffree>
    ) -> Result<String, Box<dyn Error>>
        where
            M: GenerateurMessages + ValidateurX509 + ChiffrageFactoryTrait,
            D: AsRef<str>, S: AsRef<str>, N: AsRef<str>
    {
        let user_id = user_id.as_ref();
        let niveau = niveau.as_ref();
        let domaine = domaine.as_ref();

        let cle_deja_sauvegardee = cle_dechiffree.is_some();

        let (cle_derivee, cle_id) = match cle_dechiffree {
            Some(inner) => {
                let public_peer = [0u8; 32]; // Dummy vide
                let cle_derivee = CleDerivee { secret: inner.cle_secrete, public_peer };
                (cle_derivee, Some(inner.hachage_bytes))
            },
            None => {
                debug!("emettre_notification_usager Generer une nouvelle cle secrete pour notifications de l'usager");
                let cle_privee = middleware.get_enveloppe_signature();
                let cle_millegrille_public = &cle_privee.enveloppe_ca.cle_publique;
                let cle_derivee_proprietaire = deriver_asymetrique_ed25519(cle_millegrille_public)?;
                (cle_derivee_proprietaire, None)
            }
        };

        let mut cipher = CipherMgs4::new_avec_secret(&cle_derivee)?;
        // Serialiser, compresser (gzip) et chiffrer le contenu de la notification.
        let message_contenu = Self::chiffrer_contenu_notification(&contenu, &mut cipher)?;
        let hachage_contenu = cipher.get_hachage().expect("get_hachage").to_owned();
        // Convertir contenu en message de notification
        let expiration = match expiration {
            Some(e) => Some(DateEpochSeconds::from_i64(e)),
            None => None
        };
        let mut cle_id = match cle_id {
            Some(inner) => inner,
            None => cipher.get_hachage().expect("get_hachage").to_owned()
        };

        let commande_cles_messagerie = if cle_deja_sauvegardee == false {
            debug!("emettre_notification_usager Generer commande maitre des cles");
            let mut identificateurs_document = HashMap::new();
            identificateurs_document.insert("notification".to_string(), "true".to_string());
            identificateurs_document.insert("user_id".to_string(), user_id.to_string());

            // let cle_privee = middleware.get_enveloppe_signature();
            // let cle_ca = cle_privee.enveloppe_ca.as_ref();

            let mut public_keys = middleware.get_publickeys_chiffrage();

            if public_keys.len() == 0 {
                debug!("emettre_notification_usager Il manque les certificats de chiffrage - charger");
                middleware.charger_certificats_chiffrage(middleware).await?;
                public_keys = middleware.get_publickeys_chiffrage();
                if public_keys.len() == 1 {
                    Err(format!("Erreur chargement certificats maitre des cles - non recus"))?;
                }
            }

            // public_keys.push(FingerprintCertPublicKey::new(
            //     cle_ca.fingerprint.clone(), cle_ca.cle_publique.clone(), true));
            debug!("emettre_notification_usager Public keys chiffrage {:?}", public_keys);
            let cipher_keys = cipher.get_cipher_keys(&public_keys)?;

            let mut partition = "dummy".to_string();
            for k in &public_keys {
                if k.est_cle_millegrille == false {
                    partition = k.fingerprint.clone();
                    break;
                }
            }

            let commande_cles_messagerie = cipher_keys.get_commande_sauvegarder_cles(
                "Messagerie", None, identificateurs_document)?;

            // Emettre la commande de cles messagerie en premier - il faut eviter que la commande
            // de cle pour le domaine soit acceptee avant la cle de Messagerie
            let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
                .exchanges(vec![Securite::L3Protege])
                .partition(partition.as_str())
                .build();
            debug!("emettre_notification_usager Transmettre commande maitre des cles messagerie : {:?}", commande_cles_messagerie);
            let reponse_cles = middleware.transmettre_commande(routage, &commande_cles_messagerie, true).await?;
            debug!("emettre_notification_usager Reponse commande maitre des cles : {:?}", reponse_cles);
            if verifier_reponse_ok_option(&reponse_cles) == false {
                Err(format!("Erreur sauvegarde cle notification Messagerie : {:?}", reponse_cles))?;
            }

            // Emettre cle pour le domaine immediatement - sert a reutiliser la cle
            let mut commande_cles_domaine = commande_cles_messagerie.clone();
            commande_cles_domaine.domaine = domaine.to_owned();

            let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
                .exchanges(vec![Securite::L3Protege])
                .partition(partition.as_str())
                .build();
            debug!("emettre_notification_usager Transmettre commande maitre des cles domaine {} : {:?}", domaine, commande_cles_domaine);
            let reponse_domaine = middleware.transmettre_commande(routage, &commande_cles_domaine, true).await?;
            debug!("emettre_notification_usager Reponse commande maitre des cles : {:?}", reponse_domaine);
            if verifier_reponse_ok_option(&reponse_domaine) == false {
                Err(format!("Erreur sauvegarde cle domaine {} : {:?}", domaine, reponse_domaine))?;
            }

            let commande_maitredescles = middleware.formatter_message(
                MessageKind::Commande, &commande_cles_messagerie,
                Some(DOMAINE_NOM_MESSAGERIE), Some(ACTION_NOTIFIER), Some(partition.as_str()),
                None, false)?;

            Some(commande_maitredescles)
        } else {
            None  // Cle existe deja dans maitre des cles
        };

        let message_a_signer = MessageInterMillegrille {
            contenu: message_contenu,
            origine: middleware.idmg().to_owned(),
            dechiffrage: DechiffrageInterMillegrille {
                hachage: None,
                cle_id: Some(cle_id.clone()),
                format: "mgs4".to_owned(),
                header: Some(cipher.get_header().to_owned()),
                cles: None,
            }
        };

        let mut message_signe = middleware.formatter_message(
            MessageKind::CommandeInterMillegrille, &message_a_signer,
            Some(DOMAINE_NOM_MESSAGERIE), Some("nouveauMessage"), None::<&str>,
            Some(1), false)?;
        message_signe.retirer_certificats();  // Retirer certificat, redondant

        let mut notification = Notification {
            message: message_signe,
            destinataires: Some(vec![user_id.to_string()]),
            expiration,
            niveau: Some(niveau.to_owned()),
        };

        debug!("emettre_notification_usager Notification a transmettre {:?}", notification);

        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MESSAGERIE, ACTION_NOTIFIER)
            .exchanges(vec![Securite::L1Public])
            .build();

        let mut commande = middleware.formatter_message(
            MessageKind::Commande, &notification,
            Some(DOMAINE_NOM_MESSAGERIE), Some(ACTION_NOTIFIER), None,
            None, false)?;

        // Ajouter cle en attachement au besoin
        if let Some(inner) = commande_cles_messagerie {
            debug!("Emettre commande cle messagerie : {:?}", inner);
            //commande.ajouter_attachement("cle", serde_json::to_value(inner)?);
        }

        let reponse = middleware.emettre_message_millegrille(
            routage, true, TypeMessageOut::Commande, commande).await?;

        if verifier_reponse_ok_option(&reponse) == false {
            error!("emettre_notification_usager Erreur transmission notification, messagerie reponse : {:?}", reponse);
        }

        Ok(cle_id)
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::sync::Arc;
    use log::debug;
    use openssl::x509::store::X509Store;
    use openssl::x509::X509;
    use tokio;

    use crate::certificats::{build_store_path, charger_enveloppe, charger_enveloppe_privee, EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
    use crate::constantes::Securite;
    use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
    use crate::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
    use crate::rabbitmq_dao::TypeMessageOut;
    use crate::recepteur_messages::{MessageValide, TypeMessage};

    use crate::test_setup::setup;

    use super::*;

    #[tokio::test]
    async fn test_notification() -> Result<(), Box<dyn Error>> {
        setup("test_notification");

        let generateur = preparer_generateur_dummy()?;

        // Test
        let emetteur = EmetteurNotifications::new(generateur.enveloppe_ca.as_ref(), None)?;

        let notification_interne = NotificationMessageInterne {
            from: "".to_string(),
            subject: None,
            content: "".to_string(),
            version: 0,
            format: "".to_string(),
        };

        emetteur.emettre_notification_proprietaire(
            &generateur,
            notification_interne,
            "info",
            None,
            None
        ).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_2_notifications() -> Result<(), Box<dyn Error>> {
        setup("test_2_notifications");

        let generateur = preparer_generateur_dummy()?;

        // Test
        let emetteur = EmetteurNotifications::new(generateur.enveloppe_ca.as_ref(), None)?;

        let notification_interne = NotificationMessageInterne {
            from: "".to_string(),
            subject: None,
            content: "".to_string(),
            version: 0,
            format: "".to_string(),
        };

        emetteur.emettre_notification_proprietaire(&generateur, notification_interne.clone(), "info", None, None).await?;
        emetteur.emettre_notification_proprietaire(&generateur, notification_interne, "info", None, None).await?;

        Ok(())
    }

    struct DummyGenerateurMessages {
        validateur: Arc<ValidateurX509Impl>,
        enveloppe_privee: Arc<EnveloppePrivee>,
        enveloppe_ca: Arc<EnveloppeCertificat>,
    }

    impl FormatteurMessage for DummyGenerateurMessages {
        fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
            self.enveloppe_privee.clone()
        }

        fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
            todo!()
        }
    }

    #[async_trait]
    impl ValidateurX509 for DummyGenerateurMessages {
        async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
            self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await
        }

        async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
            todo!()
        }

        fn set_flag_persiste(&self, fingerprint: &str) {
            todo!()
        }

        async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
            todo!()
        }

        fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
            todo!()
        }

        fn idmg(&self) -> &str {
            todo!()
        }

        fn ca_pem(&self) -> &str {
            todo!()
        }

        fn ca_cert(&self) -> &X509 {
            todo!()
        }

        fn store(&self) -> &X509Store {
            todo!()
        }

        fn store_notime(&self) -> &X509Store {
            todo!()
        }

        async fn entretien_validateur(&self) {
            todo!()
        }
    }

    #[async_trait]
    impl GenerateurMessages for DummyGenerateurMessages {

        async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M) -> Result<(), String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M) -> Result<TypeMessage, String> where M: Serialize + Send + Sync {
            let certificat_pem: Vec<String> = self.enveloppe_privee.enveloppe.get_pem_vec().iter().map(|f| f.pem.clone()).collect();

            todo!("fix me");
            // let entete = Entete::builder("abcd1234", "efgh5678", "ijkl9012").build();
            // let message = json!({
            //     "en-tete": entete,
            //     "certificat": certificat_pem,
            // });
            // let message = MessageSerialise::from_serializable(message).expect("from_serializable");
            // let message_valide = MessageValide {
            //     message,
            //     q: "".to_string(),
            //     reply_q: None,
            //     correlation_id: None,
            //     routing_key: None,
            //     domaine: None,
            //     exchange: None,
            //     type_message: None
            // };
            //
            // Ok(TypeMessage::Valide(message_valide))
        }

        async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!("fix me");
            // let entete = Entete::builder("abcd1234", "efgh5678", "ijkl9012").build();
            // let message = json!({"ok": true, "en-tete": entete});
            // let message_valide = MessageValide {
            //     message: MessageSerialise::from_serializable(message).expect("from_serializable"),
            //     q: "".to_string(),
            //     reply_q: None,
            //     correlation_id: None,
            //     routing_key: None,
            //     domaine: None,
            //     exchange: None,
            //     type_message: None
            // };
            // Ok(Some(TypeMessage::Valide(message_valide)))
        }

        async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
            todo!()
        }

        async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool) -> Result<Option<TypeMessage>, String> {
            todo!()
        }

        async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille) -> Result<Option<TypeMessage>, String> {
            todo!()
        }

        fn mq_disponible(&self) -> bool {
            todo!()
        }

        fn set_regeneration(&self) {
            todo!()
        }

        fn reset_regeneration(&self) {
            todo!()
        }

        fn get_mode_regeneration(&self) -> bool {
            todo!()
        }

        fn get_securite(&self) -> &Securite {
            todo!()
        }
    }

    fn preparer_generateur_dummy() -> Result<DummyGenerateurMessages, Box<dyn Error>> {
        // Setup
        let ca_certfile = PathBuf::from(std::env::var("CERTFILE").unwrap_or_else(|_| "/var/opt/millegrilles/configuration/pki.millegrille.cert".into()));
        let validateur: Arc<ValidateurX509Impl> = Arc::new(build_store_path(ca_certfile.as_path()).expect("Erreur chargement store X509"));

        let keyfile = PathBuf::from(std::env::var("KEYFILE").unwrap_or_else(|_| "/var/opt/millegrilles/secrets/pki.maitrecomptes.cle".into()));
        let certfile = PathBuf::from(std::env::var("CERTFILE").unwrap_or_else(|_| "/var/opt/millegrilles/secrets/pki.maitredescles.cert".into()));

        // Preparer enveloppe privee
        let enveloppe_privee = Arc::new(
            charger_enveloppe_privee(
                certfile.as_path(),
                keyfile.as_path(),
                validateur.clone()
            ).expect("Erreur chargement cle ou certificat")
        );
        let enveloppe_ca = enveloppe_privee.enveloppe_ca.clone();

        Ok(DummyGenerateurMessages { validateur, enveloppe_privee, enveloppe_ca })
    }

}
