use std::collections::HashMap;
use std::error::Error;
use std::sync::Mutex;
use log::{debug, warn};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io;
use std::io::prelude::*;

use async_trait::async_trait;
use multibase::{Base, encode};

use crate::certificats::{EnveloppeCertificat, FingerprintCertPublicKey, ValidateurX509};

use crate::chiffrage::{CipherMgs, CleSecrete, MgsCipherKeys};
use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::chiffrage_ed25519::{CleDerivee, deriver_asymetrique_ed25519};
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::constantes::*;
use crate::formatteur_messages::DateEpochSeconds;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::recepteur_messages::TypeMessage;

/// Contenu chiffre du message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationMessageInterne {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub content: String,
}

/// Enveloppe du message de notification
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NotificationContenu {
    niveau: String,
    ref_hachage_bytes: String,
    format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<String>,
    message_chiffre: String,
}

/// Enveloppe de la notification, routage
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Notification {
    #[serde(skip_serializing_if = "Option::is_none")]
    destinataires: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<DateEpochSeconds>,
    message: NotificationContenu,
    #[serde(rename = "_cle", skip_serializing_if = "Option::is_none")]
    cle: Option<CommandeSauvegarderCle>,
}

pub struct EmetteurNotifications {
    from: Option<String>,
    cle_derivee_proprietaire: CleDerivee,
    commande_cle_proprietaire: Mutex<Option<CommandeSauvegarderCle>>,
    commande_cle_transmise: Mutex<bool>,
}

impl EmetteurNotifications {

    pub fn new(enveloppe_ca: &EnveloppeCertificat, champ_from: Option<String>) -> Result<Self, Box<dyn Error>> {

        let cle_millegrille_public = &enveloppe_ca.cle_publique;
        let cle_derivee_proprietaire = deriver_asymetrique_ed25519(cle_millegrille_public)?;

        Ok(EmetteurNotifications {
            from: champ_from,
            cle_derivee_proprietaire,
            commande_cle_proprietaire: Mutex::new(None::<CommandeSauvegarderCle>),
            commande_cle_transmise: Mutex::new(false),
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

        // Creer cipher pour chiffrer contenu du message
        let mut cipher = CipherMgs4::new_avec_secret(&self.cle_derivee_proprietaire)?;

        // Serialiser, compresser (gzip) et chiffrer le contenu de la notification.
        let message_chiffre: String = {
            let contenu = serde_json::to_string(&contenu)?;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(contenu.as_bytes())?;
            let contenu = encoder.finish()?;

            let mut output_buffer = [0u8; 128 * 1024];
            let mut position = cipher.update(contenu.as_slice(), &mut output_buffer[..])?;
            position += cipher.finalize_keep(&mut output_buffer[position..])?;
            encode(Base::Base64, &output_buffer[..position])
        };

        let mut message = NotificationContenu {
            niveau: niveau.to_owned(),
            ref_hachage_bytes: cipher.get_hachage().expect("get_hachage").to_owned(),
            format: "mgs4".into(),
            header: Some(cipher.get_header().to_owned()),
            message_chiffre,
        };

        // Convertir contenu en message de notification
        let expiration = match expiration {
            Some(e) => Some(DateEpochSeconds::from_i64(e)),
            None => None
        };

        let cle = match commande_transmise {
            true => {
                // Remplacer ref_hachage_bytes
                match (*self.commande_cle_proprietaire.lock().expect("lock")).as_ref() {
                    Some(c) => {
                        message.ref_hachage_bytes = c.hachage_bytes.clone();
                    },
                    None => panic!("emettre_notification_proprietaire commande_transmise == true, commande None")
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

                    let public_keys = {
                        let enveloppe_maitredescles = match middleware.transmettre_requete(routage, &json!({})).await? {
                            TypeMessage::Valide(m) => {
                                let certificat_pem: Vec<String> = m.message.parsed.map_contenu(Some("certificat"))?;
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

                        fpkeys
                    };

                    let mut identificateurs_document = HashMap::new();
                    identificateurs_document.insert("notification".to_string(), "true".to_string());
                    let cles_rechiffrees = cipher.get_cipher_keys(&public_keys)?;
                    let commande = cles_rechiffrees.get_commande_sauvegarder_cles(
                        "Messagerie", None, identificateurs_document)?;

                    let mut guard = self.commande_cle_proprietaire.lock().expect("lock");
                    guard.replace(commande.clone());

                    commande_outer = Some(commande);
                }

                commande_outer
            }
        };

        let mut notification = Notification {
            destinataires,
            expiration,
            message,
            cle,
        };

        debug!("emettre_notification_proprietaire Notification a transmettre {:?}", notification);

        let routage = RoutageMessageAction::builder(DOMAINE_NOM_MESSAGERIE, ACTION_NOTIFIER)
            .exchanges(vec![Securite::L2Prive])
            .build();

        let reponse = middleware.transmettre_commande(routage, &notification, true).await?;
        match reponse {
            Some(r) => match r {
                TypeMessage::Valide(m) => {
                    let ok: bool = m.message.parsed.map_contenu(Some("ok"))?;
                    if ok == true {
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
    use crate::formatteur_messages::{Entete, FormatteurMessage, MessageMilleGrille, MessageSerialise};
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
            from: None,
            subject: None,
            content: "".to_string()
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
            from: None,
            subject: None,
            content: "".to_string()
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

            let entete = Entete::builder("abcd1234", "efgh5678", "ijkl9012").build();
            let message = json!({
                "en-tete": entete,
                "certificat": certificat_pem,
            });
            let message = MessageSerialise::from_serializable(message).expect("from_serializable");
            let message_valide = MessageValide {
                message,
                q: "".to_string(),
                reply_q: None,
                correlation_id: None,
                routing_key: None,
                domaine: None,
                exchange: None,
                type_message: None
            };

            Ok(TypeMessage::Valide(message_valide))
        }

        async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            let entete = Entete::builder("abcd1234", "efgh5678", "ijkl9012").build();
            let message = json!({"ok": true, "en-tete": entete});
            let message_valide = MessageValide {
                message: MessageSerialise::from_serializable(message).expect("from_serializable"),
                q: "".to_string(),
                reply_q: None,
                correlation_id: None,
                routing_key: None,
                domaine: None,
                exchange: None,
                type_message: None
            };
            Ok(Some(TypeMessage::Valide(message_valide)))
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
