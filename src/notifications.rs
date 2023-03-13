use std::error::Error;
use std::sync::Mutex;
use log::debug;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io;
use std::io::prelude::*;

use multibase::{Base, encode};

use crate::certificats::EnveloppeCertificat;

use crate::chiffrage::{CipherMgs, CleSecrete};
use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::chiffrage_ed25519::{CleDerivee, deriver_asymetrique_ed25519};
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::formatteur_messages::DateEpochSeconds;
use crate::generateur_messages::GenerateurMessages;

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

    pub async fn emettre_notification_proprietaire<M,N>(
        &self,
        middleware: &M,
        contenu: NotificationMessageInterne,
        niveau: &str,
        expiration: Option<i64>,
        destinataires: Option<Vec<String>>
    ) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
    {
        let commande_transmise = *self.commande_cle_transmise.lock().expect("lock");

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

        let message = NotificationContenu {
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

        let mut notification = Notification {
            destinataires,
            expiration,
            message,
            cle: None,
        };

        notification.cle = match commande_transmise {
            true => None,
            false => {
                debug!("emettre_notification_proprietaire Emettre commande cle");
                let mut commande = match (*self.commande_cle_proprietaire.lock().expect("lock")).as_ref() {
                    Some(c) => Some(c.clone()),
                    None => None
                };

                if commande.is_none() {
                    debug!("emettre_notification_proprietaire Generer la commande MaitreDesCles");
                    todo!("creer commande");
                }

                commande
            }
        };

        todo!("fix me")
    }
}
