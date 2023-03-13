use std::error::Error;
use std::sync::Mutex;
use log::debug;
use serde::{Serialize, Deserialize};
use serde_json::Value;

use crate::chiffrage::CleSecrete;
use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::formatteur_messages::DateEpochSeconds;
use crate::generateur_messages::GenerateurMessages;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NotificationContenu {
    niveau: String,
    ref_hachage_bytes: String,
    format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<String>,
    message_chiffre: String,
}

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
    cle_secrete_proprietaire: CleSecrete,
    commande_cle_proprietaire: Mutex<Option<CommandeSauvegarderCle>>,
    commande_cle_transmise: Mutex<bool>,
}

impl EmetteurNotifications {
    pub fn new() -> Self {

        let cle_secrete_proprietaire = CleSecrete::generer();

        EmetteurNotifications {
            cle_secrete_proprietaire,
            commande_cle_proprietaire: Mutex::new(None::<CommandeSauvegarderCle>),
            commande_cle_transmise: Mutex::new(false),
        }
    }

    pub async fn emettre_notification_proprietaire<M,N>(
        &self,
        middleware: &M,
        contenu: N,
        niveau: &str,
        expiration: Option<i64>,
        destinataires: Option<Vec<String>>
    ) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages,
          N: Serialize + Send + Sync
    {
        let commande_transmise = *self.commande_cle_transmise.lock().expect("lock");

        // Chiffrer contenu du message
        //let mut fpkeys = Vec::new();

        // Convertir contenu en message de notification


        let commande_cle = match commande_transmise {
            true => None,
            false => {
                debug!("emettre_notification_proprietaire Emettre commande cle");
                let mut commande = match (*self.commande_cle_proprietaire.lock().expect("lock")).as_ref() {
                    Some(c) => Some(c.clone()),
                    None => None
                };

                if commande.is_none() {
                    debug!("emettre_notification_proprietaire Generer la commande MaitreDesCles");
                }

                commande
            }
        };

        todo!("fix me")
    }
}
