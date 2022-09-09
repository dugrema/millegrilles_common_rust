use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::bson::Document;
use crate::chiffrage::FormatChiffrage;

use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::certificats::ordered_map;
use crate::constantes::*;
use crate::recepteur_messages::TypeMessage;

/// Effectue une requete pour charger des cles a partir du maitre des cles
pub async fn requete_charger_cles<M>(middleware: &M, hachage_bytes: &Vec<String>)
    -> Result<ReponseDechiffrageCles, String>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .build();

    let requete = json!({"liste_hachage_bytes": hachage_bytes});

    match middleware.transmettre_requete(routage, &requete).await? {
        TypeMessage::Valide(r) => {
            match r.message.parsed.map_contenu(None) {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("chiffrage_cle.requete_charger_cles Erreur mapping REponseDechiffrageCles: {:?}", e))
            }
        },
        _ => Err(format!("chiffrage_cles.requete_charger_cles Mauvais type de reponse pour les cles"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseDechiffrageCles {
    pub acces: String,
    pub cles: Option<HashMap<String, InformationCle>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationCle {
    pub cle: String,
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub identificateurs_document: Option<HashMap<String, String>>,
    pub iv: String,
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaInformationCle {
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub identificateurs_document: Option<HashMap<String, String>>,
    pub iv: String,
    pub tag: Option<String>,
}

impl From<InformationCle> for MetaInformationCle {
    fn from(value: InformationCle) -> Self {
        MetaInformationCle {
            domaine: value.domaine,
            format: value.format,
            hachage_bytes: value.hachage_bytes,
            identificateurs_document: value.identificateurs_document,
            iv: value.iv,
            tag: value.tag,
        }
    }
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    pub fingerprint: String,
    pub cle_chiffree: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeSauvegarderCle {
    // Identite de la cle
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub signature_identite: String,

    // Cles chiffrees
    #[serde(serialize_with = "ordered_map")]
    pub cles: HashMap<String, String>,

    // Information de dechiffrage
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,

    /// Partitions de maitre des cles (fingerprint certs). Utilise pour routage de la commande.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_partitions: Option<Vec<String>>
}

/// Converti en Document Bson pour sauvegarder dans MongoDB
impl Into<Document> for CommandeSauvegarderCle {
    fn into(self) -> Document {
        let val = serde_json::to_value(self).expect("value");
        serde_json::from_value(val).expect("bson")
    }
}
