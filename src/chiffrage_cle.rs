use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
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