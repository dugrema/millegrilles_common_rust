use std::collections::HashMap;
use std::error::Error;
use log::debug;
use serde_json::json;
use crate::chiffrage_cle::{CleDechiffree, ReponseDechiffrageCles};
use crate::common_messages::{DataChiffre, DataDechiffre};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::constantes::*;
use crate::recepteur_messages::TypeMessage;

pub async fn dechiffrer_documents<M>(middleware: &M, liste_data_chiffre: Vec<DataChiffre>)
    -> Result<Vec<DataDechiffre>, Box<dyn Error>>
    where M: GenerateurMessages
{
    let mut liste_hachage_bytes = Vec::new();
    for d in &liste_data_chiffre {
        if let Some(inner) = d.ref_hachage_bytes.as_ref() {
            liste_hachage_bytes.push(inner.as_str())
        }
    }
    let cles_dechiffrees = get_cles_dechiffrees(middleware, liste_hachage_bytes).await?;

    let mut data_dechiffre = Vec::new();
    for d in liste_data_chiffre {
        if let Some(hachage_bytes) = d.ref_hachage_bytes.as_ref() {
            if let Some(cle) = cles_dechiffrees.get(hachage_bytes) {
                let data = dechiffrer_data(cle, d).await?;
                data_dechiffre.push(data);
            }
        }
    }

    Ok(data_dechiffre)
}

pub async fn get_cles_dechiffrees<M,S>(middleware: &M, liste_hachage_bytes: Vec<S>)
    -> Result<HashMap<String, CleDechiffree>, Box<dyn Error>>
    where M: GenerateurMessages, S: AsRef<str>
{
    let requete_cles = json!({
        MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
    });
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L3Protege])
        .build();
    debug!("dechiffrer_documents Requete cles config notifications : {:?}", requete_cles);
    let reponse_cles: ReponseDechiffrageCles = match middleware.transmettre_requete(routage, &requete_cles).await? {
        TypeMessage::Valide(inner) => {
            inner.message.parsed.map_contenu(None)?
        },
        _ => Err(format!("dechiffrage.get_cles_dechiffrees Message reponse invalide"))?
    };

    debug!("dechiffrer_documents Reponse cles dechiffrer config notifications : {:?}", reponse_cles);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let mut cles = HashMap::new();
    if let Some(inner) = reponse_cles.cles {
        for (hachage_bytes, information_cle) in inner {
            let cle_dechiffree = CleDechiffree::dechiffrer_information_cle(enveloppe_privee.as_ref(), information_cle)?;
            cles.insert(hachage_bytes, cle_dechiffree);
        }
    }

    Ok(cles)
}

pub async fn dechiffrer_data(cle: &CleDechiffree, data: DataChiffre) -> Result<DataDechiffre, Box<dyn Error>> {

    todo!("fix me")
}