use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::chiffrage::{CommandeSauvegarderCle, FormatChiffrage};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCle {
    pub cle: String,
    pub domaine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    pub format: FormatChiffrage,
    pub hachage_bytes: String,
    pub identificateurs_document: HashMap<String, String>,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
}

impl TransactionCle {
    pub fn new_from_commande(commande: &CommandeSauvegarderCle, fingerprint: &str)
        -> Result<Self, Box<dyn Error>>
    {
        let cle = match commande.cles.get(fingerprint) {
            Some(c) => c,
            None => {
                Err(format!("TransactionCle.new_from_commande Cle non trouvee pour fingerprint {}", fingerprint))?
            }
        };

        Ok(TransactionCle {
            cle: cle.to_owned(),
            domaine: commande.domaine.clone(),
            partition: commande.partition.clone(),
            format: commande.format.clone(),
            hachage_bytes: commande.hachage_bytes.to_owned(),
            identificateurs_document: commande.identificateurs_document.clone(),
            iv: commande.iv.clone(),
            tag: commande.tag.clone(),
            header: commande.header.clone(),
        })
    }

    pub fn into_commande<S>(self, fingerprint: S) -> CommandeSauvegarderCle
        where S: Into<String>
    {
        let fingerprint_ = fingerprint.into();
        let mut cles: HashMap<String, String> = HashMap::new();
        cles.insert(fingerprint_, self.cle);
        CommandeSauvegarderCle {
            cles,
            domaine: self.domaine,
            partition: self.partition,
            format: self.format,
            hachage_bytes: self.hachage_bytes,
            identificateurs_document: self.identificateurs_document,
            iv: self.iv,
            tag: self.tag,
            header: self.header,
            fingerprint_partitions: None
        }
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteVerifierPreuve {
    // cles: HashMap<String, String>,
    pub cles: Vec<TransactionCle>,
    // domaine: Option<String>,
}
