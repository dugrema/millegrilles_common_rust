use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;

use crate::chiffrage::FormatChiffrage;
use crate::chiffrage_cle::{CommandeSauvegarderCle, IdentiteCle};

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionCle {
//     // Identite
//     pub hachage_bytes: String,
//     pub domaine: String,
//     pub identificateurs_document: HashMap<String, String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub user_id: Option<String>,
//     pub signature_identite: String,
//
//     // Cle chiffree
//     pub cle: String,
//
//     // Dechiffrage contenu
//     pub format: FormatChiffrage,
//     pub iv: Option<String>,
//     pub tag: Option<String>,
//     pub header: Option<String>,
//
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub partition: Option<String>,
// }
//
// impl TransactionCle {
//     pub fn new_from_commande(commande: &CommandeSauvegarderCle, fingerprint: &str)
//         -> Result<Self, Box<dyn Error>>
//     {
//         let cle = match commande.cles.get(fingerprint) {
//             Some(c) => c,
//             None => {
//                 Err(format!("TransactionCle.new_from_commande Cle non trouvee pour fingerprint {}", fingerprint))?
//             }
//         };
//
//         Ok(TransactionCle {
//             hachage_bytes: commande.hachage_bytes.to_owned(),
//             domaine: commande.domaine.clone(),
//             identificateurs_document: commande.identificateurs_document.clone(),
//             user_id: commande.user_id.clone(),
//             signature_identite: commande.signature_identite.clone(),
//             cle: cle.to_owned(),
//             format: commande.format.clone(),
//             iv: commande.iv.clone(),
//             tag: commande.tag.clone(),
//             header: commande.header.clone(),
//             partition: commande.partition.clone(),
//         })
//     }
//
//     pub fn into_commande<S>(self, fingerprint: S) -> CommandeSauvegarderCle
//         where S: Into<String>
//     {
//         let fingerprint_ = fingerprint.into();
//         let mut cles: HashMap<String, String> = HashMap::new();
//         cles.insert(fingerprint_, self.cle);
//         CommandeSauvegarderCle {
//             hachage_bytes: self.hachage_bytes,
//             domaine: self.domaine,
//             identificateurs_document: self.identificateurs_document,
//             user_id: self.user_id,
//             signature_identite: self.signature_identite,
//             cles,
//             format: self.format,
//             iv: self.iv,
//             tag: self.tag,
//             header: self.header,
//             partition: self.partition,
//             fingerprint_partitions: None
//         }
//     }
//
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteVerifierPreuve {
    pub cles: Vec<IdentiteCle>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemandeSignature {
    pub roles: Option<Vec<String>>,     // Ex: ["media", "fichiers"],
    pub domaines: Option<Vec<String>>,  // Ex: ["GrosFichiers"]
    pub exchanges: Option<Vec<String>>, // Ex: ["4.secure", "3.protege", "2.prive", "1.public"]
    pub dns: Option<Value>,  // Ex: {"localhost": true, "hostnames": ["media"], "domain": true}
}
