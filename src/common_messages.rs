use log::{debug, error};
use std::collections::HashMap;
use std::error::Error;
use mongodb::bson::{bson, Bson};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use multibase;

use crate::chiffrage::{CleSecrete, FormatChiffrage};
use crate::hachages::verifier_multihash;
use crate::formatteur_messages::DateEpochSeconds;
use crate::recepteur_messages::TypeMessage;

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

#[derive(Clone, Debug, Deserialize)]
pub struct RequeteVerifierPreuve {
    pub fingerprint: String,                    // fingerprint inclues dans la preuve
    pub preuves: HashMap<String, PreuveCle>,    // fuuid, preuve
}

#[derive(Clone, Debug, Deserialize)]
pub struct PreuveCle {
    pub date: DateEpochSeconds,
    pub preuve: String,
}

impl PreuveCle {
    pub fn verifier_preuve<S>(&self, fingerprint: S, cle: &CleSecrete) -> Result<bool, String>
        where S: AsRef<str>
    {
        let fingerprint = fingerprint.as_ref();
        //     const bufferHachage = new Uint8Array(72)
        //     bufferHachage.set(dateBytes, 0)             // Bytes 0-7   Date 64bit
        //     bufferHachage.set(fingerprintBuffer, 8)     // Bytes 8-39  Fingerprint certificat
        //     bufferHachage.set(cleSecrete, 40)           // Bytes 40-71 Cle secrete
        let mut buffer = [0u8; 72];

        // let preuve_recue_bytes: Vec<u8> = match multibase::decode(self.preuve.as_str()) {
        //     Ok(inner) => inner.1,
        //     Err(e) => Err(format!("common_messages.verifier_preuve Erreur decoder preuve : {:?}", e))?
        // };
        // debug!("Verifier preuve (recue) {:?}", preuve_recue_bytes);

        // let fingerprint_bytes: Vec<u8> = match multibase::decode(fingerprint) {
        let fingerprint_bytes: Vec<u8> = match hex::decode(fingerprint) {
            Ok(inner) => inner,
            Err(e) => Err(format!("common_messages.verifier_preuve Erreur decoder fingerprint : {:?}", e))?
        };
        debug!("Verifier preuve fingerprint bytes {:?}", fingerprint_bytes);

        let datetime_preuve = self.date.get_datetime();
        let datetime_i64 = datetime_preuve.timestamp();
        let datetime_bytes = datetime_i64.to_le_bytes();
        debug!("Datetime bytes {:?}", datetime_bytes);

        // Copier date
        buffer[0..8].copy_from_slice(&datetime_bytes[0..8]);

        // Copier fingerprint
        buffer[8..40].copy_from_slice(&fingerprint_bytes[0..32]);

        // Copier cle secrete
        buffer[40..72].copy_from_slice(&cle.0);

        // debug!("Buffer preuve : {:?}", buffer);

        // Hachage avec blake2s
        // let resultat_hachage = hacher_bytes_vu8(&buffer, Some(Code::Blake2s256));
        // debug!("Resultat hachage {:?}", resultat_hachage);
        // let valide = resultat_hachage[0..32] == preuve_recue_bytes[0..32];
        let valide = match verifier_multihash(self.preuve.as_str(), &buffer) {
            Ok(inner) => inner,
            Err(e) => {
                error!("common_messages.verifier_preuve Erreur verifier_multihash : {:?}", e);
                false
            }
        };

        Ok(valide)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemandeSignature {
    pub csr: String,
    pub roles: Option<Vec<String>>,     // Ex: ["media", "fichiers"],
    pub domaines: Option<Vec<String>>,  // Ex: ["GrosFichiers"]
    pub exchanges: Option<Vec<String>>, // Ex: ["4.secure", "3.protege", "2.prive", "1.public"]
    pub dns: Option<Value>,  // Ex: {"localhost": true, "hostnames": ["media"], "domain": true}
}

#[derive(Clone, Deserialize)]
pub struct MessageReponse {
    pub ok: Option<bool>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseSignatureCertificat {
    pub ok: Option<bool>,
    pub certificat: Option<Vec<String>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteConsignationFichiers {
    pub instance_id: Option<String>,
    pub hostname: Option<String>,
    pub primaire: Option<bool>,
    pub stats: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceFichiersRepertoire { pub taille: i64, pub nombre: i64 }

impl Into<Bson> for PresenceFichiersRepertoire {
    fn into(self) -> Bson {
        bson!({
            "taille": self.taille,
            "nombre": self.nombre,
        })
    }
}

/// Message d'information du mecanisme de consignation principal de fichiers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseInformationConsignationFichiers {
    pub instance_id: String,
    pub consignation_url: Option<String>,
    pub type_store: Option<String>,
    pub sync_intervalle: Option<i64>,
    pub sync_actif: Option<bool>,
    pub supporte_archives: Option<bool>,
    pub data_chiffre: Option<DataChiffre>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_download: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_bucket: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp_backup: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub primaire: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archives: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphelins: Option<PresenceFichiersRepertoire>,

    pub ok: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffre {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_hachage_bytes: Option<String>,
    pub data_chiffre: String,
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationDechiffrage {
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_hachage_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageConfirmation {
    ok: Option<bool>,
}

pub fn verifier_reponse_ok(message: &TypeMessage) -> bool {
    match message {
        TypeMessage::Valide(m) => {
            match m.message.parsed.map_contenu::<MessageConfirmation>() {
                Ok(r) => {
                    match r.ok {
                        Some(r) => r,
                        None => false
                    }
                },
                Err(_) => false
            }
        },
        _ => false
    }
}

pub fn verifier_reponse_ok_option(reponse: &Option<TypeMessage>) -> bool {
    match reponse {
        Some(r) => {
            verifier_reponse_ok(r)
        },
        None => false
    }
}

pub struct DataDechiffre {
    pub ref_hachage_bytes: Option<String>,
    pub data_dechiffre: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRetirerSubscriptionWebpush {
    pub endpoint: String,
    pub user_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteDechiffrage {
    pub domaine: String,
    pub liste_hachage_bytes: Vec<String>,
    pub certificat_rechiffrage: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrageCle {
      pub cle: String,
      pub cle_ref: Option<String>,
      pub domaine: String,
      pub format: String,
      pub hachage_bytes: String,
      pub header: Option<String>,
      pub identificateurs_document: Option<HashMap<String, String>>,
      pub iv: Option<String>,
      pub tag: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrage {
    pub acces: String,
    pub cles: HashMap<String, ReponseDechiffrageCle>,
    pub code: i64,
}
