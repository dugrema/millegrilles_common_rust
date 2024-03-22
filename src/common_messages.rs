use log::{debug, error};
use std::collections::HashMap;
use std::error::Error;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage::FormatChiffrage;
use mongodb::bson::{bson, Bson};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use multibase;

use millegrilles_cryptographie::messages_structs::epochseconds;

use crate::hachages::verifier_multihash;
use crate::recepteur_messages::TypeMessage;

// #[derive(Clone, Debug, Deserialize)]
// pub struct RequeteVerifierPreuve {
//     pub fingerprint: String,                    // fingerprint inclues dans la preuve
//     pub preuves: HashMap<String, PreuveCle>,    // fuuid, preuve
// }

// #[derive(Clone, Debug, Deserialize)]
// pub struct PreuveCle {
//     #[serde(with = "epochseconds")]
//     pub date: DateTime<Utc>,
//     pub preuve: String,
// }
//
// impl PreuveCle {
//     pub fn verifier_preuve<S>(&self, fingerprint: S, cle: &CleSecrete) -> Result<bool, String>
//         where S: AsRef<str>
//     {
//         let fingerprint = fingerprint.as_ref();
//         let mut buffer = [0u8; 72];
//
//         // let fingerprint_bytes: Vec<u8> = match multibase::decode(fingerprint) {
//         let fingerprint_bytes: Vec<u8> = match hex::decode(fingerprint) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("common_messages.verifier_preuve Erreur decoder fingerprint : {:?}", e))?
//         };
//         debug!("Verifier preuve fingerprint bytes {:?}", fingerprint_bytes);
//
//         let datetime_preuve = self.date.get_datetime();
//         let datetime_i64 = datetime_preuve.timestamp();
//         let datetime_bytes = datetime_i64.to_le_bytes();
//         debug!("Datetime bytes {:?}", datetime_bytes);
//
//         // Copier date
//         buffer[0..8].copy_from_slice(&datetime_bytes[0..8]);
//
//         // Copier fingerprint
//         buffer[8..40].copy_from_slice(&fingerprint_bytes[0..32]);
//
//         // Copier cle secrete
//         buffer[40..72].copy_from_slice(&cle.0);
//
//         // Hachage avec blake2s
//         let valide = match verifier_multihash(self.preuve.as_str(), &buffer) {
//             Ok(inner) => inner,
//             Err(e) => {
//                 error!("common_messages.verifier_preuve Erreur verifier_multihash : {:?}", e);
//                 false
//             }
//         };
//
//         Ok(valide)
//     }
// }

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
pub struct PresenceFichiersRepertoire { pub taille: Option<i64>, pub nombre: Option<i64> }

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
    pub port_sftp: Option<u16>,
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
    pub port_sftp_backup: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_path_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type_sftp_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_intervalle_secs: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_limit_bytes: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub primaire: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphelin: Option<PresenceFichiersRepertoire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manquant: Option<PresenceFichiersRepertoire>,

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
            let message_ref = match m.message.parse() {
                Ok(inner) => inner,
                Err(e) => {
                    error!("verifier_reponse_ok Erreur parse message buffer : {}", e);
                    return false
                }
            };
            match message_ref.contenu() {
                Ok(inner) => {
                    match inner.deserialize::<MessageConfirmation>() {
                        Ok(r) => r.ok.unwrap_or_else(|| false),
                        Err(_) => false
                    }
                },
                Err(e) => {
                    error!("chiffrage_cle.requete_charger_cles Erreur contenu() {:?}", e);
                    false
                }
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
