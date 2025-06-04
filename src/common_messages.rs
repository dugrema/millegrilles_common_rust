use log::{debug, error};
use std::collections::HashMap;
use std::error::Error;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::chiffrage::{FormatChiffrage, optionformatchiffragestr};
use mongodb::bson::{bson, Bson};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use multibase;

use millegrilles_cryptographie::{messages_structs::epochseconds, chiffrage::formatchiffragestr, heapless};
use millegrilles_cryptographie::chiffrage_cles::CleSecreteSerialisee;
use millegrilles_cryptographie::maitredescles::SignatureDomaines;

use crate::dechiffrage::DataChiffre;

use crate::error::Error as CommonError;
use crate::hachages::verifier_multihash;
use crate::recepteur_messages::TypeMessage;

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

    pub supprime: Option<bool>,

    pub ok: Option<bool>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DataChiffre {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub ref_hachage_bytes: Option<String>,
//     pub data_chiffre: String,
//     #[serde(with="formatchiffragestr")]
//     pub format: FormatChiffrage,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub header: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub tag: Option<String>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationDechiffrage {
    pub format: Option<FormatChiffrage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_hachage_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationDechiffrageV2 {
    pub cle_id: String,
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,

    /// Fuuid auquel l'information fait reference. Peut etre une reference a un
    /// fichier image, video ou audio (e.g. pour streaming) different du fuuid original.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuuid: Option<String>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageConfirmation {
    pub ok: Option<bool>,
    pub code: Option<i64>,
    pub err: Option<String>,
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

pub fn parse_confirmation_response(message: &TypeMessage) -> Option<MessageConfirmation> {
    match message {
        TypeMessage::Valide(m) => {
            let message_ref = match m.message.parse() {
                Ok(inner) => inner,
                Err(e) => {
                    error!("parse_confirmation_response Erreur parse message buffer : {}", e);
                    return None
                }
            };
            match message_ref.contenu() {
                Ok(inner) => {
                    match inner.deserialize::<MessageConfirmation>() {
                        Ok(r) => Some(r),
                        Err(_) => None
                    }
                },
                Err(e) => {
                    error!("parse_confirmation_response Erreur contenu() {:?}", e);
                    None
                }
            }
        },
        _ => None
    }
}

pub struct DataDechiffre {
    pub ref_hachage_bytes: Option<String>,
    pub data_dechiffre: Vec<u8>,
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionRetirerSubscriptionWebpush {
//     pub endpoint: String,
//     pub user_id: Option<String>,
// }

/// Requete de dechiffrage de cles par domaine/ids
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteDechiffrage {
    /// Domaine auquel appartiennent les cles
    pub domaine: String,
    /// Obsolete : liste de hachage bytes correspondant aux cles (maintenant cle_id)
    pub liste_hachage_bytes: Option<Vec<String>>,
    /// Liste de cle_id a rechiffrer
    pub cle_ids: Option<Vec<String>>,
    /// Certificat a utiliser pour la reponse chiffree
    pub certificat_rechiffrage: Option<Vec<String>>,
    /// Si true, la reponse ajoute l'element signature avec cle_id et
    pub inclure_signature: Option<bool>,
}

/// Requete de dechiffrage avec cles fournies
#[derive(Clone, Serialize, Deserialize)]
pub struct RequeteDechiffrageMessage {
    pub signature: SignatureDomaines,
    pub cles: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrageCle {
    pub cle: String,
    pub cle_id: String,
    pub domaine: String,

    // Obsolete - entrees de dechiffrage pour le contenu
    pub format: Option<String>,
    pub hachage_bytes: Option<String>,
    pub header: Option<String>,
    pub iv: Option<String>,
    pub tag: Option<String>,

    // Obsolete
    pub identificateurs_document: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrage {
    pub acces: String,
    pub cles: HashMap<String, ReponseDechiffrageCle>,
    pub code: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseRequestDechiffrageV2Cle {
    pub cle_secrete_base64: String,
    pub cle_id: Option<String>,
    #[serde(default, with="optionformatchiffragestr")]
    pub format: Option<FormatChiffrage>,
    pub nonce: Option<String>,
    pub verification: Option<String>,
    pub signature: Option<SignatureDomaines>,
}

impl From<CleSecreteSerialisee> for ResponseRequestDechiffrageV2Cle {
    fn from(value: CleSecreteSerialisee) -> Self {
        Self {
            cle_secrete_base64: value.cle_secrete_base64.to_string(),
            cle_id: match &value.cle_id {Some(inner) => Some(inner.to_string()), None => None},
            format: value.format.clone(),
            nonce: match &value.nonce {Some(inner) => Some(inner.to_string()), None => None},
            verification: match &value.verification {Some(inner) => Some(inner.to_string()), None => None},
            signature: None,
        }
    }
}

impl TryInto<CleSecreteSerialisee> for ResponseRequestDechiffrageV2Cle {
    type Error = CommonError;

    fn try_into(self) -> Result<CleSecreteSerialisee, CommonError> {
        Ok(CleSecreteSerialisee {
            cle_secrete_base64: heapless::String::try_from(self.cle_secrete_base64.as_str()).map_err(|()| CommonError::Str("TryInto<CleSecreteSerialisee>  cle_secrete_base64"))?,
            cle_id: match &self.cle_id {Some(inner) => {
                let value = heapless::String::try_from(inner.as_str()).map_err(|()| CommonError::Str("TryInto<CleSecreteSerialisee> cle_id"))?;
                Some(value)
            }, None => None},
            format: self.format.clone(),
            nonce: match &self.nonce {Some(inner) => {
                let value = heapless::String::try_from(inner.as_str()).map_err(|()| CommonError::Str("TryInto<CleSecreteSerialisee> nonce"))?;
                Some(value)
            }, None => None},
            verification: match &self.verification {Some(inner) => {
                let value = heapless::String::try_from(inner.as_str()).map_err(|()| CommonError::Str("TryInto<CleSecreteSerialisee> verification"))?;
                Some(value)
            }, None => None},
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReponseRequeteDechiffrageV2 {
    pub ok: bool,
    pub code: usize,
    pub cles: Option<Vec<ResponseRequestDechiffrageV2Cle>>,
    pub err: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostForInstanceRequest {
    pub instance_id: Option<String>,
    pub filehost_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUsage {
    // Note: using f64 rather than usize/u64 because of random bug loading large values with mongo client 2.8.1
    pub count: Option<f64>,
    pub size: Option<f64>,
}

#[derive(Serialize, Deserialize)]
pub struct RequeteFilehostItem {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub url_internal: Option<String>,
    pub url_external: Option<String>,
    pub tls_external: Option<String>,
    pub deleted: bool,
    pub sync_active: bool,
    #[serde(with = "epochseconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "epochseconds")]
    pub modified: DateTime<Utc>,
    pub fuuid: Option<FileUsage>,
}

#[derive(Serialize, Deserialize)]
pub struct RequestFilehostForInstanceResponse {
    pub ok: bool,
    pub filehost: RequeteFilehostItem,
}

#[derive(Serialize, Deserialize)]
pub struct EventFilehost {
    pub filehost_id: String,
    pub event: String,
}


#[derive(Serialize, Deserialize)]
pub struct BackupEvent {
    pub ok: bool,  // Si false, indique echec dans le backup
    pub done: bool,
    pub domaine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    pub version: Option<String>,
}
