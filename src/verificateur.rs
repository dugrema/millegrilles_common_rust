use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

use tracing::debug;
use openssl::pkey::{PKey, Public};
use serde::{Deserialize, Serialize};
use serde_json::Value;


use crate::formatteur_messages::{preparer_btree_recursif, map_valeur_recursif};
use crate::signatures::verifier_message as ref_verifier_message;
use crate::error::Error as CommonError;

pub fn verifier_signature_str(public_key: &PKey<Public>, signature: &str, message: &str) -> Result<bool, Box<dyn Error>> {
    ref_verifier_message(public_key, message.as_bytes(), signature)
}

pub fn verifier_signature_serialize<S>(public_key: &PKey<Public>, signature: &str, message: &S)
    -> Result<bool, Box<dyn Error>>
    where S: Serialize
{
    let content = {
        let val = serde_json::to_value(message)?;
        let map_val = match val.as_object() {
            Some(v) => Value::Object(preparer_btree_recursif(v.clone())?),
            None => map_valeur_recursif(val)?
        };

        serde_json::to_string(&map_val)?
    };

    debug!("verifier_signature_serialize Contenu a verifier : \n{}", content.as_str());
    verifier_signature_str(public_key, signature, content.as_str())
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegleVerification {
    pub date_courante: Option<bool>,
    pub idmg: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReglesVerification {
    pub regles: HashMap<String, RegleVerification>
}

pub fn charger_regles_verification(path: &PathBuf) -> Result<ReglesVerification, CommonError> {
    let fichier_fp = std::fs::File::open(path)?;
    let fichier_reader = std::io::BufReader::new(fichier_fp);
    let regles: ReglesVerification = serde_json::from_reader(fichier_reader)?;
    Ok(regles)
}
