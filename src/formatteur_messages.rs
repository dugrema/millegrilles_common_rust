use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::RandomState;
use std::fmt::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, error, info};
use num_traits::ToPrimitive;
use openssl::pkey::{PKey, Private};
use serde::Deserializer;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::certificats::{EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
use crate::constantes::*;
use crate::hachages::hacher_message;
use crate::signatures::signer_message;

const ENTETE: &str = "en-tete";
const SIGNATURE: &str = "_signature";
const CERTIFICATS: &str = "_certificat";

#[derive(Clone, Debug)]
pub struct MessageSigne {
    pub message: String,
    pub entete: Map<String, Value>,
}

impl MessageSigne {
}

pub struct FormatteurMessage {
    validateur: Arc<Box<ValidateurX509Impl>>,
    enveloppe_privee: Arc<Box<EnveloppePrivee>>,
}

impl FormatteurMessage {

    pub fn new(validateur: Arc<Box<ValidateurX509Impl>>, enveloppe_privee: Arc<Box<EnveloppePrivee>>) -> Self {
        FormatteurMessage { validateur, enveloppe_privee }
    }

    /// Prepare en-tete, _signature et _certificat dans un message
    pub fn formatter_value(&self, message: &MessageJson, domaine: Option<&str>) -> Result<MessageSigne, Error> {

        // Copier tous les champs qui ne commencent pas par _
        let (mut message_modifie, mut champs_retires): (BTreeMap<String, Value>, HashMap<&String, &Value, RandomState>) = nettoyer_message(message);
        // debug!("Message filtre : {:?}", message_modifie);

        // Serialiser en json pour calculer le hachage du message
        let contenu_str: String = serde_json::to_string(&message_modifie).unwrap();
        // debug!("Message contenu serialise : {}", contenu_str);
        let hachage = hacher_message(&contenu_str);
        // debug!("Hachage du message : {}\n{}", hachage, contenu_str);
        // assert_eq!("mEiAQASuxJobNtWMPmaxxLo+NLs/wfmkMl+wtiVq8vLkYaA", hachage);

        // Valeurs generees pour l'entete
        let uuid_message: Uuid = Uuid::new_v4();
        let estampille: Duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let enveloppe_privee: &EnveloppePrivee = &self.enveloppe_privee;

        // Ajouter l'entete
        let entete = json!({
            "version": 1,
            "idmg": self.validateur.idmg(),
            "fingerprint_certificat": enveloppe_privee.fingerprint(),
            "hachage_contenu": hachage,
            "uuid_transaction": uuid_message,
            "estampille": estampille.as_secs(),
        });
        let mut entete_modifie: Map<String, Value> = entete.as_object().unwrap().to_owned();
        match domaine {
            Some(d) => {
                entete_modifie.insert(String::from("domaine"), Value::from(d));
            },
            None => (),
        }
        let entete: Map<String, Value> = entete_modifie;

        let key_entete = String::from(ENTETE);
        let entete_value = Value::Object(entete.clone());
        message_modifie.insert(key_entete, entete_value);

        // Serialiser en json pour signer
        let contenu_str: String = serde_json::to_string(&message_modifie).unwrap();
        // debug!("Message serialise avec entete : {}", contenu_str);
        let signature = signer_message(enveloppe_privee.cle_privee(), contenu_str.as_bytes()).unwrap();

        // Reintroduire les champs retires
        for item in champs_retires {
            message_modifie.insert(item.0.to_owned(), item.1.to_owned());
        }

        // Conserver signature
        let key_signature = String::from(SIGNATURE);
        let signature_value = Value::String(signature);
        message_modifie.insert(key_signature, signature_value);

        // Inserer certificats
        let key_certificats = String::from(CERTIFICATS);
        let mut certificats_pem: Vec<Value> = Vec::new();
        for cert in self.enveloppe_privee.chaine_pem() {
            certificats_pem.push(Value::String(cert.to_owned()));
        }
        let certificats_pem = Value::Array(certificats_pem);
        message_modifie.insert(key_certificats, certificats_pem);

        // debug!("Message avec signature : {:?}", message_modifie);

        let contenu_str: String = serde_json::to_string(&message_modifie).unwrap();
        let resultat = MessageSigne {
            message: contenu_str,
            entete,
        };

        Ok(resultat)
    }

}

pub fn nettoyer_message<'a>(message: &'a MessageJson) -> (BTreeMap<String, Value>, HashMap<&String, &Value>) {

    let mut message_modifie: BTreeMap<String, Value> = BTreeMap::new();
    let mut champs_retires: HashMap<&String, &Value> = HashMap::new();
    for item in message.get_message().iter() {
        let nom_champ = item.0;
        let value: &'a Value = item.1;

        if !nom_champ.starts_with("_") {
            let new_value: Value;
            match filtrer_value(&value) {
                Some(v) => new_value = v,
                None => new_value = value.to_owned()
            }
            message_modifie.insert(nom_champ.to_owned(), new_value);
        } else {
            // Conserver le champ temporairement
            champs_retires.insert(nom_champ, value);
        }
    }

    (message_modifie, champs_retires)
}

/// Filtrer certains formats speciaux de valeurs
///   - Les f64 qui se terminent par .0 doivent etre changes en i64  (support ECMAScript)
fn filtrer_value(value: &Value) -> Option<Value> {
    if value.is_f64() {
        if value.to_string().ends_with(".0") {
            // debug!("On a une f64 en .0 : {:?}", value);
            let val_i64: i64 = value.as_f64().unwrap().to_i64().unwrap();
            let nouvelle_valeur = Value::from(val_i64);
            return Some(nouvelle_valeur)
        }
    } else if value.is_object() {
        // Appel recursif
        let val_object = value.as_object().unwrap();

        let mut changements = false;
        let mut nouvel_objet: Map<String, Value> = Map::new();
        for (champ, valeur) in val_object {
            // Appel recursif
            match filtrer_value(valeur) {
                Some(v) => {
                    nouvel_objet.insert(champ.to_owned(), v);
                    changements = true;
                },
                None => {
                    nouvel_objet.insert(champ.to_owned(), valeur.to_owned());
                },
            }
        }

        if changements == true {
            let nouvelle_valeur = Value::from(nouvel_objet);
            return Some(nouvelle_valeur);
        }
    }

    None
}

#[derive(Clone, Debug)]
pub struct MessageJson {
    message_json: Value
}

impl MessageJson {

    pub fn new(message_json: Value) -> MessageJson {
        // Test pour s'assurer que c'est une Map
        message_json.as_object().expect("object");

        MessageJson {
            message_json,
        }
    }

    pub fn parse(data: &Vec<u8>) -> Result<MessageJson, String> {
        let data = match String::from_utf8(data.to_owned()) {
            Ok(data) => Ok(data),
            Err(e) => {
                Err(format!("Erreur message n'est pas UTF-8 : {:?}", e))
            }
        }?;

        let map_doc: serde_json::Result<Value> = serde_json::from_str(data.as_str());
        let contenu = match map_doc {
            Ok(v) => Ok(MessageJson::new(v)),
            Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}\n{}", e, data)),
        }?;

        Ok(contenu)
    }

    pub fn ok() -> MessageJson {
        MessageJson { message_json: json!({"ok": true}) }
    }

    pub fn get_message(&self) -> &Map<String, Value> {
        self.message_json.as_object().expect("map")
    }

    fn get_entete(&self) -> Result<&Map<String,Value>, String> {
        match self.get_message().get(TRANSACTION_CHAMP_ENTETE) {
            Some(entete) => match entete.as_object() {
                Some(entete) => Ok(entete),
                None => Err("en-tete n'est pas un document".into()),
            },
            None => Err("en-tete manquante".into()),
        }
    }

    pub fn get_idmg(&self) -> Result<String, String> {
        let contenu = self.get_entete()?;
        match contenu.get(TRANSACTION_CHAMP_IDMG) {
            Some(idmg) => match idmg.as_str() {
                Some(idmg) => Ok(idmg.to_owned()),
                None => Err("idmg n'est pas un str".into()),
            },
            None => Err("idmg absent de l'entete".into())
        }
    }

    pub fn get_estampille(&self) -> Result<DateTime<Utc>, String> {
        let contenu = self.get_entete()?;
        match contenu.get(TRANSACTION_CHAMP_ESTAMPILLE) {
            Some(d) => lire_date_value(d),
            None => Err("idmg absent de l'entete".into())
        }
    }
}

pub fn lire_date_value(date: &Value) -> Result<DateTime<Utc>, String> {
    let date_epoch = match date.as_i64() {
        Some(d) => Ok(d),
        None => Err("Date n'est pas un i64"),
    }?;
    let date_naive = NaiveDateTime::from_timestamp(date_epoch, 0);
    Ok(DateTime::from_utc(date_naive, Utc))
}
