use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::RandomState;
use std::fmt::{Error, Formatter};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, NaiveDateTime, Utc, NaiveDate, NaiveTime};
use log::{debug, error, info};
use num_traits::ToPrimitive;
use openssl::pkey::{PKey, Private};
use serde::{Serialize, Deserialize, Deserializer, Serializer};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::certificats::{EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
use crate::constantes::*;
use crate::hachages::hacher_message;
use crate::signatures::signer_message;
use serde::de::Visitor;

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

#[derive(Clone, Debug)]
pub struct DateEpochSeconds {
    date: DateTime<Utc>,
}

impl DateEpochSeconds {
    pub fn now() -> DateEpochSeconds {
        DateEpochSeconds { date: Utc::now() }
    }

    pub fn from_i64(ts_seconds: i64) -> DateEpochSeconds {
        let date_naive = NaiveDateTime::from_timestamp(ts_seconds, 0);
        let date = DateTime::from_utc(date_naive, Utc);
        DateEpochSeconds { date }
    }

    pub fn from_heure(annee: i32, mois: u32, jour: u32, heure: u32) -> DateEpochSeconds {
        let date_naive = NaiveDate::from_ymd(annee, mois, jour);
        let heure_naive = NaiveTime::from_hms(heure, 0, 0);
        let datetime_naive = NaiveDateTime::new(date_naive, heure_naive);
        let date = DateTime::from_utc(datetime_naive, Utc);

        DateEpochSeconds { date }
    }

    pub fn get_datetime(&self) -> &DateTime<Utc> {
        &self.date
    }
}

impl Serialize for DateEpochSeconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let ts = self.date.timestamp();
        serializer.serialize_i64(ts)
    }
}

impl<'de> Deserialize<'de> for DateEpochSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        println!("*** Deserializer!");
        deserializer.deserialize_u32(DateEpochSecondsVisitor)
        // Ok(DateEpochSeconds::from_timestamp(valeur))
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error> where D: Deserializer<'de> {
        let date_inner = deserializer.deserialize_i64(DateEpochSecondsVisitor)?;
        // let date_inner = DateEpochSeconds::from_timestamp(valeur);
        place.date = date_inner.date;

        Ok(())
    }
}

struct DateEpochSecondsVisitor;

impl <'de> Visitor<'de> for DateEpochSecondsVisitor {

    type Value = DateEpochSeconds;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("integer")
    }

    fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where E: serde::de::Error {
        Ok(DateEpochSeconds::from_i64(value))
    }

    fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where E: serde::de::Error {
        self.visit_i64(value as i64)
    }

}


#[cfg(test)]
mod serialization_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn serializer_date() {
        let date = DateEpochSeconds::now();
        let value = serde_json::to_value(date).unwrap();
        let date_epoch_secs = value.as_i64().expect("i64");
        assert_eq!(date_epoch_secs>1629813607, true);
    }

    #[test]
    fn deserializer_date() {
        let value_int = 1629813607;
        let value = Value::from(value_int);

        let date: DateEpochSeconds = serde_json::from_value(value).expect("date");
        println!("Date deserializee : {:?}", date);
    }
}
