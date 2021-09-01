use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::RandomState;
use std::fmt::{Error, Formatter};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{format, DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use log::{debug, error, info};
use num_traits::ToPrimitive;
use openssl::pkey::{PKey, Private};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::certificats::{EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
use crate::constantes::*;
use crate::hachages::hacher_message;
use crate::signatures::signer_message;
use crate::EnveloppeCertificat;
use serde::ser::SerializeMap;
use env_logger::fmt::TimestampPrecision::Micros;

const ENTETE: &str = "en-tete";
const SIGNATURE: &str = "_signature";
const CERTIFICATS: &str = "_certificat";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entete {
    // Note : s'assurer de conserver les champs en ordre alphabetique
    pub domaine: Option<String>,
    pub estampille: DateEpochSeconds,
    pub fingerprint_certificat: String,
    pub hachage_contenu: String,
    pub idmg: String,
    pub uuid_transaction: String,
    pub version: u32,
}

impl Entete {
    pub fn builder(fingerprint_certificat: &str, hachage_contenu: &str, idmg: &str) -> EnteteBuilder {
        EnteteBuilder::new(fingerprint_certificat.to_owned(), hachage_contenu.to_owned(), idmg.to_owned())
    }
}

pub struct EnteteBuilder {
    domaine: Option<String>,
    estampille: DateEpochSeconds,
    fingerprint_certificat: String,
    hachage_contenu: String,
    idmg: String,
    uuid_transaction: String,
    version: u32,
}

impl EnteteBuilder {
    pub fn new(fingerprint_certificat: String, hachage_contenu: String, idmg: String) -> EnteteBuilder {
        EnteteBuilder {
            domaine: None,
            estampille: DateEpochSeconds::now(),
            fingerprint_certificat,
            hachage_contenu,
            idmg,
            uuid_transaction: Uuid::new_v4().to_string(),
            version: 1,
        }
    }

    pub fn domaine(mut self, domaine: String) -> EnteteBuilder {
        self.domaine = Some(domaine);
        self
    }

    pub fn estampille(mut self, estampille: DateEpochSeconds) -> EnteteBuilder {
        self.estampille = estampille;
        self
    }

    pub fn version(mut self, version: u32) -> EnteteBuilder {
        self.version = version;
        self
    }

    pub fn build(self) -> Entete {
        Entete {
            domaine: self.domaine,
            estampille: self.estampille,
            fingerprint_certificat: self.fingerprint_certificat,
            hachage_contenu: self.hachage_contenu,
            idmg: self.idmg,
            uuid_transaction: self.uuid_transaction,
            version: self.version,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct MessageMilleGrille {
    #[serde(rename = "en-tete")]
    pub entete: Entete,

    #[serde(rename = "_certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<String>>,

    #[serde(rename = "_signature")]
    pub signature: Option<String>,

    #[serde(flatten)]
    pub contenu: Map<String, Value>,
}

impl MessageMilleGrille {

    pub fn new_signer(enveloppe_privee: &EnveloppePrivee, contenu: &impl Serialize) -> Result<Self, Box<dyn std::error::Error>> {

        // Serialiser le contenu
        let value: Map<String, Value> = MessageMilleGrille::serialiser_contenu(contenu)?;

        // Calculer le hachage du contenu

        // Generer l'entete
        let entete = Entete::builder(
            enveloppe_privee.fingerprint(),
            "hachage",
            enveloppe_privee.idmg().expect("idmg").as_str()
        )
            .estampille(DateEpochSeconds::now())
            .version(1)
            .build();

        let pems: Vec<String> = {
            let pem_vec = enveloppe_privee.enveloppe.get_pem_vec();
            let mut pem_str: Vec<String> = Vec::new();
            for p in pem_vec.iter().map(|c| c.pem.as_str()) {
                pem_str.push(p.to_owned());
            }
            pem_str
        };

        let signature = MessageMilleGrille::signer_message(enveloppe_privee, &entete, &value)?;

        Ok(MessageMilleGrille {
            entete,
            certificat: Some(pems),
            signature: Some(signature),
            contenu: value,
        })
    }

    fn serialiser_contenu(contenu: &impl Serialize) -> Result<Map<String, Value>, Box<dyn std::error::Error>> {
        Ok(serde_json::to_value(contenu).expect("value").as_object().expect("value map").to_owned())
    }

    fn calculer_hachage_contenu(contenu: &Map<String, Value>) -> Result<String, Box<dyn std::error::Error>> {
        // let ordered: BTreeMap<_, _> = contenu.iter().collect();
        let mut ordered = BTreeMap::new();

        // Copier dans une BTreeMap. Retirer champs _ et en-tete
        for (k, v) in contenu {
            if ! k.starts_with("_") && k != "en-tete" {
                ordered.insert(k, v);
            }
        }

        let message_string = serde_json::to_string(&ordered)?;
        Ok(hacher_message(message_string.as_str()))
    }

    fn signer_message(enveloppe_privee: &EnveloppePrivee, entete: &Entete, contenu: &Map<String, Value>) -> Result<String, Box<dyn std::error::Error>> {
        // let ordered: BTreeMap<_, _> = contenu.iter().collect();
        let mut ordered = BTreeMap::new();

        // Copier dans une BTreeMap. Retirer champs _ et en-tete
        for (k, v) in contenu {
            if ! k.starts_with("_") {
                ordered.insert(k.as_str(), v);
            }
        }

        // Ajouter entete
        let entete_value = serde_json::to_value(entete)?;
        ordered.insert("en-tete", &entete_value);

        // Serialiser en json pour signer
        let message_string = serde_json::to_string(&ordered)?;

        // debug!("Message serialise avec entete : {}", contenu_str);
        let signature = signer_message(enveloppe_privee.cle_privee(), message_string.as_bytes())?;

        Ok(signature)
    }

    fn signer(&mut self, enveloppe_privee: &EnveloppePrivee) -> Result<(), Box<dyn std::error::Error>> {
        let signature = MessageMilleGrille::signer_message(enveloppe_privee, &self.entete, &self.contenu)?;
        self.signature = Some(signature);
        Ok(())
    }

    // pub fn set_contenu(&mut self, map: Map<String, Value>) {
    //     for (k, v) in map {
    //         self.contenu.insert(k, v);
    //     }
    // }
    //
    // pub fn set_objet(&mut self, objet: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    //     let contenu: Map<String, Value> = serde_json::to_value(objet).expect("value").as_object().expect("object").to_owned();
    //     self.set_contenu(contenu);
    //
    //     Ok(())
    // }

    /// Sert a retirer les certificats pour serialisation (e.g. backup, transaction Mongo, etc)
    pub fn retirer_certificats(&mut self) {
        self.certificat = None;
    }

}

impl Serialize for MessageMilleGrille {
    fn serialize<'a, S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {

        // Creer BTreeMap avec toutes les values
        // let mut ordered: BTreeMap<_, _> = self.contenu.iter().collect();
        let mut ordered: BTreeMap<&str, &Value> = BTreeMap::new();
        for (k, v) in &self.contenu {
            ordered.insert(k.as_str(), v);
        }

        // Ajouter en-tete
        let entete = serde_json::to_value(&self.entete).expect("val");
        ordered.insert("en-tete", &entete);

        // Ajouter certificats si presents
        let cert = match &self.certificat {
            Some(c) => serde_json::to_value(c).expect("certs"),
            None => Value::Null
        };
        if cert != Value::Null {
            ordered.insert("_certificat", &cert);
        }

        // Ajouter signature si presente
        let signature = match &self.signature {
            Some(c) => serde_json::to_value(c).expect("signature"),
            None => Value::Null
        };
        if signature != Value::Null {
            ordered.insert("_signature", &signature);
        }

        // Serialiser la map triee
        let mut map_ser = serializer.serialize_map(Some(ordered.len()))?;
        for (k, v) in ordered {
            map_ser.serialize_entry(k, v)?;
        }
        map_ser.end()

    }
}

#[derive(Clone, Debug)]
pub struct MessageSerialise {
    pub message: String,
    pub entete: Entete,
    enveloppe: Option<Arc<EnveloppeCertificat>>,
}

impl MessageSerialise {
}

pub trait Formatteur: Send + Sync {
    fn formatter_value(&self, message: &MessageJson, domaine: Option<&str>) -> Result<MessageSerialise, Error>;
}

pub struct FormatteurMessage {
    validateur: Arc<Box<ValidateurX509Impl>>,
    enveloppe_privee: Arc<Box<EnveloppePrivee>>,
}

impl FormatteurMessage {
    pub fn new(validateur: Arc<Box<ValidateurX509Impl>>, enveloppe_privee: Arc<Box<EnveloppePrivee>>) -> Self {
        FormatteurMessage { validateur, enveloppe_privee }
    }
}

impl Formatteur for FormatteurMessage {

    /// Prepare en-tete, _signature et _certificat dans un message
    fn formatter_value(&self, message: &MessageJson, domaine: Option<&str>) -> Result<MessageSerialise, Error> {

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
        // let entete = json!({
        //     "estampille": estampille.as_secs(),
        //     "fingerprint_certificat": enveloppe_privee.fingerprint(),
        //     "hachage_contenu": hachage,
        //     "idmg": self.validateur.idmg(),
        //     "uuid_transaction": uuid_message,
        //     "version": 1,
        // });
        // let mut entete_modifie: Map<String, Value> = entete.as_object().unwrap().to_owned();
        // match domaine {
        //     Some(d) => {
        //         entete_modifie.insert(String::from("domaine"), Value::from(d));
        //     },
        //     None => (),
        // }
        // let mut entete: BTreeMap<String, Value> = BTreeMap::new();
        // entete.extend(entete_modifie);

        let entete = Entete::builder(
            enveloppe_privee.fingerprint(),
            &hachage,
            self.validateur.idmg()
        ).build();

        let key_entete = String::from(ENTETE);
        let entete_value = serde_json::to_value(&entete).expect("entete");
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
        let resultat = MessageSerialise {
            message: contenu_str,
            entete,
            enveloppe: Some(enveloppe_privee.enveloppe.clone())
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

    pub fn get_entete(&self) -> Result<&Map<String,Value>, String> {
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

#[derive(Clone, Debug, PartialEq)]
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

    pub fn format_ymdh(&self) -> String {
        self.date.format("%Y%m%d%H").to_string()
    }
}

impl Default for DateEpochSeconds {
    fn default() -> Self {
        DateEpochSeconds::now()
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
        deserializer.deserialize_u32(DateEpochSecondsVisitor)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error> where D: Deserializer<'de> {
        let date_inner = deserializer.deserialize_i64(DateEpochSecondsVisitor)?;
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

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

#[cfg(test)]
mod serialization_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::test_setup::setup;
    use crate::certificats_tests::charger_enveloppe_privee_env;

    #[test]
    fn serializer_date() {
        setup("serializer_date");
        let date = DateEpochSeconds::from_i64(1629813607);

        let value = serde_json::to_value(date).unwrap();

        let date_epoch_secs = value.as_i64().expect("i64");
        assert_eq!(date_epoch_secs, 1629813607);
    }

    #[test]
    fn deserializer_date() {
        setup("deserializer_date");
        let value_int = 1629813607;
        let value = Value::from(value_int);

        let date: DateEpochSeconds = serde_json::from_value(value).expect("date");

        assert_eq!(date.date.timestamp() as i32, value_int);
    }

    #[test]
    fn serializer_entete() {
        setup("deserializer_date");
        let fingerprint = "zQmPD1VZCEgPDvpNdSK8SCv6SuhdrtbvzAy5nUDvRWYn3Wv";
        let hachage_contenu = "mEiAoFMueZNEcSQ97UXcOWmezPuQyjBYWpm8+1NZDKJvb2g";
        let idmg = "z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s";
        let entete = Entete::builder(fingerprint, hachage_contenu, idmg).build();

        let value = serde_json::to_value(entete).unwrap();

        assert_eq!(value.get("fingerprint_certificat").expect("fp").as_str().expect("fp str"), fingerprint);
        assert_eq!(value.get("hachage_contenu").expect("hachage").as_str().expect("hachage str"), hachage_contenu);
        assert_eq!(value.get("idmg").expect("idmg").as_str().expect("idmg str"), idmg);
    }

    #[test]
    fn deserializer_entete() {
        setup("deserializer_date");
        let value = json!({
	    	"domaine": "Backup.catalogueHoraire",
		    "estampille": 1627585202,
		    "fingerprint_certificat": "zQmPD1VZCEgPDvpNdSK8SCv6SuhdrtbvzAy5nUDvRWYn3Wv",
		    "hachage_contenu": "mEiAoFMueZNEcSQ97UXcOWmezPuQyjBYWpm8+1NZDKJvb2g",
		    "idmg": "z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s",
		    "uuid_transaction": "2da93aa1-f09f-11eb-95a5-bf4298f92e28",
		    "version": 6
        });

        let entete: Entete = serde_json::from_value(value).expect("deserialiser entete");

        assert_eq!(entete.domaine.expect("domaine").as_str(), "Backup.catalogueHoraire");
        assert_eq!(entete.estampille.date.timestamp(), 1627585202);

    }

    #[test]
    fn creer_message_millegrille_signe() {
        setup("creer_message_millegrille");
        let (_, enveloppe_privee) = charger_enveloppe_privee_env();
        let entete = Entete::builder("dummy", "hachage", "idmg").build();

        let val = json!({
            "valeur": 1,
            "texte": "oui!",
            "alpaca": true,
        });
        let message = MessageMilleGrille::new_signer(&enveloppe_privee, &val).expect("map");

        let message_str = serde_json::to_string(&message).expect("string");
        debug!("Message MilleGrille serialise : {}", message_str)
    }



}
