use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt::Formatter;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use log::{debug, info};
use num_traits::ToPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;
use serde::ser::SerializeMap;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{EnveloppeCertificat, ResultatValidation, ValidationOptions, verifier_message};
use crate::certificats::{EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
use crate::constantes::*;
use crate::hachages::hacher_message;
use crate::signatures::signer_message;

const ENTETE: &str = "en-tete";
const SIGNATURE: &str = "_signature";
const CERTIFICATS: &str = "_certificat";

pub trait FormatteurMessage {
    /// Retourne l'enveloppe privee utilisee pour signer le message
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;

    /// Implementation de formattage et signature d'un message de MilleGrille
    fn formatter_message(&self, contenu: &impl Serialize, domaine: Option<&str>, version: Option<u32>) -> Result<MessageMilleGrille, Box<dyn Error>> {
        let enveloppe = self.get_enveloppe_privee();
        MessageMilleGrille::new_signer(enveloppe.as_ref(), contenu, domaine, version)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Entete de messages de MilleGrille (champ "en-tete").
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

/// Builder pour les entetes de messages.
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
/// Structure a utiliser pour creer un nouveau message
/// Utiliser methode MessageMilleGrille::new_signer().
pub struct MessageMilleGrille {
    /// Entete du message. Contient domaine.action, hachage du contenu, fingerprint certificat, estampille, etc.
    #[serde(rename = "en-tete")]
    pub entete: Entete,

    /// Chaine de certificats en format PEM. Inclus le certificat root (dernier de la liste).
    #[serde(rename = "_certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<String>>,

    /// Signature encodee en multibase
    #[serde(rename = "_signature")]
    pub signature: Option<String>,

    /// Contenu du message autre que les elements structurels.
    #[serde(flatten)]
    pub contenu: Map<String, Value>,
}

impl MessageMilleGrille {

    /// Creer un nouveau message et inserer les valeurs a la main.
    pub fn new() -> Self {
        const PLACEHOLDER: &str = "PLACEHOLDER";
        MessageMilleGrille {
            entete: Entete::builder(PLACEHOLDER, PLACEHOLDER, PLACEHOLDER).build(),
            certificat: None,
            signature: None,
            contenu: Map::new(),
        }
    }

    pub fn new_signer<S>(enveloppe_privee: &EnveloppePrivee, contenu: &S, domaine: Option<&str>, version: Option<u32>) -> Result<Self, Box<dyn std::error::Error>>
    where
        S: Serialize,
    {
        // Serialiser le contenu
        let value: Map<String, Value> = MessageMilleGrille::serialiser_contenu(contenu)?;

        let entete = MessageMilleGrille::creer_entete(enveloppe_privee, domaine, version, &value)?;

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

    fn creer_entete(enveloppe_privee: &EnveloppePrivee, domaine: Option<&str>, version: Option<u32>, value: &Map<String, Value>) -> Result<Entete, Box<dyn Error>> {
        // Calculer le hachage du contenu
        let hachage = MessageMilleGrille::calculer_hachage_contenu(&value)?;

        // Generer l'entete
        let mut entete_builder = Entete::builder(
            enveloppe_privee.fingerprint(),
            &hachage,
            enveloppe_privee.idmg().expect("idmg").as_str()
        )
            .estampille(DateEpochSeconds::now())
            .version(1);

        match domaine {
            Some(d) => entete_builder = entete_builder.domaine(d.to_owned()),
            None => (),
        }

        match version {
            Some(v) => entete_builder = entete_builder.version(v),
            None => (),
        }

        let entete = entete_builder.build();
        Ok(entete)
    }

    pub fn set_value(&mut self, name: &str, value: Value) {
        self.contenu.insert(name.to_owned(), value);
    }

    pub fn set_int(&mut self, name: &str, value: i64) {
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_float(&mut self, name: &str, value: f64) {
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_bool(&mut self, name: &str, value: bool) {
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_serializable<S>(&mut self, name: &str, value: &S) -> Result<(), Box<dyn Error>>
    where
        S: Serialize,
    {
        let val_ser = serde_json::to_value(value)?;
        self.contenu.insert(name.to_owned(), val_ser);
        Ok(())
    }

    fn serialiser_contenu<S>(contenu: &S) -> Result<Map<String, Value>, Box<dyn std::error::Error>>
    where
        S: Serialize,
    {
        Ok(serde_json::to_value(contenu).expect("value").as_object().expect("value map").to_owned())
    }

    fn calculer_hachage_contenu(contenu: &Map<String, Value>) -> Result<String, Box<dyn std::error::Error>> {
        let message_string = MessageMilleGrille::preparer_pour_hachage(contenu)?;
        Ok(hacher_message(message_string.as_str()))
    }

    fn signer_message(enveloppe_privee: &EnveloppePrivee, entete: &Entete, contenu: &Map<String, Value>) -> Result<String, Box<dyn std::error::Error>> {
        let message_string = MessageMilleGrille::preparer_pour_signature(entete, contenu)?;

        // debug!("Message serialise avec entete : {}", contenu_str);
        let signature = signer_message(enveloppe_privee.cle_privee(), message_string.as_bytes())?;

        Ok(signature)
    }

    /// Genere une String avec le contenu serialise correctement pour hachage / validation.
    pub fn preparer_pour_hachage(contenu: &Map<String, Value>) -> Result<String, Box<dyn Error>> {
        let mut ordered = BTreeMap::new();

        // Copier dans une BTreeMap. Retirer champs _ et en-tete
        for (k, v) in contenu {
            if ! k.starts_with("_") && k != "en-tete" {
                ordered.insert(k, v);
            }
        }

        Ok(serde_json::to_string(&ordered)?)
    }

    /// Generer une String avec le contenu et l'entete serialises correctement pour signature / validation.
    pub fn preparer_pour_signature(entete: &Entete, contenu: &Map<String, Value>) -> Result<String, Box<dyn Error>> {
        let mut ordered = BTreeMap::new();

        // Copier dans une BTreeMap. Retirer champs _ et en-tete
        for (k, v) in contenu {
            if !k.starts_with("_") {
                ordered.insert(k.as_str(), v);
            }
        }

        // Ajouter entete
        let entete_value = serde_json::to_value(entete)?;
        ordered.insert("en-tete", &entete_value);

        // Serialiser en json pour signer
        Ok(serde_json::to_string(&ordered)?)
    }

    fn signer(&mut self, enveloppe_privee: &EnveloppePrivee, domaine: Option<&str>, version: Option<u32>) -> Result<(), Box<dyn std::error::Error>> {

        let entete = MessageMilleGrille::creer_entete(enveloppe_privee, domaine, version, &self.contenu)?;

        // Remplacer l'entete
        self.entete = entete;
        self.certificat = Some(enveloppe_privee.chaine_pem().to_owned());

        let signature = MessageMilleGrille::signer_message(enveloppe_privee, &self.entete, &self.contenu)?;
        self.signature = Some(signature);
        Ok(())
    }

    /// Sert a retirer les certificats pour serialisation (e.g. backup, transaction Mongo, etc)
    pub fn retirer_certificats(&mut self) { self.certificat = None }
}

/// Serialiser message de MilleGrille. Met les elements en ordre.
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
    entete: Entete,
    message: String,
    parsed: MessageMilleGrille,
    pub certificat: Option<Arc<EnveloppeCertificat>>,
}

impl MessageSerialise {
    pub fn from_parsed(msg: MessageMilleGrille) -> Result<Self, Box<dyn std::error::Error>> {
        let msg_str = serde_json::to_string(&msg)?;
        Ok(MessageSerialise {
            entete: msg.entete.clone(),
            message: msg_str,
            parsed: msg,
            certificat: None,
        })
    }

    pub fn from_str(msg: &str) -> Result<Self, Box<dyn std::error::Error>> {
        MessageSerialise::from_string(msg.to_owned())
    }

    pub fn from_string(msg: String) -> Result<Self, Box<dyn std::error::Error>> {
        let msg_parsed: MessageMilleGrille = serde_json::from_str(&msg)?;
        // debug!("Comparaison message original:\n{}\nParsed\n{:?}", msg, msg_parsed);
        Ok(MessageSerialise {
            message: msg,
            entete: msg_parsed.entete.clone(),
            parsed: msg_parsed,
            certificat: None,
        })
    }

    pub fn from_serializable<T>(value: T) -> Result<MessageSerialise, Box<dyn Error>>
    where
        T: Serialize,
    {
        let ser_value = serde_json::to_value(value)?;
        let msg_parsed: MessageMilleGrille = serde_json::from_value(ser_value)?;
        let msg = serde_json::to_string(&msg_parsed)?;
        // debug!("Comparaison message original:\n{}\nParsed\n{:?}", msg, msg_parsed);
        Ok(MessageSerialise {
            message: msg,
            entete: msg_parsed.entete.clone(),
            parsed: msg_parsed,
            certificat: None,
        })
    }

    // pub fn from_value(value: Value) -> Result<Self, Box<dyn std::error::Error>> {
    //     let msg_parsed: MessageMilleGrille = serde_json::from_value(value)?;
    //     let msg = serde_json::to_string(&msg_parsed)?;
    //     // debug!("Comparaison message original:\n{}\nParsed\n{:?}", msg, msg_parsed);
    //     Ok(MessageSerialise {
    //         message: msg,
    //         entete: msg_parsed.entete.clone(),
    //         parsed: msg_parsed,
    //         certificat: None,
    //     })
    // }

    pub fn set_certificat(&mut self, certificat: Arc<EnveloppeCertificat>) {
        self.certificat = Some(certificat);
    }

    pub fn get_entete(&self) -> &Entete {
        &self.entete
    }

    pub fn get_str(&self) -> &str {
        self.message.as_str()
    }

    pub fn get_msg(&self) -> &MessageMilleGrille {
        &self.parsed
    }

    pub async fn valider<V>(&mut self, validateur: &V, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>>
    where
        V: ValidateurX509,
    {
        match &self.certificat {
            Some(_) => {
                // Ok, on a un certificat. Valider la signature.
                verifier_message(&self, validateur.idmg(), options)
            },
            None => {
                // Tenter de charger le certificat
                // let enveloppe : Option<Arc<EnveloppeCertificat>> = self.charger_certificat(validateur).await?;
                match self.charger_certificat(validateur).await? {
                    Some(e) => {
                        self.certificat = Some(e);
                        verifier_message(&self, validateur.idmg(), options)
                    },
                    None => Err("Certificat manquant")?
                }
            },
        }
    }

    async fn charger_certificat(&mut self, validateur: &dyn ValidateurX509) -> Result<Option<Arc<EnveloppeCertificat>>, Box<dyn Error>> {
        let fp_certificat = self.entete.fingerprint_certificat.as_str();
        let enveloppe : Option<Arc<EnveloppeCertificat>> = match &self.parsed.certificat {
            Some(c) => {
                let enveloppe = validateur.charger_enveloppe(c, Some(fp_certificat)).await?;
                Some(enveloppe)
            },
            None => {
                validateur.get_certificat(fp_certificat).await
            }
        };
        Ok(enveloppe)
    }

}

// pub trait Formatteur: Send + Sync {
//     fn formatter_value(&self, message: &MessageJson, domaine: Option<&str>) -> Result<MessageSerialise, Box<dyn std::error::Error>>;
// }
//
// pub struct FormatteurMessage {
//     validateur: Arc<Box<ValidateurX509Impl>>,
//     enveloppe_privee: Arc<Box<EnveloppePrivee>>,
// }
//
// impl FormatteurMessage {
//     pub fn new(validateur: Arc<Box<ValidateurX509Impl>>, enveloppe_privee: Arc<Box<EnveloppePrivee>>) -> Self {
//         FormatteurMessage { validateur, enveloppe_privee }
//     }
// }
//
// impl Formatteur for FormatteurMessage {
//
//     /// Prepare en-tete, _signature et _certificat dans un message
//     fn formatter_value(&self, message: &MessageJson, domaine: Option<&str>) -> Result<MessageSerialise, Box<dyn std::error::Error>> {
//
//         let message_signe = MessageMilleGrille::new_signer(
//             self.enveloppe_privee.as_ref(),
//             &message.message_json,
//             domaine
//         )?;
//
//         let mut message_serialise = MessageSerialise::from_parsed(message_signe)?;
//         message_serialise.set_certificat(self.enveloppe_privee.enveloppe.clone());
//
//         Ok(message_serialise)
//     }
//
// }

// pub fn nettoyer_message<'a>(message: &'a MessageJson) -> (BTreeMap<String, Value>, HashMap<&String, &Value>) {
//
//     let mut message_modifie: BTreeMap<String, Value> = BTreeMap::new();
//     let mut champs_retires: HashMap<&String, &Value> = HashMap::new();
//     for item in message.get_message().iter() {
//         let nom_champ = item.0;
//         let value: &'a Value = item.1;
//
//         if !nom_champ.starts_with("_") {
//             let new_value: Value;
//             match filtrer_value(&value) {
//                 Some(v) => new_value = v,
//                 None => new_value = value.to_owned()
//             }
//             message_modifie.insert(nom_champ.to_owned(), new_value);
//         } else {
//             // Conserver le champ temporairement
//             champs_retires.insert(nom_champ, value);
//         }
//     }
//
//     (message_modifie, champs_retires)
// }

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

// #[derive(Clone, Debug)]
// pub struct MessageJson {
//     message_json: Value
// }
//
// impl MessageJson {
//
//     pub fn new(message_json: Value) -> MessageJson {
//         // Test pour s'assurer que c'est une Map
//         message_json.as_object().expect("object");
//
//         MessageJson {
//             message_json,
//         }
//     }
//
//     pub fn parse(data: &Vec<u8>) -> Result<MessageJson, String> {
//         let data = match String::from_utf8(data.to_owned()) {
//             Ok(data) => Ok(data),
//             Err(e) => {
//                 Err(format!("Erreur message n'est pas UTF-8 : {:?}", e))
//             }
//         }?;
//
//         let map_doc: serde_json::Result<Value> = serde_json::from_str(data.as_str());
//         let contenu = match map_doc {
//             Ok(v) => Ok(MessageJson::new(v)),
//             Err(e) => Err(format!("Erreur lecture JSON message : erreur {:?}\n{}", e, data)),
//         }?;
//
//         Ok(contenu)
//     }
//
//     pub fn ok() -> MessageJson {
//         MessageJson { message_json: json!({"ok": true}) }
//     }
//
//     pub fn get_message(&self) -> &Map<String, Value> {
//         self.message_json.as_object().expect("map")
//     }
//
//     pub fn get_entete(&self) -> Result<&Map<String,Value>, String> {
//         match self.get_message().get(TRANSACTION_CHAMP_ENTETE) {
//             Some(entete) => match entete.as_object() {
//                 Some(entete) => Ok(entete),
//                 None => Err("en-tete n'est pas un document".into()),
//             },
//             None => Err("en-tete manquante".into()),
//         }
//     }
//
//     pub fn get_idmg(&self) -> Result<String, String> {
//         let contenu = self.get_entete()?;
//         match contenu.get(TRANSACTION_CHAMP_IDMG) {
//             Some(idmg) => match idmg.as_str() {
//                 Some(idmg) => Ok(idmg.to_owned()),
//                 None => Err("idmg n'est pas un str".into()),
//             },
//             None => Err("idmg absent de l'entete".into())
//         }
//     }
//
//     pub fn get_estampille(&self) -> Result<DateTime<Utc>, String> {
//         let contenu = self.get_entete()?;
//         match contenu.get(TRANSACTION_CHAMP_ESTAMPILLE) {
//             Some(d) => lire_date_value(d),
//             None => Err("idmg absent de l'entete".into())
//         }
//     }
// }
//
// pub fn lire_date_value(date: &Value) -> Result<DateTime<Utc>, String> {
//     let date_epoch = match date.as_i64() {
//         Some(d) => Ok(d),
//         None => Err("Date n'est pas un i64"),
//     }?;
//     let date_naive = NaiveDateTime::from_timestamp(date_epoch, 0);
//     Ok(DateTime::from_utc(date_naive, Utc))
// }

#[derive(Clone, Debug, PartialEq)]
/// Date a utiliser pour conserver compatibilite avec messages MilleGrille (format epoch secondes i64).
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
    use crate::certificats_tests::charger_enveloppe_privee_env;
    use crate::test_setup::setup;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    /// Sample
    const MESSAGE_STR: &str = r#"{"_certificat":["-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIUOhOPjxIYcu/2KtUKOfVf9gjtRWswDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRj\nYjFhYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDgxMDExMzkzOFoXDTIxMDkwOTExNDEzOFowZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBANQpo8awOOHgdRO56fwZ3/eQbAsqJSS8LNR/\nJHf/1ExHY0AbqH88w+X9Rhh2uU92ECQA1usueJHSMDsKeOSTAuw/7yZNxs5Pv/uu\nfgH4Yq1JnM0r1SqT2zeiLxpKyYuB06XgD1jA5+rz0nD593ARTpGP6bx1HQO7F5sj\nc1+N1Ujf/XHDA9SDptREbpsmwzgmgBgVlbTVm4VQrl99B1LZhQPjDX6nLomQ2jmc\n42CXJRzgihIh7Ym6wggKDgVqlOIevlIRuK4oxITaFRMgtzeBbhj7bw1nMZ8BjxYw\nUpvangdvT3W5s9zTg0C4LgRdihCtFMHIXZOR86J27x1DqhLvH7sCAwEAAaOBgTB/\nMB0GA1UdDgQWBBQhkD483zW0QLedR2BlAZcR0glN6zAfBgNVHSMEGDAWgBT170DQ\ne1NxyrKp2GduPOZ6P9b5iDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQq\nAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5lczANBgkqhkiG9w0BAQsFAAOC\nAQEAPLe/7wTifOq24aGzbuB/BXcAbKm53CcnUQH7CbrnFh7VaHEM8WssZmKX5nYw\nKAts+ORk10xoLMddO9mEFtuKQD4QTjMFQe5EXnOuEuxzF51c3Gv2cY+b0Q/GcAcX\nu/UDN5Cw1SoRYd1SfYkvK8+8Deo7ds1Zib1gYehWmTYPA9ZD+bBIISd1pvgif6cz\nHl12aMusZ2F2m6Qhnot31vB90NPNa/hZ9cOAz+WnjwvcYXUXhCKV/wwuHtNWVNOS\nAphmpcYYJxAjqj1ok/EJF9L5/Z83NvTyz6omZbdptxa0ak4Qchql87rM1B6tGEVD\nkA1HOXEzYkfgtP4gGZZsKQhcxA==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJJ0USglmGk0UAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDcyMDEzNTc0MFoXDTI0MDcyMjEzNTc0MFow\ngYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRjYjFh\nYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCNK7g/7AzTTRT3SX7vTzQIKhXvZ\nTkjphiJ38SoL4jZnv4tEyTV2j2a6v8UgluG/zab6W38n0YpLr1/J2+xVNOKO5P4t\ni//Qiygjkbl/2HGSjttorwdnybFIUdDqMQAHHZMfuvgZOgzXOG4xRxAD/uoTh1+B\ndj55uLKIwITtAY7e/Zxwia8cH9qPLRUETdp2/3rIGHSSkj1GDucnipGJHqrD2wF5\nylgy1kLLzV87wF55g7+nHYFpWXl19h8pAfxrQM1wMIY/rqAKwYoitePRaaLPfTKR\nTrzP4Ei4lStzuR4MocO2wZRSKKNuJw5GFML7PQf+ZV43KOGlpq8GmyNZxQIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBT170DQe1NxyrKp2Gdu\nPOZ6P9b5iDAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAcH0Qbyeap2+uCTXyua+z8JpPAgW25GefOAkyzsaEgaSrOp7U\nic16YmZQz6QXZSkq0+agZ0dVue+9J5iPniujJjkACdClWsMl98eFcen0gb35humU\n20QDgvTDdmNpb2psfVfLMn50B1FxcYTVV3J2jjgBQa0/Q69+DPAbagKF/TJgMERY\nm8vBiHLruFWx7iuO5l9zI9/TCfMdZ1c0i+caUEEf4urCmxp7BjdWfDp+HshcJqok\nQN8PMVu4GfexJOD9gdHBaIA2VAuTCElL9K1Iy5kUcklu0qFxBKDi1N0mKOUeaGnq\nxbVEt7CZD3fF0xKnyNXAZzoCvqvkXtUORdkiZIH7k3EPgpgmLKvx2WNyXgFKs7y0\nMsucRkCixTRCdoju5h410hh7hpfR6eT+kHicJMSH1MKDJ/72MeFNeiOatKq8x72L\nzgGYVkuDlfXjPr5zPalw3BVNToikhVAgvVENiEaRzBKDJIkq1MnwK6VAzLMC60Cm\nSLqr6N7dHrSBO27B\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----\n"],"_signature":"mAXnWu4SZaiBNJMJgc4cVH9XcMsqBphRHvupwQ12oOODFplqz2c4UOdJ1V69DBGcoUZDVYElATHEM7Esm35gADXJdc/hc9yeb6WRK7fMjup1+cYDajPr8yCNezQlPyO6No8wSO9v6BUTXTgLS8sYFY8QXumMQyXd5XfAuo0KL61gG3a++aViaJ8GWdm52i7Hy+FJnuU+gNf4YXRtWfMTOcrFz563y0zMHRYyXnXO72mcYnmkL4Z79TEMLJcBR8A11LSmAteYvBcSJVJnJHXIJEoRPLNPAUR2id+CPpJE3ZDKUECq0gW8ONrvtIt9a5ApLyteXBARaOuVDX5Sh0STtcTE","alpaca":true,"en-tete":{"domaine":null,"estampille":1630600162,"fingerprint_certificat":"zQmRUqgaeEJiB4uM1M8ui7jV7bD8zdcgDufeu9fczwUSrds","hachage_contenu":"mEiCerWQ+xmJBauIR2JdRX1pBa+1wYlUNg/Q0dbhCGUOSww","idmg":"z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s","uuid_transaction":"f5488642-01f3-42a0-9423-5f895bfed17a","version":1},"texte":"oui!","valeur":1}"#;

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
        // let entete = Entete::builder("dummy", "hachage", "idmg").build();

        let val = json!({
            "valeur": 1,
            "texte": "oui!",
            "alpaca": true,
        });
        let message = MessageMilleGrille::new_signer(&enveloppe_privee, &val, None, None).expect("map");

        let message_str = serde_json::to_string(&message).expect("string");
        debug!("Message MilleGrille serialise : {}", message_str)
    }

    #[test]
    fn lire_message_millegrille() {
        setup("lire_message_millegrille");
        let (_, enveloppe_privee) = charger_enveloppe_privee_env();
        let message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");
        let entete = message.get_entete();
        let contenu = &message.get_msg().contenu;
        debug!("Entete message : ${:?}", entete);
        debug!("Contenu parsed : ${:?}", contenu);

        assert_eq!("f5488642-01f3-42a0-9423-5f895bfed17a", entete.uuid_transaction);
        assert_eq!("oui!", contenu.get("texte").expect("texte").as_str().expect("str"));
        assert_eq!(true, contenu.get("alpaca").expect("texte").as_bool().expect("bool"));
        assert_eq!(1, contenu.get("valeur").expect("texte").as_i64().expect("i64"));
    }

    #[tokio::test]
    async fn valider_message_millegrille() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(true, resultat.signature_valide);
        assert_eq!(true, resultat.certificat_valide);
        assert_eq!(None, resultat.hachage_valide);
    }

    #[tokio::test]
    async fn valider_message_corrompu() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        // Corrompre le message
        message.parsed.contenu.insert(String::from("corruption"), Value::String(String::from("je te corromps!")));

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(false, resultat.signature_valide);
        assert_eq!(true, resultat.certificat_valide);
        assert_eq!(Some(false), resultat.hachage_valide);
    }

    #[tokio::test]
    async fn valider_entete_corrompue() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        // Corrompre le message
        message.entete.uuid_transaction = String::from("CORROMPU");

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(false, resultat.signature_valide);
        assert_eq!(true, resultat.certificat_valide);
        assert_eq!(Some(true), resultat.hachage_valide);
    }

    #[tokio::test]
    async fn valider_mauvais_idmg() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        // Corrompre le message
        message.entete.idmg = String::from("CORROMPU");

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(false, resultat.signature_valide);
        assert_eq!(false, resultat.certificat_valide);
        assert_eq!(Some(true), resultat.hachage_valide);
    }

    #[test]
    fn retirer_certificats() {
        setup("creer_message_millegrille");
        let (_, enveloppe_privee) = charger_enveloppe_privee_env();
        // let entete = Entete::builder("dummy", "hachage", "idmg").build();

        let val = json!({
            "valeur": 1,
            "texte": "oui!",
            "alpaca": true,
        });
        let mut message = MessageMilleGrille::new_signer(&enveloppe_privee, &val, None, None).expect("map");

        let message_str = serde_json::to_string(&message).expect("string");
        let idx_certificat = message_str.find("\"_certificat\"");
        debug!("Message MilleGrille serialise avec _certificat (position : {:?} : {}", idx_certificat, message_str);
        assert_eq!(Some(1), idx_certificat);

        message.retirer_certificats();
        let message_str = serde_json::to_string(&message).expect("string");
        let idx_certificat = message_str.find("\"_certificat\"");
        debug!("Message MilleGrille serialise avec _certificat (position : {:?} : {}", idx_certificat, message_str);
        assert_eq!(true, idx_certificat.is_none());
    }

    #[test]
    fn creer_message_manuellement() {
        setup("creer_message_manuellement");
        let (validateur, enveloppe_privee) = charger_enveloppe_privee_env();

        let mut message = MessageMilleGrille::new();
        message.set_value("ma_valeur", Value::String(String::from("mon contenu")));
        message.set_serializable("contenu_String", &String::from("J'ai du contenu"));
        message.set_int("contenu_int", 22);
        message.set_float("contenu_float", 22.89);
        message.set_bool("contenu_bool", true);

        // Signer le message
        message.signer(&enveloppe_privee, Some("MonDomaine"), Some(2)).expect("signer");
        debug!("creer_message_manuellement message signe : {:?}", message);

        assert_eq!(message.certificat.is_some(), true);
        assert_eq!(message.signature.is_some(), true);
        assert_eq!(message.entete.version, 2);
        assert_eq!(message.entete.domaine.expect("domaine"), "MonDomaine");
    }

}
