use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::collections::btree_map::IntoIter;
use std::error::Error;
use std::fmt::Formatter;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use env_logger::fmt::TimestampPrecision::Millis;
use log::{debug, info, warn};
use mongodb::bson as bson;
use multibase::{Base, decode};
use num_traits::ToPrimitive;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{DeserializeOwned, Visitor};
use serde::ser::SerializeMap;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use crate::constantes::*;
use crate::hachages::{hacher_message, verifier_multihash};
use crate::middleware::{IsConfigurationPki, map_msg_to_bson};
use crate::signatures::{signer_message, verifier_message as ref_verifier_message, VERSION_2};
use crate::verificateur::{ResultatValidation, ValidationOptions, verifier_message};
use crate::bson::{Document, Bson};
use std::convert::{TryFrom, TryInto};
use crate::mongo_dao::convertir_to_bson;

const ENTETE: &str = "en-tete";
const SIGNATURE: &str = "_signature";
const CERTIFICATS: &str = "_certificat";

pub trait FormatteurMessage: IsConfigurationPki {
    // /// Retourne l'enveloppe privee utilisee pour signer le message
    // fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;

    /// Implementation de formattage et signature d'un message de MilleGrille
    fn formatter_message<S, T>(
        &self,
        contenu: &S,
        domaine: Option<T>,
        action: Option<T>,
        partition: Option<T>,
        version: Option<i32>
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        S: Serialize,
        T: AsRef<str>
    {
        let enveloppe = self.get_enveloppe_privee();
        MessageMilleGrille::new_signer(enveloppe.as_ref(), contenu, domaine, action, partition, version)
    }

    fn formatter_reponse<S>(
        &self,
        contenu: S,
        version: Option<i32>
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        S: Serialize,
    {
        let enveloppe = self.get_enveloppe_privee();
        MessageMilleGrille::new_signer(enveloppe.as_ref(), &contenu, None::<&str>, None::<&str>, None::<&str>, version)
    }

    fn signer_message(
        &self,
        message: &mut MessageMilleGrille,
        domaine: Option<&str>,
        action: Option<&str>,
        partition: Option<&str>,
        version: Option<i32>
    ) -> Result<(), Box<dyn Error>> {
        if message.signature.is_some() {
            Err(format!("Message {} est deja signe", message.entete.uuid_transaction))?
        }
        message.signer(self.get_enveloppe_privee().as_ref(), domaine, action, partition, version)
    }

    fn confirmation(&self, ok: bool, message: Option<&str>) -> Result<MessageMilleGrille, Box<dyn Error>> {
        let reponse = json!({"ok": ok, "message": message});
        self.formatter_message(&reponse, None::<&str>, None, None, None)
    }

    fn reponse_ok(&self) -> Result<Option<MessageMilleGrille>, String> {
        let reponse = json!({"ok": true});
        match self.formatter_reponse(&reponse,None) {
            Ok(m) => Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Entete de messages de MilleGrille (champ "en-tete").
pub struct Entete {
    // Note : s'assurer de conserver les champs en ordre alphabetique
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domaine: Option<String>,
    pub estampille: DateEpochSeconds,
    pub fingerprint_certificat: String,
    pub hachage_contenu: String,
    pub idmg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    pub uuid_transaction: String,
    pub version: i32,
}

impl Entete {
    pub fn builder(fingerprint_certificat: &str, hachage_contenu: &str, idmg: &str) -> EnteteBuilder {
        EnteteBuilder::new(fingerprint_certificat.to_owned(), hachage_contenu.to_owned(), idmg.to_owned())
    }
}

impl TryInto<Document> for Entete {
    type Error = String;

    fn try_into(self) -> Result<Document, Self::Error> {
        match convertir_to_bson(self) {
            Ok(e) => Ok(e),
            Err(e) => Err(format!("transaction_catalogue_horaire Erreur conversion entete vers bson : {:?}", e))?
        }
    }
}

/// Builder pour les entetes de messages.
pub struct EnteteBuilder {
    action: Option<String>,
    domaine: Option<String>,
    estampille: DateEpochSeconds,
    fingerprint_certificat: String,
    hachage_contenu: String,
    idmg: String,
    partition: Option<String>,
    uuid_transaction: String,
    version: i32,
}

impl EnteteBuilder {
    pub fn new(fingerprint_certificat: String, hachage_contenu: String, idmg: String) -> EnteteBuilder {
        EnteteBuilder {
            action: None,
            domaine: None,
            estampille: DateEpochSeconds::now(),
            fingerprint_certificat,
            hachage_contenu,
            idmg,
            partition: None,
            uuid_transaction: Uuid::new_v4().to_string(),
            version: 1,
        }
    }

    pub fn action(mut self, action: String) -> EnteteBuilder {
        self.action = Some(action);
        self
    }

    pub fn domaine(mut self, domaine: String) -> EnteteBuilder {
        self.domaine = Some(domaine);
        self
    }

    pub fn estampille(mut self, estampille: DateEpochSeconds) -> EnteteBuilder {
        self.estampille = estampille;
        self
    }

    pub fn partition(mut self, partition: String) -> EnteteBuilder {
        self.partition = Some(partition);
        self
    }

    pub fn version(mut self, version: i32) -> EnteteBuilder {
        self.version = version;
        self
    }

    pub fn build(self) -> Entete {
        Entete {
            action: self.action,
            domaine: self.domaine,
            estampille: self.estampille,
            fingerprint_certificat: self.fingerprint_certificat,
            hachage_contenu: self.hachage_contenu,
            idmg: self.idmg,
            partition: self.partition,
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

    #[serde(skip)]
    contenu_traite: bool,
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
            contenu_traite: false,
        }
    }

    pub fn new_signer<S, T, U, V>(
        enveloppe_privee: &EnveloppePrivee,
        contenu: &S,
        domaine: Option<T>,
        action: Option<U>,
        partition: Option<V>,
        version: Option<i32>
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        S: Serialize,
        T: AsRef<str>,
        U: AsRef<str>,
        V: AsRef<str>,
    {
        // Serialiser le contenu
        let value_ordered: Map<String, Value> = MessageMilleGrille::serialiser_contenu(contenu)?;

        debug!("message a serialiser avec B-Tree {}", serde_json::to_string(&value_ordered)?);

        let entete = MessageMilleGrille::creer_entete(
            enveloppe_privee, domaine, action, partition, version, &value_ordered)?;

        let pems: Vec<String> = {
            let pem_vec = enveloppe_privee.enveloppe.get_pem_vec();
            let mut pem_str: Vec<String> = Vec::new();
            for p in pem_vec.iter().map(|c| c.pem.as_str()) {
                pem_str.push(p.to_owned());
            }
            pem_str
        };

        // let message_ordered = MessageMilleGrille::preparer_message_ordered(entete, value)?;

        let mut message = MessageMilleGrille {
            entete,
            certificat: Some(pems),
            signature: None,
            contenu: value_ordered,
            contenu_traite: true,
        };

        MessageMilleGrille::signer_message(&mut message, enveloppe_privee)?;

        Ok(message)
    }

    /// Va creer une nouvelle entete, calculer le hachag
    /// Note : value doit etre deja trie (BTreeMap recursif)
    fn creer_entete<S, T, U>(
        enveloppe_privee: &EnveloppePrivee,
        domaine: Option<S>,
        action: Option<T>,
        partition: Option<U>,
        version: Option<i32>,
        value: &Map<String, Value>
    )
        -> Result<Entete, Box<dyn Error>>
        where S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
    {

        // Calculer le hachage du contenu
        let message_string = serde_json::to_string(&value)?;
        let hachage = hacher_message(message_string.as_str());

        // Generer l'entete
        let mut entete_builder = Entete::builder(
            enveloppe_privee.fingerprint(),
            &hachage,
            enveloppe_privee.idmg().expect("idmg").as_str()
        )
            .estampille(DateEpochSeconds::now())
            .version(1);

        match domaine {
            Some(d) => entete_builder = entete_builder.domaine(d.as_ref().to_owned()),
            None => (),
        }

        match action {
            Some(a) => entete_builder = entete_builder.action(a.as_ref().to_owned()),
            None => (),
        }

        match partition {
            Some(p) => entete_builder = entete_builder.partition(p.as_ref().to_owned()),
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
        if self.signature.is_some() { panic!("set_value sur message signe") }
        self.contenu.insert(name.to_owned(), value);
    }

    pub fn set_int(&mut self, name: &str, value: i64) {
        if self.signature.is_some() { panic!("set_int sur message signe") }
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_float(&mut self, name: &str, value: f64) {
        if self.signature.is_some() { panic!("set_float sur message signe") }
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_bool(&mut self, name: &str, value: bool) {
        if self.signature.is_some() { panic!("set_bool sur message signe") }
        self.contenu.insert(name.to_owned(), Value::from(value));
    }

    pub fn set_serializable<S>(&mut self, name: &str, value: &S) -> Result<(), Box<dyn Error>>
    where
        S: Serialize,
    {
        if self.signature.is_some() { panic!("set_serializable sur message signe") }

        let val_ser = serde_json::to_value(value)?;
        self.contenu.insert(name.to_owned(), val_ser);
        Ok(())
    }

    fn serialiser_contenu<S>(contenu: &S) -> Result<Map<String, Value>, Box<dyn std::error::Error>>
    where
        S: Serialize,
    {
        let mut map = serde_json::to_value(contenu).expect("value").as_object().expect("value map").to_owned();
        let contenu = preparer_btree_recursif(map)?;
        Ok(contenu)
    }

    fn calculer_hachage_contenu(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        if ! self.contenu_traite {
            self.traiter_contenu();
        }

        // Filtrer champs avec _
        let contenu_string = {
            let mut map: BTreeMap<&str, &Value> = BTreeMap::new();
            for (k, v) in &self.contenu {
                if !k.starts_with("_") {
                    map.insert(k.as_str(), v);
                }
            }
            serde_json::to_string(&map)?
        };

        Ok(hacher_message(contenu_string.as_str()))
    }

    fn signer_message(&mut self, enveloppe_privee: &EnveloppePrivee) -> Result<(), Box<dyn std::error::Error>> {
        let message_string = self.preparer_pour_signature()?;

        debug!("Message serialise avec entete : {}", message_string);
        let signature = signer_message(enveloppe_privee.cle_privee(), message_string.as_bytes())?;

        self.signature = Some(signature);

        Ok(())
    }

    fn preparer_pour_signature(&mut self) -> Result<String, Box<dyn Error>> {
        if !self.contenu_traite {
            self.traiter_contenu();
        }

        // Creer une map avec l'entete (refs uniquements)
        let mut map_ordered: BTreeMap<&str, &Value> = BTreeMap::new();

        // Copier references du reste du contenu (exclure champs _)
        for (k, v) in &self.contenu {
            if !k.starts_with("_") {
                map_ordered.insert(k.as_str(), v);
            }
        }

        // Ajouter entete
        let entete_value = serde_json::to_value(&self.entete)?;
        map_ordered.insert("en-tete", &entete_value);

        let message_string = serde_json::to_string(&map_ordered)?;
        Ok(message_string)
    }

    /// Genere une String avec le contenu serialise correctement pour hachage / validation.
    // pub fn preparer_pour_hachage(&mut self) -> Result<String, Box<dyn Error>> {
    //     // let mut ordered = BTreeMap::new();
    //     //
    //     // // Copier dans une BTreeMap. Retirer champs _ et en-tete
    //     // for (k, v) in contenu {
    //     //     if ! k.starts_with("_") && k != "en-tete" {
    //     //         ordered.insert(k, v);
    //     //     }
    //     // }
    //
    //     if ! self.contenu_traite {
    //         self.traiter_contenu();
    //     }
    //
    //     Ok(serde_json::to_string(&self.contenu)?)
    // }

    // /// Preparer recursivement le contenu en triant les cles.
    // fn preparer_btree_recursif_into_iter(mut iter: IntoIter<String, Value>) -> Result<BTreeMap<String, Value>, Box<dyn Error>> {
    //     let mut map = Map::new();
    //     // let mut iter = contenu.into_iter();
    //     while let Some((k, v)) = iter.next() {
    //         map.insert(k, v);
    //     }
    //
    //     let ordered = MessageMilleGrille::preparer_btree_recursif(map)?;
    //
    //     Ok(ordered)
    // }

    // /// Reorganise un message en ordre pour hachage, signature ou verification.
    // pub fn preparer_message_ordered(entete: Entete, contenu: &mut Map<String, Value>) -> Result<Map<&str, &Value>, Box<dyn Error>> {
    //     let mut map_ordered = MessageMilleGrille::preparer_btree_recursif(contenu)?;
    //     let mut iter_ordered = map_ordered.into_iter();
    //
    //     // Creer un b-tree (top level) pour ajouter l'en-tete
    //     let mut btmap: BTreeMap<&str, &Value> = BTreeMap::new();
    //     while let Some((k, v)) = iter_ordered.next() {
    //         btmap.insert(k.as_str(), &v);
    //     }
    //
    //     // Ajouter entete
    //     let entete_value = serde_json::to_value(entete)?;
    //     btmap.insert("en-tete", entete_value.to_owned());
    //
    //     let mut map_ordered = Map::new();  // Recreer map (indexed)
    //     let mut iter_btmap = btmap.into_iter();
    //     while let Some((k, v)) = iter_btmap.next() {
    //         map_ordered.insert(k, v);
    //     }
    //
    //     Ok(map_ordered)
    // }

    // /// Generer une String avec le contenu et l'entete serialises correctement pour signature / validation.
    // pub fn preparer_pour_signature(entete: &Entete, contenu: &Map<String, Value>) -> Result<String, Box<dyn Error>> {
    //     let mut ordered = BTreeMap::new();
    //
    //     // Copier dans une BTreeMap. Retirer champs _ et en-tete
    //     // for (k, v) in contenu {
    //     //     if !k.starts_with("_") {
    //     //         ordered.insert(k.as_str(), v);
    //     //     }
    //     // }
    //     let mut ordered = MessageMilleGrille::preparer_btree_recursif(contenu)?;
    //
    //     // Ajouter entete
    //     let entete_value = serde_json::to_value(entete)?;
    //     ordered.insert(String::from("en-tete"), entete_value.to_owned());
    //
    //     // Serialiser en json pour signer
    //     Ok(serde_json::to_string(&ordered)?)
    // }

    fn signer(
        &mut self,
        enveloppe_privee: &EnveloppePrivee,
        domaine: Option<&str>,
        action: Option<&str>,
        partition: Option<&str>,
        version: Option<i32>
    ) -> Result<(), Box<dyn std::error::Error>> {

        if self.signature.is_some() {
            warn!("appel signer() sur message deja signe, on ignore");
            return Ok(())
        }

        let entete = MessageMilleGrille::creer_entete(enveloppe_privee, domaine, action, partition, version, &self.contenu)?;

        // Remplacer l'entete
        self.entete = entete;
        self.certificat = Some(enveloppe_privee.chaine_pem().to_owned());

        self.signer_message(enveloppe_privee)?;

        Ok(())
    }

    fn traiter_contenu(&mut self) -> Result<(), Box<dyn Error>>{
        if ! self.contenu_traite {
            let mut contenu = Map::new();
            let mut contenu_ref = &mut self.contenu;

            let keys: Vec<String> = contenu_ref.keys().map(|k| k.to_owned()).collect();
            for k in keys {
                if let Some(v) = contenu_ref.remove(k.as_str()) {
                    contenu.insert(k, v);
                }
            }

            // let mut contenu_prev: serde_json::map::IntoIter = self.contenu.into_iter();
            // for ((k, v)) in self.contenu {
            //     contenu.insert(k, v);
            // }
            // while let Some((k, v)) = contenu_prev.next() {
            //     contenu.insert(k, v);
            // }

            // let mut contenu = &self.contenu;
            // let contenu_prev: serde_json::map::IntoIter = contenu.into_iter();
            // self.contenu = MessageMilleGrille::preparer_btree_recursif_into_iter(contenu_prev)?;
            self.contenu = preparer_btree_recursif(contenu)?;
            self.contenu_traite = true;
        }
        Ok(())
    }

    /// Sert a retirer les certificats pour serialisation (e.g. backup, transaction Mongo, etc)
    pub fn retirer_certificats(&mut self) { self.certificat = None }

    /// Mapper le contenu ou un champ (1er niveau) du contenu vers un objet Deserialize
    pub fn map_contenu<C>(&self, nom_champ: Option<&str>) -> Result<C, Box<dyn Error>>
        where C: DeserializeOwned
    {
        let value = match nom_champ {
            Some(c) => {
                match self.contenu.get(c) {
                    Some(c) => c.to_owned(),
                    None => Err(format!("formatteur_messages.map_contenu Champ {} introuvable", c))?,
                }
            },
            None => serde_json::to_value(self.contenu.clone())?,
        };

        let deser: C = serde_json::from_value(value)?;

        Ok(deser)
    }

    pub fn map_to_bson(&self) -> Result<Document, Box<dyn Error>> {
        map_msg_to_bson(self)
    }

    pub fn verifier_hachage(&mut self) -> Result<bool, Box<dyn Error>> {
        if ! self.contenu_traite {
            self.traiter_contenu();
        }

        let entete = &self.entete;
        let hachage_str = entete.hachage_contenu.as_str();

        // Filtrer champs avec _
        let contenu_string = {
            let mut map: BTreeMap<&str, &Value> = BTreeMap::new();
            for (k, v) in &self.contenu {
                if !k.starts_with("_") {
                    map.insert(k.as_str(), v);
                }
            }
            serde_json::to_string(&map)?
        };

        verifier_multihash(hachage_str, contenu_string.as_bytes())
    }

    pub fn verifier_signature(&mut self, public_key: &PKey<Public>) -> Result<bool, Box<dyn Error>> {
        // let contenu_str = MessageMilleGrille::preparer_pour_signature(entete, contenu)?;
        debug!("verifier_signature_str (signature: {:?}, public key: {:?})", self.signature, public_key);

        let message = self.preparer_pour_signature()?;
        match &self.signature {
            Some(s) => {
                debug!("Message prepare pour signature\n{}", message);
                let resultat = ref_verifier_message(public_key, message.as_bytes(), s.as_str())?;
                Ok(resultat)
                // decode(s)?
            },
            None => Err(format!("Signature absente"))?,
        }
        // let version_signature = signature_bytes.1[0];
        // if version_signature != VERSION_2 {
        //     Err(format!("La version de la signature n'est pas 2"))?;
        // }

        // let mut verifier = match Verifier::new(MessageDigest::sha512(), &public_key) {
        //     Ok(v) => v,
        //     Err(e) => Err(format!("Erreur verification signature : {:?}", e))?
        // };
        //
        // verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        // verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
        // verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH))?;
        // verifier.update(message.as_bytes())?;
        //
        // // Retourner la reponse
        // Ok(verifier.verify(&signature_bytes.1[1..])?)
    }
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

pub fn preparer_btree_recursif(mut contenu: Map<String, Value>) -> Result<Map<String, Value>, Box<dyn Error>> {
    let mut iter: serde_json::map::IntoIter = contenu.into_iter();
    preparer_btree_recursif_into_iter(iter)
}

/// Preparer recursivement le contenu en triant les cles.
fn preparer_btree_recursif_into_iter(mut iter: serde_json::map::IntoIter) -> Result<Map<String, Value>, Box<dyn Error>> {
    let mut ordered: BTreeMap<String, Value> = BTreeMap::new();

    // Copier dans une BTreeMap (via trier les keys)
    // let mut iter: serde_json::map::IntoIter = contenu.into_iter();
    while let Some((k, mut v)) = iter.next() {
        let value = map_valeur_recursif(v)?;
        ordered.insert(k, value);
    }

    // Reconvertir en Map<String, Value> (flag preserve_order est actif)
    let mut map_ordered = Map::new();
    let mut iter_ordered = ordered.into_iter();
    while let Some((k, v)) = iter_ordered.next() {
        map_ordered.insert(k, v);
    }

    Ok(map_ordered)
}

pub fn map_valeur_recursif(v: Value) -> Result<Value, Box<dyn Error>> {
    let res = match v {
        Value::Object(o) => {
            let map = preparer_btree_recursif(o)?;
            Value::Object(map)
        },
        Value::Array(o) => {
            // Parcourir array recursivement
            let mut arr = o.into_iter();
            let mut vec_values = Vec::new();

            while let Some(v) = arr.next() {
                vec_values.push(map_valeur_recursif(v)?)
            }

            // Retourner le nouvel array
            Value::Array(vec_values)
        },
        Value::Bool(o) => Value::Bool(o),
        Value::Number(o) => {
            match o.is_f64() {
                true => {
                    // Traiter un float, on converti en i64 si le nombre fini en .0
                    match o.as_f64() {
                        Some(float_num) => {
                            let int_num = float_num.floor() as i64;
                            match int_num as f64 == float_num {
                                true => {
                                    // Float fini par .0, on transforme en i64
                                    Value::from(int_num)
                                },
                                false => Value::from(float_num),  // partie fractionnaire presente
                            }
                        },
                        None => Value::Number(o)
                    }
                },
                false => Value::Number(o)
            }
        },
        Value::String(o) => Value::String(o),
        Value::Null => Value::Null,
    };

    Ok(res)
}


#[derive(Clone, Debug)]
pub struct MessageSerialise {
    entete: Entete,
    message: String,
    pub parsed: MessageMilleGrille,
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

    pub async fn valider<V>(&mut self, validateur: &V, options: Option<&ValidationOptions<'_>>) -> Result<ResultatValidation, Box<dyn Error>>
    where
        V: ValidateurX509,
    {
        match &self.certificat {
            Some(_) => {
                // Ok, on a un certificat. Valider la signature.
                verifier_message(self, validateur, options)
            },
            None => {
                // Tenter de charger le certificat
                // let enveloppe : Option<Arc<EnveloppeCertificat>> = self.charger_certificat(validateur).await?;
                match self.charger_certificat(validateur).await? {
                    Some(e) => {
                        self.certificat = Some(e);
                        verifier_message(self, validateur, options)
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

    /// Sert a extraire le message pour une restauration - deplace (move) le message.
    pub fn preparation_restaurer(mut self) -> MessageMilleGrille {
        let mut message = self.parsed;
        let evenements = message.contenu
            .get_mut("_evenements").expect("evenements")
            .as_object_mut().expect("object");
        evenements.insert(String::from("backup_flag"), Value::Bool(true));
        evenements.insert(String::from("transaction_restauree"), serde_json::to_value(bson::DateTime::now()).expect("date") );

        message
    }
}

impl VerificateurPermissions for MessageSerialise {
    fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
        // Valider certificat. Doit etre de niveau 4.secure
        match &self.certificat {
            Some(c) => c.get_extensions(),
            None => None,
        }
    }
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

    /// Retirer l'heure (mettre a 0/minuit UTC)
    pub fn get_jour(&self) -> Self {
        let date_naive = self.date.naive_utc().date();
        let heure_naive = NaiveTime::from_hms(0, 0, 0);
        let datetime_naive = NaiveDateTime::new(date_naive, heure_naive);
        let date = DateTime::from_utc(datetime_naive, Utc);
        DateEpochSeconds { date }
    }
}

impl Default for DateEpochSeconds {
    fn default() -> Self {
        DateEpochSeconds::now()
    }
}

impl From<DateTime<Utc>> for DateEpochSeconds {
    fn from(dt: DateTime<Utc>) -> Self {
        DateEpochSeconds {date: dt}
    }
}

impl Into<Bson> for DateEpochSeconds {
    fn into(self) -> Bson {
        // Bson::DateTime(bson::DateTime::from(self.date))
        Bson::Int32(self.date.timestamp() as i32)
    }
}

impl TryFrom<Bson> for DateEpochSeconds {
    type Error = String;

    fn try_from(value: Bson) -> Result<Self, Self::Error> {
        match value.as_datetime() {
            Some(inner_d) => {
                Ok(DateEpochSeconds {
                    date: inner_d.to_chrono()
                })
            },
            None => Err(format!("Mauvais format bson (pas datetime)"))
        }
    }
}

impl Serialize for DateEpochSeconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let ts = self.date.timestamp();
        serializer.serialize_i32(ts as i32)
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
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
    use crate::test_setup::setup;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    /// Sample
    const MESSAGE_STR: &str = r#"{"_certificat":["-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIUFGTSBu4f2hbzgnca0GuSsmLgr7UwDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRj\nYjFhYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDgzMDExNTcxNVoXDTIxMDkyOTExNTkxNVowZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMcAz3SshFSHxyd+KfTZVHWG3OQg9t7kdHtV\nkrXySXdPYc+svArawMKhy/XRrFJ+NfLNoUyz+KPma5mEWxXZDRZVyvmdodDh/eNu\nqJ4aB078AkxyKWNgT/aF1/EuZ+pZseVlaDrD1yoEiC4stXwm6ay7mnWTyczDt8FI\ntCZ6/9nDNwPsnwC6cbqXRH4gqkwDqBGolX9Jz6TU4pqisIroacwOW+NEmNassM2b\nQqP/W4saEQQqD2BV78I9hQxouE8JLR6SIL5XD7j6Pq6pG86TSkFGAqQsSPd1w+5l\nxMRQgitYJ7ITo/Eq0qmAxv1INnxLyLmXQ2FysUNVTtgGgN3O7OUCAwEAAaOBgTB/\nMB0GA1UdDgQWBBQSOxwSTijPrcKRmCWzoFpf8cJQbDAfBgNVHSMEGDAWgBT170DQ\ne1NxyrKp2GduPOZ6P9b5iDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQq\nAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5lczANBgkqhkiG9w0BAQsFAAOC\nAQEARX75Y2kVlxiJSmbDi1hZRj3mfe7ihT69EL51R6YiB0c/fpQUYxWfpddbg4DY\nlzAssE2XtSv1gYBZkZJXGWS4jB6dW6r+7Mhbtb6ZSXXG5ba9LydSxI8++//GZwG/\np8nce6fNmR8b06s/TQjpqwOa+hXqiqkWzqoVal/ucQWhdLtTkx/DVFUjHMcDMhZT\nVKIX7/SGEi9uGM9LNIVhCc7TsndcmiNXkV7ybiJ02rqxXPrD0QJ6h28rHIEGbWWs\napOlHiqtHYWQCuM0h5kygqknYKmHZIFBfba/xCf1rJi9HQUFZZfuw0VS9BcFmBg/\n5Hx8faWZNWWE9Iu+366P1t9GxA==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJJ0USglmGk0UAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDcyMDEzNTc0MFoXDTI0MDcyMjEzNTc0MFow\ngYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRjYjFh\nYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCNK7g/7AzTTRT3SX7vTzQIKhXvZ\nTkjphiJ38SoL4jZnv4tEyTV2j2a6v8UgluG/zab6W38n0YpLr1/J2+xVNOKO5P4t\ni//Qiygjkbl/2HGSjttorwdnybFIUdDqMQAHHZMfuvgZOgzXOG4xRxAD/uoTh1+B\ndj55uLKIwITtAY7e/Zxwia8cH9qPLRUETdp2/3rIGHSSkj1GDucnipGJHqrD2wF5\nylgy1kLLzV87wF55g7+nHYFpWXl19h8pAfxrQM1wMIY/rqAKwYoitePRaaLPfTKR\nTrzP4Ei4lStzuR4MocO2wZRSKKNuJw5GFML7PQf+ZV43KOGlpq8GmyNZxQIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBT170DQe1NxyrKp2Gdu\nPOZ6P9b5iDAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAcH0Qbyeap2+uCTXyua+z8JpPAgW25GefOAkyzsaEgaSrOp7U\nic16YmZQz6QXZSkq0+agZ0dVue+9J5iPniujJjkACdClWsMl98eFcen0gb35humU\n20QDgvTDdmNpb2psfVfLMn50B1FxcYTVV3J2jjgBQa0/Q69+DPAbagKF/TJgMERY\nm8vBiHLruFWx7iuO5l9zI9/TCfMdZ1c0i+caUEEf4urCmxp7BjdWfDp+HshcJqok\nQN8PMVu4GfexJOD9gdHBaIA2VAuTCElL9K1Iy5kUcklu0qFxBKDi1N0mKOUeaGnq\nxbVEt7CZD3fF0xKnyNXAZzoCvqvkXtUORdkiZIH7k3EPgpgmLKvx2WNyXgFKs7y0\nMsucRkCixTRCdoju5h410hh7hpfR6eT+kHicJMSH1MKDJ/72MeFNeiOatKq8x72L\nzgGYVkuDlfXjPr5zPalw3BVNToikhVAgvVENiEaRzBKDJIkq1MnwK6VAzLMC60Cm\nSLqr6N7dHrSBO27B\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----\n"],"_signature":"mAWm3oYujnuCUtXlqyUnLWRNDJFtDUiG3wmy1sdU8YLTf0yNDENYLB8t1jUtXYyHRx5Dawd6sy0RhKXCUwnWl9q+Q/9u+wAwSxvR+dKiweYsdDZJAXrTwkYQmEu/X8/vbQcVMVX8VWwinDgalFSR0q//6V14Bp8jgAKFZifd2N9gPSEy0RBze1TUHuNlW7phUP5dAPcviiDLbpcQNJ3suD8Oq9m3ob61N04QFMvr8glWGs8yf0VbEJ8UXi22WOL/L02UWcMuqf5v9SKaKd/7we/jVW10GnYfH/coWdl62FrTNLBMGonkO9KzR8dXxNzDMvpt4A1kpcEZ7488EjTAhgzs","alpaca":true,"en-tete":{"estampille":1631884993,"fingerprint_certificat":"zQmSTKik15nFmLe4tQtndoEWA6aDdGUcVjpNHt4RtKQvnC3","hachage_contenu":"mEiCerWQ+xmJBauIR2JdRX1pBa+1wYlUNg/Q0dbhCGUOSww","idmg":"z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s","uuid_transaction":"6ba61473-18fc-4ff2-9de7-95470eadb2d8","version":1},"texte":"oui!","valeur":1}"#;

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
        let message = MessageMilleGrille::new_signer(
            &enveloppe_privee, &val, None::<&str>, None::<&str>, None::<&str>, None).expect("map");

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
        debug!("Message serialise a valider\n{:?}", message);

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(true, resultat.signature_valide);
        // assert_eq!(false, resultat.certificat_valide);  // Expire
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
        assert_eq!(false, resultat.certificat_valide);  // expire
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
        assert_eq!(false, resultat.certificat_valide);  // expire
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
        let mut message = MessageMilleGrille::new_signer(
            &enveloppe_privee, &val, None::<&str>, None::<&str>, None::<&str>, None).expect("map");

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
        message.signer(&enveloppe_privee, Some("MonDomaine"), None, None, Some(2)).expect("signer");
        debug!("creer_message_manuellement message signe : {:?}", message);

        assert_eq!(message.certificat.is_some(), true);
        assert_eq!(message.signature.is_some(), true);
        assert_eq!(message.entete.version, 2);
        assert_eq!(message.entete.domaine.as_ref().expect("domaine").as_str(), "MonDomaine");

        // Signer a nouveau, devrait juste lancer un warning
        message.signer(&enveloppe_privee, Some("MonDomaine"), None, None, Some(2)).expect("signer");
    }

    #[test]
    #[should_panic]
    fn creer_message_panic_set() {
        setup("creer_message_panic_set");
        let (validateur, enveloppe_privee) = charger_enveloppe_privee_env();

        // Creer et signer le message
        let mut message = MessageMilleGrille::new();
        message.signer(&enveloppe_privee, Some("MonDomaine"), None, None, Some(2)).expect("signer");

        // Panic, le messsage est signe (immuable)
        message.set_value("ma_valeur", Value::String(String::from("mon contenu")));
    }

}
