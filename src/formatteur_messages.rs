use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt::Formatter;
use std::sync::Arc;
use hex;

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use log::debug;
use mongodb::bson as bson;
use openssl::pkey::{Id, PKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{DeserializeOwned, Visitor};
use serde_json::{json, Map, Number, Value};
use uuid::Uuid;

use crate::certificats::{ValidateurX509, VerificateurPermissions};
use crate::hachages::{hacher_bytes, hacher_message};
use crate::middleware::map_msg_to_bson;
use crate::signatures::signer_message;
// use crate::verificateur::{ResultatValidation, ValidationOptions};
use crate::bson::{Document, Bson};
use std::convert::{TryFrom, TryInto};
use millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_cryptographie::ed25519_dalek::{SecretKey, SigningKey};
use millegrilles_cryptographie::heapless;
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, MessageMilleGrillesBufferDefault, RoutageMessage, MessageMilleGrillesBuilderDefault};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use multibase::Base;
use multihash::Code;
use openssl::sign::Verifier;
use crate::chiffrage_cle::CommandeSauvegarderCle;
use crate::common_messages::{DataChiffre, DataDechiffre};
use crate::constantes::MessageKind;
use crate::constantes::MessageKind::ReponseChiffree;
// use crate::dechiffrage::dechiffrer_data;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::mongo_dao::convertir_to_bson;

pub fn build_reponse<M>(message: M, enveloppe_privee: &EnveloppePrivee)
                        -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where M: Serialize + Send + Sync
{
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_reponse Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    // Allouer un Vec et serialiser le message signe.
    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let generateur = MessageMilleGrillesBuilderDefault::new(
            millegrilles_cryptographie::messages_structs::MessageKind::Reponse, contenu.as_str())
            .signing_key(&signing_key)
            .certificat(certificat);

        let message_ref = generateur.build_into_alloc(&mut buffer)?;
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

pub fn build_message_action<R,M>(type_message: millegrilles_cryptographie::messages_structs::MessageKind,
                                 routage: R, message: M, enveloppe_privee: &EnveloppePrivee)
                                 -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
    where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync
{
    let routage = routage.into();
    let contenu = match serde_json::to_string(&message) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur serde::to_vec : {:?}", e))?
    };

    let routage_message: RoutageMessage = (&routage).into();

    let mut cle_privee_u8 = SecretKey::default();
    match enveloppe_privee.cle_privee.raw_private_key() {
        Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
        Err(e) => Err(format!("build_message_action Erreur raw_private_key {:?}", e))?
    };
    let signing_key = SigningKey::from_bytes(&cle_privee_u8);

    let pem_vec = &enveloppe_privee.chaine_pem;

    let mut buffer = Vec::new();
    let message_id = {
        let mut certificat: heapless::Vec<&str, 4> = heapless::Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));

        let generateur = MessageMilleGrillesBuilderDefault::new(
            type_message, contenu.as_str())
            .routage(routage_message)
            .signing_key(&signing_key)
            .certificat(certificat);

        // Allouer un Vec et serialiser le message signe.
        let message_ref = generateur.build_into_alloc(&mut buffer)?;
        message_ref.id.to_owned()
    };

    // Retourner le nouveau message
    Ok((MessageMilleGrillesBufferDefault::from(buffer), message_id))
}

#[derive(Serialize)]
struct ReponseMessage<'a> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<&'a str>,
}

pub trait FormatteurMessage {
    /// Retourne l'enveloppe privee utilisee pour signer le message
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee>;

    /// Permet de modifier l'enveloppe utilisee pour la signature de messages
    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>);

    fn build_message_action<R, M>(&self, type_message: millegrilles_cryptographie::messages_structs::MessageKind, routage: R, message: M)
                                  -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
        let enveloppe_privee = self.get_enveloppe_signature();
        build_message_action(type_message, routage, message, enveloppe_privee.as_ref())
    }

    fn build_reponse<M>(&self, message: M)
                        -> Result<(MessageMilleGrillesBufferDefault, String), crate::error::Error>
        where M: Serialize + Send + Sync {
        let enveloppe_privee = self.get_enveloppe_signature();
        build_reponse(message, enveloppe_privee.as_ref())
    }

    // fn formatter_inter_millegrille<M,S>(
    //     &self,
    //     middleware: &M,
    //     contenu: S,
    //     certificat_demandeur: &EnveloppeCertificat
    // ) -> Result<MessageMilleGrille, crate::error::Error>
    // where
    //     M: ChiffrageFactoryTrait + FormatteurMessage,
    //     S: Serialize,
    // {
    //     let enveloppe = self.get_enveloppe_signature();
    //     let reponse_chiffree = MessageInterMillegrille::new(
    //         middleware, contenu, Some(vec![certificat_demandeur]))?;
    //     MessageMilleGrille::new_signer(
    //         enveloppe.as_ref(), MessageKind::ReponseChiffree, &reponse_chiffree,
    //         None::<&str>, None::<&str>, None::<&str>, None::<&str>, None::<i32>, false)
    // }

    fn reponse_ok<O>(&self, code: O, message: Option<&str>)
        -> Result<MessageMilleGrillesBufferDefault, String>
        where O: Into<Option<usize>>
    {
        let code = code.into();
        let message = match message { Some(inner) => { Some(inner.into()) }, None => None };
        let reponse = ReponseMessage { ok: true, code, message, err: None };
        match self.build_reponse(reponse) {
            Ok(m) => Ok(m.0),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

    fn reponse_err<O>(&self, code: O, message: Option<&str>, err: Option<&str>)
        -> Result<MessageMilleGrillesBufferDefault, String>
        where O: Into<Option<usize>>
    {
        let code = code.into();
        let message = match message { Some(inner) => { Some(inner.into()) }, None => None };
        let err = match err { Some(inner) => { Some(inner.into()) }, None => None };

        let reponse = ReponseMessage { ok: false, code, message, err };

        match self.build_reponse(reponse) {
            Ok(m) => Ok(m.0),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// /// Structure a utiliser pour creer un nouveau message
// /// Utiliser methode MessageMilleGrille::new_signer().
// pub struct MessageMilleGrille {
//     /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
//     pub id: String,
//
//     /// Cle publique du certificat utilise pour la signature
//     pub pubkey: String,
//
//     /// Date de creation du message
//     pub estampille: DateEpochSeconds,
//
//     /// Kind du message, correspond a enum MessageKind
//     pub kind: u16,
//
//     /// Contenu du message en format json-string
//     pub contenu: String,
//
//     /// Information de routage de message (optionnel, depend du kind)
//     pub routage: Option<RoutageMessage>,
//
//     /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
//     #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
//     pub pre_migration: Option<HashMap<String, Value>>,
//
//     /// IDMG d'origine du message
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub origine: Option<String>,
//
//     /// Information de dechiffrage pour contenu chiffre
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub dechiffrage: Option<DechiffrageInterMillegrille>,
//
//     /// Signature ed25519 encodee en hex
//     #[serde(rename = "sig")]
//     pub signature: String,
//
//     /// Chaine de certificats en format PEM.
//     #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
//     pub certificat: Option<Vec<String>>,
//
//     /// Certificat de millegrille (root).
//     #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
//     pub millegrille: Option<String>,
//
//     /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub attachements: Option<Map<String, Value>>,
//
//     #[serde(skip)]
//     contenu_valide: Option<(bool, bool)>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct RoutageMessage {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub action: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub domaine: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub partition: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub user_id: Option<String>,
// }

// #[derive(Debug, Serialize, Deserialize)]
// pub struct EnveloppeHachageMessage<'a> {
//     pub pubkey: String,
//     pub estampille: DateEpochSeconds,
//     pub kind: u16,
//     pub contenu: &'a str,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub routage: Option<RoutageMessage>,
//     #[serde(rename="pre-migration", skip_serializing_if = "Option::is_none")]
//     pub pre_migration: Option<HashMap<String, Value>>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub origine: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub dechiffrage: Option<DechiffrageInterMillegrille>
// }

// impl<'a> EnveloppeHachageMessage<'a> {
//     pub fn new(certificat: &EnveloppeCertificat, kind: MessageKind, contenu: &'a str,
//                routage: Option<RoutageMessage>, pre_migration: Option<HashMap<String, Value>>,
//                origine: Option<String>, dechiffrage: Option<DechiffrageInterMillegrille>
//     ) -> Result<Self, crate::error::Error> {
//         let pubkey = certificat.publickey_bytes_encoding(Base::Base16Lower, true)?;
//         let estampille = DateEpochSeconds::now();
//         Ok(Self {
//             pubkey,
//             estampille,
//             kind: kind.into(),
//             contenu,
//             routage,
//             pre_migration,
//             origine,
//             dechiffrage
//         })
//     }
//
//     pub fn hacher(&self) -> Result<String, crate::error::Error> {
//
//         let message_value = match &self.kind {
//             0 | 4 | 6 => {
//                 json!([
//                     &self.pubkey,
//                     &self.estampille,
//                     &self.kind,
//                     self.contenu,
//                 ])
//             },
//             1 | 2 | 3 | 5 => {
//                 match self.routage.as_ref() {
//                     Some(routage) => {
//                         json!([
//                             &self.pubkey,
//                             &self.estampille,
//                             &self.kind,
//                             self.contenu,
//                             routage,
//                         ])
//                     },
//                     None => Err(format!("Message format {} sans routage", self.kind))?
//                 }
//             },
//             7 => {
//                 match self.routage.as_ref() {
//                     Some(routage) => {
//                         match self.pre_migration.as_ref() {
//                             Some(pre_migration) => {
//                                 json!([
//                                     &self.pubkey,
//                                     &self.estampille,
//                                     &self.kind,
//                                     self.contenu,
//                                     routage,
//                                     pre_migration,
//                                 ])
//                             },
//                             None => Err(format!("Message format {} sans pre_migration", self.kind))?
//                         }
//                     },
//                     None => Err(format!("Message format {} sans routage", self.kind))?
//                 }
//             },
//             8 => {
//                 match self.routage.as_ref() {
//                     Some(routage) => {
//                         match self.origine.as_ref() {
//                             Some(origine) => {
//                                 match self.dechiffrage.as_ref() {
//                                     Some(dechiffrage) => {
//                                         json!([
//                                             &self.pubkey,
//                                             &self.estampille,
//                                             &self.kind,
//                                             self.contenu,
//                                             routage,
//                                             origine,
//                                             dechiffrage
//                                         ])
//                                     },
//                                     None => Err(format!("Message format {} sans dechiffrage", self.kind))?
//                                 }
//                             },
//                             None => Err(format!("Message format {} sans origine", self.kind))?
//                         }
//                     },
//                     None => Err(format!("Message format {} sans routage", self.kind))?
//                 }
//             },
//             _ => Err(format!("Message format {} non supporte", self.kind))?
//         };
//
//         let value_str = serde_json::to_string(&message_value)?;
//         debug!("Message string a hacher : {}", value_str);
//         let value_bytes = value_str.as_bytes();
//         let message_hache = hacher_bytes(value_bytes, Some(Code::Blake2s256), Some(Base::Base16Lower));
//         // Retirer encodage multibase (1 char) et multihash (4 bytes), 9 chars en tout
//         let message_hache = &message_hache[9..];
//
//         Ok(message_hache.to_string())
//     }
// }

// impl MessageMilleGrille {
//
//     pub fn new_signer<S, T, U, V, W>(
//         enveloppe_privee: &EnveloppePrivee,
//         kind: MessageKind,
//         contenu: &S,
//         domaine: Option<T>,
//         action: Option<U>,
//         partition: Option<V>,
//         user_id: Option<W>,
//         version: Option<i32>,
//         ajouter_ca: bool
//     ) -> Result<Self, Box<dyn std::error::Error>>
//     where
//         S: Serialize,
//         T: AsRef<str>,
//         U: AsRef<str>,
//         V: AsRef<str>,
//         W: AsRef<str>,
//     {
//         // Serialiser le contenu
//         let (value_serialisee, origine, dechiffrage) = match kind {
//             MessageKind::ReponseChiffree => {
//                 let reponse_chiffree: MessageReponseChiffree = serde_json::from_value(serde_json::to_value(contenu)?)?;
//                 (reponse_chiffree.contenu, None, Some(reponse_chiffree.dechiffrage))
//             },
//             MessageKind::CommandeInterMillegrille => {
//                 let commande_inter_millegrille: MessageInterMillegrille = serde_json::from_value(serde_json::to_value(contenu)?)?;
//                 (commande_inter_millegrille.contenu, Some(commande_inter_millegrille.origine), Some(commande_inter_millegrille.dechiffrage))
//             },
//             _ => {
//                 let value_ordered: Map<String, Value> = MessageMilleGrille::serialiser_contenu(contenu)?;
//                 let value_serialisee = serde_json::to_string(&value_ordered)?;
//                 (value_serialisee, None, None)
//             }
//         };
//
//         let action_str = match action { Some(inner) => Some(inner.as_ref().to_string()), None => None};
//         let domaine_str = match domaine { Some(inner) => Some(inner.as_ref().to_string()), None => None};
//         let partition_str = match partition { Some(inner) => Some(inner.as_ref().to_string()), None => None};
//         let user_id_str = match user_id { Some(inner) => Some(inner.as_ref().to_string()), None => None};
//
//         let routage_message = match &kind {
//             MessageKind::Requete | MessageKind::Commande | MessageKind::Transaction | MessageKind::Evenement | MessageKind::CommandeInterMillegrille => {
//                 Some(RoutageMessage { action: action_str, domaine: domaine_str, partition: partition_str, user_id: user_id_str })
//             },
//             _ => None
//         };
//
//         // Hacher le message pour obtenir le id
//         let (id_message, pubkey, routage, estampille, origine, dechiffrage) = {
//             let enveloppe_message = EnveloppeHachageMessage::new(
//                 enveloppe_privee.enveloppe.as_ref(), kind.clone(), value_serialisee.as_str(), routage_message,
//                 None, origine, dechiffrage)?;
//             debug!("message a hacher {:?}", enveloppe_message);
//             let id_message = enveloppe_message.hacher()?;
//             debug!("ID message (hachage) : {}", id_message);
//             (id_message, enveloppe_message.pubkey, enveloppe_message.routage, enveloppe_message.estampille, enveloppe_message.origine, enveloppe_message.dechiffrage)
//         };
//
//         // Signer le id
//         let id_message_bytes = hex::decode(&id_message)?;
//         let signature = signer_message(enveloppe_privee.cle_privee(), &id_message_bytes[..])?;
//         debug!("Signature message {}", signature);
//
//         // let entete = MessageMilleGrille::creer_entete(
//         //     enveloppe_privee, None::<&str>, None::<&str>, None::<&str>, version, &value_ordered)?;
//
//         let pems: Vec<String> = {
//             let pem_vec = enveloppe_privee.enveloppe.chaine_fingerprint_pem()?;
//             let mut pem_str: Vec<String> = Vec::new();
//             for p in pem_vec.iter().map(|c| c.pem.as_str()) {
//                 pem_str.push(p.to_owned());
//             }
//             pem_str
//         };
//
//         // let message_ordered = MessageMilleGrille::preparer_message_ordered(entete, value)?;
//         // warn!("Ajouter CA ? {} : {:?}", ajouter_ca, enveloppe_privee.ca);
//         let millegrille = match ajouter_ca {
//             true => Some(enveloppe_privee.ca.clone()),
//             false => None
//         };
//
//         Ok(MessageMilleGrille {
//             id: id_message,
//             pubkey,
//             estampille,
//             kind: kind.into(),
//             contenu: value_serialisee,
//             routage,
//             pre_migration: None,
//             origine,
//             dechiffrage,
//             signature,
//             certificat: Some(pems),
//             millegrille,
//             attachements: None,
//             contenu_valide: Some((true, true)),
//         })
//     }
//
//     pub fn serialiser_contenu<S>(contenu: &S) -> Result<Map<String, Value>, Box<dyn std::error::Error>>
//     where
//         S: Serialize,
//     {
//         let ser_va1 = serde_json::to_value(contenu)?;
//         let map = match ser_va1.as_object() {
//             Some(inner) => inner.to_owned(),
//             None => Err(format!("serialiser_contenu Contenu n'est pas un object (Map) : {:?}", ser_va1))?
//         };
//         let contenu = preparer_btree_recursif(map)?;
//         Ok(contenu)
//     }
//
//     /// Sert a retirer les certificats pour serialisation (e.g. backup, transaction Mongo, etc)
//     pub fn retirer_certificats(&mut self) { self.certificat = None; self.millegrille = None; }
//
//     pub fn retirer_attachments(&mut self) { self.attachements = None; }
//
//     /// Mapper le contenu ou un champ (1er niveau) du contenu vers un objet Deserialize
//     pub fn map_contenu<C>(&self) -> Result<C, crate::error::Error>
//         where C: DeserializeOwned
//     {
//         let value = serde_json::from_str(self.contenu.as_str())?;
//         let deser: C = serde_json::from_value(value)?;
//         Ok(deser)
//     }
//
//     pub fn map_to_bson(&self) -> Result<Document, crate::error::Error> {
//         map_msg_to_bson(self)
//     }
//
//     /// Verifie le hachage et la signature
//     /// :return: True si hachage et signature valides
//     pub fn verifier_contenu(&mut self) -> Result<(bool, bool), crate::error::Error> {
//         if let Some(inner) = self.contenu_valide {
//             return Ok(inner);  // Deja verifie
//         }
//
//         // Hachage du message (id)
//         let id_message = hex::decode(self.id.as_str())?;
//
//         // Verifier signature
//         let signature_valide = {
//             let signature = hex::decode(self.signature.as_str())?;
//             let pubkey = hex::decode(self.pubkey.as_str())?;
//             let cle_ed25519_publique = PKey::public_key_from_raw_bytes(
//                 &pubkey[..], Id::ED25519)?;
//             let mut verifier = Verifier::new_without_digest(&cle_ed25519_publique)?;
//             let signature_valide = verifier.verify_oneshot(&signature[..], &id_message[..])?;
//             debug!("Validite signature message : {}", signature_valide);
//             signature_valide
//         };
//
//         // Verifier hachage
//         debug!("Verifier hachage");
//         let message_enveloppe = EnveloppeHachageMessage {
//             pubkey: self.pubkey.clone(),
//             estampille: self.estampille.clone(),
//             kind: self.kind.clone(),
//             contenu: self.contenu.as_str(),
//             routage: self.routage.clone(),
//             pre_migration: self.pre_migration.clone(),
//             origine: self.origine.clone(),
//             dechiffrage: self.dechiffrage.clone()
//         };
//         let hachage_calcule = message_enveloppe.hacher()?;
//         let hachage_valide = hachage_calcule == self.id;
//         debug!("Validite hachage contenu message {}", hachage_valide);
//
//         self.contenu_valide = Some((signature_valide, hachage_valide));  // Conserver pour reference future
//
//         Ok((signature_valide, hachage_valide))
//     }
//
//     pub fn verifier_hachage(&mut self) -> Result<bool, crate::error::Error> {
//         Ok(self.verifier_contenu()?.1)
//     }
//
//     pub fn ajouter_attachement<S,V>(&mut self, key: S, value: V)
//         where S: Into<String>, V: Into<Value>
//     {
//         let key = key.into();
//         let value = value.into();
//
//         match &mut self.attachements {
//             Some(inner) => {
//                 inner.insert(key, value);
//             },
//             None => {
//                 let mut attachements = Map::new();
//                 attachements.insert(key, value);
//                 self.attachements = Some(attachements);
//             }
//         }
//     }
// }

pub fn preparer_btree_recursif(contenu: Map<String, Value>) -> Result<Map<String, Value>, crate::error::Error> {
    let iter: serde_json::map::IntoIter = contenu.into_iter();
    preparer_btree_recursif_into_iter(iter)
}

/// Preparer recursivement le contenu en triant les cles.
fn preparer_btree_recursif_into_iter(mut iter: serde_json::map::IntoIter) -> Result<Map<String, Value>, crate::error::Error> {
    let mut ordered: BTreeMap<String, Value> = BTreeMap::new();

    // Copier dans une BTreeMap (via trier les keys)
    // let mut iter: serde_json::map::IntoIter = contenu.into_iter();
    while let Some((k, v)) = iter.next() {
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

pub fn map_valeur_recursif(v: Value) -> Result<Value, crate::error::Error> {
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
            // Return entiers immediatement
            if o.is_i64() || o.is_u64() { Value::Number(o) }
            else {
                debug!("Number pas int/uint : {:?}", o);
                // Correctif pour 0.0
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
                                    // partie fractionnaire presente. Note : parfois f32 match javascript
                                    false => Value::Number(o),
                                }
                            },
                            None => Value::Number(o)
                        }
                    },
                    false => Value::Number(o)
                }
            }
        },
        Value::String(o) => Value::String(o),
        Value::Null => Value::Null,
    };

    Ok(res)
}


// #[derive(Clone, Debug)]
// pub struct MessageSerialise {
//     //entete: Entete,
//     message: String,
//     pub parsed: MessageMilleGrille,
//     pub certificat: Option<Arc<EnveloppeCertificat>>,
//     pub millegrille: Option<Arc<EnveloppeCertificat>>,
// }

// impl TryFrom<&str> for MessageSerialise {
//     type Error = String;
//     fn try_from(value: &str) -> Result<Self, Self::Error> {
//
//         let msg_parsed: MessageMilleGrille = match serde_json::from_str(value) {
//             Ok(m) => m,
//             Err(e) => Err(format!("MessageSerialise.TryFrom Erreur from_str : {:?}", e))?
//         };
//
//         Ok(Self {
//             message: value.to_owned(),
//             // entete: msg_parsed.entete.clone(),
//             parsed: msg_parsed,
//             certificat: Default::default(),
//             millegrille: Default::default(),
//         })
//     }
// }

// impl TryFrom<String> for MessageSerialise {
//     type Error = String;
//     fn try_from(value: String) -> Result<Self, Self::Error> {
//         let msg_parsed: MessageMilleGrille = match serde_json::from_str(value.as_str()) {
//             Ok(m) => m,
//             Err(e) => Err(format!("MessageSerialise.TryFrom Erreur from_str : {:?}", e))?
//         };
//         Ok(Self {
//             message: value,
//             // entete: msg_parsed.entete.clone(),
//             parsed: msg_parsed,
//             certificat: None,
//             millegrille: None,
//         })
//     }
// }

// impl MessageSerialise {
//     pub fn from_parsed(msg: MessageMilleGrille) -> Result<Self, Box<dyn std::error::Error>> {
//         let msg_str = serde_json::to_string(&msg)?;
//         Ok(MessageSerialise {
//             // entete: msg.entete.clone(),
//             message: msg_str,
//             parsed: msg,
//             certificat: None,
//             millegrille: None,
//         })
//     }
//
//     pub fn from_str(msg: &str) -> Result<Self, Box<dyn std::error::Error>> {
//         Ok(MessageSerialise::try_from(msg)?)
//     }
//
//     pub fn from_string(msg: String) -> Result<Self, Box<dyn std::error::Error>> {
//         Ok(MessageSerialise::try_from(msg)?)
//     }
//
//     pub fn from_serializable<T>(value: T) -> Result<MessageSerialise, crate::error::Error>
//     where
//         T: Serialize,
//     {
//         let ser_value = serde_json::to_value(value)?;
//         let msg_parsed: MessageMilleGrille = serde_json::from_value(ser_value)?;
//         let msg = serde_json::to_string(&msg_parsed)?;
//         // debug!("Comparaison message original:\n{}\nParsed\n{:?}", msg, msg_parsed);
//         Ok(MessageSerialise {
//             message: msg,
//             // entete: msg_parsed.entete.clone(),
//             parsed: msg_parsed,
//             certificat: None,
//             millegrille: None,
//         })
//     }
//
//     pub fn set_certificat(&mut self, certificat: Arc<EnveloppeCertificat>) {
//         self.certificat = Some(certificat);
//     }
//
//     pub fn set_millegrille(&mut self, certificat: Arc<EnveloppeCertificat>) {
//         self.millegrille = Some(certificat);
//     }
//
//     // pub fn get_entete(&self) -> &Entete {
//     //     &self.entete
//     // }
//
//     pub fn get_str(&self) -> &str {
//         self.message.as_str()
//     }
//
//     pub fn get_msg(&self) -> &MessageMilleGrille {
//         &self.parsed
//     }
//
//     pub async fn valider<V>(&mut self, validateur: &V, options: Option<&ValidationOptions<'_>>) -> Result<ResultatValidation, crate::error::Error>
//     where
//         V: ValidateurX509,
//     {
//         match &self.certificat {
//             Some(_) => {
//                 // Ok, on a un certificat. Valider la signature.
//                 verifier_message(self, validateur, options)
//             },
//             None => {
//                 // Tenter de charger le certificat
//                 // let enveloppe : Option<Arc<EnveloppeCertificat>> = self.charger_certificat(validateur).await?;
//                 match self.charger_certificat(validateur).await? {
//                     Some(e) => {
//                         self.certificat = Some(e);
//                         verifier_message(self, validateur, options)
//                     },
//                     None => Err("Certificat manquant")?
//                 }
//             },
//         }
//     }
//
//     async fn charger_certificat(&mut self, validateur: &dyn ValidateurX509) -> Result<Option<Arc<EnveloppeCertificat>>, crate::error::Error> {
//         let fp_certificat = self.parsed.pubkey.as_str();
//
//         // Charger l'enveloppe du certificat de millegrille (CA)
//         //let ca : Option<Arc<EnveloppeCertificat>> =
//         match &self.parsed.millegrille {
//             Some(c) => {
//                 let vec_pems = vec![c.clone()];
//                 debug!("charger_certificat Certificat millegrille {:?}", vec_pems);
//                 let enveloppe = validateur.charger_enveloppe(&vec_pems, None, None).await?;
//                 self.millegrille = Some(enveloppe.clone());
//                 // Some(enveloppe)
//             },
//             None => ()  //None
//         };
//
//         // Charger l'enveloppe du certificat de signature du message
//         let enveloppe : Option<Arc<EnveloppeCertificat>> = match &self.parsed.certificat {
//             Some(c) => {
//                 let ca_pem = match &self.parsed.millegrille {
//                     Some(c) => {
//                         debug!("charger_certificat Utiliser CA {}", c);
//                         Some(c.as_str())
//                     },
//                     None => None
//                 };
//                 let enveloppe = validateur.charger_enveloppe(c, Some(fp_certificat), ca_pem).await?;
//                 Some(enveloppe)
//             },
//             None => {
//                 validateur.get_certificat(fp_certificat).await
//             }
//         };
//
//         self.certificat = enveloppe.clone();
//
//         Ok(enveloppe)
//     }
//
//     /// Sert a extraire le message pour une restauration - deplace (move) le message.
//     pub fn preparation_restaurer(self) -> MessageMilleGrille {
//         let mut message = self.parsed;
//         todo!("fix me")
//     }
//
// }

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DechiffrageInterMillegrille {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub cle_id: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub cles: Option<BTreeMap<String, String>>,
//     pub format: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub hachage: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub header: Option<String>,
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct MessageInterMillegrille {
//     pub contenu: String,  // Contenu compresse/chiffre et encode en multibase
//     pub origine: String,
//     pub dechiffrage: DechiffrageInterMillegrilleOwned,
// }
//
// impl MessageInterMillegrille {
//     pub fn new<M,S>(middleware: &M, contenu: S, certificats_demandeur: Option<Vec<&EnveloppeCertificat>>)
//         -> Result<Self, crate::error::Error>
//         where M: FormatteurMessage + ChiffrageFactoryTrait, S: Serialize
//     {
//         let (data_chiffre, keys) = chiffrer_data_get_keys(middleware, contenu)?;
//         let idmg = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;
//
//         let mut dechiffrage = keys.get_dechiffrage(None)?;
//         match certificats_demandeur {
//             Some(certificats) => {
//                 let mut cles_rechiffrees = BTreeMap::new();
//                 for cert in certificats {
//                     let cle_rechiffree = keys.rechiffrer(cert)?;
//                     cles_rechiffrees.insert(cert.fingerprint()?, cle_rechiffree);
//                 }
//                 // Remplacer cles rechiffrage
//                 dechiffrage.cles = Some(cles_rechiffrees);
//             },
//             None => ()
//         }
//
//         Ok(Self { contenu: data_chiffre.data_chiffre, origine: idmg, dechiffrage })
//     }
//
//     pub fn dechiffrer<M>(&self, middleware: &M)  -> Result<DataDechiffre, crate::error::Error>
//         where M: GenerateurMessages + CleChiffrageHandler
//     {
//         let enveloppe_privee = middleware.get_enveloppe_signature();
//         let fingerprint_local = enveloppe_privee.fingerprint()?;
//         let cle_secrete = match self.dechiffrage.cles.as_ref() {
//             Some(inner) => match inner.get(fingerprint_local.as_str()) {
//                 Some(inner) => {
//                     // Cle chiffree, on dechiffre
//                     let cle_bytes = multibase::decode(inner)?;
//                     let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], &enveloppe_privee.cle_privee)?;
//                     cle_secrete
//                 },
//                 None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, dechiffrage absent"))?
//             },
//             None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, dechiffrage absent"))?
//         };
//
//         self.dechiffrer_avec_cle(middleware, cle_secrete)
//     }
//
//     pub fn dechiffrer_avec_cle<M>(&self, middleware: &M, cle_secrete: CleSecrete)  -> Result<DataDechiffre, crate::error::Error>
//         where M: GenerateurMessages + CleChiffrageHandler
//     {
//         let header = match self.dechiffrage.header.as_ref() {
//             Some(inner) => inner.as_str(),
//             None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, header absent"))?
//         };
//
//         // Dechiffrer le contenu
//         let data_chiffre = DataChiffre {
//             ref_hachage_bytes: None,
//             data_chiffre: format!("m{}", self.contenu),
//             format: FormatChiffrage::mgs4,
//             header: Some(header.to_owned()),
//             tag: None,
//         };
//         debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Data chiffre contenu : {:?}", data_chiffre);
//
//         let cle_dechiffre = CleDechiffree {
//             cle: "m".to_string(),
//             cle_secrete,
//             domaine: "MaitreDesCles".to_string(),
//             format: "mgs4".to_string(),
//             hachage_bytes: "".to_string(),
//             identificateurs_document: None,
//             iv: None,
//             tag: None,
//             header: Some(header.to_owned()),
//             // signature_identite: "".to_string(),
//         };
//
//         debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Dechiffrer data avec cle dechiffree");
//         let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
//         debug!("formatteur_messages.MessageInterMillegrille.dechiffrer.MessageReponseChiffree.dechiffrerfrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
//         // debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));
//
//         Ok(data_dechiffre)
//     }
// }

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct MessageReponseChiffree {
//     pub contenu: String,  // Contenu compresse/chiffre et encode en multibase
//     pub dechiffrage: DechiffrageInterMillegrille,
// }
//
// impl TryFrom<MessageMilleGrille> for MessageReponseChiffree {
//     type Error = String;
//
//     fn try_from(mut value: MessageMilleGrille) -> Result<Self, Self::Error> {
//         let dechiffrage = match value.dechiffrage.take() {
//             Some(inner) => inner,
//             None => Err(format!("commande_rechiffrer_batch Information de dechiffrage absente"))?
//         };
//         Ok(Self {
//             contenu: value.contenu,
//             dechiffrage,
//         })
//     }
// }
//
// impl MessageReponseChiffree {
//     pub fn new<M,S>(middleware: &M, contenu: S, certificat_demandeur: &EnveloppeCertificat)
//         -> Result<Self, crate::error::Error>
//         where M: ChiffrageFactoryTrait, S: Serialize
//     {
//         let (data_chiffre, dechiffrage) = chiffrer_data(middleware, contenu)?;
//         Ok(Self { contenu: data_chiffre.data_chiffre, dechiffrage })
//     }
//
//     pub fn dechiffrer<M>(&self, middleware: &M)  -> Result<DataDechiffre, crate::error::Error>
//         where M: GenerateurMessages + CleChiffrageHandler
//     {
//         let enveloppe_privee = middleware.get_enveloppe_signature();
//         let fingerprint_local = enveloppe_privee.fingerprint().as_str();
//         let header = match self.dechiffrage.header.as_ref() {
//             Some(inner) => inner.as_str(),
//             None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, header absent"))?
//         };
//
//         let (header, cle_secrete) = match self.dechiffrage.cles.as_ref() {
//             Some(inner) => match inner.get(fingerprint_local) {
//                 Some(inner) => {
//                     // Cle chiffree, on dechiffre
//                     let cle_bytes = multibase::decode(inner)?;
//                     let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], enveloppe_privee.cle_privee())?;
//                     (header, cle_secrete)
//                 },
//                 None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
//             },
//             None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
//         };
//
//         // Dechiffrer le contenu
//         let data_chiffre = DataChiffre {
//             ref_hachage_bytes: None,
//             data_chiffre: format!("m{}", self.contenu),
//             format: FormatChiffrage::mgs4,
//             header: Some(header.to_owned()),
//             tag: None,
//         };
//         debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data chiffre contenu : {:?}", data_chiffre);
//
//         let cle_dechiffre = CleDechiffree {
//             cle: "m".to_string(),
//             cle_secrete,
//             domaine: "MaitreDesCles".to_string(),
//             format: "mgs4".to_string(),
//             hachage_bytes: "".to_string(),
//             identificateurs_document: None,
//             iv: None,
//             tag: None,
//             header: Some(header.to_owned()),
//             // signature_identite: "".to_string(),
//         };
//
//         debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Dechiffrer data avec cle dechiffree");
//         let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
//         debug!("formatteur_messages.MessageReponseChiffree.dechiffrer.MessageReponseChiffree.dechiffrerfrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
//         // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));
//
//         Ok(data_dechiffre)
//     }
// }
