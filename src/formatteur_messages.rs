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

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille, ValidateurX509, VerificateurPermissions};
use crate::hachages::{hacher_bytes, hacher_message};
use crate::middleware::{ChiffrageFactoryTrait, map_msg_to_bson};
use crate::signatures::signer_message;
use crate::verificateur::{ResultatValidation, ValidationOptions, verifier_message};
use crate::bson::{Document, Bson};
use std::convert::{TryFrom, TryInto};
use multibase::Base;
use multihash::Code;
use openssl::sign::Verifier;
use crate::chiffrage::{ChiffrageFactory, chiffrer_data, chiffrer_data_get_keys, CipherMgs, CleChiffrageHandler, FormatChiffrage, MgsCipherKeys};
use crate::chiffrage_cle::CleDechiffree;
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use crate::common_messages::{DataChiffre, DataDechiffre};
use crate::constantes::MessageKind;
use crate::constantes::MessageKind::ReponseChiffree;
use crate::dechiffrage::dechiffrer_data;
use crate::generateur_messages::GenerateurMessages;
use crate::mongo_dao::convertir_to_bson;

pub trait FormatteurMessage {
    /// Retourne l'enveloppe privee utilisee pour signer le message
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee>;

    /// Permet de modifier l'enveloppe utilisee pour la signature de messages
    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>);

    /// Implementation de formattage et signature d'un message de MilleGrille
    fn formatter_message<S,T>(
        &self,
        kind: MessageKind,
        contenu: &S,
        domaine: Option<T>,
        action: Option<T>,
        partition: Option<T>,
        version: Option<i32>,
        ajouter_ca: bool
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        S: Serialize,
        T: AsRef<str>
    {
        let enveloppe = self.get_enveloppe_signature();
        MessageMilleGrille::new_signer(
            enveloppe.as_ref(), kind, contenu,
            domaine, action, partition, version, ajouter_ca)
    }

    fn formatter_reponse<S>(
        &self,
        contenu: S,
        version: Option<i32>
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        S: Serialize,
    {
        let enveloppe = self.get_enveloppe_signature();
        MessageMilleGrille::new_signer(
            enveloppe.as_ref(), MessageKind::Reponse, &contenu,
            None::<&str>, None::<&str>, None::<&str>, version, false)
    }

    /// Repondre en chiffrant le contenu avec le certificat du demandeur
    fn formatter_reponse_chiffree<M,S>(
        &self,
        middleware: &M,
        contenu: S,
        certificat_demandeur: &EnveloppeCertificat
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        M: ChiffrageFactoryTrait,
        S: Serialize,
    {
        let enveloppe = self.get_enveloppe_signature();
        let reponse_chiffree = MessageReponseChiffree::new(
            middleware, contenu, certificat_demandeur)?;
        MessageMilleGrille::new_signer(
            enveloppe.as_ref(), MessageKind::ReponseChiffree, &reponse_chiffree,
            None::<&str>, None::<&str>, None::<&str>, None::<i32>, false)
    }

    fn formatter_inter_millegrille<M,S>(
        &self,
        middleware: &M,
        contenu: S,
        certificat_demandeur: &EnveloppeCertificat
    ) -> Result<MessageMilleGrille, Box<dyn Error>>
    where
        M: ChiffrageFactoryTrait + FormatteurMessage,
        S: Serialize,
    {
        let enveloppe = self.get_enveloppe_signature();
        let reponse_chiffree = MessageInterMillegrille::new(
            middleware, contenu, Some(vec![certificat_demandeur]))?;
        MessageMilleGrille::new_signer(
            enveloppe.as_ref(), MessageKind::ReponseChiffree, &reponse_chiffree,
            None::<&str>, None::<&str>, None::<&str>, None::<i32>, false)
    }

    // fn signer_message(
    //     &self,
    //     kind: MessageKind,
    //     message: &mut MessageMilleGrille,
    //     domaine: Option<&str>,
    //     action: Option<&str>,
    //     partition: Option<&str>,
    //     version: Option<i32>
    // ) -> Result<(), Box<dyn Error>> {
    //     if message.signature.is_some() {
    //         Err(format!("Message {} est deja signe", message.entete.uuid_transaction))?
    //     }
    //     message.signer(self.get_enveloppe_signature().as_ref(),
    //                    kind, domaine, action, partition, version)
    // }

    fn confirmation(&self, ok: bool, message: Option<&str>) -> Result<MessageMilleGrille, Box<dyn Error>> {
        let reponse = json!({"ok": ok, "message": message});
        self.formatter_message(MessageKind::Reponse, &reponse,
                               None::<&str>, None, None, None,
                               false)
    }

    fn reponse_ok(&self) -> Result<Option<MessageMilleGrille>, String> {
        let reponse = json!({"ok": true});
        match self.formatter_reponse(&reponse,None) {
            Ok(m) => Ok(Some(m)),
            Err(e) => Err(format!("Erreur preparation reponse_ok : {:?}", e))?
        }
    }

}

// #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// /// Entete de messages de MilleGrille (champ "en-tete").
// pub struct Entete {
//     // Note : s'assurer de conserver les champs en ordre alphabetique
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub action: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub domaine: Option<String>,
//     pub estampille: DateEpochSeconds,
//     pub fingerprint_certificat: String,
//     pub hachage_contenu: String,
//     pub idmg: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub partition: Option<String>,
//     pub uuid_transaction: String,
//     pub version: i32,
// }

// impl Entete {
//     pub fn builder(fingerprint_certificat: &str, hachage_contenu: &str, idmg: &str) -> EnteteBuilder {
//         EnteteBuilder::new(fingerprint_certificat.to_owned(), hachage_contenu.to_owned(), idmg.to_owned())
//     }
// }

// impl TryInto<Document> for Entete {
//     type Error = String;
//
//     fn try_into(self) -> Result<Document, Self::Error> {
//         match convertir_to_bson(self) {
//             Ok(e) => Ok(e),
//             Err(e) => Err(format!("transaction_catalogue_horaire Erreur conversion entete vers bson : {:?}", e))?
//         }
//     }
// }

// /// Builder pour les entetes de messages.
// pub struct EnteteBuilder {
//     action: Option<String>,
//     domaine: Option<String>,
//     estampille: DateEpochSeconds,
//     fingerprint_certificat: String,
//     hachage_contenu: String,
//     idmg: String,
//     partition: Option<String>,
//     uuid_transaction: String,
//     version: i32,
// }

// impl EnteteBuilder {
//     pub fn new(fingerprint_certificat: String, hachage_contenu: String, idmg: String) -> EnteteBuilder {
//         EnteteBuilder {
//             action: None,
//             domaine: None,
//             estampille: DateEpochSeconds::now(),
//             fingerprint_certificat,
//             hachage_contenu,
//             idmg,
//             partition: None,
//             uuid_transaction: Uuid::new_v4().to_string(),
//             version: 1,
//         }
//     }
//
//     pub fn action(mut self, action: String) -> EnteteBuilder {
//         self.action = Some(action);
//         self
//     }
//
//     pub fn domaine(mut self, domaine: String) -> EnteteBuilder {
//         self.domaine = Some(domaine);
//         self
//     }
//
//     pub fn estampille(mut self, estampille: DateEpochSeconds) -> EnteteBuilder {
//         self.estampille = estampille;
//         self
//     }
//
//     pub fn partition(mut self, partition: String) -> EnteteBuilder {
//         self.partition = Some(partition);
//         self
//     }
//
//     pub fn version(mut self, version: i32) -> EnteteBuilder {
//         self.version = version;
//         self
//     }
//
//     pub fn build(self) -> Entete {
//         Entete {
//             action: self.action,
//             domaine: self.domaine,
//             estampille: self.estampille,
//             fingerprint_certificat: self.fingerprint_certificat,
//             hachage_contenu: self.hachage_contenu,
//             idmg: self.idmg,
//             partition: self.partition,
//             uuid_transaction: self.uuid_transaction,
//             version: self.version,
//         }
//     }
// }

/// Identificateurs d'un message MilleGrille (sans contenu/signature)
#[derive(Clone, Debug, Deserialize)]
pub struct MessageMilleGrilleIdentificateurs {
    pub id: String,
    pub pubkey: String,
    pub estampille: DateEpochSeconds,
    pub kind: u16,
    pub routage: Option<RoutageMessage>,
    #[serde(rename="pre-migration")]
    pub pre_migration: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Structure a utiliser pour creer un nouveau message
/// Utiliser methode MessageMilleGrille::new_signer().
pub struct MessageMilleGrille {
    /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
    pub id: String,

    /// Cle publique du certificat utilise pour la signature
    pub pubkey: String,

    /// Date de creation du message
    pub estampille: DateEpochSeconds,

    /// Kind du message, correspond a enum MessageKind
    pub kind: u16,

    /// Contenu du message en format json-string
    pub contenu: String,

    /// Information de routage de message (optionnel, depend du kind)
    pub routage: Option<RoutageMessage>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<HashMap<String, Value>>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<String>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: String,

    /// Chaine de certificats en format PEM.
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<String>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<String>,

    /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachements: Option<Map<String, Value>>,

    #[serde(skip)]
    contenu_valide: Option<(bool, bool)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutageMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domaine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnveloppeHachageMessage<'a> {
    pub pubkey: String,
    pub estampille: DateEpochSeconds,
    pub kind: u16,
    pub contenu: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessage>,
    #[serde(rename="pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille>
}

impl<'a> EnveloppeHachageMessage<'a> {
    pub fn new(certificat: &EnveloppeCertificat, kind: MessageKind, contenu: &'a str,
               routage: Option<RoutageMessage>, pre_migration: Option<HashMap<String, Value>>,
               origine: Option<String>, dechiffrage: Option<DechiffrageInterMillegrille>
    ) -> Result<Self, Box<dyn Error>> {
        let pubkey = certificat.publickey_bytes_encoding(Base::Base16Lower, true)?;
        let estampille = DateEpochSeconds::now();
        Ok(Self {
            pubkey,
            estampille,
            kind: kind.into(),
            contenu,
            routage,
            pre_migration,
            origine,
            dechiffrage
        })
    }

    pub fn hacher(&self) -> Result<String, Box<dyn Error>> {

        let message_value = match &self.kind {
            0 | 4 | 6 => {
                json!([
                    &self.pubkey,
                    &self.estampille,
                    &self.kind,
                    self.contenu,
                ])
            },
            1 | 2 | 3 | 5 => {
                match self.routage.as_ref() {
                    Some(routage) => {
                        json!([
                            &self.pubkey,
                            &self.estampille,
                            &self.kind,
                            self.contenu,
                            routage,
                        ])
                    },
                    None => Err(format!("Message format {} sans routage", self.kind))?
                }
            },
            7 => {
                match self.routage.as_ref() {
                    Some(routage) => {
                        match self.pre_migration.as_ref() {
                            Some(pre_migration) => {
                                json!([
                                    &self.pubkey,
                                    &self.estampille,
                                    &self.kind,
                                    self.contenu,
                                    routage,
                                    pre_migration,
                                ])
                            },
                            None => Err(format!("Message format {} sans pre_migration", self.kind))?
                        }
                    },
                    None => Err(format!("Message format {} sans routage", self.kind))?
                }
            },
            8 => {
                match self.routage.as_ref() {
                    Some(routage) => {
                        match self.origine.as_ref() {
                            Some(origine) => {
                                match self.dechiffrage.as_ref() {
                                    Some(dechiffrage) => {
                                        json!([
                                            &self.pubkey,
                                            &self.estampille,
                                            &self.kind,
                                            self.contenu,
                                            routage,
                                            origine,
                                            dechiffrage
                                        ])
                                    },
                                    None => Err(format!("Message format {} sans dechiffrage", self.kind))?
                                }
                            },
                            None => Err(format!("Message format {} sans origine", self.kind))?
                        }
                    },
                    None => Err(format!("Message format {} sans routage", self.kind))?
                }
            },
            _ => Err(format!("Message format {} non supporte", self.kind))?
        };

        let value_str = serde_json::to_string(&message_value)?;
        debug!("Message string a hacher : {}", value_str);
        let value_bytes = value_str.as_bytes();
        let message_hache = hacher_bytes(value_bytes, Some(Code::Blake2s256), Some(Base::Base16Lower));
        // Retirer encodage multibase (1 char) et multihash (4 bytes), 9 chars en tout
        let message_hache = &message_hache[9..];

        Ok(message_hache.to_string())
    }
}

impl MessageMilleGrille {

    /// Creer un nouveau message et inserer les valeurs a la main.
    // pub fn new() -> Self {
    //     const PLACEHOLDER: &str = "PLACEHOLDER";
    //     MessageMilleGrille {
    //         entete: Entete::builder(PLACEHOLDER, PLACEHOLDER, PLACEHOLDER).build(),
    //         certificat: None,
    //         millegrille: None,
    //         signature: None,
    //         contenu: Map::new(),
    //         contenu_traite: false,
    //     }
    // }

    pub fn new_signer<S, T, U, V>(
        enveloppe_privee: &EnveloppePrivee,
        kind: MessageKind,
        contenu: &S,
        domaine: Option<T>,
        action: Option<U>,
        partition: Option<V>,
        version: Option<i32>,
        ajouter_ca: bool
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        S: Serialize,
        T: AsRef<str>,
        U: AsRef<str>,
        V: AsRef<str>,
    {
        // Serialiser le contenu
        let (value_serialisee, origine, dechiffrage) = match kind {
            MessageKind::ReponseChiffree => {
                let reponse_chiffree: MessageReponseChiffree = serde_json::from_value(serde_json::to_value(contenu)?)?;
                (reponse_chiffree.contenu, None, Some(reponse_chiffree.dechiffrage))
            },
            MessageKind::CommandeInterMillegrille => {
                let commande_inter_millegrille: MessageInterMillegrille = serde_json::from_value(serde_json::to_value(contenu)?)?;
                (commande_inter_millegrille.contenu, Some(commande_inter_millegrille.origine), Some(commande_inter_millegrille.dechiffrage))
            },
            _ => {
                let value_ordered: Map<String, Value> = MessageMilleGrille::serialiser_contenu(contenu)?;
                let value_serialisee = serde_json::to_string(&value_ordered)?;
                (value_serialisee, None, None)
            }
        };

        let action_str = match action { Some(inner) => Some(inner.as_ref().to_string()), None => None};
        let domaine_str = match domaine { Some(inner) => Some(inner.as_ref().to_string()), None => None};
        let partition_str = match partition { Some(inner) => Some(inner.as_ref().to_string()), None => None};

        let routage_message = match &kind {
            MessageKind::Requete | MessageKind::Commande | MessageKind::Transaction | MessageKind::Evenement | MessageKind::CommandeInterMillegrille => {
                Some(RoutageMessage { action: action_str, domaine: domaine_str, partition: partition_str })
            },
            _ => None
        };

        // Hacher le message pour obtenir le id
        let (id_message, pubkey, routage, estampille, origine, dechiffrage) = {
            let enveloppe_message = EnveloppeHachageMessage::new(
                enveloppe_privee.enveloppe.as_ref(), kind.clone(), value_serialisee.as_str(), routage_message,
                None, origine, dechiffrage)?;
            debug!("message a hacher {:?}", enveloppe_message);
            let id_message = enveloppe_message.hacher()?;
            debug!("ID message (hachage) : {}", id_message);
            (id_message, enveloppe_message.pubkey, enveloppe_message.routage, enveloppe_message.estampille, enveloppe_message.origine, enveloppe_message.dechiffrage)
        };

        // Signer le id
        let id_message_bytes = hex::decode(&id_message)?;
        let signature = signer_message(enveloppe_privee.cle_privee(), &id_message_bytes[..])?;
        debug!("Signature message {}", signature);

        // let entete = MessageMilleGrille::creer_entete(
        //     enveloppe_privee, None::<&str>, None::<&str>, None::<&str>, version, &value_ordered)?;

        let pems: Vec<String> = {
            let pem_vec = enveloppe_privee.enveloppe.get_pem_vec();
            let mut pem_str: Vec<String> = Vec::new();
            for p in pem_vec.iter().map(|c| c.pem.as_str()) {
                pem_str.push(p.to_owned());
            }
            pem_str
        };

        // let message_ordered = MessageMilleGrille::preparer_message_ordered(entete, value)?;
        // warn!("Ajouter CA ? {} : {:?}", ajouter_ca, enveloppe_privee.ca);
        let millegrille = match ajouter_ca {
            true => Some(enveloppe_privee.ca.clone()),
            false => None
        };

        Ok(MessageMilleGrille {
            id: id_message,
            pubkey,
            estampille,
            kind: kind.into(),
            contenu: value_serialisee,
            routage,
            pre_migration: None,
            origine,
            dechiffrage,
            signature,
            certificat: Some(pems),
            millegrille,
            attachements: None,
            contenu_valide: Some((true, true)),
        })
    }

    // /// Va creer une nouvelle entete, calculer le hachag
    // /// Note : value doit etre deja trie (BTreeMap recursif)
    // fn creer_entete<S, T, U>(
    //     enveloppe_privee: &EnveloppePrivee,
    //     domaine: Option<S>,
    //     action: Option<T>,
    //     partition: Option<U>,
    //     version: Option<i32>,
    //     value: &Map<String, Value>
    // )
    //     -> Result<Entete, Box<dyn Error>>
    //     where S: AsRef<str>, T: AsRef<str>, U: AsRef<str>
    // {
    //
    //     // Calculer le hachage du contenu
    //     let message_string = serde_json::to_string(&value)?;
    //     let hachage = hacher_message(message_string.as_str());
    //
    //     // Generer l'entete
    //     let mut entete_builder = Entete::builder(
    //         enveloppe_privee.fingerprint(),
    //         &hachage,
    //         enveloppe_privee.idmg().expect("idmg").as_str()
    //     )
    //         .estampille(DateEpochSeconds::now())
    //         .version(1);
    //
    //     match domaine {
    //         Some(d) => entete_builder = entete_builder.domaine(d.as_ref().to_owned()),
    //         None => (),
    //     }
    //
    //     match action {
    //         Some(a) => entete_builder = entete_builder.action(a.as_ref().to_owned()),
    //         None => (),
    //     }
    //
    //     match partition {
    //         Some(p) => entete_builder = entete_builder.partition(p.as_ref().to_owned()),
    //         None => (),
    //     }
    //
    //     match version {
    //         Some(v) => entete_builder = entete_builder.version(v),
    //         None => (),
    //     }
    //
    //     let entete = entete_builder.build();
    //     Ok(entete)
    // }

    // pub fn set_value(&mut self, name: &str, value: Value) {
    //     if self.signature.is_some() { panic!("set_value sur message signe") }
    //     self.contenu.insert(name.to_owned(), value);
    // }
    //
    // pub fn set_int(&mut self, name: &str, value: i64) {
    //     if self.signature.is_some() { panic!("set_int sur message signe") }
    //     self.contenu.insert(name.to_owned(), Value::from(value));
    // }
    //
    // pub fn set_float(&mut self, name: &str, value: f64) {
    //     if self.signature.is_some() { panic!("set_float sur message signe") }
    //     self.contenu.insert(name.to_owned(), Value::from(value));
    // }
    //
    // pub fn set_bool(&mut self, name: &str, value: bool) {
    //     if self.signature.is_some() { panic!("set_bool sur message signe") }
    //     self.contenu.insert(name.to_owned(), Value::from(value));
    // }

    // pub fn set_serializable<S>(&mut self, name: &str, value: &S) -> Result<(), Box<dyn Error>>
    // where
    //     S: Serialize,
    // {
    //     if self.signature.is_some() { panic!("set_serializable sur message signe") }
    //
    //     let val_ser = serde_json::to_value(value)?;
    //     self.contenu.insert(name.to_owned(), val_ser);
    //     Ok(())
    // }

    pub fn serialiser_contenu<S>(contenu: &S) -> Result<Map<String, Value>, Box<dyn std::error::Error>>
    where
        S: Serialize,
    {
        let map = serde_json::to_value(contenu).expect("value").as_object().expect("value map").to_owned();
        let contenu = preparer_btree_recursif(map)?;
        Ok(contenu)
    }

    // fn signer_message(&mut self, enveloppe_privee: &EnveloppePrivee) -> Result<(), Box<dyn std::error::Error>> {
    //     let message_string = self.preparer_pour_signature()?;
    //
    //     debug!("Message serialise avec entete : {}", message_string);
    //     let signature = signer_message(enveloppe_privee.cle_privee(), message_string.as_bytes())?;
    //
    //     self.signature = Some(signature);
    //
    //     Ok(())
    // }

    // fn preparer_pour_signature(&mut self) -> Result<String, Box<dyn Error>> {
    //     if !self.contenu_traite {
    //         self.traiter_contenu()?;
    //     }
    //
    //     // Creer une map avec l'entete (refs uniquements)
    //     let mut map_ordered: BTreeMap<&str, &Value> = BTreeMap::new();
    //
    //     // Copier references du reste du contenu (exclure champs _)
    //     for (k, v) in &self.contenu {
    //         if !k.starts_with("_") {
    //             map_ordered.insert(k.as_str(), v);
    //         }
    //     }
    //
    //     // Ajouter entete
    //     let entete_value = serde_json::to_value(&self.entete)?;
    //     map_ordered.insert("en-tete", &entete_value);
    //
    //     let message_string = serde_json::to_string(&map_ordered)?;
    //     Ok(message_string)
    // }

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

    // fn signer(
    //     &mut self,
    //     enveloppe_privee: &EnveloppePrivee,
    //     kind: MessageKind,
    //     domaine: Option<&str>,
    //     action: Option<&str>,
    //     partition: Option<&str>,
    //     version: Option<i32>
    // ) -> Result<(), Box<dyn std::error::Error>> {
    //
    //     if self.signature.is_some() {
    //         warn!("appel signer() sur message deja signe, on ignore");
    //         return Ok(())
    //     }
    //
    //     let entete = MessageMilleGrille::creer_entete(enveloppe_privee, domaine, action, partition, version, &self.contenu)?;
    //
    //     // Remplacer l'entete
    //     self.entete = entete;
    //     self.certificat = Some(enveloppe_privee.chaine_pem().to_owned());
    //     self.millegrille = None;
    //
    //     self.signer_message(enveloppe_privee)?;
    //
    //     Ok(())
    // }

    // fn traiter_contenu(&mut self) -> Result<(), Box<dyn Error>>{
    //     if ! self.contenu_traite {
    //         let mut contenu = Map::new();
    //         let contenu_ref = &mut self.contenu;
    //
    //         let keys: Vec<String> = contenu_ref.keys().map(|k| k.to_owned()).collect();
    //         for k in keys {
    //             if let Some(v) = contenu_ref.remove(k.as_str()) {
    //                 contenu.insert(k, v);
    //             }
    //         }
    //
    //         // let mut contenu_prev: serde_json::map::IntoIter = self.contenu.into_iter();
    //         // for ((k, v)) in self.contenu {
    //         //     contenu.insert(k, v);
    //         // }
    //         // while let Some((k, v)) = contenu_prev.next() {
    //         //     contenu.insert(k, v);
    //         // }
    //
    //         // let mut contenu = &self.contenu;
    //         // let contenu_prev: serde_json::map::IntoIter = contenu.into_iter();
    //         // self.contenu = MessageMilleGrille::preparer_btree_recursif_into_iter(contenu_prev)?;
    //         self.contenu = preparer_btree_recursif(contenu)?;
    //         self.contenu_traite = true;
    //     }
    //     Ok(())
    // }

    /// Sert a retirer les certificats pour serialisation (e.g. backup, transaction Mongo, etc)
    pub fn retirer_certificats(&mut self) { self.certificat = None; self.millegrille = None; }

    pub fn retirer_attachments(&mut self) { self.attachements = None; }

    /// Mapper le contenu ou un champ (1er niveau) du contenu vers un objet Deserialize
    pub fn map_contenu<C>(&self) -> Result<C, Box<dyn Error>>
        where C: DeserializeOwned
    {
        let value = serde_json::from_str(self.contenu.as_str())?;
        let deser: C = serde_json::from_value(value)?;
        Ok(deser)
    }

    pub fn map_to_bson(&self) -> Result<Document, Box<dyn Error>> {
        map_msg_to_bson(self)
    }

    /// Verifie le hachage et la signature
    /// :return: True si hachage et signature valides
    pub fn verifier_contenu(&mut self) -> Result<(bool, bool), Box<dyn Error>> {
        if let Some(inner) = self.contenu_valide {
            return Ok(inner);  // Deja verifie
        }

        // Hachage du message (id)
        let id_message = hex::decode(self.id.as_str())?;

        // Verifier signature
        let signature_valide = {
            let signature = hex::decode(self.signature.as_str())?;
            let pubkey = hex::decode(self.pubkey.as_str())?;
            let cle_ed25519_publique = PKey::public_key_from_raw_bytes(
                &pubkey[..], Id::ED25519)?;
            let mut verifier = Verifier::new_without_digest(&cle_ed25519_publique)?;
            let signature_valide = verifier.verify_oneshot(&signature[..], &id_message[..])?;
            debug!("Validite signature message : {}", signature_valide);
            signature_valide
        };

        // Verifier hachage
        debug!("Verifier hachage");
        let message_enveloppe = EnveloppeHachageMessage {
            pubkey: self.pubkey.clone(),
            estampille: self.estampille.clone(),
            kind: self.kind.clone(),
            contenu: self.contenu.as_str(),
            routage: self.routage.clone(),
            pre_migration: self.pre_migration.clone(),
            origine: self.origine.clone(),
            dechiffrage: self.dechiffrage.clone()
        };
        let hachage_calcule = message_enveloppe.hacher()?;
        let hachage_valide = hachage_calcule == self.id;
        debug!("Validite hachage contenu message {}", hachage_valide);

        self.contenu_valide = Some((signature_valide, hachage_valide));  // Conserver pour reference future

        Ok((signature_valide, hachage_valide))
    }

    pub fn verifier_hachage(&mut self) -> Result<bool, Box<dyn Error>> {
        Ok(self.verifier_contenu()?.1)

        // let entete = &self.entete;
        // let hachage_str = entete.hachage_contenu.as_str();
        //
        // // Filtrer champs avec _
        // let contenu_string = {
        //     let mut map: BTreeMap<&str, &Value> = BTreeMap::new();
        //     for (k, v) in &self.contenu {
        //         if !k.starts_with("_") {
        //             map.insert(k.as_str(), v);
        //         }
        //     }
        //     serde_json::to_string(&map)?
        // };
        //
        // verifier_multihash(hachage_str, contenu_string.as_bytes())
    }

    // pub fn verifier_signature(&mut self, public_key: &PKey<Public>) -> Result<bool, Box<dyn Error>> {
    //     // let contenu_str = MessageMilleGrille::preparer_pour_signature(entete, contenu)?;
    //     debug!("verifier_signature_str (signature: {:?}, public key: {:?})", self.signature, public_key);
    //
    //     let message = self.preparer_pour_signature()?;
    //     match &self.signature {
    //         Some(s) => {
    //             debug!("Message prepare pour signature\n{}", message);
    //             let resultat = ref_verifier_message(public_key, message.as_bytes(), s.as_str())?;
    //             Ok(resultat)
    //             // decode(s)?
    //         },
    //         None => Err(format!("Signature absente"))?,
    //     }
    //     // let version_signature = signature_bytes.1[0];
    //     // if version_signature != VERSION_2 {
    //     //     Err(format!("La version de la signature n'est pas 2"))?;
    //     // }
    //
    //     // let mut verifier = match Verifier::new(MessageDigest::sha512(), &public_key) {
    //     //     Ok(v) => v,
    //     //     Err(e) => Err(format!("Erreur verification signature : {:?}", e))?
    //     // };
    //     //
    //     // verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    //     // verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
    //     // verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH))?;
    //     // verifier.update(message.as_bytes())?;
    //     //
    //     // // Retourner la reponse
    //     // Ok(verifier.verify(&signature_bytes.1[1..])?)
    // }

    pub fn ajouter_attachement<S,V>(&mut self, key: S, value: V)
        where S: Into<String>, V: Into<Value>
    {
        let key = key.into();
        let value = value.into();

        match &mut self.attachements {
            Some(inner) => {
                inner.insert(key, value);
            },
            None => {
                let mut attachements = Map::new();
                attachements.insert(key, value);
                self.attachements = Some(attachements);
            }
        }
    }
}

/// Serialiser message de MilleGrille. Met les elements en ordre.
// impl Serialize for MessageMilleGrille {
//     fn serialize<'a, S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
//
//         // Creer BTreeMap avec toutes les values
//         // let mut ordered: BTreeMap<_, _> = self.contenu.iter().collect();
//         let mut ordered: BTreeMap<&str, &Value> = BTreeMap::new();
//         for (k, v) in &self.contenu {
//             ordered.insert(k.as_str(), v);
//         }
//
//         // Ajouter en-tete
//         let entete = serde_json::to_value(&self.entete).expect("val");
//         ordered.insert("en-tete", &entete);
//
//         // Ajouter certificats si presents
//         let cert = match &self.certificat {
//             Some(c) => serde_json::to_value(c).expect("certs"),
//             None => Value::Null
//         };
//         if cert != Value::Null {
//             ordered.insert("_certificat", &cert);
//         }
//         let cert_millegrille = match &self.millegrille {
//             Some(c) => serde_json::to_value(c).expect("cert millegrille"),
//             None => Value::Null
//         };
//         if cert_millegrille != Value::Null {
//             ordered.insert("_millegrille", &cert_millegrille);
//         }
//
//         // Ajouter signature si presente
//         let signature = match &self.signature {
//             Some(c) => serde_json::to_value(c).expect("signature"),
//             None => Value::Null
//         };
//         if signature != Value::Null {
//             ordered.insert("_signature", &signature);
//         }
//
//         // Serialiser la map triee
//         let mut map_ser = serializer.serialize_map(Some(ordered.len()))?;
//         for (k, v) in ordered {
//             map_ser.serialize_entry(k, v)?;
//         }
//         map_ser.end()
//
//     }
// }

pub fn preparer_btree_recursif(contenu: Map<String, Value>) -> Result<Map<String, Value>, Box<dyn Error>> {
    let iter: serde_json::map::IntoIter = contenu.into_iter();
    preparer_btree_recursif_into_iter(iter)
}

/// Preparer recursivement le contenu en triant les cles.
fn preparer_btree_recursif_into_iter(mut iter: serde_json::map::IntoIter) -> Result<Map<String, Value>, Box<dyn Error>> {
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


#[derive(Clone, Debug)]
pub struct MessageSerialise {
    //entete: Entete,
    message: String,
    pub parsed: MessageMilleGrille,
    pub certificat: Option<Arc<EnveloppeCertificat>>,
    pub millegrille: Option<Arc<EnveloppeCertificat>>,
}

impl TryFrom<&str> for MessageSerialise {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {

        let msg_parsed: MessageMilleGrille = match serde_json::from_str(value) {
            Ok(m) => m,
            Err(e) => Err(format!("MessageSerialise.TryFrom Erreur from_str : {:?}", e))?
        };

        Ok(Self {
            message: value.to_owned(),
            // entete: msg_parsed.entete.clone(),
            parsed: msg_parsed,
            certificat: Default::default(),
            millegrille: Default::default(),
        })
    }
}

impl TryFrom<String> for MessageSerialise {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let msg_parsed: MessageMilleGrille = match serde_json::from_str(value.as_str()) {
            Ok(m) => m,
            Err(e) => Err(format!("MessageSerialise.TryFrom Erreur from_str : {:?}", e))?
        };
        Ok(Self {
            message: value,
            // entete: msg_parsed.entete.clone(),
            parsed: msg_parsed,
            certificat: None,
            millegrille: None,
        })
    }
}

impl MessageSerialise {
    pub fn from_parsed(msg: MessageMilleGrille) -> Result<Self, Box<dyn std::error::Error>> {
        let msg_str = serde_json::to_string(&msg)?;
        Ok(MessageSerialise {
            // entete: msg.entete.clone(),
            message: msg_str,
            parsed: msg,
            certificat: None,
            millegrille: None,
        })
    }

    pub fn from_str(msg: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(MessageSerialise::try_from(msg)?)
    }

    pub fn from_string(msg: String) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(MessageSerialise::try_from(msg)?)
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
            // entete: msg_parsed.entete.clone(),
            parsed: msg_parsed,
            certificat: None,
            millegrille: None,
        })
    }

    pub fn set_certificat(&mut self, certificat: Arc<EnveloppeCertificat>) {
        self.certificat = Some(certificat);
    }

    pub fn set_millegrille(&mut self, certificat: Arc<EnveloppeCertificat>) {
        self.millegrille = Some(certificat);
    }

    // pub fn get_entete(&self) -> &Entete {
    //     &self.entete
    // }

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
        let fp_certificat = self.parsed.pubkey.as_str();

        // Charger l'enveloppe du certificat de millegrille (CA)
        //let ca : Option<Arc<EnveloppeCertificat>> =
        match &self.parsed.millegrille {
            Some(c) => {
                let vec_pems = vec![c.clone()];
                debug!("charger_certificat Certificat millegrille {:?}", vec_pems);
                let enveloppe = validateur.charger_enveloppe(&vec_pems, None, None).await?;
                self.millegrille = Some(enveloppe.clone());
                // Some(enveloppe)
            },
            None => ()  //None
        };

        // Charger l'enveloppe du certificat de signature du message
        let enveloppe : Option<Arc<EnveloppeCertificat>> = match &self.parsed.certificat {
            Some(c) => {
                let ca_pem = match &self.parsed.millegrille {
                    Some(c) => {
                        debug!("charger_certificat Utiliser CA {}", c);
                        Some(c.as_str())
                    },
                    None => None
                };
                let enveloppe = validateur.charger_enveloppe(c, Some(fp_certificat), ca_pem).await?;
                Some(enveloppe)
            },
            None => {
                validateur.get_certificat(fp_certificat).await
            }
        };

        // match &self.parsed.millegrille {
        //     Some(c) => {
        //         if self.millegrille.is_none() {
        //             debug!("Chargement du certificat de millegrille inclue {}", c);
        //             let vec_certs = vec!(c.to_owned());
        //             let enveloppe = validateur.charger_enveloppe(&vec_certs, None, None).await?;
        //             self.millegrille = Some(enveloppe);
        //         }
        //     },
        //     None => ()
        // }

        Ok(enveloppe)
    }

    /// Sert a extraire le message pour une restauration - deplace (move) le message.
    pub fn preparation_restaurer(self) -> MessageMilleGrille {
        let mut message = self.parsed;
        todo!("fix me")
        // let evenements = message.contenu
        //     .get_mut("_evenements").expect("evenements")
        //     .as_object_mut().expect("object");
        // evenements.insert(String::from("backup_flag"), Value::Bool(true));
        // evenements.insert(String::from("transaction_restauree"), serde_json::to_value(bson::DateTime::now()).expect("date") );
        //
        // message
    }

    // pub async fn valider_message_tiers<V>(&mut self, validateur: &V)
    //     -> Result<String, ResultatValidation>
    //     where V: ValidateurX509
    // {
    //     // Charger certificat CA du tiers
    //     let certificat_ca_tiers = match &self.millegrille {
    //         Some(c) => Ok(c.clone()),
    //         None => {
    //             info!("valider_message_tiers Fiche publique manquante");
    //             Err(ResultatValidation::new(false, None, false, false))
    //         }
    //     }?;
    //
    //     debug!("resoudre_url Certificat CA tiers : {:?}", certificat_ca_tiers);
    //     let idmg_tiers = match certificat_ca_tiers.calculer_idmg() {
    //         Ok(i) => Ok(i),
    //         Err(e) => {
    //             info!("valider_message_tiers Erreur calcul idmg sur certificat de millegrille : {}", e);
    //             Err(ResultatValidation::new(false, None, false, false))
    //         }
    //     }?;
    //     debug!("resoudre_url Certificat idmg tiers : {}", idmg_tiers);
    //     self.set_millegrille(certificat_ca_tiers.clone());
    //
    //     // Charger et verificat certificat tiers
    //     let certificat_tiers = match &self.parsed.certificat {
    //         Some(c) => match validateur.charger_enveloppe(&c, None).await {
    //             Ok(enveloppe) => {
    //                 let valide = match validateur.valider_chaine(
    //                     enveloppe.as_ref(), Some(certificat_ca_tiers.as_ref())) {
    //                     Ok(v) => Ok(v),
    //                     Err(e) => {
    //                         info!("valider_message_tiers Erreur valider chaine de certificat : {}", e);
    //                         Err(ResultatValidation::new(false, None, false, false))
    //                     }
    //                 }?;
    //                 if valide &&
    //                     enveloppe.verifier_exchanges(vec![Securite::L4Secure]) &&
    //                     enveloppe.verifier_roles(vec![RolesCertificats::Core]) {
    //                     Ok(enveloppe)
    //                 } else {
    //                     info!("core_topologie.resoudre_url Erreur verification certificat fiche publique : chaine invalide");
    //                     Err(ResultatValidation::new(false, None, false, false))
    //                 }
    //             }
    //             Err(e) => {
    //                 info!("core_topologie.resoudre_url Certificat fiche publique ne peut pas etre charge : {:?}", e);
    //                 Err(ResultatValidation::new(false, None, false, false))
    //             }
    //         },
    //         None => {
    //             info!("core_topologie.resoudre_url Certificat fiche publique manquant");
    //             Err(ResultatValidation::new(false, None, false, false))
    //         }
    //     }?;
    //     self.set_certificat(certificat_tiers);
    //
    //     // Valider le message avec certificat de la millegrille tierce
    //     let validation_option = ValidationOptions::new(true, true, true);
    //     let resultat_validation = match self.valider(validateur, Some(&validation_option)).await {
    //         Ok(r) => Ok(r),
    //         Err(e) => {
    //             info!("valider_message_tiers Erreur execution de la validation : {}", e);
    //             Err(ResultatValidation::new(false, None, true, false))
    //         }
    //     }?;
    //
    //     debug!("resoudre_url Resultat validation : {:?}", resultat_validation);
    //     match resultat_validation.valide() {
    //         true => Ok(idmg_tiers),
    //         false => Err(resultat_validation)
    //     }
    // }
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

impl Into<Value> for DateEpochSeconds {
    fn into(self) -> Value {
        Value::Number(Number::from(self.date.timestamp()))
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DechiffrageInterMillegrille {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cles: Option<BTreeMap<String, String>>,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hachage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageInterMillegrille {
    pub contenu: String,  // Contenu compresse/chiffre et encode en multibase
    pub origine: String,
    pub dechiffrage: DechiffrageInterMillegrille,
}

impl MessageInterMillegrille {
    pub fn new<M,S>(middleware: &M, contenu: S, certificats_demandeur: Option<Vec<&EnveloppeCertificat>>)
        -> Result<Self, Box<dyn Error>>
        where M: FormatteurMessage + ChiffrageFactoryTrait, S: Serialize
    {
        let (data_chiffre, keys) = chiffrer_data_get_keys(middleware, contenu)?;
        let idmg = middleware.get_enveloppe_signature().idmg()?;

        let mut dechiffrage = keys.get_dechiffrage(None)?;
        match certificats_demandeur {
            Some(certificats) => {
                let mut cles_rechiffrees = BTreeMap::new();
                for cert in certificats {
                    let cle_rechiffree = keys.rechiffrer(cert)?;
                    cles_rechiffrees.insert(cert.fingerprint.clone(), cle_rechiffree);
                }
                // Remplacer cles rechiffrage
                dechiffrage.cles = Some(cles_rechiffrees);
            },
            None => ()
        }

        Ok(Self { contenu: data_chiffre.data_chiffre, origine: idmg, dechiffrage })
    }

    pub fn dechiffrer<M>(&self, middleware: &M)  -> Result<DataDechiffre, Box<dyn Error>>
        where M: GenerateurMessages + CleChiffrageHandler
    {
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let fingerprint_local = enveloppe_privee.fingerprint().as_str();
        let header = match self.dechiffrage.header.as_ref() {
            Some(inner) => inner.as_str(),
            None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, header absent"))?
        };

        let (header, cle_secrete) = match self.dechiffrage.cles.as_ref() {
            Some(inner) => match inner.get(fingerprint_local) {
                Some(inner) => {
                    // Cle chiffree, on dechiffre
                    let cle_bytes = multibase::decode(inner)?;
                    let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], enveloppe_privee.cle_privee())?;
                    (header, cle_secrete)
                },
                None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, dechiffrage absent"))?
            },
            None => Err(format!("formatteur_messages.MessageInterMillegrille.dechiffrer Erreur format message, dechiffrage absent"))?
        };

        // Dechiffrer le contenu
        let data_chiffre = DataChiffre {
            ref_hachage_bytes: None,
            data_chiffre: format!("m{}", self.contenu),
            format: FormatChiffrage::mgs4,
            header: Some(header.to_owned()),
            tag: None,
        };
        debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Data chiffre contenu : {:?}", data_chiffre);

        let cle_dechiffre = CleDechiffree {
            cle: "m".to_string(),
            cle_secrete,
            domaine: "MaitreDesCles".to_string(),
            format: "mgs4".to_string(),
            hachage_bytes: "".to_string(),
            identificateurs_document: None,
            iv: None,
            tag: None,
            header: Some(header.to_owned()),
            signature_identite: "".to_string(),
        };

        debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Dechiffrer data avec cle dechiffree");
        let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
        debug!("formatteur_messages.MessageInterMillegrille.dechiffrer.MessageReponseChiffree.dechiffrerfrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
        // debug!("formatteur_messages.MessageInterMillegrille.dechiffrer Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));

        Ok(data_dechiffre)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageReponseChiffree {
    pub contenu: String,  // Contenu compresse/chiffre et encode en multibase
    pub dechiffrage: DechiffrageInterMillegrille,
}

impl TryFrom<MessageMilleGrille> for MessageReponseChiffree {
    type Error = String;

    fn try_from(mut value: MessageMilleGrille) -> Result<Self, Self::Error> {
        let dechiffrage = match value.dechiffrage.take() {
            Some(inner) => inner,
            None => Err(format!("commande_rechiffrer_batch Information de dechiffrage absente"))?
        };
        Ok(Self {
            contenu: value.contenu,
            dechiffrage,
        })
    }
}

impl MessageReponseChiffree {
    pub fn new<M,S>(middleware: &M, contenu: S, certificat_demandeur: &EnveloppeCertificat)
        -> Result<Self, Box<dyn Error>>
        where M: ChiffrageFactoryTrait, S: Serialize
    {
        let (data_chiffre, dechiffrage) = chiffrer_data(middleware, contenu)?;
        Ok(Self { contenu: data_chiffre.data_chiffre, dechiffrage })
    }

    pub fn dechiffrer<M>(&self, middleware: &M)  -> Result<DataDechiffre, Box<dyn Error>>
        where M: GenerateurMessages + CleChiffrageHandler
    {
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let fingerprint_local = enveloppe_privee.fingerprint().as_str();
        let header = match self.dechiffrage.header.as_ref() {
            Some(inner) => inner.as_str(),
            None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, header absent"))?
        };

        let (header, cle_secrete) = match self.dechiffrage.cles.as_ref() {
            Some(inner) => match inner.get(fingerprint_local) {
                Some(inner) => {
                    // Cle chiffree, on dechiffre
                    let cle_bytes = multibase::decode(inner)?;
                    let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes.1[..], enveloppe_privee.cle_privee())?;
                    (header, cle_secrete)
                },
                None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
            },
            None => Err(format!("formatteur_messages.MessageReponseChiffree.dechiffrer Erreur format message, dechiffrage absent"))?
        };

        // Dechiffrer le contenu
        let data_chiffre = DataChiffre {
            ref_hachage_bytes: None,
            data_chiffre: format!("m{}", self.contenu),
            format: FormatChiffrage::mgs4,
            header: Some(header.to_owned()),
            tag: None,
        };
        debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data chiffre contenu : {:?}", data_chiffre);

        let cle_dechiffre = CleDechiffree {
            cle: "m".to_string(),
            cle_secrete,
            domaine: "MaitreDesCles".to_string(),
            format: "mgs4".to_string(),
            hachage_bytes: "".to_string(),
            identificateurs_document: None,
            iv: None,
            tag: None,
            header: Some(header.to_owned()),
            signature_identite: "".to_string(),
        };

        debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Dechiffrer data avec cle dechiffree");
        let data_dechiffre = dechiffrer_data(cle_dechiffre, data_chiffre)?;
        debug!("formatteur_messages.MessageReponseChiffree.dechiffrer.MessageReponseChiffree.dechiffrerfrer_batch Data dechiffre len {}", data_dechiffre.data_dechiffre.len());
        // debug!("formatteur_messages.MessageReponseChiffree.dechiffrer Data dechiffre {:?}", String::from_utf8(data_dechiffre.data_dechiffre.clone()));

        Ok(data_dechiffre)
    }
}

#[cfg(test)]
mod serialization_tests {
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
    use crate::test_setup::setup;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    /// Sample
    //const MESSAGE_STR: &str = r#"{"_certificat":["-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIUFGTSBu4f2hbzgnca0GuSsmLgr7UwDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRj\nYjFhYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDgzMDExNTcxNVoXDTIxMDkyOTExNTkxNVowZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMcAz3SshFSHxyd+KfTZVHWG3OQg9t7kdHtV\nkrXySXdPYc+svArawMKhy/XRrFJ+NfLNoUyz+KPma5mEWxXZDRZVyvmdodDh/eNu\nqJ4aB078AkxyKWNgT/aF1/EuZ+pZseVlaDrD1yoEiC4stXwm6ay7mnWTyczDt8FI\ntCZ6/9nDNwPsnwC6cbqXRH4gqkwDqBGolX9Jz6TU4pqisIroacwOW+NEmNassM2b\nQqP/W4saEQQqD2BV78I9hQxouE8JLR6SIL5XD7j6Pq6pG86TSkFGAqQsSPd1w+5l\nxMRQgitYJ7ITo/Eq0qmAxv1INnxLyLmXQ2FysUNVTtgGgN3O7OUCAwEAAaOBgTB/\nMB0GA1UdDgQWBBQSOxwSTijPrcKRmCWzoFpf8cJQbDAfBgNVHSMEGDAWgBT170DQ\ne1NxyrKp2GduPOZ6P9b5iDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQq\nAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5lczANBgkqhkiG9w0BAQsFAAOC\nAQEARX75Y2kVlxiJSmbDi1hZRj3mfe7ihT69EL51R6YiB0c/fpQUYxWfpddbg4DY\nlzAssE2XtSv1gYBZkZJXGWS4jB6dW6r+7Mhbtb6ZSXXG5ba9LydSxI8++//GZwG/\np8nce6fNmR8b06s/TQjpqwOa+hXqiqkWzqoVal/ucQWhdLtTkx/DVFUjHMcDMhZT\nVKIX7/SGEi9uGM9LNIVhCc7TsndcmiNXkV7ybiJ02rqxXPrD0QJ6h28rHIEGbWWs\napOlHiqtHYWQCuM0h5kygqknYKmHZIFBfba/xCf1rJi9HQUFZZfuw0VS9BcFmBg/\n5Hx8faWZNWWE9Iu+366P1t9GxA==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJJ0USglmGk0UAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDcyMDEzNTc0MFoXDTI0MDcyMjEzNTc0MFow\ngYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRjYjFh\nYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCNK7g/7AzTTRT3SX7vTzQIKhXvZ\nTkjphiJ38SoL4jZnv4tEyTV2j2a6v8UgluG/zab6W38n0YpLr1/J2+xVNOKO5P4t\ni//Qiygjkbl/2HGSjttorwdnybFIUdDqMQAHHZMfuvgZOgzXOG4xRxAD/uoTh1+B\ndj55uLKIwITtAY7e/Zxwia8cH9qPLRUETdp2/3rIGHSSkj1GDucnipGJHqrD2wF5\nylgy1kLLzV87wF55g7+nHYFpWXl19h8pAfxrQM1wMIY/rqAKwYoitePRaaLPfTKR\nTrzP4Ei4lStzuR4MocO2wZRSKKNuJw5GFML7PQf+ZV43KOGlpq8GmyNZxQIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBT170DQe1NxyrKp2Gdu\nPOZ6P9b5iDAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAcH0Qbyeap2+uCTXyua+z8JpPAgW25GefOAkyzsaEgaSrOp7U\nic16YmZQz6QXZSkq0+agZ0dVue+9J5iPniujJjkACdClWsMl98eFcen0gb35humU\n20QDgvTDdmNpb2psfVfLMn50B1FxcYTVV3J2jjgBQa0/Q69+DPAbagKF/TJgMERY\nm8vBiHLruFWx7iuO5l9zI9/TCfMdZ1c0i+caUEEf4urCmxp7BjdWfDp+HshcJqok\nQN8PMVu4GfexJOD9gdHBaIA2VAuTCElL9K1Iy5kUcklu0qFxBKDi1N0mKOUeaGnq\nxbVEt7CZD3fF0xKnyNXAZzoCvqvkXtUORdkiZIH7k3EPgpgmLKvx2WNyXgFKs7y0\nMsucRkCixTRCdoju5h410hh7hpfR6eT+kHicJMSH1MKDJ/72MeFNeiOatKq8x72L\nzgGYVkuDlfXjPr5zPalw3BVNToikhVAgvVENiEaRzBKDJIkq1MnwK6VAzLMC60Cm\nSLqr6N7dHrSBO27B\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----\n"],"_signature":"mAWm3oYujnuCUtXlqyUnLWRNDJFtDUiG3wmy1sdU8YLTf0yNDENYLB8t1jUtXYyHRx5Dawd6sy0RhKXCUwnWl9q+Q/9u+wAwSxvR+dKiweYsdDZJAXrTwkYQmEu/X8/vbQcVMVX8VWwinDgalFSR0q//6V14Bp8jgAKFZifd2N9gPSEy0RBze1TUHuNlW7phUP5dAPcviiDLbpcQNJ3suD8Oq9m3ob61N04QFMvr8glWGs8yf0VbEJ8UXi22WOL/L02UWcMuqf5v9SKaKd/7we/jVW10GnYfH/coWdl62FrTNLBMGonkO9KzR8dXxNzDMvpt4A1kpcEZ7488EjTAhgzs","alpaca":true,"en-tete":{"estampille":1631884993,"fingerprint_certificat":"zQmSTKik15nFmLe4tQtndoEWA6aDdGUcVjpNHt4RtKQvnC3","hachage_contenu":"mEiCerWQ+xmJBauIR2JdRX1pBa+1wYlUNg/Q0dbhCGUOSww","idmg":"z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s","uuid_transaction":"6ba61473-18fc-4ff2-9de7-95470eadb2d8","version":1},"texte":"oui!","valeur":1}"#;
    const MESSAGE_STR: &str = r#"{"id":"45e8347dd1adbb7b633bb0fd2621596cff22657ddd219ac6327e5a70a3f5f353","pubkey":"30d241f794e561486abd5a2ffddf86ff08f89b78856080466aedff7837b8ba89","estampille":1681766892,"kind":1,"contenu":"{\"alpaca\":true,\"texte\":\"oui!\",\"valeur\":1}","routage":{"action":"requeteDummy","domaine":"Dummy"},"sig":"e0275248dfce879afc78b2e4798cf621b2885ea822e0a733138ce7494386443fb84e2cad5dbbd10a1aa5c712972fc3c0e476d012f9347cada283d201d1f71e0c","certificat":["-----BEGIN CERTIFICATE-----\nMIIClDCCAkagAwIBAgIUVFctVKeWq04RXiftJ3tj/Fw8mLIwBQYDK2VwMHIxLTAr\nBgNVBAMTJDI2Yzc0YmYwLWE1NWUtNDBjYi04M2U2LTdlYTgxOGUyZDQxNjFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjMwNDE2MjIwNzM5WhcNMjMwNTE3MjIwNzU5WjCB\ngTEtMCsGA1UEAwwkYTcxMzA3YzUtMWNiOC00NGI1LWExM2EtY2Q5NDQwM2I2N2Vm\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhADDS\nQfeU5WFIar1aL/3fhv8I+Jt4hWCARmrt/3g3uLqJo4HdMIHaMCsGBCoDBAAEIzQu\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\nBgNVHSMEGDAWgBQHLJvHVM5P2+40plzpsr4b47oS7zAdBgNVHQ4EFgQUwnVgI/E/\nAZJlrA2h7rPLMaHmOqQwBQYDK2VwA0EAc717NCOIchhGhCJUZY+WeajoeubIwpGq\nqyRJ5bgC6XZJ8wVzpikUIvT3PcafQKdTGWtNOT0Jehi2xjLOT36ZAg==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKEiZUUAGScUVHVDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjMwNDE2MjEzNDM5WhcNMjQxMDI1MjEzNDM5WjByMS0wKwYD\nVQQDEyQyNmM3NGJmMC1hNTVlLTQwY2ItODNlNi03ZWE4MThlMmQ0MTYxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAb0VPx+wJvYRWgBnxW1QuMMAj1U6nhdqd\na1bz0mVXWoSjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBQHLJvHVM5P2+40plzpsr4b47oS7zAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQDHCMn7gdqOu7NAbYNRKQBa8/YZGoifuRuB\nCdVpEB7NGL1mWYfv78Rbtgw26ESC9aRbbL3imXBKQt1CgeCTN5gF\n-----END CERTIFICATE-----\n"]}"#;

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
            &enveloppe_privee, MessageKind::Requete, &val,
            Some("Dummy"), Some("requeteDummy"), None::<&str>, None,
            false).expect("map");

        let message_str = serde_json::to_string(&message).expect("string");
        debug!("Message MilleGrille serialise : {}", message_str)
    }

    #[test]
    fn lire_message_millegrille() {
        setup("lire_message_millegrille");
        let (_, _) = charger_enveloppe_privee_env();
        let message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");
        let contenu = &message.get_msg().contenu;
        debug!("Contenu parsed : {:?}", contenu);

        let map_parsed: HashMap<String, Value> = message.parsed.map_contenu().expect("map_contenu");

        assert_eq!("45e8347dd1adbb7b633bb0fd2621596cff22657ddd219ac6327e5a70a3f5f353", message.parsed.id);
        assert_eq!("oui!", map_parsed.get("texte").expect("texte").as_str().expect("str"));
        assert_eq!(true, map_parsed.get("alpaca").expect("texte").as_bool().expect("bool"));
        assert_eq!(1, map_parsed.get("valeur").expect("texte").as_i64().expect("i64"));
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
        assert_eq!(Some(true), resultat.hachage_valide);
    }

    #[tokio::test]
    async fn valider_message_corrompu() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        // Corrompre le message
        message.parsed.contenu = message.parsed.contenu.replace("true", "false");

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(true, resultat.signature_valide);
        // assert_eq!(false, resultat.certificat_valide);  // expire
        assert_eq!(Some(false), resultat.hachage_valide);
    }

    #[tokio::test]
    async fn valider_hachage_corrompu() {
        setup("valider_message_millegrille");
        let (validateur_arc, _) = charger_enveloppe_privee_env();
        let mut message = MessageSerialise::from_str(MESSAGE_STR).expect("msg");

        // Corrompre le message
        message.parsed.id = String::from("45e8347dd1adbb7b633bb0fd2621596cff22657ddd219ac6327e5a70a3f5f354");

        let validateur = validateur_arc.as_ref();
        let resultat = message.valider(validateur, None).await.expect("valider");
        assert_eq!(false, resultat.signature_valide);
        // assert_eq!(false, resultat.certificat_valide);  // expire
        assert_eq!(Some(false), resultat.hachage_valide);
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
            &enveloppe_privee, MessageKind::Document, &val, None::<&str>, None::<&str>, None::<&str>, None, false).expect("map");

        let message_str = serde_json::to_string(&message).expect("string");
        let idx_certificat = message_str.find("\"certificat\"");
        debug!("Message MilleGrille serialise avec _certificat (position : {:?} : {}", idx_certificat, message_str);
        assert_eq!(true, idx_certificat.is_some());

        message.retirer_certificats();
        let message_str = serde_json::to_string(&message).expect("string");
        let idx_certificat = message_str.find("\"certificat\"");
        debug!("Message MilleGrille serialise avec _certificat (position : {:?} : {}", idx_certificat, message_str);
        assert_eq!(true, idx_certificat.is_none());
    }

}
