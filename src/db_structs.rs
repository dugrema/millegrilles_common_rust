use std::borrow::Cow;
use std::collections::HashMap;
use std::str::from_utf8;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use log::error;
use millegrilles_cryptographie::ed25519::{MessageId, verifier};
use millegrilles_cryptographie::ed25519_dalek::VerifyingKey;
use millegrilles_cryptographie::error::Error;
use millegrilles_cryptographie::hachages::{HacheurBlake2s256, HacheurInterne};
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrille, DechiffrageInterMillegrilleOwned, MessageKind, MessageMilleGrillesRef, RoutageMessage, RoutageMessageOwned, epochseconds, optionepochseconds, HacheurMessage, PreMigrationOwned, PreMigration, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use crate::mongo_dao::opt_chrono_datetime_as_bson_datetime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use mongodb::bson;
use crate::recepteur_messages::MessageValide;

/// Mapping avec references des documents d'une table de Transactions.
#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionRef<'a> {
    /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
    pub id: &'a str,

    /// Cle publique du certificat utilise pour la signature
    pub pubkey: &'a str,

    /// Date de creation du message
    #[serde(with = "epochseconds")]
    pub estampille: DateTime<Utc>,

    /// Kind du message, correspond a enum MessageKind
    pub kind: MessageKind,

    /// Contenu du message en format **json-string escaped**
    #[serde(skip)]
    pub contenu_escaped: Option<&'a str>,

    #[serde(rename = "contenu")]
    /// Contenu du message
    pub contenu: Option<&'a str>,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessage<'a>>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    // pub pre_migration: Option<HashMap<&'a str, Value>>,
    pub pre_migration: Option<PreMigration<'a>>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<&'a str>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille<'a>>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: &'a str,

    /// Chaine de certificats en format PEM (**escaped** en json).
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat_escaped: Option<Vec<&'a str>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<&'a str>,

    /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachements: Option<HashMap<String, Value>>,

    #[serde(rename = "_evenements")]
    pub evenements: Option<EvenementsTransaction>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

impl<'a> TransactionRef<'a> {

    /// Parse le contenu et retourne un buffer qui peut servir a deserializer avec serde
    pub fn contenu(&self) -> Result<Cow<str>, crate::error::Error> {
        match self.contenu {
            Some(inner) => Ok(Cow::Borrowed(inner)),
            None => match self.contenu_escaped {
                Some(inner) => {
                    let contenu_escaped: String = match serde_json::from_str(format!("\"{}\"", inner).as_str()) {
                        Ok(inner) => inner,
                        Err(e) => {
                            Err(Error::String(format!("db_structs TransactionRef.contenu Erreur escape String avec format! : {:?}", e)))?
                        }
                    };
                    Ok(Cow::Owned(contenu_escaped))
                },
                None => Err(Error::Str("Aucun contenu"))?
            }
        }
    }

    pub fn certificat(&self) -> Result<Option<Vec<String>>, crate::error::Error> {
        match self.certificat_escaped.as_ref() {
            Some(inner) => {
                let mut certificat_string = Vec::new();
                for c in inner {
                    let certificat: String = match serde_json::from_str(format!("\"{}\"", c).as_str()) {
                        Ok(inner) => inner,
                        Err(_) => {
                            // Assumer que le certificat n'etait pas escaped
                            c.to_string()
                            // Err(Error::String(format!("db_structs TransactionRef.certificat Erreur escape certificat String : {:?}\n{}", e, *c)))?
                        }
                    };
                    certificat_string.push(certificat);
                }
                Ok(Some(certificat_string))
            },
            None => Ok(None)
        }
    }

}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct PreMigration {
//     pub id: Option<String>,
//     #[serde(default, with = "optionepochseconds")]
//     pub estampille: Option<DateTime<Utc>>,
//     pub pubkey: Option<String>,
//     pub idmg: Option<String>,
// }

// impl<'a, const C: usize> Into<TransactionRef<'a>> for MessageMilleGrillesRef<'a, C> {
//     fn into(self) -> TransactionRef<'a> {
//
//         let certificat = match self.certificat {
//             Some(inner) => Some(inner.into_iter().collect()),
//             None => None
//         };
//
//         TransactionRef {
//             id: self.id,
//             pubkey: self.pubkey,
//             estampille: self.estampille,
//             kind: self.kind.clone(),
//             contenu: self.contenu,
//             routage: self.routage,
//             pre_migration: None,
//             origine: self.origine,
//             dechiffrage: self.dechiffrage,
//             signature: self.signature,
//             certificat,
//             millegrille: self.millegrille,
//             attachements: self.attachements,
//             evenements: None,
//             contenu_valide: self.contenu_valide,
//         }
//     }
// }

impl<'a, const C: usize> From<MessageMilleGrillesRef<'a, C>> for TransactionRef<'a> {
    fn from(value: MessageMilleGrillesRef<'a, C>) -> Self {
        let certificat = match value.certificat_escaped {
            Some(inner) => Some(inner.into_iter().collect()),
            None => None
        };

        Self {
            id: value.id,
            pubkey: value.pubkey,
            estampille: value.estampille,
            kind: value.kind.clone(),
            contenu_escaped: Some(value.contenu_escaped),
            contenu: None,
            routage: value.routage,
            pre_migration: None,
            origine: value.origine,
            dechiffrage: value.dechiffrage,
            signature: value.signature,
            certificat_escaped: certificat,
            millegrille: value.millegrille,
            attachements: None,
            evenements: None,
            contenu_valide: value.contenu_valide,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// Structure d'un message MilleGrille. Tous les elements sont en reference
/// a des sources externes (e.g. buffer);
/// C: nombre maximal de certificats (recommande: 4)
pub struct TransactionOwned {
    /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
    pub id: String,

    /// Cle publique du certificat utilise pour la signature
    pub pubkey: String,

    /// Date de creation du message
    #[serde(with = "epochseconds")]
    pub estampille: DateTime<Utc>,

    /// Kind du message, correspond a enum MessageKind
    pub kind: MessageKind,

    /// Contenu du message en format json-string
    pub contenu: String,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessageOwned>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<PreMigrationOwned>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<String>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrilleOwned>,

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
    pub attachements: Option<HashMap<String, Value>>,

    #[serde(rename = "_evenements")]
    pub evenements: Option<EvenementsTransaction>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

impl TransactionOwned {

    pub fn verifier_signature(&mut self) -> Result<(), crate::error::Error> {
        if let Some(inner) = self.contenu_valide {
            if inner == (true, true) {
                return Ok(())
            }
            Err(Error::Str("verifier_signature Invalide"))?
        }

        // Verifier le hachage du message
        // let contenu_escaped = serde_json::to_string(self.contenu.as_str())?;
        let hacheur = self.get_hacheur(self.contenu.as_str(), false)?;
        let hachage_string = hacheur.hacher()?;
        if self.id != hachage_string.as_str() {
            self.contenu_valide = Some((false, false));
            error!("TransactionOwned verifier_signature hachage invalide : id: {}, calcule: {} Contenu:\n{}", self.id, hachage_string, self.contenu);
            Err(Error::Str("TransactionOwned verifier_signature hachage invalide"))?
        }

        // Extraire cle publique (bytes de pubkey) pour verifier la signature
        let mut buf_pubkey = [0u8; 32];
        hex::decode_to_slice(&self.pubkey, &mut buf_pubkey).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&buf_pubkey).unwrap();

        // Extraire la signature (bytes de sig)
        let mut hachage_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(&self.id, &mut hachage_bytes) {
            error!("verifier_signature Erreur hex {:?}", e);
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature:E1"))?
        }

        // Verifier la signature
        if ! verifier(&verifying_key, &hachage_bytes, &self.signature) {
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature signature invalide"))?
        }

        // Marquer signature valide=true, hachage valide=true
        self.contenu_valide = Some((true, true));

        Ok(())
    }
}

impl<'a> TryInto<TransactionOwned> for TransactionRef<'a> {

    type Error = crate::error::Error;

    fn try_into(self) -> Result<TransactionOwned, Self::Error> {
        let contenu = match self.contenu()? {
            Cow::Borrowed(inner) => inner.to_owned(),
            Cow::Owned(inner) => inner
        };
        let certificat = self.certificat()?;

        Ok(TransactionOwned {
            id: self.id.into(),
            pubkey: self.pubkey.into(),
            estampille: self.estampille,
            kind: self.kind,
            contenu,
            routage: match &self.routage { Some(inner) => Some(inner.into()), None => None },
            // pre_migration: match self.pre_migration { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            pre_migration: match self.pre_migration.as_ref() { Some(inner) => Some(inner.into()), None => None},
            origine: match self.origine { Some(inner) => Some(inner.to_owned()), None => None },
            dechiffrage: match &self.dechiffrage { Some(inner) => Some(inner.into()), None => None },
            signature: self.signature.into(),
            certificat,
            millegrille: match self.millegrille { Some(inner) => Some(inner.to_string()), None => None },
            attachements: match self.attachements { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            // evenements: match self.evenements { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            evenements: self.evenements,
            contenu_valide: self.contenu_valide,
        })
    }
}

impl TransactionOwned {

    fn get_hacheur<'a>(&'a self, contenu: &'a str, contenu_escaped: bool) -> Result<HacheurMessage<'a>, crate::error::Error> {
        Ok(HacheurMessage {
            hacheur: HacheurBlake2s256::new(),
            pubkey: self.pubkey.as_str(),
            estampille: &self.estampille,
            kind: self.kind.clone(),
            contenu,
            contenu_escaped,
            routage: match self.routage.as_ref() { Some(inner) => Some(inner.into()), None => None },
            pre_migration: match self.pre_migration.as_ref() { Some(inner) => Some(inner.into()), None => None },
            origine: match self.origine.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            dechiffrage: match self.dechiffrage.as_ref() { Some(inner) => Some(inner.try_into()?), None => None },
        })
    }
}

#[derive(Clone)]
pub struct TransactionValide {
    pub transaction: TransactionOwned,
    pub certificat: Arc<EnveloppeCertificat>,
}

impl TryFrom<MessageValide> for TransactionValide {
    type Error = crate::error::Error;
    fn try_from(value: MessageValide) -> Result<Self, Self::Error> {
        let message_ref = match value.message.parse() {
            Ok(inner) => inner,
            Err(e) => Err(crate::error::Error::String(e.to_string()))?
        };
        let transaction_ref: TransactionRef = message_ref.into();
        Ok(Self {
            transaction: transaction_ref.try_into()?,
            certificat: value.certificat,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EvenementsTransaction {
    #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub document_persiste: DateTime<Utc>,
    #[serde(rename="_estampille", with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub estampille: DateTime<Utc>,
    pub transaction_complete: Option<bool>,
    pub backup_flag: Option<bool>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub signature_verifiee: Option<DateTime<Utc>>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub transaction_traitee: Option<DateTime<Utc>>,
    #[serde(default, with = "opt_chrono_datetime_as_bson_datetime")]
    pub backup_horaire: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: Option<HashMap<String, Value>>,
}

impl EvenementsTransaction {
    pub fn new() -> Self {
        Self {
            document_persiste: Default::default(),
            estampille: Default::default(),
            transaction_complete: None,
            backup_flag: None,
            signature_verifiee: None,
            transaction_traitee: None,
            backup_horaire: None,
            extra: None,
        }
    }
}

// impl TryInto<MessageValide> for TransactionValide {
//     type Error = String;
//
//     fn try_into(self) -> Result<MessageValide, Self::Error> {
//         let kind = self.message.kind.clone();
//         let routage_message = self.message.routage.clone();
//
//         let buffer = match serde_json::to_vec(&self.message) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("try_into Erreur : {:?}", e))?
//         };
//         let message = MessageMilleGrillesBufferDefault::from(buffer);
//
//         let type_message = match kind {
//             crate::constantes::MessageKind::Document => Err(String::from("Non supporte"))?,
//             crate::constantes::MessageKind::Requete |
//             crate::constantes::MessageKind::Commande |
//             crate::constantes::MessageKind::Transaction |
//             crate::constantes::MessageKind::Evenement => {
//                 let routage = match &routage_message {
//                     Some(inner) => inner,
//                     None => Err(String::from("Non supporte"))?
//                 };
//                 let domaine = match routage.domaine.as_ref() {
//                     Some(inner) => inner.to_owned(),
//                     None => Err(String::from("Domaine requis"))?
//                 };
//                 let action = match routage.action.as_ref() {
//                     Some(inner) => inner.to_owned(),
//                     None => Err(String::from("Action requise"))?
//                 };
//
//                 let routage = RoutageMessageAction::builder(domaine, action, vec![]).build();
//
//                 MessageValide {
//                     message,
//                     type_message: TypeMessage,
//                     certificat: self.certificat,
//                 }
//             }
//             crate::constantes::MessageKind::Reponse => {
//
//             }
//             crate::constantes::MessageKind::ReponseChiffree |
//             crate::constantes::MessageKind::TransactionMigree |
//             crate::constantes::MessageKind::CommandeInterMillegrille => {
//                 Err(String::from("Non supporte"))?
//             }
//         }
//
//         Ok(MessageValide{
//             message,
//             type_message: (),
//             certificat: self.certificat,
//         })
//     }
// }
