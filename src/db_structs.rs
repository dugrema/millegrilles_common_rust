use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrille, DechiffrageInterMillegrilleOwned, MessageKind, MessageMilleGrillesRef, RoutageMessage, RoutageMessageOwned, epochseconds, MessageMilleGrillesBufferDefault};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::certificats::EnveloppeCertificat;
use crate::generateur_messages::RoutageMessageAction;
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

    /// Contenu du message en format json-string
    pub contenu: &'a str,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessage<'a>>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<HashMap<&'a str, Value>>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<&'a str>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille<'a>>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: &'a str,

    /// Chaine de certificats en format PEM.
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<&'a str>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<&'a str>,

    /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachements: Option<HashMap<&'a str, Value>>,

    #[serde(rename = "_evenements")]
    pub evenements: Option<HashMap<&'a str, Value>>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

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
        let certificat = match value.certificat {
            Some(inner) => Some(inner.into_iter().collect()),
            None => None
        };

        Self {
            id: value.id,
            pubkey: value.pubkey,
            estampille: value.estampille,
            kind: value.kind,
            contenu: value.contenu,
            routage: value.routage,
            pre_migration: value.pre_migration,
            origine: value.origine,
            dechiffrage: value.dechiffrage,
            signature: value.signature,
            certificat,
            millegrille: value.millegrille,
            attachements: value.attachements,
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
    pub pre_migration: Option<HashMap<String, Value>>,

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
    pub evenements: Option<HashMap<String, Value>>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

impl<'a> Into<TransactionOwned> for TransactionRef<'a> {
    fn into(self) -> TransactionOwned {
        TransactionOwned {
            id: self.id.into(),
            pubkey: self.pubkey.into(),
            estampille: self.estampille,
            kind: self.kind,
            contenu: self.contenu.into(),
            routage: match &self.routage { Some(inner) => Some(inner.into()), None => None },
            pre_migration: match self.pre_migration { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            origine: match self.origine { Some(inner) => Some(inner.to_owned()), None => None },
            dechiffrage: match &self.dechiffrage { Some(inner) => Some(inner.into()), None => None },
            signature: self.signature.into(),
            certificat: match self.certificat { Some(inner) => Some(inner.into_iter().map(|s| s.to_string()).collect()), None => None },
            millegrille: match self.millegrille { Some(inner) => Some(inner.to_string()), None => None },
            attachements: match self.attachements { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            evenements: match self.evenements { Some(inner) => Some(inner.into_iter().map(|(key, value)| (key.to_string(), value)).collect()), None => None },
            contenu_valide: self.contenu_valide,
        }
    }
}

#[derive(Clone)]
pub struct TransactionValide {
    pub transaction: TransactionOwned,
    pub certificat: Arc<EnveloppeCertificat>,
}

impl TryFrom<MessageValide> for TransactionValide {
    type Error = String;
    fn try_from(value: MessageValide) -> Result<Self, Self::Error> {
        let message_ref = match value.message.parse() {
            Ok(inner) => inner,
            Err(e) => Err(e.to_string())?
        };
        let transaction_ref: TransactionRef = message_ref.into();
        Ok(Self {
            transaction: transaction_ref.into(),
            certificat: value.certificat,
        })
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
