use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::messages_structs::{RoutageMessage, epochseconds, optionepochseconds, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::{bson::doc, Collection, Cursor};
use mongodb::bson as bson;
use mongodb::bson::{Bson, Document};
use mongodb::error::{BulkWriteError, ErrorKind};
use mongodb::options::{FindOptions, Hint, InsertManyOptions};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio_stream::StreamExt;

use crate::certificats::{ValidateurX509, VerificateurPermissions};
use crate::constantes::*;
use crate::db_structs::{EvenementsTransaction, TransactionOwned, TransactionRef, TransactionValide};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::messages_generiques::CommandeUsager;
use crate::middleware::{map_serializable_to_bson, requete_certificat};
use crate::mongo_dao::{convertir_bson_deserializable, MongoDao};
use crate::recepteur_messages::{MessageValide, TypeMessage};
// use crate::verificateur::VerificateurMessage;
use crate::error::Error as CommonError;

pub async fn transmettre_evenement_persistance<S>(
    middleware: &impl GenerateurMessages,
    uuid_transaction: S,
    domaine: S,
    action: S,
    partition: Option<&String>,
    reply_to: Option<&String>,
    correlation_id: Option<&String>
) -> Result<(), crate::error::Error>
    where S: AsRef<str>
{
    let mut evenement = json!({
        "id": uuid_transaction.as_ref(),
        "evenement": EVENEMENT_TRANSACTION_PERSISTEE,
        "domaine": domaine.as_ref(),
        "action": action.as_ref(),
        "partition": partition,
    });

    let evenement_map = evenement.as_object_mut().expect("map");

    if let Some(reply_to) = reply_to {
        evenement_map.insert("reply_to".into(), Value::from(reply_to.to_owned()));
    }

    if let Some(correlation_id) = correlation_id {
        evenement_map.insert("correlation_id".into(), Value::from(correlation_id.to_owned()));
    }

    let mut routage_builder = RoutageMessageAction::builder(
        domaine.as_ref(), EVENEMENT_TRANSACTION_PERSISTEE, vec!(Securite::L4Secure));
    if let Some(p) = partition {
        routage_builder = routage_builder.partition(p.as_str());
    }
    let routage = routage_builder.build();

    Ok(middleware.emettre_evenement(routage, &evenement).await?)
}

#[derive(Clone, Debug, Deserialize)]
pub struct TriggerTransaction {
    pub domaine: String,
    pub evenement: String,
    // pub uuid_transaction: String,
    pub id: String,
    pub reply_to: Option<String>,
    pub correlation_id: Option<String>,
}

impl TriggerTransaction {
    pub fn reply_info(&self) -> Option<RoutageMessageReponse> {
        if let Some(corr) = self.correlation_id.as_ref() {
            if let Some(r) = self.reply_to.as_ref() {
                let routage = RoutageMessageReponse::new(r, corr);
                return Some(routage)
            }
        }
        None
    }
}

pub async fn charger_transaction<M>(middleware: &M, nom_collection: &str, trigger: &TriggerTransaction) -> Result<TransactionValide, String>
where
    M: ValidateurX509 + MongoDao,
{
    debug!("Traitement d'une transaction : {:?}", trigger);
    // let trigger = &m.message;
    // let entete = trigger.get_entete();
    // let contenu = &m.message.get_msg().contenu;
    let uuid_transaction = trigger.id.as_str();

    // Charger transaction a partir de la base de donnees
    let collection = middleware.get_collection_typed::<TransactionOwned>(nom_collection)?;

    let filtre = doc! {TRANSACTION_CHAMP_ID: uuid_transaction};

    match collection.find_one(filtre, None).await {
        Ok(d) => match d {
            Some(d) => extraire_transaction(middleware, d).await,
            None => Err(format!("Transaction introuvable : {}", uuid_transaction)),
        },
        Err(e) => Err(format!("Erreur chargement transaction {} : {:?}", uuid_transaction, e)),
    }
}

async fn extraire_transaction(validateur: &impl ValidateurX509, transaction: TransactionOwned) -> Result<TransactionValide, String> {
    let certificat = {
        let fingerprint = transaction.pubkey.as_str();
        match validateur.get_certificat(fingerprint).await {
            Some(e) => e.clone(),
            None => Err(format!("extraire_transaction Certificat {} introuvable", fingerprint))?,
        }
    };
    Ok(TransactionValide { transaction, certificat })
}

pub trait Transaction: Clone + Debug + Send + Sync {
    fn get_contenu(&self) -> &str;
    fn get_routage(&self) -> &RoutageMessage;
    fn get_id(&self) -> &str;
    fn get_uuid_transaction(&self) -> &str;
    fn get_estampille(&self) -> &DateTime<Utc>;
    fn get_enveloppe_certificat(&self) -> Option<&EnveloppeCertificat>;
    fn get_evenements(&self) -> &HashMap<String, Value>;

    fn convertir<S>(self) -> Result<S, Box<dyn Error>>
        where S: DeserializeOwned;
}

// #[derive(Clone, Debug, Deserialize)]
// /// Permet de charger une transaction MilleGrille
// pub struct DocumentTransactionMillegrille {
//     /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
//     pub id: String,
//
//     /// Cle publique du certificat utilise pour la signature
//     pub pubkey: String,
//
//     /// Date de creation du message
//     #[serde(with = "epochseconds")]
//     pub estampille: DateTime<Utc>,
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
//     #[serde(rename = "_evenements", skip_serializing_if = "Option::is_none")]
//     pub evenements: Option<HashMap<String, Value>>,
//
//     #[serde(skip)]
//     contenu_valide: Option<(bool, bool)>,
// }

// pub struct TransactionOwned {
//     pub message: MessageMilleGrillesOwned,
//     pub certificat: Arc<EnveloppeCertificat>,
// }
//
// impl TryInto<MessageValide> for TransactionOwned {
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
//             MessageKind::Document => Err(String::from("Non supporte"))?,
//             MessageKind::Requete |
//             MessageKind::Commande |
//             MessageKind::Transaction |
//             MessageKind::Evenement => {
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
//             MessageKind::Reponse => {
//
//             }
//             MessageKind::ReponseChiffree |
//             MessageKind::TransactionMigree |
//             MessageKind::CommandeInterMillegrille => {
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

// #[derive(Clone, Debug, Serialize)]
// pub struct TransactionImpl {
//     id: String,
//     pubkey: String,
//     estampille: DateTime<Utc>,
//     kind: u16,
//     contenu: String,
//     routage: RoutageMessage,
//     #[serde(rename="pre-migration")]
//     pre_migration: Option<HashMap<String, Value>>,
//     sig: String,
//     #[serde(rename="_evenements")]
//     evenements: HashMap<String, Value>,
//     #[serde(skip)]
//     enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
// }

// impl TransactionImpl {
//     pub fn new(enveloppe_transaction: Document, enveloppe_certificat: Option<Arc<EnveloppeCertificat>>) -> Result<TransactionImpl, Box<dyn Error>> {
//         let message_transaction: DocumentTransactionMillegrille = convertir_bson_deserializable(enveloppe_transaction)?;
//         let uuid_transaction = message_transaction.id;
//
//         // let entete = contenu.get_document(TRANSACTION_CHAMP_ENTETE).expect("en-tete");
//         let routage = match message_transaction.routage {
//             Some(inner) => inner,
//             None => Err(format!("transactions.TransactionImpl Routage absent de la transaction {}", uuid_transaction))?
//         };
//
//         let evenements = match message_transaction.evenements {
//             Some(inner) => inner,
//             None => HashMap::new()
//         };
//
//         Ok(TransactionImpl {
//             id: uuid_transaction,
//             pubkey: message_transaction.pubkey,
//             estampille: message_transaction.estampille.get_datetime().to_owned(),
//             kind: message_transaction.kind,
//             contenu: message_transaction.contenu,
//             routage,
//             pre_migration: message_transaction.pre_migration,
//             sig: message_transaction.signature,
//             evenements,
//             enveloppe_certificat,
//         })
//     }
//
//     pub fn set_evenements(&mut self, evenements: HashMap<String, Value>) {
//         self.evenements = evenements;
//     }
// }

// impl TryFrom<MessageSerialise> for TransactionImpl {
//     type Error = Box<dyn Error>;
//
//     fn try_from(value: MessageSerialise) -> Result<Self, Self::Error> {
//         let routage = match value.parsed.routage {
//             Some(inner) => inner,
//             None => Err(format!("TryFrom<MessageSerialise> for TransactionImpl Routage absent"))?
//         };
//         Ok(TransactionImpl {
//             id: value.parsed.id,
//             pubkey: value.parsed.pubkey,
//             estampille: value.parsed.estampille.get_datetime().to_owned(),
//             kind: value.parsed.kind,
//             contenu: value.parsed.contenu,
//             routage,
//             pre_migration: value.parsed.pre_migration,
//             sig: value.parsed.signature,
//             evenements: Default::default(),
//             enveloppe_certificat: value.certificat,
//         })
//     }
// }

// impl Transaction for TransactionImpl {
//
//     fn get_contenu(&self) -> &str {
//         self.contenu.as_str()
//     }
//
//     fn get_routage(&self) -> &RoutageMessage {
//         &self.routage
//     }
//
//     fn get_id(&self) -> &str {
//         &self.id
//     }
//
//     fn get_uuid_transaction(&self) -> &str {
//         self.get_id()
//     }
//
//     fn get_estampille(&self) -> &DateTime<Utc> {
//         &self.estampille
//     }
//
//     fn get_enveloppe_certificat(&self) -> Option<&EnveloppeCertificat> {
//         match &self.enveloppe_certificat {
//             Some(e) => Some(e.as_ref()),
//             None => None,
//         }
//     }
//
//     fn get_evenements(&self) -> &HashMap<String, Value> {
//         &self.evenements
//     }
//
//     fn convertir<S>(self) -> Result<S, Box<dyn Error>>
//         where S: DeserializeOwned
//     {
//         Ok(serde_json::from_str(self.contenu.as_str())?)
//     }
// }

// impl VerificateurPermissions for TransactionImpl {
//     fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
//         match &self.enveloppe_certificat {
//             Some(e) => e.get_extensions(),
//             None => None,
//         }
//     }
// }

// #[derive(Clone, Debug, Serialize)]
// pub struct TransactionPersistee {
//     id: String,
//     pubkey: String,
//     estampille: DateEpochSeconds,
//     kind: u16,
//     contenu: String,
//     routage: RoutageMessage,
//     #[serde(rename="pre-migration", skip_serializing_if = "Option::is_none")]
//     pre_migration: Option<HashMap<String, Value>>,
//     sig: String,
//     #[serde(rename="_evenements")]
//     pub evenements: Map<String, Value>,
// }

// impl TryFrom<MessageSerialise> for TransactionPersistee {
//     type Error = Box<dyn Error>;
//
//     fn try_from(mut value: MessageSerialise) -> Result<Self, Self::Error> {
//         let routage = match value.parsed.routage {
//             Some(inner) => inner,
//             None => Err(format!("TryFrom<MessageSerialise> for TransactionPersistee Routage absent"))?
//         };
//
//         let evenements = match value.parsed.attachements.take() {
//             Some(inner) => match inner.get("evenements") {
//                 Some(evenements) => match evenements.as_object() {
//                     Some(inner) => inner.to_owned(),
//                     None => {
//                         debug!("attachements.evenements - mauvais format (pas dict) (1)");
//                         Map::new()
//                     }
//                 },
//                 None => {
//                     debug!("attachements.evenements absent (2)");
//                     Map::new()
//                 }
//             },
//             None => {
//                 debug!("attachements absent (3)");
//                 Map::new()
//             }
//         };
//
//         Ok(TransactionPersistee {
//             id: value.parsed.id,
//             pubkey: value.parsed.pubkey,
//             estampille: value.parsed.estampille,
//             kind: value.parsed.kind,
//             contenu: value.parsed.contenu,
//             routage,
//             pre_migration: value.parsed.pre_migration,
//             sig: value.parsed.signature,
//             evenements,
//         })
//     }
// }

pub enum EtatTransaction {
    Complete,
}

pub async fn marquer_transaction<'a, M, S, T>(middleware: &M, nom_collection: S, uuid_transaction: T, etat: EtatTransaction)
    -> Result<(), String>
    where
        M: MongoDao,
        S: AsRef<str>,
        T: AsRef<str>,
{

    let mut set = doc! {};
    let mut current_date = doc! {};
    let uuid_transaction_str = uuid_transaction.as_ref();

    match etat {
        EtatTransaction::Complete => {
            set.insert("_evenements.transaction_complete", Bson::Boolean(true));
            current_date.insert("_evenements.transaction_traitee", Bson::Boolean(true));
        },
    };

    let ops = doc! {
        "$set": set,
        "$currentDate": current_date,
    };
    let filtre = doc! {
        TRANSACTION_CHAMP_ID: uuid_transaction_str,
    };

    let collection = middleware.get_collection(nom_collection.as_ref())?;
    match collection.update_one(filtre, ops, None).await {
        Ok(update_result) => {
            if update_result.matched_count == 1 {
                Ok(())
            } else {
                Err(format!("Erreur update transaction {}, aucun match", uuid_transaction_str))
            }
        },
        Err(e) => Err(format!("Erreur maj etat transaction {} : {:?}", uuid_transaction_str, e)),
    }
}

/// Resoumet une batch de transaction non completee pour chaque collection.
pub async fn resoumettre_transactions(middleware: &(impl GenerateurMessages + MongoDao), collections_transactions: &Vec<String>) -> Result<(), String> {

    debug!("Resoumettre transactions incompletes pour {:?}", collections_transactions);
    if middleware.mq_disponible() == false {
        Err("MQ n'est pas disponible, resoumission des transactions annulee")?;
    };

    // Date d'expiration des transactions est 15 minutes apres date de persistence.
    let exp_transactions = chrono::Utc::now() - chrono::Duration::days(15);

    for nom_collection in collections_transactions {
        let collection =
            middleware.get_collection_typed::<TransactionRef>(nom_collection.as_str())?;

        // Marquer les tranactions avec un compteur de resoumission >= limite comme abandonnees (erreur).
        let filtre_expiree = doc! {
            TRANSACTION_CHAMP_EVENEMENT_COMPLETE: false,
            "$or": [
                {TRANSACTION_CHAMP_COMPTE_RESOUMISE: {"$gte": TRANSACTION_LIMITE_RESOUMISSION}},
                {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: {"$lt": exp_transactions}},
            ]
        };
        let ops = doc! {
            "$set": { TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true },
            "$currentDate": {
                TRANSACTION_CHAMP_ERREUR_RESOUMISSION: true,
                TRANSACTION_CHAMP_ERREUR_TRAITEMENT: true,
            }
        };
        match collection.update_many(filtre_expiree, ops, None).await {
            Ok(r) => {
                if r.modified_count == 0 {
                    debug!("Aucunes transactions marquees en erreur.");
                } else {
                    warn!("Marquer {} transactions de {} comme erreur non-recuperable (resoumises trop de fois ou expiree)", r.modified_count, nom_collection)
                }
            },
            Err(e) => error!("resoumettre_transactions: Erreur resoumission transactions domaine {} : {:?}", nom_collection, e)
        }

        // Charger une batch de transactions non-completee par ordre de document_persiste
        // et resoumettre les triggers vers MQ. Incrementer le compteur de resoumission.
        let filtre_incomplets = doc! {
            TRANSACTION_CHAMP_EVENEMENT_COMPLETE: false,
        };
        let sort_incomplets = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
        // let projection_incomplets = doc! {
        //     TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: 1,
        // };
        let hint_incomplets = Hint::Name("transaction_complete".into());
        let options_incomplets = FindOptions::builder()
            // .projection(projection_incomplets)
            .sort(sort_incomplets)
            .hint(hint_incomplets)
            .limit(1000)
            .build();
        let mut curseur = match collection.find(filtre_incomplets, options_incomplets).await {
            Ok(c) => c,
            Err(e) => {
                error!("resoumettre_transactions: Erreur curseur transactions a resoumettre domaine {} : {:?}", nom_collection, e);
                continue
            }
        };
        let ops = doc! {
            "$inc": { TRANSACTION_CHAMP_COMPTE_RESOUMISE: 1 },
            "$currentDate": { TRANSACTION_CHAMP_DATE_RESOUMISE: true }
        };
        // while let Some(Ok(transaction)) = curseur.next().await {
        while match curseur.advance().await { Ok(inner) => inner, Err(e) => Err(String::from("Erreur curseur.advance"))?} {
            let transaction = match curseur.deserialize_current() {
                Ok(inner) => inner,
                Err(e) => {
                    warn!("Transaction mal formattee dans {} : {:?}", nom_collection, e);
                    continue
                }
            };
            let filtre_transaction_resoumise = doc! {"id": &transaction.id};

            let resultat = resoumettre(middleware, &transaction).await;

            match resultat {
                Ok(_) => {
                    let _ = collection.update_one(filtre_transaction_resoumise, ops.clone(), None).await;
                },
                Err(e) => {
                    error!("resoumettre_transactions: Erreur emission trigger de resoumission : {:?}", e);
                    if ! e.recuperable {
                        // Erreur qui n'est pas necessairement recuperable (e.g. data, autre...)
                        // On marque l'essaie.
                        let _ = collection.update_one(filtre_transaction_resoumise, ops.clone(), None).await;
                    }
                }
            }
        }

    }

    Ok(())
}

async fn resoumettre<'a, M>(middleware: &M, transaction: &TransactionRef<'a>) -> Result<(), ErreurResoumission>
where
    M: GenerateurMessages + MongoDao
{
    // let message_ids: MessageMilleGrilleIdentificateurs = match convertir_bson_deserializable(d.clone()) {
    //     Ok(inner) => inner,
    //     Err(e) => {
    //         error!("Identificateurs transactions illisibles, transaction ne peut pas etre re-emise {:?}Transaction: \n{:?}", e, d);
    //         Err(ErreurResoumission::new(false, None::<String>))?
    //     }
    // };

    let uuid_transaction = transaction.id;

    let routage = match &transaction.routage {
        Some(inner) => inner,
        None => {
            error!("Identificateurs routage absents, transaction ne peut pas etre re-emise. Message id: {}", uuid_transaction);
            Err(ErreurResoumission::new(false, Some(uuid_transaction.to_string())))?
        }
    };

    let domaine = match routage.domaine.as_ref() {
        Some(d) => *d,
        None => {
            error!("Domaine absent, transaction ne peut etre re-emise : {}", uuid_transaction);
            Err(ErreurResoumission::new(false, Some(uuid_transaction)))?
        }
    };
    let action = match routage.action.as_ref() {
        Some(a) => *a,
        None => {
            error!("Action absente, transaction ne peut etre re-emise : {}", uuid_transaction);
            Err(ErreurResoumission::new(false, Some(uuid_transaction)))?
        }
    };
    let partition = match routage.partition.as_ref() {
        Some(p) => Some(p.to_string()),
        None => None
    };

    debug!("Transaction a resoumettre : {}", uuid_transaction);
    let resultat = transmettre_evenement_persistance(
        middleware, uuid_transaction, domaine, action, partition.as_ref(), None, None).await;

    match &resultat {
        Ok(()) => {
            Ok(())
        },
        Err(_e) => {
            error!("Erreur resoumission transaction avec mongo : {:?}", resultat);
            Err(ErreurResoumission::new(true, Some(uuid_transaction)))
        }
    }
}

#[derive(Clone, Debug)]
struct ErreurResoumission {
    recuperable: bool,
    uuid_transaction: Option<String>,
}
impl ErreurResoumission {
    fn new<S: Into<String>>(recuperable: bool, uuid_transaction: Option<S>) -> Self {
        let uuid_string = match uuid_transaction {
            Some(u) => Some(u.into()),
            None => None,
        };
        ErreurResoumission {
            recuperable,
            uuid_transaction: uuid_string,
        }
    }
}

pub async fn sauvegarder_batch<'a, M>(middleware: &M, nom_collection: &str, mut transactions: Vec<&mut TransactionOwned>)
    -> Result<ResultatBatchInsert, String>
    where M: MongoDao
{
    let collection = match middleware.get_collection(nom_collection) {
        Ok(c) => c,
        Err(_e) => Err(format!("Erreur ouverture collection {}", nom_collection))?
    };

    // Determiner les transactions qui existent deja (dedupe)
    let mut transactions_bson = Vec::new();
    transactions_bson.reserve(transactions.len());
    {
        // let mut uuid_transactions = HashSet::new();
        // let mut curseur = {
        //     for t in &transactions {
        //         uuid_transactions.insert(t.id.clone());
        //     }
        //     let projection = doc! {"id": 1};
        //     let vec_uuid_transactions = uuid_transactions.iter().collect::<Vec<&String>>();
        //     let filtre = doc! {"id": {"$in": vec_uuid_transactions}};
        //     let options = FindOptions::builder()
        //         .projection(projection)
        //         .hint(Hint::Name("index_champ_id".into()))
        //         .build();
        //     match collection.find(filtre, options).await {
        //         Ok(c) => c,
        //         Err(e) => Err(format!("sauvegarder_batch Erreur collection.find : {:?}",e ))?
        //     }
        // };
        //
        // // Retirer tous les uuid_transactions connus, on va les ignorer
        // while let Some(result_uuid_transactions) = curseur.next().await {
        //     let doc_uuid_transactions = match result_uuid_transactions {
        //         Ok(d) => d,
        //         Err(e) => Err(format!("sauvegarder_batch Erreur curseur.next() : {:?}", e))?
        //     };
        //     let row_uuid_transaction: RowResultatUuidTransaction = match convertir_bson_deserializable(doc_uuid_transactions) {
        //         Ok(r) => r,
        //         Err(e) => Err(format!("sauvegarder_batch Erreur convertir_bson_deserializable RowResultatUuidTransaction : {:?}", e))?
        //     };
        //     // Retirer les transactions qui existent deja (connues)
        //     let uuid_transaction = row_uuid_transaction.id;
        //     uuid_transactions.remove(uuid_transaction.as_str());
        // }

        // Serialiser les transactions vers le format bson
        while let Some(mut t) = transactions.pop() {
            debug!("sauvegarder_batch Message a serialiser en bson Id: {}", t.id);

            // Injecter backup flag true (c'est une restoration, le backup existe deja)
            let evenements = match t.evenements.as_mut() {
                Some(inner) => inner,
                None => {
                    t.evenements = Some(EvenementsTransaction::new());
                    t.evenements.as_mut().unwrap()
                }
            };
            match evenements.backup_flag.clone() {
                Some(true) => {
                    // Ok
                },
                _ => {
                    // Set flag a true
                    // evenements.insert("backup_flag".into(), Value::Bool(true));
                    evenements.backup_flag = Some(true);
                }
            }

            let bson_doc = bson::to_document(&t).expect("serialiser bson");
            transactions_bson.push(bson_doc);
        }

    }

    debug!("Soumettre batch transactions dans collection {} : {:?}", nom_collection, transactions_bson);
    if transactions_bson.is_empty() {
        debug!("sauvegarder_batch Aucune transaction a soumettre, abort");
        let mut res_insert = ResultatBatchInsert::new();
        res_insert.inserted = 0;
        return Ok(res_insert)
    }

    let options = InsertManyOptions::builder()
        .ordered(false)
        .build();

    let nombre_transactions = transactions_bson.len() as u32;
    let resultat = match collection.insert_many(transactions_bson, Some(options)).await {
        Ok(r) => {
            let mut res_insert = ResultatBatchInsert::new();
            res_insert.inserted = r.inserted_ids.len() as u32;
            Ok(res_insert)
        },
        Err(e) => {
            let mut res_insert = ResultatBatchInsert::new();
            match e.kind.as_ref() {
                ErrorKind::BulkWrite(failure) => {
                    // Verifier si toutes les erreurs sont des duplicatas (code 11000)
                    debug!("Resultat bulk write : {:?}", failure);

                    let autres_erreurs = match &failure.write_errors {
                        Some(we) => {
                            let mut res = Vec::new();
                            for bwe in we {
                                // Separer erreurs duplication (11000) des autres
                                if bwe.code == 11000 {
                                    // Erreur duplication, OK.
                                    res_insert.duplicate += 1;
                                } else {
                                    res.push(bwe.to_owned());
                                    res_insert.errors += 1;
                                }
                            }

                            if res.len() > 0 {
                                Some(res)
                            } else {
                                None
                            }
                        },
                        None => None,
                    };

                    if autres_erreurs.is_some() {
                        Err(format!("Erreurs d'ecriture : {:?}", autres_erreurs))?;
                        res_insert.error_vec = autres_erreurs;
                    }

                    // Calculer le nombre d'insertion avec la difference entre total, dups et erreurs
                    res_insert.inserted = nombre_transactions - res_insert.duplicate - res_insert.errors;

                    Ok(res_insert)
                },
                _ => Err(format!("Erreur non supportee : {:?}", e))
            }
        }
    }?;
    // debug!("Resultat insertion transactions sous {} : {:?}", nom_collection, resultat);

    Ok(resultat)
}

#[derive(Clone, Debug, Deserialize)]
pub struct RowResultatUuidTransaction {
    // #[serde(rename="en-tete")]
    // entete: RowEnteteUuidTransaction
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RowEnteteUuidTransaction {
    uuid_transaction: String
}

#[derive(Clone, Debug)]
pub struct ResultatBatchInsert {
    pub inserted: u32,
    pub duplicate: u32,
    pub errors: u32,
    pub error_vec: Option<Vec<BulkWriteError>>,
}

impl ResultatBatchInsert {
    pub fn new() -> Self {
        ResultatBatchInsert {
            inserted: 0,
            duplicate: 0,
            errors: 0,
            error_vec: None,
        }
    }
}

#[derive(Serialize)]
struct EvenementRegeneration {
    ok: bool,
    termine: bool,
    domaine: String,
    position: Option<i64>,
    err: Option<String>,
}

pub async fn regenerer<M,D,T>(middleware: &M, nom_domaine: D, nom_collection_transactions: &str, noms_collections_docs: &Vec<String>, processor: &T)
    -> Result<(), crate::error::Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
    D: AsRef<str>,
    T: TraiterTransaction,
{
    let nom_domaine = nom_domaine.as_ref();
    debug!("transactions.regenerer Regenerer {}", nom_domaine);

    // Skip la validation des transactions si on charge CorePki (les certificats)
    let skip_certificats = nom_collection_transactions == DOMAINE_PKI;

    // Supprimer contenu des collections
    for nom_collection in noms_collections_docs {
        let collection = middleware.get_collection(nom_collection.as_str())?;
        let resultat_delete = collection.delete_many(doc! {}, None).await?;
        debug!("Delete collection {} documents : {:?}", nom_collection, resultat_delete);
    }

    // Creer curseur sur les transactions en ordre de traitement
    let resultat_transactions = {
        let filtre = doc! {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true},
        };
        let sort = doc! {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: 1,
        };

        let options = FindOptions::builder()
            .sort(sort)
            .hint(Hint::Name(String::from("backup_transactions")))
            .build();

        let collection_transactions = middleware.get_collection_typed::<TransactionRef>(nom_collection_transactions)?;
        if skip_certificats == false {
            let curseur_certs = collection_transactions.find(filtre.clone(), None).await?;
            regenerer_charger_certificats(middleware, curseur_certs, skip_certificats).await?;
        } else {
            info!("Regeneration CorePki - skip chargement certificats pour validation");
        }

        collection_transactions.find(filtre, options).await
    }?;

    {
        let routage = RoutageMessageAction::builder(nom_domaine, EVENEMENT_REGENERATION_MAJ, vec![Securite::L3Protege])
            .build();
        let message = EvenementRegeneration { ok: true, termine: false, domaine: nom_domaine.into(), position: Some(0), err: None };
        if let Err(e) = middleware.emettre_evenement(routage, &message).await {
            warn!("regenerer Erreur emission evenement maj regeneration : {:?}", e);
        }
    }

    middleware.set_regeneration(); // Desactiver emission de messages

    // Executer toutes les transactions du curseur en ordre
    if let Err(e) = regenerer_transactions(middleware, resultat_transactions, processor, skip_certificats).await {
        error!("regenerer Erreur regeneration domaine {} : {:?}", nom_domaine, e);
    } else {
        info!("transactions.regenerer Resultat regenerer {:?}", nom_collection_transactions);
    }

    middleware.reset_regeneration(); // Reactiver emission de messages

    {
        let routage = RoutageMessageAction::builder(nom_domaine, EVENEMENT_REGENERATION_MAJ, vec![Securite::L3Protege])
            .build();
        let message = EvenementRegeneration { ok: true, termine: true, domaine: nom_domaine.into(), position: None, err: None };
        if let Err(e) = middleware.emettre_evenement(routage, &message).await {
            warn!("regenerer Erreur emission evenement maj regeneration : {:?}", e);
        }
    }

    Ok(())
}

// fn get_entete_from_doc(doc: &Document) -> Result<Entete, Box<dyn Error>> {
//     let entete_bson = doc.get_document("en-tete")?;
//     let entete_value = serde_json::to_value(entete_bson)?;
//
//     Ok(serde_json::from_value(entete_value)?)
// }

// S'assurer d'avoir tous les certificats dans redis ou cache
async fn regenerer_charger_certificats<'a, M>(middleware: &M, mut curseur: Cursor<TransactionRef<'a>>, skip_certificats: bool)
    -> Result<(), crate::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    //while let Some(result) = curseur.next().await {
    while curseur.advance().await? {
        let transaction = curseur.deserialize_current()?;
        // let message = result?;

        // let message_identificateurs: MessageMilleGrilleIdentificateurs = match convertir_bson_deserializable(transaction.clone()) {
        //     Ok(inner) => inner,
        //     Err(_e) => {
        //         error!("transactions.regenerer_transactions Erreur transaction chargement identificateurs - ** SKIP **");
        //         continue  // Skip
        //     }
        // };

        // let entete = match get_entete_from_doc(&transaction) {
        //     Ok(t) => t,
        //     Err(_e) => {
        //         error!("transactions.regenerer_transactions Erreur transaction chargement en-tete - ** SKIP **");
        //         continue  // Skip
        //     }
        // };

        let fingerprint_certificat = transaction.pubkey;
        if middleware.get_certificat(fingerprint_certificat).await.is_none() {
            debug!("Certificat {} inconnu, charger via PKI", fingerprint_certificat);
            if requete_certificat(middleware, fingerprint_certificat).await?.is_none() {
                warn!("Certificat {} inconnu, ** SKIP **", fingerprint_certificat);
            }
        }
        if let Some(pre_migration) = transaction.pre_migration.as_ref() {
            if let Some(pubkey) = pre_migration.get("pubkey") {
                if let Some(pubkey_str) = pubkey.as_str() {
                    if middleware.get_certificat(pubkey_str).await.is_none() {
                        if skip_certificats == false {
                            debug!("Certificat pre-migration {} inconnu, charger via PKI", pubkey_str);
                            if requete_certificat(middleware, pubkey_str).await?.is_none() {
                                warn!("Certificat pre-migration Certificat {} inconnu, ** SKIP **", pubkey_str);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct PreMigration {
    id: Option<String>,
    #[serde(with = "optionepochseconds")]
    estampille: Option<DateTime<Utc>>,
    pubkey: Option<String>,
    idmg: Option<String>,
}

async fn regenerer_transactions<'a, M, T>(middleware: &M, mut curseur: Cursor<TransactionRef<'a>>, processor: &T, skip_certificats: bool)
    -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
    T: TraiterTransaction,
{
    // while let Some(result) = curseur.next().await {
    while curseur.advance().await? {
        let mut transaction = curseur.deserialize_current()?;
        // let mut message = result?;

        // //let entete = match get_entete_from_doc(&transaction) {
        // let message_identificateurs: MessageMilleGrilleIdentificateurs = match convertir_bson_deserializable(transaction.clone()) {
        //     Ok(t) => t,
        //     Err(_e) => {
        //         error!("transactions.regenerer_transactions Erreur transaction chargement en-tete - ** SKIP **");
        //         continue  // Skip
        //     }
        // };

        // let uuid_transaction = message_identificateurs.id.as_str();
        let message_id = transaction.id.to_owned();
        debug!("regenerer_transactions Traiter transaction : {:?}", message_id);

        // Charger pubkey du certificat - en cas de migration, utiliser certificat original
        let pre_migration = match &transaction.pre_migration {
            Some(inner) => {
                // Mapper pre-migration
                Some(serde_json::from_value::<PreMigration>(serde_json::to_value(inner)?)?)
            },
            None => None
        };

        let certificat = {
            let pubkey = match &transaction.kind {
                millegrilles_cryptographie::messages_structs::MessageKind::TransactionMigree => {
                    // &KIND_TRANSACTION_MIGREE => {
                    match &pre_migration {
                        Some(inner) => match inner.pubkey.as_ref() {
                            Some(inner) => inner.as_str(),
                            None => transaction.pubkey
                        },
                        None => transaction.pubkey
                    }
                },
                _ => transaction.pubkey
            };

            match middleware.get_certificat(pubkey).await {
                Some(c) => c,
                None => {
                    warn!("Certificat {} inconnu, ** SKIP **", pubkey);
                    continue;
                }
            }
        };
        let mut transaction = TransactionValide { transaction: transaction.try_into()?, certificat };

        if let Some(overrides) = pre_migration {
            if let Some(id) = overrides.id {
                debug!("Override attributs pre_migration dans la transaction, nouvel id {}", id);
                // transaction_impl.id = id;
                transaction.transaction.id = id;
            }
            if let Some(pubkey) = overrides.pubkey {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {}", pubkey);
                transaction.transaction.pubkey = pubkey;
            }
            if let Some(estampille) = overrides.estampille {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {:?}", estampille);
                transaction.transaction.estampille = estampille.clone();
            }
        }

        match processor.appliquer_transaction(middleware, transaction).await {
            Ok(_resultat) => (),
            Err(e) => error!("transactions.regenerer_transactions ** ERREUR REGENERATION {} ** {:?}", message_id, e)
        }
    }

    Ok(())
}

#[async_trait]
pub trait TraiterTransaction {
    async fn appliquer_transaction<M,T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: TryInto<TransactionValide> + Send;
}

/// Retourne le user_id dans la commande si certificat est exchange 2.prive, 3.protege ou 4.secure
/// Sinon retourne le user_id du certificat.
pub fn get_user_effectif<'a,T,M>(transaction: &T, transaction_mappee: &'a M) -> Result<String, crate::error::Error>
    where T: Transaction, M: CommandeUsager<'a>
{
    let enveloppe = match transaction.get_enveloppe_certificat() {
        Some(e) => e,
        None => Err(format!("transaction_supprimer_video Certificat inconnu, transaction ignoree"))?
    };

    if enveloppe.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        if let Some(user_id) = transaction_mappee.get_user_id() {
            return Ok(user_id.to_owned());
        }
    }

    match enveloppe.get_user_id()? {
        Some(inner) => Ok(inner.to_owned()),
        None => Err(format!("get_user_effectif user_id absent du certificat"))?
    }
}
