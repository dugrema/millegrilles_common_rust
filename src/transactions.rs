use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use mongodb::{bson::{doc, to_bson}, Client, Collection, Cursor, Database};
use mongodb::bson as bson;
use mongodb::bson::{Bson, Document};
use mongodb::error::{BulkWriteError, BulkWriteFailure, ErrorKind};
use mongodb::options::{FindOptions, Hint, InsertManyOptions, UpdateOptions};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppeCertificat, ExtensionsMilleGrille, ValidateurX509, VerificateurPermissions};
use crate::constantes::*;
use crate::formatteur_messages::{Entete, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::mongo_dao::MongoDao;
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::{MessageTrigger, MessageValideAction};
use std::convert::{TryInto, TryFrom};
use std::fmt::Debug;
use std::borrow::Borrow;

pub async fn transmettre_evenement_persistance<S>(
    middleware: &impl GenerateurMessages,
    uuid_transaction: S,
    domaine: S,
    action: S,
    partition: Option<&String>,
    reply_to: Option<&String>,
    correlation_id: Option<&String>
) -> Result<(), String>
    where S: AsRef<str>
{
    let mut evenement = json!({
        "uuid_transaction": uuid_transaction.as_ref(),
        "evenement": EVENEMENT_TRANSACTION_PERSISTEE,
        "domaine": domaine.as_ref(),
        "action": action.as_ref(),
        "partition": partition,
    });

    let mut evenement_map = evenement.as_object_mut().expect("map");

    if let Some(reply_to) = reply_to {
        evenement_map.insert("reply_to".into(), Value::from(reply_to.to_owned()));
    }

    if let Some(correlation_id) = correlation_id {
        evenement_map.insert("correlation_id".into(), Value::from(correlation_id.to_owned()));
    }

    let routage = RoutageMessageAction::builder(domaine.as_ref(), EVENEMENT_TRANSACTION_PERSISTEE)
        .exchanges(vec!(Securite::L4Secure))
        .build();

    Ok(middleware.emettre_evenement(routage, &evenement).await?)
}

#[derive(Clone, Debug, Deserialize)]
pub struct TriggerTransaction {
    domaine: String,
    evenement: String,
    uuid_transaction: String,
}

pub async fn charger_transaction<M>(middleware: &M, nom_collection: &str, trigger: &TriggerTransaction) -> Result<TransactionImpl, String>
where
    M: ValidateurX509 + MongoDao,
{
    debug!("Traitement d'une transaction : {:?}", trigger);
    // let trigger = &m.message;
    // let entete = trigger.get_entete();
    // let contenu = &m.message.get_msg().contenu;
    let uuid_transaction = trigger.uuid_transaction.as_str();

    // Charger transaction a partir de la base de donnees
    let collection = middleware.get_collection(nom_collection)?;

    let filtre = doc! {TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: uuid_transaction};

    match collection.find_one(filtre, None).await {
        Ok(d) => match d {
            Some(d) => extraire_transaction(middleware, d).await,
            None => Err(format!("Transaction introuvable : {}", uuid_transaction)),
        },
        Err(e) => Err(format!("Erreur chargement transaction {} : {:?}", uuid_transaction, e)),
    }
}

async fn extraire_transaction(validateur: &(impl ValidateurX509), doc_transaction: Document) -> Result<TransactionImpl, String> {
    let entete = doc_transaction.get_document(TRANSACTION_CHAMP_ENTETE).expect("en-tete");
    let fingerprint = entete.get_str(TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT).expect("fingerprint_certificat");
    let enveloppe = match validateur.get_certificat(fingerprint).await {
        Some(e) => Some(e.clone()),
        None => None,
    };

    Ok(TransactionImpl::new(doc_transaction, enveloppe))
}

pub trait Transaction: Clone + Debug + Send + Sync {
    fn get_contenu(&self) -> &Document;
    fn contenu(self) -> Document;
    fn get_entete(&self) -> &Document;
    fn get_domaine(&self) -> &str;
    fn get_action(&self) -> &str;
    fn get_uuid_transaction(&self) -> &str;
    fn get_estampille(&self) -> &DateTime<Utc>;
    fn get_enveloppe_certificat(&self) -> Option<&EnveloppeCertificat>;
    fn get_evenements(&self) -> &Document;

    fn convertir<S>(self) -> Result<S, Box<dyn Error>>
        where S: DeserializeOwned;
}

#[derive(Clone, Debug)]
pub struct TransactionImpl {
    contenu: Document,
    domaine: String,
    action: String,
    uuid_transaction: String,
    estampille: DateTime<Utc>,
    enveloppe_certificat: Option<Arc<EnveloppeCertificat>>,
}

impl TransactionImpl {
    pub fn new(contenu: Document, enveloppe_certificat: Option<Arc<EnveloppeCertificat>>) -> TransactionImpl {

        let entete = contenu.get_document(TRANSACTION_CHAMP_ENTETE).expect("en-tete");
        let domaine = String::from(entete.get_str(TRANSACTION_CHAMP_DOMAINE).expect("domaine"));
        let action = String::from(entete.get_str(TRANSACTION_CHAMP_ACTION).expect("action"));

        // let mut domaine_split = domaine_action.split(".");
        // let domaine = domaine_split.next().expect("domaine").to_owned();
        // let action = domaine_split.last().expect("action").to_owned();

        let uuid_transaction = String::from(entete.get_str(TRANSACTION_CHAMP_UUID_TRANSACTION).expect("domaine"));

        let evenements = contenu.get_document(TRANSACTION_CHAMP_EVENEMENTS).expect("_evenements");
        let estampille = evenements.get_datetime("_estampille").expect("_estampille").to_chrono();

        TransactionImpl {
            contenu,
            domaine,
            action,
            uuid_transaction,
            estampille,
            enveloppe_certificat,
        }
    }
}

impl TryFrom<MessageSerialise> for TransactionImpl {
    type Error = Box<dyn Error>;

    fn try_from(value: MessageSerialise) -> Result<Self, Self::Error> {
        let entete = value.get_entete();
        let domaine = match &entete.domaine {
            Some(d) => d.to_owned(),
            None => Err(format!("Domaine absent"))?
        };
        let action = match &entete.action {
            Some(a) => a.to_owned(),
            None => Err(format!("Action absente"))?
        };

        let contenu: Document = value.get_msg().map_contenu(None)?;

        Ok(TransactionImpl {
            contenu,
            domaine,
            action,
            uuid_transaction: entete.uuid_transaction.clone(),
            estampille: entete.estampille.get_datetime().to_owned(),
            enveloppe_certificat: value.certificat,
        })
    }
}

impl Transaction for TransactionImpl {
    fn get_contenu(&self) -> &Document {
        &self.contenu
    }

    fn contenu(mut self) -> Document {
        self.contenu
    }

    fn get_entete(&self) -> &Document {
        self.contenu.get_document(TRANSACTION_CHAMP_ENTETE).expect("en-tete")
    }

    fn get_domaine(&self) -> &str {
        &self.domaine
    }

    fn get_action(&self) -> &str {
        &self.action
    }

    fn get_uuid_transaction(&self) -> &str {
        &self.uuid_transaction
    }

    fn get_estampille(&self) -> &DateTime<Utc> {
        &self.estampille
    }

    fn get_enveloppe_certificat(&self) -> Option<&EnveloppeCertificat> {
        match &self.enveloppe_certificat {
            Some(e) => Some(e.as_ref()),
            None => None,
        }
    }

    fn get_evenements(&self) -> &Document {
        self.contenu.get_document(TRANSACTION_CHAMP_EVENEMENTS).expect("_evenements")
    }

    fn convertir<S>(self) -> Result<S, Box<dyn Error>>
        where S: DeserializeOwned
    {
        let content = serde_json::from_value(serde_json::to_value(self.contenu)?)?;
        Ok(content)
    }
}

impl VerificateurPermissions for TransactionImpl {
    fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
        match &self.enveloppe_certificat {
            Some(e) => e.get_extensions(),
            None => None,
        }
    }
}

pub enum EtatTransaction {
    Complete,
}

pub async fn marquer_transaction<'a, M, S>(middleware: &M, nom_collection: S, uuid_transaction: S, etat: EtatTransaction)
    -> Result<(), String>
    where
        M: MongoDao,
        S: AsRef<str>
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
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: uuid_transaction_str,
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
pub async fn resoumettre_transactions(middleware: &(impl GenerateurMessages + MongoDao), collections_transactions: &Vec<&str>) -> Result<(), String> {

    debug!("Resoumettre transactions incompletes pour {:?}", collections_transactions);
    if middleware.mq_disponible() == false {
        Err("MQ n'est pas disponible, resoumission des transactions annulee")?;
    };

    // Date d'expiration des transactions est 15 minutes apres date de persistence.
    let exp_transactions = chrono::Utc::now() - chrono::Duration::days(15);

    for nom_collection in collections_transactions {
        let collection = middleware.get_collection(nom_collection)?;

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
            Err(e) => error!("Erreur resoumission transactions domaine {} : {:?}", nom_collection, e)
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
                error!("Erreur curseur transactions a resoumettre domaine {} : {:?}", nom_collection, e);
                continue
            }
        };
        let ops = doc! {
            "$inc": { TRANSACTION_CHAMP_COMPTE_RESOUMISE: 1 },
            "$currentDate": { TRANSACTION_CHAMP_DATE_RESOUMISE: true }
        };
        while let Some(Ok(d)) = curseur.next().await {
            let id_doc = d.get("_id").expect("_id");
            let filtre_transaction_resoumise = doc! {"_id": id_doc};

            let resultat = resoumettre(middleware, &collection, &ops, d).await;

            match resultat {
                Ok(_) => {
                    let _ = collection.update_one(filtre_transaction_resoumise, ops.clone(), None).await;
                },
                Err(e) => {
                    error!("Erreur emission trigger de resoumission : {:?}", e);
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

async fn resoumettre<M>(middleware: &M, collection: &Collection<Document>, ops: &Document, d: Document) -> Result<(), ErreurResoumission>
where
    M: GenerateurMessages + MongoDao
{
    let entete_value = match d.get("en-tete") {
        Some(e) => e,
        None => {
            error!("Erreur chargement entete pour resoumission de {:?}", d);
            Err(ErreurResoumission::new(false, None::<String>))?
        },
    };
    let entete: Entete = match serde_json::from_value::<Entete>(serde_json::to_value(entete_value).expect("val")) {
        Ok(e) => e,
        Err(e) => {
            error!("En-tete illisible, transaction ne peut pas etre re-emise {:?}Transaction: \n{:?}", e, d);
            Err(ErreurResoumission::new(false, None::<String>))?
        }
    };

    let uuid_transaction = entete.uuid_transaction.as_str();
    let domaine = match &entete.domaine {
        Some(d) => d.as_str(),
        None => {
            error!("Domaine absent, transaction ne peut etre re-emise : {:?}", entete);
            Err(ErreurResoumission::new(false, Some(uuid_transaction)))?
        }
    };
    let action = match &entete.action {
        Some(a) => a.as_str(),
        None => {
            error!("Action absente, transaction ne peut etre re-emise : {:?}", entete);
            Err(ErreurResoumission::new(false, Some(uuid_transaction)))?
        }
    };
    let partition = match &entete.partition {
        Some(p) => Some(p),
        None => None
    };

    let filtre_transaction_resoumise = doc! {
                TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: uuid_transaction,
            };

    debug!("Transaction a resoumettre : {:?}", uuid_transaction);
    let resultat = transmettre_evenement_persistance(
        middleware, uuid_transaction, domaine, action, partition, None, None).await;

    match &resultat {
        Ok(()) => {
            Ok(())
        },
        Err(e) => {
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

pub async fn sauvegarder_batch<M>(middleware: &M, nom_collection: &str, mut transactions: Vec<MessageMilleGrille>) -> Result<ResultatBatchInsert, String>
where
    M: MongoDao,
{
    // Serialiser les transactions vers le format bson
    let mut transactions_bson = Vec::new();
    transactions_bson.reserve(transactions.len());
    while let Some(t) = transactions.pop() {
        debug!("Message a serialiser en bson : {:?}", t);
        let bson_doc = bson::to_document(&t).expect("serialiser bson");
        transactions_bson.push(bson_doc);
    }

    debug!("Soumettre batch transactions dans collection {} : {:?}", nom_collection, transactions_bson);
    let collection = match middleware.get_collection(nom_collection) {
        Ok(c) => c,
        Err(e) => Err(format!("Erreur ouverture collection {}", nom_collection))?
    };

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

                    Ok((res_insert))
                },
                _ => Err(format!("Erreur non supportee : {:?}", e))
            }
        }
    }?;
    // debug!("Resultat insertion transactions sous {} : {:?}", nom_collection, resultat);

    Ok(resultat)
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

pub async fn regenerer<M, T>(middleware: &M, nom_collection_transactions: &str, noms_collections_docs: &Vec<String>, processor: &T) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TraiterTransaction,
{
    // Supprimer contenu des collections
    for nom_collection in noms_collections_docs {
        let collection = middleware.get_collection(nom_collection.as_str())?;
        let resultat_delete = collection.delete_many(doc! {}, None).await?;
        debug!("Delete collection {} documents : {:?}", nom_collection, resultat_delete);
    }

    // Creer curseur sur les transactions en ordre de traitement
    let mut resultat_transactions = {
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

        let collection_transactions = middleware.get_collection(nom_collection_transactions)?;
        collection_transactions.find(filtre, options).await
    }?;

    middleware.set_regeneration(); // Desactiver emission de messages

    // Executer toutes les transactions du curseur en ordre
    let resultat = regenerer_transactions(middleware, &mut resultat_transactions, processor).await;

    middleware.reset_regeneration(); // Reactiver emission de messages

    resultat
}

fn get_entete_from_doc(doc: &Document) -> Result<Entete, Box<dyn Error>> {
    let entete_bson = doc.get_document("en-tete")?;
    let entete_value = serde_json::to_value(entete_bson)?;

    Ok(serde_json::from_value(entete_value)?)
}

async fn regenerer_transactions<M, T>(middleware: &M, curseur: &mut Cursor<Document>, processor: &T) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TraiterTransaction,
{
    while let Some(result) = curseur.next().await {
        let transaction = result?;
        // let message = MessageSerialise::from_serializable(transaction)?;

        let entete = match get_entete_from_doc(&transaction) {
            Ok(t) => t,
            Err(e) => {
                error!("Erreur transaction chargement en-tete");
                continue  // Skip
            }
        };
        let uuid_transaction = entete.uuid_transaction.as_str();

        // let entete = message.get_entete();
        debug!("Message serialise charge : {:?}", uuid_transaction);

        let certificat = middleware.get_certificat(entete.fingerprint_certificat.as_str()).await;

        //
        // let (uuid_transaction, domaine, action) = match entete.domaine.as_ref() {
        //     Some(inner_domaine) => {
        //         let uuid_transaction = entete.uuid_transaction.to_owned();
        //         let action = match &entete.action {
        //             Some(a) => a.to_owned(),
        //             None => {
        //                 error!("Erreur chargement transaction, entete sans action : {:?}", entete);
        //                 continue;  // Skip
        //             },
        //         };
        //         (uuid_transaction, inner_domaine.to_owned(), action)
        //     },
        //     None => {
        //         warn!("Transaction sans domaine - invalide: {:?}", message);
        //         continue  // Skip
        //     }
        // };
        //
        // debug!("Preparer MessageValideAction");
        //
        // let transaction_prep = MessageValideAction {
        //     message,
        //     reply_q: None,
        //     correlation_id: Some(uuid_transaction.to_owned()),
        //     routing_key: String::from("regeneration"),
        //     domaine,
        //     action,
        //     exchange: None,
        //     type_message: TypeMessageOut::Transaction,
        // };

        let transaction_impl = TransactionImpl::new(transaction, certificat);

        debug!("Traiter transaction");

        processor.traiter_transaction(middleware, transaction_impl).await?;
    }

    Ok(())
}

#[async_trait]
pub trait TraiterTransaction {
    async fn traiter_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao;
}