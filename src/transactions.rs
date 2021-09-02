use std::sync::Arc;

use bson::{Bson, Document};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use mongodb::{bson::{doc, to_bson}, Client, Database};
use mongodb::options::{FindOptions, Hint, UpdateOptions};
use serde_json::{json, Value};
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppeCertificat, ValidateurX509};
use crate::constantes::*;
use crate::formatteur_messages::MessageJson;
use crate::generateur_messages::GenerateurMessages;
use crate::mongo_dao::MongoDao;
use crate::recepteur_messages::MessageValideAction;

pub async fn transmettre_evenement_persistance(
    middleware: &impl GenerateurMessages,
    uuid_transaction: &str,
    domaine: &str,
    reply_to: Option<String>,
    correlation_id: Option<String>
) -> Result<(), String> {
    let mut evenement = json!({
        "uuid_transaction": uuid_transaction,
        "evenement": EVENEMENT_TRANSACTION_PERSISTEE,
        "domaine": domaine,
    });

    let mut evenement_map = evenement.as_object_mut().expect("map");

    if let Some(reply_to) = reply_to {
        evenement_map.insert("reply_to".into(), Value::from(reply_to));
    }

    if let Some(correlation_id) = correlation_id {
        evenement_map.insert("reply_to".into(), Value::from(correlation_id));
    }

    let rk = format!("evenement.{}.transaction_persistee", domaine);

    let message = MessageJson::new(evenement);

    middleware.emettre_evenement(&rk, &message, Some(vec!(Securite::L4Secure))).await
}

pub async fn charger_transaction(middleware: &(impl ValidateurX509 + MongoDao), m: &MessageValideAction) -> Result<TransactionImpl, String> {
    debug!("Traitement d'une transaction : {:?}", m);
    let trigger = &m.message;
    let entete = trigger.get_entete();
    let uuid_transaction = entete.uuid_transaction.as_str();

    // Charger transaction a partir de la base de donnees
    let collection = middleware.get_collection(PKI_COLLECTION_TRANSACTIONS_NOM)?;

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

pub trait Transaction {
    fn get_contenu(&self) -> &Document;
    fn get_entete(&self) -> &Document;
    fn get_domaine(&self) -> &str;
    fn get_action(&self) -> &str;
    fn get_uuid_transaction(&self) -> &str;
    fn get_estampille(&self) -> &DateTime<Utc>;
    fn get_enveloppe_certificat(&self) -> Option<&EnveloppeCertificat>;
    fn get_evenements(&self) -> &Document;
}

#[derive(Debug)]
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
        let domaine_action = String::from(entete.get_str(TRANSACTION_CHAMP_DOMAINE).expect("domaine"));

        let mut domaine_split = domaine_action.split(".");
        let domaine = domaine_split.next().expect("domaine").to_owned();
        let action = domaine_split.last().expect("action").to_owned();

        let uuid_transaction = String::from(entete.get_str(TRANSACTION_CHAMP_UUID_TRANSACTION).expect("domaine"));

        let evenements = contenu.get_document(TRANSACTION_CHAMP_EVENEMENTS).expect("_evenements");
        let estampille = evenements.get_datetime("_estampille").expect("_estampille").to_owned();

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

impl Transaction for TransactionImpl {
    fn get_contenu(&self) -> &Document {
        &self.contenu
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
}

pub enum EtatTransaction {
    Complete,
}

pub async fn marquer_transaction(middleware: &impl MongoDao, uuid_transaction: &str, etat: EtatTransaction) -> Result<(), String> {

    let mut set = doc! {};
    let mut current_date = doc! {};

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
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: uuid_transaction,
    };

    let collection = middleware.get_collection(PKI_COLLECTION_TRANSACTIONS_NOM)?;
    match collection.update_one(filtre, ops, None).await {
        Ok(update_result) => {
            if update_result.matched_count == 1 {
                Ok(())
            } else {
                Err(format!("Erreur update transaction {}, aucun match", uuid_transaction))
            }
        },
        Err(e) => Err(format!("Erreur maj etat transaction {} : {:?}", uuid_transaction, e)),
    }
}

/// Resoumet une batch de transaction non completee pour chaque collection.
pub async fn resoumettre_transactions(middleware: &(impl GenerateurMessages + MongoDao), domaine: &str, collections_transactions: &Vec<&str>) -> Result<(), String> {

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
        let projection_incomplets = doc! {
            TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: 1,
        };
        let hint_incomplets = Hint::Name("transaction_complete".into());
        let options_incomplets = FindOptions::builder()
            .projection(projection_incomplets)
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
            let uuid_transaction = d
                .get_document(TRANSACTION_CHAMP_ENTETE).expect(TRANSACTION_CHAMP_ENTETE)
                .get_str(TRANSACTION_CHAMP_UUID_TRANSACTION).expect(TRANSACTION_CHAMP_UUID_TRANSACTION);

            debug!("Transaction a resoumettre : {:?}", uuid_transaction);
            let resultat = transmettre_evenement_persistance(middleware, uuid_transaction, domaine, None, None).await;
            match resultat {
                Ok(_) => {
                    let filtre_transaction_resoumise = doc! {
                        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: uuid_transaction,
                    };
                    let _ = collection.update_one(filtre_transaction_resoumise, ops.clone(), None).await;
                },
                Err(e) => {
                    error!("Erreur emission trigger de resoumission pour {} {} : {:?}", domaine, uuid_transaction, e);
                }
            }
        }

    }

    Ok(())
}
