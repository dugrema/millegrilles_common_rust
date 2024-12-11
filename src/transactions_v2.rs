use std::borrow::Cow;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use mongodb::bson::{doc, Bson};
use mongodb::{bson, ClientSession, Cursor};
use mongodb::options::{FindOptions, Hint, UpdateOptions};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::{join, spawn};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::backup_v2::{charger_cles_backup, charger_cles_backup_message, extraire_stats_backup, lire_transactions_fichiers, organiser_fichiers_backup, FichierArchiveBackup, RegenerationBackup, StatsBackup, StatusRegeneration, PATH_FICHIERS_ARCHIVES};
use crate::certificats::{charger_enveloppe, ValidateurX509};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::db_structs::{TransactionOwned, TransactionRef, TransactionValide};
use crate::domaines_traits::AiguillageTransactions;
use crate::domaines_v2::GestionnaireDomaineSimple;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::mongo_dao::{start_transaction_regular, MongoDao};
use crate::messages_generiques::{CommandeRegenerer, EvenementRegeneration, ReponseCommande};
use crate::transactions::{regenerer_charger_certificats, EtatTransaction, TransactionCorePkiNouveauCertificat};
use crate::error::Error as CommonError;

pub async fn regenerer_v2<M,G,D,T>(
    middleware: &M, gestionnaire_domaine: &G, nom_domaine: D, nom_collection_transactions: &str,
    noms_collections_docs: &Vec<String>, processor: &T, commande: CommandeRegenerer, routage_reponse: RoutageMessageReponse
)
    -> Result<(), crate::error::Error>
where
    M: GenerateurMessages + MongoDao + ValidateurX509 + ConfigMessages /*+ VerificateurMessage*/,
    G: GestionnaireDomaineSimple,
    D: AsRef<str>,
    T: AiguillageTransactions,
{
    let nom_domaine = nom_domaine.as_ref();
    debug!("regenerer_v2 Regenerer {}", nom_domaine);

    // Skip la validation des transactions si on charge CorePki (les certificats)
    let skip_certificats = nom_collection_transactions == DOMAINE_PKI;

    // Drop collections
    for nom_collection in noms_collections_docs {
        let collection = middleware.get_collection(nom_collection.as_str())?;
        collection.drop(None).await?;
        debug!("regenerer_v2 Dropped collection {}", nom_collection);
    }
    // Recreate all indexes (idempotent)
    gestionnaire_domaine.preparer_database_mongodb(middleware).await?;
    let mut session = middleware.get_session().await?;

    // Traiter transactions dans les fichiers d'archive
    let path_backup = PathBuf::from(format!("{}/{}", PATH_FICHIERS_ARCHIVES, nom_domaine));
    let idmg = middleware.idmg();
    let fichiers_backup = organiser_fichiers_backup(path_backup.as_path(), idmg, true).await?;
    let stats_backup = extraire_stats_backup(middleware, nom_collection_transactions, &fichiers_backup).await?;
    let cles_backup = match commande.cles_chiffrees {
        Some(inner) => charger_cles_backup_message(middleware, inner).await?,
        None => charger_cles_backup(middleware, nom_domaine, &fichiers_backup, None).await?
    };

    debug!("regenerer_v2 Path {:?}\n{} fichiers de backup, {} cles chargees", path_backup, fichiers_backup.len(), cles_backup.len());
    let status_regeneration = Mutex::new(StatusRegeneration { nombre_transaction_traites: 0, done: false });

    let (tx_transaction, rx_transaction) = mpsc::channel(2);
    let info_regeneration = RegenerationBackup {
        domaine: nom_domaine.to_string(),
        fichiers: fichiers_backup,
        cles: cles_backup,
    };
    let thread_lire_transactions = lire_transactions_fichiers(info_regeneration, tx_transaction);
    let thread_traiter_transactions = traiter_transactions_receiver(
        middleware, nom_collection_transactions, rx_transaction, processor, skip_certificats, &status_regeneration, &mut session);
    let thread_status_updates = thread_regeneration_status_updates(
        middleware, nom_domaine, &stats_backup, &status_regeneration);

    // Repondre Ok immediatement au client pour indiquer que la regeneration est demarree
    info!("regenerer_v2 Debut regeneration domaine {}", nom_domaine);
    middleware.repondre(routage_reponse, ReponseCommande {ok: Some(true), message: None, err: None }).await?;
    let routage_regeneration = RoutageMessageAction::builder(nom_domaine, EVENEMENT_REGENERATION, vec![Securite::L3Protege])
        .build();

    // Desactiver emission de messages, met le domaine en mode regeneration
    middleware.set_regeneration();

    let (result_lire, _, result_status_updates) = join![
        thread_lire_transactions, thread_traiter_transactions, thread_status_updates];
    result_lire?;
    result_status_updates?;

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

    // Executer toutes les transactions du curseur en ordre
    let mut db_transaction_counter = 0u64;
    match regenerer_transactions_v2(middleware, nom_collection_transactions, resultat_transactions, processor, skip_certificats, &mut session).await {
        Ok(inner) => {
            db_transaction_counter = inner;
        },
        Err(e) => {
            error!("regenerer Erreur regeneration domaine {} : {:?}", nom_domaine, e);
        }
    }

    middleware.reset_regeneration(); // Reactiver emission de messages

    {
        let total_transactions = {
            let status_guard = status_regeneration.lock().expect("lock");
            let nb_transactions_archives = status_guard.nombre_transaction_traites;
            nb_transactions_archives + db_transaction_counter
        };
        // Emettre evenement de fin de regeneration
        let message_regeneration = EvenementRegeneration {
            ok: true,
            err: None,
            domaine: nom_domaine,
            event: "done",
            termine: true,
            position: Some(total_transactions),
            stats_backup: Some(&stats_backup),
        };
        if let Err(e) = middleware.emettre_evenement(routage_regeneration, &message_regeneration).await {
            warn!("regenerer Erreur emission evenement maj regeneration : {:?}", e);
        }
    }

    info!("regenerer_v2 Fin regeneration domaine {}", nom_domaine);

    Ok(())
}

async fn traiter_transactions_receiver<'a, M, T>(
    middleware: &M, nom_collection_transactions: &str, mut rx: Receiver<TransactionOwned>, processor: &T,
    skip_certificats: bool, status_regeneration: &Mutex<StatusRegeneration>, session: &mut ClientSession,
)
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: AiguillageTransactions,
{
    let mut transaction_counter = 0u64;
    #[cfg(debug_assertions)]
    let mut process_start = Utc::now().timestamp_micros();

    if let Err(e) = start_transaction_regular(session).await {
        panic!("Error starting new transaction: {:?}", e);
    }

    loop {
        let transaction = match rx.recv().await {
            Some(inner) => inner,
            None => break  // Done
        };

        if transaction_counter % 1000 == 0 {
            info!(target: "millegrilles_common_rust::rebuild_transaction", "traiter_transactions_receiver: Regeneration {} transactions processed, in progress ...", transaction_counter);
            if let Err(e) = session.commit_transaction().await {
                panic!("Error committing batch: {:?}", e);
            };
            if let Err(e) = start_transaction_regular(session).await {
                panic!("Error starting new transaction: {:?}", e);
            }
        }

        // let uuid_transaction = message_identificateurs.id.as_str();
        let message_id = transaction.id.to_owned();
        debug!("traiter_transactions_receiver Traiter transaction id:{} => {:?}", message_id, transaction.routage);
        let date_traitee = match transaction.evenements.as_ref() {
            Some(inner) => match inner.transaction_traitee.as_ref() {
                Some(inner) => inner.clone(),
                None => {
                    warn!("regenerer_transactions_v2 Transaction sans date de traitement, {} **SKIP**", message_id);
                    continue
                }
            },
            None => {
                // Skip
                warn!("regenerer_transactions_v2 Transaction sans evenements (date de traitement), {} **SKIP**", message_id);
                continue
            }
        };

        // Charger pubkey du certificat - en cas de migration, utiliser certificat original
        let pre_migration = transaction.pre_migration.clone();

        let certificat = {
            let pubkey = match &transaction.kind {
                millegrilles_cryptographie::messages_structs::MessageKind::TransactionMigree => {
                    // &KIND_TRANSACTION_MIGREE => {
                    match &pre_migration {
                        Some(inner) => match &inner.pubkey {
                            Some(inner) => inner,
                            None => &transaction.pubkey
                        },
                        None => &transaction.pubkey
                    }
                },
                _ => &transaction.pubkey
            };

            match middleware.get_certificat(pubkey).await {
                Some(c) => c,
                None => {
                    if skip_certificats {
                        // Reload de CorePki, tenter de charger l'enveloppe a partir du contenu
                        let message: TransactionCorePkiNouveauCertificat = match serde_json::from_str(transaction.contenu.as_str()) {
                            Ok(inner) => inner,
                            Err(e) => {
                                debug!("traiter_transactions_receiver Erreur chargement certificat via transaction CorePki (1) : {:?}", e);
                                continue
                            }
                        };
                        match charger_enveloppe(message.pem.as_str(), None, None) {
                            Ok(inner) => Arc::new(inner),
                            Err(e) => {
                                debug!("traiter_transactions_receiver Erreur chargement certificat via transaction CorePki (2) : {:?}", e);
                                continue
                            }
                        }
                    } else {
                        // Process normal mais certificat inconnu de CorePki
                        match transaction.certificat.as_ref() {
                            Some(inner) => {
                                match middleware.charger_enveloppe(inner, None, None).await {
                                    Ok(inner) => {
                                        info!("traiter_transactions_receiver Utilisation certificat {} inclus dans les transactions (inconnu de CorePki)", pubkey);
                                        inner
                                    },
                                    Err(_) => {
                                        warn!("traiter_transactions_receiver Certificat {} inclus dans la transaction est invalide, ** SKIP **", pubkey);
                                        continue;
                                    }
                                }
                            },
                            None => {
                                warn!("traiter_transactions_receiver Certificat {} inconnu, ** SKIP **", pubkey);
                                continue
                            }
                        }
                    }
                }
            }
        };

        #[cfg(debug_assertions)]
        {
            debug!("traiter_transactions_receiver Convertir en structure TransactionValide\n{}", transaction.contenu.as_str());
        }
        let mut transaction = TransactionValide {
            transaction: match transaction.try_into() {
                Ok(inner) => inner,
                Err(e) => {
                    warn!("traiter_transactions_receiver Erreur transaction.try_into : {:?}, ** SKIP **", e);
                    continue
                }
            },
            certificat
        };

        if let Some(overrides) = pre_migration {
            if let Some(id) = overrides.id {
                debug!("traiter_transactions_receiver Override attributs pre_migration dans la transaction, nouvel id {}", id);
                // transaction_impl.id = id;
                transaction.transaction.id = id.to_owned();
            }
            if let Some(pubkey) = overrides.pubkey {
                debug!("traiter_transactions_receiver Override attributs pre_migration dans la transaction, nouveau pubkey {}", pubkey);
                transaction.transaction.pubkey = pubkey.to_owned();
            }
            if let Some(estampille) = &overrides.estampille {
                debug!("traiter_transactions_receiver Override attributs pre_migration dans la transaction, nouveau pubkey {:?}", estampille);
                transaction.transaction.estampille = estampille.clone();
            }
        }

        #[cfg(debug_assertions)]
        let (start_processing, transaction_copy) = {
            let duration = Utc::now().timestamp_micros() - process_start;
            if duration > 150 {
                debug!(target: "millegrilles_common_rust::rebuild_transaction", "regenerer_transactions_v2 Transaction {}/{:?} other processing duration: {} us",
                    transaction.transaction.id, match transaction.transaction.routage.as_ref(){Some(inner)=>inner.action.as_ref(),None=>None}, duration);
            }

            (Utc::now().timestamp_micros(), transaction.transaction.clone())
        };

        debug!("traiter_transactions_receiver Appliquer transaction");
        match processor.aiguillage_transaction(middleware, transaction, session).await {
            Ok(_resultat) => {
                // S'assurer que la transaction est dans la collection DOMAINE/transactions_traitees
                if let Err(e) = upsert_transactions_traitees(
                    middleware, nom_collection_transactions, &message_id, EtatTransaction::Complete, Some(true), Some(date_traitee)).await {
                    error!("traiter_transactions_receiver ** ERREUR REGENERATION {} ** {:?}", message_id, e)
                }
            },
            Err(e) => error!("traiter_transactions_receiver ** ERREUR REGENERATION {} ** {:?}", message_id, e)
        }

        #[cfg(debug_assertions)]
        {
            let duration = Utc::now().timestamp_micros() - start_processing;
            if duration > 9_000 {
                debug!(target: "millegrilles_common_rust::rebuild_transaction", "regenerer_transactions_v2 Transaction {}/{:?} duration: {} us",
                    transaction_copy.id, match transaction_copy.routage.as_ref(){Some(inner)=>inner.action.as_ref(),None=>None}, duration);
            }
            process_start = Utc::now().timestamp_micros();  // Reset start of processing
        }

        // Update status
        transaction_counter += 1;
        {
            let mut guard = status_regeneration.lock().expect("lock");
            guard.nombre_transaction_traites = transaction_counter;
        }
    }

    if let Err(e) = session.commit_transaction().await {
        panic!("Error committing final transaction batch: {:?}", e);
    }

    // Mis a jour status, indique aux autres threads que le traitement est termine
    let mut guard = status_regeneration.lock().expect("lock");
    guard.done = true;

    info!("traiter_transactions_receiver: Regeneration {} transactions processed, done.", transaction_counter);
}

async fn regenerer_transactions_v2<'a, M, T>(
    middleware: &M, nom_collection_transactions: &str, mut curseur: Cursor<TransactionRef<'a>>, processor: &T,
    skip_certificats: bool, session: &mut ClientSession)
    -> Result<u64, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
    T: AiguillageTransactions,
{
    let mut counter = 0u64;

    // Session cleanup
    session.commit_transaction().await?;
    session.start_transaction(None).await?;

    // while let Some(result) = curseur.next().await {
    while curseur.advance().await? {
        counter += 1;
        let mut transaction = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(_) => {
                error!("regenerer_transactions_v2 Erreur transaction deserialize_current - ** SKIP **");
                continue  // Skip
            }
        };

        // let uuid_transaction = message_identificateurs.id.as_str();
        let transaction_id = transaction.id.to_owned();
        debug!("regenerer_transactions_v2 Traiter transaction id:{} => {:?}", transaction_id, transaction.routage);
        let date_traitee = match transaction.evenements.as_ref() {
            Some(inner) => match inner.transaction_traitee.as_ref() {
                Some(inner) => inner.clone(),
                None => {
                    warn!("regenerer_transactions_v2 Transaction sans date de traitement, {} **SKIP**", transaction_id);
                    continue
                }
            },
            None => {
                // Skip
                warn!("regenerer_transactions_v2 Transaction sans evenements (date de traitement), {} **SKIP**", transaction_id);
                continue
            }
        };

        // Charger pubkey du certificat - en cas de migration, utiliser certificat original
        let pre_migration = transaction.pre_migration.clone();

        let certificat = {
            let pubkey = match &transaction.kind {
                millegrilles_cryptographie::messages_structs::MessageKind::TransactionMigree => {
                    // &KIND_TRANSACTION_MIGREE => {
                    match &pre_migration {
                        Some(inner) => match inner.pubkey {
                            Some(inner) => inner,
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
                    if skip_certificats {
                        // Reload de CorePki, tenter de charger l'enveloppe a partir du contenu
                        let message: TransactionCorePkiNouveauCertificat = match serde_json::from_str(transaction.contenu()?.as_ref()) {
                            Ok(inner) => inner,
                            Err(e) => {
                                debug!("regenerer_transactions_v2 Erreur chargement certificat via transaction CorePki (1) : {:?}", e);
                                continue
                            }
                        };
                        match charger_enveloppe(message.pem.as_str(), None, None) {
                            Ok(inner) => Arc::new(inner),
                            Err(e) => {
                                debug!("regenerer_transactions_v2 Erreur chargement certificat via transaction CorePki (2) : {:?}", e);
                                continue
                            }
                        }
                    } else {
                        warn!("regenerer_transactions_v2 Certificat {} inconnu, ** SKIP **", pubkey);
                        continue;
                    }
                }
            }
        };

        #[cfg(debug_assertions)]
        {
            let contenu_str = match transaction.contenu() {
                Ok(inner) => match inner {
                    Cow::Borrowed(inner) => inner.to_string(),
                    Cow::Owned(inner) => inner
                },
                Err(e) => {
                    error!("regenerer_transactions_v2 Erreur conversion contenu {:?}", e);
                    "**erreur**".to_string()
                }
            };
            debug!("regenerer_transactions_v2 Convertir en structure TransactionValide\n{}", contenu_str);
        }
        let mut transaction = TransactionValide {
            transaction: match transaction.try_into() {
                Ok(inner) => inner,
                Err(e) => {
                    warn!("regenerer_transactions_v2 Erreur transaction.try_into : {:?}, ** SKIP **", e);
                    continue
                }
            },
            certificat
        };

        if let Some(overrides) = pre_migration {
            if let Some(id) = overrides.id {
                debug!("regenerer_transactions_v2 Override attributs pre_migration dans la transaction, nouvel id {}", id);
                // transaction_impl.id = id;
                transaction.transaction.id = id.to_owned();
            }
            if let Some(pubkey) = overrides.pubkey {
                debug!("regenerer_transactions_v2 Override attributs pre_migration dans la transaction, nouveau pubkey {}", pubkey);
                transaction.transaction.pubkey = pubkey.to_owned();
            }
            if let Some(estampille) = &overrides.estampille {
                debug!("regenerer_transactions_v2 Override attributs pre_migration dans la transaction, nouveau pubkey {:?}", estampille);
                transaction.transaction.estampille = estampille.clone();
            }
        }

        match processor.aiguillage_transaction(middleware, transaction, session).await {
            Ok(_resultat) => {
                upsert_transactions_traitees(
                    middleware, nom_collection_transactions, transaction_id, EtatTransaction::Complete, Some(true), Some(date_traitee)).await?;
            },
            Err(e) => error!("regenerer_transactions_v2 ** ERREUR REGENERATION {} ** {:?}", transaction_id, e)
        }
    }

    session.commit_transaction().await?;

    Ok(counter)
}


pub async fn upsert_transactions_traitees<'a, M, S, T>(
    middleware: &M, nom_collection: S, uuid_transaction: T, etat: EtatTransaction, ok: Option<bool>, date_traitee: Option<DateTime<Utc>>
)
    -> Result<(), CommonError>
where
    M: MongoDao,
    S: AsRef<str>,
    T: AsRef<str>,
{
    let date_traitee = date_traitee.unwrap_or_else(|| Utc::now());

    let mut set = doc! {};
    let transaction_id = uuid_transaction.as_ref();

    let bid_complete = hex::decode(transaction_id)?;
    let bid_truncated = &bid_complete[0..16];
    let bid_truncated_base64 = general_purpose::STANDARD.encode(bid_truncated);

    debug!("upsert_transactions_traitees Marquer id {} (bid: {:?}) complete", transaction_id, bid_truncated_base64);
    let bid_truncated_bson = Bson::Binary(bson::Binary::from_base64(bid_truncated_base64, None)
        .expect("bid_truncated_bson base64"));

    match etat {
        EtatTransaction::Complete => {
            set.insert("_evenements.transaction_complete", Bson::Boolean(true));
            set.insert("_evenements.transaction_traitee", Bson::DateTime(date_traitee.clone().into()));
        },
    };

    // Table transactions_traitees
    let filtre_transactions_traitees = doc! {
        "bid_truncated": &bid_truncated_bson,
    };

    let ops_transactions_traitees = doc!{
        "$setOnInsert": {
            TRANSACTION_CHAMP_ID: transaction_id,
            "date_traitement": &date_traitee,
        },
        "$set": {
            "ok": ok,
        },
    };
    let options = UpdateOptions::builder().upsert(true).build();
    let collection_traitees = middleware.get_collection(format!("{}/transactions_traitees", nom_collection.as_ref()))?;
    collection_traitees.update_one(filtre_transactions_traitees, ops_transactions_traitees, options).await?;

    Ok(())
}


pub async fn marquer_transaction_v2<'a, M, S, T>(middleware: &M, nom_collection: S, uuid_transaction: T, etat: EtatTransaction, ok: Option<bool>)
                                                 -> Result<(), CommonError>
where
    M: MongoDao,
    S: AsRef<str>,
    T: AsRef<str>,
{

    let date_now = Utc::now();
    let mut set = doc! {};
    let uuid_transaction_str = uuid_transaction.as_ref();

    let bid_complete = hex::decode(uuid_transaction_str)?;
    let bid_truncated = &bid_complete[0..16];
    let bid_truncated_base64 = general_purpose::STANDARD.encode(bid_truncated);

    debug!("marquer_transaction_v2 Marquer id {} (bid: {:?}) complete", uuid_transaction_str, bid_truncated_base64);
    let bid_truncated_bson = Bson::Binary(bson::Binary::from_base64(bid_truncated_base64, None)
        .expect("bid_truncated_bson base64"));

    match etat {
        EtatTransaction::Complete => {
            set.insert("_evenements.transaction_complete", Bson::Boolean(true));
            set.insert("_evenements.transaction_traitee", Bson::DateTime(date_now.clone().into()));
        },
    };

    // Table transactions avec ancienne methode
    let ops = doc! {
        "$set": set,
    };
    let filtre = doc! {
        TRANSACTION_CHAMP_ID: uuid_transaction_str,
    };

    // Nouvelle table transactions_traitees
    let filtre_transactions_traitees = doc! {
        "bid_truncated": &bid_truncated_bson,
    };

    let ops_transactions_traitees = doc!{
        "$setOnInsert": {
            TRANSACTION_CHAMP_ID: uuid_transaction_str,
        },
        "$set": {
            "ok": ok,
            "date_traitement": &date_now,
        },
    };
    let options = UpdateOptions::builder().upsert(true).build();

    let collection = middleware.get_collection(nom_collection.as_ref())?;
    let collection_traitees = middleware.get_collection(format!("{}/transactions_traitees", nom_collection.as_ref()))?;

    // Executer les deux operations
    match collection.update_one(filtre, ops, None).await {
        Ok(update_result) => {
            if update_result.matched_count == 1 {
                ()
            } else {
                Err(format!("Erreur update transaction {}, aucun match", uuid_transaction_str))?
            }
        },
        Err(e) => Err(format!("Erreur maj etat transaction {} : {:?}", uuid_transaction_str, e))?,
    };

    collection_traitees.update_one(filtre_transactions_traitees, ops_transactions_traitees, options).await?;

    Ok(())
}

// #[derive(Serialize)]
// struct RegenerationStatusUpdate<'a> {
//     stats_backup: &'a StatsBackup,
//     transaction_courante: u64,
//     done: bool,
//     event: &'a str,
// }

async fn thread_regeneration_status_updates<M>(middleware: &M, domaine: &str, stats_backup: &StatsBackup, status_regeneration: &Mutex<StatusRegeneration>)
    -> Result<(), CommonError>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(domaine, EVENEMENT_REGENERATION, vec![Securite::L3Protege])
        .build();

    // Emettre status debut de regeneration
    middleware.emettre_evenement(routage.clone(), EvenementRegeneration {
        ok: true,
        err: None,
        domaine,
        event: "start",
        termine: false,
        position: Some(0),
        stats_backup: Some(stats_backup),
    }).await?;

    let mut current_count = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
        {
            let guard = status_regeneration.lock().expect("lock");
            current_count = guard.nombre_transaction_traites;
            if guard.done {
                break;  // Complete
            }
        }

        // Emettre status de regeneration
        middleware.emettre_evenement(routage.clone(),EvenementRegeneration {
            ok: true,
            err: None,
            domaine,
            event: "update",
            termine: false,
            position: Some(current_count),
            stats_backup: Some(stats_backup),
        }).await?;
    }

    // Note: l'evenement de fin n'est pas emis ici parce qu'il peut rester des transactions a
    // traiter dans la base de donnees.
    // Emettre status de regeneration
    middleware.emettre_evenement(routage.clone(),EvenementRegeneration {
        ok: true,
        err: None,
        domaine,
        event: "update",
        termine: false,
        position: Some(current_count),
        stats_backup: Some(stats_backup),
    }).await?;

    Ok(())
}
