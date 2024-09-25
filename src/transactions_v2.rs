use std::borrow::Cow;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use log::{debug, error, info, warn};
use mongodb::bson::doc;
use mongodb::Cursor;
use mongodb::options::{FindOptions, Hint};
use tokio::join;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::backup_v2::{charger_cles_backup, lire_transactions_fichiers, organiser_fichiers_backup, RegenerationBackup, PATH_FICHIERS_BACKUP};
use crate::certificats::{charger_enveloppe, ValidateurX509};
use crate::constantes::*;
use crate::db_structs::{TransactionOwned, TransactionRef, TransactionValide};
use crate::domaines_traits::AiguillageTransactions;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::mongo_dao::MongoDao;
use crate::messages_generiques::EvenementRegeneration;
use crate::transactions::{regenerer_charger_certificats, TransactionCorePkiNouveauCertificat};
use crate::error::Error as CommonError;

pub async fn regenerer_v2<M,D,T>(
    middleware: &M, nom_domaine: D, nom_collection_transactions: &str,
    noms_collections_docs: &Vec<String>, processor: &T
)
    -> Result<(), crate::error::Error>
where
    M: GenerateurMessages + MongoDao + ValidateurX509 /*+ VerificateurMessage*/,
    D: AsRef<str>,
    T: AiguillageTransactions,
{
    let nom_domaine = nom_domaine.as_ref();
    debug!("regenerer_v2 Regenerer {}", nom_domaine);

    // Skip la validation des transactions si on charge CorePki (les certificats)
    let skip_certificats = nom_collection_transactions == DOMAINE_PKI;

    // Supprimer contenu des collections
    for nom_collection in noms_collections_docs {
        let collection = middleware.get_collection(nom_collection.as_str())?;
        let resultat_delete = collection.delete_many(doc! {}, None).await?;
        debug!("regenerer_v2 Delete collection {} documents : {:?}", nom_collection, resultat_delete);
    }

    // Traiter transactions dans les fichiers d'archive
    let path_backup = PathBuf::from(format!("{}/{}", PATH_FICHIERS_BACKUP, nom_domaine));
    let fichiers_backup = organiser_fichiers_backup(path_backup.as_path(), true).await?;
    let cles_backup = charger_cles_backup(middleware, nom_domaine, &fichiers_backup, None).await?;

    debug!("regenerer_v2 Path {:?}\n{} fichiers de backup, {} cles chargees", path_backup, fichiers_backup.len(), cles_backup.len());

    let (tx_transaction, rx_transaction) = mpsc::channel(2);
    let info_regeneration = RegenerationBackup {
        domaine: nom_domaine.to_string(),
        fichiers: fichiers_backup,
        cles: cles_backup,
    };
    let thread_lire_transactions = lire_transactions_fichiers(info_regeneration, tx_transaction);
    let thread_traiter_transactions = traiter_transactions_receiver(
        middleware, rx_transaction, processor, true);

    let (result_lire, result_traiter) = join![thread_lire_transactions, thread_traiter_transactions];
    result_lire?;
    result_traiter?;

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
    if let Err(e) = regenerer_transactions_v2(middleware, resultat_transactions, processor, skip_certificats).await {
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

async fn traiter_transactions_receiver<'a, M, T>(
    middleware: &M, mut rx: Receiver<TransactionOwned>, processor: &T, skip_certificats: bool)
    -> Result<(), CommonError>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
    T: AiguillageTransactions,
{
    loop {
        let transaction = match rx.recv().await {
            Some(inner) => inner,
            None => break  // Done
        };

        // let uuid_transaction = message_identificateurs.id.as_str();
        let message_id = transaction.id.to_owned();
        debug!("regenerer_transactions Traiter transaction id:{} => {:?}", message_id, transaction.routage);

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
                                debug!("Erreur chargement certificat via transaction CorePki (1) : {:?}", e);
                                continue
                            }
                        };
                        match charger_enveloppe(message.pem.as_str(), None, None) {
                            Ok(inner) => Arc::new(inner),
                            Err(e) => {
                                debug!("Erreur chargement certificat via transaction CorePki (2) : {:?}", e);
                                continue
                            }
                        }
                    } else {
                        warn!("transactions.regenerer_transactions Certificat {} inconnu, ** SKIP **", pubkey);
                        continue;
                    }
                }
            }
        };

        #[cfg(debug_assertions)]
        {
            debug!("transactions.regenerer_transactions Convertir en structure TransactionValide\n{}", transaction.contenu.as_str());
        }
        let mut transaction = TransactionValide {
            transaction: match transaction.try_into() {
                Ok(inner) => inner,
                Err(e) => {
                    warn!("transactions.regenerer_transactions Erreur transaction.try_into : {:?}, ** SKIP **", e);
                    continue
                }
            },
            certificat
        };

        if let Some(overrides) = pre_migration {
            if let Some(id) = overrides.id {
                debug!("Override attributs pre_migration dans la transaction, nouvel id {}", id);
                // transaction_impl.id = id;
                transaction.transaction.id = id.to_owned();
            }
            if let Some(pubkey) = overrides.pubkey {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {}", pubkey);
                transaction.transaction.pubkey = pubkey.to_owned();
            }
            if let Some(estampille) = &overrides.estampille {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {:?}", estampille);
                transaction.transaction.estampille = estampille.clone();
            }
        }

        debug!("transactions.regenerer_transactions Appliquer transaction");
        match processor.aiguillage_transaction(middleware, transaction).await {
            Ok(_resultat) => (),
            Err(e) => error!("transactions.regenerer_transactions ** ERREUR REGENERATION {} ** {:?}", message_id, e)
        }
    }

    Ok(())
}

async fn regenerer_transactions_v2<'a, M, T>(middleware: &M, mut curseur: Cursor<TransactionRef<'a>>, processor: &T, skip_certificats: bool)
                                             -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
    T: AiguillageTransactions,
{
    // while let Some(result) = curseur.next().await {
    while curseur.advance().await? {
        let mut transaction = match curseur.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                error!("transactions.regenerer_transactions Erreur transaction deserialize_current - ** SKIP **");
                continue  // Skip
            }
        };

        // let uuid_transaction = message_identificateurs.id.as_str();
        let message_id = transaction.id.to_owned();
        debug!("regenerer_transactions Traiter transaction id:{} => {:?}", message_id, transaction.routage);

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
                                debug!("Erreur chargement certificat via transaction CorePki (1) : {:?}", e);
                                continue
                            }
                        };
                        match charger_enveloppe(message.pem.as_str(), None, None) {
                            Ok(inner) => Arc::new(inner),
                            Err(e) => {
                                debug!("Erreur chargement certificat via transaction CorePki (2) : {:?}", e);
                                continue
                            }
                        }
                    } else {
                        warn!("transactions.regenerer_transactions Certificat {} inconnu, ** SKIP **", pubkey);
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
                    error!("Erreur conversion contenu {:?}", e);
                    "**erreur**".to_string()
                }
            };
            debug!("transactions.regenerer_transactions Convertir en structure TransactionValide\n{}", contenu_str);
        }
        let mut transaction = TransactionValide {
            transaction: match transaction.try_into() {
                Ok(inner) => inner,
                Err(e) => {
                    warn!("transactions.regenerer_transactions Erreur transaction.try_into : {:?}, ** SKIP **", e);
                    continue
                }
            },
            certificat
        };

        if let Some(overrides) = pre_migration {
            if let Some(id) = overrides.id {
                debug!("Override attributs pre_migration dans la transaction, nouvel id {}", id);
                // transaction_impl.id = id;
                transaction.transaction.id = id.to_owned();
            }
            if let Some(pubkey) = overrides.pubkey {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {}", pubkey);
                transaction.transaction.pubkey = pubkey.to_owned();
            }
            if let Some(estampille) = &overrides.estampille {
                debug!("Override attributs pre_migration dans la transaction, nouveau pubkey {:?}", estampille);
                transaction.transaction.estampille = estampille.clone();
            }
        }

        debug!("transactions.regenerer_transactions Appliquer transaction");
        match processor.aiguillage_transaction(middleware, transaction).await {
            Ok(_resultat) => (),
            Err(e) => error!("transactions.regenerer_transactions ** ERREUR REGENERATION {} ** {:?}", message_id, e)
        }
    }

    Ok(())
}
