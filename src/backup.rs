use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::sync::{Arc, mpsc, Mutex};

use async_std::fs::File;
use async_std::prelude::FutureExt;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use futures::pin_mut;
use log::{debug, error, info, warn};

use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult, CipherResultVec, CleChiffrageHandler, CleChiffrageStruct};
use millegrilles_cryptographie::chiffrage_mgs4::CipherMgs4;
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, epochseconds, MessageMilleGrillesBufferDefault, MessageMilleGrillesRef, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::bson::{doc, Document};
use mongodb::Cursor;
use mongodb::options::{FindOptions, Hint};
use multibase::{Base, encode};
use multihash::Code;
use reqwest::Body;
use reqwest::multipart::Part;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tempfile::{TempDir, tempdir};
use tokio::fs::File as File_tokio;
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::try_join;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, Result as TokioResult};
use tokio::time::timeout;
use tokio_util::{bytes::Bytes, io::{ReaderStream, StreamReader}, codec::{BytesCodec, FramedRead}};
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::certificats::{CollectionCertificatsPem, ValidateurX509};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::constantes::Securite::{L2Prive, L3Protege};
use crate::db_structs::TransactionOwned;
use crate::fichiers::{CompressionChiffrageProcessor, FichierCompressionChiffrage, FichierCompressionResult};
use crate::formatteur_messages::FormatteurMessage;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::hachages::hacher_bytes;
use crate::middleware::IsConfigurationPki;
use crate::middleware_db::MiddlewareDb;
use crate::mongo_dao::{convertir_bson_deserializable, CurseurIntoIter, CurseurMongo, CurseurStream, MongoDao};
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use crate::error::Error as CommonError;

// Max size des transactions, on tente de limiter la taille finale du message
// decompresse a 5MB (bytes vers base64 augmente taille de 50%)
const TRANSACTIONS_DECOMPRESSED_MAX_SIZE: usize = 10 * 1024 * 1024;
const BACKUP_TRANSACTIONS_MAX_SIZE: usize = 9 * 1024 * 1024;
// const TRANSACTIONS_MAX_NB: usize = 10000;  // Limite du nombre de transactions par fichier

// Epoch en ms du demarrage du backup courant
// Utilise pour ignorer des flags de demande de backup recus durant le backup
const PERIODE_PROTECTION_FIN_COMPLET: i64 = 30_000;
static mut DERNIER_BACKUP_COMPLET_FIN_DOMAINES: Option<HashMap<String, i64>> = None;
const CONST_EVENEMENT_KEEPALIVE: &str = "keepAlive";

/// Handler de backup qui ecoute sur un mpsc. Lance un backup a la fois dans une thread separee.
pub async fn thread_backup<M>(middleware: Arc<M>, mut rx: Receiver<CommandeBackup>)
    where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler + 'static
{
    while let Some(commande) = rx.recv().await {
        let mut abandonner_backup = false;
        if commande.complet {
            // Protection de backup complet a repetition (reset toutes les transactions)
            let now = Utc::now().timestamp_millis();
            unsafe {
                let dernier_backup_complet = match DERNIER_BACKUP_COMPLET_FIN_DOMAINES.as_ref() {
                    Some(inner) => {
                        match inner.get(commande.nom_domaine.as_str()) {
                            Some(inner) => inner.to_owned(),
                            None => 0
                        }
                    },
                    None => {
                        DERNIER_BACKUP_COMPLET_FIN_DOMAINES = Some(HashMap::new());
                        0
                    }
                };
                if dernier_backup_complet > 0 && now - PERIODE_PROTECTION_FIN_COMPLET < dernier_backup_complet {
                    info!("thread_backup Backup complet deja termine recemment ({}:{}) - SKIP", commande.nom_domaine, dernier_backup_complet);
                    abandonner_backup = true;
                }
            }
        }

        if abandonner_backup {
            let routage = RoutageMessageReponse::new(commande.reply_q, commande.correlation_id);
            // let reponse = match middleware.formatter_reponse(json!({"ok": false, "code": 2}), None) {
            //     Ok(inner) => inner,
            //     Err(e) => {
            //         error!("backup.thread_backup Erreur reponse backup refuse (1.) domaine {} : {:?}", commande.nom_domaine, e);
            //         continue
            //     }
            // };

            // Emettre le message
            if let Err(e) = middleware.repondre(routage, json!({"ok": false, "code": 2})).await {
                error!("backup.thread_backup Erreur reponse backup refuse (2.) domaine {} : {:?}", commande.nom_domaine, e);
            }

            // Skip le backup
            continue
        }

        debug!("thread_backup Debut commande backup {:?}", commande);
        info!("Debut backup {}", commande.nom_domaine);
        match backup(middleware.as_ref(), &commande).await {
            Ok(_) => info!("Backup {} OK", commande.nom_domaine),
            Err(e) => error!("backup.thread_backup Erreur backup domaine {} : {:?}", commande.nom_domaine, e)
        };
        if commande.complet {
            unsafe {
                DERNIER_BACKUP_COMPLET_FIN_DOMAINES
                    .as_mut()
                    .expect("DERNIER_BACKUP_COMPLET_FIN_DOMAINES")
                    .insert(commande.nom_domaine.clone(), Utc::now().timestamp_millis());
            }  // Set flag fin complet
        }
    }
}


#[derive(Clone, Debug)]
pub struct CommandeBackup {
    pub nom_domaine: String,
    pub nom_collection_transactions: String,
    pub complet: bool,
    pub reply_q: String,
    pub correlation_id: String,
}

#[async_trait]
pub trait BackupStarter {
    fn get_tx_backup(&self) -> Sender<CommandeBackup>;

    async fn demarrer_backup<S,T,Q,C>(&self, nom_domaine: S, nom_collection_transactions: T, complet: bool, reply_q: Q, correlation_id: C)
        -> Result<(), crate::error::Error>
        where S: Into<String> + Send, T: Into<String> + Send, Q: Into<String> + Send, C: Into<String> + Send
    {
        let commande = CommandeBackup {
            nom_domaine: nom_domaine.into(),
            nom_collection_transactions: nom_collection_transactions.into(),
            complet,
            reply_q: reply_q.into(),
            correlation_id: correlation_id.into(),
        };

        let tx_backup = self.get_tx_backup();
        debug!("backup.BackupStarter Demarrage backup {:?}", &commande);
        if let Err(e) = tx_backup.send(commande).await {
            Err(crate::error::Error::String(format!("backup.BackupStarter Erreur send trigger demarrage : {:?}", e)))?
        }

        Ok(())
    }
}

/// Lance un backup complet de la collection en parametre.
pub async fn backup<M>(middleware: &M, commande: &CommandeBackup)
    -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
    where
        M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    let nom_coll_str = commande.nom_collection_transactions.as_str();
    let nom_domaine_str = commande.nom_domaine.as_str();

    {
        // Indiquer au processus trigger qu'on demarre le backup
        let routage = RoutageMessageReponse::new(&commande.reply_q, &commande.correlation_id);
        middleware.repondre(routage, json!({"ok": true, "code": 0})).await?;
    }

    // Persister et retirer les certificats des transactions recentes.
    persister_certificats(middleware, nom_coll_str).await?;

    if commande.complet {
        debug!("Backup complet");
        // Reset le flag de backup de toutes les transactions dans mongodb
        reset_backup_flag(middleware, nom_coll_str).await?;
    }

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempdir()?;
    info!("backup.backup Backup horaire de {} vers tmp : {:?}", nom_domaine_str, workdir);

    let info_backup = BackupInformation::new(
        nom_domaine_str,
        nom_coll_str,
        Some(workdir.path().to_owned())
    )?;

    emettre_evenement_backup(middleware, &info_backup, "backupDemarre", &Utc::now()).await?;

    let curseur_transactions = requete_transactions(middleware, &info_backup).await?;

    let (tx_keepalive, rx_keepalive) = tokio::sync::oneshot::channel();
    let handle_generer = generer_backup_wrapper(middleware, curseur_transactions, &info_backup, tx_keepalive);
    let handle_keepalive = generer_keepalive(middleware, &info_backup, rx_keepalive);

    let resultat = try_join!(handle_generer, handle_keepalive)?;

    // Emettre evenement fin backup pour le domaine
    emettre_evenement_backup(middleware, &info_backup, "backupTermine", &Utc::now()).await?;

    Ok(None)
}

async fn generer_backup_wrapper<M>(
    middleware: &M, mut curseur: Cursor<TransactionOwned>, info_backup: &BackupInformation,
    tx_keepalive: tokio::sync::oneshot::Sender<bool>
)
    -> Result<(), crate::error::Error>
    where
        M: MongoDao + ValidateurX509 + FormatteurMessage + GenerateurMessages + CleChiffrageHandler
{
    let resultat = generer_backup(middleware, curseur, info_backup).await;

    if let Err(e) = tx_keepalive.send(true) {
        warn!("generer_backup_wrapper Erreur tx_keepalive.send : {:?}", e);
    }

    match resultat {
        Ok(inner) => Ok(inner),
        Err(e) => Err(format!("generer_backup_wrapper Erreur : {:?}", e))?
    }
}

async fn generer_backup<M>(middleware: &M, mut curseur: Cursor<TransactionOwned>, info_backup: &BackupInformation)
    -> Result<(), crate::error::Error>
    where
        M: MongoDao + ValidateurX509 + FormatteurMessage + GenerateurMessages + CleChiffrageHandler
{
    let timestamp_backup = Utc::now();
    debug!("generer_fichiers_backup Debut generer fichiers de backup avec timestamp {:?}", timestamp_backup);
    let mut termine = false;
    let mut transactions_total: usize = 0;

    while ! &termine {
        let (tx, rx) = tokio::sync::mpsc::channel(10);

        let handle_verifier = verifier_transactions(middleware, &mut curseur, tx);
        let handle_catalogue = generer_catalogue(middleware, rx, info_backup);

        let resultat = try_join!(handle_verifier, handle_catalogue)?;
        termine = resultat.0;
    }

    Ok(())
}

async fn verifier_transactions<M>(middleware: &M, curseur: &mut Cursor<TransactionOwned>, sender: Sender<TransactionOwned>)
    -> Result<bool, crate::error::Error>
    where M: ValidateurX509
{
    debug!("verifier_transactions Debut");
    let mut compteur = 0;
    // let mut taille_transactions = 0;  // Calcul la taille dechiffree/decompressee

    while let Some(doc_transaction) = curseur.next().await {
        let mut transaction = match doc_transaction {
            Ok(inner) => inner,
            Err(e) => {
                error!("Erreur conversion transaction, SKIP : {:?}", e);
                continue
            }
        };
        debug!("verifier_transactions Traiter transaction id:{}", transaction.id);
        compteur = compteur + 1;

        if let Err(e) = transaction.verifier_signature() {
            error!("verifier_transactions Transaction {} invalide (hachage/signature) - SKIP", transaction.id);
            continue
        }

        // // S'assurer que le certificat est connu
        // let fingerprint_certificat = transaction.pubkey.as_str();
        // match middleware.get_certificat(fingerprint_certificat).await {
        //     Some(inner) => {
        //         // Ajouter le certificat dans la transaction
        //         transaction.certificat = Some(inner.chaine_pem()?);
        //     },
        //     None => {
        //         error!("verifier_transactions Certificat inconnu {}, transaction {:?} *** SKIPPED ***",
        //             fingerprint_certificat, transaction.id);
        //         continue;
        //     }
        // }

        // let resultat_verification = middleware.verifier_message(&mut transaction, Some(&options_validation))?;
        // debug!("verifier_transactions Resultat verification transaction : {:?}", resultat_verification);
        //
        // if ! resultat_verification.valide() {
        //     error!("verifier_transactions Transaction {:?} invalide, ** SKIP **", transaction.parsed);
        // }

        // // Inserer date de traitement de la transaction dans les attachements
        // match doc_transaction.get("_evenements") {
        //     Some(d) => match d.as_document() {
        //         Some(evenements_doc) => {
        //             let evenements_value: Map<String, Value> = convertir_bson_deserializable(evenements_doc.to_owned())?;
        //             let mut attachements = Map::new();
        //             attachements.insert("evenements".to_string(), Value::from(evenements_value));
        //             transaction.parsed.attachements = Some(attachements);
        //         },
        //         None => ()
        //     },
        //     None => ()
        // };

        // Calculer la taille de la transaction pour appliquer la limite
        // {
        //     // Retirer le certificat pour calculer la taille de la transaction
        //     let cert = transaction.parsed.certificat.take();
        //     match serde_json::to_string(&transaction.parsed) {
        //         Ok(inner) => {
        //             taille_transactions = taille_transactions + inner.len();
        //         },
        //         Err(e) => {
        //             error!("verifier_transactions Erreur traitement transaction {:?}, taille inconnue : {:?}", doc_transaction, e);
        //         }
        //     }
        //     transaction.parsed.certificat = cert;  // Remettre le certificat
        // }

        // Transferer la transaction vers le processus d'ajout au catalogue
        sender.send(transaction).await?;

        // if compteur >= TRANSACTIONS_MAX_NB || taille_transactions >= TRANSACTIONS_DECOMPRESSED_MAX_SIZE {
        //     debug!("verifier_transactions Transactions pour catalogue : {}, taille initiale : {}", compteur, taille_transactions);
        //     // Indiquer qu'on termine cette batch mais qu'il reste probablement des transactions
        //     return Ok(false)
        // }
    }

    debug!("verifier_transactions Fin des transactions, compte : {}", compteur) ; //, taille_transactions);
    Ok(true)
}

async fn generer_keepalive<M>(middleware: &M, info_backup: &BackupInformation, mut receiver: tokio::sync::oneshot::Receiver<bool>)
    -> Result<(), crate::error::Error>
    where M: GenerateurMessages
{
    debug!("generer_keepalive Debut");

    let duration = tokio::time::Duration::from_secs(5);
    pin_mut!(receiver);

    loop {
        match timeout(duration, &mut receiver).await {
            Ok(_) => break,
            Err(e) => {
                // Ok, attendre
            }
        }

        debug!("generer_keepalive Emettre keepalive");
        if let Err(e) = emettre_evenement_backup(middleware, info_backup, CONST_EVENEMENT_KEEPALIVE, &Utc::now()).await {
            warn!("generer_keepalive Erreur emission keepalive : {:?}", e);
        }
    }

    debug!("generer_keepalive Fin");

    Ok(())
}

async fn generer_catalogue<M>(middleware: &M, mut receiver: Receiver<TransactionOwned>, info_backup: &BackupInformation)
    -> Result<(), crate::error::Error>
    where M: GenerateurMessages + ValidateurX509 + MongoDao + CleChiffrageHandler
{
    debug!("generer_catalogue Debut generer catalogues");
    // let mut messages_recus = false;
    // let mut buffer_output: Vec<u8> = Vec::new();
    // buffer_output.reserve(BACKUP_TRANSACTIONS_MAX_SIZE);

    // Creer un builder initial. Va etre remplace sur chaque rotation de catalogue.
    let mut builder = CatalogueBackupBuilder::new(
        Utc::now(),
        info_backup.domaine.clone(),
        info_backup.partition.clone(),
        info_backup.uuid_backup.clone()
    );

    let mut gzip_writer = GzEncoder::new(Vec::new(), Compression::best());

    let ca = middleware.get_enveloppe_signature().enveloppe_ca.clone();

    // Calculer la taille compressee a respecter pour rester dans les limites de messages
    let transactions_max_compresse = (0.72 * BACKUP_TRANSACTIONS_MAX_SIZE as f64) as usize;

    // Boucler pour toutes les transactions du domaine. Creer un nouveau catalogue chaque fois
    // que la taille limite est atteinte (buffer_output depasse).
    let mut taille_transactions = 0;
    while let Some(mut transaction) = receiver.recv().await {
        let transaction_id = transaction.id.clone();

        let (transaction_bytes, certificat, date_traitement_transaction) = match traiter_transaction_catalogue(middleware, &mut builder, transaction).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("generer_catalogue Erreur traitement transaction {} : {:?}", transaction_id, e);
                continue  // Skip la transaction
            }
        };

        taille_transactions += transaction_bytes.len();

        // Estimer la taille compressee courante + taille transaction courante. Si la valeur
        // depasse la limite, on genere un nouveau catalogue.
        // Certificats : Estimer 2kb par certificat, on doit se tenir dans une limite totale de 10mb pour le catalogue.
        if taille_transactions > 0 && (
            builder.certificats.len() > 200 ||
            gzip_writer.get_ref().len() + (transaction_bytes.len() as f64 * 0.7) as usize > transactions_max_compresse
        )
        {
            debug!("generer_catalogue Fermer le catalogue");

            // Emettre le catalogue vers le module de backup
            serialiser_catalogue(middleware, gzip_writer, builder, &info_backup, ca.as_ref()).await?;

            // Rotation du builder
            taille_transactions = 0;
            gzip_writer = GzEncoder::new(Vec::new(), Compression::best());
            builder = CatalogueBackupBuilder::new(
                Utc::now(),
                info_backup.domaine.clone(),
                info_backup.partition.clone(),
                info_backup.uuid_backup.clone()
            );
        }

        debug!("generer_catalogue Ajouter transaction {} au backup", transaction_id);
        builder.ajouter_certificat(certificat.as_ref());
        builder.ajouter_transaction(transaction_id.as_str(), &date_traitement_transaction);
        gzip_writer.write_all(transaction_bytes.as_slice())?;
    }

    // Verifier si on doit faire un dernier catalogue
    if builder.uuid_transactions.len() > 0 {
        debug!("generer_catalogue Generer le dernier catalogue");
        serialiser_catalogue(middleware, gzip_writer, builder, &info_backup, ca.as_ref()).await?;
    }

    // Creer un builder pour le nouveau catalogue. Va cumuler l'information des transactions.
    // let mut builder = CatalogueBackupBuilder::new(
    //     Utc::now(),
    //     info_backup.domaine.clone(),
    //     info_backup.partition.clone(),
    //     info_backup.uuid_backup.clone()
    // );
    //
    // let (mut chiffreur, sender) = CompressionChiffrageProcessor::new();
    //
    // let sender_handler = traiter_transactions_catalogue(middleware, info_backup, &mut builder, &mut receiver, sender);
    // let chiffreur_handler = chiffreur.run_vec(middleware.get_chiffrage_factory(), &mut buffer_output);

    // let resultat = try_join!(sender_handler, chiffreur_handler)?;
    //
    // if builder.uuid_transactions.len() == 0 {
    //     debug!("_generer_catalogue_wrapper Fin generer catalogue (0 transactions)");
    //     return Ok(())  // Rien a faire
    // }
    //
    // let chiffrage_resultat = resultat.1;
    // debug!("Resultat chiffrage (vec: {}, hachage: {}, bytes: {}): {:?}",
    //     buffer_output.len(), chiffrage_resultat.hachage, chiffrage_resultat.byte_count, chiffrage_resultat.cipher_data);
    //
    // // Generer le catalogue, emettre la commande pour sauvegarder le fichier
    // serialiser_catalogue(middleware, builder, &buffer_output, chiffrage_resultat, info_backup).await?;
    // debug!("_generer_catalogue_wrapper Catalogue chiffre et signe pour domaine {}, uuid {}", info_backup.domaine, info_backup.uuid_backup);
    //
    debug!("generer_catalogue Fin generer catalogues");
    Ok(())
}

async fn traiter_transaction_catalogue<M>(
    middleware: &M, builder: &mut CatalogueBackupBuilder<32>, transaction: TransactionOwned
)
    -> Result<(Vec<u8>, Arc<EnveloppeCertificat>, DateTime<Utc>), crate::error::Error>
    where M: GenerateurMessages + ValidateurX509
{
    let transaction_id = transaction.id.as_str();
    debug!("generer_catalogue Ajouter transaction {} au catalogue", transaction_id);

    let date_traitement_transaction = match transaction.evenements.as_ref() {
        Some(inner) => match inner.transaction_traitee.as_ref() {
            Some(inner) => inner.clone(),
            None => {
                Err(crate::error::Error::String(format!("traiter_transactions_catalogue Transaction {} sans date de traitement (2) *** SKIPPED ***", transaction.id)))?
            }
        },
        None => {
            Err(crate::error::Error::String(format!("traiter_transactions_catalogue Transaction {} sans date de traitement (3) *** SKIPPED ***", transaction.id)))?
        }
    };

    // S'assurer que le certificat est connu
    let fingerprint_certificat = transaction.pubkey.as_str();
    let certificat = match middleware.get_certificat(fingerprint_certificat).await {
        Some(inner) => inner,
        None => {
            Err(crate::error::Error::String(format!("verifier_transactions Certificat inconnu {}, transaction {:?} *** SKIPPED ***",
                fingerprint_certificat, transaction.id)))?
        }
    };

    // // Ajouter l'information sur la transaction
    // builder.ajouter_certificat(certificat.as_ref());
    // builder.ajouter_transaction(transaction_id, &date_traitement_transaction);

    // Convertir value en bytes
    let mut contenu_bytes = {
        let contenu_str = serde_json::to_string(&transaction)?;
        contenu_str.as_bytes().to_vec()
    };

    // Ajouter line feed (\n)
    contenu_bytes.push(NEW_LINE_BYTE);

    Ok((contenu_bytes, certificat, date_traitement_transaction))
}

// async fn traiter_transactions_catalogue<M>(
//     middleware: &M, info_backup: &BackupInformation, builder: &mut CatalogueBackupBuilder,
//     receiver: &mut Receiver<TransactionOwned>, mut sender: Sender<TokioResult<Bytes>>
// )
//     -> Result<bool, crate::error::Error>
//     where M: GenerateurMessages + ValidateurX509
// {
//     let mut messages_recus = false;
//
//     let mut dernier_evenement = Utc::now();
//     let intervalle_evenements = Duration::seconds(5);
//
//     while let Some(mut transaction) = receiver.recv().await {
//         messages_recus = true;  // S'assurer d'avoir au moins une transaction a traiter dans le catalogue
//         let transaction_id = transaction.id.as_str();
//         let fingerprint = transaction.pubkey.as_str();
//         debug!("generer_catalogue Ajouter transaction {} au catalogue", transaction_id);
//
//         let date_traitement_transaction = match transaction.evenements.as_ref() {
//             Some(inner) => match inner.get("transaction_traitee") {
//                 Some(inner) => {
//                     let date: DateTime<Utc> = match serde_json::from_value(inner.clone()) {
//                         Ok(inner) => inner,
//                         Err(e) => {
//                             error!("traiter_transactions_catalogue Transaction {} sans date de traitement (date invalide : {:?}) (1) - SKIP", transaction.id, e);
//                             continue
//                         }
//                     };
//                     date
//                 },
//                 None => {
//                     error!("traiter_transactions_catalogue Transaction {} sans date de traitement (2) - SKIP", transaction.id);
//                     continue
//                 }
//             },
//             None => {
//                 error!("traiter_transactions_catalogue Transaction {} sans date de traitement (3) - SKIP", transaction.id);
//                 continue
//             }
//         };
//         // let date_traitement_transaction = trouver_date_traitement_transaction(&message_ref)?;
//
//         // S'assurer que le certificat est connu
//         let fingerprint_certificat = transaction.pubkey.as_str();
//         match middleware.get_certificat(fingerprint_certificat).await {
//             Some(inner) => {
//                 // Ajouter le certificat dans le builder de catalogue
//                 builder.ajouter_certificat(inner.as_ref())
//             },
//             None => {
//                 error!("verifier_transactions Certificat inconnu {}, transaction {:?} *** SKIPPED ***",
//                     fingerprint_certificat, transaction.id);
//                 continue;
//             }
//         }
//
//         builder.ajouter_transaction(transaction_id, &date_traitement_transaction);
//
//         // Convertir value en bytes
//         let mut contenu_bytes = {
//             let contenu_str = serde_json::to_string(&transaction)?;
//             contenu_str.as_bytes().to_vec()
//         };
//
//         // Ajouter line feed (\n)
//         contenu_bytes.push(NEW_LINE_BYTE);
//
//         // Write
//         sender.send(TokioResult::Ok(Bytes::from(contenu_bytes))).await?;
//     }
//
//     Ok(messages_recus)
// }

// fn trouver_date_traitement_transaction(transaction: &MessageMilleGrillesRefDefault) -> Result<DateTime<Utc>, Box<dyn Error>> {
//     debug!("trouver_date_transaction Dans transaction : {:?}", transaction.id);
//     todo!("fix me")
//     // match &transaction.attachements {
//     //     Some(attachements) => match attachements.get("evenements") {
//     //         None => (),
//     //         Some(evenements) => {
//     //             debug!("trouver_date_transaction evenements : {:?}", evenements);
//     //             if let Some(evenements) = evenements.as_object() {
//     //                 if let Some(transaction_traitee) = evenements.get("transaction_traitee") {
//     //                     if let Some(transaction_traitee) = transaction_traitee.as_object() {
//     //                         if let Some(date_transaction) = transaction_traitee.get("$date") {
//     //                             if let Some(date_transaction) = date_transaction.as_object() {
//     //                                 if let Some(date_transaction) = date_transaction.get("$numberLong") {
//     //                                     if let Some(date_string) = date_transaction.as_str() {
//     //                                         debug!("trouver_date_transaction Date attachement string : {}", date_string);
//     //                                         match date_string.parse::<i64>() {
//     //                                             Ok(inner) => {
//     //                                                 match DateTime::from_timestamp(inner/1000, 0) {
//     //                                                     Some(inner) => return Ok(inner),
//     //                                                     None => warn!("trouver_date_transaction Erreur conversion date (absente)")
//     //                                                 }
//     //                                                 // let date_epoch = DateEpochSeconds::from_i64(inner/1000);
//     //                                                 // debug!("trouver_date_transaction Date attachement string : {:?}", date_epoch);
//     //                                                 // return Ok(date_epoch)
//     //                                             },
//     //                                             Err(e) => {
//     //                                                 warn!("trouver_date_transaction Erreur parse date transaction_traitee {:?}, fallback estampille", e);
//     //                                             }
//     //                                         }
//     //                                     }
//     //                                 }
//     //                             }
//     //                         }
//     //                     }
//     //                 }
//     //             }
//     //         },
//     //     },
//     //     None => ()
//     // }
//     //
//     // // Fallback
//     // Ok(transaction.estampille.clone())
// }

async fn serialiser_catalogue<M>(
    middleware: &M, mut gzip_writer: GzEncoder<Vec<u8>>, mut builder: CatalogueBackupBuilder<32>, info_backup: &BackupInformation, ca: &EnveloppeCertificat)
    -> Result<(), crate::error::Error>
    where M: MongoDao + GenerateurMessages
{
    let nom_collection_transactions = info_backup.nom_collection_transactions.as_str();

    // Fermer le buffer de compression
    let buffer_compresse = gzip_writer.finish()?;

    // Chiffrer le contenu
    let cipher = CipherMgs4::with_ca(ca)?;
    let resultat_chiffrage = cipher.to_vec(buffer_compresse.as_slice())?;
    debug!("generer_catalogue Taille catalogue backup {} bytes chiffres", resultat_chiffrage.ciphertext.len());
    builder.charger_transactions_chiffrees(resultat_chiffrage)?;

    // builder.set_cles(&chiffrage.cipher_data);
    //
    // builder.charger_transactions_chiffrees(transactions_chiffrees).await?;  // Charger, hacher transactions
    //
    // // Comparer hachages ecrits et lus
    // if chiffrage.hachage.as_str() != builder.data_hachage_bytes.as_str() {
    //     Err(format!("sauvegarder_catalogue Erreur creation backup - hachage transactions memoire {} et disque {} mismatch, abandon",
    //                 chiffrage.hachage, builder.data_hachage_bytes))?;
    // }

    let mut catalogue = builder.build()?;

    let uuid_transactions = catalogue.uuid_transactions.take().unwrap_or_else(|| Vec::new());

    // // let mut catalogue_signe = middleware.formatter_message(
    // //     MessageKind::Commande, &catalogue, Some(DOMAINE_BACKUP), Some("backupTransactions"),
    // //     None::<&str>, None::<&str>, None, false)?;
    //
    // // let uuid_message_backup = catalogue_signe.id.clone();

    debug!("serialiser_catalogue Catalogue serialise");

    let routage = RoutageMessageAction::builder(DOMAINE_BACKUP, "backupTransactions", vec![Securite::L2Prive])
        .timeout_blocking(90_000)
        .build();

    let reponse = match middleware.transmettre_commande(routage, catalogue).await {
        Ok(inner) => match inner {
            Some(inner) => match inner {
                TypeMessage::Valide(inner) => inner,
                _ => Err(crate::error::Error::String(String::from("serialiser_catalogue Erreur sauvegarde fichier backup - mauvais type reponse, ** SKIPPED **")))?
            },
            None => {
                Err(crate::error::Error::String(String::from("serialiser_catalogue Erreur sauvegarder fichier backup, ** SKIPPED **")))?
            }
        },
        Err(e) => {
            Err(crate::error::Error::String(String::from("backup.serialiser_catalogue Aucune reponse, on assume que le backup a echoue, ** SKIPPED **")))?
        }
    };

    if reponse.message.buffer.len() > BACKUP_TRANSACTIONS_MAX_SIZE {
        warn!("generer_catalogue Le catalogue en cours depasse la limite max_size : {} bytes, on va le generer quand meme", reponse.message.buffer.len());
    }

    // // let reponse = middleware.emettre_message_millegrille(
    // //     routage, true, TypeMessageOut::Commande, catalogue_signe).await;
    //
    // let reponse = middleware.transmettre_commande(routage, catalogue).await;
    //
    // let reponse = match reponse {
    //     Ok(result) => match result {
    //         Some(r) => match r {
    //             TypeMessage::Valide(r) => r,
    //             _ => {
    //                 Err(String::from("backup.serialiser_catalogue Erreur sauvegarder fichier backup, ** SKIPPED **"))?
    //             }
    //         },
    //         None => {
    //             Err(String::from("backup.serialiser_catalogue Aucune reponse, on assume que le backup a echoue, ** SKIPPED **"))?
    //         }
    //     },
    //     Err(_) => {
    //         Err(format!("backup.serialiser_catalogue Timeout reponse, on assume que le backup a echoue, ** SKIPPED **"))?
    //     }
    // };

    let message_ref = reponse.message.parse()?;
    debug!("Reponse backup {:?}", from_utf8(reponse.message.buffer.as_slice()));
    let message_contenu = message_ref.contenu()?;
    let reponse_mappee: ReponseBackup = message_contenu.deserialize()?;

    if let Some(true) = reponse_mappee.ok {
        debug!("Catalogue transactions sauvegarde OK")
    } else {
        Err(format!("backup.serialiser_catalogue Erreur sauvegarde catalogue transactions {:?} (application backup), ABORT. Erreur : {:?}",
                    nom_collection_transactions, reponse_mappee.err))?;
    }

    // Marquer transactions comme etant completees
    marquer_transaction_backup_complete(
        middleware,
        nom_collection_transactions,
        &uuid_transactions).await?;

    Ok(())
}


// /// Generer les fichiers de backup localement
// /// returns: Liste de fichiers generes
// async fn generer_fichiers_backup<M,S,P>(middleware: &M, mut transactions: S, workdir: P, info_backup: &BackupInformation)
//     -> Result<Vec<PathBuf>, Box<dyn Error>>
//     where
//         M: ValidateurX509 + FormatteurMessage + VerificateurMessage + GenerateurMessages + ChiffrageFactoryTrait,  // + Chiffreur<CipherMgs3, Mgs3CipherKeys>
//         S: CurseurStream,
//         P: AsRef<Path>
// {
//     let workir_path = workdir.as_ref();
//     let timestamp_backup = Utc::now();
//     debug!("generer_fichiers_backup Debut generer fichiers de backup avec timestamp {:?}", timestamp_backup);
//
//     let mut fichiers_generes: Vec<PathBuf> = Vec::new();
//     let mut len_written: usize = 0;
//     let mut nb_transactions_written: usize = 0;
//     let mut nb_transactions_total: usize = 0;
//     let (mut builder, mut path_fichier) = nouveau_catalogue(workir_path, info_backup, fichiers_generes.len())?;
//     debug!("generer_fichiers_backup Creation fichier backup : {:?}", path_fichier);
//     let mut writer = TransactionWriter::new(&path_fichier, Some(middleware)).await?;
//
//     let options_validation = ValidationOptions::new(false, true, true);
//     while let Some(doc_transaction) = transactions.try_next().await? {
//         debug!("generer_fichiers_backup Traitement transaction {:?}", doc_transaction);
//
//         if len_written >= TRANSACTIONS_DECOMPRESSED_MAX_SIZE || nb_transactions_written >= TRANSACTIONS_MAX_NB {
//             debug!("generer_fichiers_backup Limite transaction par fichier atteinte, on fait une rotation");
//             let path_catalogue = sauvegarder_catalogue(
//                 middleware, workir_path, &mut fichiers_generes, builder, &mut path_fichier, writer).await?;
//             fichiers_generes.push(path_catalogue.clone());
//
//             // Reset compteur de catalogue
//             len_written = 0;
//             nb_transactions_written = 0;
//
//             // Ouvrir nouveau fichier
//             let (builder_1, path_fichier_1) = nouveau_catalogue(workir_path, info_backup, fichiers_generes.len())?;
//             builder = builder_1;
//             path_fichier = path_fichier_1;
//             writer = TransactionWriter::new(&path_fichier, Some(middleware)).await?;
//
//             // Emettre evenement mise a jour
//             emettre_evenement_backup_catalogue(middleware, &info_backup, nb_transactions_total as i64).await?;
//         }
//
//         // Verifier la transaction - doit etre completement valide, certificat connu
//         let mut transaction = MessageSerialise::from_serializable(&doc_transaction)?;
//         let fingerprint_certificat = transaction.parsed.pubkey.as_str();
//         match middleware.get_certificat(fingerprint_certificat).await {
//             Some(c) => transaction.set_certificat(c),
//             None => {
//                 info!("Certificat {} n'est pas dans le cache. On fait une requete vers CorePki", fingerprint_certificat);
//                 let requete = json!({"fingerprint": fingerprint_certificat});
//                 let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM, PKI_REQUETE_CERTIFICAT)
//                     .exchanges(vec![Securite::L3Protege])
//                     .build();
//
//                 // let entete = transaction.get_entete();
//                 let fingerprint_certificat = transaction.parsed.pubkey.as_str();
//                 let message_id = transaction.parsed.id.as_str();
//
//                 let reponse = match middleware.transmettre_requete(routage, &requete).await {
//                     Ok(c) => match c {
//                         TypeMessage::Valide(c) => {
//                             match c.message.get_msg().map_contenu::<ReponseCertificat>() {
//                                 Ok(r) => r,
//                                 Err(e) => {
//                                     error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: {:?}) *** SKIPPED ***",
//                                         fingerprint_certificat, message_id, e);
//                                     continue;
//                                 }
//                             }
//                         },
//                         _ => {
//                             error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: Mauvais type reponse) *** SKIPPED ***",
//                                     fingerprint_certificat, message_id);
//                             continue;
//                         }
//                     },
//                     Err(e) => {
//                         error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: {:?}) *** SKIPPED ***",
//                                             fingerprint_certificat, message_id, e);
//                         continue;
//                     }
//                 };
//
//                 if let Some(ok) = reponse.ok {
//                     if ok == false {
//                         error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: Reponse CorePki: Certificat inconnu) *** SKIPPED ***",
//                             fingerprint_certificat, message_id);
//                         continue;
//                     }
//                 }
//
//                 match reponse.chaine_pem {
//                     Some(c) => {
//                         // Charger le certificat
//                         match middleware.charger_enveloppe(&c, Some(fingerprint_certificat), None).await {
//                             Ok(e) => transaction.set_certificat(e),  // OK, certificat recu
//                             Err(e) => {
//                                 error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: {:?}) *** SKIPPED ***",
//                                     fingerprint_certificat, message_id, e);
//                                 continue;
//                             }
//                         }
//                     },
//                     None => {
//                         error!("generer_fichiers_backup Certificat inconnu {}, transaction {} (err: Reponse CorePki: chaine_pem vide) *** SKIPPED ***",
//                             fingerprint_certificat, message_id);
//                         continue;
//                     }
//                 }
//
//                 // let entete = transaction.get_entete();
//                 // error!("generer_fichiers_backup Certificat inconnu {}, transaction {} *** SKIPPED ***",
//                 //     entete.fingerprint_certificat, entete.uuid_transaction);
//                 // continue;
//             }
//         };
//         let resultat_verification = middleware.verifier_message(&mut transaction, Some(&options_validation))?;
//         debug!("generer_fichiers_backup Resultat verification transaction : {:?}", resultat_verification);
//
//         // let entete = transaction.get_entete();
//         let message_id = transaction.parsed.id.as_str();
//         // let uuid_transaction = entete.uuid_transaction.as_str();
//         let date_traitement_transaction = match doc_transaction.get("_evenements") {
//             Some(d) => match d.as_document() {
//                 Some(evenements_doc) => {
//                     let date_traitee = match evenements_doc.get("transaction_traitee") {
//                         Some(d) => match d.as_datetime() {
//                             Some(d) => {
//                                 DateEpochSeconds::from_i64(d.timestamp_millis()/1000)
//                             },
//                             None => {
//                                 debug!("Mauvais type d'element _evenements.transaction_traitee pour {} transaction. Utiliser estampille.", message_id);
//                                 transaction.parsed.estampille.clone()
//                             }
//                         },
//                         None => {
//                             debug!("Mauvais type d'element _evenements.transaction_traitee pour {} transaction. Utiliser estampille.", message_id);
//                             transaction.parsed.estampille.clone()
//                         }
//                     };
//
//                     let evenements_value: Map<String, Value> = convertir_bson_deserializable(evenements_doc.to_owned())?;
//                     let mut attachements = Map::new();
//                     attachements.insert("evenements".to_string(), Value::from(evenements_value));
//                     transaction.parsed.attachements = Some(attachements);
//
//                     date_traitee
//                 },
//                 None => {
//                     debug!("Mauvais type d'element _evenements pour {} transaction. Utiliser estampille.", message_id);
//                     transaction.parsed.estampille.clone()
//                 }
//             },
//             None => {
//                 debug!("Aucune information d'evenements (_evenements) pour une transaction. Utiliser estampille.");
//                 transaction.parsed.estampille.clone()
//             }
//         };
//
//         if resultat_verification.valide() {
//             debug!("backup.generer_fichiers_backup Transaction {} valide", transaction.parsed.id);
//             let fingerprint_certificat = transaction.parsed.pubkey.as_str();
//             let certificat = match middleware.get_certificat(fingerprint_certificat).await {
//                 Some(c) => c,
//                 None => {
//                     error!("Certificat introuvable pour transaction {}, ** SKIP TRANSACTION **", message_id);
//                     continue;
//                 }
//             };
//             builder.ajouter_certificat(certificat.as_ref());
//             builder.ajouter_transaction(message_id, &date_traitement_transaction);
//
//             // Retirer le certificat de la transaction - le backup les store separement
//             transaction.parsed.retirer_certificats();
//
//             // let len_message = writer.write_bson_line(&doc_transaction).await?;
//             let len_message = writer.write_json_line(&transaction.parsed).await?;
//             len_written += len_message;
//             nb_transactions_written += 1;
//             nb_transactions_total += 1;
//         } else {
//             error!("Transaction {} invalide ({:?}), ** SKIPPED **", message_id, resultat_verification);
//             continue;
//         }
//     }
//
//     debug!("backup.generer_fichiers_backup {} transactions pour backup", builder.uuid_transactions.len());
//     if builder.uuid_transactions.len() > 0 {
//         let path_catalogue = sauvegarder_catalogue(middleware, workir_path, &mut fichiers_generes, builder, &mut path_fichier, writer).await?;
//         fichiers_generes.push(path_catalogue.clone());
//
//         // Emettre evenement mise a jour
//         emettre_evenement_backup_catalogue(middleware, &info_backup, nb_transactions_total as i64).await?;
//     } else {
//         debug!("generer_fichiers_backup Fichier de backup vide, on skip");
//     }
//
//     Ok(fichiers_generes)
// }

// async fn sauvegarder_catalogue<M>(
//     middleware: &M, workir_path: &Path, fichiers_generes: &mut Vec<PathBuf>, mut builder: CatalogueBackupBuilder, path_fichier: &mut PathBuf, writer: TransactionWriter)
//     -> Result<PathBuf, Box<dyn Error>>
//     where M: FormatteurMessage
// {
//     let (hachage, keys) = writer.fermer().await?;
//
//     if let Some(c) = &keys {
//         builder.set_cles(c);
//     }
//
//     builder.charger_transactions_chiffrees(&path_fichier).await?;  // Charger, hacher transactions
//     // Comparer hachages ecrits et lus
//     if hachage != builder.data_hachage_bytes {
//         Err(format!("sauvegarder_catalogue Erreur creation backup - hachage transactions memoire {} et disque {} mismatch, abandon", hachage, builder.data_hachage_bytes))?;
//     }
//     let catalogue = builder.build();
//     let mut path_catalogue = PathBuf::new();
//     path_catalogue.push(workir_path);
//     path_catalogue.push(format!("catalogue_{}.json", fichiers_generes.len()));
//     let fichier_catalogue = std::fs::File::create(&path_catalogue)?;
//
//     let mut catalogue_signe = middleware.formatter_message(
//         MessageKind::Commande, &catalogue, Some("Backup"), Some("backupTransactions"),
//         None::<&str>, None::<&str>, None, false)?;
//
//     // Conserver les uuid_transactions separement (ne sont pas inclues dans la signature)
//     match catalogue.uuid_transactions {
//         Some(u) => {
//             let mut attachements = match catalogue_signe.attachements.as_mut() {
//                 Some(inner) => inner,
//                 None => {
//                     catalogue_signe.attachements = Some(Map::new());
//                     catalogue_signe.attachements.as_mut().expect("attachements.as_mut")
//                 }
//             };
//             attachements.insert("uuid_transactions".to_string(), serde_json::to_value(&u)?);
//         },
//         None => ()
//     }
//
//     serde_json::to_writer(fichier_catalogue, &catalogue_signe)?;
//
//     debug!("sauvegarder_catalogue Catalogue sauvegarde : {:?}", path_fichier);
//
//     Ok(path_catalogue)
// }

// fn nouveau_catalogue<P>(workdir: P, info_backup: &BackupInformation, compteur: usize)
//                         -> Result<(CatalogueBackupBuilder, PathBuf), Box<dyn Error>>
//     where P: AsRef<Path>
// {
//     let workdir_path = workdir.as_ref();
//
//     let date_transaction = DateEpochSeconds::now();
//     let builder = CatalogueBackupBuilder::new(
//         date_transaction,
//         info_backup.domaine.clone(),
//         info_backup.partition.clone(),
//         info_backup.uuid_backup.clone()
//     );
//
//     let mut path_fichier: PathBuf = PathBuf::new();
//     path_fichier.push(workdir_path);
//     path_fichier.push(PathBuf::from(format!("backup_{}.dat", compteur)));
//
//     Ok((builder, path_fichier))
// }

async fn requete_transactions<M>(middleware: &M, info: &BackupInformation)
    -> Result<Cursor<TransactionOwned>, crate::error::Error>
    where M: MongoDao
{
    let nom_collection = &info.nom_collection_transactions;
    let collection = middleware.get_collection_typed::<TransactionOwned>(nom_collection)?;

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
    };

    // Sort cause erreur :
    // code: 292
    // code_name: "QueryExceededMemoryLimitNoDiskUseAllowed"
    // Executor error during find command :: caused by :: Sort exceeded memory limit of 104857600 bytes, but did not opt in to external sorting.
    // Fix -> Utiliser index backup_transactions
    let find_options = FindOptions::builder()
        .hint(Hint::Name(String::from("backup_transactions")))
        .batch_size(50)
        .build();

    debug!("backup.requete_transactions Collection {}, filtre {:?}", nom_collection, filtre);
    let curseur = collection.find(filtre, find_options).await?;
    Ok(curseur)
}

async fn marquer_transaction_backup_complete<M,S,T>(middleware: &M, nom_collection_ref: S, uuid_transactions_ref: &Vec<T>)
    -> Result<(), crate::error::Error>
    where
        M: MongoDao,
        S: AsRef<str>,
        T: AsRef<str>
{
    // debug!("Set flag backup pour transactions de {} : {:?}", nom_collection, catalogue_horaire.uuid_transactions);
    let uuid_transactions: Vec<&str> = uuid_transactions_ref.iter().map(|s| s.as_ref()).collect();
    let nom_collection = nom_collection_ref.as_ref();
    debug!("Set flag backup pour transactions de {} : {:?}", nom_collection, uuid_transactions);

    let collection = middleware.get_collection(nom_collection)?;
    let filtre = doc! {
        TRANSACTION_CHAMP_ID: {"$in": &uuid_transactions}
    };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: true},
        "$currentDate": {TRANSACTION_CHAMP_BACKUP_HORAIRE: true},
    };

    let r = collection.update_many(filtre, ops, None).await?;
    if r.matched_count as usize != uuid_transactions.len() {
        Err(format!(
            "Erreur mismatch nombre de transactions maj apres backup : {:?} dans le backup != {:?} mises a jour",
            uuid_transactions.len(),
            r.matched_count
        ))?;
    }

    Ok(())
}

trait BackupHandler {
    fn run() -> Result<(), String>;
}

/// Struct de backup
#[derive(Debug)]
pub struct BackupInformation {
    /// Nom complet de la collection de transactions mongodb
    nom_collection_transactions: String,
    /// Nom du domaine
    domaine: String,
    /// Partition (groupe logique) du backup.
    partition: Option<String>,
    /// Path de travail pour conserver les fichiers temporaires de chiffrage
    workpath: PathBuf,
    /// Identificateur unique du backup (collateur)
    pub uuid_backup: String,
    /// Repertoire temporaire qui est supprime automatiquement apres le backup.
    tmp_workdir: Option<TempDir>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueBackup<const K: usize> {
    /// Heure de la premiere transaction du backup (traitement interne initial)
    #[serde(with = "epochseconds")]
    pub date_backup: DateTime<Utc>,
    /// Heure de la premiere transaction du backup
    #[serde(with = "epochseconds")]
    pub date_transactions_debut: DateTime<Utc>,
    /// Heure de la derniere tranaction du backup
    #[serde(with = "epochseconds")]
    pub date_transactions_fin: DateTime<Utc>,
    /// True si c'est un snapshot
    // pub snapshot: bool,
    /// Nom du domaine
    pub domaine: String,
    /// Partition (optionnel)
    pub partition: Option<String>,
    /// Identificateur unique du groupe de backup (collateur)
    pub uuid_backup: String,

    /// Collection des certificats presents dans les transactions du backup
    certificats: CollectionCertificatsPem,

    pub catalogue_nomfichier: String,
    // pub transactions_nomfichier: String,
    pub data_hachage_bytes: String,
    pub data_transactions: String,
    pub nombre_transactions: usize,

    /// Liste des transactions - resultat intermediaire, va etre retiree du fichier final
    #[serde(skip_serializing)]
    pub uuid_transactions: Option<Vec<String>>,

    pub dechiffrage: DechiffrageInterMillegrilleOwned,
}

impl<const K: usize> CatalogueBackup<K> {

    pub fn builder(heure: DateTime<Utc>, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> CatalogueBackupBuilder<K> {
        CatalogueBackupBuilder::new(heure, nom_domaine, partition, uuid_backup)
    }

    // pub fn get_cipher_data(&self) -> Result<MgsCipherDataCurrent, Box<dyn Error>> {
    //     match &self.cle {
    //         Some(c) => {
    //             let header = self.header.as_ref().expect("header");
    //             MgsCipherDataCurrent::new(
    //                 c.as_str(),
    //                 header,
    //             )
    //         },
    //         None => Err("Non chiffre")?,
    //     }
    // }
}

struct CatalogueBackupBuilder<const K: usize> {
    date_backup: DateTime<Utc>,      // Date de creation du backup (now)
    date_debut_backup: Option<DateTime<Utc>>,  // Date de traitement de la premiere transaction
    date_fin_backup: Option<DateTime<Utc>>,  // Date de traitement de la derniere transaction
    nom_domaine: String,
    partition: Option<String>,
    uuid_backup: String,                // Identificateur unique de ce backup
    certificats: CollectionCertificatsPem,
    uuid_transactions: Vec<String>,     // Liste des transactions inclues (pas mis dans catalogue)
    data_hachage_bytes: String,         // Hachage du contenu chiffre
    data_transactions: String,          // Contenu des transactions en base64 (chiffre)
    dechiffrage: Option<DechiffrageInterMillegrilleOwned>,
}

impl<const K: usize> CatalogueBackupBuilder<K> {

    fn new(heure: DateTime<Utc>, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> Self {
        CatalogueBackupBuilder {
            date_backup: heure.clone(),
            date_debut_backup: None,  // Va etre la date de la derniere transaction
            date_fin_backup: None,  // Va etre la date de la derniere transaction
            nom_domaine, partition, uuid_backup, // chiffrer, snapshot,
            certificats: CollectionCertificatsPem::new(),
            uuid_transactions: Vec::new(),
            data_hachage_bytes: "".to_owned(),
            data_transactions: "".to_owned(),
            dechiffrage: None,
            // cles: None,
            // backup_precedent: None,
        }
    }

    fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat).expect("certificat");
    }

    fn ajouter_transaction(&mut self, uuid_transaction: &str, date_estampille: &DateTime<Utc>) {
        self.uuid_transactions.push(String::from(uuid_transaction));

        // Ajuste date debut et fin des transactions du backup
        match &self.date_debut_backup {
            Some(d) => {
                if d > date_estampille {
                    self.date_debut_backup = Some(date_estampille.to_owned());
                }
            },
            None => self.date_debut_backup = Some(date_estampille.to_owned())
        }
        match &self.date_fin_backup {
            Some(d) => {
                if d < date_estampille {
                    self.date_fin_backup = Some(date_estampille.to_owned());
                }
            },
            None => self.date_fin_backup = Some(date_estampille.to_owned())
        }
    }

    // fn set_cles(&mut self, cles: &MgsCipherKeysCurrent) {
    //     self.cles = Some(cles.clone());
    // }

    fn charger_transactions_chiffrees(&mut self, chiffrage: CipherResultVec<K>)
        -> Result<(), crate::error::Error>
    {
        // Hacher le contenu (pour verification)
        self.data_hachage_bytes = chiffrage.hachage_bytes;

        // Convertir le contenu en base64
        self.data_transactions = encode(Base::Base64, chiffrage.ciphertext.as_slice());

        // Conserver les cles, information de format de chiffrage
        self.dechiffrage = Some(chiffrage.cles.into());

        Ok(())
    }

    pub fn build(self) -> Result<CatalogueBackup<K>, crate::error::Error> {

        // let date_str = self.date_backup.format_ymdh();
        let date_str = format!("{}", self.date_backup.format("%Y%m%d%H"));

        // Build collections de certificats
        let catalogue_nomfichier = match &self.partition {
            Some(p) => {
                format!("{}.{}_{}.json.xz", &self.nom_domaine, p, date_str)
            },
            None => format!("{}_{}.json.xz", &self.nom_domaine, date_str)
        };

        // let (format, cle, header) = match self.cles {
        //     Some(cles) => {
        //         (Some(cles.get_format()), cles.get_cle_millegrille(), Some(cles.header))
        //     },
        //     None => (None, None, None)
        // };

        let date_transactions_debut = match self.date_debut_backup {
            Some(d) => d,
            None => self.date_backup.clone()
        };
        let date_transactions_fin = match self.date_fin_backup {
            Some(d) => d,
            None => self.date_backup.clone()
        };

        let dechiffrage = match self.dechiffrage {
            Some(inner) => inner,
            None => Err(crate::error::Error::Str("Information de dechiffrage absente"))?
        };

        Ok(CatalogueBackup {
            date_backup: self.date_backup,
            date_transactions_debut,
            date_transactions_fin,
            domaine: self.nom_domaine,
            partition: self.partition,
            uuid_backup: self.uuid_backup,
            catalogue_nomfichier,

            certificats: self.certificats,

            data_hachage_bytes: self.data_hachage_bytes,
            data_transactions: self.data_transactions,
            nombre_transactions: self.uuid_transactions.len(),
            uuid_transactions: Some(self.uuid_transactions),

            dechiffrage
        })
    }

}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new<S>(
        domaine: S,
        nom_collection_transactions: S,
        workpath: Option<PathBuf>
    ) -> Result<BackupInformation, crate::error::Error>
    where S: Into<String>
    {
        let (workpath_inner, tmp_workdir): (PathBuf, Option<TempDir>) = match workpath {
            Some(wp) => (wp, None),
            None => {
                let tmp_workdir = tempdir()?;
                let path_tmp = tmp_workdir.path().to_owned();

                (path_tmp, Some(tmp_workdir))
            },
        };

        let uuid_backup = Uuid::new_v4().to_string();

        Ok(BackupInformation {
            nom_collection_transactions: nom_collection_transactions.into(),
            domaine: domaine.into(),
            partition: None,
            workpath: workpath_inner,
            uuid_backup,
            tmp_workdir,
        })
    }

}

impl BackupHandler for BackupInformation {
    fn run() -> Result<(), String> {
        info!("Demarrage backup");
        Ok(())
    }
}

// struct TransactionWriter {
//     fichier_writer: FichierWriter<MgsCipherKeysCurrent, CipherMgsCurrent>,
// }
//
// impl TransactionWriter {
//
//     pub async fn new<C,P>(path_fichier: P, middleware: Option<&C>) -> Result<TransactionWriter, Box<dyn Error>>
//     where
//         C: ChiffrageFactoryTrait,
//         P: Into<PathBuf>
//     {
//         // let chiffreur = match middleware {
//         //     Some(m) => Some(m.get_chiffreur()?),
//         //     None => None
//         // };
//         let chiffrage_factory = match middleware {
//             Some(m) => Some(m.get_chiffrage_factory()),
//             None => None
//         };
//         let fichier_writer = FichierWriter::new(path_fichier, chiffrage_factory).await?;
//         Ok(TransactionWriter{fichier_writer})
//     }
//
//     /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
//     pub async fn write_json_line<S>(&mut self, contenu: &S) -> Result<usize, Box<dyn Error>>
//         where S: Serialize
//     {
//         // Convertir value en bytes
//         let mut contenu_bytes = {
//             let contenu_str = serde_json::to_string(contenu)?;
//             debug!("backup.TransactionWriter.write_json_line Ecrire transaction bytes {}", contenu_str);
//             contenu_str.as_bytes().to_owned()
//         };
//
//         // Ajouter line feed (\n)
//         contenu_bytes.push(NEW_LINE_BYTE);
//
//         // Write dans le fichier
//         self.fichier_writer.write(contenu_bytes.as_slice()).await
//     }
//
//     pub async fn write_bson_line(&mut self, contenu: &Document) -> Result<usize, Box<dyn Error>> {
//         let mut value = serde_json::to_value(contenu)?;
//
//         // S'assurer qu'on a un document (map)
//         // Retirer le champ _id si present
//         match value.as_object_mut() {
//             Some(doc) => {
//                 doc.remove("_id");
//                 self.write_json_line(&value).await
//             },
//             None => {
//                 warn!("Valeur bson fournie en backup n'est pas un _Document_, on l'ignore : {:?}", contenu);
//                 Ok(0)
//             }
//         }
//     }
//
//     pub async fn fermer(self) -> Result<(String, Option<MgsCipherKeysCurrent>), Box<dyn Error>> {
//         self.fichier_writer.fermer().await
//     }
//
// }

#[derive(Deserialize)]
struct ReponseBackup {
    ok: Option<bool>,
    err: Option<String>,
}

/// Emet une liste de backup de transactions.
// async fn emettre_backup_transactions<M,T,S>(middleware: &M, nom_collection_transactions: T, fichiers: &Vec<S>)
//     -> Result<(), Box<dyn Error>>
//     where
//         M: GenerateurMessages + MongoDao,
//         S: AsRef<Path>,
//         T: AsRef<str>
// {
//     let nom_collection_transactions = nom_collection_transactions.as_ref();
//
//     for fichier_ref in fichiers {
//         let fichier = fichier_ref.as_ref();
//         debug!("emettre_backup_transactions Traitement fichier {:?}", fichier);
//
//         // Charger fichier de backup
//         let (message_backup, uuid_transactions) = {
//             let fichier_fp = std::fs::File::open(fichier)?;
//             let fichier_reader = std::io::BufReader::new(fichier_fp);
//
//             let mut message_backup: MessageMilleGrille = serde_json::from_reader(fichier_reader)?;
//             debug!("emettre_backup_transactions Message backup a emettre : {:?}", message_backup);
//
//             // Conserver liste de transactions, retirer du message a emettre
//             let uuid_transactions: Vec<String> = match message_backup.attachements.take() {
//                 Some(mut attachements) => match attachements.remove("uuid_transactions") {
//                     Some(liste) => serde_json::from_value(liste)?,
//                     None => {
//                         error!("emettre_backup_transactions Message backup sans liste uuid_transactions - skip");
//                         continue;
//                     }
//                 },
//                 None => {
//                     error!("emettre_backup_transactions Message backup sans liste uuid_transactions - skip");
//                     continue;
//                 }
//             };
//
//             (message_backup, uuid_transactions)
//         };
//
//         let uuid_message_backup = message_backup.id.clone();
//         debug!("emettre_backup_transactions Emettre transactions dans le backup {} : {:?}", uuid_message_backup, uuid_transactions);
//
//         let routage = RoutageMessageAction::builder(DOMAINE_BACKUP, "backupTransactions")
//             .exchanges(vec![Securite::L2Prive])
//             // .correlation_id(uuid_message_backup.clone())
//             .timeout_blocking(90_000)
//             .build();
//         let reponse = middleware.emettre_message_millegrille(
//             routage, true, TypeMessageOut::Commande, message_backup).await;
//
//         let reponse = match reponse {
//             Ok(result) => match result {
//                 Some(r) => match r {
//                     TypeMessage::Valide(r) => r,
//                     _ => {
//                         error!("emettre_backup_transactions Erreur sauvegarder fichier backup {}, ** SKIPPED **", uuid_message_backup);
//                         continue;
//                     }
//                 },
//                 None => {
//                     error!("emettre_backup_transactions Aucune reponse, on assume que le backup de {} a echoue, ** SKIPPED **", uuid_message_backup);
//                     continue;
//                 }
//             },
//             Err(_) => {
//                 error!("emettre_backup_transactions Timeout reponse, on assume que le backup de {} a echoue, ** SKIPPED **", uuid_message_backup);
//                 continue;
//             }
//         };
//
//         debug!("Reponse backup {} : {:?}", uuid_message_backup, reponse.message.parsed);
//         let reponse_mappee: ReponseBackup = reponse.message.parsed.map_contenu()?;
//
//         if let Some(true) = reponse_mappee.ok {
//             debug!("Catalogue transactions sauvegarde OK")
//         } else {
//             Err(format!("Erreur sauvegarde catalogue transactions {:?}, ABORT. Erreur : {:?}",
//                         nom_collection_transactions, reponse_mappee.err))?;
//         }
//
//         // Marquer transactions comme etant completees
//         marquer_transaction_backup_complete(
//             middleware,
//             nom_collection_transactions,
//             &uuid_transactions).await?;
//     }
//
//     Ok(())
// }


/// Genere une nouvelle Part pour un fichier a uploader dans un form multipart
async fn file_to_part(filename: &str, file: File_tokio) -> Part {
    let metadata = &file.metadata().await.expect("md");
    let len = metadata.len();

    let stream = FramedRead::new(file, BytesCodec::new());
    // let reader = BufReader::new(file);
    let body = Body::wrap_stream(stream);

    Part::stream_with_length(body, len)
        .mime_str("application/octet-stream").expect("mimetype")
        .file_name(filename.to_owned())
}

/// Genere une nouvelle Part pour un fichier a uploader dans un form multipart
fn bytes_to_part(filename: &str, contenu: Vec<u8>, mimetype: Option<&str>) -> Part {

    let mimetype_inner = match mimetype {
        Some(m) => m,
        None => "application/octet-stream"
    };

    let vec_message = Vec::from(contenu);
    Part::bytes(vec_message)
        .mime_str(mimetype_inner).expect("mimetype")
        .file_name(filename.to_owned())
}

/// Reset l'etat de backup des transactions d'une collection
pub async fn reset_backup_flag<M>(middleware: &M, nom_collection_transactions: &str) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
    where M: MongoDao + GenerateurMessages,
{
    let collection = middleware.get_collection(nom_collection_transactions)?;
    let filtre = doc! { TRANSACTION_CHAMP_BACKUP_FLAG: true };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: false},
        "$unset": {
            TRANSACTION_CHAMP_BACKUP_HORAIRE: true,
            TRANSACTION_CHAMP_TRANSACTION_RESTAUREE: true,
        },
    };
    debug!("reset_backup_flag Filtre update flags sur {} : {:?}, ops: {:?}", nom_collection_transactions, filtre, ops);
    let (reponse, _) = match collection.update_many(filtre, ops, None).await {
        Ok(r) => {
            debug!("reset_backup_flag Update result {} : {:?}", nom_collection_transactions, r);
            middleware.build_reponse(json!({"ok": true, "count": r.modified_count}))?
        },
        Err(e) => {
            error!("reset_backup_flag Erreur sur {} : {:?}", nom_collection_transactions, e);
            middleware.build_reponse(json!({"ok": false, "err": format!("{:?}", e)}))?
        }
    };

    Ok(Some(reponse))
}

pub async fn persister_certificats<M>(middleware: &M, nom_collection_transactions: &str)
    -> Result<(), crate::error::Error>
    where M: MongoDao + GenerateurMessages,
{
    debug!("persister_certificats Debut");

    let collection = middleware.get_collection(nom_collection_transactions)?;
    let mut curseur = {
        let filtre = doc! {"certificat": {"$exists": true}};
        let projection = doc! {"pubkey": 1, "certificat": 1};
        let find_opts = FindOptions::builder()
            .projection(projection)
            .build();

        collection.find(filtre, Some(find_opts)).await?
    };

    let mut fingerprint_traites_set = HashSet::new();
    let routage = RoutageMessageAction::builder(DOMAINE_PKI, COMMANDE_SAUVEGARDER_CERTIFICAT, vec![Securite::L3Protege])
        .timeout_blocking(3000)
        .build();

    while let Some(row_cert) = curseur.next().await {
        let row_cert = row_cert?;
        let row_cert_mappe: TransactionCertRow = match convertir_bson_deserializable(row_cert) {
            Ok(inner) => inner,
            Err(e) => {
                warn!("persister_certificats Erreur mapping row : {:?}", e);
                continue;
            }
        };

        let fingerprint = row_cert_mappe.pubkey;

        if ! fingerprint_traites_set.contains(fingerprint.as_str()) {
            debug!("persister_certificats Sauvegarder certificat {}", fingerprint);

            let commande_sauvegarde = json!({
                "chaine_pem": row_cert_mappe.certificat,
                // "ca": ...
            });

            match middleware.transmettre_commande(routage.clone(), &commande_sauvegarde).await {
                Ok(_) => {
                    // Conserver marqueur pour indiquer que le certificat a ete traite
                    fingerprint_traites_set.insert(fingerprint);
                },
                Err(e) => warn!("persister_certificats Erreur sauvegarde certificat : {:?}", e)
            }
        }

    }

    if fingerprint_traites_set.len() > 0 {
        // Cleanup de tous les certificats traites dans les transaction
        let fingerprint_traites: Vec<String> = fingerprint_traites_set.into_iter().collect();
        let filtre = doc! {
            "certificat": {"$exists": true},
            "pubkey": {"$in": fingerprint_traites}
        };
        debug!("persister_certificats Filtre nettoyage certificats : {:?}", filtre);
        let ops = doc! {
            "$unset": {"certificat": 1},
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        collection.update_many(filtre, ops, None).await?;
    }

    debug!("persister_certificats Fin");

    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct TransactionCertRow {
    pubkey: String,
    certificat: Vec<String>
}

pub async fn emettre_evenement_backup<M>(
    middleware: &M, info_backup: &BackupInformation, evenement: &str, timestamp: &DateTime<Utc>)
    -> Result<(), crate::error::Error>
    where M: GenerateurMessages
{
    let value = json!({
        "uuid_rapport": info_backup.uuid_backup.as_str(),
        "evenement": evenement,
        "domaine": info_backup.domaine.as_str(),
        "timestamp": timestamp.timestamp(),
    });

    let routage = RoutageMessageAction::builder(info_backup.domaine.as_str(), BACKUP_EVENEMENT_MAJ, vec![L2Prive])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

pub async fn emettre_evenement_backup_catalogue<M>(
    middleware: &M, info_backup: &BackupInformation, transactions_traitees: i64) -> Result<(), CommonError>
    where M: GenerateurMessages
{
    let value = json!({
        "uuid_rapport": info_backup.uuid_backup.as_str(),
        "evenement": "cataloguePret",
        "domaine": info_backup.domaine.as_str(),
        "transactions_traitees": transactions_traitees,
    });

    let routage = RoutageMessageAction::builder(info_backup.domaine.as_str(), BACKUP_EVENEMENT_MAJ, vec![L2Prive])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

pub async fn emettre_evenement_restauration<M>(
    middleware: &M, domaine: &str, evenement: &str) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let value = json!({
        "evenement": evenement,
        "domaine": domaine,
    });

    let routage = RoutageMessageAction::builder(BACKUP_NOM_DOMAINE_GLOBAL, "restaurationMaj", vec![L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

pub async fn emettre_evenement_regeneration<M>(
    middleware: &M, domaine: &str, evenement: &str) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let value = json!({
        "evenement": evenement,
        "domaine": domaine,
    });

    let routage = RoutageMessageAction::builder(BACKUP_NOM_DOMAINE_GLOBAL, "regenerationMaj", vec![L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

#[derive(Clone, Debug, Deserialize)]
struct ReponseCertificat {
    ok: Option<bool>,
    chaine_pem: Option<Vec<String>>,
}

// #[cfg(test)]
// mod backup_tests {
//     use std::io::ErrorKind;
//
//     use async_std::fs;
//     use chrono::TimeZone;
//     use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesRef, MessageMilleGrillesRefDefault};
//     use mongodb::Database;
//     use openssl::x509::store::X509Store;
//     use openssl::x509::X509;
//     use serde_json::json;
//
//     use crate::backup_restoration::TransactionReader;
//     use crate::certificats::{FingerprintCertPublicKey, ValidateurX509Impl};
//     use crate::certificats::certificats_tests::{CERT_CORE, charger_enveloppe_privee_env, prep_enveloppe};
//     // use crate::middleware_db::preparer_middleware_db;
//     use crate::chiffrage::{ChiffrageFactoryImpl, CipherMgsCurrent, CleChiffrageHandler, MgsCipherData, MgsCipherKeysCurrent};
//     use crate::generateur_messages::RoutageMessageReponse;
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     const NOM_DOMAINE_BACKUP: &str = "DomaineTest";
//     const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";
//
//     trait TestChiffreurMgs4Trait: Chiffreur<CipherMgsCurrent, MgsCipherKeysCurrent> + ValidateurX509 +
//         FormatteurMessage + VerificateurMessage {}
//
//     struct TestChiffreurMgs4 {
//         cles_chiffrage: Vec<FingerprintCertPublicKey>,
//         validateur: Arc<ValidateurX509Impl>,
//         enveloppe_privee: Arc<EnveloppePrivee>,
//     }
//
//     impl ChiffrageFactoryTrait for TestChiffreurMgs4 {
//         fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
//             todo!("fix me")
//         }
//     }
//
//     #[async_trait]
//     impl CleChiffrageHandler for TestChiffreurMgs4 {
//         fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
//             self.cles_chiffrage.clone()
//         }
//
//         async fn charger_certificats_chiffrage<M>(&self, _middleware: &M)
//             -> Result<(), Box<dyn Error>>
//             where M: GenerateurMessages
//         {
//             Ok(())  // Rien a faire
//         }
//
//         async fn recevoir_certificat_chiffrage<M>(&self, _middleware: &M, _message: &TypeMessage) -> Result<(), String>
//             where M: ConfigMessages
//         {
//             Ok(())  // Rien a faire
//         }
//     }
//
//     #[async_trait]
//     impl Chiffreur<CipherMgsCurrent, MgsCipherKeysCurrent> for TestChiffreurMgs4 {
//         fn get_cipher(&self) -> Result<CipherMgsCurrent, Box<dyn Error>> {
//             let fp_public_keys = self.get_publickeys_chiffrage();
//             Ok(CipherMgs4::new(&fp_public_keys)?)
//         }
//     }
//
//     #[async_trait]
//     impl ValidateurX509 for TestChiffreurMgs4 {
//         async fn charger_enveloppe(&self, _chaine_pem: &Vec<String>, _fingerprint: Option<&str>, _ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
//             todo!()
//         }
//
//         async fn cacher(&self, _certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {
//             todo!()
//         }
//
//         fn set_flag_persiste(&self, fingerprint: &str) {
//             todo!()
//         }
//
//         async fn get_certificat(&self, _fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
//             Some(self.enveloppe_privee.enveloppe.clone())
//         }
//
//         fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
//             todo!()
//         }
//
//         fn idmg(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_pem(&self) -> &str {
//             todo!()
//         }
//
//         fn ca_cert(&self) -> &X509 {
//             todo!()
//         }
//
//         fn store(&self) -> &X509Store {
//             todo!()
//         }
//
//         fn store_notime(&self) -> &X509Store {
//             todo!()
//         }
//
//         async fn entretien_validateur(&self) {
//             todo!()
//         }
//     }
//
//     impl IsConfigurationPki for TestChiffreurMgs4 {
//         fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
//             self.enveloppe_privee.clone()
//         }
//     }
//
//     impl VerificateurMessage for TestChiffreurMgs4 {
//         fn verifier_message(
//             &self,
//             message: &MessageMilleGrillesRefDefault,
//             options: Option<&ValidationOptions>
//         ) -> Result<ResultatValidation, Box<dyn Error>> {
//             Ok(ResultatValidation {
//                 signature_valide: true,
//                 hachage_valide: Some(true),
//                 certificat_valide: true,
//                 regles_valides: true
//             })
//         }
//     }
//
//     impl FormatteurMessage for TestChiffreurMgs4 {
//         fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
//             todo!()
//         }
//
//         fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
//             todo!()
//         }
//     }
//
//     impl MongoDao for TestChiffreurMgs4 {
//         fn get_database(&self) -> Result<Database, String> {
//             todo!()
//         }
//     }
//
//     #[async_trait]
//     impl GenerateurMessages for TestChiffreurMgs4 {
//
//         async fn emettre_evenement<R, M>(&self, routage: R, message: &M) -> Result<(), String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn transmettre_requete<R, M>(&self, routage: R, message: &M) -> Result<TypeMessage, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn soumettre_transaction<R, M>(&self, routage: R, message: &M) -> Result<Option<TypeMessage>, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn transmettre_commande<R, M>(&self, routage: R, message: &M) -> Result<Option<TypeMessage>, String> where R: Into<RoutageMessageAction>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn repondre<R, M>(&self, routage: R, message: M) -> Result<(), String> where R: Into<RoutageMessageReponse>, M: Serialize + Send + Sync {
//             todo!()
//         }
//
//         async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M) -> Result<Option<TypeMessage>, String> where M: Into<MessageMilleGrillesBufferDefault> {
//             let json_message = match serde_json::to_string(&message) {
//                 Ok(j) => j,
//                 Err(e) => Err(format!("emettre_message Erreur conversion json : {:?}", e))?
//             };
//             debug!("emettre_message(stub) {:?}", json_message);
//             Ok(None)
//         }
//
//         fn mq_disponible(&self) -> bool {
//             todo!()
//         }
//
//         fn set_regeneration(&self) {
//             todo!()
//         }
//
//         fn reset_regeneration(&self) {
//             todo!()
//         }
//
//         fn get_mode_regeneration(&self) -> bool {
//             todo!()
//         }
//
//         fn get_securite(&self) -> &Securite {
//             todo!()
//         }
//     }
//
//     #[test]
//     fn init_backup_information() {
//         setup("init_backup_information");
//
//         let info = BackupInformation::new(
//             NOM_DOMAINE_BACKUP,
//             NOM_COLLECTION_BACKUP,
//             None
//         ).expect("init");
//
//         let workpath = info.workpath.to_str().unwrap();
//
//         assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
//         // assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
//         // assert_eq!(info.chiffrer, false);
//         assert_eq!(workpath.starts_with("/tmp/."), true);
//     }
//
//     // #[test]
//     // fn init_backup_horaire_builder() {
//     //     setup("init_backup_horaire_builder");
//     //
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
//     //     let uuid_backup = Uuid::new_v4().to_string();
//     //
//     //     let catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup);
//     //
//     //     assert_eq!(catalogue_builder.date_backup.get_datetime().timestamp(), heure.get_datetime().timestamp());
//     //     assert_eq!(&catalogue_builder.nom_domaine, NOM_DOMAINE_BACKUP);
//     // }
//
//     // #[test]
//     // fn build_catalogue() {
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     let catalogue = catalogue_builder.build();
//     //     debug!("Catalogue : {:?}", catalogue);
//     //
//     //     assert_eq!(catalogue.date_backup, heure);
//     //     assert_eq!(&catalogue.uuid_backup, uuid_backup);
//     //     assert_eq!(&catalogue.catalogue_nomfichier, "DomaineTest_2021080105.json.xz");
//     //     // assert_eq!(&catalogue.transactions_nomfichier, "Domaine.test_2021080105.jsonl.xz");
//     // }
//
//     // #[test]
//     // fn build_catalogue_params() {
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let transactions_hachage = "zABCD1234";
//     //
//     //     let mut catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     catalogue_builder.data_hachage_bytes = transactions_hachage.to_owned();
//     //
//     //     let catalogue = catalogue_builder.build();
//     //
//     //     assert_eq!(&catalogue.data_hachage_bytes, transactions_hachage);
//     // }
//
//     // #[test]
//     // fn serialiser_catalogue() {
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     let catalogue = catalogue_builder.build();
//     //
//     //     let _ = serde_json::to_value(catalogue).expect("value");
//     //
//     //     // debug!("Valeur catalogue : {:?}", value);
//     // }
//
//     // #[test]
//     // fn catalogue_to_json() {
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     let catalogue = catalogue_builder.build();
//     //
//     //     let value = serde_json::to_value(catalogue).expect("value");
//     //     let catalogue_str = serde_json::to_string(&value).expect("json");
//     //     // debug!("Json catalogue : {:?}", catalogue_str);
//     //
//     //     assert_eq!(true, catalogue_str.find("1627794000").expect("val") > 0);
//     //     assert_eq!(true, catalogue_str.find(NOM_DOMAINE_BACKUP).expect("val") > 0);
//     //     assert_eq!(true, catalogue_str.find(uuid_backup).expect("val") > 0);
//     // }
//
//     // #[test]
//     // fn build_catalogue_1certificat() {
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let mut catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     let certificat = prep_enveloppe(CERT_CORE);
//     //     // debug!("!!! Enveloppe : {:?}", certificat);
//     //
//     //     catalogue_builder.ajouter_certificat(&certificat);
//     //
//     //     let catalogue = catalogue_builder.build();
//     //     debug!("!!! Catalogue : {:?}", catalogue);
//     //     assert_eq!(catalogue.certificats.len(), 1);
//     // }
//
//     // #[tokio::test]
//     // async fn roundtrip_json() {
//     //     let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions.jsonl.xz");
//     //
//     //     let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");
//     //     let doc_json = json!({
//     //         "contenu": "Du contenu a encoder",
//     //         "valeur": 1234,
//     //         // "date": Utc.timestamp(1629464027, 0),
//     //     });
//     //     writer.write_json_line(&doc_json).await.expect("write");
//     //     writer.write_json_line(&doc_json).await.expect("write");
//     //     writer.write_json_line(&doc_json).await.expect("write");
//     //
//     //     let _ = writer.fermer().await.expect("fermer");
//     //     debug!("File du writer : {:?}", path_fichier);
//     //
//     //     let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
//     //     let mut reader = TransactionReader::new(fichier_cs, None).expect("reader");
//     //     debug!("Extraction transactions du xz");
//     //     let transactions = reader.read_transactions().await.expect("transactions");
//     //     for t in transactions {
//     //         debug!("Transaction : {:?}", t);
//     //         assert_eq!(&doc_json, &t);
//     //     }
//     //
//     // }
//
//     fn get_doc_reference() -> (String, Document) {
//         let doc_bson = doc! {
//             "_id": "Un ID dummy qui doit etre retire",
//             "contenu": "Du contenu BSON (Document) a encoder",
//             "valeur": 5678,
//             "date": Utc.timestamp(1629464026, 0),
//         };
//
//         (String::from("zSEfXUAj2MrtorrFTqvt38Je8XrW78425oDMseC3QMiX29xXi1SPu4xhzjDoNTizh7eXHgpbsc5UY9aasHoy2tXCpURFjt"), doc_bson)
//     }
//
//     // #[tokio::test]
//     // async fn ecrire_transactions_writer_bson() {
//     //     let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz");
//     //     let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");
//     //
//     //     let (mh_reference, doc_bson) = get_doc_reference();
//     //     writer.write_bson_line(&doc_bson).await.expect("write");
//     //
//     //     let (mh, _) = writer.fermer().await.expect("fermer");
//     //     // debug!("File du writer : {:?}, multihash: {}", file, mh);
//     //
//     //     assert_eq!(mh.as_str(), &mh_reference);
//     // }
//
//     // #[tokio::test]
//     // async fn charger_transactions() {
//     //     let path_fichier = PathBuf::from("/tmp/test_charger_fichier.json");
//     //     {
//     //         let mut fichier = File::create(&path_fichier).await.expect("create");
//     //         fichier.write("Allo".as_bytes()).await.expect("write");
//     //         fichier.close().await.expect("close");
//     //     }
//     //
//     //     let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
//     //     let uuid_backup = "DUMMY-11d8-4ff2-aa6f-1a605bd17336";
//     //
//     //     let mut catalogue_builder = CatalogueBackupBuilder::new(
//     //         heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());
//     //
//     //     catalogue_builder.charger_transactions_chiffrees(&path_fichier).await.expect("transactions");
//     //
//     //     debug!("Transactions hachage : {}", catalogue_builder.data_hachage_bytes);
//     //     debug!("Transactions data : {}", catalogue_builder.data_transactions);
//     //
//     //     assert_eq!("zSEfXUBUUM6YRxhgeJraN95eUyibKjQUg9oxHtnsKSix7GNPjxZHvhQVwTweuwySe9fdeHtFpg6kQtNgDNp6GQw1uj9Qff", catalogue_builder.data_hachage_bytes);
//     //     assert_eq!("mQWxsbw", catalogue_builder.data_transactions);
//     // }
//
//     // /// Test de chiffrage du backup - round trip
//     // #[tokio::test]
//     // async fn chiffrer_roundtrip_backup() {
//     //     let (validateur, enveloppe) = charger_enveloppe_privee_env();
//     //     let enveloppe = Arc::new(enveloppe);
//     //
//     //     let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.mgs");
//     //     let _fp_certs = vec!(FingerprintCertPublicKey::new(
//     //         String::from("dummy"),
//     //         enveloppe.certificat().public_key().clone().expect("cle"),
//     //         true
//     //     ));
//     //
//     //     let (fingerprint_cert, chiffreur) = creer_test_middleware(enveloppe.clone(), validateur);
//     //
//     //     let mut writer = TransactionWriter::new(
//     //         path_fichier.as_path(),
//     //         Some(&chiffreur)
//     //     ).await.expect("writer");
//     //
//     //     let (mh_reference, doc_bson) = get_doc_reference();
//     //     writer.write_bson_line(&doc_bson).await.expect("write chiffre");
//     //     let (mh, decipher_data_option) = writer.fermer().await.expect("fermer");
//     //
//     //     // Verifier que le hachage n'est pas egal au hachage de la version non chiffree
//     //     assert_ne!(mh.as_str(), &mh_reference);
//     //
//     //     let decipher_keys = decipher_data_option.expect("decipher data");
//     //     let mut decipher_key = decipher_keys.get_cipher_data(fingerprint_cert.as_str()).expect("cle");
//     //     decipher_key.dechiffrer_cle(enveloppe.cle_privee()).expect("dechiffrer");
//     //     debug!("Cle dechiffree : {:?}", decipher_key);
//     //
//     //     todo!("Fix decipher keys mgs4");
//     //
//     //     // let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
//     //     // let mut reader = TransactionReader::new(fichier_cs, Some(&decipher_key)).expect("reader");
//     //     // let transactions = reader.read_transactions().await.expect("transactions");
//     //     //
//     //     // for t in transactions {
//     //     //     debug!("Transaction dechiffree : {:?}", t);
//     //     //     let valeur_chiffre = t.get("valeur").expect("valeur").as_i64().expect("val");
//     //     //     assert_eq!(valeur_chiffre, 5678);
//     //     // }
//     //
//     // }
//
//     // fn creer_test_middleware(enveloppe: Arc<EnveloppePrivee>, validateur: Arc<ValidateurX509Impl>) -> (String, TestChiffreurMgs4) {
//     //     let mut fp_public_keys = Vec::new();
//     //     let fingerprint_cert = enveloppe.enveloppe.fingerprint.clone();
//     //     let cle_publique = &enveloppe.enveloppe.cle_publique;
//     //     fp_public_keys.push(FingerprintCertPublicKey {
//     //         fingerprint: fingerprint_cert.clone(),
//     //         public_key: cle_publique.to_owned(),
//     //         est_cle_millegrille: false,
//     //     });
//     //     let cle_publique_ca = &enveloppe.enveloppe_ca.cle_publique;
//     //     fp_public_keys.push(FingerprintCertPublicKey {
//     //         fingerprint: enveloppe.enveloppe_ca.fingerprint.clone(),
//     //         public_key: cle_publique_ca.to_owned(),
//     //         est_cle_millegrille: true,
//     //     });
//     //     let chiffreur = TestChiffreurMgs4 { cles_chiffrage: fp_public_keys, validateur, enveloppe_privee: enveloppe };
//     //     (fingerprint_cert, chiffreur)
//     // }
//
//     // #[tokio::test]
//     // async fn test_emettre_fichiers_backup() {
//     //
//     //     // Setup
//     //     let (validateur, enveloppe) = charger_enveloppe_privee_env();
//     //     let enveloppe = Arc::new(enveloppe);
//     //     let (_fingerprint_cert, m) = creer_test_middleware(enveloppe.clone(), validateur);
//     //
//     //     //let temp_dir = tempdir().expect("tempdir");
//     //     let temp_dir = PathBuf::from(format!("/tmp/test_generer_fichiers_backup"));
//     //     match fs::create_dir(&temp_dir).await {
//     //         Ok(()) => (),
//     //         Err(e) => {
//     //             match e.kind() {
//     //                 ErrorKind::AlreadyExists => (),
//     //                 _ => panic!("Erreur createdir: {:?}", e)
//     //             }
//     //         }
//     //     }
//     //
//     //     let fichiers_backup = vec!["/tmp/test_generer_fichiers_backup/catalogue_0.json"];
//     //
//     //     emettre_backup_transactions(&m, "DUMMY_COLLECTION", &fichiers_backup)
//     //         .await.expect("emettre_backup_transactions");
//     //
//     // }
//
// }
