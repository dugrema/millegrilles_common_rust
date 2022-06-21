use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufWriter, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use core::str::FromStr;

use async_std::fs::File;
use async_std::io::BufReader;
use async_std::prelude::Stream;
use async_trait::async_trait;
use bytes::buf::Writer;
use chrono::{DateTime, Duration, Timelike, Utc};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use futures::TryStream;
use futures_util::TryStreamExt;
use log::{debug, error, info, warn};
use mongodb::bson::{doc, Document};
use mongodb::Cursor;
use mongodb::options::{AggregateOptions, FindOptions, Hint};
use multibase::{Base, decode, encode};
use multihash::Code;
use redis::transaction;
use reqwest::{Body, Response};
use reqwest::multipart::Part;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::{TempDir, tempdir, tempfile};
use tokio::fs::File as File_tokio;
use tokio::sync::mpsc::Sender;
use tokio_stream::{Iter, StreamExt};
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;
use xz2::stream;

use crate::certificats::{CollectionCertificatsPem, EnveloppeCertificat, EnveloppePrivee, ValidateurX509};
use crate::chiffrage::{Chiffreur, Dechiffreur, DecipherMgs, MgsCipherKeys};
use crate::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use crate::configuration::{ConfigMessages, IsConfigNoeud};
use crate::constantes::*;
use crate::constantes::Securite::L3Protege;
use crate::fichiers::{CompresseurBytes, DecompresseurBytes, FichierWriter, parse_tar, TraiterFichier};
use crate::formatteur_messages::{DateEpochSeconds, Entete, FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::hachages::{hacher_bytes, hacher_serializable};
use crate::middleware::IsConfigurationPki;
use crate::middleware_db::MiddlewareDb;
use crate::mongo_dao::{MongoDao, CurseurIntoIter, CurseurStream, convertir_bson_deserializable, CurseurMongo};
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use crate::tokio::sync::mpsc::Receiver;
use crate::transactions::{regenerer, sauvegarder_batch, TraiterTransaction};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};

// Max size des transactions, on tente de limiter la taille finale du message
// decompresse a 5MB (bytes vers base64 augmente taille de 50%)
const TRANSACTIONS_MAX_SIZE: usize = 3 * 1024 * 1024;
const TRANSACTIONS_MAX_NB: usize = 1000;  // Limite du nombre de transactions par fichier

/// Handler de backup qui ecoute sur un mpsc. Lance un backup a la fois dans une thread separee.
pub async fn thread_backup<M>(middleware: Arc<M>, mut rx: Receiver<CommandeBackup>)
    where M: MongoDao + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + GenerateurMessages + ConfigMessages + VerificateurMessage
{
    while let Some(commande) = rx.recv().await {
        let nom_domaine = commande.nom_domaine;
        info!("Debug backup {}", nom_domaine);
        match backup(middleware.as_ref(), &nom_domaine, commande.nom_collection_transactions).await {
            Ok(_) => info!("Backup {} OK", nom_domaine),
            Err(e) => error!("backup.thread_backup Erreur backup domaine {} : {:?}", nom_domaine, e)
        };
    }
}

#[derive(Clone, Debug)]
pub struct CommandeBackup {
    pub nom_domaine: String,
    pub nom_collection_transactions: String,
    pub complet: bool,
}

#[async_trait]
pub trait BackupStarter {
    fn get_tx_backup(&self) -> Sender<CommandeBackup>;

    async fn demarrer_backup<S,T>(&self, nom_domaine: S, nom_collection_transactions: T, complet: bool)
        -> Result<(), Box<dyn Error>>
        where S: Into<String> + Send, T: Into<String> + Send
    {
        let commande = CommandeBackup {
            nom_domaine: nom_domaine.into(),
            nom_collection_transactions: nom_collection_transactions.into(),
            complet,
        };

        let tx_backup = self.get_tx_backup();
        debug!("backup.BackupStarter Demarrage backup {:?}", &commande);
        tx_backup.send(commande).await?;

        Ok(())
    }
}

/// Lance un backup complet de la collection en parametre.
pub async fn backup<M,S,T>(middleware: &M, nom_domaine: S, nom_collection_transactions: T)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where
        M: MongoDao + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + GenerateurMessages + ConfigMessages + VerificateurMessage,
        S: AsRef<str>, T: AsRef<str>,
{
    let nom_coll_str = nom_collection_transactions.as_ref();
    let nom_domaine_str = nom_domaine.as_ref();

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempdir()?;
    info!("backup.backup Backup horaire de {} vers tmp : {:?}", nom_domaine_str, workdir);

    let info_backup = BackupInformation::new(
        nom_domaine_str,
        nom_coll_str,
        Some(workdir.path().to_owned())
    )?;

    let transactions = requete_transactions(middleware, &info_backup).await?;
    let fichiers_backup = generer_fichiers_backup(middleware, transactions, workdir, &info_backup).await?;

    emettre_backup_transactions(middleware, &fichiers_backup).await?;

    Ok(None)
}

/// Generer les fichiers de backup localement
/// returns: Liste de fichiers generes
async fn generer_fichiers_backup<M,S,P>(middleware: &M, mut transactions: S, workdir: P, info_backup: &BackupInformation)
    -> Result<Vec<PathBuf>, Box<dyn Error>>
    where
        M: ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + FormatteurMessage + VerificateurMessage,
        S: CurseurStream,
        P: AsRef<Path>
{
    let workir_path = workdir.as_ref();
    let timestamp_backup = Utc::now();
    debug!("Debut generer fichiers de backup avec timestamp {:?}", timestamp_backup);

    let mut fichiers_generes: Vec<PathBuf> = Vec::new();
    let mut len_written: usize = 0;
    let mut nb_transactions_written: usize = 0;
    let (mut builder, mut path_fichier) = nouveau_catalogue(workir_path, info_backup, fichiers_generes.len())?;
    debug!("Creation fichier backup : {:?}", path_fichier);
    let mut writer = TransactionWriter::new(&path_fichier, Some(middleware)).await?;

    let options_validation = ValidationOptions::new(false, true, true);
    while let Some(doc_transaction) = transactions.try_next().await? {
        debug!("Traitement transaction {:?}", doc_transaction);

        if len_written >= TRANSACTIONS_MAX_SIZE || nb_transactions_written >= TRANSACTIONS_MAX_NB {
            debug!("Limite transaction par fichier atteinte, on fait une rotation");
            let path_catalogue = sauvegarder_catalogue(
                middleware, workir_path, &mut fichiers_generes, builder, &mut path_fichier, writer).await?;
            fichiers_generes.push(path_catalogue.clone());

            // Reset compteur de catalogue
            len_written = 0;
            nb_transactions_written = 0;

            // Ouvrir nouveau fichier
            let (builder_1, path_fichier_1) = nouveau_catalogue(workir_path, info_backup, fichiers_generes.len())?;
            builder = builder_1;
            path_fichier = path_fichier_1;
            writer = TransactionWriter::new(&path_fichier, Some(middleware)).await?;
        }

        // Verifier la transaction - doit etre completement valide, certificat connu
        let mut transaction = MessageSerialise::from_serializable(&doc_transaction)?;
        let resultat_verification = middleware.verifier_message(&mut transaction, Some(&options_validation))?;
        debug!("Resultat verification transaction : {:?}", resultat_verification);

        let entete = transaction.get_entete();
        let uuid_transaction = entete.uuid_transaction.as_str();
        let date_traitement_transaction = match doc_transaction.get("_evenements") {
            Some(d) => match d.as_document() {
                Some(e) => match e.get("transaction_traitee") {
                    Some(d) => match d.as_datetime() {
                        Some(d) => {
                            DateEpochSeconds::from_i64(d.timestamp_millis()/1000)
                        },
                        None => {
                            debug!("Mauvais type d'element _evenements.transaction_traitee pour {} transaction. Utiliser estampille.", entete.uuid_transaction);
                            entete.estampille.clone()
                        }
                    },
                    None => {
                        debug!("Mauvais type d'element _evenements.transaction_traitee pour {} transaction. Utiliser estampille.", entete.uuid_transaction);
                        entete.estampille.clone()
                    }
                },
                None => {
                    debug!("Mauvais type d'element _evenements pour {} transaction. Utiliser estampille.", entete.uuid_transaction);
                    entete.estampille.clone()
                }
            },
            None => {
                debug!("Aucune information d'evenements (_eveneemnts) pour une transaction. Utiliser estampille.");
                entete.estampille.clone()
            }
        };

        if resultat_verification.valide() {
            let fingerprint_certificat = entete.fingerprint_certificat.as_str();
            let estampille = &entete.estampille;
            let certificat = match middleware.get_certificat(fingerprint_certificat).await {
                Some(c) => c,
                None => {
                    error!("Certificat introuvable pour transaction {}, ** SKIP TRANSACTION **", uuid_transaction);
                    continue;
                }
            };
            builder.ajouter_certificat(certificat.as_ref());
            builder.ajouter_transaction(uuid_transaction, &date_traitement_transaction);

            let len_message = writer.write_bson_line(&doc_transaction).await?;
            len_written += len_message;
            nb_transactions_written += 1;
        } else {
            error!("Transaction {} invalide ({:?}), ** SKIPPED **", uuid_transaction, resultat_verification);
            continue;
        }
    }

    let path_catalogue = sauvegarder_catalogue(middleware, workir_path, &mut fichiers_generes, builder, &mut path_fichier, writer).await?;
    fichiers_generes.push(path_catalogue.clone());

    Ok(fichiers_generes)
}

async fn sauvegarder_catalogue<M>(
    middleware: &M, workir_path: &Path, mut fichiers_generes: &mut Vec<PathBuf>, mut builder: CatalogueBackupBuilder, path_fichier: &mut PathBuf, writer: TransactionWriter)
    -> Result<PathBuf, Box<dyn Error>>
    where M: FormatteurMessage
{
    let (hachage, keys) = writer.fermer().await?;

    if let Some(c) = &keys {
        builder.set_cles(c);
    }

    builder.charger_transactions_chiffrees(&path_fichier).await?;  // Charger, hacher transactions
    // Comparer hachages ecrits et lus
    if hachage != builder.data_hachage_bytes {
        Err(format!("Erreur creation backup - hachage transactions memoire {} et disque {} mismatch, abandon", hachage, builder.data_hachage_bytes))?;
    }
    let catalogue = builder.build();
    let mut path_catalogue = PathBuf::new();
    path_catalogue.push(workir_path);
    path_catalogue.push(format!("catalogue_{}.json", fichiers_generes.len()));
    let mut fichier_catalogue = std::fs::File::create(&path_catalogue)?;

    let catalogue_signe = middleware.formatter_message(
        &catalogue, Some("Backup"), Some("backupTransactions"), None, None, false)?;
    serde_json::to_writer(fichier_catalogue, &catalogue_signe)?;

    Ok(path_catalogue)
}

fn nouveau_catalogue<P>(workdir: P, info_backup: &BackupInformation, compteur: usize)
                        -> Result<(CatalogueBackupBuilder, PathBuf), Box<dyn Error>>
    where P: AsRef<Path>
{
    let workdir_path = workdir.as_ref();

    let date_transaction = DateEpochSeconds::now();
    let mut builder = CatalogueBackupBuilder::new(
        date_transaction,
        info_backup.domaine.clone(),
        info_backup.partition.clone(),
        info_backup.uuid_backup.clone()
    );

    let mut path_fichier: PathBuf = PathBuf::new();
    path_fichier.push(workdir_path);
    path_fichier.push(PathBuf::from(format!("backup_{}.dat", compteur)));

    Ok((builder, path_fichier))
}

async fn requete_transactions(middleware: &impl MongoDao, info: &BackupInformation)
    -> Result<CurseurMongo, Box<dyn Error>>
{
    let nom_collection = &info.nom_collection_transactions;
    let collection = middleware.get_collection(nom_collection)?;

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
    };

    let sort = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
    let find_options = FindOptions::builder()
        .sort(sort)
        .hint(Hint::Name(String::from("backup_transactions")))
        .batch_size(50)
        .build();

    let curseur = collection.find(filtre, find_options).await?;

    // Wrapper dans CurseurMongo
    let curseur = CurseurMongo { curseur };

    Ok(curseur)
}

// async fn uploader_backup<M>(
//     middleware: &M,
//     path_transactions: &Path,
//     catalogue: &CatalogueBackup,
//     catalogue_signe: &MessageMilleGrille,
//     commande_cles: Option<MessageMilleGrille>
// ) -> Result<Response, Box<dyn Error>>
// where
//     M: ConfigMessages + IsConfigurationPki,
// {
//     let message_serialise = MessageSerialise::from_parsed(catalogue_signe.clone()).expect("ser");
//
//     // Compresser catalogue et commande maitre des cles en XZ
//     let mut compresseur_catalogue = CompresseurBytes::new().expect("compresseur");
//     compresseur_catalogue.write(message_serialise.get_str().as_bytes()).await.expect("write");
//     let (catalogue_bytes, _) = compresseur_catalogue.fermer().expect("finish");
//
//     let commande_bytes = match commande_cles {
//         Some(c) => {
//             let message_serialise = MessageSerialise::from_parsed(c).expect("ser");
//             let mut compresseur_commande = CompresseurBytes::new().expect("compresseur");
//             debug!("Commande maitre cles : {}", message_serialise.get_str());
//             compresseur_commande.write(message_serialise.get_str().as_bytes()).await.expect("write");
//             let (commande_bytes, _) = compresseur_commande.fermer().expect("finish");
//
//             Some(commande_bytes)
//         },
//         None => None
//     };
//
//     // let mut path_transactions = workdir.to_owned();
//     // path_transactions.push(PathBuf::from(catalogue.transactions_nomfichier.as_str()));
//
//     if ! path_transactions.exists() {
//         Err(format!("Fichier {:?} n'existe pas", path_transactions))?;
//     }
//
//     let enveloppe = middleware.get_enveloppe_privee().clone();
//     let ca_cert_pem = enveloppe.chaine_pem().last().expect("last cert").as_str();
//     let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
//     let identity = reqwest::Identity::from_pem(enveloppe.clecert_pem.as_bytes())?;
//
//     let fichier_transactions_read = File_tokio::open(path_transactions).await?;
//
//     // Uploader fichiers et contenu backup
//     let form = {
//         let mut form = reqwest::multipart::Form::new()
//             .text("timestamp_backup", catalogue.date_backup.format_ymdh())
//             //.part("transactions", file_to_part(catalogue.transactions_nomfichier.as_str(), fichier_transactions_read).await)
//             .part("catalogue", bytes_to_part(catalogue.catalogue_nomfichier.as_str(), catalogue_bytes, Some("application/xz")));
//
//         if let Some(b) = commande_bytes {
//             form = form.part("cles", bytes_to_part(
//                 "commande_maitredescles.json", b, Some("text/json")));
//         }
//
//         form
//     };
//
//     let client = reqwest::Client::builder()
//         .add_root_certificate(root_ca)
//         .identity(identity)
//         .https_only(true)
//         .use_rustls_tls()
//         .timeout(core::time::Duration::new(20, 0))
//         .build()?;
//
//     let mut url = match middleware.get_configuration_noeud().fichiers_url.as_ref() {
//         Some(url) => url.to_owned(),
//         None => {
//             Err("URL fichiers n'est pas configure pour les backups")?
//         }
//     };
//
//     let path_commande = format!("backup/domaine/{}", catalogue.catalogue_nomfichier);
//     url.set_path(path_commande.as_str());
//
//     debug!("Url backup : {:?}", url);
//
//     let request = client.put(url).multipart(form);
//
//     let response = request.send().await?;
//     debug!("Resultat {} : {:?}", response.status(), response);
//
//     Ok(response)
// }

async fn marquer_transaction_backup_complete<M,S,T>(middleware: &M, nom_collection_ref: S, uuid_transactions_ref: &Vec<T>)
    -> Result<(), Box<dyn Error>>
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
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: {"$in": &uuid_transactions}
    };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: true},
        "$currentDate": {TRANSACTION_CHAMP_BACKUP_HORAIRE: true},
    };

    let r= collection.update_many(filtre, ops, None).await?;
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
    uuid_backup: String,
    /// Repertoire temporaire qui est supprime automatiquement apres le backup.
    tmp_workdir: Option<TempDir>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueBackup {
    /// Heure de la premiere transaction du backup (traitement interne initial)
    pub date_backup: DateEpochSeconds,
    /// Heure de la premiere transaction du backup
    pub date_transactions_debut: DateEpochSeconds,
    /// Heure de la derniere tranaction du backup
    pub date_transactions_fin: DateEpochSeconds,
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

    /// En-tete du message de catalogue. Presente uniquement lors de deserialization.
    #[serde(rename = "en-tete", skip_serializing)]
    pub entete: Option<Entete>,

    /// Liste des transactions - resultat intermediaire, va etre retiree du fichier final
    #[serde(rename = "_uuid_transactions")]
    pub uuid_transactions: Vec<String>,

    /// Enchainement backup precedent
    //backup_precedent: Option<EnteteBackupPrecedent>,

    /// Cle chiffree avec la cle de MilleGrille (si backup chiffre)
    cle: Option<String>,

    /// IV du contenu chiffre
    iv: Option<String>,

    /// Compute tag du contenu chiffre
    tag: Option<String>,

    /// Format du chiffrage
    format: Option<String>,
}

impl CatalogueBackup {

    pub fn builder(heure: DateEpochSeconds, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> CatalogueBackupBuilder {
        CatalogueBackupBuilder::new(heure, nom_domaine, partition, uuid_backup)
    }

    pub fn get_cipher_data(&self) -> Result<Mgs3CipherData, Box<dyn Error>> {
        match &self.cle {
            Some(c) => {
                let iv = self.iv.as_ref().expect("iv");
                let tag = self.tag.as_ref().expect("tag");
                Mgs3CipherData::new(
                    c.as_str(),
                    iv,
                    tag
                )
            },
            None => Err("Non chiffre")?,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogueBackupBuilder {
    date_backup: DateEpochSeconds,      // Date de creation du backup (now)
    date_debut_backup: Option<DateEpochSeconds>,  // Date de traitement de la premiere transaction
    date_fin_backup: Option<DateEpochSeconds>,  // Date de traitement de la derniere transaction
    nom_domaine: String,
    partition: Option<String>,
    uuid_backup: String,                // Identificateur unique de ce backup
    // chiffrer: bool,
    // snapshot: bool,

    certificats: CollectionCertificatsPem,
    uuid_transactions: Vec<String>,     // Liste des transactions inclues (pas mis dans catalogue)
    data_hachage_bytes: String,         // Hachage du contenu chiffre
    data_transactions: String,          // Contenu des transactions en base64 (chiffre)
    cles: Option<Mgs3CipherKeys>,       // Cles pour dechiffrer le contenu
    // backup_precedent: Option<EnteteBackupPrecedent>,
}

impl CatalogueBackupBuilder {

    fn new(heure: DateEpochSeconds, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> Self {
        CatalogueBackupBuilder {
            date_backup: heure.clone(),
            date_debut_backup: None,  // Va etre la date de la derniere transaction
            date_fin_backup: None,  // Va etre la date de la derniere transaction
            nom_domaine, partition, uuid_backup, // chiffrer, snapshot,
            certificats: CollectionCertificatsPem::new(),
            uuid_transactions: Vec::new(),
            data_hachage_bytes: "".to_owned(),
            data_transactions: "".to_owned(),
            cles: None,
            // backup_precedent: None,
        }
    }

    fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat).expect("certificat");
    }

    fn ajouter_transaction(&mut self, uuid_transaction: &str, date_estampille: &DateEpochSeconds) {
        self.uuid_transactions.push(String::from(uuid_transaction));

        // Ajuste date debut et fin des transactions du backup
        match &self.date_debut_backup {
            Some(d) => {
                if d.get_datetime() > date_estampille.get_datetime() {
                    self.date_debut_backup = Some(date_estampille.to_owned());
                }
            },
            None => self.date_debut_backup = Some(date_estampille.to_owned())
        }
        match &self.date_fin_backup {
            Some(d) => {
                if d.get_datetime() < date_estampille.get_datetime() {
                    self.date_fin_backup = Some(date_estampille.to_owned());
                }
            },
            None => self.date_fin_backup = Some(date_estampille.to_owned())
        }
    }

    fn set_cles(&mut self, cles: &Mgs3CipherKeys) {
        self.cles = Some(cles.clone());
    }

    // fn get_nomfichier_catalogue(&self) -> PathBuf {
    //     let mut date_str = self.heure.format_ymdh();
    //     match self.snapshot {
    //         true => date_str = format!("{}-SNAPSHOT", date_str),
    //         false => (),
    //     }
    //     PathBuf::from(format!("{}_{}.json.xz", &self.nom_domaine, date_str))
    // }

    async fn charger_transactions_chiffrees(&mut self, path_fichier: &Path) -> Result<(), Box<dyn Error>> {
        let mut data = Vec::new();

        {
            let file = File::open(path_fichier).await?;
            let mut reader = BufReader::new(file);
            let mut buffer = [0u8; 64 * 1024];
            while let read_len = reader.read(&mut buffer).await? {
                if read_len == 0 { break; }
                data.extend(&buffer[..read_len]);
                if data.len() > TRANSACTIONS_MAX_SIZE {
                    Err(format!("La taille du fichier est plus grande que la limite de {} bytes", TRANSACTIONS_MAX_SIZE))?;
                }
            }
        }

        // Hacher le contenu (pour verification)
        self.data_hachage_bytes = hacher_bytes(data.as_slice(), Some(Code::Blake2b512), Some(Base::Base58Btc));

        // Convertir le contenu en base64
        debug!("Convertir data en base64 : {:?}", data);
        self.data_transactions = encode(Base::Base64, data.as_slice());

        Ok(())
    }

    pub fn build(self) -> CatalogueBackup {

        let date_str = self.date_backup.format_ymdh();

        // Build collections de certificats
        let catalogue_nomfichier = match &self.partition {
            Some(p) => {
                format!("{}.{}_{}.json.xz", &self.nom_domaine, p, date_str)
            },
            None => format!("{}_{}.json.xz", &self.nom_domaine, date_str)
        };

        let (format, cle, iv, tag) = match self.cles {
            Some(cles) => {
                (Some(cles.get_format()), cles.get_cle_millegrille(), Some(cles.iv), Some(cles.tag))
            },
            None => (None, None, None, None)
        };

        let date_transactions_debut = match self.date_debut_backup {
            Some(d) => d,
            None => self.date_backup.clone()
        };
        let date_transactions_fin = match self.date_fin_backup {
            Some(d) => d,
            None => self.date_backup.clone()
        };

        CatalogueBackup {
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
            uuid_transactions: self.uuid_transactions,

            entete: None,  // En-tete chargee lors de la deserialization

            cle, iv, tag, format,
        }
    }

}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new<S>(
        domaine: S,
        nom_collection_transactions: S,
        workpath: Option<PathBuf>
    ) -> Result<BackupInformation, Box<dyn Error>>
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

struct TransactionWriter {
    fichier_writer: FichierWriter<Mgs3CipherKeys, CipherMgs3>,
}

impl TransactionWriter {

    pub async fn new<C,P>(path_fichier: P, middleware: Option<&C>) -> Result<TransactionWriter, Box<dyn Error>>
    where
        C: Chiffreur<CipherMgs3, Mgs3CipherKeys>,
        P: Into<PathBuf>
    {
        let fichier_writer = FichierWriter::new(path_fichier, middleware).await?;
        Ok(TransactionWriter{fichier_writer})
    }

    /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
    pub async fn write_json_line(&mut self, contenu: &Value) -> Result<usize, Box<dyn Error>> {
        // Convertir value en bytes
        let mut contenu_bytes = serde_json::to_string(contenu)?.as_bytes().to_owned();

        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);

        // Write dans le fichier
        self.fichier_writer.write(contenu_bytes.as_slice()).await
    }

    pub async fn write_bson_line(&mut self, contenu: &Document) -> Result<usize, Box<dyn Error>> {
        let mut value = serde_json::to_value(contenu)?;

        // S'assurer qu'on a un document (map)
        // Retirer le champ _id si present
        match value.as_object_mut() {
            Some(doc) => {
                doc.remove("_id");
                self.write_json_line(&value).await
            },
            None => {
                warn!("Valeur bson fournie en backup n'est pas un _Document_, on l'ignore : {:?}", contenu);
                Ok(0)
            }
        }
    }

    pub async fn fermer(self) -> Result<(String, Option<Mgs3CipherKeys>), Box<dyn Error>> {
        self.fichier_writer.fermer().await
    }

}

/// Emet une liste de backup de transactions.
async fn emettre_backup_transactions<M,S>(middleware: &M, fichiers: &Vec<S>)
    -> Result<(), Box<dyn Error>>
    where
        M: GenerateurMessages,
        S: TryInto<PathBuf>
{
    for fichier_ref in fichiers {
        let fichier = fichier_ref.try_into()?;
        debug!("emettre_backup_transactions Traitement fichier {:?}", fichier);
        let fichier_fp = std::fs::File::open(fichier.as_path())?;
        let mut fichier_reader = std::io::BufReader::new(fichier_fp);

        // Charger fichier de backup
        let (message_backup, uuid_transactions) = {
            let mut message_backup: MessageMilleGrille = serde_json::from_reader(fichier_reader)?;
            debug!("emettre_backup_transactions Message backup a emettre : {:?}", message_backup);

            // Conserver liste de transactions, retirer du message a emettre
            let uuid_transactions: Vec<String> = message_backup.map_contenu(Some("_uuid_transactions"))?;
            message_backup.contenu.remove("_uuid_transactions");

            (message_backup, uuid_transactions)
        };

        let uuid_message_backup = message_backup.entete.uuid_transaction.clone();
        debug!("emettre_backup_transactions Emettre transactions dans le backup {} : {:?}", uuid_message_backup, uuid_transactions);

        let routage = RoutageMessageAction::builder(DOMAINE_FICHIERS, "backupTransactions")
            .exchanges(vec![Securite::L2Prive])
            .build();
        let reponse = middleware.emettre_message_millegrille(
            routage, true, TypeMessageOut::Commande, message_backup).await?;

        let reponse = match reponse {
            Some(r) => match r {
                TypeMessage::Valide(r) => r,
                _ => {
                    error!("emettre_backup_transactions Erreur sauvegarder fichier backup {}, ** SKIPPED **", uuid_message_backup);
                    continue;
                }
            },
            None => {
                error!("emettre_backup_transactions Aucune reponse, on assume que le backup de {} a echoue, ** SKIPPED **", uuid_message_backup);
                continue
            }
        };

        debug!("Reponse backup {} : {:?}", uuid_message_backup, reponse);

        // Marquer transactions comme etant completees
        todo!("marques transactions completees")
    }

    Ok(())
}


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
pub async fn reset_backup_flag<M>(middleware: &M, nom_collection_transactions: &str) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: MongoDao + GenerateurMessages,
{
    let collection = middleware.get_collection(nom_collection_transactions).expect("coll");
    let filtre = doc! { TRANSACTION_CHAMP_BACKUP_FLAG: true };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: false},
        "$unset": {
            TRANSACTION_CHAMP_BACKUP_HORAIRE: true,
            TRANSACTION_CHAMP_TRANSACTION_RESTAUREE: true,
        },
    };
    let reponse = match collection.update_many(filtre, ops, None).await {
        Ok(r) => {
            middleware.formatter_reponse(json!({"ok": true, "count": r.modified_count}), None)?
        },
        Err(e) => {
            middleware.formatter_reponse(json!({"ok": false, "err": format!("{:?}", e)}), None)?
        }
    };

    Ok(Some(reponse))
}

pub async fn emettre_evenement_backup<M>(
    middleware: &M, info_backup: &BackupInformation, evenement: &str, timestamp: &DateTime<Utc>) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages
{
    let value = json!({
        "uuid_rapport": info_backup.uuid_backup.as_str(),
        "evenement": evenement,
        "domaine": info_backup.domaine.as_str(),
        "timestamp": timestamp.timestamp(),
    });

    let routage = RoutageMessageAction::builder(BACKUP_NOM_DOMAINE_GLOBAL, BACKUP_EVENEMENT_MAJ)
        .exchanges(vec![L3Protege])
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

    let routage = RoutageMessageAction::builder(BACKUP_NOM_DOMAINE_GLOBAL, "restaurationMaj")
        .exchanges(vec![L3Protege])
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

    let routage = RoutageMessageAction::builder(BACKUP_NOM_DOMAINE_GLOBAL, "regenerationMaj")
        .exchanges(vec![L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &value).await?)
}

// def transmettre_evenement_backup(self, uuid_rapport: str, evenement: str, heure: datetime.datetime, info: dict = None, sousdomaine: str = None):
//     if sousdomaine is None:
//         sousdomaine = self._nom_domaine
//
//     evenement_contenu = {
//         ConstantesBackup.CHAMP_UUID_RAPPORT: uuid_rapport,
//         Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement,
//         ConstantesBackup.LIBELLE_DOMAINE: sousdomaine,
//         Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP: int(heure.timestamp()),
//         ConstantesBackup.LIBELLE_SECURITE: self.__niveau_securite,
//     }
//     if info:
//         evenement_contenu['info'] = info
//
//     domaine = 'evenement.Backup.' + ConstantesBackup.EVENEMENT_BACKUP_MAJ
//
//     self._contexte.generateur_transactions.emettre_message(
//         evenement_contenu, domaine, exchanges=[Constantes.SECURITE_PROTEGE]
//     )


#[cfg(test)]
mod backup_tests {
    use std::io::ErrorKind;
    use async_std::fs;
    use serde_json::json;

    use crate::certificats::certificats_tests::{CERT_CORE, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    use crate::fichiers::CompresseurBytes;
    use crate::fichiers::fichiers_tests::ChiffreurDummy;
    use crate::test_setup::setup;
    use chrono::TimeZone;
    use futures::io::BufReader;
    use openssl::x509::store::X509Store;
    use openssl::x509::X509;
    use crate::backup_restoration::TransactionReader;
    use crate::certificats::{FingerprintCertPublicKey, ValidateurX509Impl};
    use crate::middleware_db::preparer_middleware_db;
    use crate::chiffrage::MgsCipherData;
    use crate::generateur_messages::RoutageMessageReponse;
    use crate::mongo_dao::convertir_to_bson;

    use super::*;

    const NOM_DOMAINE_BACKUP: &str = "DomaineTest";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    trait TestChiffreurMgs3Trait: Chiffreur<CipherMgs3, Mgs3CipherKeys> + ValidateurX509 +
        FormatteurMessage + VerificateurMessage {}

    struct TestChiffreurMgs3 {
        cles_chiffrage: Vec<FingerprintCertPublicKey>,
        validateur: Arc<ValidateurX509Impl>,
        enveloppe_privee: Arc<EnveloppePrivee>,
    }

    #[async_trait]
    impl Chiffreur<CipherMgs3, Mgs3CipherKeys> for TestChiffreurMgs3 {

        fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
            self.cles_chiffrage.clone()
        }

        fn get_cipher(&self) -> Result<CipherMgs3, Box<dyn Error>> {
            let fp_public_keys = self.get_publickeys_chiffrage();
            Ok(CipherMgs3::new(&fp_public_keys)?)
        }

        async fn charger_certificats_chiffrage(&self, cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>> {
            Ok(())  // Rien a faire
        }

        async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>> {
            Ok(())  // Rien a faire
        }
    }

    #[async_trait]
    impl ValidateurX509 for TestChiffreurMgs3 {
        async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
            todo!()
        }

        async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
            todo!()
        }

        async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
            Some(self.enveloppe_privee.enveloppe.clone())
        }

        fn idmg(&self) -> &str {
            todo!()
        }

        fn ca_pem(&self) -> &str {
            todo!()
        }

        fn ca_cert(&self) -> &X509 {
            todo!()
        }

        fn store(&self) -> &X509Store {
            todo!()
        }

        fn store_notime(&self) -> &X509Store {
            todo!()
        }

        async fn entretien_validateur(&self) {
            todo!()
        }
    }

    impl IsConfigurationPki for TestChiffreurMgs3 {
        fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
            self.enveloppe_privee.clone()
        }
    }

    impl VerificateurMessage for TestChiffreurMgs3 {
        fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
            Ok(ResultatValidation {
                signature_valide: true,
                hachage_valide: Some(true),
                certificat_valide: true,
                regles_valides: true
            })
        }
    }

    impl FormatteurMessage for TestChiffreurMgs3 {}

    #[async_trait]
    impl GenerateurMessages for TestChiffreurMgs3 {
        async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M) -> Result<(), String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M) -> Result<TypeMessage, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool) -> Result<Option<TypeMessage>, String> where M: Serialize + Send + Sync {
            todo!()
        }

        async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
            todo!()
        }

        async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool) -> Result<Option<TypeMessage>, String> {
            todo!()
        }

        async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille) -> Result<Option<TypeMessage>, String> {
            let json_message = match serde_json::to_string(&message) {
                Ok(j) => j,
                Err(e) => Err(format!("emettre_message_millegrille Erreur conversion json : {:?}", e))?
            };
            debug!("emettre_message_millegrille(stub) {:?}", json_message);
            Ok(None)
        }

        fn mq_disponible(&self) -> bool {
            todo!()
        }

        fn set_regeneration(&self) {
            todo!()
        }

        fn reset_regeneration(&self) {
            todo!()
        }

        fn get_mode_regeneration(&self) -> bool {
            todo!()
        }

        fn get_securite(&self) -> &Securite {
            todo!()
        }
    }

    #[test]
    fn init_backup_information() {
        setup("init_backup_information");

        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP,
            NOM_COLLECTION_BACKUP,
            None
        ).expect("init");

        let workpath = info.workpath.to_str().unwrap();

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        // assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        // assert_eq!(info.chiffrer, false);
        assert_eq!(workpath.starts_with("/tmp/."), true);
    }

    #[test]
    fn init_backup_horaire_builder() {
        setup("init_backup_horaire_builder");

        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup);

        assert_eq!(catalogue_builder.date_backup.get_datetime().timestamp(), heure.get_datetime().timestamp());
        assert_eq!(&catalogue_builder.nom_domaine, NOM_DOMAINE_BACKUP);
    }

    #[test]
    fn build_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();
        debug!("Catalogue : {:?}", catalogue);

        assert_eq!(catalogue.date_backup, heure);
        assert_eq!(&catalogue.uuid_backup, uuid_backup);
        assert_eq!(&catalogue.catalogue_nomfichier, "DomaineTest_2021080105.json.xz");
        // assert_eq!(&catalogue.transactions_nomfichier, "Domaine.test_2021080105.jsonl.xz");
    }

    #[test]
    fn build_catalogue_params() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let transactions_hachage = "zABCD1234";

        let mut catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        catalogue_builder.data_hachage_bytes = transactions_hachage.to_owned();

        let catalogue = catalogue_builder.build();

        assert_eq!(&catalogue.data_hachage_bytes, transactions_hachage);
    }

    #[test]
    fn serialiser_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let _ = serde_json::to_value(catalogue).expect("value");

        // debug!("Valeur catalogue : {:?}", value);
    }

    #[test]
    fn catalogue_to_json() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");
        let catalogue_str = serde_json::to_string(&value).expect("json");
        // debug!("Json catalogue : {:?}", catalogue_str);

        assert_eq!(true, catalogue_str.find("1627794000").expect("val") > 0);
        assert_eq!(true, catalogue_str.find(NOM_DOMAINE_BACKUP).expect("val") > 0);
        assert_eq!(true, catalogue_str.find(uuid_backup).expect("val") > 0);
    }

    #[test]
    fn build_catalogue_1certificat() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let mut catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        let certificat = prep_enveloppe(CERT_CORE);
        // debug!("!!! Enveloppe : {:?}", certificat);

        catalogue_builder.ajouter_certificat(&certificat);

        let catalogue = catalogue_builder.build();
        debug!("!!! Catalogue : {:?}", catalogue);
        assert_eq!(catalogue.certificats.len(), 1);
    }

    #[tokio::test]
    async fn roundtrip_json() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions.jsonl.xz");

        let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");
        let doc_json = json!({
            "contenu": "Du contenu a encoder",
            "valeur": 1234,
            // "date": Utc.timestamp(1629464027, 0),
        });
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");

        let _ = writer.fermer().await.expect("fermer");
        debug!("File du writer : {:?}", path_fichier);

        let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
        let mut reader = TransactionReader::new(fichier_cs, None).expect("reader");
        debug!("Extraction transactions du xz");
        let transactions = reader.read_transactions().await.expect("transactions");
        for t in transactions {
            debug!("Transaction : {:?}", t);
            assert_eq!(&doc_json, &t);
        }

    }

    fn get_doc_reference() -> (String, Document) {
        let doc_bson = doc! {
            "_id": "Un ID dummy qui doit etre retire",
            "contenu": "Du contenu BSON (Document) a encoder",
            "valeur": 5678,
            "date": Utc.timestamp(1629464026, 0),
        };

        (String::from("zSEfXUAj2MrtorrFTqvt38Je8XrW78425oDMseC3QMiX29xXi1SPu4xhzjDoNTizh7eXHgpbsc5UY9aasHoy2tXCpURFjt"), doc_bson)
    }

    #[tokio::test]
    async fn ecrire_transactions_writer_bson() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");

        let (mh_reference, doc_bson) = get_doc_reference();
        writer.write_bson_line(&doc_bson).await.expect("write");

        let (mh, _) = writer.fermer().await.expect("fermer");
        // debug!("File du writer : {:?}, multihash: {}", file, mh);

        assert_eq!(mh.as_str(), &mh_reference);
    }

    #[tokio::test]
    async fn charger_transactions() {
        let path_fichier = PathBuf::from("/tmp/test_charger_fichier.json");
        {
            let mut fichier = File::create(&path_fichier).await.expect("create");
            fichier.write("Allo".as_bytes()).await.expect("write");
            fichier.close().await.expect("close");
        }

        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "DUMMY-11d8-4ff2-aa6f-1a605bd17336";

        let mut catalogue_builder = CatalogueBackupBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        catalogue_builder.charger_transactions_chiffrees(&path_fichier).await.expect("transactions");

        debug!("Transactions hachage : {}", catalogue_builder.data_hachage_bytes);
        debug!("Transactions data : {}", catalogue_builder.data_transactions);

        assert_eq!("zSEfXUBUUM6YRxhgeJraN95eUyibKjQUg9oxHtnsKSix7GNPjxZHvhQVwTweuwySe9fdeHtFpg6kQtNgDNp6GQw1uj9Qff", catalogue_builder.data_hachage_bytes);
        assert_eq!("mQWxsbw", catalogue_builder.data_transactions);
    }

    /// Test de chiffrage du backup - round trip
    #[tokio::test]
    async fn chiffrer_roundtrip_backup() {
        let (validateur, enveloppe) = charger_enveloppe_privee_env();
        let enveloppe = Arc::new(enveloppe);

        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.mgs");
        let fp_certs = vec!(FingerprintCertPublicKey::new(
            String::from("dummy"),
            enveloppe.certificat().public_key().clone().expect("cle"),
            true
        ));

        let (fingerprint_cert, chiffreur) = creer_test_middleware(enveloppe.clone(), validateur);

        let mut writer = TransactionWriter::new(
            path_fichier.as_path(),
            Some(&chiffreur)
        ).await.expect("writer");

        let (mh_reference, doc_bson) = get_doc_reference();
        writer.write_bson_line(&doc_bson).await.expect("write chiffre");
        let (mh, mut decipher_data_option) = writer.fermer().await.expect("fermer");

        // Verifier que le hachage n'est pas egal au hachage de la version non chiffree
        assert_ne!(mh.as_str(), &mh_reference);

        let decipher_keys = decipher_data_option.expect("decipher data");
        let mut decipher_key = decipher_keys.get_cipher_data(fingerprint_cert.as_str()).expect("cle");
        decipher_key.dechiffrer_cle(enveloppe.cle_privee()).expect("dechiffrer");
        debug!("Cle dechiffree : {:?}", decipher_key);

        let fichier_cs = Box::new(File::open(path_fichier.as_path()).await.expect("open read"));
        let mut reader = TransactionReader::new(fichier_cs, Some(&decipher_key)).expect("reader");
        let transactions = reader.read_transactions().await.expect("transactions");

        for t in transactions {
            debug!("Transaction dechiffree : {:?}", t);
            let valeur_chiffre = t.get("valeur").expect("valeur").as_i64().expect("val");
            assert_eq!(valeur_chiffre, 5678);
        }

    }

    fn creer_test_middleware(enveloppe: Arc<EnveloppePrivee>, validateur: Arc<ValidateurX509Impl>) -> (String, TestChiffreurMgs3) {
        let mut fp_public_keys = Vec::new();
        let fingerprint_cert = enveloppe.enveloppe.fingerprint.clone();
        let cle_publique = &enveloppe.enveloppe.cle_publique;
        fp_public_keys.push(FingerprintCertPublicKey {
            fingerprint: fingerprint_cert.clone(),
            public_key: cle_publique.to_owned(),
            est_cle_millegrille: false,
        });
        let cle_publique_ca = &enveloppe.enveloppe_ca.cle_publique;
        fp_public_keys.push(FingerprintCertPublicKey {
            fingerprint: enveloppe.enveloppe_ca.fingerprint.clone(),
            public_key: cle_publique_ca.to_owned(),
            est_cle_millegrille: true,
        });
        let chiffreur = TestChiffreurMgs3 { cles_chiffrage: fp_public_keys, validateur, enveloppe_privee: enveloppe };
        (fingerprint_cert, chiffreur)
    }

    #[tokio::test]
    async fn test_generer_fichiers_backup() {

        //let temp_dir = tempdir().expect("tempdir");
        let temp_dir = PathBuf::from(format!("/tmp/test_generer_fichiers_backup"));
        match fs::create_dir(&temp_dir).await {
            Ok(()) => (),
            Err(e) => {
                match e.kind() {
                    ErrorKind::AlreadyExists => (),
                    _ => panic!("Erreur createdir: {:?}", e)
                }
            }
        }

        let info_backup = BackupInformation::new(
            "DUMMY",
            "dummy_collection",
            Some(temp_dir.clone())
        ).expect("BackupInformation::new");

        let (validateur, enveloppe) = charger_enveloppe_privee_env();
        let enveloppe = Arc::new(enveloppe);
        let (fingerprint_cert, m) = creer_test_middleware(enveloppe.clone(), validateur);

        // Generer transactions dummy
        let mut transactions_vec = Vec::new();
        let mut date_debut = Utc::now();
        date_debut = date_debut - chrono::Duration::minutes(10);

        for i in 0..3 {
            let message = m.formatter_message(
                &json!({}), Some("Test"), None, None, None, false)
                .expect("formatter_message");
            let mut m_bson = message.map_to_bson().expect("bson");

            let date_transaction = date_debut + Duration::minutes(i);

            let evenements = doc! { "transaction_traitee": date_transaction };
            m_bson.insert("_evenements", evenements);

            transactions_vec.push( m_bson );
        }
        let mut transactions = CurseurIntoIter { data: transactions_vec.into_iter() };

        let resultat = generer_fichiers_backup(&m, transactions, temp_dir, &info_backup)
            .await.expect("generer_fichiers_backup");
        debug!("Fichiers generes : {:?}", resultat);

    }

    #[tokio::test]
    async fn test_emettre_fichiers_backup() {

        // Setup
        let (validateur, enveloppe) = charger_enveloppe_privee_env();
        let enveloppe = Arc::new(enveloppe);
        let (fingerprint_cert, m) = creer_test_middleware(enveloppe.clone(), validateur);

        //let temp_dir = tempdir().expect("tempdir");
        let temp_dir = PathBuf::from(format!("/tmp/test_generer_fichiers_backup"));
        match fs::create_dir(&temp_dir).await {
            Ok(()) => (),
            Err(e) => {
                match e.kind() {
                    ErrorKind::AlreadyExists => (),
                    _ => panic!("Erreur createdir: {:?}", e)
                }
            }
        }

        let fichiers_backup = vec!["/tmp/test_generer_fichiers_backup/catalogue_0.json"];

        emettre_backup_transactions(&m, &fichiers_backup).await.expect("emettre_backup_transactions");

    }

}
