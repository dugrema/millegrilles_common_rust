use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::usize::MAX;

use async_std::fs::File;
use async_std::io::BufReader;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, Utc};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use log::{debug, error, info, warn};
use mongodb::bson::{doc, Document};
use mongodb::Cursor;
use mongodb::options::{AggregateOptions, FindOptions, Hint};
use multibase::{Base, decode, encode};
use multihash::Code;
use reqwest::{Body, Response};
use reqwest::multipart::Part;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::{TempDir, tempdir};
use tokio::fs::File as File_tokio;
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
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
use crate::mongo_dao::MongoDao;
use crate::rabbitmq_dao::TypeMessageOut;
use crate::recepteur_messages::TypeMessage;
use crate::tokio::sync::mpsc::Receiver;
use crate::transactions::{regenerer, sauvegarder_batch, TraiterTransaction};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage};

/// Handler de backup qui ecoute sur un mpsc. Lance un backup a la fois dans une thread separee.
pub async fn thread_backup<M>(middleware: Arc<M>, mut rx: Receiver<CommandeBackup>)
    where M: MongoDao + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + FormatteurMessage + GenerateurMessages + ConfigMessages
{
    while let Some(commande) = rx.recv().await {
        let nom_domaine = commande.nom_domaine;
        info!("Debug backup {}", nom_domaine);
        match backup(middleware.as_ref(), &nom_domaine, commande.nom_collection_transactions, commande.chiffrer).await {
            Ok(_) => info!("Backup {} OK", nom_domaine),
            Err(e) => error!("backup.thread_backup Erreur backup domaine {} : {:?}", nom_domaine, e)
        };
    }
}

#[derive(Clone, Debug)]
pub struct CommandeBackup {
    pub nom_domaine: String,
    pub nom_collection_transactions: String,
    pub chiffrer: bool,
}

#[async_trait]
pub trait BackupStarter {
    fn get_tx_backup(&self) -> Sender<CommandeBackup>;

    async fn demarrer_backup<S,T>(&self, nom_domaine: S, nom_collection_transactions: T, chiffrer: bool)
        -> Result<(), Box<dyn Error>>
        where S: Into<String> + Send, T: Into<String> + Send
    {
        let commande = CommandeBackup {
            nom_domaine: nom_domaine.into(),
            nom_collection_transactions: nom_collection_transactions.into(),
            chiffrer,
        };

        let tx_backup = self.get_tx_backup();
        debug!("backup.BackupStarter Demarrage backup {:?}", &commande);
        tx_backup.send(commande).await?;

        Ok(())
    }
}

/// Lance un backup complet de la collection en parametre.
pub async fn backup<M,S,T>(middleware: &M, nom_domaine: S, nom_collection_transactions: T, chiffrer: bool)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where
        M: MongoDao + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + FormatteurMessage + GenerateurMessages + ConfigMessages,
        S: AsRef<str>, T: AsRef<str>,
{
    let nom_coll_str = nom_collection_transactions.as_ref();
    let nom_domaine_str = nom_domaine.as_ref();

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempfile::tempdir()?;
    info!("backup.backup Backup horaire de {} vers tmp : {:?}", nom_domaine_str, workdir);

    // S'assurer d'avoir des certificats de maitredescles presentement valide
    if middleware.get_publickeys_chiffrage().len() < 2 {
        Err(format!("Certificats de chiffrage non disponibles"))?
    }

    //middleware.charger_certificats_chiffrage(middleware.get_enveloppe_privee().enveloppe.as_ref()).await?;

    let info_backup = BackupInformation::new(
        nom_domaine_str,
        nom_coll_str,
        chiffrer,
        Some(workdir.path().to_owned())
    )?;

    let (reponse, flag_erreur) = match backup_horaire(middleware, workdir, nom_coll_str, &info_backup).await {
        Ok(()) => {
            // Emettre trigger pour declencher backup du jour precedent
            let reponse = middleware.formatter_reponse(json!({"ok": true}), None)?;
            (reponse, false)
        },
        Err(e) => {
            error!("Erreur traitement backup : {:?}", e);
            // let timestamp_backup = Utc::now();
            // if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireErreur", &timestamp_backup).await {
            //     error!("backup_horaire: Erreur emission evenement debut backup : {:?}", e);
            // }

            let reponse = middleware.formatter_reponse(json!({"ok": false, "err": format!("{:?}", e)}), None)?;

            (reponse, true)
        },
    };

    // Utiliser flag pour emettre evenement erreur (note : faire hors du match a cause Err not Send)
    if flag_erreur {
        let timestamp_backup = Utc::now();
        if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireErreur", &timestamp_backup).await {
            error!("Erreur emission evenement erreur de backup : {:?}", e);
        }
        Err("Erreur backup horaire, voir logs")?
    }
    // else {
    //     debug!("backup Emettre trigger pour backup quotidien : {:?}", &info_backup);
    //     trigger_backup_quotidien(middleware, &info_backup).await?;
    // }

    Ok(Some(reponse))
}

/// Effectue un backup horaire
async fn backup_horaire<M>(middleware: &M, workdir: TempDir, nom_coll_str: &str, info_backup: &BackupInformation) -> Result<(), Box<dyn Error>>
where M: MongoDao + ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys> + FormatteurMessage + GenerateurMessages + ConfigMessages,
{
    let timestamp_backup = Utc::now();
    if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireDebut", &timestamp_backup).await {
        error!("backup_horaire: Erreur emission evenement debut backup : {:?}", e);
    }

    todo!("Fix me")
    // Generer liste builders domaine/heures
    // let builders = grouper_backups(middleware, &info_backup).await?;
    //
    // info!("backup.backup_horaire: Backup horaire collection {} : {:?}", nom_coll_str, builders);
    //
    // // Tenter de charger entete du dernier backup de ce domaine/partition
    // // let mut entete_precedente: Option<Entete> = requete_entete_dernier(middleware, nom_coll_str).await?;
    //
    // for mut builder in builders {
    //
    //     // Creer fichier de transactions
    //     let mut path_fichier_transactions = workdir.path().to_owned();
    //     // path_fichier_transactions.push(PathBuf::from(builder.get_nomfichier_transactions()));
    //     path_fichier_transactions.push(PathBuf::from("transactions_tmp.mgs"));
    //
    //     let mut curseur = requete_transactions(middleware, &info_backup, &builder).await?;
    //     serialiser_transactions(
    //         middleware,
    //         &mut curseur,
    //         &mut builder,
    //         path_fichier_transactions.as_path()
    //     ).await?;
    //
    //     // Signer et serialiser catalogue
    //     let (catalogue_horaire, catalogue_signe, commande_cles, uuid_transactions) = serialiser_catalogue(
    //         middleware, builder).await?;
    //     info!("backup_horaire: Nouveau catalogue horaire : {:?}\nCommande maitredescles : {:?}", catalogue_horaire, commande_cles);
    //     let reponse = uploader_backup(
    //         middleware,
    //         path_fichier_transactions.as_path(),
    //         &catalogue_horaire,
    //         &catalogue_signe,
    //         commande_cles
    //     ).await?;
    //
    //     if !reponse.status().is_success() {
    //         Err(format!("Erreur upload fichier : {:?}", reponse))?;
    //     }
    //
    //     // entete_precedente = Some(catalogue_signe.entete.clone());
    //     // Marquer transactions du backup comme completees
    //     marquer_transaction_backup_complete(
    //         middleware,
    //         info_backup.nom_collection_transactions.as_str(),
    //         &catalogue_horaire,
    //         &uuid_transactions
    //     ).await?;
    //
    //     // Soumettre catalogue horaire sous forme de transaction (domaine Backup)
    //     let routage = RoutageMessageAction::new(BACKUP_NOM_DOMAINE, BACKUP_TRANSACTION_CATALOGUE_HORAIRE);
    //     // Avertissement : blocking FALSE, sinon sur le meme module que CoreBackup va capturer la transaction comme la reponse sans la traiter
    //     let reponse_catalogue = middleware.emettre_message_millegrille(
    //         routage,false, TypeMessageOut::Transaction, catalogue_signe
    //     ).await?;
    //     debug!("Reponse soumission catalogue : {:?}", reponse_catalogue);
    // }
    //
    // if let Err(e) = emettre_evenement_backup(middleware, &info_backup, "backupHoraireTermine", &timestamp_backup).await {
    //     error!("Erreur emission evenement fin backup : {:?}", e);
    // }
    //
    // Ok(())
}

async fn requete_transactions(middleware: &impl MongoDao, info: &BackupInformation, builder: &CatalogueHoraireBuilder) -> Result<Cursor<Document>, Box<dyn Error>> {
    let nom_collection = &info.nom_collection_transactions;
    let collection = middleware.get_collection(nom_collection)?;

    let debut_heure = builder.date_backup.get_datetime();
    let fin_heure = debut_heure.clone() + chrono::Duration::hours(1);

    // Backup heure specifique
    let doc_transaction_traitee = doc! {"$gte": debut_heure, "$lt": &fin_heure};

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: doc_transaction_traitee,
    };

    let sort = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
    let find_options = FindOptions::builder()
        .sort(sort)
        .hint(Hint::Name(String::from("backup_transactions")))
        .batch_size(50)
        .build();

    let curseur = collection.find(filtre, find_options).await?;

    Ok(curseur)
}

async fn serialiser_transactions<M>(
    middleware: &M,
    curseur: &mut Cursor<Document>,
    builder: &mut CatalogueHoraireBuilder,
    path_transactions: &Path,
) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + Chiffreur<CipherMgs3, Mgs3CipherKeys>,
{
    // Creer i/o stream lzma pour les transactions avec chiffrage
    let mut transaction_writer = TransactionWriter::new(path_transactions, Some(middleware)).await?;

    // Obtenir curseur sur transactions en ordre chronologique de flag complete
    while let Some(Ok(d)) = curseur.next().await {
        let entete = d.get("en-tete").expect("en-tete").as_document().expect("document");
        let uuid_transaction = entete.get(TRANSACTION_CHAMP_UUID_TRANSACTION).expect("uuid-transaction").as_str().expect("str");
        let fingerprint_certificat = entete.get(TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT).expect("fingerprint certificat").as_str().expect("str");

        info!("Backup transaction {}", uuid_transaction);

        // Trouver certificat et ajouter au catalogue
        match middleware.get_certificat(fingerprint_certificat).await {
            Some(c) => {
                // debug!("OK Certificat ajoute : {}", fingerprint_certificat);
                builder.ajouter_certificat(c.as_ref());

                // Valider la transaction avec le certificat
                let mut transaction = MessageSerialise::from_serializable(&d)?;
                debug!("Transaction serialisee pour validation :\n{:?}", transaction);
                let options = ValidationOptions::new(true, true, true);
                let resultat = transaction.valider(middleware, Some(&options)).await?;

                if ! ( resultat.signature_valide && resultat.certificat_valide && resultat.hachage_valide.expect("hachage") ) {
                    warn!("Resultat validation invalide pour {}: {:?}", uuid_transaction, resultat);
                    debug!("Resultat validation invalide pour transaction :\n{}", transaction.get_str());
                    continue;
                }

            },
            None => {
                warn!("Certificat {} inconnu, transaction {} ne peut pas etre mise dans le backup", fingerprint_certificat, uuid_transaction);
                continue;
            },
        }

        // Serialiser transaction
        transaction_writer.write_bson_line(&d).await?;

        // Ajouter uuid_transaction dans buidler - utilise pour marquer transactions completees
        builder.ajouter_transaction(uuid_transaction);
    }

    let (hachage, cipher_keys) = transaction_writer.fermer().await?;

    builder.data_hachage_bytes = hachage;
    match &cipher_keys {
        Some(k) => builder.set_cles(k),
        None => (),
    }

    Ok(())
}

async fn serialiser_catalogue(
    middleware: &impl FormatteurMessage,
    builder: CatalogueHoraireBuilder
) -> Result<(CatalogueBackup, MessageMilleGrille, Option<MessageMilleGrille>, Vec<String>), Box<dyn Error>> {

    let commande_signee = match &builder.cles {
        Some(cles) => {

            // Signer commande de maitre des cles
            let mut identificateurs_document: HashMap<String, String> = HashMap::new();
            identificateurs_document.insert("domaine".into(), builder.nom_domaine.clone());
            identificateurs_document.insert("heure".into(), format!("{}00", builder.date_backup.format_ymdh()));

            let commande_maitredescles = cles.get_commande_sauvegarder_cles(
                BACKUP_NOM_DOMAINE,
                None,
                identificateurs_document,
            );

            let fingerprint_partitions = cles.get_fingerprint_partitions();
            let partition = fingerprint_partitions[0].as_str();  // Prendre une partition au hazard

            let value_commande: Value = serde_json::to_value(commande_maitredescles).expect("commande");
            // let msg_commande = MessageJson::new(value_commande);
            let commande_signee = middleware.formatter_message(
                &value_commande,
                Some(DOMAINE_NOM_MAITREDESCLES),
                Some(MAITREDESCLES_COMMANDE_NOUVELLE_CLE),
                Some(partition),
                None,
                false
            )?;

            Some(commande_signee)
        },
        None => None,
    };

    // Signer et serialiser catalogue
    let uuid_transactions = builder.uuid_transactions.clone();
    let catalogue = builder.build();
    let catalogue_value = serde_json::to_value(&catalogue)?;
    let catalogue_signe = middleware.formatter_message(
        &catalogue_value,
        Some(BACKUP_NOM_DOMAINE),
        Some(BACKUP_TRANSACTION_CATALOGUE_HORAIRE),
        None,
        None,
        false
    )?;

    Ok((catalogue, catalogue_signe, commande_signee, uuid_transactions))
}

async fn uploader_backup<M>(
    middleware: &M,
    path_transactions: &Path,
    catalogue: &CatalogueBackup,
    catalogue_signe: &MessageMilleGrille,
    commande_cles: Option<MessageMilleGrille>
) -> Result<Response, Box<dyn Error>>
where
    M: ConfigMessages + IsConfigurationPki,
{
    let message_serialise = MessageSerialise::from_parsed(catalogue_signe.clone()).expect("ser");

    // Compresser catalogue et commande maitre des cles en XZ
    let mut compresseur_catalogue = CompresseurBytes::new().expect("compresseur");
    compresseur_catalogue.write(message_serialise.get_str().as_bytes()).await.expect("write");
    let (catalogue_bytes, _) = compresseur_catalogue.fermer().expect("finish");

    let commande_bytes = match commande_cles {
        Some(c) => {
            let message_serialise = MessageSerialise::from_parsed(c).expect("ser");
            let mut compresseur_commande = CompresseurBytes::new().expect("compresseur");
            debug!("Commande maitre cles : {}", message_serialise.get_str());
            compresseur_commande.write(message_serialise.get_str().as_bytes()).await.expect("write");
            let (commande_bytes, _) = compresseur_commande.fermer().expect("finish");

            Some(commande_bytes)
        },
        None => None
    };

    // let mut path_transactions = workdir.to_owned();
    // path_transactions.push(PathBuf::from(catalogue.transactions_nomfichier.as_str()));

    if ! path_transactions.exists() {
        Err(format!("Fichier {:?} n'existe pas", path_transactions))?;
    }

    let enveloppe = middleware.get_enveloppe_privee().clone();
    let ca_cert_pem = enveloppe.chaine_pem().last().expect("last cert").as_str();
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;
    let identity = reqwest::Identity::from_pem(enveloppe.clecert_pem.as_bytes())?;

    let fichier_transactions_read = File_tokio::open(path_transactions).await?;

    // Uploader fichiers et contenu backup
    let form = {
        let mut form = reqwest::multipart::Form::new()
            .text("timestamp_backup", catalogue.date_backup.format_ymdh())
            //.part("transactions", file_to_part(catalogue.transactions_nomfichier.as_str(), fichier_transactions_read).await)
            .part("catalogue", bytes_to_part(catalogue.catalogue_nomfichier.as_str(), catalogue_bytes, Some("application/xz")));

        if let Some(b) = commande_bytes {
            form = form.part("cles", bytes_to_part(
                "commande_maitredescles.json", b, Some("text/json")));
        }

        form
    };

    let client = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        .identity(identity)
        .https_only(true)
        .use_rustls_tls()
        .timeout(core::time::Duration::new(20, 0))
        .build()?;

    let mut url = match middleware.get_configuration_noeud().fichiers_url.as_ref() {
        Some(url) => url.to_owned(),
        None => {
            Err("URL fichiers n'est pas configure pour les backups")?
        }
    };

    let path_commande = format!("backup/domaine/{}", catalogue.catalogue_nomfichier);
    url.set_path(path_commande.as_str());

    debug!("Url backup : {:?}", url);

    let request = client.put(url).multipart(form);

    let response = request.send().await?;
    debug!("Resultat {} : {:?}", response.status(), response);

    Ok(response)
}

async fn marquer_transaction_backup_complete(middleware: &dyn MongoDao, nom_collection: &str,
                                             catalogue_horaire: &CatalogueBackup,
                                             uuid_transactions: &Vec<String>)
                                             -> Result<(), Box<dyn Error>>
{
    // debug!("Set flag backup pour transactions de {} : {:?}", nom_collection, catalogue_horaire.uuid_transactions);
    debug!("Set flag backup pour transactions de {} : {:?}", nom_collection, uuid_transactions);

    let collection = middleware.get_collection(nom_collection)?;
    let filtre = doc! {
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: {"$in": uuid_transactions}
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
    /// Flag de chiffrage
    chiffrer: bool,
    /// Repertoire temporaire qui est supprime automatiquement apres le backup.
    tmp_workdir: Option<TempDir>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogueBackup {
    /// Heure de la premiere transaction du backup (traitement interne initial)
    pub date_backup: DateEpochSeconds,
    /// Heure de la derniere tranaction du backup
    pub date_fin_backup: DateEpochSeconds,
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
    // pub uuid_transactions: Vec<String>,

    /// En-tete du message de catalogue. Presente uniquement lors de deserialization.
    #[serde(rename = "en-tete", skip_serializing)]
    pub entete: Option<Entete>,

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

    pub fn builder(heure: DateEpochSeconds, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> CatalogueHoraireBuilder {
        CatalogueHoraireBuilder::new(heure, nom_domaine, partition, uuid_backup)
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
pub struct CatalogueHoraireBuilder {
    date_backup: DateEpochSeconds,      // Date de traitement de la premiere transaction
    date_fin_backup: DateEpochSeconds,  // Date de traitement de la derniere transaction
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

impl CatalogueHoraireBuilder {

    fn new(heure: DateEpochSeconds, nom_domaine: String, partition: Option<String>, uuid_backup: String) -> Self {
        CatalogueHoraireBuilder {
            date_backup: heure.clone(),
            date_fin_backup: heure,  // Temporaire, va etre la date de la derniere transaction
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

    fn ajouter_transaction(&mut self, uuid_transaction: &str) {
        self.uuid_transactions.push(String::from(uuid_transaction));
    }

    // fn transactions_hachage(&mut self, hachage: String) {
    //     self.transactions_hachage = hachage;
    // }

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

    // fn get_nomfichier_transactions(&self) -> PathBuf {
    //     let mut date_str = self.date_backup.format_ymdh();
    //     // match self.snapshot {
    //     //     true => date_str = format!("{}-SNAPSHOT", date_str),
    //     //     false => (),
    //     // }
    //
    //     let nom_domaine_partition = match &self.partition {
    //         Some(p) => format!("{}.{}", self.nom_domaine, p),
    //         None => self.nom_domaine.clone()
    //     };
    //
    //     let nom_fichier = match self.chiffrer {
    //         true => format!("{}_{}.jsonl.xz.mgs2", &nom_domaine_partition, date_str),
    //         false => format!("{}_{}.jsonl.xz", &nom_domaine_partition, date_str),
    //     };
    //     PathBuf::from(nom_fichier)
    // }

    // /// Set backup_precedent en calculant le hachage de l'en-tete.
    // fn set_backup_precedent(&mut self, entete: &Entete) -> Result<(), Box<dyn Error>> {
    //
    //     let hachage_entete = hacher_serializable(entete)?;
    //
    //     let entete_calculee = EnteteBackupPrecedent {
    //         hachage_entete,
    //         uuid_transaction: entete.uuid_transaction.clone(),
    //     };
    //
    //     self.backup_precedent = Some(entete_calculee);
    //
    //     Ok(())
    // }

    async fn charger_transactions_chiffrees(&mut self, path_fichier: &Path) -> Result<(), Box<dyn Error>> {
        const MAX_SIZE: usize = 5 * 1024 * 1024;

        let mut data = Vec::new();

        {
            let file = File::open(path_fichier).await?;
            let mut reader = BufReader::new(file);
            let mut buffer = [0u8; 64 * 1024];
            while let read_len = reader.read(&mut buffer).await? {
                if read_len == 0 { break; }
                data.extend(&buffer[..read_len]);
                if data.len() > MAX_SIZE {
                    Err(format!("La taille du fichier est plus grande que la limite de {} bytes", MAX_SIZE))?;
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
        // let transactions_hachage = self.data_hachage_bytes.clone();
        // let transactions_nomfichier = self.get_nomfichier_transactions().to_str().expect("str").to_owned();
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

        CatalogueBackup {
            date_backup: self.date_backup,
            date_fin_backup: self.date_fin_backup,
            domaine: self.nom_domaine,
            partition: self.partition,
            uuid_backup: self.uuid_backup,
            catalogue_nomfichier,

            certificats: self.certificats,

            data_hachage_bytes: self.data_hachage_bytes,
            data_transactions: self.data_transactions,
            // transactions_nomfichier,
            // uuid_transactions: self.uuid_transactions,

            entete: None,  // En-tete chargee lors de la deserialization

            // backup_precedent: self.backup_precedent,
            cle, iv, tag, format,
        }
    }

}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new<S>(
        domaine: S,
        nom_collection_transactions: S,
        chiffrer: bool,
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
            chiffrer,
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

struct TransactionWriter<'a> {
    fichier_writer: FichierWriter<'a, Mgs3CipherKeys, CipherMgs3>,
}

impl<'a> TransactionWriter<'a> {

    pub async fn new<C>(path_fichier: &'a Path, middleware: Option<&C>) -> Result<TransactionWriter<'a>, Box<dyn Error>>
    where
        C: Chiffreur<CipherMgs3, Mgs3CipherKeys>,
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
    use serde_json::json;

    use crate::certificats::certificats_tests::{CERT_CORE, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    use crate::fichiers::CompresseurBytes;
    use crate::fichiers::fichiers_tests::ChiffreurDummy;
    use crate::test_setup::setup;
    use chrono::TimeZone;
    use futures::io::BufReader;
    use crate::backup_restoration::TransactionReader;
    use crate::certificats::FingerprintCertPublicKey;
    use crate::middleware_db::preparer_middleware_db;
    use crate::chiffrage::MgsCipherData;

    use super::*;

    const NOM_DOMAINE_BACKUP: &str = "DomaineTest";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    trait TestChiffreurMgs3Trait: Chiffreur<CipherMgs3, Mgs3CipherKeys> {}

    struct TestChiffreurMgs3 {
        cles_chiffrage: Vec<FingerprintCertPublicKey>,
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

    #[test]
    fn init_backup_information() {
        setup("init_backup_information");

        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP,
            NOM_COLLECTION_BACKUP,
            false,
            None
        ).expect("init");

        let workpath = info.workpath.to_str().unwrap();

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        // assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        assert_eq!(info.chiffrer, false);
        assert_eq!(workpath.starts_with("/tmp/."), true);
    }

    #[test]
    fn init_backup_horaire_builder() {
        setup("init_backup_horaire_builder");

        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup);

        assert_eq!(catalogue_builder.date_backup.get_datetime().timestamp(), heure.get_datetime().timestamp());
        assert_eq!(&catalogue_builder.nom_domaine, NOM_DOMAINE_BACKUP);
    }

    #[test]
    fn build_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
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

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        catalogue_builder.data_hachage_bytes = transactions_hachage.to_owned();

        let catalogue = catalogue_builder.build();

        assert_eq!(&catalogue.data_hachage_bytes, transactions_hachage);
    }

    #[test]
    fn serialiser_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), None, uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let _ = serde_json::to_value(catalogue).expect("value");

        // debug!("Valeur catalogue : {:?}", value);
    }

    #[test]
    fn catalogue_to_json() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
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

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
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

        (String::from("z8VwF3dEpgBm31rY1ocA9Hdk74q61ukLybuVSv83ie2hZ9wFQ9oMQKtKDAqYxPemu1hYYHJw6i5NrRvULMNBowPD5YX"), doc_bson)
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

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
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

        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.mgs");
        let fp_certs = vec!(FingerprintCertPublicKey::new(
            String::from("dummy"),
            enveloppe.certificat().public_key().clone().expect("cle"),
            true
        ));

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
        let chiffreur = TestChiffreurMgs3 { cles_chiffrage: fp_public_keys };

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

}
