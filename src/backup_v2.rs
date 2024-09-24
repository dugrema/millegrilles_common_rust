use std::any::Any;
use std::sync::Arc;
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use fs2::FileExt;
use chrono::Utc;
use log::{debug, error, info, warn};
use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult, CleChiffrageHandler, CleChiffrageStruct};
use millegrilles_cryptographie::deser_message_buffer;
use millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519, CleSecreteX25519};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use async_compression::tokio::bufread::{DeflateEncoder, GzipEncoder};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, Receiver};

use millegrilles_cryptographie::chiffrage::CleSecrete;
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher};
use millegrilles_cryptographie::maitredescles::{generer_cle_avec_ca, SignatureDomaines};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::bson::doc;
use mongodb::options::{FindOneOptions, FindOptions, Hint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, Result as TokioResult};
use tokio::join;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{bytes::Bytes, io::{ReaderStream, StreamReader}};
use x509_parser::nom::AsBytes;
use crate::backup::CommandeBackup;
use crate::mongo_dao::MongoDao;
use crate::certificats::{CollectionCertificatsPem, ValidateurX509};
use crate::chiffrage_cle::{ajouter_cles_domaine, generer_cle_v2, get_cles_rechiffrees_v2, requete_charger_cles};
use crate::common_messages::{ReponseInformationConsignationFichiers, RequeteConsignationFichiers};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::db_structs::TransactionOwned;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::error::Error as CommonError;
use crate::messages_generiques::ReponseCommande;
use crate::recepteur_messages::TypeMessage;

const PATH_FICHIERS_BACKUP: &str = "/var/opt/millegrilles/backup";

pub async fn thread_backup_v2<M>(middleware: &M, mut rx: Receiver<CommandeBackup>)
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler + 'static
{
    // Verifier que le path de backup est disponible
    fs::create_dir_all(PATH_FICHIERS_BACKUP).unwrap();

    while let Some(commande) = rx.recv().await {
        debug!("thread_backup Debut commande backup {:?}", commande);

        let backup_complet = commande.complet;

        let path_backup = preparer_path_backup(PATH_FICHIERS_BACKUP, commande.nom_domaine.as_str());

        // Lock pour empecher autre process de backup
        let (lock_file, path_lock_file) = {
            let mut path_lockfile = path_backup.clone();
            path_lockfile.push("backup.lock");
            let file = match File::open(&path_lockfile) {
                Ok(inner) => inner,
                Err(e) => {
                    if ErrorKind::NotFound == e.kind() {
                        File::create(&path_lockfile).expect("new lockfile")
                    } else {
                        warn!("Error opening lockfile {:?} - SKIP backup", e);
                        continue;
                    }
                }
            };
            match file.try_lock_exclusive() {
                Ok(()) => (file, path_lockfile),
                Err(_) => {
                    info!("Backup file already locked, SKIP backup");
                    continue;
                }
            }
        };

        // Charger la cle de backup
        let cle_backup_domaine = match recuperer_cle_backup(middleware, commande.nom_domaine.as_str()).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("Erreur chargement de la cle de backup, SKIP: {:?}", e);
                if let Err(e) = lock_file.unlock() {
                    info!("Error unlocking backup file: {:?}", e);
                }
                continue;
            }
        };

        // Charger le serveur de consignation
        let serveur_consignation = match get_serveur_consignation(middleware).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("Erreur chargement de l'information de consignation, SKIP: {:?}", e);
                if let Err(e) = lock_file.unlock() {
                    info!("Error unlocking backup file: {:?}", e);
                }
                continue;
            }
        };

        // Toujours commencer par un backup incremental pour vider
        // les nouvelles transactions de la base de donnees.
        if let Err(e) = backup_incremental(middleware, &commande, &cle_backup_domaine, &serveur_consignation, path_backup.as_ref()).await {
            error!("Erreur durant backup incremental: {:?}", e);
        }

        if backup_complet == true  {
            // Generer un nouveau fichier concatene, potentiellement des nouveaux fichiers finaux.
            if let Err(e) = run_backup_complet(middleware, &commande, &cle_backup_domaine).await {
                error!("Erreur durant backup complet: {:?}", e);
            }
        }

        // Retirer le lock de backup
        if let Err(e) = lock_file.unlock() {
            info!("Error unlocking backup file: {:?}", e);
        }
        if let Err(e) = fs::remove_file(path_lock_file) {
            info!("Error deleting lock file: {:?}", e);
        };
    }
}

fn preparer_path_backup(path_backup: &str, domaine: &str) -> PathBuf {
    let path_domaine = PathBuf::from(format!("{}/{}", path_backup, domaine));
    fs::create_dir_all(&path_domaine).unwrap();
    path_domaine
}

async fn get_serveur_consignation<M>(middleware: &M) -> Result<ReponseInformationConsignationFichiers, CommonError>
    where M: GenerateurMessages
{

    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "getConsignationFichiers", vec![Securite::L1Public])
        .build();
    let requete = RequeteConsignationFichiers {
        instance_id: None,
        hostname: None,
        primaire: None,
        stats: None,
    };
    let reponse: ReponseInformationConsignationFichiers = match middleware.transmettre_requete(routage, &requete).await? {
        Some(TypeMessage::Valide(reponse)) => deser_message_buffer!(reponse.message),
        _ => Err("backup_v2.get_serveur_consignation Reponse information consignation de type invalide")?
    };

    debug!("Information de consignation pour le backup: {:?}", reponse);

    if reponse.ok != Some(true) {
        Err("backup_v2.get_serveur_consignation Reponse information consignation est en erreur (ok==false)")?
    }
    if reponse.hostnames.is_none() && reponse.consignation_url.is_none() {
        Err("backup_v2.get_serveur_consignation Aucun hostname/url de consignation recu")?
    }

    Ok(reponse)
}

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
async fn backup_incremental<M>(
    middleware: &M, commande: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine,
    serveur_consignation: &ReponseInformationConsignationFichiers,
    path_backup: &Path,
) -> Result<(), CommonError>
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    let domaine_backup = commande.nom_domaine.as_str();
    info!("Debut backup incremental sur {}", domaine_backup);

    // Verifier si on a au moins une transaction à mettre dans le backup
    let nom_collection = commande.nom_collection_transactions.as_str();
    let collection = middleware.get_collection_typed::<TransactionOwned>(nom_collection)?;
    let filtre = doc! { TRANSACTION_CHAMP_BACKUP_FLAG: false, TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true };
    let find_options = FindOneOptions::builder()
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let idmg = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;

    if collection.find_one(filtre, find_options).await?.is_some() {
        debug!("backup_incremental Au moins une transaction a ajouter au backup incremental de {}", domaine_backup);
        traiter_transactions_incremental(
            middleware, path_backup, commande,
            cle_backup_domaine, domaine_backup, idmg.as_str()).await?;
        uploader_consignation().await?;
    } else {
        info!("backup_incremental Aucunes transactions a ajouter au backup incremental de {}, skip cette etape.", domaine_backup);
    }

    Ok(())
}

#[derive(Serialize)]
struct RequeteCleIdBackup {
    domaine: String,
}

#[derive(Deserialize)]
struct ReponseCleIdBackup {
    ok: bool,
    code: Option<usize>,
    err: Option<String>,
    cle_id: Option<String>,
}

#[derive(Serialize)]
struct CommandeEnregistrerCleidBackup {
    domaine: String,
    cle_id: Option<String>,
    reset: Option<bool>
}

struct CleBackupDomaine {
    cle: CleSecrete<32>,
    cle_id: String,
    signature_cle: SignatureDomaines,
}

/// Recupere la cle de backup de transactions.
/// En genere une nouvelle si elle n'existe pas ou est trop vieille.
async fn recuperer_cle_backup<M>(middleware: &M, domaine_backup: &str) -> Result<CleBackupDomaine, CommonError>
    where M: GenerateurMessages + ValidateurX509 + CleChiffrageHandler
{
    let requete_cleid_backup = RequeteCleIdBackup { domaine: domaine_backup.to_owned() };
    let routage_demande_cleid = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "getCleidBackupDomaine", vec![Securite::L3Protege]).build();

    let mut reponse_cle_id = match middleware.transmettre_requete(routage_demande_cleid, requete_cleid_backup).await? {
        Some(TypeMessage::Valide(m)) => {
            let reponse: ReponseCleIdBackup = deser_message_buffer!(m.message);
            if reponse.ok {
                reponse.cle_id
            } else {
                None
            }
        },
        _ => Err("backup_v2.recuperer_cle_backup Reponse invalide pour cle_id, reessayer plus tard")?
    };

    let cle_backup_domaine = match reponse_cle_id {
        Some(cle_id_backup) => {
            debug!("recuperer_cle_backup Charger la cle a partir du maitre des cles");
            let cles = get_cles_rechiffrees_v2(
                middleware, domaine_backup, vec![cle_id_backup.as_str()], Some(true)).await?;
            if cles.len() != 1 {
                Err(format!("backup_v2.recuperer_cle_backup Mauvais nombre de cles recus: {:?}", cles.len()))?;
            }
            let cle = &cles[0];

            // Decoder la cle secrete
            let mut cle_secrete = CleSecreteX25519 {0: [0u8;32]};
            cle_secrete.0.copy_from_slice(base64_nopad.decode(&cle.cle_secrete_base64)?.as_slice());
            let signature_cle = match cle.signature.as_ref() {
                Some(inner) => inner.clone(),
                None => Err("Signature cle n'as pas ete recue")?
            };

            CleBackupDomaine {
                cle: cle_secrete,
                cle_id: cle_id_backup,
                signature_cle,
            }
        }
        None => {
            debug!("recuperer_cle_backup Generer une nouvelle cle de backup");
            let (info_chiffrage, cle_derivee) = generer_cle_v2(
                middleware, vec![domaine_backup.to_owned()])?;
            debug!("Info chiffrage nouvelle cle: {:?}", info_chiffrage);

            // Sauvegarder la nouvelle cle aupres du maitre des cles
            let signature = match info_chiffrage.signature {
                Some(inner) => inner,
                None => Err("backup_v2.recuperer_cle_backup SignatureDomaine non genere")?
            };
            let cle_ref = signature.get_cle_ref()?.to_string();
            let cles = match info_chiffrage.cles {
                Some(inner) => inner,
                None => Err("backup_v2.recuperer_cle_backup Cles chiffrees non genere")?
            };
            let cles = cles.into_iter().collect();
            ajouter_cles_domaine(middleware, signature.clone(), cles, None).await?;

            // Enregistrer cle_id aupres de CoreTopologie
            let routage_enregistrer_cleid = RoutageMessageAction::builder(
                DOMAINE_TOPOLOGIE, "setCleidBackupDomaine", vec![Securite::L3Protege]).build();
            let commande_enregistrer_cleid = CommandeEnregistrerCleidBackup {
                domaine: domaine_backup.to_owned(), cle_id: Some(cle_ref.clone()), reset: None };
            if let Some(TypeMessage::Valide(message)) = middleware.transmettre_commande(routage_enregistrer_cleid, &commande_enregistrer_cleid).await? {
                let message_ref = message.message.parse()?.contenu()?;
                let reponse: ReponseCommande = message_ref.deserialize()?;
                if reponse.ok != Some(true) {
                    Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie (reponse false)")?
                }
            } else {
                Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie")?
            };

            // Retourner la cle secrete
            CleBackupDomaine {
                cle: cle_derivee.secret,
                cle_id: cle_ref,
                signature_cle: signature,
            }
        }
    };

    Ok(cle_backup_domaine)
}

#[derive(Serialize, Deserialize)]
struct HeaderFichierArchive {
    idmg: String,
    domaine: String,
    /// Type de fichier: I (incremental), C (concatene), F (final)
    type_archive: String,
    /// Date de la premiere transaction du backup (epoch seconds)
    debut_backup: u64,
    /// Date de la derniere transaction du backup (epoch seconds)
    fin_backup: u64,
    /// Nombre de transactions dans le backup
    nombre_transactions: u64,
    cle_id: String,
    cle_dechiffrage: SignatureDomaines,
    nonce: String,
    format: String,
    compression: Option<String>,
}

struct InfoTransactions {
    date_premiere_transaction: u64,
    date_derniere_transaction: u64,
    nombre_transactions: u64
}

/// Prepare un nouveau fichier avec stream de compression et cipher. Ajouter l'espace necessaire
/// pour le header du fichier.
async fn preparer_fichier_chiffrage(
    path_backup: &Path, rx: Receiver<TokioResult<Bytes>>, mut rx_info_transactions: Receiver<InfoTransactions>, cle_backup_domaine: &CleBackupDomaine,
    domaine: &str, idmg: &str
)
    -> Result<PathBuf, CommonError>
{

    let mut path_backup_file = path_backup.to_owned();
    path_backup_file.push("incremental.mgbak.work");
    if let Err(e) = fs::remove_file(&path_backup_file) {
        debug!("preparer_fichier_chiffrage Delete file result: {:?}", e);
    }
    let mut backup_file = tokio::io::BufWriter::new(tokio::fs::File::create(&path_backup_file).await?);

    // Ecrire le header
    static FILE_VERSION: u16 = 1;
    let mut header = HeaderFichierArchive {
        idmg: idmg.to_string(),
        domaine: domaine.to_string(),
        type_archive: "I".to_string(),
        debut_backup: u64::MAX,
        fin_backup: u64::MAX,
        nombre_transactions: u64::MAX,
        cle_id: cle_backup_domaine.cle_id.to_string(),
        cle_dechiffrage: cle_backup_domaine.signature_cle.to_owned(),
        nonce: "DUMMY_NONCE_HEADER_40_CHARS_____________".to_string(),
        format: "mgs4".to_string(),
        compression: Some("deflate".to_string()),
    };
    let header_str = serde_json::to_string(&header)?;
    let header_size = header_str.len() as u16;
    debug!("Header taille initiale {}", header_size);

    backup_file.write(&FILE_VERSION.to_le_bytes()).await?;
    backup_file.write(&header_size.to_le_bytes()).await?;
    backup_file.write_all(header_str.as_bytes()).await?;
    backup_file.flush().await?;

    // Creer threads de compression et chiffrage
    let cipher_result = {
        let (tx_deflate, rx_deflate) = mpsc::channel(5);
        let (tx_encrypt, rx_encrypt) = mpsc::channel(10);

        // Receive cleartext bytes, deflate, encrypt, output to file.
        let deflate_thread = start_deflate_thread(rx, tx_deflate);
        let encryption_thread = start_encryption_thread(&cle_backup_domaine.cle, rx_deflate, tx_encrypt);
        let filewriter_thread = start_filewriter_thread(rx_encrypt, &mut backup_file);

        let (deflate_result, cipher_result, filewriter_result) = join![deflate_thread, encryption_thread, filewriter_thread];
        deflate_result?;
        filewriter_result?;

        cipher_result?
    };

    // Flush le contenu et fermer le fichier
    backup_file.flush().await?;

    // Update header
    let info_transactions = match rx_info_transactions.recv().await {
        Some(inner) => inner,
        None => Err("Le channel d'information de transactions est ferme, aucune information recue")?
    };
    header.debut_backup = info_transactions.date_premiere_transaction;
    header.fin_backup = info_transactions.date_derniere_transaction;
    header.nombre_transactions = info_transactions.nombre_transactions;
    match cipher_result.cles.nonce {
        Some(inner) => {
            header.nonce = inner;
        },
        None => Err("Nonce absent du resultat de chiffrage")?
    }
    let header_str = serde_json::to_string(&header)?;
    let header_updated_size = header_str.len() as u16;
    debug!("Header taille mise a jour {}, valeur: {}", header_updated_size, header_str);
    if header_size < header_updated_size {
        Err("Header mis a jour est plus grand que l'espace reserve")?;
    }

    // Fix file header with missing information, keey same version (bytes 0-1)
    backup_file.seek(SeekFrom::Start(2)).await?;
    backup_file.write(&header_updated_size.to_le_bytes()).await?;
    backup_file.write_all(header_str.as_bytes()).await?;
    // Truncate by filling in 0s over the remaining original header
    for _ in header_updated_size..header_size {
        backup_file.write(&[0u8]).await?;
    }
    backup_file.flush().await?;

    Ok(path_backup_file)
}

async fn start_filewriter_thread(mut rx: Receiver<TokioResult<Bytes>>, backup_file: &mut tokio::io::BufWriter<tokio::fs::File>)
    -> Result<(), CommonError>
{
    while let Some(result) = rx.recv().await {
        let data = result?;
        backup_file.write_all(data.as_ref()).await?;
    }
    Ok(())
}

async fn start_encryption_thread(cle_secrete: &CleSecrete<32>, mut rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>)
    -> Result<CipherResult<32>, CommonError>
{
    let cle_secrete_cipher = CleSecreteCipher::CleSecrete(cle_secrete.to_owned());

    let mut cipher = CipherMgs4::with_secret(cle_secrete_cipher)?;

    let mut data_output = [0u8; 64 * 1024];
    static CHUNK_SIZE: usize = 64 * 1024 - 17;

    while let Some(result) = rx.recv().await {
        let data = result?;
        for chunk in data.chunks(CHUNK_SIZE) {
            let output = cipher.update(chunk, &mut data_output)?;
            let encrypted_data = &data_output[0..output];
            tx.send(Ok(Bytes::from(encrypted_data.to_vec()))).await?;
        }
    }

    // Finaliser chiffrage
    let result = cipher.finalize(&mut data_output)?;
    if result.len > 0 {
        // Output last buffer
        let encrypted_data = &data_output[0..result.len];
        tx.send(Ok(Bytes::from(encrypted_data.to_vec()))).await?;
    }
    Ok(result)
}

async fn start_deflate_thread(mut rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>) -> Result<(), CommonError> {
    let stream = ReceiverStream::new(rx);
    let reader = StreamReader::new(stream);
    let encoder = DeflateEncoder::new(BufReader::new(reader));
    let mut encoder_stream = ReaderStream::new(encoder);

    while let Some(result) = encoder_stream.next().await {
        let data = result?;
        tx.send(Ok(data)).await?;
    }

    Ok(())
}

/// Fait le backup des nouvelles transactions dans un fichier de backup incremental.
async fn traiter_transactions_incremental<M>(
    middleware: &M, path_backup: &Path, commande_backup: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine,
    domaine: &str, idmg: &str
)
    -> Result<(), CommonError>
    where M: MongoDao
{
    debug!("traiter_transactions_incremental Debut");

    // Creer channels de communcation entre threads
    let (tx_transactions, rx_transactions) = mpsc::channel(2);
    let (tx_info_transactions, rx_info_transactions) = mpsc::channel(2);

    // Preparer une thread de traitement du fichier
    let pipe = preparer_fichier_chiffrage(
        path_backup, rx_transactions, rx_info_transactions, cle_backup_domaine, domaine, idmg);

    // Traiter les transactions en ordre sequentiel.
    let transaction_process = traiter_transactions_incrementales(
        middleware, commande_backup, tx_transactions, tx_info_transactions);

    let result = join![pipe, transaction_process];
    debug!("Resultat process: {:?}", result);

    debug!("traiter_transactions_incremental Fin");
    Ok(())
}

async fn traiter_transactions_incrementales<M>(middleware: &M, commande_backup: &CommandeBackup,
                                               tx: Sender<TokioResult<Bytes>>, tx_info_transactions: Sender<InfoTransactions>)
    -> Result<(), CommonError>
    where M: MongoDao
{
    let nom_collection_transactions = commande_backup.nom_collection_transactions.as_str();

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

    debug!("backup.requete_transactions Collection {}, filtre {:?}", nom_collection_transactions, filtre);
    let collection = middleware.get_collection_typed::<TransactionOwned>(nom_collection_transactions)?;
    let mut curseur = collection.find(filtre, find_options).await?;

    let mut nombre_transactions = 0u64;
    let mut date_premiere = 0u64;
    let mut date_derniere = 0u64;

    while curseur.advance().await? {
        let transaction = curseur.deserialize_current()?;

        // Compteurs et dates
        nombre_transactions += 1;
        let estampille = transaction.estampille.timestamp() as u64;
        if date_premiere == 0 {
            date_premiere = estampille;
        }
        date_derniere = estampille;

        let mut contenu_bytes = {
            let contenu_str = serde_json::to_string(&transaction)?;
            contenu_str.as_bytes().to_vec()
        };
        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);
        tx.send(Ok(Bytes::from(contenu_bytes))).await?;
    }

    let info_transactions = InfoTransactions {
        date_premiere_transaction: date_premiere,
        date_derniere_transaction: date_derniere,
        nombre_transactions,
    };
    tx_info_transactions.send(info_transactions).await?;

    Ok(())
}

/// Upload le fichier de backup vers la consignation.
async fn uploader_consignation() -> Result<(), CommonError> {
    todo!()
}

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
async fn run_backup_complet<M>(middleware: &M, commande: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine) -> Result<(), CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    info!("Debut backup complet sur {}", commande.nom_domaine);

    todo!();

    Ok(())
}
