use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::sync::Arc;
use std::fs;
use std::fs::{File, FileType};
use std::io::{ErrorKind, SeekFrom};
use std::ops::Index;
use std::path::{Path, PathBuf};
use fs2::FileExt;
use chrono::{{SecondsFormat, TimeZone, Utc}, format::strftime::StrftimeItems};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult, CleChiffrageHandler, CleChiffrageStruct, CleDechiffrageStruct, Decipher};
use millegrilles_cryptographie::deser_message_buffer;
use millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519, CleSecreteX25519};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use async_compression::tokio::bufread::{DeflateEncoder, GzipEncoder, DeflateDecoder};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, Receiver};

use millegrilles_cryptographie::chiffrage::{CleSecrete, FormatChiffrage};
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher, DecipherMgs4};
use millegrilles_cryptographie::hachages::HacheurBlake2b512;
use millegrilles_cryptographie::maitredescles::{generer_cle_avec_ca, SignatureDomaines};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use mongodb::bson::doc;
use mongodb::options::{FindOneOptions, FindOptions, Hint};
use multibase::Base;
use multihash::Code;
use substring::Substring;
use tokio::fs::read_dir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, Result as TokioResult};
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
use crate::hachages::HacheurBuilder;
use crate::messages_generiques::{CommandeSauvegarderCertificat, ReponseCommande};
use crate::recepteur_messages::TypeMessage;

pub const PATH_FICHIERS_BACKUP: &str = "/var/opt/millegrilles/backup";

#[derive(Clone)]
enum TypeArchive {
    Incremental,
    Concatene,
    Final
}

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
            if let Err(e) = run_backup_complet(middleware, &commande, &cle_backup_domaine, path_backup.as_ref()).await {
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
/// S'assure que tous les certificats sont sauvegardés dans CorePki.
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

pub struct CleBackupDomaine {
    pub cle: CleSecrete<32>,
    pub cle_id: String,
    pub signature_cle: SignatureDomaines,
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Clone)]
pub struct InfoTransactions {
    pub date_premiere_transaction: u64,
    pub date_derniere_transaction: u64,
    pub nombre_transactions: u64
}

/// Prepare un nouveau fichier avec stream de compression et cipher. Ajouter l'espace necessaire
/// pour le header du fichier.
async fn preparer_fichier_chiffrage(
    path_backup: &Path, type_fichier: TypeArchive, rx: Receiver<TokioResult<Bytes>>,
    mut rx_info_transactions: Receiver<InfoTransactions>, cle_backup_domaine: &CleBackupDomaine,
    domaine: &str, idmg: &str
)
    -> Result<(PathBuf, CipherResult<32>), CommonError>
{

    let mut path_backup_file = path_backup.to_owned();

    let (marqueur_type_archive, prefixe_nom_work) = match type_fichier {
        TypeArchive::Incremental => ("I", "incremental"),
        TypeArchive::Concatene => ("C", "concatene)"),
        _ => Err("Non supporte")?
    };

    path_backup_file.push(format!("{}.mgbak.work", prefixe_nom_work));
    if let Err(e) = fs::remove_file(&path_backup_file) {
        debug!("preparer_fichier_chiffrage Delete file result: {:?}", e);
    }
    let mut backup_file = tokio::io::BufWriter::new(tokio::fs::File::create(&path_backup_file).await?);

    // Ecrire le header
    static FILE_VERSION: u16 = 1;
    let mut header = HeaderFichierArchive {
        idmg: idmg.to_string(),
        domaine: domaine.to_string(),
        type_archive: marqueur_type_archive.to_string(),
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
    debug!("preparer_fichier_chiffrage Header taille initiale {}", header_size);

    backup_file.write(&FILE_VERSION.to_le_bytes()).await?;
    backup_file.write(&header_size.to_le_bytes()).await?;
    backup_file.write_all(header_str.as_bytes()).await?;
    backup_file.flush().await?;

    // Creer threads de compression et chiffrage
    let cipher_result = {
        let (tx_deflate, rx_deflate) = mpsc::channel(5);
        let (tx_encrypt, rx_encrypt) = mpsc::channel(10);

        // Receive cleartext bytes, deflate, encrypt, output to file.
        let deflate_thread = deflate_pipe_thread(rx, tx_deflate);
        let encryption_thread = encryption_pipe_thread(&cle_backup_domaine.cle, rx_deflate, tx_encrypt);
        let filewriter_thread = filewriter_pipe_thread(rx_encrypt, &mut backup_file);

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
        None => Err("backup_v2.preparer_fichier_chiffrage Le channel d'information de transactions est ferme, aucune information recue")?
    };
    header.debut_backup = info_transactions.date_premiere_transaction;
    header.fin_backup = info_transactions.date_derniere_transaction;
    header.nombre_transactions = info_transactions.nombre_transactions;
    match cipher_result.cles.nonce.as_ref() {
        Some(inner) => {
            header.nonce = inner.clone();
        },
        None => Err("backup_v2.preparer_fichier_chiffrage Nonce absent du resultat de chiffrage")?
    }
    let header_str = serde_json::to_string(&header)?;
    let header_updated_size = header_str.len() as u16;
    debug!("preparer_fichier_chiffrage Header taille mise a jour {}, valeur: {}", header_updated_size, header_str);
    if header_size < header_updated_size {
        Err("backup_v2.preparer_fichier_chiffrage Header mis a jour est plus grand que l'espace reserve")?;
    }

    // Fix file header with missing information, keep same version and header size info (bytes 0-3)
    // The unused header portion will be padded with 0s.
    backup_file.seek(SeekFrom::Start(4)).await?;
    backup_file.write_all(header_str.as_bytes()).await?;
    // Truncate by filling in 0s over the remaining original header
    for _ in header_updated_size..header_size {
        backup_file.write(&[0u8]).await?;
    }
    backup_file.flush().await?;

    Ok((path_backup_file, cipher_result))
}

async fn filewriter_pipe_thread(mut rx: Receiver<TokioResult<Bytes>>, backup_file: &mut tokio::io::BufWriter<tokio::fs::File>)
                                -> Result<(), CommonError>
{
    while let Some(result) = rx.recv().await {
        let data = result?;
        backup_file.write_all(data.as_ref()).await?;
    }
    Ok(())
}

async fn encryption_pipe_thread(cle_secrete: &CleSecrete<32>, mut rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>)
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

async fn deflate_pipe_thread(mut rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>) -> Result<(), CommonError> {
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

/// Execute le digest black2b-512 sur le fichier, retourne le resultat en base58btc.
async fn digest_file(file_path: &Path) -> Result<String, CommonError> {
    let mut backup_file = tokio::io::BufReader::new(tokio::fs::File::open(&file_path).await?);

    let mut digester = HacheurBuilder::new().digester(Code::Blake2b512).base(Base::Base58Btc).build();

    let mut buffer = [0u8; 64*1024];
    loop {
        let len = backup_file.read(&mut buffer).await?;
        if len == 0 {
            break;
        }
        digester.update(&buffer[..len]);
    }

    Ok(digester.finalize())
}

async fn rename_work_file(type_archive: &TypeArchive, info_transactions: &InfoTransactions,
                          domaine: &str, path_backup: &Path, path_fichier_work: &Path)
    -> Result<PathBuf, CommonError>
{
    // Rename work file
    let date_premiere_transaction = Utc.timestamp_millis_opt(info_transactions.date_premiere_transaction as i64).unwrap();
    let date_str = date_premiere_transaction.format_with_items(StrftimeItems::new("%Y%m%d%H%M%S%3fZ"));

    // Calculer le digest du fichier (apres modification du header).
    let digest_str = digest_file(path_fichier_work).await?;

    let marqueur_type_archive = match type_archive {
        TypeArchive::Incremental => "I",
        TypeArchive::Concatene => "C",
        TypeArchive::Final => "F",
    };

    // Exemple de nom de fichier : AiLanguage_2024-09-24T21:43:07.162Z_I_KozFJz4vLFe7.mgbak
    let backup_file_name = format!(
        "{}_{}_{}_{}.mgbak",
        domaine,
        date_str,
        marqueur_type_archive,
        &digest_str[digest_str.len()-12..digest_str.len()]  // Garder les 12 derniers chars du digest
    );

    debug!("rename_work_file Date {}, digest {}, filename: {}", date_str, digest_str, backup_file_name);
    let mut backup_file_path = path_backup.to_owned();
    backup_file_path.push(backup_file_name);
    fs::rename(path_fichier_work, &backup_file_path)?;

    Ok(backup_file_path)
}

/// Fait le backup des nouvelles transactions dans un fichier de backup incremental.
async fn traiter_transactions_incremental<M>(
    middleware: &M, path_backup: &Path, commande_backup: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine,
    domaine: &str, idmg: &str
)
    -> Result<(), CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages
{
    debug!("traiter_transactions_incremental Debut");
    let debut_traitement = Utc::now();

    // Creer channels de communcation entre threads
    let (tx_transactions, rx_transactions) = mpsc::channel(2);
    let (tx_info_transactions, rx_info_transactions) = mpsc::channel(2);

    // Preparer une thread de traitement du fichier
    let type_archive = TypeArchive::Incremental;
    let pipe = preparer_fichier_chiffrage(
        path_backup, type_archive.clone(), rx_transactions, rx_info_transactions, cle_backup_domaine, domaine, idmg);

    // Traiter les transactions en ordre sequentiel.
    let transaction_process = traiter_transactions_incrementales(
        middleware, commande_backup, tx_transactions, tx_info_transactions);

    let (pipe_result, transaction_result) = join![pipe, transaction_process];

    // Rename work file
    let info_transactions = transaction_result?;
    let (temp_file, _) = pipe_result?;
    rename_work_file(&type_archive, &info_transactions, domaine, path_backup, temp_file.as_ref()).await?;

    // let date_premiere_transaction = Utc.timestamp_millis_opt(info_transactions.date_premiere_transaction as i64).unwrap();
    let date_derniere_transaction = Utc.timestamp_millis_opt(info_transactions.date_derniere_transaction as i64).unwrap();
    // let date_str = date_premiere_transaction.format_with_items(StrftimeItems::new("%Y%m%d%H%M%S%3fZ"));

    // Calculer le digest du fichier (apres modification du header).
    // let digest_str = digest_file(temp_file.as_ref()).await?;

    // Exemple de nom de fichier : AiLanguage_2024-09-24T21:43:07.162Z_I_KozFJz4vLFe7.mgbak
    // let backup_file_name = format!(
    //     "{}_{}_{}_{}.mgbak",
    //     domaine,
    //     date_str,
    //     "I",
    //     &digest_str[digest_str.len()-12..digest_str.len()]  // Garder les 12 derniers chars du digest
    // );
    // debug!("Date {}, digest {}, filename: {}", date_str, digest_str, backup_file_name);
    // let mut backup_file_path = path_backup.to_owned();
    // backup_file_path.push(backup_file_name);
    // fs::rename(temp_file, backup_file_path)?;

    // Supprimer les transactions traitees. On utilise la date de la plus recente transaction archivee
    // pour s'assurer de ne pas effacer de nouvelles transactions non traitees.
    let collection = middleware.get_collection(commande_backup.nom_collection_transactions.as_str())?;
    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$lte": date_derniere_transaction},
    };
    collection.delete_many(filtre, None).await?;

    let fin_traitement = Utc::now();
    debug!("traiter_transactions_incremental Fin, duree: {}", fin_traitement - debut_traitement);
    Ok(())
}

async fn traiter_transactions_incrementales<M>(middleware: &M, commande_backup: &CommandeBackup,
                                               tx: Sender<TokioResult<Bytes>>, tx_info_transactions: Sender<InfoTransactions>)
    -> Result<InfoTransactions, CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages
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

    let mut certificats_traites = HashSet::new();
    let mut certificats_pending = HashMap::new();

    while curseur.advance().await? {
        let transaction = curseur.deserialize_current()?;

        // Sauvegarder les certificats
        let fingerprint = &transaction.pubkey;
        if ! certificats_traites.contains(fingerprint) {
            if ! certificats_pending.contains_key(fingerprint) {
                if let Some(certificat) = transaction.certificat.clone() {
                    certificats_pending.insert(fingerprint.to_owned(), certificat);
                } else {
                    warn!("Certificat de transaction {} absent de la table transactions", fingerprint);
                }

                // Sauvegarder batch au besoin
                if certificats_pending.len() > 20 {
                    match sauvegarder_certificats(middleware, &certificats_pending).await {
                        Ok(()) => {
                            // Conserver liste des certificats sauvegardes, reset (drain) liste de certificats
                            certificats_traites.extend(certificats_pending.drain().map(|(key,_)| key));
                        },
                        Err(e) => {
                            warn!("Erreur sauvegarde de certificats, continuer le backup pour reessayer plus tard: {:?}", e);
                        }
                    }
                }
            }
        }  // Fin sauvegarder certificats

        let date_transaction_traitee = match transaction.evenements.as_ref() {
            Some(inner) => {
                match inner.transaction_traitee.as_ref() {
                    Some(inner) => inner,
                    None => continue // Transaction non traitee, skip
                }
            },
            None => continue // Transaction non traitee, skip
        };

        // Compteurs et dates
        nombre_transactions += 1;
        let date_traiee = date_transaction_traitee.timestamp_millis() as u64;
        if date_premiere == 0 {
            date_premiere = date_traiee;
        }
        date_derniere = date_traiee;

        let mut contenu_bytes = {
            let contenu_str = serde_json::to_string(&transaction)?;
            contenu_str.as_bytes().to_vec()
        };
        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);
        tx.send(Ok(Bytes::from(contenu_bytes))).await?;
    }

    // Sauvegarder la derniere batch de certificats
    if certificats_pending.len() > 0 {
        sauvegarder_certificats(middleware, &certificats_pending).await?;
    }

    let info_transactions = InfoTransactions {
        date_premiere_transaction: date_premiere,
        date_derniere_transaction: date_derniere,
        nombre_transactions,
    };
    tx_info_transactions.send(info_transactions.clone()).await?;

    Ok(info_transactions)
}

/// Upload le fichier de backup vers la consignation.
async fn uploader_consignation() -> Result<(), CommonError> {
    error!("TODO Uploader consignation");
    Ok(())
}

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
async fn run_backup_complet<M>(middleware: &M, commande: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine, path_backup: &Path)
    -> Result<(), CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    info!("Debut backup complet sur {}", commande.nom_domaine);

    let domaine = commande.nom_domaine.as_str();
    let fichiers = organiser_fichiers_backup(path_backup, false).await?;

    {
        // Verifier si on a au moins un fichier incremental
        let marqueur_incremental = "I".to_string();
        let fichiers_incrementaux = fichiers.iter().filter(|f| f.header.type_archive == marqueur_incremental).count();
        if fichiers_incrementaux == 0 {
            info!("Aucuns fichiers incrementaux, skip backup complet");
            return Ok(());
        }
    }

    let cles_backup = charger_cles_backup(middleware, domaine, &fichiers, Some(cle_backup_domaine)).await?;
    let (path_archive, info_transactions) = generer_archive_concatenee(
        middleware, path_backup, commande, cle_backup_domaine, &fichiers, &cles_backup).await?;

    // Renommer vieilles archives concatenee et incrementales a .old
    for file in &fichiers {
        let mut new_name = file.path_fichier.clone();
        new_name.set_extension(".mgbak.old");
        tokio::fs::rename(&file.path_fichier, new_name).await?;
    }

    // Renommer nouvelle archive concatenee
    rename_work_file(&TypeArchive::Concatene, &info_transactions, domaine, path_backup, path_archive.as_ref()).await?;

    // Uploader nouvelle archive concatenee

    // Supprimer vieilles archives obsoletes (.old)
    for file in &fichiers {
        let mut new_name = file.path_fichier.clone();
        new_name.set_extension(".mgbak.old");
        tokio::fs::remove_file(new_name).await?;
    }

    Ok(())
}

async fn sauvegarder_certificats<M>(middleware: &M, certificats: &HashMap<String, Vec<String>>)
    -> Result<(), CommonError>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_PKI, COMMANDE_SAUVEGARDER_CERTIFICAT, vec![Securite::L3Protege]).build();

    debug!("Sauvegarder {} certificats", certificats.len());

    for certificat in certificats.values() {
        let commande = CommandeSauvegarderCertificat {
            chaine_pem: certificat.to_owned(),
            ca: None,
        };
        let reponse = middleware.transmettre_commande(routage.clone(), &commande).await?;
        if let Some(TypeMessage::Valide(reponse)) = reponse {
            let reponse_owned = reponse.message.parse_to_owned()?;
            let reponse_commande: ReponseCommande = reponse_owned.deserialize()?;
            if reponse_commande.ok != Some(true) {
                Err(format!("backup_v2.sauvegarder_certificats Reponse de type erreur durant la sauvegarde de certificat : {:?}", reponse_commande.err))?
            }
        } else {
            Err("backup_v2.sauvegarder_certificats Mauvais type de reponse pour la sauvegarde de certificat")?
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct FichierArchiveBackup {
    pub path_fichier: PathBuf,
    pub header: HeaderFichierArchive,
    pub position_data: usize,
}

/// Fait la liste des fichiers de backup sur disque, lit le header et les trie.
pub async fn organiser_fichiers_backup(backup_path: &Path, inclure_final: bool) -> Result<Vec<FichierArchiveBackup>, CommonError> {
    let mut paths = read_dir(backup_path).await?;

    let mgback_ext: OsString = "mgbak".into();

    debug!("organiser_fichiers_backup Parcourir {:?} pour fichiers d'archive .mgbak", backup_path);

    let mut fichiers = Vec::new();
    loop {
        let file_path = match paths.next_entry().await? {
            Some(inner) => {
                if inner.file_type().await?.is_file() {
                    let file_path = inner.path();
                    if file_path.extension() != Some(mgback_ext.as_os_str()) {
                        continue;  // Wrong extension
                    }
                    file_path
                } else {
                    continue;  // Directory, skip
                }
            },
            None => break  // Done
        };

        let mut fp = tokio::fs::File::open(&file_path).await?;
        let version = fp.read_i16_le().await?;
        if version != 1 {
            Err(format!("Unsupported archive version {}", version))?
        }
        let taille_header = fp.read_i16_le().await?;
        let mut header_vec: Vec<u8> = Vec::new();
        header_vec.resize(taille_header as usize, 0u8);
        let mut buffer = header_vec.as_mut_slice();
        fp.read(&mut buffer).await?;

        // Trouver la fin du header json (premier trailing 0x0)
        let mut header_len_effective = taille_header as usize;
        if let Some(v) = header_vec.iter().position(|&x| x == 0u8) {
            header_len_effective = v;
        }
        let header: HeaderFichierArchive = serde_json::from_slice(&header_vec[0..header_len_effective])?;

        // Verification d'integrite entre les fichiers. On s'assure que le fichier courant
        // n'as pas de transactions plus anciennes que la derniere transaction du fichier precedent.

        let position_data = (4 + taille_header) as usize;  // 4 bytes (version u16, taille header u16) + header
        if inclure_final || header.format != "F".to_string() {
            fichiers.push(FichierArchiveBackup { path_fichier: file_path, header, position_data });
        }
    }

    // Trier les fichiers par date de transactions
    fichiers.sort_by(|a, b| {
        a.header.debut_backup.partial_cmp(&b.header.debut_backup).expect("header partial_cmp")
    });

    // Verifier l'ordre des fichiers, pas d'overlap de transactions
    let mut date_transaction_precedente = 0u64;
    for fichier in &fichiers {
        if fichier.header.debut_backup < date_transaction_precedente {
            Err(format!("backup_v2.organiser_fichiers_backup Fichiers de transactions dans le mauvais ordre, transaction plus ancienne trouvee dans {:?}", fichier.path_fichier))?
        }
        date_transaction_precedente = fichier.header.fin_backup;
    }

    debug!("organiser_fichiers_backup Liste fichiers tries\n{:?}", fichiers);

    Ok(fichiers)
}

pub async fn charger_cles_backup<M>(middleware: &M, domaine: &str, fichiers: &Vec<FichierArchiveBackup>, cle_backup_domaine: Option<&CleBackupDomaine>)
    -> Result<HashMap<String, CleSecrete<32>>, CommonError>
    where M: GenerateurMessages
{
    let cle_ids: Vec<&str> = fichiers.iter().map(|f|f.header.cle_id.as_str()).collect();

    // Dedupe
    let mut cle_ids_set = HashSet::new();
    cle_ids_set.extend(cle_ids.into_iter());
    if let Some(cle_domaine) = cle_backup_domaine {
        cle_ids_set.remove(cle_domaine.cle_id.as_str());
    }
    let vec_cle_ids: Vec<&str> = cle_ids_set.into_iter().collect();
    let nombre_cles_a_charger = vec_cle_ids.len();

    // Recuperer cles a partir du maitre des cles
    let mut cles = HashMap::new();
    if nombre_cles_a_charger > 0 {
        let reponse_cles = get_cles_rechiffrees_v2(
            middleware, domaine, vec_cle_ids, Some(false)).await?;
        if reponse_cles.len() != 1 {
            Err(format!("backup_v2.recuperer_cle_backup Mauvais nombre de cles recus: {:?}", reponse_cles.len()))?;
        }
        for cle in reponse_cles {
            let cle_id = match cle.cle_id {
                Some(inner) => inner,
                None => Err("Reponse cle sans cle_id")?
            };
            let mut cle_secrete = CleSecreteX25519 { 0: [0u8; 32] };
            cle_secrete.0.copy_from_slice(base64_nopad.decode(&cle.cle_secrete_base64)?.as_slice());
            cles.insert(cle_id, cle_secrete);
        }

        if cles.len() != nombre_cles_a_charger {
            Err(format!("backup_v2.recuperer_cle_backup Certaines cles de backup n'ont pas ete trouvees, il en manque {}/{}", cles.len() - nombre_cles_a_charger, nombre_cles_a_charger))?
        }
    }

    if let Some(cle_domaine) = cle_backup_domaine {
        cles.insert(cle_domaine.cle_id.clone(), cle_domaine.cle.clone());
    }

    Ok(cles)
}

/// Genere une nouvelle archive concatenee a partir de tous les fichiers concatenes et incrementaux existants
async fn generer_archive_concatenee<M>(
    middleware: &M, path_backup: &Path, commande_backup: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine,
    fichiers: &Vec<FichierArchiveBackup>, cles: &HashMap<String, CleSecrete<32>>
)
    -> Result<(PathBuf, InfoTransactions), CommonError>
    where M: GenerateurMessages
{
    let idmg = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;
    let domaine = commande_backup.nom_domaine.as_str();

    let (tx_deflate, rx_deflate) = mpsc::channel(5);
    let (tx_transactions, rx_transactions) = mpsc::channel(5);
    let (tx_info_transactions, rx_info_transactions) = mpsc::channel(1);

    let thread_lecture = lire_archives_thread(fichiers, cles, tx_deflate);
    let thread_transaction_reader = process_transactions(rx_deflate, tx_transactions, tx_info_transactions);
    let thread_fichier_concatene = preparer_fichier_chiffrage(
        path_backup, TypeArchive::Concatene, rx_transactions, rx_info_transactions, cle_backup_domaine, domaine, idmg.as_str());

    // Effectuer le traitement
    let (lecture_result, result_transactions, result_fichier_concatene) = join![
        thread_lecture, thread_transaction_reader, thread_fichier_concatene];

    // Consommer resultats
    lecture_result?;
    let info_transactions = result_transactions?;
    let (temp_file, _) = result_fichier_concatene?;

    // Rename work file
    // rename_work_file(&TypeArchive::Concatene, &info_transactions, domaine, path_backup, temp_file.as_ref()).await?;

    Ok((temp_file, info_transactions))
}

async fn lire_archives_thread(
    fichiers: &Vec<FichierArchiveBackup>, cles: &HashMap<String, CleSecrete<32>>,
    mut tx: Sender<TokioResult<Bytes>>
)
    -> Result<(), CommonError>
{
    for fichier in fichiers {
        let cle = match cles.get(&fichier.header.cle_id) {
            Some(inner) => inner,
            None => Err(format!("Cle_id {} manquant pour archive {:?}", fichier.header.cle_id, fichier.path_fichier))?
        };

        let (tx_decrypt, rx_decrypt) = mpsc::channel(10);
        let thread_dechiffrer = dechiffrer_archive(fichier, cle, tx_decrypt);
        let thread_deflate_decoder = deflate_decoder_pipe_thread(rx_decrypt, tx.clone());

        let (result_dechiffrer, result_deflate) = join![thread_dechiffrer, thread_deflate_decoder];
        // Consommer resultats
        result_dechiffrer?;
        result_deflate?;
    }

    debug!("lire_archives_thread Thread terminee");

    Ok(())
}

async fn dechiffrer_archive(
    fichier_archive: &FichierArchiveBackup, cle_dechiffrage: &CleSecrete<32>,
    tx: Sender<TokioResult<Bytes>>
)
    -> Result<(), CommonError>
{
    debug!("dechiffrer_archive {:?}", fichier_archive.path_fichier);

    let cle_dechiffrage_struct = CleDechiffrageStruct {
        cle_chiffree: "NA".to_string(),
        cle_secrete: Some(cle_dechiffrage.to_owned()),
        format: fichier_archive.header.format.as_str().try_into()?,
        nonce: Some(fichier_archive.header.nonce.clone()),
        verification: None,
    };
    let mut decipher = DecipherMgs4::new(&cle_dechiffrage_struct)?;

    let mut backup_file = tokio::io::BufReader::new(tokio::fs::File::open(&fichier_archive.path_fichier).await?);

    // Skip header, aller directement au data
    backup_file.seek(SeekFrom::Start(fichier_archive.position_data as u64)).await?;

    let mut buffer_in = [0u8; 64*1024];
    let mut buffer_out = [0u8; 64*1024];  // Avec MGS4, decipher output toujours plus petit que input
    loop {
        let len = backup_file.read(&mut buffer_in).await?;
        if len == 0 { break; }
        let output_len = decipher.update(&buffer_in[..len], &mut buffer_out)?;
        if output_len > 0 {
            if let Err(e) = tx.send(Ok(Bytes::from(buffer_out[0..output_len].to_vec()))).await {
                Err(format!("dechiffrer_archive {:?} Error sending data (update): {:?}", fichier_archive.path_fichier, e))?
            }
        }
    }

    // Decrypt final block, authenticate
    let output_len = decipher.finalize(&mut buffer_out)?;

    // Pipe out
    if output_len > 0 {
        // debug!("dechiffrer_archive Sending last {} bytes", output_len);
        if let Err(e) = tx.send(Ok(Bytes::from(buffer_out[0..output_len].to_vec()))).await {
            Err(format!("dechiffrer_archive {:?} Error sending data (final): {:?}", fichier_archive.path_fichier, e))?
        }
    }

    // debug!("dechiffrer_archive Archive {:?} dechiffree correctement", fichier_archive.path_fichier);

    Ok(())
}

async fn deflate_decoder_pipe_thread(rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>) -> Result<(), CommonError> {
    let stream = ReceiverStream::new(rx);
    let reader = StreamReader::new(stream);
    let encoder = DeflateDecoder::new(BufReader::new(reader));
    let mut encoder_stream = ReaderStream::new(encoder);

    while let Some(result) = encoder_stream.next().await {
        let data = result?;
        if let Err(e) = tx.send(Ok(data)).await {
            error!("deflate_decoder_pipe_thread Error sending data: {:?}", e);
            Err(e)?;
        }
    }

    debug!("deflate_decoder_pipe_thread Thread terminee");

    Ok(())
}

async fn process_transactions(rx: Receiver<TokioResult<Bytes>>, tx: Sender<TokioResult<Bytes>>, tx_info_transactions: Sender<InfoTransactions>)
    -> Result<InfoTransactions, CommonError>
{
    let stream = ReceiverStream::new(rx);
    let mut reader = StreamReader::new(stream);

    let mut line = String::new();
    let mut compteur_transactions = 0;
    let mut date_premiere = 0;
    let mut date_derniere = 0;

    loop {
        let output_len = reader.read_line(&mut line).await?;

        if output_len == 0 {
            break;  // Done
        }

        let transaction_str = line.substring(0, output_len);
        // debug!("process_transactions Transaction lue: \n*/{}\\*", transaction_str);

        // Parse transaction pour garantir structure
        let transaction: TransactionOwned = serde_json::from_str(transaction_str)?;
        let date_traitement = match transaction.evenements.as_ref() {
            Some(evenements) => match evenements.transaction_traitee.as_ref() {
                Some(inner) => inner,
                None => Err("process_transactions transaction sans date de traitement")?
            },
            None => Err("process_transactions transaction sans elements pour evenements")?
        };

        // Mettre a jour compteur et marqueurs de date pour l'archive
        compteur_transactions += 1;
        let date_traitement_u64 = date_traitement.timestamp_millis() as u64;
        if date_traitement_u64 < date_derniere {
            Err(format!("backup_v2.process_transactions Erreur transaction compteur:{} id:{} plus ancienne que les transactions precedentes", compteur_transactions, transaction.id))?
        }
        if date_premiere == 0 { date_premiere = date_traitement_u64; }
        date_derniere = date_traitement_u64;

        if let Err(e) = tx.send(Ok(Bytes::from(transaction_str.to_string()))).await {
            error!("process_transactions Error sending data: {:?}", e);
            Err(e)?;
        }

        line.clear();  // Reset buffer
    }

    let info_transactions = InfoTransactions {
        date_premiere_transaction: date_premiere,
        date_derniere_transaction: date_derniere,
        nombre_transactions: compteur_transactions,
    };
    tx_info_transactions.send(info_transactions.clone()).await?;

    debug!("process_transactions Fin thread");

    Ok(info_transactions)
}

pub struct RegenerationBackup {
    pub domaine: String,
    pub fichiers: Vec<FichierArchiveBackup>,
    pub cles: HashMap<String, CleSecrete<32>>,
}

/// Lit toutes les transactions dans l'ordre, emet via Sender.
pub async fn lire_transactions_fichiers(info_regeneration: RegenerationBackup, tx: Sender<TransactionOwned>)
    -> Result<InfoTransactions, CommonError>
{
    let (tx_deflate, rx_deflate) = mpsc::channel(5);

    let thread_lecture = lire_archives_thread(
        &info_regeneration.fichiers, &info_regeneration.cles, tx_deflate);
    let thread_transaction_reader = pipe_transactions(rx_deflate, tx);

    let (result_lecture, result_transactions) = join![thread_lecture, thread_transaction_reader];
    result_lecture?;
    let info_transactions = result_transactions?;

    Ok(info_transactions)
}

async fn pipe_transactions(rx: Receiver<TokioResult<Bytes>>, tx: Sender<TransactionOwned>)
    -> Result<InfoTransactions, CommonError>
{
    let stream = ReceiverStream::new(rx);
    let mut reader = StreamReader::new(stream);

    let mut line = String::new();
    let mut compteur_transactions = 0;
    let mut date_premiere = 0;
    let mut date_derniere = 0;

    loop {
        let output_len = reader.read_line(&mut line).await?;

        if output_len == 0 {
            break;  // Done
        }

        let transaction_str = line.substring(0, output_len);
        // debug!("process_transactions Transaction lue: \n*/{}\\*", transaction_str);

        // Parse transaction pour garantir structure
        let transaction: TransactionOwned = serde_json::from_str(transaction_str)?;
        let date_traitement = match transaction.evenements.as_ref() {
            Some(evenements) => match evenements.transaction_traitee.as_ref() {
                Some(inner) => inner,
                None => Err("process_transactions transaction sans date de traitement")?
            },
            None => Err("process_transactions transaction sans elements pour evenements")?
        };

        // Mettre a jour compteur et marqueurs de date pour l'archive
        compteur_transactions += 1;
        let date_traitement_u64 = date_traitement.timestamp_millis() as u64;
        if date_premiere == 0 { date_premiere = date_traitement_u64; }

        if date_traitement_u64 < date_derniere {
            Err(format!("backup_v2.pipe_transactions Erreur transaction compteur:{} id:{} plus ancienne que les transactions precedentes",
                        compteur_transactions, transaction.id))?
        }
        date_derniere = date_traitement_u64;

        if let Err(e) = tx.send(transaction).await {
            error!("process_transactions Error sending data: {:?}", e);
            Err(e)?;
        }

        line.clear();  // Reset buffer
    }

    let info_transactions = InfoTransactions {
        date_premiere_transaction: date_premiere,
        date_derniere_transaction: date_derniere,
        nombre_transactions: compteur_transactions,
    };

    debug!("process_transactions Fin thread");

    Ok(info_transactions)
}