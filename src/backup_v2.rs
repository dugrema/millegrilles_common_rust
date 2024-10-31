use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use std::fs;
use std::fs::{File, FileType};
use std::io::{ErrorKind, SeekFrom};
use std::ops::Index;
use std::path::{Path, PathBuf};
use fs2::FileExt;
use futures_util::{StreamExt, TryStreamExt};

use chrono::{{SecondsFormat, TimeZone, Utc}, format::strftime::StrftimeItems, Duration, DateTime};
use log::{debug, error, info, warn};
use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult, CleChiffrageHandler, CleChiffrageStruct, CleDechiffrageStruct, Decipher};
use millegrilles_cryptographie::deser_message_buffer;
use millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519, CleSecreteX25519};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, engine::general_purpose::STANDARD as base64, Engine as _};
use async_compression::tokio::bufread::{DeflateEncoder, GzipEncoder, DeflateDecoder};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, Receiver};

use millegrilles_cryptographie::chiffrage::{CleSecrete, FormatChiffrage};
use millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_cryptographie::chiffrage_mgs4::{CipherMgs4, CleSecreteCipher, DecipherMgs4};
use millegrilles_cryptographie::hachages::HacheurBlake2b512;
use millegrilles_cryptographie::maitredescles::{generer_cle_avec_ca, SignatureDomaines};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_cryptographie::messages_structs::MessageKind;
use mongodb::bson::doc;
use mongodb::options::{DeleteOptions, FindOneOptions, FindOptions, Hint};
use multibase::Base;
use multihash::Code;
use reqwest::{Body, Client, Response};
use serde_json::json;
use substring::Substring;
use tokio::fs::read_dir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, Result as TokioResult};
use tokio::join;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{bytes::Bytes, io::{ReaderStream, StreamReader}};
use url::Url;
use x509_parser::nom::AsBytes;
use crate::backup::CommandeBackup;
use crate::mongo_dao::MongoDao;
use crate::certificats::{CollectionCertificatsPem, ValidateurX509};
use crate::chiffrage_cle::{ajouter_cles_domaine, generer_cle_v2, get_cles_rechiffrees_v2, requete_charger_cles};
use crate::common_messages::{FilehostForInstanceRequest, ReponseInformationConsignationFichiers, RequestFilehostForInstanceResponse, RequeteConsignationFichiers, RequeteFilehostItem};
use crate::configuration::ConfigMessages;
use crate::constantes::*;
use crate::constantes::Securite::L3Protege;
use crate::db_structs::TransactionOwned;
use crate::dechiffrage::decrypt_document;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::error::{Error as CommonError, Error};
use crate::hachages::HacheurBuilder;
use crate::messages_generiques::{CommandeSauvegarderCertificat, ReponseCommande};
use crate::recepteur_messages::TypeMessage;

pub const PATH_FICHIERS_ARCHIVES: &str = "/var/opt/millegrilles/archives";

pub const CONST_ARCHIVE_NEW_VERSION: &str = "NEW";

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
    fs::create_dir_all(PATH_FICHIERS_ARCHIVES).unwrap();

    while let Some(commande) = rx.recv().await {
        debug!("thread_backup_v2 Debut commande backup {:?}", commande);

        let backup_complet = commande.complet;

        let path_backup = preparer_path_backup(PATH_FICHIERS_ARCHIVES, commande.nom_domaine.as_str());

        let mut backup_ok= true;

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
                        warn!("thread_backup_v2 Error opening lockfile {:?} - SKIP backup", e);
                        continue;
                    }
                }
            };
            match file.try_lock_exclusive() {
                Ok(()) => (file, path_lockfile),
                Err(_) => {
                    info!("thread_backup_v2 Backup file already locked, SKIP backup");
                    continue;
                }
            }
        };

        // Charger la cle de backup
        let cle_backup_domaine = match recuperer_cle_backup(middleware, commande.nom_domaine.as_str()).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("thread_backup_v2 Erreur chargement de la cle de backup domaine {}, SKIP: {:?}", commande.nom_domaine, e);
                if let Err(e) = lock_file.unlock() {
                    info!("thread_backup_v2 Error unlocking backup file: {:?}", e);
                }
                continue;
            }
        };

        // Charger le serveur de consignation
        let serveur_consignation = match get_serveur_consignation(middleware).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("thread_backup_v2 Erreur chargement de l'information de consignation, SKIP: {:?}", e);
                if let Err(e) = lock_file.unlock() {
                    info!("thread_backup_v2 Error unlocking backup file: {:?}", e);
                }
                continue;
            }
        };

        // L'information de base est OK, repondre (si declenchement manuel)
        let routage_reponse = RoutageMessageReponse::new(&commande.reply_q, &commande.correlation_id);
        if let Err(e) = middleware.repondre(routage_reponse, ReponseCommande { ok: Some(true), err: None, message: None}).await {
            warn!("thread_backup_v2 Erreur emission reponse declenchement de backup: {:?}", e);
        }

        // Evenement intial de backup (done=false)
        emettre_evenement_backup(middleware, commande.nom_domaine.as_str(),
                                 BackupEvent {ok: backup_ok, done: false, err: None}).await;

        // Toujours commencer par un backup incremental pour vider
        // les nouvelles transactions de la base de donnees.
        if let Err(e) = backup_incremental(middleware, &commande, &cle_backup_domaine, path_backup.as_ref()).await {
            error!("thread_backup_v2 Erreur durant backup incremental: {:?}", e);
            backup_ok = false;
            emettre_evenement_backup(middleware, commande.nom_domaine.as_str(),
                                     BackupEvent {ok: backup_ok, done: false, err: Some("Erreur durant un backup incremental".to_string())}).await;
        }

        if backup_complet == true  {
            // Generer un nouveau fichier concatene, potentiellement des nouveaux fichiers finaux.
            if let Err(e) = run_backup_complet(middleware, &commande, &cle_backup_domaine, path_backup.as_ref()).await {
                error!("thread_backup_v2 Erreur durant un backup complet: {:?}", e);
                backup_ok = false;
                emettre_evenement_backup(middleware, commande.nom_domaine.as_str(),
                                         BackupEvent {ok: backup_ok, done: false, err: Some("Erreur durant un backup complet".to_string())}).await;
            }
        } else {
            // Verifier si c'est le premier backup incremental
            match middleware.get_enveloppe_signature().enveloppe_pub.idmg() {
                Ok(idmg) => match trouver_version_backup_local(path_backup.as_ref(), idmg.as_str()).await {
                    Ok((fichiers, version)) => {
                        if fichiers.len() > 0 && version.is_none() {
                            // Au moins 1 fichier et aucune version (pas de fichier Concatene)
                            info!("thread_backup_v2 Declencehement backup complet sur premier backup incremental");
                            if let Err(e) = run_backup_complet(middleware, &commande, &cle_backup_domaine, path_backup.as_ref()).await {
                                error!("thread_backup_v2 Erreur durant le premier backup complet: {:?}", e);
                            }
                        }
                    },
                    Err(e) => {
                        error!("thread_backup_v2 Erreur durant verification version locale: {:?}", e);
                    }
                },
                Err(e) => {
                    error!("thread_backup_v2 Erreur chargement idmg: {:?}", e);
                }
            }
        }

        // Synchroniser les archives avec le serveur de consignation
        if let Err(e) = synchroniser_consignation(middleware, &commande, path_backup.as_path(), serveur_consignation.as_str()).await {
            error!("thread_backup_v2 Erreur durant upload des fichiers de backup: {:?}", e);
            backup_ok = false;
            emettre_evenement_backup(middleware, commande.nom_domaine.as_str(),
                                     BackupEvent {ok: backup_ok, done: false, err: Some("Erreur durant upload des fichiers de backup".to_string())}).await;
        }

        // Retirer le lock de backup
        if let Err(e) = lock_file.unlock() {
            info!("thread_backup_v2 Error unlocking backup file: {:?}", e);
        }
        if let Err(e) = fs::remove_file(path_lock_file) {
            info!("thread_backup_v2 Error deleting lock file: {:?}", e);
        };

        // Evenement final de backup (done=true)
        emettre_evenement_backup(middleware, commande.nom_domaine.as_str(),
                                 BackupEvent {ok: backup_ok, done: true, err: None}).await;
    }
}

fn preparer_path_backup(path_backup: &str, domaine: &str) -> PathBuf {
    let path_domaine = PathBuf::from(format!("{}/{}", path_backup, domaine));
    fs::create_dir_all(&path_domaine).unwrap();
    path_domaine
}

async fn get_serveur_consignation<M>(middleware: &M) -> Result<String, CommonError>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, REQUETE_GET_FILEHOST_FOR_INSTANCE, vec![Securite::L1Public]).build();
    let requete = FilehostForInstanceRequest {instance_id: None, filehost_id: None};
    let reponse: RequestFilehostForInstanceResponse = match middleware.transmettre_requete(routage, &requete).await? {
        Some(TypeMessage::Valide(reponse)) => deser_message_buffer!(reponse.message),
        _ => Err("backup_v2.get_serveur_consignation Reponse information consignation de type invalide")?
    };

    if ! reponse.ok {
        Err("backup_v2.get_serveur_consignation Reponse information consignation est en erreur (ok==false)")?
    }

    let filehost = reponse.filehost;

    let url = match filehost.url_external {
        Some(inner) => inner,
        None => match filehost.url_internal {
            Some(inner) => inner,
            None => Err("backup_v2.get_serveur_consignation No filehost server availabled")?
        }
    };

    Ok(url)
}

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
/// S'assure que tous les certificats sont sauvegardés dans CorePki.
async fn backup_incremental<M>(middleware: &M, commande: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine, path_backup: &Path)
    -> Result<(), CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    let domaine_backup = commande.nom_domaine.as_str();
    info!("Debut backup incremental sur {}", domaine_backup);

    // Verifier si on a au moins une transaction à mettre dans le backup
    let nom_collection = commande.nom_collection_transactions.as_str();
    let collection = middleware.get_collection_typed::<TransactionOwned>(nom_collection)?;
    let filtre = doc! { TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true}, TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true };
    let find_options = FindOneOptions::builder()
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let idmg = middleware.get_enveloppe_signature().enveloppe_pub.idmg()?;

    if collection.find_one(filtre, find_options).await?.is_some() {
        debug!("backup_incremental Au moins une transaction a ajouter au backup incremental de {}", domaine_backup);
        traiter_transactions_incremental(
            middleware, path_backup, commande,
            cle_backup_domaine, domaine_backup, idmg.as_str()).await?;
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
        TypeArchive::Concatene => ("C", "concatene"),
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

    let date_derniere_transaction = Utc.timestamp_millis_opt(info_transactions.date_derniere_transaction as i64).unwrap();

    // Supprimer les transactions traitees. On utilise la date de la plus recente transaction archivee
    // pour s'assurer de ne pas effacer de nouvelles transactions non traitees.
    let collection = middleware.get_collection(commande_backup.nom_collection_transactions.as_str())?;
    let filtre = doc! {
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$lte": date_derniere_transaction},
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
    };
    let options = DeleteOptions::builder().hint(Hint::Name(String::from("backup_transactions"))).build();
    collection.delete_many(filtre, options).await?;

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
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true},
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

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
async fn run_backup_complet<M>(middleware: &M, commande: &CommandeBackup, cle_backup_domaine: &CleBackupDomaine, path_backup: &Path)
    -> Result<(), CommonError>
    where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    info!("Debut backup complet sur {}", commande.nom_domaine);

    let domaine = commande.nom_domaine.as_str();
    let idmg = middleware.idmg();
    let fichiers = organiser_fichiers_backup(path_backup, idmg, false).await?;

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

    // Deplacer vieilles archives concatenee et incrementales a /backup.1
    rotation_repertoires_backup(path_backup, &fichiers).await?;

    // Renommer nouvelle archive concatenee
    rename_work_file(&TypeArchive::Concatene, &info_transactions, domaine, path_backup, path_archive.as_ref()).await?;

    // Supprimer vieilles archives obsoletes (.old)
    // for file in &fichiers {
    //     let mut new_name = file.path_fichier.clone();
    //     new_name.set_extension(".mgbak.old");
    //     tokio::fs::remove_file(new_name).await?;
    // }

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
    pub digest_suffix: String,
    pub len: u64,
}

/// Fait la liste des fichiers de backup sur disque, lit le header et les trie.
pub async fn organiser_fichiers_backup(backup_path: &Path, idmg: &str, inclure_final: bool) -> Result<Vec<FichierArchiveBackup>, CommonError> {
    let mut paths = read_dir(backup_path).await?;

    let mgback_ext: OsString = "mgbak".into();

    debug!("organiser_fichiers_backup Parcourir {:?} pour fichiers d'archive .mgbak", backup_path);

    let mut fichiers = Vec::new();
    loop {
        let (file_path, file_len) = match paths.next_entry().await? {
            Some(inner) => {
                if inner.file_type().await?.is_file() {
                    let meta = inner.metadata().await?;
                    let file_len = meta.len();
                    let file_path = inner.path();
                    if file_path.extension() != Some(mgback_ext.as_os_str()) {
                        continue;  // Wrong extension
                    }
                    (file_path, file_len)
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
        if header.idmg.as_str() != idmg {
            warn!("Fichier avec mauvais IDMG (systeme) dans le repertoire : {:?} => {}, **SKIP**", file_path, header.idmg);
            continue;
        }

        // Extrait le digest partiel du nom du fichier
        let nom_fichier = file_path.file_stem().expect("file stem").to_str().expect("nom_fichier to_str");
        let mut split: Vec<&str> = nom_fichier.split("_").collect();
        let digest_suffix = split.pop().expect("version").to_string();

        // Verification d'integrite entre les fichiers. On s'assure que le fichier courant
        // n'as pas de transactions plus anciennes que la derniere transaction du fichier precedent.

        let position_data = (4 + taille_header) as usize;  // 4 bytes (version u16, taille header u16) + header
        if inclure_final || header.format != "F".to_string() {
            fichiers.push(FichierArchiveBackup { path_fichier: file_path, header, position_data, digest_suffix, len: file_len });
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

    info!("charger_cles_backup Charger {} cles de backup", nombre_cles_a_charger);

    // Recuperer cles a partir du maitre des cles
    let mut cles = HashMap::new();
    if nombre_cles_a_charger > 0 {
        let reponse_cles = get_cles_rechiffrees_v2(
            middleware, domaine, vec_cle_ids, Some(false)).await?;
        // if reponse_cles.len() != 1 {
        //     Err(format!("backup_v2.recuperer_cle_backup Mauvais nombre de cles recus: {:?}", reponse_cles.len()))?;
        // }
        for cle in reponse_cles {
            let cle_id = match cle.cle_id {
                Some(inner) => inner,
                None => Err("backup_v2.charger_cles_backup Reponse cle sans cle_id")?
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

#[derive(Debug, Deserialize)]
struct ListeClesBackupBase64 {
    cles: HashMap<String, String>
}

pub async fn charger_cles_backup_message<M>(middleware: &M, doc_cles: EncryptedDocument)
    -> Result<HashMap<String, CleSecrete<32>>, CommonError>
    where M: GenerateurMessages
{
   let cles_string: ListeClesBackupBase64 = decrypt_document(middleware, doc_cles)?;

    let mut cles_dechiffrees = HashMap::new();
    for (cle_id, cle_secrete_base64) in cles_string.cles {
        let mut cle_secrete = CleSecrete([0u8; 32]);
        cle_secrete.0.copy_from_slice(&base64_nopad.decode(cle_secrete_base64)?);
        cles_dechiffrees.insert(cle_id, cle_secrete);
    }

    Ok(cles_dechiffrees)
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

async fn rotation_repertoires_backup(path_archives: &Path, fichiers: &Vec<FichierArchiveBackup>)
    -> Result<(), CommonError>
{
    if fichiers.len() == 0 {
        // Aucuns fichiers a conserver dans un nouveau repertoire de backup
        return Ok(());
    }

    // Rotation des anciens repertoires de backup au besoin
    let mut path_first_old = path_archives.to_path_buf();
    path_first_old.push("backup.1");

    if tokio::fs::try_exists(&path_first_old).await? {
        // Rotate all backup folders up 1.
        const MAX_BACKUP_HISTORY: i8 = 4;
        for i in (1..MAX_BACKUP_HISTORY+1).rev() {
            let mut path_old = path_archives.to_path_buf();
            path_old.push(format!("backup.{}", i));
            if tokio::fs::try_exists(&path_old).await? {
                if i == MAX_BACKUP_HISTORY {
                    // Remove, this is the last possible folder
                    tokio::fs::remove_dir_all(path_old).await?;
                } else {
                    let mut path_moved = path_archives.to_path_buf();
                    path_moved.push(format!("backup.{}", i + 1));
                    tokio::fs::rename(path_old, path_moved).await?;
                }
            }
        }
    }

    // Transferer les fichiers vers le repertoire backup.1
    tokio::fs::create_dir(&path_first_old).await?;
    for file in fichiers {
        let filename = file.path_fichier.file_name().expect("filename");

        // Sous-repertoire /backup.1/nomfichier
        let mut new_name = path_first_old.clone();
        new_name.push(filename);

        tokio::fs::rename(&file.path_fichier, new_name).await?;
    }

    Ok(())
}

/// Upload le fichier de backup vers la consignation.
async fn synchroniser_consignation<M>(
    middleware: &M, commande_backup: &CommandeBackup, path_backup: &Path, serveur_consignation: &str
)
    -> Result<(), CommonError>
    where M: GenerateurMessages
{
    let domaine = commande_backup.nom_domaine.as_str();

    let (client, url_consignation) = preparer_client_consignation(middleware, serveur_consignation).await?;

    info!("synchroniser_consignation Utilisation url_consignation {}", url_consignation);

    // Determiner version de backup
    let enveloppe = middleware.get_enveloppe_signature();;
    let idmg = enveloppe.enveloppe_pub.idmg()?;
    let (fichiers_locaux, version) = trouver_version_backup(
        idmg.as_str(), domaine, path_backup, &client, &url_consignation).await?;

    let version_effective = match version.as_ref() {
        Some(version) => version.as_str(),
        // None => CONST_ARCHIVE_NEW_VERSION
        None => {
            if fichiers_locaux.len() == 0 {
                info!("synchroniser_consignation Aucunes transactions locales dans le domaine {} et aucune version dans consignation, SKIP sync", domaine);
                return Ok(());
            } else {
                Err(format!("backup_v2.synchroniser_consignation Aucune version pour le backup domaine {}", domaine))?
            }
        }
    };

    // Downloader les listes de fichier (fichiers finaux et version courante)
    let listes = download_liste_fichiers_backup(domaine, version_effective, &fichiers_locaux, &client, &url_consignation).await?;
    debug!("Listes de synchronisation: {:?}", listes);

    // Uploader les fichiers manquants du serveur de consignation, en ordre : Final, Concatene, Incremental
    uploader_fichiers_consignation(domaine, version_effective, &listes, &client, &url_consignation).await?;

    // Downloader les fichiers manquants localement
    let mut nouveaux_fichiers_downloades = false;
    if ! listes.download_final.is_empty() {
        nouveaux_fichiers_downloades = true;
        download_backup_files(path_backup, &listes.download_final, domaine, version_effective, &client, &url_consignation).await?;
    }

    if ! listes.download_archives.is_empty() {
        nouveaux_fichiers_downloades = true;
        debug!("Download {} archives manquantes", listes.download_archives.len());
        download_backup_files(path_backup, &listes.download_archives, domaine, version_effective, &client, &url_consignation).await?;
    }

    if nouveaux_fichiers_downloades {
        // TODO : Declencher regeneration
        warn!("De nouveaux fichiers d'archives on ete downloades a partir du serveur de consignation.");
    }

    Ok(())
}

async fn preparer_client_consignation<M>(middleware: &M, serveur_consignation: &str)
    -> Result<(reqwest::Client, Url), CommonError>
    where M: GenerateurMessages
{
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let cert_ca = enveloppe_privee.enveloppe_ca.chaine_pem()?;
    let ca_cert_pem = match cert_ca.last() {
        Some(cert) => cert.as_str(),
        None => Err(format!("Certificat CA manquant"))?
    };
    let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())?;

    let cle_privee_pem = enveloppe_privee.cle_privee_pem.as_str();
    let mut cert_pem_list = enveloppe_privee.chaine_pem.clone();
    cert_pem_list.insert(0, cle_privee_pem.to_string());
    let pem_keycert = cert_pem_list.join("\n");

    // let identity = reqwest::Identity::from_pem(pem_keycert.as_bytes())?;

    let cert = pem_keycert.as_bytes();
    let key = cle_privee_pem.as_bytes();
    let pkcs8 = reqwest::Identity::from_pkcs8_pem(&cert, &key)?;

    let client = reqwest::Client::builder()
        .add_root_certificate(root_ca)
        //.identity(identity)
        .identity(pkcs8)
        .https_only(true)
        .use_native_tls()
        // .use_rustls_tls()
        .connect_timeout(core::time::Duration::new(20, 0))
        .http2_adaptive_window(true)
        .cookie_store(true)
        .build()?;

    // Authenticate
    let filehost_url = url::Url::parse(serveur_consignation)?;
    let authentication_url = filehost_url.join("/filehost/authenticate")?;
    debug!("Authentication url: {:?}", authentication_url.as_str());
    let routage = RoutageMessageAction::builder("filehost", "authenticate", vec!{})
        .ajouter_ca(true)
        .build();
    let nomessage = json!({"auth": true});
    let authentication_message = middleware.build_message_action(MessageKind::Commande, routage, nomessage)?.0;
    let result = client.post(authentication_url).body(authentication_message.buffer).send().await?.error_for_status()?;
    info!("Result: {:?}", result);

    Ok((client, filehost_url))
}

#[derive(Debug, Deserialize)]
struct VersionBackup {
    date: u64,
    version: String,
}

#[derive(Debug, Deserialize)]
struct ReponseVersionsBackup {
    version_courante: Option<VersionBackup>,
    versions: Option<Vec<VersionBackup>>,
}

async fn trouver_version_backup_local(path_backup: &Path, idmg: &str) -> Result<(Vec<FichierArchiveBackup>, Option<String>), CommonError>{
    let fichiers = organiser_fichiers_backup(path_backup, idmg, false).await?;
    let mut version_courante_locale = None;
    for f in &fichiers {
        if f.header.type_archive.as_str() == "C" {
            if version_courante_locale.is_some() {
                Err("backup_v2.trouver_version_backup Plus d'un fichier concatene present")?
            } else {
                version_courante_locale = Some(f.digest_suffix.clone());
            }
        }
    }
    Ok((fichiers, version_courante_locale))
}

async fn trouver_version_backup(idmg: &str, domaine: &str, path_backup: &Path, client: &reqwest::Client, url_consignation: &Url)
    -> Result<(Vec<FichierArchiveBackup>, Option<String>), CommonError>
{
    // Recuperer les fichiers presents localement
    let (fichiers, version_courante_locale) = trouver_version_backup_local(path_backup, idmg).await?;
    debug!("Version courante du backup: {:?}", version_courante_locale);

    // Interroger le serveur de consignation
    let mut version_remote: Option<String> = None;
    // let resultat = client.get(format!("{}/fichiers_transfert/backup_v2/{}/archives", url_consignation, domaine)).send().await?;
    let url_archives = url_consignation.join(format!("filehost/backup_v2/{}/archives", domaine).as_str())?;
    // let resultat = client.get(format!("{}/filehost/backup_v2/{}/archives", url_consignation, domaine)).send().await?;
    let resultat = client.get(url_archives).send().await?.error_for_status()?;
    debug!("trouver_version_backup Resultat get https: {:?}", resultat);
    let versions: ReponseVersionsBackup = resultat.json().await?;
    debug!("Versions backup recu: {:?}", versions);
    if let Some(version) = versions.version_courante.as_ref() {
        version_remote = Some(version.version.clone());
    }

    let version = match version_courante_locale {
        // Privilegier la version locale. Permet d'uploader une nouvelle archive concatene lorsque presente
        Some(version_locale) => Some(version_locale),
        None => match version_remote {
            // Lorsqu'on n'a pas de version locale, utiliser la version remote si presente.
            Some(version_remote) => Some(version_remote),
            // Nouveau domaine, aucuns fichier concatene present
            None => None
        }
    };

    Ok((fichiers, version))
}

#[derive(Debug)]
struct InformationSynchronisation<'a> {
    upload_final: Vec<&'a FichierArchiveBackup>,
    download_final: Vec<String>,
    upload_archives: Vec<&'a FichierArchiveBackup>,
    download_archives: Vec<String>,
}

async fn download_liste_fichiers_backup<'a>(
    domaine: &str, version: &str, fichiers: &'a Vec<FichierArchiveBackup>, client: &reqwest::Client, url_consignation: &Url
)
    -> Result<InformationSynchronisation<'a>, CommonError>
{
    let mut info_sync = InformationSynchronisation {
        upload_final: vec![],
        download_final: vec![],
        upload_archives: vec![],
        download_archives: vec![],
    };

    let mut set_final_local = HashMap::new();
    let mut set_archives_local = HashMap::new();
    for f in fichiers {
        let file_name = f.path_fichier.file_name().expect("f.path_fichier file name")
            .to_str().expect("f.path_fichier to str");
        if f.header.type_archive.as_str() == "F" {
            set_final_local.insert(file_name, f);
        } else {
            set_archives_local.insert(file_name, f);
        }
    }

    // let resultat_fichiers_finaux = client.get(
    //     // format!("{}/fichiers_transfert/backup_v2/{}/final", url_consignation, domaine)).send().await?;
    //     format!("{}/filehost/backup_v2/{}/final", url_consignation, domaine)).send().await?;
    // debug!("Resultat fichiers finaux: {:?}", resultat_fichiers_finaux);
    // if resultat_fichiers_finaux.status() != 200 {
    //     Err(format!("backup_v2.download_liste_fichiers_backup Erreur reponse serveur sur GET final, status: {}", resultat_fichiers_finaux.status()))?
    // }

    // Retirer fichiers connus partout de set_final_local. Recuperer liste de fichiers manquants localement a downloader.
    //info_sync.download_final = parse_stream_liste_fichiers(&mut set_final_local, resultat_fichiers_finaux).await?;
    // Les fichiers restants dans le set doivent etre uploades.
    info_sync.upload_final.extend(set_final_local.into_iter().map(|(_,v)| v));

    let url_archives = url_consignation.join(format!("filehost/backup_v2/{}/archives/{}", domaine, version).as_str())?;
    // format!("{}/fichiers_transfert/backup_v2/{}/archives/{}", url_consignation, domaine, version)).send().await?;
    let resultat_fichiers_archives = client.get(url_archives).send().await?;
    if resultat_fichiers_archives.status() == 200 {
        debug!("Resultat fichiers archives: {:?}", resultat_fichiers_archives);

        // Retirer fichiers connus partout de set_final_local. Recuperer liste de fichiers manquants localement a downloader.
        info_sync.download_archives = parse_stream_liste_fichiers(&mut set_archives_local, resultat_fichiers_archives).await?;
    } else if(resultat_fichiers_archives.status() == 404) {
        // Ok, fichiers ne sont pas uploades pour cette version
    } else {
        resultat_fichiers_archives.error_for_status()?;  // Raise error
    }

    // Les fichiers restants dans le set doivent etre uploades.
    info_sync.upload_archives.extend(set_archives_local.into_iter().map(|(_,v)| v));

    Ok(info_sync)
}

fn convert_reader_err(err: reqwest::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("parse_stream_liste_fichiers Error {:?}", err))
}

async fn parse_stream_liste_fichiers(fichiers_locaux: &mut HashMap<&str, &FichierArchiveBackup>, response: Response)
    -> Result<Vec<String>, CommonError>
{
    let byte_stream = response.bytes_stream();
    let mut reader_response = StreamReader::new(byte_stream.map_err(convert_reader_err));

    debug!("Fichiers locaux: {:?}", fichiers_locaux.keys());

    // Liste de fichiers manquants du set de fichiers locaux
    let mut fichiers_manquants = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let output_len = reader_response.read_line(&mut line).await?;
        if output_len == 0 { break; }
        let nom_fichier = &line[..output_len].trim();
        debug!("parse_stream_liste_fichiers Fichier: *{}*", nom_fichier);
        let removed = fichiers_locaux.remove(*nom_fichier);
        if removed.is_none() {
            // Fichier manquant localement
            debug!("Fichier manquant localement trouve: {}", nom_fichier);
            fichiers_manquants.push(nom_fichier.to_string());
        }
    }

    Ok(fichiers_manquants)
}

async fn uploader_fichiers_consignation<'a>(
    domaine: &str, version: &str, information_sync: &InformationSynchronisation<'a>, client: &reqwest::Client, url_consignation: &Url
)
    -> Result<(), CommonError>
{
    // for fichier in &information_sync.upload_final {
    //     if fichier.header.type_archive.as_str() == "F" {
    //         debug!("uploader_fichiers_consignation Uploader fichier final {:?}", fichier.path_fichier.file_name());
    //         put_backup_file(domaine, version, client, url_consignation, *fichier).await?;
    //     } else {
    //         Err(format!("Fichier {:?} mis dans la liste des fichiers finaux, le header corrompu", fichier.path_fichier))?
    //     }
    // }

    // Verifier si on doit uploader un fichier concatene. Ceci change la version sur la consignation.
    let mut fichier_concatene: Option<&FichierArchiveBackup> = None;
    for f in &information_sync.upload_archives {
        if f.header.type_archive.as_str() == "C" {
            if f.digest_suffix.as_str() != version {
                Err("backup_v2.uploader_fichiers_consignation Fichier concatene : mismatch de version")?
            }
            if fichier_concatene.is_some() {
                Err("backup_v2.uploader_fichiers_consignation Plusieurs fichiers concatene a uploader")?
            }
            fichier_concatene = Some(f);
        }
    }

    if let Some(fichier) = fichier_concatene {
        debug!("uploader_fichiers_consignation Uploader le fichier concatene {:?}", fichier.path_fichier.file_name());
        put_backup_file(domaine, version, client, url_consignation, fichier).await?;
    }

    for fichier in &information_sync.upload_archives {
        if fichier.header.type_archive.as_str() == "I" {
            debug!("uploader_fichiers_consignation Uploader fichier incremental {:?}", fichier.path_fichier.file_name());
            put_backup_file(domaine, version, client, url_consignation, *fichier).await?;
        }
    }

    Ok(())
}

async fn put_backup_file(domaine: &str, version: &str, client: &Client, url_consignation: &Url, fichier: &FichierArchiveBackup)
    -> Result<(), Error>
{
    // Verifier l'integrite du fichier avant l'upload
    let digest = digest_file(fichier.path_fichier.as_path()).await?;
    if !digest.ends_with(fichier.digest_suffix.as_str()) {
        Err(format!("backup_v2.put_backup_file Fichier corrompu, digest mismatch sur {:?}", fichier.path_fichier))?
    }

    let nom_fichier = fichier.path_fichier.file_name().expect("file name").to_str().expect("file name to_str");

    let url_upload = match fichier.header.type_archive.as_str() {
        "C" => {
            // format!("{}/fichiers_transfert/backup_v2/{}/concatene/{}/{}", url_consignation, domaine, version, nom_fichier)
            // format!("{}/filehost/backup_v2/{}/concatene/{}/{}", url_consignation, domaine, version, nom_fichier)
            url_consignation.join(format!("filehost/backup_v2/{}/concatene/{}/{}", domaine, version, nom_fichier).as_str())?
        },
        "I" => {
            // format!("{}/fichiers_transfert/backup_v2/{}/incremental/{}/{}", url_consignation, domaine, version, nom_fichier)
            // format!("{}/filehost/backup_v2/{}/incremental/{}/{}", url_consignation, domaine, version, nom_fichier)
            url_consignation.join(format!("filehost/backup_v2/{}/incremental/{}/{}", domaine, version, nom_fichier).as_str())?
        },
        "F" => {
            // format!("{}/fichiers_transfert/backup_v2/{}/final/{}", url_consignation, domaine, nom_fichier)
            // format!("{}/filehost/backup_v2/{}/final/{}", url_consignation, domaine, nom_fichier)
            url_consignation.join(format!("filehost/backup_v2/{}/final/{}", domaine, nom_fichier).as_str())?
        },
        _ => Err(format!("backup_v2.put_backup_file Mauvais type d'archive, doit etre C, I ou F : {}", fichier.header.type_archive))?
    };

    let file_reader = tokio::io::BufReader::new(tokio::fs::File::open(fichier.path_fichier.as_path()).await?);
    let file_stream = ReaderStream::new(file_reader);
    debug!("PUT file at {}", url_upload.as_str());
    let resultat_upload = client.put(url_upload)
        .body(Body::wrap_stream(file_stream))
        .header("Content-Length", fichier.len)
        .send().await?;

    if resultat_upload.status() != 200 {
        Err(format!("backup_v2.put_backup_file Erreur upload fichier {:?}, status : {}", fichier.path_fichier, resultat_upload.status()))?
    }

    Ok(())
}

async fn download_backup_files(path_backup: &Path, liste: &Vec<String>, domaine: &str, version: &str, client: &Client, url_consignation: &Url)
    -> Result<(), CommonError>
{

    for nom_fichier in liste {
        let mut split: Vec<&str> = nom_fichier.split("_").collect();
        let file_end = split.pop().expect("version").to_string();
        let digest_suffix = file_end.split(".").next().expect("split suffix");

        let mut path_backup_file = path_backup.to_owned();
        path_backup_file.push(nom_fichier);
        let mut path_work_file = path_backup.to_owned();
        path_work_file.push(format!("{}.work", nom_fichier));

        let url_download = match nom_fichier.contains("_F_") {
            true => {
                // format!("{}/fichiers_transfert/backup_v2/{}/final/{}", url_consignation, domaine, nom_fichier)
                // format!("{}/filehost/backup_v2/{}/final/{}", url_consignation, domaine, nom_fichier)
                url_consignation.join(format!("filehost/backup_v2/{}/final/{}", domaine, nom_fichier).as_str())?
            },
            false => {
                // format!("{}/fichiers_transfert/backup_v2/{}/archives/{}/{}", url_consignation, domaine, version, nom_fichier)
                // format!("{}/filehost/backup_v2/{}/archives/{}/{}", url_consignation, domaine, version, nom_fichier)
                url_consignation.join(format!("filehost/backup_v2/{}/archives/{}/{}", domaine, version, nom_fichier).as_str())?
            }
        };

        let response = client.get(url_download).send().await?.error_for_status()?;

        let mut backup_work_file = tokio::io::BufWriter::new(tokio::fs::File::create(path_work_file.as_path()).await?);

        let byte_stream = response.bytes_stream();
        let mut reader_response = StreamReader::new(byte_stream.map_err(convert_reader_err));

        let mut digester = HacheurBuilder::new().digester(Code::Blake2b512).base(Base::Base58Btc).build();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let output_len = reader_response.read(&mut buffer).await?;
            if output_len == 0 { break; }
            backup_work_file.write_all(buffer[0..output_len].as_ref()).await?;
            digester.update(buffer[0..output_len].as_ref());
        }
        backup_work_file.shutdown().await?;

        let digest = digester.finalize();
        debug!("Digest {} (suffix: {}) pour fichier {}", digest, digest_suffix, nom_fichier);
        if ! digest.as_str().ends_with(digest_suffix) {
            // Supprimer fichier (invalide)
            tokio::fs::remove_file(path_work_file.as_path()).await?;
            Err("backup_v2.download_backup_files Erreur download fichier, digest mismatch")?
        }

        // Rename work file
        tokio::fs::rename(path_work_file.as_path(), path_backup_file.as_path()).await?;
    }

    Ok(())
}

#[derive(Serialize)]
pub struct StatsBackup {
    pub nombre_transactions: u64,
    pub nombre_fichiers: u64,
    pub date_premiere_transaction: Option<u64>,
    pub date_derniere_transaction: Option<u64>,
}

pub struct StatusRegeneration {
    pub nombre_transaction_traites: u64,
    pub done: bool,
}

pub async fn extraire_stats_backup<M>(middleware: &M, collection_transaction: &str, fichiers: &Vec<FichierArchiveBackup>)
    -> Result<StatsBackup, CommonError>
    where M: MongoDao
{

    let filtre = doc!{};
    let collection = middleware.get_collection(collection_transaction)?;
    let transactions_non_traitees = collection.count_documents(filtre, None).await?;

    let mut stats = StatsBackup {
        nombre_transactions: transactions_non_traitees,
        nombre_fichiers: 0,
        date_premiere_transaction: None,
        date_derniere_transaction: None,
    };
    for fichier in fichiers {
        let header = &fichier.header;
        if stats.date_premiere_transaction.is_none() {
            stats.date_premiere_transaction = Some(header.debut_backup);
        }
        stats.date_derniere_transaction = Some(header.fin_backup);
        stats.nombre_fichiers += 1;
        stats.nombre_transactions += header.nombre_transactions;
    }

    Ok(stats)
}

#[derive(Serialize)]
struct BackupEvent {
    ok: bool,  // Si false, indique echec dans le backup
    done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,
}

pub async fn emettre_evenement_backup<M>(middleware: &M, domaine: &str, event: BackupEvent)
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        domaine, BACKUP_EVENEMENT_MAJ, vec![L3Protege]).build();
    if let Err(e) = middleware.emettre_evenement(routage, &event).await {
        error!("emettre_evenement_backup Erreur emission evenement backup: {:?}", e);
    }
}

// pub async fn emettre_evenement_backup<M>(
//     middleware: &M, info_backup: &BackupInformation, evenement: &str, timestamp: &DateTime<Utc>)
//     -> Result<(), crate::error::Error>
//     where M: GenerateurMessages
// {
//     let value = json!({
//         "uuid_rapport": info_backup.uuid_backup.as_str(),
//         "evenement": evenement,
//         "domaine": info_backup.domaine.as_str(),
//         "timestamp": timestamp.timestamp(),
//     });
//
//     let routage = RoutageMessageAction::builder(info_backup.domaine.as_str(), BACKUP_EVENEMENT_MAJ, vec![L2Prive])
//         .build();
//
//     Ok(middleware.emettre_evenement(routage, &value).await?)
// }