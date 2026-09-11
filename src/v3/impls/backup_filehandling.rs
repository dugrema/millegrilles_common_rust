use crate::error::Error as CommonError;
use crate::v3::models::{BackupResult, LockFile};
use fs2::FileExt;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use chrono::format::StrftimeItems;
use chrono::{TimeZone, Utc};
use tracing::{debug, info};
use crate::backup_v2::{FichierArchiveBackup, TypeArchive};
use crate::v3::ChiffrageService;

/// Use to create a lockfile with exclusive access - prevents multiple simultaneous backup processes.
/// Raises errors when lock is unsuccessful.
pub async fn create_lockfile(backup_path: &PathBuf, wait: bool) -> Result<LockFile, CommonError> {
    let mut path_lockfile = backup_path.clone();
    path_lockfile.push("backup.lock");
    let file = match File::open(&path_lockfile) {
        Ok(inner) => inner,
        Err(e) => {
            if ErrorKind::NotFound == e.kind() {
                match File::create(&path_lockfile) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(CommonError::String(format!("Error creating lockfile {:?} - SKIP backup", e)));
                    }
                }
            } else {
                return Err(CommonError::String(format!("Error opening lockfile {:?} - SKIP backup", e)));
            }
        }
    };

    let mut retries = 0;
    loop {
        match file.try_lock_exclusive() {
            Ok(_) => break,
            Err(_e) => {
                retries += 1;
                if retries > 20 {
                    return Err(CommonError::Str("Lockfile not being released, SKIPPING backup"));
                }
                if wait {
                    info!("Backup lockfile present, waiting ...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                } else {
                    return Err(CommonError::Str("Backup lockfile already present, SKIP backup"));
                }
            }
        }
    }

    Ok(LockFile { file, path: path_lockfile })
}

pub fn unlock_lockfile(file: LockFile) {
    if let Err(e) = file.file.unlock() {
        info!("unlock_lockfile Error unlocking lock file: {:?}", e);
    }
    if let Err(e) = fs::remove_file(file.path) {
        info!("unlock_lockfile Error deleting lock file: {:?}", e);
    };
}

/// Rewrites the backup file header to be Concatene
pub async fn promote_incremental_to_concatene(file: &FichierArchiveBackup) -> Result<FichierArchiveBackup, CommonError> {

    todo!()
}

pub async fn promote_concatene_to_final() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

pub async fn prepare_incremental_backup_file(domain_backup_path: &Path) -> Result<PathBuf, CommonError> {
    let prefix = "incremental";
    let file_path = domain_backup_path.join(format!("{}.mgbak.work", prefix));
    // Remove any old workfile
    if let Err(e) = tokio::fs::remove_file(&file_path).await {
        debug!("prepare_incremental_backup_file Delete file result: {:?}", e);
    }
    Ok(file_path)
}

pub async fn rename_backup_file(
    chiffrage: &dyn ChiffrageService,
    archive_type: &TypeArchive,
    backup_result: &BackupResult,
    domain: &str,
    backup_path: &Path,
    workfile_path: &Path
) -> Result<(PathBuf, String, u64), CommonError> {
    // Rename work file
    let date_premiere_transaction = Utc.timestamp_millis_opt(backup_result.first_transaction as i64).unwrap();
    let date_str = date_premiere_transaction.format_with_items(StrftimeItems::new("%Y%m%d%H%M%S%3fZ"));

    // Calculer le digest du fichier (apres modification du header).
    let digest_str = chiffrage.digest_file(backup_path, multihash::Code::Blake2b512, multibase::Base::Base58Btc).await?;

    let archive_type_marker = match archive_type {
        TypeArchive::Incremental => "I",
        TypeArchive::Concatene => "C",
        TypeArchive::Final => "F",
    };

    // Keep last 12 chars of digest
    let digest_suffix = digest_str[digest_str.len()-12..digest_str.len()].to_string();

    // File name example : AiLanguage_2024-09-24T21:43:07.162Z_I_KozFJz4vLFe7.mgbak
    let backup_file_name = format!(
        "{}_{}_{}_{}.mgbak",
        domain,
        date_str,
        archive_type_marker,
        &digest_suffix
    );

    debug!("rename_work_file Date {}, digest {}, filename: {}", date_str, digest_str, backup_file_name);
    let mut backup_file_path = backup_path.to_owned();
    backup_file_path.push(backup_file_name);

    let metadata = workfile_path.metadata()?;
    let filesize = metadata.len();

    // Last operation - rename. If this success
    fs::rename(workfile_path, &backup_file_path)?;

    Ok((backup_file_path, digest_suffix, filesize))
}

pub async fn rotate_backup_files(domain_backup_path: &Path) -> Result<(), CommonError> {
    
    // List backup_DATE folders in order, keep the last 2 only
    
    // Create new backup_NOW folder, move *.mgbak files to that folder
    
    todo!()
}
