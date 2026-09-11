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
    use chrono::Utc;
    use tokio::fs;

    // 1. Create new backup_DATE folder (date is now).
    let now = Utc::now();
    let date_str = now.format("%Y%m%d%H%M%S").to_string();
    let new_backup_dir_name = format!("backup_{}", date_str);
    let new_backup_dir = domain_backup_path.join(new_backup_dir_name);

    if let Err(e) = fs::create_dir_all(&new_backup_dir).await {
        return Err(CommonError::String(format!("Failed to create backup directory {:?}: {:?}", new_backup_dir, e)));
    }

    // 2. Move *.mgbak files from domain_backup_path to new_backup_dir
    let mut entries = fs::read_dir(domain_backup_path)
        .await
        .map_err(|e| CommonError::String(format!("Failed to read directory {:?}: {:?}", domain_backup_path, e)))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "mgbak") {
            let dest = new_backup_dir.join(path.file_name().unwrap());
            if let Err(e) = fs::rename(&path, &dest).await {
                return Err(CommonError::String(format!("Failed to move file {:?} to {:?}: {:?}", path, dest, e)));
            }
        }
    }

    // 3. List backup_DATE folders and keep only the most recent 2
    let mut entries = fs::read_dir(domain_backup_path)
        .await
        .map_err(|e| CommonError::String(format!("Failed to read directory {:?}: {:?}", domain_backup_path, e)))?;
    
    let mut backup_dirs = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() && path.file_name().map_or(false, |name| name.to_string_lossy().starts_with("backup_")) {
            backup_dirs.push(path);
        }
    }

    // Sort by name (which is date-based)
    backup_dirs.sort();

    // Keep the last 3
    const KEEP_LAST_N: usize = 3;
    if backup_dirs.len() > KEEP_LAST_N {
        let to_delete_count = backup_dirs.len() - KEEP_LAST_N;
        for i in 0..to_delete_count {
            if let Err(e) = fs::remove_dir_all(&backup_dirs[i]).await {
                return Err(CommonError::String(format!("Failed to delete old backup directory {:?}: {:?}", backup_dirs[i], e)));
            }
        }
    }

    Ok(())
}
