use crate::backup_v2::{FichierArchiveBackup, HeaderFichierArchive, TypeArchive};
use crate::error::Error as CommonError;
use crate::v3::ChiffrageService;
use crate::v3::models::{BackupResult, LockFile};
use chrono::format::StrftimeItems;
use chrono::{TimeZone, Utc};
use fs2::FileExt;
use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::sleep;
use tokio_util::io::simplex::new;
use tracing::{debug, info};

/// Use to create a lockfile with exclusive access - prevents multiple simultaneous backup processes.
/// Raises errors when lock is unsuccessful.
pub async fn create_lockfile(backup_path: &PathBuf, wait: bool) -> Result<LockFile, CommonError> {
    use std::fs::File;

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
                    sleep(tokio::time::Duration::from_secs(15)).await;
                } else {
                    return Err(CommonError::Str("Backup lockfile already present, SKIP backup"));
                }
            }
        }
    }

    Ok(LockFile { file, path: path_lockfile })
}

pub async fn unlock_lockfile(file: LockFile) {
    if let Err(e) = file.file.unlock() {
        info!("unlock_lockfile Error unlocking lock file: {:?}", e);
    }
    if let Err(e) = fs::remove_file(file.path).await {
        info!("unlock_lockfile Error deleting lock file: {:?}", e);
    };
}

/// Rewrites the backup file header to be a new type, recalculates digest and renames file.
pub async fn promote_backup_file(
    chiffrage: &dyn ChiffrageService,
    file_info: &FichierArchiveBackup,
    archive_type: TypeArchive,
) -> Result<FichierArchiveBackup, CommonError> {
    // Update type to Concatene
    let mut header = file_info.header.clone();
    header.type_archive = (&archive_type).into();

    // Extract date information from header
    let first_transaction = match Utc.timestamp_opt(header.debut_backup as i64, 0).single() {
        Some(timestamp) => timestamp,
        None => return Err(CommonError::Str("Unable to get time of first transaction from seconds"))
    };

    let parent_folder = match file_info.path_fichier.parent() {
        Some(parent) => parent,
        None => return Err(CommonError::Str("Unable to find parent folder for file"))
    };

    // Write header back
    overwrite_backup_file_header(file_info.path_fichier.as_path(), &header).await?;

    // Recalculate hash (header changed) and rename file
    let (new_file_path, digest_suffix, filesize) = rename_backup_file(
        chiffrage,
        &archive_type,
        first_transaction,
        header.domaine.as_str(),
        parent_folder,
        file_info.path_fichier.as_path(),
    ).await?;

    // Update information and return
    let mut new_file_info = file_info.clone();
    new_file_info.header = header;
    new_file_info.path_fichier = new_file_path;
    new_file_info.digest_suffix = digest_suffix;
    new_file_info.len = filesize;

    Ok(new_file_info)
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
    first_transaction: chrono::DateTime<Utc>,
    domain: &str,
    backup_path: &Path,
    workfile_path: &Path
) -> Result<(PathBuf, String, u64), CommonError> {
    // Rename work file
    let date_str = first_transaction.format_with_items(StrftimeItems::new("%Y%m%d%H%M%S%3fZ"));

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
    fs::rename(workfile_path, &backup_file_path).await?;

    Ok((backup_file_path, digest_suffix, filesize))
}

pub async fn rotate_backup_files(domain_backup_path: &Path) -> Result<(), CommonError> {
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

pub async fn overwrite_backup_file_header(file_path: &Path, header: &HeaderFichierArchive) -> Result<(), CommonError> {
    // Open file in read/write mode
    let mut file = File::options().read(true).write(true).open(file_path).await?;

    // From beginning, read version (u16) and header length (u16)
    file.seek(SeekFrom::Start(0)).await?;
    let file_version = file.read_u16_le().await?;
    static FILE_VERSION: u16 = 1;
    if file_version != FILE_VERSION {
        return Err(CommonError::Str("Unsupported backup file version"))
    }
    let header_size = file.read_u16_le().await?;

    // Prepare new header, ensure it does not exceed existing header spacing in file
    let header_str = serde_json::to_string(&header)?;
    let header_updated_size = header_str.len() as u16;
    debug!("preparer_fichier_chiffrage Header taille mise a jour {}, valeur: {}", header_updated_size, header_str);
    if header_size < header_updated_size {
        Err("backup_v2.preparer_fichier_chiffrage Header mis a jour est plus grand que l'espace reserve")?;
    }

    // Fix file header with missing information, keep same version and header size info (bytes 0-3)
    // The unused header portion will be padded with 0s.
    file.seek(SeekFrom::Start(4)).await?;
    file.write_all(header_str.as_bytes()).await?;
    // Truncate by filling in 0s over the remaining original header
    let padding_size = (header_size - header_updated_size) as usize;
    if padding_size > 0 {
        file.write_all(&vec![0u8; padding_size]).await?;
    }
    file.shutdown().await?;

    Ok(())
}
