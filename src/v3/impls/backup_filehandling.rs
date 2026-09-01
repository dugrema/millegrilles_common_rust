use crate::error::Error as CommonError;
use crate::v3::models::LockFile;
use fs2::FileExt;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;
use tracing::info;
use crate::backup_v2::FichierArchiveBackup;

/// Use to create a lockfile with exclusive access - prevents multiple simultaneous backup processes.
/// Raises errors when lock is unsuccessful.
pub fn create_lockfile(backup_path: &PathBuf) -> Result<LockFile, CommonError> {
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

    if let Err(_e) = file.try_lock_exclusive() {
        return Err(CommonError::Str("Backup file already locked, SKIP backup"));
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

pub async fn promote_incremental_to_concatene() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

pub async fn promote_concatene_to_final() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}
