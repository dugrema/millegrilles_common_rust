use crate::backup_v2::{FichierArchiveBackup, TypeArchive};
use crate::common_messages::BackupEvent;
use crate::constantes::{BACKUP_EVENEMENT_MAJ, Securite};
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_filehandling::{create_lockfile, produce_final_file, promote_backup_file, unlock_lockfile};
use crate::v3::impls::backup_producer::{preflight_check, produce_concatenated_backup_file, produce_incremental_backup_file};
use crate::v3::models::PreflightError;
use crate::v3::{BackupService, ChiffrageService, ConfigService, TransactionService};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use openssl::pkey::{PKey, Private};
use tracing::{debug, error, info, warn};
use crate::v3::impls::backup_restorer::{process_transactions_from_backup, restore_preflight_check, truncate_data_tables, RestorationState};

/// Size of concatenated file that triggers moving it to final directory as final backup archive.
const TRIGGER_CONCATENATED_TO_FINAL_SIZE: u64 = 630_000_000; // About 600MB
const TRIGGER_CONCATENATED_TO_FINAL_DAYS: i64 = 365;

pub struct DomainBackupServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    chiffrage: Arc<dyn ChiffrageService>,
    mongo: Arc<MongoDaoImpl>,
    transaction: Arc<dyn TransactionService>,
    /// List of data tables to truncate on restore
    data_tables: Vec<String>,
}

impl DomainBackupServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        chiffrage: Arc<dyn ChiffrageService>,
        mongo: Arc<MongoDaoImpl>,
        transaction: Arc<dyn TransactionService>,
        data_tables: Vec<String>,
    ) -> Self {
        Self {
            config,
            outbound,
            chiffrage,
            mongo,
            transaction,
            data_tables,
        }
    }

    async fn run_backup(
        &self,
        domain_name: &str,
        redolog_collection_name: &str,
        incremental: bool,
    ) -> Result<(), CommonError> {
        // Emit initial message to indicate start of backup for domain
        emit_backup_event(self.outbound.as_ref(), BackupEvent::new_ok(domain_name)).await?;

        match self.run_backup_process(domain_name, redolog_collection_name, incremental).await {
            Ok(()) => {
                emit_backup_event(self.outbound.as_ref(), BackupEvent::new_done(domain_name)).await?;
                Ok(())
            },
            Err(e) => {
                emit_backup_event(self.outbound.as_ref(), BackupEvent::new_err(domain_name, e.to_string())).await.ok();
                Err(e)
            }
        }
    }

    async fn run_backup_process(&self, domain_name: &str, redolog_collection_name: &str, incremental: bool) -> Result<(), CommonError> {
        // Run a check to ensure we have all required information to start a backup (raises Error on issue)
        debug!("run_backup_process Starting");
        let mut domain_info = match preflight_check(
            self.config.as_ref(),
            self.mongo.as_ref(),
            self.outbound.as_ref(),
            self.chiffrage.as_ref(),
            domain_name,
            redolog_collection_name,
            incremental
        ).await {
            Ok(info) => info,
            Err(PreflightError::NotReadyForBackup) => {
                warn!("The system is not ready for backing-up transactions (ready.txt file missing)");
                return Ok(())
            },
            Err(PreflightError::NothingToDo) => {
                debug!("No transactions in redo-log to backup or files to concatenate");
                return Ok(())
            },
            Err(PreflightError::CommonError(e)) => return Err(e)
        };
        debug!("run_backup_process Pre-flight successful, {} transactions in redo-log", domain_info.redolog_count);

        // Run incremental backup
        let incremental_file: Option<FichierArchiveBackup> = if domain_info.redolog_count > 0 {
            // Extract all transactions into an incremental file even when we do a full backup
            // On full backups, the incremental file gets rotated out with the old backup set.
            let incremental_file = produce_incremental_backup_file(
                self.outbound.as_ref(),
                self.mongo.as_ref(),
                self.chiffrage.as_ref(),
                &domain_info,
                redolog_collection_name,
            ).await?;
            Some(incremental_file)
        } else {
            None
        };

        // Concatenate backup when applicable
        let mut concatenated_file = None;
        for file in &domain_info.files {
            if file.header.type_archive == TypeArchive::Concatene.to_string() {
                debug!("Found existing Concatene file: {:?}", file.path_fichier);
                concatenated_file = Some(file.clone());
                break;
            }
        }

        // Add the new incremental file to list of existing backup files
        if let Some(new_file) = incremental_file {
            if concatenated_file.is_none() {
                debug!("Promoting incremental file to Concatene");
                // There is no current Concatenated file
                // Promote the incremental file to Concatene
                let new_concatenated_file = promote_backup_file(self.chiffrage.as_ref(), &new_file, TypeArchive::Concatene).await?;
                domain_info.files.push(new_concatenated_file.clone());
                concatenated_file = Some(new_concatenated_file);
            } else {
                // Add the new incremental file to the list of files
                domain_info.files.push(new_file);
            }
        }

        if ! incremental && domain_info.contains_incremental() {
            // This is a complete backup - run if the backup contains incremental files
            // The check is necessary because there could be multiple Final and a Concatene file in the list.
            concatenated_file = Some(
                produce_concatenated_backup_file(self.chiffrage.as_ref(), self.outbound.as_ref(), &domain_info).await?
            );
        }

        // Check if we can promote the Concatenated file to Final archive
        // Triggers: size of file or age of oldest transaction
        if let Some(file) = concatenated_file && ! incremental {
            let expired_date = Utc::now() - chrono::Duration::days(TRIGGER_CONCATENATED_TO_FINAL_DAYS);
            if file.len > TRIGGER_CONCATENATED_TO_FINAL_SIZE || file.header.debut_backup < expired_date.timestamp() as u64 {
                // Promote the concatenated file to final
                produce_final_file(self.chiffrage.as_ref(), &file).await?;
            }
        }

        Ok(())
    }

    pub async fn run_restore(
        &self,
        domain_name: &str,
        redolog_collection_name: &str,
        tracking_collection_name: &str,
        resume: bool,
        version: Option<String>,
        master_key: Option<&PKey<Private>>,
    ) -> Result<RestorationState, CommonError> {

        let preflight = restore_preflight_check(
            self.config.as_ref(),
            self.mongo.as_ref(),
            self.outbound.as_ref(),
            domain_name,
            redolog_collection_name,
            tracking_collection_name,
            version.as_ref(),
            resume,
            master_key,
        ).await?;

        if preflight.last_processed_id.is_none() {
            info!("Truncate tracking collection and all data collections from domain {}", domain_name);
            truncate_data_tables(self.mongo.as_ref(), &self.data_tables, Some(tracking_collection_name)).await?;
        }

        let result = process_transactions_from_backup(
            self.mongo.as_ref(),
            &preflight,
            self.outbound.as_ref(),
            self.transaction.as_ref(),
            redolog_collection_name,
        ).await?;

        Ok(result)
    }
}

#[async_trait]
impl BackupService for DomainBackupServiceImpl {
    async fn backup_domain(
        &self,
        domain_name: &str,
        redolog_collection_name: &str,
        incremental: bool,
    ) -> Result<(), CommonError> {
        let backup_path = self.mongo.get_path_backup().as_path();
        let domain_backup_path = backup_path.join(domain_name);

        // Lock the backup folder (all domains, only process one domain at a time)
        let root_lockfile = create_lockfile(backup_path, true).await?;
        // Also get a lock on the domain - if another process (e.g. restore) is already occurring, fail fast
        let domain_lockfile = match create_lockfile(domain_backup_path.as_path(), false).await {
            Ok(lockfile) => lockfile,
            Err(e) => {
                error!("Error locking domain {} for backup, aborting", domain_name);
                unlock_lockfile(root_lockfile).await;   // Remove backup root lockfile
                return Err(e);
            }
        };

        let result = self.run_backup(domain_name, redolog_collection_name, incremental).await;

        // Unlock backup folders
        unlock_lockfile(domain_lockfile).await;
        unlock_lockfile(root_lockfile).await;

        result
    }

    async fn restore_domain(
        &self,
        domain_name: &str,
        redolog_collection_name: &str,
        tracking_collection_name: &str,
        resume: bool,
        version: Option<String>,
        master_key: Option<&PKey<Private>>,
    ) -> Result<RestorationState, CommonError> {
        let backup_path = self.mongo.get_path_backup().as_path();
        let domain_backup_path = backup_path.join(domain_name);

        // Lock the domain folder (only specific domain). Fail fast.
        let lockfile = create_lockfile(domain_backup_path.as_path(), false).await?;

        let result = self.run_restore(
            domain_name,
            redolog_collection_name,
            tracking_collection_name,
            resume,
            version,
            master_key,
        ).await;

        // Unlock backup folder
        unlock_lockfile(lockfile).await;

        result
    }
}

async fn emit_backup_event(outbound: &MessageOutboundFacade, event: BackupEvent) -> Result<(), CommonError> {
    let routing = RoutageMessageAction::builder(
        &event.domaine,
        BACKUP_EVENEMENT_MAJ,
        vec![Securite::L1Public]
    ).build();
    outbound.emit_event(routing, event).await?;
    Ok(())
}
