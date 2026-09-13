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
use crate::v3::{BackupService, ChiffrageService, ConfigService};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::debug;

/// Size of concatenated file that triggers moving it to final directory as final backup archive.
const TRIGGER_CONCATENATED_TO_FINAL_SIZE: u64 = 630_000_000; // About 600MB
const TRIGGER_CONCATENATED_TO_FINAL_DAYS: i64 = 365;

pub struct DomainBackupServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    chiffrage: Arc<dyn ChiffrageService>,
    mongo: Arc<MongoDaoImpl>,
}

impl DomainBackupServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        chiffrage: Arc<dyn ChiffrageService>,
        mongo: Arc<MongoDaoImpl>,
    ) -> Self {
        Self {
            config,
            outbound,
            chiffrage,
            mongo,
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
            Err(PreflightError::NothingToDo) => {
                debug!("No transactions in redo-log to backup or files to concatenate");
                return Ok(());
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
        for file in &domain_info.existing_files {
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
                domain_info.existing_files.push(new_concatenated_file.clone());
                concatenated_file = Some(new_concatenated_file);
            } else {
                // Add the new incremental file to the list of files
                domain_info.existing_files.push(new_file);
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
}

#[async_trait]
impl BackupService for DomainBackupServiceImpl {
    async fn backup_domain(
        &self,
        domain_name: &str,
        redolog_collection_name: &str,
        incremental: bool,
    ) -> Result<(), CommonError> {
        let backup_path = self.mongo.get_path_backup();

        // Lock the backup folder (all domains, only process one domain at a time)
        let lockfile = create_lockfile(backup_path, true).await?;

        let result = self.run_backup(domain_name, redolog_collection_name, incremental).await;

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
