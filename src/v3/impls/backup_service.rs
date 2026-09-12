use crate::backup_v2::{FichierArchiveBackup, TypeArchive};
use crate::common_messages::BackupEvent;
use crate::constantes::{BACKUP_EVENEMENT_MAJ, Securite};
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_filehandling::{create_lockfile, produce_final_file, promote_backup_file, unlock_lockfile};
use crate::v3::impls::backup_producer::{preflight_check, produce_concatenated_backup_file, produce_incremental_backup_file};
use crate::v3::{BackupService, ChiffrageService, ConfigService};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;

/// Size of concatenated file that triggers moving it to final directory as final backup archive.
const TRIGGER_CONCATENATED_TO_FINAL: u64 = 630_000_000; // About 600MB

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
        domain_name: String,
        redolog_collection_name: String,
        incremental: bool,
    ) -> Result<(), CommonError> {
        // Emit initial message to indicate start of backup for domain
        emit_backup_event(self.outbound.as_ref(), BackupEvent::new_ok(domain_name.as_str())).await?;

        match self.run_backup_process(domain_name.as_str(), redolog_collection_name.as_str(), incremental).await {
            Ok(()) => {
                emit_backup_event(self.outbound.as_ref(), BackupEvent::new_done(domain_name.as_str())).await?;
                Ok(())
            },
            Err(e) => {
                emit_backup_event(self.outbound.as_ref(), BackupEvent::new_err(domain_name.as_str(), e.to_string())).await.ok();
                Err(e)
            }
        }
    }

    async fn run_backup_process(&self, domain_name: &str, redolog_collection_name: &str, incremental: bool) -> Result<(), CommonError> {
        // Run a check to ensure we have all required information to start a backup (raises Error on issue)
        let mut domain_info = preflight_check(
            self.config.as_ref(),
            self.mongo.as_ref(),
            self.outbound.as_ref(),
            self.chiffrage.as_ref(),
            domain_name,
            redolog_collection_name,
            incremental
        ).await?;

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
        match domain_info.existing_files.take() {
            Some(mut existing_files) => {
                if incremental {
                    debug!("Incremental backup complete");
                } else {
                    // Complete backup, concatenate all files including the new one
                    if let Some(new_file) = incremental_file {
                        // Add the new incremental file to the list of files
                        existing_files.push(new_file);
                    }
                    // Put updated files back (removed by .take)
                    domain_info.existing_files = Some(existing_files);
                    // Build new concatene file and rotate previous backup set.
                    concatenated_file = Some(
                        produce_concatenated_backup_file(self.chiffrage.as_ref(), self.outbound.as_ref(), &domain_info).await?
                    );
                }
            },
            None => {
                // There are no pre-existing files.
                if let Some(new_file) = incremental_file {
                    // Promote the incremental file to Concatene
                    concatenated_file = Some(
                        promote_backup_file(self.chiffrage.as_ref(), &new_file, TypeArchive::Concatene).await?
                    );
                }
            }
        }

        if let Some(file) = concatenated_file {
            if file.len > TRIGGER_CONCATENATED_TO_FINAL {
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
        domain_name: String,
        redolog_collection_name: String,
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
