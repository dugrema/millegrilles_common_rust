use crate::backup_v2::{FichierArchiveBackup, InfoTransactions};
use crate::error::Error as CommonError;
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_filehandling::{create_lockfile, unlock_lockfile};
use crate::v3::{BackupService, ChiffrageService, ConfigService};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;
use crate::v3::impls::backup_producer::{preflight_check, produce_concatene_backup_file, produce_incremental_backup_file, promote_incremental_to_concatene};

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
        correlation_id: String,
    ) -> Result<(), CommonError> {
        // Run a check to ensure we have all required information to start a backup (raises Error on issue)
        let mut domain_info = preflight_check(
            self.config.as_ref(),
            self.mongo.as_ref(),
            self.outbound.as_ref(),
            self.chiffrage.as_ref(),
            domain_name.as_str(),
            redolog_collection_name.as_str(),
            incremental
        ).await?;

        // Run incremental backup
        let incremental_file: Option<FichierArchiveBackup> = if domain_info.redolog_count > 0 {
            // Extract all transactions into an incremental file even when we do a full backup
            // On full backups, the incremental file gets rotated out with the old backup set.
            let incremental_file = produce_incremental_backup_file().await?;
            Some(incremental_file)
        } else {
            None
        };

        if !incremental {
            // Run full backup
            match domain_info.existing_files.as_mut() {
                Some(existing_files) => {
                    if let Some(new_file) = incremental_file {
                        // Add the new incremental file to the list of files
                        existing_files.push(new_file);
                    }

                    // Build new concatene file and rotate previous backup set.
                    produce_concatene_backup_file().await?;
                },
                None => {
                    // There are no pre-existing file and this is a full backup. Promote the
                    // incremental file to Concatene: overwrite header and rename from I to C.
                    promote_incremental_to_concatene().await?;
                }
            }
        } else {
            debug!("Incremental backup complete");
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
        correlation_id: String
    ) -> Result<(), CommonError> {
        let backup_path = self.mongo.get_path_backup();

        // Lock the backup folder
        let lockfile = create_lockfile(backup_path)?;

        let result = self.run_backup(
            domain_name, redolog_collection_name, incremental, correlation_id
        ).await;

        // Unlock backup folder
        unlock_lockfile(lockfile);

        result
    }
}
