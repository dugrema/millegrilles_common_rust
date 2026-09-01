use crate::backup_v2::InfoTransactions;
use crate::error::Error as CommonError;
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_filehandling::{create_lockfile, unlock_lockfile};
use crate::v3::{BackupService, ConfigService};
use async_trait::async_trait;
use std::sync::Arc;
use crate::v3::impls::backup_producer::preflight_check;

pub struct DomainBackupServiceImpl {
    config: Arc<dyn ConfigService>,
    outbound: Arc<MessageOutboundFacade>,
    mongo: Arc<MongoDaoImpl>,
}

impl DomainBackupServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        outbound: Arc<MessageOutboundFacade>,
        mongo: Arc<MongoDaoImpl>,
    ) -> Self {
        Self {
            config,
            outbound,
            mongo,
        }
    }

    async fn run_backup(
        &self,
        domain_name: String,
        redolog_collection_name: String,
        incremental: bool,
        correlation_id: String,
    ) -> Result<InfoTransactions, CommonError> {
        // Run a check to ensure we have all required information to start a backup (raises Error on issue)
        let domain_info = preflight_check(
            self.config.as_ref(),
            self.mongo.as_ref(),
            self.outbound.as_ref(),
            domain_name.as_str(),
            redolog_collection_name.as_str(),
            incremental
        ).await?;

        todo!()
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
    ) -> Result<InfoTransactions, CommonError> {
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
