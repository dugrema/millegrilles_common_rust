use crate::backup_v2::{organiser_fichiers_backup, FichierArchiveBackup};
use crate::error::Error as CommonError;
use crate::mongo_dao::MongoDao;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_encryption::get_domain_backup_key;
use crate::v3::models::PreflightResult;
use crate::v3::{ChiffrageService, ConfigService};
use bson::doc;

pub async fn preflight_check(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
    redolog_collection_name: &str,
    incremental: bool,
) -> Result<PreflightResult, CommonError> {
    // Check how many transactions are in the redo-log (if incremental, we need at least 1)
    let waiting_transaction_count = check_redo_log_size(mongo, redolog_collection_name).await?;

    let existing_files = if incremental {
        if waiting_transaction_count == 0 {
            return Err(CommonError::Str("No transactions waiting in redo collection for incremental backup, aborting"));
        }
        None
    } else {
        let domain_backup_path = mongo.get_path_backup().join(domain_name);
        let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

        // Check if we have existing incremental backups to concatenate
        let files = organiser_fichiers_backup(
            domain_backup_path.as_path(),
            idmg.as_str(),
            false
        ).await?;

        if waiting_transaction_count == 0 && files.len() <= 1 {
            // We only have 1 backup file (Concatene) and there are no additional transactions to back-up
            return Err(CommonError::Str("All transactions are already in Final/Concatene files, aborting full backup"));
        }

        Some(files)
    };

    // Get encryption key for this domain
    let decryption_key = get_domain_backup_key(outbound, chiffrage, domain_name).await?;

    Ok(PreflightResult {
        existing_files,
        redolog_count: 0,
        key: decryption_key,
    })
}

async fn check_redo_log_size(mongo: &dyn MongoDao, redolog_collection_name: &str) -> Result<u64, CommonError> {
    let collection = mongo.get_collection(redolog_collection_name)?;
    Ok(collection.count_documents(doc!{}).await?)
}

pub async fn promote_incremental_to_concatene() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

pub async fn promote_concatene_to_final() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

pub async fn produce_incremental_backup_file() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}

pub async fn produce_concatene_backup_file() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}
