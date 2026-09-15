use tracing::{debug, info};
use crate::error::Error as CommonError;
use crate::mongo_dao::MongoDao;
use crate::v3::{ConfigService, FilehostService};
use crate::v3::impls::backup_filehandling::load_backup_file_list;

pub async fn transfer_backup_files_to_filehost(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    filehost: &dyn FilehostService,
    domain_name: &str
) -> Result<(), CommonError> {
    // Prepare information
    let backup_path = mongo.get_path_backup();
    let domain_backup_path = backup_path.join(domain_name);
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    // Load file list
    let backup_file_list = load_backup_file_list(
        domain_backup_path.as_path(),
        idmg.as_str()
    ).await?;

    if backup_file_list.is_empty() {
        return Ok(())   // Nothing to do
    }

    info!("Transferring up to {} backup files to filehost", backup_file_list.len());

    // Upload files
    let mut version: Option<String> = None;
    for file in backup_file_list {
        if file.header.type_archive.as_str() == "C" {
            debug!("Setting backup version to {:?} for incremental uploads", file.digest_suffix);
            version = Some(file.digest_suffix.clone());
        }
        filehost.put_backup_file(&file, version.as_ref()).await?;
    }

    Ok(())
}
