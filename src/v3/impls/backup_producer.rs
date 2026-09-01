use crate::backup_v2::{organiser_fichiers_backup, FichierArchiveBackup};
use crate::error::Error as CommonError;
use crate::mongo_dao::MongoDao;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::impls::backup_encryption::get_domain_backup_key;
use crate::v3::models::PreflightResult;
use crate::v3::{ChiffrageService, ConfigService};
use bson::doc;
use tracing::debug;

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

pub async fn produce_incremental_backup_file() -> Result<FichierArchiveBackup, CommonError> {
    debug!("Starting incremental backup");



    todo!()
    // debug!("traiter_transactions_incremental Debut");
    //     let debut_traitement = Utc::now();
    //
    //     // Creer channels de communcation entre threads
    //     let (tx_transactions, rx_transactions) = mpsc::channel(2);
    //     let (tx_info_transactions, rx_info_transactions) = mpsc::channel(2);
    //
    //     // Preparer une thread de traitement du fichier
    //     let type_archive = TypeArchive::Incremental;
    //     let pipe = preparer_fichier_chiffrage(
    //         path_backup, type_archive.clone(), rx_transactions, rx_info_transactions, cle_backup_domaine, domaine, idmg);
    //
    //     // Traiter les transactions en ordre sequentiel.
    //     let transaction_process = traiter_transactions_incrementales(
    //         middleware, commande_backup, tx_transactions, tx_info_transactions);
    //
    //     let (pipe_result, transaction_result) = join![pipe, transaction_process];
    //
    //     // Rename work file
    //     let info_transactions = transaction_result?;
    //     let (temp_file, _) = pipe_result?;
    //     rename_work_file(&type_archive, &info_transactions, domaine, path_backup, temp_file.as_ref()).await?;
    //
    //     let date_derniere_transaction = Utc.timestamp_millis_opt(info_transactions.date_derniere_transaction as i64).unwrap();
    //
    //     // Supprimer les transactions traitees. On utilise la date de la plus recente transaction archivee
    //     // pour s'assurer de ne pas effacer de nouvelles transactions non traitees.
    //     let collection = middleware.get_collection(commande_backup.nom_collection_transactions.as_str())?;
    //     let filtre = doc! {
    //         TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$lte": date_derniere_transaction},
    //         TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
    //     };
    //     // let options = DeleteOptions::builder().hint(Hint::Name(String::from("backup_transactions"))).build();
    //     collection
    //         .delete_many(filtre)
    //         .hint(Hint::Name(String::from("backup_transactions")))
    //         .await?;
    //
    //     let fin_traitement = Utc::now();
    //     debug!("traiter_transactions_incremental Fin, duree: {}", fin_traitement - debut_traitement);
    //     Ok(())
}

pub async fn produce_concatene_backup_file() -> Result<FichierArchiveBackup, CommonError> {
    todo!()
}
