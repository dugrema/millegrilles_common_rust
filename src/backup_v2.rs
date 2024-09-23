use std::sync::Arc;
use chrono::Utc;
use log::{debug, error, info};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use tokio::sync::mpsc::Receiver;
use crate::backup::CommandeBackup;
use crate::mongo_dao::MongoDao;
use crate::certificats::{CollectionCertificatsPem, ValidateurX509};
use crate::configuration::ConfigMessages;
use crate::generateur_messages::GenerateurMessages;

pub async fn thread_backup_v2<M>(middleware: &M, mut rx: Receiver<CommandeBackup>)
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler + 'static
{
    while let Some(commande) = rx.recv().await {
        debug!("thread_backup Debut commande backup {:?}", commande);
        info!("Debut backup {}", commande.nom_domaine);
        // match backup(middleware, &commande).await {
        //     Ok(_) => info!("Backup {} OK", commande.nom_domaine),
        //     Err(e) => error!("backup.thread_backup Erreur backup domaine {} : {:?}", commande.nom_domaine, e)
        // };
    }
}
