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
use crate::error::Error as CommonError;

pub async fn thread_backup_v2<M>(middleware: &M, mut rx: Receiver<CommandeBackup>)
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler + 'static
{
    while let Some(commande) = rx.recv().await {
        debug!("thread_backup Debut commande backup {:?}", commande);

        let backup_complet = commande.complet;

        // Lock pour empecher autre process de backup

        // Toujours commencer par un backup incremental pour vider
        // les nouvelles transactions de la base de donnees.
        if let Err(e) = backup_incremental(middleware, commande).await {
            error!("Erreur durant backup incremental: {:?}", e);
        }

        if backup_complet == true  {
            // Generer un nouveau fichier concatene, potentiellement des nouveaux fichiers finaux.

            // TODO Backup complet
            error!("TODO - backup complet");
        }

        // Retirer le lock de backup

    }
}

/// Fait un backup incremental en transferant les transactions completees avec succes dans un fichier.
/// Retire les transactions de la base de donnees.
pub async fn backup_incremental<M>(middleware: &M, commande: CommandeBackup) -> Result<(), CommonError>
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    info!("Debut backup incremental sur {}", commande.nom_domaine);

    // Verifier si on a au moins une transaction à mettre dans le backup


    recuperer_cle_backup().await;
    traiter_transactions_incremental().await;
    uploader_consignation().await;

    Ok(())
}

/// Recupere la cle de backup de transactions.
/// En genere une nouvelle si elle n'existe pas ou est trop vieille.
async fn recuperer_cle_backup() {

}

/// Prepare un nouveau fichier avec stream de compression et cipher. Ajouter l'espace necessaire
/// pour le header du fichier.
async fn preparer_fichier_chiffrage() {

}

/// Met a jour le header d'un fichier avec l'information manquante.
async fn maj_header_fichier() {

}

/// Fait le backup des nouvelles transactions dans un fichier de backup incremental.
async fn traiter_transactions_incremental() {

    // Preparer une methode de compression et header
    preparer_fichier_chiffrage().await;

    // Traiter les transactions en ordre sequentiel.

    // Fermer le fichier et mettre a jour le header avec l'information manquante.
    maj_header_fichier().await;
}

/// Upload le fichier de backup vers la consignation.
async fn uploader_consignation() {

}

