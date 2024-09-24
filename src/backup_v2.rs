use std::sync::Arc;
use chrono::Utc;
use log::{debug, error, info};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::deser_message_buffer;
use millegrilles_cryptographie::x25519::{chiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519, CleSecreteX25519};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use millegrilles_cryptographie::maitredescles::generer_cle_avec_ca;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use crate::backup::CommandeBackup;
use crate::mongo_dao::MongoDao;
use crate::certificats::{CollectionCertificatsPem, ValidateurX509};
use crate::chiffrage_cle::{ajouter_cles_domaine, generer_cle_v2, get_cles_rechiffrees_v2, requete_charger_cles};
use crate::configuration::ConfigMessages;
use crate::constantes::{Securite, DOMAINE_TOPOLOGIE};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::error::Error as CommonError;
use crate::messages_generiques::ReponseCommande;
use crate::recepteur_messages::TypeMessage;

pub async fn thread_backup_v2<M>(middleware: &M, mut rx: Receiver<CommandeBackup>)
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler + 'static
{
    while let Some(commande) = rx.recv().await {
        debug!("thread_backup Debut commande backup {:?}", commande);

        let backup_complet = commande.complet;

        // Lock pour empecher autre process de backup

        // Charger la cle de backup
        let cle_backup = match recuperer_cle_backup(middleware, commande.nom_domaine.as_str()).await {
            Ok(inner) => inner,
            Err(e) => {
                error!("Erreur chargement de la cle de backup, SKIP: {:?}", e);
                continue;
            }
        };

        // Toujours commencer par un backup incremental pour vider
        // les nouvelles transactions de la base de donnees.
        if let Err(e) = backup_incremental(middleware, &commande).await {
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
pub async fn backup_incremental<M>(middleware: &M, commande: &CommandeBackup) -> Result<(), CommonError>
where M: MongoDao + ValidateurX509 + GenerateurMessages + ConfigMessages + CleChiffrageHandler
{
    info!("Debut backup incremental sur {}", commande.nom_domaine);
    let domaine_backup = commande.nom_domaine.as_str();

    // Verifier si on a au moins une transaction à mettre dans le backup


    traiter_transactions_incremental().await;
    uploader_consignation().await;

    Ok(())
}

#[derive(Serialize)]
struct RequeteCleIdBackup {
    domaine: String,
}

#[derive(Deserialize)]
struct ReponseCleIdBackup {
    ok: bool,
    code: Option<usize>,
    err: Option<String>,
    cle_id: Option<String>,
}

#[derive(Serialize)]
struct CommandeEnregistrerCleidBackup {
    domaine: String,
    cle_id: Option<String>,
    reset: Option<bool>
}

/// Recupere la cle de backup de transactions.
/// En genere une nouvelle si elle n'existe pas ou est trop vieille.
async fn recuperer_cle_backup<M>(middleware: &M, domaine_backup: &str) -> Result<(), CommonError>
    where M: GenerateurMessages + ValidateurX509 + CleChiffrageHandler
{
    let requete_cleid_backup = RequeteCleIdBackup { domaine: domaine_backup.to_owned() };
    let routage_demande_cleid = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE, "getCleidBackupDomaine", vec![Securite::L3Protege]).build();

    let mut reponse_cle_id = match middleware.transmettre_requete(routage_demande_cleid, requete_cleid_backup).await? {
        Some(TypeMessage::Valide(m)) => {
            let reponse: ReponseCleIdBackup = deser_message_buffer!(m.message);
            if reponse.ok {
                reponse.cle_id
            } else {
                None
            }
        },
        _ => Err("backup_v2.recuperer_cle_backup Reponse invalide pour cle_id, reessayer plus tard")?
    };

    let cle_backup_secrete = match reponse_cle_id {
        Some(cle_id_backup) => {
            debug!("recuperer_cle_backup Charger la cle a partir du maitre des cles");
            let cles = get_cles_rechiffrees_v2(
                middleware, domaine_backup, vec![cle_id_backup.as_str()]).await?;
            if cles.len() != 1 {
                Err(format!("backup_v2.recuperer_cle_backup Mauvais nombre de cles recus: {:?}", cles.len()))?;
            }
            let cle = &cles[0];

            // Decoder la cle secrete
            let mut cle_secrete = CleSecreteX25519 {0: [0u8;32]};
            cle_secrete.0.copy_from_slice(base64_nopad.decode(&cle.cle_secrete_base64)?.as_slice());

            cle_secrete
        }
        None => {
            debug!("recuperer_cle_backup Generer une nouvelle cle de backup");
            let (info_chiffrage, cle_derivee) = generer_cle_v2(
                middleware, vec![domaine_backup.to_owned()])?;
            debug!("Info chiffrage nouvelle cle: {:?}", info_chiffrage);

            // Sauvegarder la nouvelle cle aupres du maitre des cles
            let signature = match info_chiffrage.signature {
                Some(inner) => inner,
                None => Err("backup_v2.recuperer_cle_backup SignatureDomaine non genere")?
            };
            let cle_ref = signature.get_cle_ref()?.to_string();
            let cles = match info_chiffrage.cles {
                Some(inner) => inner,
                None => Err("backup_v2.recuperer_cle_backup Cles chiffrees non genere")?
            };
            let cles = cles.into_iter().collect();
            ajouter_cles_domaine(middleware, signature, cles, None).await?;

            // Enregistrer cle_id aupres de CoreTopologie
            let routage_enregistrer_cleid = RoutageMessageAction::builder(
                DOMAINE_TOPOLOGIE, "setCleidBackupDomaine", vec![Securite::L3Protege]).build();
            let commande_enregistrer_cleid = CommandeEnregistrerCleidBackup {
                domaine: domaine_backup.to_owned(), cle_id: Some(cle_ref), reset: None };
            if let Some(TypeMessage::Valide(message)) = middleware.transmettre_commande(routage_enregistrer_cleid, &commande_enregistrer_cleid).await? {
                let message_ref = message.message.parse()?.contenu()?;
                let reponse: ReponseCommande = message_ref.deserialize()?;
                if reponse.ok != Some(true) {
                    Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie (reponse false)")?
                }
            } else {
                Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie")?
            };

            // Retourner la cle secrete
            cle_derivee.secret
        }
    };

    todo!()
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

