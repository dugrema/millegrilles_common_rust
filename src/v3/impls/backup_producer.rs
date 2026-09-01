use crate::backup_v2::{CleBackupDomaine, ReponseCleIdBackup, RequeteCleIdBackup, organiser_fichiers_backup};
use crate::constantes::{DOMAINE_TOPOLOGIE, Securite};
use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::mongo_dao::MongoDao;
use crate::v3::{ChiffrageService, ConfigService};
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::PreflightResult;
use bson::doc;
use tracing::warn;

pub async fn preflight_check(
    config: &dyn ConfigService,
    mongo: &dyn MongoDao,
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
    redolog_collection_name: &str,
    incremental: bool,
) -> Result<PreflightResult, CommonError> {
    let domain_backup_path = mongo.get_path_backup().join(domain_name);
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;

    // Check how many transactions are in the redo-log (if incremental, we need at least 1)
    let waiting_transaction_count = check_redo_log_size(mongo, redolog_collection_name).await?;

    let existing_files = if incremental {
        if waiting_transaction_count == 0 {
            return Err(CommonError::Str("No transactions waiting in redo collection for incremental backup, aborting"));
        }
        None
    } else {
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

/// Loads or generates a domain backup key
async fn get_domain_backup_key(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
) -> Result<CleBackupDomaine, CommonError> {

    // Request key information from CoreTopologie
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "getCleidBackupDomaine",
        vec![Securite::L3Protege]
    ).build();
    let key_request = RequeteCleIdBackup { domaine: domain_name.to_owned() };
    let response = outbound.send_request(routing, key_request).await?;
    let key_information: ReponseCleIdBackup = response.message.deserialize()?;
    let backup_key = match key_information.cle_id {
        Some(key_id) => {
            load_backup_key(chiffrage, key_id.as_str()).await?
        },
        None => {
            warn!("Error requesting domain backup key, will generate a new one: {:?}", key_information.err);
            generer_cle_backup_domaine(domain_name).await?
        }
    };

    Ok(backup_key)
}

async fn load_backup_key(chiffrage: &dyn ChiffrageService, key_id: &str) -> Result<CleBackupDomaine, CommonError> {
    let reponse = chiffrage.get_keys(vec![key_id.to_string()]).await?;

    todo!()

    //     let cle_backup_domaine = match reponse_cle_id {
    //         Some(cle_id_backup) => {
    //             debug!("recuperer_cle_backup Charger la cle a partir du maitre des cles");
    //             let cles = match get_cles_rechiffrees_v2(
    //                 middleware, domaine_backup, vec![cle_id_backup.as_str()], Some(true)).await {
    //                 Ok(c) => c,
    //                 Err(e) => {
    //                     error!("Key {} unknown to MaitreDesCles, read all available backup files and resubmit encrypted keys.", cle_id_backup);
    //                     return if let Err(e2) = resubmit_backup_keys(middleware, domaine_backup, cle_id_backup.as_str()).await {
    //                         Err(CommonError::String(format!("Backup of {} failed (missing key). Key resubmission failed: {:?} Original error: {:?}", domaine_backup, e2, e)))
    //                     } else {
    //                         Err(CommonError::String(format!("Backup of {} failed (missing key). Encrypted backup keys have been resubmitted - you can now decrypt manually and retry the backup. Original error: {:?}", domaine_backup, e)))
    //                     }
    //                 }
    //             };
    //
    //             if cles.len() != 1 {
    //                 Err(format!("backup_v2.recuperer_cle_backup Mauvais nombre de cles recus: {:?}", cles.len()))?;
    //             }
    //             let cle = &cles[0];
    //
    //             // Decoder la cle secrete
    //             let mut cle_secrete = CleSecreteX25519 {0: [0u8;32]};
    //             cle_secrete.0.copy_from_slice(base64_nopad.decode(&cle.cle_secrete_base64)?.as_slice());
    //             let signature_cle = match cle.signature.as_ref() {
    //                 Some(inner) => inner.clone(),
    //                 None => Err("Signature cle n'as pas ete recue")?
    //             };
    //
    //             CleBackupDomaine {
    //                 cle: cle_secrete,
    //                 cle_id: cle_id_backup,
    //                 signature_cle,
    //             }
    //         }
    //         None => {
    //             debug!("recuperer_cle_backup Generer une nouvelle cle de backup");
    //             generer_cle_backup_domaine(middleware, domaine_backup).await?
    //         }
    //     };
    //
    //     Ok(cle_backup_domaine)
}

async fn generer_cle_backup_domaine(domaine: &str) -> Result<CleBackupDomaine, CommonError> {
    todo!()

    // let ca = middleware.get_enveloppe_signature();
    // let enveloppes_chiffrage = middleware.get_publickeys_chiffrage();
    // if enveloppes_chiffrage.len() == 0 {
    //     Err("chiffrage_cle.generer_cle_v2 Aucuns certificats de chiffrage recus")?
    // }
    // let enveloppes_ref: Vec<&EnveloppeCertificat> = enveloppes_chiffrage.iter().map(|item| item.as_ref()).collect();
    //
    // // Generer la cle et chiffrer pour les certificats
    // let (info_chiffrage, cle_derivee) = generer_cle_avec_ca(
    //     vec![domaine],
    //     ca.enveloppe_ca.as_ref(),
    //     enveloppes_ref
    // )?;
    // debug!("Info chiffrage nouvelle cle: {:?}", info_chiffrage);
    //
    // // Sauvegarder la nouvelle cle aupres du maitre des cles
    // let signature = match info_chiffrage.signature {
    //     Some(inner) => inner,
    //     None => Err("backup_v2.recuperer_cle_backup SignatureDomaine non genere")?
    // };
    // let cle_ref = signature.get_cle_ref()?.to_string();
    // let cles = match info_chiffrage.cles {
    //     Some(inner) => inner,
    //     None => Err("backup_v2.recuperer_cle_backup Cles chiffrees non genere")?
    // };
    // let cles = cles.into_iter().collect();
    // let timeout = 15_000;
    //
    // let add_key_command = CommandeAjouterCleDomaine { cles, signature };
    // let routing = RoutageMessageAction::builder(
    //     DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public])
    //     .timeout_blocking(timeout)
    //     .build();
    //
    // match middleware.transmettre_commande(routing, add_key_command).await {
    //     Ok(inner) => match inner {
    //         Some(TypeMessage::Valide(inner)) => {
    //             let parsed_response = inner.message.parse()?;
    //             let parsed_buffer = parsed_response.contenu()?;
    //             let response: ReponseCommande = parsed_buffer.deserialize()?;
    //             if Some(true) != response.ok {
    //                 Err(format!("chiffrage_cle.ajouter_cles_domaine Error saving conversation key: {:?}", response.err))?;
    //             }
    //         },
    //         _ => Err("chiffrage_cle.ajouter_cles_domaine Error saving conversation key: wrong response type")?
    //     },
    //     Err(e) => Err(format!("chiffrage_cle.ajouter_cles_domaine Error saving conversation key: {:?}", e))?
    // };
    //
    // // Enregistrer cle_id aupres de CoreTopologie
    // let routage_enregistrer_cleid = RoutageMessageAction::builder(
    //     DOMAINE_TOPOLOGIE, "setCleidBackupDomaine", vec![Securite::L3Protege]).build();
    // let commande_enregistrer_cleid = crate::backup_v2::CommandeEnregistrerCleidBackup {
    //     domaine: domaine.to_owned(), cle_id: Some(cle_ref.clone()), reset: None };
    // if let Some(TypeMessage::Valide(message)) = middleware.transmettre_commande(routage_enregistrer_cleid, &commande_enregistrer_cleid).await? {
    //     let message_ref = message.message.parse()?.contenu()?;
    //     let reponse: ReponseCommande = message_ref.deserialize()?;
    //     if reponse.ok != Some(true) {
    //         Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie (reponse false)")?
    //     }
    // } else {
    //     Err("backup_v2.recuperer_cle_backup Erreur enregistrement cle_id backup aupres de CoreTopologie")?
    // };
    //
    // // Retourner la cle secrete
    // Ok(CleBackupDomaine {
    //     cle: cle_derivee.secret,
    //     cle_id: cle_ref,
    //     signature_cle: signature,
    // })
}
