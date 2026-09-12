use std::collections::HashSet;
use tracing::{debug, warn};
use crate::backup_v2::{CommandeEnregistrerCleidBackup, FichierArchiveBackup, ReponseCleIdBackup, RequeteCleIdBackup};
use crate::constantes::{Securite, DOMAINE_TOPOLOGIE};
use crate::generateur_messages::RoutageMessageAction;
use crate::messages_generiques::ReponseCommande;
use crate::v3::ChiffrageService;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::DecryptedKey;
use crate::error::Error as CommonError;

/// Loads or generates a domain backup key
pub async fn get_domain_backup_key(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
) -> Result<DecryptedKey, CommonError> {
    debug!("get_domain_backup_key for domain {}", domain_name);

    // Request key information from CoreTopologie
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "getCleidBackupDomaine",
        vec![Securite::L3Protege]
    ).build();
    let key_request = RequeteCleIdBackup { domaine: domain_name.to_owned() };
    let response = outbound.send_request(routing, key_request).await?;

    // Figure out if we get an existing key or generate a new one
    let key_information: ReponseCleIdBackup = response.message.deserialize()?;
    let backup_key = match key_information.cle_id {
        Some(key_id) => {
            match load_backup_key(outbound, domain_name, key_id.as_str()).await {
                Ok(key) => key,
                Err(e) => {
                    warn!("Error loading domain {} backup key, generating a new one: {:?}", domain_name, e);
                    generate_backup_key_for_domain(outbound, chiffrage, domain_name).await?
                }
            }
        },
        None => {
            warn!("Error requesting domain backup key, will generate a new one: {:?}", key_information.err);
            generate_backup_key_for_domain(outbound, chiffrage, domain_name).await?
        }
    };

    Ok(backup_key)
}

async fn load_backup_key(outbound: &MessageOutboundFacade, domain: &str, key_id: &str) -> Result<DecryptedKey, CommonError> {
    let reponse = outbound.get_keys(domain, vec![key_id.to_string()], Some(true)).await?;
    match reponse.into_iter().next() {
        Some(key) => Ok(key),
        None => Err(CommonError::String(format!("Backup key id {} not found", key_id)))
    }
}

pub async fn load_backup_keys(outbound: &MessageOutboundFacade, backup_files: &Vec<FichierArchiveBackup>) -> Result<Vec<DecryptedKey>, CommonError> {
    let mut key_ids = HashSet::new();
    let mut domain = None;
    for file in backup_files {
        key_ids.insert(file.header.cle_id.clone());
        if domain.is_none() {
            domain = Some(file.header.domaine.clone());
        }
    }
    let key_count = key_ids.len();
    let domain = match domain { Some(domain) => domain, None => return Err(CommonError::Str("No file/domain provided"))};
    let reponse = outbound.get_keys(domain.as_str(), key_ids.into_iter().collect(), Some(true)).await?;
    if reponse.len() == key_count {
        Ok(reponse)
    } else {
        Err(CommonError::String(format!("Need {} keys for concatenating backup, only received {}", key_count, reponse.len())))
    }
}

async fn generate_backup_key_for_domain(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain: &str
) -> Result<DecryptedKey, CommonError> {
    let new_key = chiffrage.generate_new_key(&vec![domain.to_string()]).await?;

    // Save the new backup key immediately
    outbound.save_keys(&vec![&new_key], None).await?;

    // Send the key id to CoreTopologie for usage in this domain
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "setCleidBackupDomaine",
        vec![Securite::L3Protege]
    ).build();
    let command = CommandeEnregistrerCleidBackup {
        domaine: domain.to_string(),
        cle_id: Some(new_key.key_id.clone()),
        reset: None,
    };
    match outbound.send_command(routing, command).await? {
        Some(response) => {
            let command_response: ReponseCommande = response.message.deserialize()?;
            if Some(true) != command_response.ok {
                return Err(CommonError::String(format!("Error when saving new key_id for domain: {:?}", command_response.err)))
            }
        },
        None => {
            return Err(CommonError::Str("No response provided when setting new key_id for domain backup"))
        }
    };

    Ok(new_key.try_into()?)
}
