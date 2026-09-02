use tracing::warn;
use crate::backup_v2::{CommandeEnregistrerCleidBackup, ReponseCleIdBackup, RequeteCleIdBackup};
use crate::constantes::{Securite, DOMAINE_TOPOLOGIE};
use crate::generateur_messages::RoutageMessageAction;
use crate::messages_generiques::ReponseCommande;
use crate::v3::ChiffrageService;
use crate::v3::facades::message_outbound::MessageOutboundFacade;
use crate::v3::models::DecryptedKey;
use std::pin::Pin;
use std::task::{Context, Poll};
use millegrilles_cryptographie::chiffrage_mgs4::CipherMgs4;
use millegrilles_cryptographie::chiffrage_cles::{Cipher, CipherResult};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use crate::error::Error as CommonError;

/// Loads or generates a domain backup key
pub async fn get_domain_backup_key(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain_name: &str,
) -> Result<DecryptedKey, CommonError> {

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
            load_backup_key(chiffrage, key_id.as_str()).await?
        },
        None => {
            warn!("Error requesting domain backup key, will generate a new one: {:?}", key_information.err);
            generate_backup_key_for_domain(outbound, chiffrage, domain_name).await?
        }
    };

    Ok(backup_key)
}

async fn load_backup_key(chiffrage: &dyn ChiffrageService, key_id: &str) -> Result<DecryptedKey, CommonError> {
    let reponse = chiffrage.get_keys(vec![key_id.to_string()]).await?;
    match reponse.into_iter().next() {
        Some(key) => Ok(key),
        None => Err(CommonError::String(format!("Backup key id {} not found", key_id)))
    }
}

async fn generate_backup_key_for_domain(
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    domain: &str
) -> Result<DecryptedKey, CommonError> {
    let new_key = chiffrage.generate_new_key(&vec![domain.to_string()]).await?;

    // Save the new backup key immediately
    chiffrage.save_keys(vec![new_key.clone()]).await?;

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
