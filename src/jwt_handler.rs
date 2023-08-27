use log::{debug, error, info, warn};
use std::collections::BTreeMap;
use std::error::Error;

use jwt_simple::prelude::*;

use crate::certificats::{ValidateurX509, VerificateurPermissions};
use crate::constantes::{DOMAINE_NOM_MESSAGERIE, RolesCertificats, Securite};
use crate::generateur_messages::GenerateurMessages;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClaimsTokenFichier {
    #[serde(rename="userId")]
    user_id: Option<String>,
}

pub struct FichierClaims {
    pub fuuid: Option<String>,
    pub user_id: Option<String>,
}

pub async fn verify_jwt<M,S>(middleware: &M, jwt_token: S) -> Result<FichierClaims, Box<dyn Error>>
    where M: ValidateurX509, S: AsRef<str>
{
    let jwt_token = jwt_token.as_ref();

    let metadata = Token::decode_metadata(&jwt_token)?;
    let fingerprint = match metadata.key_id() {
        Some(inner) => inner,
        None => Err(format!("jwt_handler.verify_jwt fingerprint (kid) manquant du JWT"))?
    };

    debug!("verify_jwt Token fingerprint (kid) : {}", fingerprint);

    let enveloppe = match middleware.get_certificat(fingerprint).await {
        Some(inner) => inner,
        None => Err(format!("jwt_handler.verify_jwt Certificat inconnu pour fingerprint {}", fingerprint))?
    };

    // Verifier le domaine de l'enveloppe
    // if ! enveloppe.verifier_domaines(vec![DOMAINE_NOM_MESSAGERIE, DOMAINE_NOM_GROSFICHIERS]) {
    //     Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un domaine supporte {}", fingerprint))?
    // }
    // TODO : Fix me - utiliser domaine (GrosFichiers, Messagerie). Pour l'instance c'est le niveau L2Prive ou L4Secure
    if ! enveloppe.verifier_exchanges(vec![Securite::L2Prive, Securite::L4Secure]) {
        Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un exchange supporte {}", fingerprint))?
    }

    let key = enveloppe.cle_publique.as_ref(); //.as_ref();
    let key_ed25519 = Ed25519PublicKey::from_bytes(key.raw_public_key()?.as_slice())?;
    let claims = key_ed25519.verify_token::<ClaimsTokenFichier>(&jwt_token, None)?;
    debug!("verify_jwt Claims : {:?}", claims);

    let custom = claims.custom;

    Ok(FichierClaims {
        fuuid: claims.subject,
        user_id: custom.user_id,
    })
}
