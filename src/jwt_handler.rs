use log::{debug, error, info, warn};
use std::collections::BTreeMap;
use std::error::Error;

use jwt_simple::prelude::*;

use crate::certificats::{ValidateurX509, VerificateurPermissions};
use crate::common_messages::InformationDechiffrage;
use crate::constantes::{DOMAINE_NOM_GROSFICHIERS, DOMAINE_NOM_MESSAGERIE, RolesCertificats, Securite};
use crate::formatteur_messages::FormatteurMessage;
use crate::generateur_messages::GenerateurMessages;

pub const CONST_DUREE_TOKEN_VALIDE: u64 = 60 * 60 * 6;

#[derive(Debug, Serialize, Deserialize)]
struct ClaimsTokenFichier {
    #[serde(rename="userId")]
    user_id: Option<String>,
    // domaine: Option<String>,
    mimetype: Option<String>,

    // Dechiffrage
    #[serde(rename="ref")]
    ref_: Option<String>,
    header: Option<String>,
    // iv: Option<String>,
    tag: Option<String>,
    format: Option<String>
}

pub struct FichierClaims {
    pub fuuid: Option<String>,
    pub user_id: Option<String>,
}

pub async fn verify_jwt<M,S>(middleware: &M, jwt_token: S) -> Result<FichierClaims, crate::error::Error>
    where M: ValidateurX509, S: AsRef<str>
{
    let jwt_token = jwt_token.as_ref();

    let metadata = match Token::decode_metadata(&jwt_token) {
        Ok(inner) => inner,
        Err(e) => Err(crate::error::Error::String(format!("Erreur Token::decode_metatada : {:?}", e)))?
    };
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
    if ! enveloppe.verifier_domaines(vec![DOMAINE_NOM_MESSAGERIE.to_string(), DOMAINE_NOM_GROSFICHIERS.to_string()])? {
        Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un domaine supporte {}", fingerprint))?
    }
    if ! enveloppe.verifier_exchanges(vec![Securite::L4Secure])? {
        Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un exchange supporte (doit etre 4.secure) {}", fingerprint))?
    }
    // // TODO : Fix me - utiliser domaine (GrosFichiers, Messagerie). Pour l'instance c'est le niveau L2Prive ou L4Secure
    // if ! enveloppe.verifier_exchanges(vec![Securite::L2Prive, Securite::L4Secure]) {
    //     Err(format!("jwt_handler.verify_jwt Certificat signature n'a pas un exchange supporte {}", fingerprint))?
    // }

    let public_key = enveloppe.pubkey()?;  //cle_publique.as_ref(); //.as_ref();
    let key_ed25519 = match Ed25519PublicKey::from_bytes(public_key.as_slice()) {
        Ok(inner) => inner,
        Err(e) => Err(crate::error::Error::String(format!("Erreur Ed25519PublicKey::from_bytes {:?}", e)))?
    };
    let claims = match key_ed25519.verify_token::<ClaimsTokenFichier>(&jwt_token, None) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur key_ed25519.verify_token::<ClaimsTokenFichier> : {:?}",e ))?
    };
    debug!("verify_jwt Claims : {:?}", claims);

    let custom = claims.custom;

    Ok(FichierClaims {
        fuuid: claims.subject,
        user_id: custom.user_id,
    })
}

pub fn generer_jwt<M,F,U,T>(middleware: &M, user_id: U, fuuid: F, mimetype: T, dechiffrage: InformationDechiffrage)
    -> Result<String, crate::error::Error>
    where
        M: FormatteurMessage,
        F: ToString, U: ToString, T: ToString
{
    let user_id = user_id.to_string();
    let fuuid = fuuid.to_string();
    let mimetype = mimetype.to_string();

    let ref_fuuid = match dechiffrage.ref_hachage_bytes {
        Some(inner) => Some(inner),
        None => None
    };

    let format_chiffrage_string: &str = dechiffrage.format.into();
    let info_fichier = ClaimsTokenFichier {
        user_id: Some(user_id),
        // domaine: None,
        mimetype: Some(mimetype),
        ref_: ref_fuuid,
        header: dechiffrage.header,
        // iv: None,
        tag: dechiffrage.tag,
        format: Some(format_chiffrage_string.to_string()),
    };

    let mut claims = Claims::with_custom_claims(
        info_fichier, Duration::from_secs(CONST_DUREE_TOKEN_VALIDE));
    claims.subject = Some(fuuid);

    // Recuperer cle pour signer le token
    let enveloppe = middleware.get_enveloppe_signature();
    claims.issuer = Some(DOMAINE_NOM_GROSFICHIERS.into());
    let cle_privee = enveloppe.cle_privee.private_key_to_der()?;
    let cle_der = match Ed25519KeyPair::from_der(cle_privee.as_slice()) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Ed25519KeyPair::from_der : {:?}",e ))?
    };
    let cle_signature = cle_der.with_key_id(enveloppe.fingerprint()?.as_str());

    // Signer et retourner le nouveau token
    let jwt_token = match cle_signature.sign(claims) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur cle_signature.sign(claims) : {:?}",e ))?
    };
    Ok(jwt_token)
}