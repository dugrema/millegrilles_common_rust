use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::RandomState;

use chrono::{DateTime, Utc};
use log::{debug, error, info};
use multibase::{Base, decode};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use serde_json::{Map, Value};

use crate::certificats::EnveloppeCertificat;
use crate::formatteur_messages::{MessageJson, nettoyer_message};
use crate::hachages::verifier_multihash;
use crate::signatures::{SALT_LENGTH, VERSION_1};

pub struct ResultatValidation {
    pub signature_valide: bool,
    pub hachage_valide: Option<bool>,
    pub certificat_valide: bool,
    idmg: String,
    estampille: DateTime<Utc>,
}

impl ResultatValidation {
    pub fn valide(&self) -> bool {
        self.signature_valide && self.certificat_valide
    }
}

pub struct ValidationOptions {
    utiliser_idmg_message: bool,
    utiliser_date_message: bool,
    toujours_verifier_hachage: bool,
}

pub fn verifier_message(
    message: &MessageJson,
    certificat: &EnveloppeCertificat,
    idmg_local: &str,
    options: Option<ValidationOptions>
) -> Result<ResultatValidation, String> {

    let (utiliser_idmg_message, utiliser_date_message, toujours_verifier_hachage) = match options {
        Some(o) => (o.utiliser_idmg_message, o.utiliser_date_message, o.toujours_verifier_hachage),
        None => (false, false, false),
    };

    let idmg = message.get_idmg()?;
    let estampille = message.get_estampille()?;

    let mut certificat_idmg_valide = false;
    let mut certificat_date_valide = false;

    if utiliser_idmg_message == true {
        // S'assurer que le certificat correspond au idmg du message
        certificat_idmg_valide = idmg == certificat.idmg()?;
    } else {
        // Utiliser le IDMG de la MilleGrille locale
        certificat_idmg_valide = idmg == idmg_local;

        if certificat_idmg_valide == false {
            debug!("Message invalide, idmg certificat {} ne correspond pas au idmg local {}", idmg, idmg_local);
        }

    }

    if utiliser_date_message == true {
        // Utiliser la date du message pour confirmer que le certificat est valide
        todo!()
    } else {
        // Le certificat doit etre valide presentement
        if certificat.presentement_valide {
            // Le certificat est presentement valide, on s'assure que l'estampille du message correspond.
            certificat_date_valide = estampille <= certificat.not_valid_after()? &&
                estampille >= certificat.not_valid_before()?;

            if certificat_date_valide == false {
                debug!("Message invalide, date estampille {} n'est pas entre {:?} et {:?}",
                    estampille, certificat.not_valid_before(), certificat.not_valid_after());
            }

        } else if certificat_idmg_valide == true {
            // Le certificat pourrait ne pas etre valide parce que le idmg est celui d'un tiers
            //certificat.
            todo!()
        }
    }

    // On verifie la signature - si valide, court-circuite le reste de la validation.
    let public_key = match certificat.certificat().public_key() {
        Ok(p) => Ok(p),
        Err(e) => Err(format!("Erreur extraction public_key du certificat : {:?}", e)),
    }?;

    let resultat_verifier_signature = match verifier_signature(&public_key, message) {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("Erreur verification signature message : {:?}", e)),
    }?;

    if resultat_verifier_signature == true && toujours_verifier_hachage == false {
        // La signature est valide, on court-circuite le hachage.
        return Ok(ResultatValidation{
            signature_valide: true,
            hachage_valide: None,
            certificat_valide: certificat_idmg_valide && certificat_date_valide,
            idmg,
            estampille,
        })
    };

    // La signature n'est pas valide, on verifie le hachage (troubleshooting)
    let hachage_valide = match verifier_hachage(message) {
        Ok(h) => Ok(h),
        Err(e) => Err(format!("Erreur verification du message : {:?}", e)),
    }?;

    Ok(ResultatValidation{
        signature_valide: false,
        hachage_valide: Some(hachage_valide),
        certificat_valide: certificat_idmg_valide && certificat_date_valide,
        idmg,
        estampille,
    })
}

pub fn verifier_hachage(message: &MessageJson) -> Result<bool, ErrorStack> {
    let (mut message_modifie, _): (BTreeMap<String, Value>, _) = nettoyer_message(message);

    let key_entete = String::from("en-tete");
    let (_, entete) = message_modifie.remove_entry(&key_entete).unwrap();
    let contenu_str: String = serde_json::to_string(&message_modifie).unwrap();

    let key_hachage = "hachage_contenu";
    let hachage_str = entete.get(&key_hachage).unwrap().as_str().unwrap();

    verifier_multihash(hachage_str, contenu_str.as_bytes())
}

pub fn verifier_signature(public_key: &PKey<Public>, message: &MessageJson) -> Result<bool, ErrorStack> {
    let (mut message_modifie, _): (BTreeMap<String, Value>, _) = nettoyer_message(message);

    let signature = message.get_message().get("_signature").unwrap().as_str().unwrap();
    debug!("Signature : {}", signature);

    let contenu_str: String = serde_json::to_string(&message_modifie).unwrap();

    debug!("Message a verifier (signature)\n{}", contenu_str);

    let signature_bytes: (Base, Vec<u8>) = decode(signature).unwrap();
    let version_signature = signature_bytes.1[0];
    assert_eq!(VERSION_1, version_signature);

    let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
    verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH))?;
    verifier.update(contenu_str.as_bytes())?;

    // Retourner la reponse
    verifier.verify(&signature_bytes.1[1..])
}
