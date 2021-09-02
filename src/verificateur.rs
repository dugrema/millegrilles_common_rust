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
use std::error::Error;
use crate::{MessageMilleGrille, MqMessageSendInformation, MessageSerialise};

pub trait VerificateurMessage {
    fn verifier_message(
        &self,
        message: &MessageSerialise,
        options: Option<ValidationOptions>
    ) -> Result<ResultatValidation, Box<dyn Error>>;
}

#[derive(Clone, Debug)]
pub struct ResultatValidation {
    pub signature_valide: bool,
    pub hachage_valide: Option<bool>,
    pub certificat_valide: bool,
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
    message: &MessageSerialise,
    idmg_local: &str,
    options: Option<&ValidationOptions>
) -> Result<ResultatValidation, Box<dyn Error>> {

    let (utiliser_idmg_message, utiliser_date_message, toujours_verifier_hachage) = match options {
        Some(o) => (o.utiliser_idmg_message, o.utiliser_date_message, o.toujours_verifier_hachage),
        None => (false, false, false),
    };

    let entete = message.get_entete();
    let idmg = entete.idmg.as_str();
    let estampille = entete.estampille.get_datetime();
    let certificat = match &message.certificat {
        Some(c) => c.as_ref(),
        None => Err("Certificat manquant")?,
    };
    let signature = match &message.get_msg().signature {
        Some(s) => s.as_str(),
        None => Err("Signature manquante")?,
    };

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
            certificat_date_valide = estampille <= &certificat.not_valid_after()? &&
                estampille >= &certificat.not_valid_before()?;

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

    let contenu_string = MessageMilleGrille::preparer_pour_signature(entete, &message.get_msg().contenu)?;
    debug!("Message a verifier (signature)\n{}", contenu_string);

    let resultat_verifier_signature = match verifier_signature_str(&public_key, signature, contenu_string.as_str()) {
        Ok(r) => Ok(r),
        Err(e) => Err(format!("Erreur verification signature message : {:?}", e)),
    }?;

    if resultat_verifier_signature == true && toujours_verifier_hachage == false {
        // La signature est valide, on court-circuite le hachage.
        return Ok(ResultatValidation{
            signature_valide: true,
            hachage_valide: None,
            certificat_valide: certificat_idmg_valide && certificat_date_valide,
        })
    };

    // La signature n'est pas valide, on verifie le hachage (troubleshooting)
    let hachage_valide = match verifier_hachage(message.get_msg()) {
        Ok(h) => Ok(h),
        Err(e) => Err(format!("Erreur verification du message : {:?}", e)),
    }?;

    Ok(ResultatValidation{
        signature_valide: false,
        hachage_valide: Some(hachage_valide),
        certificat_valide: certificat_idmg_valide && certificat_date_valide,
    })
}

pub fn verifier_hachage(message: &MessageMilleGrille) -> Result<bool, Box<dyn Error>> {
    let entete = &message.entete;
    let hachage_str = &entete.hachage_contenu;
    let contenu_string = MessageMilleGrille::preparer_pour_hachage(&message.contenu)?;

    verifier_multihash(hachage_str, contenu_string.as_bytes())
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

pub fn verifier_signature_str(public_key: &PKey<Public>, signature: &str, message: &str) -> Result<bool, Box<dyn Error>> {
    // let entete = message.get_entete();
    // let contenu = &message.get_msg().contenu;
    //
    // let signature = match &message.get_msg().signature {
    //     Some(s) => s.as_str(),
    //     None => Err("Signature manquante")?,
    // };
    // let certificat = match &message.certificat {
    //     Some(c) => c.as_ref(),
    //     None => Err("Certificat manquant")?,
    // };
    // let public_key = certificat.certificat().public_key()?;
    // debug!("Signature : {}, certificat {:?}", signature, certificat);

    // let contenu_str = MessageMilleGrille::preparer_pour_signature(entete, contenu)?;
    debug!("Message a verifier (signature)\n{}", message);

    let signature_bytes: (Base, Vec<u8>) = decode(signature).unwrap();
    let version_signature = signature_bytes.1[0];
    assert_eq!(VERSION_1, version_signature);

    let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
    verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH))?;
    verifier.update(message.as_bytes())?;

    // Retourner la reponse
    Ok(verifier.verify(&signature_bytes.1[1..])?)
}
