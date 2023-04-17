use std::error::Error;

use log::debug;
use openssl::pkey::{PKey, Public};
use serde::Serialize;
use serde_json::Value;

use crate::certificats::VerificateurRegles;
use crate::certificats::ValidateurX509;
use crate::formatteur_messages::{MessageSerialise, preparer_btree_recursif, map_valeur_recursif};
use crate::signatures::verifier_message as ref_verifier_message;

pub trait VerificateurMessage {
    fn verifier_message(
        &self,
        message: &mut MessageSerialise,
        options: Option<&ValidationOptions>
    ) -> Result<ResultatValidation, Box<dyn Error>>;
}

#[derive(Clone, Debug)]
pub struct ResultatValidation {
    pub signature_valide: bool,
    pub hachage_valide: Option<bool>,
    pub certificat_valide: bool,
    pub regles_valides: bool,
}

impl ResultatValidation {
    pub fn new(signature_valide: bool, hachage_valide: Option<bool>, certificat_valide: bool, regles_valides: bool) -> Self {
        ResultatValidation {
            signature_valide,
            hachage_valide,
            certificat_valide,
            regles_valides,
        }
    }

    pub fn valide(&self) -> bool {
        self.signature_valide && self.certificat_valide && self.regles_valides
    }
}

#[derive(Debug)]
pub struct ValidationOptions<'a> {
    utiliser_idmg_message: bool,
    utiliser_date_message: bool,
    toujours_verifier_hachage: bool,
    pub verificateur: Option<&'a VerificateurRegles<'a>>,
}

impl ValidationOptions<'_> {
    pub fn new(utiliser_idmg_message: bool, utiliser_date_message: bool, toujours_verifier_hachage: bool) -> Self {
        ValidationOptions {
            utiliser_idmg_message,
            utiliser_date_message,
            toujours_verifier_hachage,
            verificateur: None
        }
    }
}

pub fn verifier_message<V>(
    message: &mut MessageSerialise,
    validateur: &V,
    options: Option<&ValidationOptions>
) -> Result<ResultatValidation, Box<dyn Error>>
where
    V: ValidateurX509,
{
    debug!("Verifier message {:?}\nOptions : {:?}", message, options);

    let (utiliser_idmg_message, utiliser_date_message, toujours_verifier_hachage, verificateur) = match options {
        Some(o) => (o.utiliser_idmg_message, o.utiliser_date_message, o.toujours_verifier_hachage, o.verificateur),
        None => (false, false, false, None),
    };

    // let entete = message.get_entete().clone();
    // let idmg = entete.idmg.as_str();
    let estampille = message.parsed.estampille.get_datetime();
    let uuid_transaction = &message.parsed.id;
    let certificat = match &message.certificat {
        Some(c) => c.as_ref(),
        None => Err("Verificateur.verifier_message Certificat manquant")?,
    };

    // Verifier les regles de validation custom du certificat
    let regles_ok = match verificateur {
        Some(v) => {
            // Verifier les regles de certificat
            debug!("Verifier regles message {:?}", message);
            v.verifier(certificat)
        },
        None => true
    };

    let certificat_idmg_valide = match utiliser_idmg_message {
        true => {
            let idmg_cert = certificat.idmg()?;
            // let msg_match_certificat = idmg == idmg_cert.as_str();
            let msg_match_certificat = true;  // Le idmg n'est plus dans le message
            if msg_match_certificat {
                // Verifier si le IDMG est local ou celui d'un tiers
                let idmg_validateur = validateur.idmg();
                let certificat_millegrille = match idmg_validateur == idmg_cert.as_str() {
                    true => None,  // IDMG local, on utilise store local
                    false => {
                        debug!("Message avec idmg tiers : {}, verifier avec {:?}", idmg_cert.as_str(), message.millegrille);
                        match &message.millegrille {
                            Some(certmg) => Some(certmg.as_ref()),
                            None => Err(format!("verifier_message certificat de millegrille tiers manquant (_millegrille)"))?
                        }
                    }  // IDMG tiers, on va devoir batir un nouveau store
                };
                let resultat = validateur.valider_chaine(certificat, certificat_millegrille)?;
                debug!("verifier_message Resultat valider chaine : {}", resultat);
                resultat
            } else {
                false
            }
        },
        false => true  // idmg == validateur.idmg()  ** Idmg n'est plus un champ du message
    };
    let certificat_date_valide = match utiliser_date_message {
        true => {
            validateur.valider_pour_date(certificat, estampille)?
        },
        false => certificat.presentement_valide
    };

    // Le certificat est valide pour le message, on s'assure que l'estampille du message correspond.
    let message_date_valide = estampille <= &certificat.not_valid_after()? &&
        estampille >= &certificat.not_valid_before()?;

    // On verifie la signature - si valide, court-circuite le reste de la validation.
    // let public_key = match certificat.certificat().public_key() {
    //     Ok(p) => Ok(p),
    //     Err(e) => Err(format!("Erreur extraction public_key du certificat : {:?}", e)),
    // }?;

    // let resultat_verifier_signature = message.parsed.verifier_signature(&public_key)?;
    let resultat_verifier_message = message.parsed.verifier_contenu()?;

    // if resultat_verifier_signature == true && toujours_verifier_hachage == false {
        // La signature est valide, on court-circuite le hachage.
        return Ok(ResultatValidation{
            signature_valide: resultat_verifier_message,
            hachage_valide: Some(resultat_verifier_message),
            certificat_valide: certificat_idmg_valide && certificat_date_valide && message_date_valide,
            regles_valides: regles_ok,
        })
    // } else if resultat_verifier_signature == false {
    //     debug!("Signature invalide pour message {}", uuid_transaction);
    // }
    //
    // // La signature n'est pas valide, on verifie le hachage (troubleshooting)
    // let hachage_valide = match message.parsed.verifier_hachage() {
    //     Ok(h) => Ok(h),
    //     Err(e) => Err(format!("Erreur verification du message : {:?}", e)),
    // }?;
    //
    // debug!("Certificat {} idmg: {}, cert date {}, msg date {}", certificat.fingerprint, certificat_idmg_valide, certificat_date_valide, message_date_valide);
    //
    // Ok(ResultatValidation{
    //     signature_valide: resultat_verifier_signature,
    //     hachage_valide: Some(hachage_valide),
    //     certificat_valide: certificat_idmg_valide && certificat_date_valide && message_date_valide,
    //     regles_valides: regles_ok,
    // })
}

pub fn verifier_signature_str(public_key: &PKey<Public>, signature: &str, message: &str) -> Result<bool, Box<dyn Error>> {
    ref_verifier_message(public_key, message.as_bytes(), signature)
}

pub fn verifier_signature_serialize<S>(public_key: &PKey<Public>, signature: &str, message: &S)
    -> Result<bool, Box<dyn Error>>
    where S: Serialize
{
    let content = {
        let val = serde_json::to_value(message)?;
        let map_val = match val.as_object() {
            Some(v) => Value::Object(preparer_btree_recursif(v.clone())?),
            None => map_valeur_recursif(val)?
        };

        serde_json::to_string(&map_val)?
    };

    debug!("verifier_signature_serialize Contenu a verifier : \n{}", content.as_str());
    verifier_signature_str(public_key, signature, content.as_str())
}

#[cfg(test)]
mod verificateur_tests {
    use super::*;

    use std::sync::Arc;
    use openssl::x509::store::X509Store;
    use openssl::x509::X509;
    use crate::certificats::EnveloppeCertificat;
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;

    use crate::test_setup::setup;

    const CATALOGUE_1: &str = "{\"dependances\": [{\"certificat\": {\"domaines\": [\"MaitreDesCles\"], \"exchanges\": [\"4.secure\", \"3.protege\", \"2.prive\", \"1.public\"], \"roles\": [\"maitredescles\", \"maitrecles\"]}, \"configs\": [{\"current\": \"cert\", \"filename\": \"/run/secrets/cert.pem\", \"name\": \"pki.maitredescles\"}, {\"filename\": \"/run/secrets/millegrille.cert.pem\", \"name\": \"pki.millegrille\"}], \"constraints\": [\"node.labels.millegrilles.maitredescles == true\"], \"env\": {\"CAFILE\": \"/run/secrets/millegrille.cert.pem\", \"CERTFILE\": \"/run/secrets/cert.pem\", \"KEYFILE\": \"/run/secrets/key.pem\", \"MG_MAITREDESCLES_MODE\": \"partition\", \"MG_MONGO_HOST\": \"mongo\", \"MG_MQ_AUTH_CERT\": \"on\", \"MG_MQ_HOST\": \"mq\", \"MG_MQ_PORT\": \"5673\", \"MG_MQ_SSL\": \"on\", \"MG_REDIS_PASSWORD_FILE\": \"/run/secrets/passwd.redis.txt\", \"MG_REDIS_URL\": \"rediss://client_rust@redis:6379#insecure\", \"RUST_LOG\": \"warn\"}, \"image\": \"docker.maceroc.com/millegrilles_maitredescles:2022.6.0\", \"mode\": {\"mode\": \"replicated\", \"replicas\": 1}, \"name\": \"maitredescles\", \"networks\": [{\"target\": \"millegrille_net\"}], \"resources\": {\"cpu_limit\": 1000000000, \"mem_limit\": 250000000}, \"restart_policy\": {\"condition\": \"on-failure\", \"delay\": 60000000000, \"max_attempts\": 2}, \"secrets\": [{\"current\": \"key\", \"filename\": \"key.pem\", \"name\": \"pki.maitredescles\"}, {\"current\": \"password\", \"filename\": \"passwd.redis.txt\", \"name\": \"passwd.redis\"}]}], \"nom\": \"maitredescles\", \"securite\": \"4.secure\", \"version\": \"2022.6.0\", \"en-tete\": {\"idmg\": \"zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf\", \"uuid_transaction\": \"c1698a20-39f1-11ed-9d27-37d984004598\", \"estampille\": 1663794601, \"version\": 1, \"domaine\": \"CoreCatalogues\", \"action\": \"catalogueApplication\", \"hachage_contenu\": \"m4OQCIJ5oAjz5IWrM1ABTEdu2s5FwOPz9KOWDzW3QewNuck4Y\", \"fingerprint_certificat\": \"z2i3XjxATYCJd5Lns3yTDWPAE4VYsbosQ6CUzSAR43EJCETUKGx\"}, \"_signature\": \"mAnk7YPHkuZxky86cijr136stv6jGni09AfCdzKev+Bf1fH4R3sLlzfgfxA+lGuG/hMgk7xAZ9lDZUw1xnOfxrAU\", \"_certificat\": [\"-----BEGIN CERTIFICATE-----\\nMIIClDCCAkagAwIBAgIUfJOwAg7KNg3EWTT+JB5BkJTzDHMwBQYDK2VwMHIxLTAr\\nBgNVBAMTJDI2Yzc0YmYwLWE1NWUtNDBjYi04M2U2LTdlYTgxOGUyZDQxNjFBMD8G\\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\\nWHJwMjJiQXR3R203SmYwHhcNMjIwOTE2MTA0MzI2WhcNMjIxMDE3MTA0MzQ2WjCB\\ngTEtMCsGA1UEAwwkMjZjNzRiZjAtYTU1ZS00MGNiLTgzZTYtN2VhODE4ZTJkNDE2\\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhAOqv\\neCTQlPtt1FyQjY6l6opfqkrkUEl4nuP1hIOdUdmVo4HdMIHaMCsGBCoDBAAEIzQu\\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\\nBgNVHSMEGDAWgBQD9vRntL7qirUyHq9zmcG45Z47gzAdBgNVHQ4EFgQUQL5Qblu0\\n6QOndvsWEtt/4P1pMqIwBQYDK2VwA0EAVySc4PByHK4EDggd2e+vmMgsWTUaBDJk\\nvH06j7z3tq6IMNTAfVEJkyo0hWk/j6Sj6nsQVFl3L4e8DC5ONksDDg==\\n-----END CERTIFICATE-----\", \"-----BEGIN CERTIFICATE-----\\r\\nMIIBozCCAVWgAwIBAgIKEUVzkzZwaSQpWDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\\r\\nbGVHcmlsbGUwHhcNMjIwOTE2MTA0MzM1WhcNMjQwMzI3MTA0MzM1WjByMS0wKwYD\\r\\nVQQDEyQyNmM3NGJmMC1hNTVlLTQwY2ItODNlNi03ZWE4MThlMmQ0MTYxQTA/BgNV\\r\\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\\r\\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAFEBEdYuof2APUzJCq75LwIrPK71xO6OW\\r\\n/yS7q6/dQkqjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\\r\\nA1UdDgQWBBQD9vRntL7qirUyHq9zmcG45Z47gzAfBgNVHSMEGDAWgBTTiP/MFw4D\\r\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQD3h5RSRWUsRZ157odrEaDllF0zIVIYtRL8\\r\\na+mLFw+8ZO7uqwZXbTvfaj4x6uvobeMmUQpV4rIedDHRFxZoJn4C\\n-----END CERTIFICATE-----\"], \"_millegrille\": \"-----BEGIN CERTIFICATE-----\\nMIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs\\nZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV\\nBAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I\\n/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G\\nA1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p\\nMJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI\\n-----END CERTIFICATE-----\\n\"}";
    const CATALOGUE_2: &str = "{\"dependances\": [{\"certificat\": {\"domaines\": [\"MaitreDesCles\"], \"exchanges\": [\"4.secure\", \"3.protege\", \"2.prive\", \"1.public\"], \"roles\": [\"maitredescles\", \"maitrecles\"]}, \"configs\": [{\"current\": \"cert\", \"filename\": \"/run/secrets/cert.pem\", \"name\": \"pki.maitredescles\"}, {\"filename\": \"/run/secrets/millegrille.cert.pem\", \"name\": \"pki.millegrille\"}], \"constraints\": [\"node.labels.millegrilles.maitredescles == true\"], \"env\": {\"CAFILE\": \"/run/secrets/millegrille.cert.pem\", \"CERTFILE\": \"/run/secrets/cert.pem\", \"KEYFILE\": \"/run/secrets/key.pem\", \"MG_MAITREDESCLES_MODE\": \"partition\", \"MG_MONGO_HOST\": \"mongo\", \"MG_MQ_AUTH_CERT\": \"on\", \"MG_MQ_HOST\": \"mq\", \"MG_MQ_PORT\": \"5673\", \"MG_MQ_SSL\": \"on\", \"MG_REDIS_PASSWORD_FILE\": \"/run/secrets/passwd.redis.txt\", \"MG_REDIS_URL\": \"rediss://client_rust@redis:6379#insecure\", \"RUST_LOG\": \"warn\"}, \"image\": \"docker.maceroc.com/millegrilles_maitredescles:2022.6.0\", \"mode\": {\"mode\": \"replicated\", \"replicas\": 1}, \"name\": \"maitredescles\", \"networks\": [{\"target\": \"millegrille_net\"}], \"resources\": {\"cpu_limit\": 1000000000, \"mem_limit\": 250000000}, \"restart_policy\": {\"condition\": \"on-failure\", \"delay\": 60000000000, \"max_attempts\": 2}, \"secrets\": [{\"current\": \"key\", \"filename\": \"key.pem\", \"name\": \"pki.maitredescles\"}, {\"current\": \"password\", \"filename\": \"passwd.redis.txt\", \"name\": \"passwd.redis\"}]}], \"nom\": \"maitredescles\", \"securite\": \"4.secure\", \"version\": \"2022.6.0\", \"en-tete\": {\"idmg\": \"zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf\", \"uuid_transaction\": \"c1698a20-39f1-11ed-9d27-37d984004598\", \"estampille\": 1663794601, \"version\": 1, \"domaine\": \"CoreCatalogues\", \"action\": \"catalogueApplication\", \"hachage_contenu\": \"m4OQCIJ5oAjz5IWrM1ABTEdu2s5FwOPz9KOWDzW3QewNuck4Y\", \"fingerprint_certificat\": \"z2i3XjxATYCJd5Lns3yTDWPAE4VYsbosQ6CUzSAR43EJCETUKGx\"}, \"_signature\": \"mAnk7YPHkuZxky86cijr136stv6jGni09AfCdzKev+Bf1fH4R3sLlzfgfxA+lGuG/hMgk7xAZ9lDZUw1xnOfxrAU\", \"_certificat\": [\"-----BEGIN CERTIFICATE-----\\nMIIClDCCAkagAwIBAgIUfJOwAg7KNg3EWTT+JB5BkJTzDHMwBQYDK2VwMHIxLTAr\\nBgNVBAMTJDI2Yzc0YmYwLWE1NWUtNDBjYi04M2U2LTdlYTgxOGUyZDQxNjFBMD8G\\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\\nWHJwMjJiQXR3R203SmYwHhcNMjIwOTE2MTA0MzI2WhcNMjIxMDE3MTA0MzQ2WjCB\\ngTEtMCsGA1UEAwwkMjZjNzRiZjAtYTU1ZS00MGNiLTgzZTYtN2VhODE4ZTJkNDE2\\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhAOqv\\neCTQlPtt1FyQjY6l6opfqkrkUEl4nuP1hIOdUdmVo4HdMIHaMCsGBCoDBAAEIzQu\\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\\nBgNVHSMEGDAWgBQD9vRntL7qirUyHq9zmcG45Z47gzAdBgNVHQ4EFgQUQL5Qblu0\\n6QOndvsWEtt/4P1pMqIwBQYDK2VwA0EAVySc4PByHK4EDggd2e+vmMgsWTUaBDJk\\nvH06j7z3tq6IMNTAfVEJkyo0hWk/j6Sj6nsQVFl3L4e8DC5ONksDDg==\\n-----END CERTIFICATE-----\", \"-----BEGIN CERTIFICATE-----\\r\\nMIIBozCCAVWgAwIBAgIKEUVzkzZwaSQpWDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\\r\\nbGVHcmlsbGUwHhcNMjIwOTE2MTA0MzM1WhcNMjQwMzI3MTA0MzM1WjByMS0wKwYD\\r\\nVQQDEyQyNmM3NGJmMC1hNTVlLTQwY2ItODNlNi03ZWE4MThlMmQ0MTYxQTA/BgNV\\r\\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\\r\\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAFEBEdYuof2APUzJCq75LwIrPK71xO6OW\\r\\n/yS7q6/dQkqjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\\r\\nA1UdDgQWBBQD9vRntL7qirUyHq9zmcG45Z47gzAfBgNVHSMEGDAWgBTTiP/MFw4D\\r\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQD3h5RSRWUsRZ157odrEaDllF0zIVIYtRL8\\r\\na+mLFw+8ZO7uqwZXbTvfaj4x6uvobeMmUQpV4rIedDHRFxZoJn4C\\n-----END CERTIFICATE-----\"], \"_millegrille\": \"-----BEGIN CERTIFICATE-----\\nMIIBQzCB9qADAgECAgoJCXgQCXBSIyGXMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs\\nZUdyaWxsZTAeFw0yMjA5MjUxNzI2MTFaFw00MjA5MjUxNzI2MTFaMBYxFDASBgNV\\nBAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAjnhGdFu7+cxMnjGDyeJJ780GrLzy\\nbqnBqWd8zVRNvvijYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G\\nA1UdDgQWBBTjl7ksVf5vyrK65FmsvmnzmUvMUTAfBgNVHSMEGDAWgBTjl7ksVf5v\\nyrK65FmsvmnzmUvMUTAFBgMrZXADQQCUJI3AiLHKqVZrzJEewaEx+wyrbXw56O10\\nCuDlqpxzKtb1JF7kb6ouveLdLi5UzRi8d0C4d5FlYzD0zws1rA0L\\n-----END CERTIFICATE-----\"}";
    const MESSAGE_1: &str = "{  \"_certificat\": [    \"-----BEGIN CERTIFICATE-----\\nMIICZDCCAhagAwIBAgIUQQEEcaO6q7KPFG1xP3VtHjPo7gkwBQYDK2VwMHIxLTAr\\nBgNVBAMTJGM1NTE2ODRkLTc4N2YtNDNmYy05ZjJjLWRiNGFiMmM2ZGQ3NTFBMD8G\\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\\nWHJwMjJiQXR3R203SmYwHhcNMjMwMTA0MTM0MjEyWhcNMjMwMjA0MTM0MjMyWjCB\\njDEtMCsGA1UEAwwkYzU1MTY4NGQtNzg3Zi00M2ZjLTlmMmMtZGI0YWIyYzZkZDc1\\nMRgwFgYDVQQLDA9zZW5zZXVyc3Bhc3NpZnMxQTA/BgNVBAoMOHplWW5jUnFFcVo2\\nZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhycDIyYkF0d0dtN0pmMCow\\nBQYDK2VwAyEAwJJh4+TE6gq4xc2QqSx0sqwhyBa4EhJuErPz6UAJLQmjgaIwgZ8w\\nKwYEKgMEAAQjNC5zZWN1cmUsMy5wcm90ZWdlLDIucHJpdmUsMS5wdWJsaWMwFwYE\\nKgMEAQQPc2Vuc2V1cnNwYXNzaWZzMBcGBCoDBAIED1NlbnNldXJzUGFzc2lmczAf\\nBgNVHSMEGDAWgBRHjT6DcEgMWcWbXCWfMpeuUWMwLzAdBgNVHQ4EFgQU66DGA96D\\n4/HSMDsoQpCtLX3kDSYwBQYDK2VwA0EA2rR9TmemOwDHfEv9UXsob2ypcOdphTGy\\nXgFcRo5gKH8POZzCiYKuaE8abGnI4P7ZgWT/Ky3Drdn50lCQEW01AA==\\n-----END CERTIFICATE-----\\n\",    \"-----BEGIN CERTIFICATE-----\\nMIIBozCCAVWgAwIBAgIKA2eGMGBSlYWZMTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\\nbGVHcmlsbGUwHhcNMjIxMjA4MjIzOTIwWhcNMjQwNjE4MjIzOTIwWjByMS0wKwYD\\nVQQDEyRjNTUxNjg0ZC03ODdmLTQzZmMtOWYyYy1kYjRhYjJjNmRkNzUxQTA/BgNV\\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAw9Ad50QMyE9X0vAtFHGICKRyyu7j3wuO\\nnUaC4bwwQo+jYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\\nA1UdDgQWBBRHjT6DcEgMWcWbXCWfMpeuUWMwLzAfBgNVHSMEGDAWgBTTiP/MFw4D\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQC1NpJptK9fZxNaVWl2hPzeoDi6CsohWbQ6\\neBciqksWvE8o+S8PIqHzHhbQsXMsqDGerlWCXi0yzsg618gPBK0B\\n-----END CERTIFICATE-----\\n\"  ],  \"_signature\": \"mAscUM3yU8rgarc395Mq0rY6uzEXxQDuXQk12DFqkIp+duCkEMryPXG8Ke5O9jY8q7BiOnYYstw6hvixYXEfSMAk\",  \"avg\": 100.89384313725489,  \"en-tete\": {    \"action\": \"senseurHoraire\",    \"domaine\": \"SenseursPassifs\",    \"estampille\": 1672858502,    \"fingerprint_certificat\": \"z2i3XjxKEzSLur1NnpoAaSVtm848REihLt9uCJiiX28NSXVBVsF\",    \"hachage_contenu\": \"mEiCwBPHx+aeSLVRsdQS6Yh3JZy8PhmhFsL1lYlnUnmd77A\",    \"idmg\": \"zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf\",    \"uuid_transaction\": \"86cfe76a-1481-4431-9a77-9029e529ce5f\",    \"version\": 1  },  \"heure\": 1672848000,  \"lectures\": [    {      \"timestamp\": 1672848027,      \"type\": \"pression\",      \"valeur\": 100.954    },    {      \"timestamp\": 1672848050,      \"type\": \"pression\",      \"valeur\": 100.957    },    {      \"timestamp\": 1672848137,      \"type\": \"pression\",      \"valeur\": 100.946    },    {      \"timestamp\": 1672848146,      \"type\": \"pression\",      \"valeur\": 100.946    },    {      \"timestamp\": 1672848173,      \"type\": \"pression\",      \"valeur\": 100.942    },    {      \"timestamp\": 1672848196,      \"type\": \"pression\",      \"valeur\": 100.941    },    {      \"timestamp\": 1672848226,      \"type\": \"pression\",      \"valeur\": 100.93    },    {      \"timestamp\": 1672848249,      \"type\": \"pression\",      \"valeur\": 100.924    },    {      \"timestamp\": 1672848279,      \"type\": \"pression\",      \"valeur\": 100.923    },    {      \"timestamp\": 1672848302,      \"type\": \"pression\",      \"valeur\": 100.919    },    {      \"timestamp\": 1672848332,      \"type\": \"pression\",      \"valeur\": 100.915    },    {      \"timestamp\": 1672848356,      \"type\": \"pression\",      \"valeur\": 100.907    },    {      \"timestamp\": 1672848384,      \"type\": \"pression\",      \"valeur\": 100.909    },    {      \"timestamp\": 1672848408,      \"type\": \"pression\",      \"valeur\": 100.908    },    {      \"timestamp\": 1672848437,      \"type\": \"pression\",      \"valeur\": 100.911    },    {      \"timestamp\": 1672848460,      \"type\": \"pression\",      \"valeur\": 100.909    },    {      \"timestamp\": 1672848489,      \"type\": \"pression\",      \"valeur\": 100.911    },    {      \"timestamp\": 1672848512,      \"type\": \"pression\",      \"valeur\": 100.907    },    {      \"timestamp\": 1672848542,      \"type\": \"pression\",      \"valeur\": 100.914    },    {      \"timestamp\": 1672849883,      \"type\": \"pression\",      \"valeur\": 100.908    },    {      \"timestamp\": 1672849912,      \"type\": \"pression\",      \"valeur\": 100.908    },    {      \"timestamp\": 1672849935,      \"type\": \"pression\",      \"valeur\": 100.903    },    {      \"timestamp\": 1672849964,      \"type\": \"pression\",      \"valeur\": 100.902    },    {      \"timestamp\": 1672849987,      \"type\": \"pression\",      \"valeur\": 100.899    },    {      \"timestamp\": 1672850016,      \"type\": \"pression\",      \"valeur\": 100.896    },    {      \"timestamp\": 1672850039,      \"type\": \"pression\",      \"valeur\": 100.9    },    {      \"timestamp\": 1672850068,      \"type\": \"pression\",      \"valeur\": 100.896    },    {      \"timestamp\": 1672850091,      \"type\": \"pression\",      \"valeur\": 100.891    },    {      \"timestamp\": 1672850795,      \"type\": \"pression\",      \"valeur\": 100.865    },    {      \"timestamp\": 1672850818,      \"type\": \"pression\",      \"valeur\": 100.868    },    {      \"timestamp\": 1672850847,      \"type\": \"pression\",      \"valeur\": 100.874    },    {      \"timestamp\": 1672850871,      \"type\": \"pression\",      \"valeur\": 100.868    },    {      \"timestamp\": 1672850902,      \"type\": \"pression\",      \"valeur\": 100.872    },    {      \"timestamp\": 1672850938,      \"type\": \"pression\",      \"valeur\": 100.872    },    {      \"timestamp\": 1672850970,      \"type\": \"pression\",      \"valeur\": 100.874    },    {      \"timestamp\": 1672850998,      \"type\": \"pression\",      \"valeur\": 100.865    },    {      \"timestamp\": 1672851022,      \"type\": \"pression\",      \"valeur\": 100.871    },    {      \"timestamp\": 1672851050,      \"type\": \"pression\",      \"valeur\": 100.86    },    {      \"timestamp\": 1672851073,      \"type\": \"pression\",      \"valeur\": 100.868    },    {      \"timestamp\": 1672851102,      \"type\": \"pression\",      \"valeur\": 100.863    },    {      \"timestamp\": 1672851125,      \"type\": \"pression\",      \"valeur\": 100.859    },    {      \"timestamp\": 1672851154,      \"type\": \"pression\",      \"valeur\": 100.863    },    {      \"timestamp\": 1672851178,      \"type\": \"pression\",      \"valeur\": 100.859    },    {      \"timestamp\": 1672851416,      \"type\": \"pression\",      \"valeur\": 100.862    },    {      \"timestamp\": 1672851440,      \"type\": \"pression\",      \"valeur\": 100.861    },    {      \"timestamp\": 1672851468,      \"type\": \"pression\",      \"valeur\": 100.857    },    {      \"timestamp\": 1672851492,      \"type\": \"pression\",      \"valeur\": 100.869    },    {      \"timestamp\": 1672851520,      \"type\": \"pression\",      \"valeur\": 100.868    },    {      \"timestamp\": 1672851544,      \"type\": \"pression\",      \"valeur\": 100.865    },    {      \"timestamp\": 1672851572,      \"type\": \"pression\",      \"valeur\": 100.864    },    {      \"timestamp\": 1672851595,      \"type\": \"pression\",      \"valeur\": 100.863    }  ],  \"max\": 100.957,  \"min\": 100.857,  \"senseur_id\": \"bmp180/pression\",  \"user_id\": \"z2i3Xjx83MSb5eEAJPN4ZC35bYjceHCHsiuee34zLqzbHCXBuQY\",  \"uuid_appareil\": \"rpi-pico-e6614104033e722b\"}";

    struct ValidateurX509Impl {
        idmg: String,
    }

    #[tokio::test]
    async fn verification_1() {
        setup("verification bon CA");

        let (validateur, enveloppe_privee) = charger_enveloppe_privee_env();

        let options = ValidationOptions::new(true, true, true);
        let mut message = MessageSerialise::from_str(CATALOGUE_1).expect("message serialise");

        let millegrille = message.get_msg().millegrille.as_ref().expect("millegrille").clone();
        let certificat = message.get_msg().certificat.as_ref().expect("certificat");
        let enveloppe = validateur.charger_enveloppe(certificat, None, Some(millegrille.as_str())).await
            .expect("charger_enveloppe");
        message.set_certificat(enveloppe);

        let enveloppe_millegrille = validateur.charger_enveloppe(&vec![millegrille], None, None).await
            .expect("charger_enveloppe");
        message.set_millegrille(enveloppe_millegrille);

        let resultat = verifier_message(
            &mut message,
            validateur.as_ref(),
            Some(&options)
        );

        debug!("Resultat : {:?}", resultat);

        let resultat = resultat.expect("resultat");
        assert_eq!(Some(true), resultat.hachage_valide);
        assert_eq!(true, resultat.regles_valides);
        assert_eq!(true, resultat.signature_valide);
        assert_eq!(true, resultat.certificat_valide, "Certificat valide");

    }

    #[tokio::test]
    async fn verification_2() {
        setup("verification mauvais CA");

        let (validateur, enveloppe_privee) = charger_enveloppe_privee_env();

        let options = ValidationOptions::new(true, true, true);
        let mut message = MessageSerialise::from_str(CATALOGUE_2).expect("message serialise");

        let millegrille = message.get_msg().millegrille.as_ref().expect("millegrille").clone();
        let certificat = message.get_msg().certificat.as_ref().expect("certificat");
        let enveloppe = validateur.charger_enveloppe(certificat, None, Some(millegrille.as_str())).await
            .expect("charger_enveloppe");
        message.set_certificat(enveloppe);

        let enveloppe_millegrille = validateur.charger_enveloppe(&vec![millegrille], None, None).await
            .expect("charger_enveloppe");
        message.set_millegrille(enveloppe_millegrille);

        let resultat = verifier_message(
            &mut message,
            validateur.as_ref(),
            Some(&options)
        );

        debug!("Resultat : {:?}", resultat);

        let resultat = resultat.expect("resultat");
        assert_eq!(Some(true), resultat.hachage_valide);
        assert_eq!(true, resultat.regles_valides);
        assert_eq!(true, resultat.signature_valide);
        assert_eq!(false, resultat.certificat_valide, "Certificat invalide");

    }

    #[tokio::test]
    async fn verification_3() {
        setup("verification local");

        let (validateur, enveloppe_privee) = charger_enveloppe_privee_env();

        let options = ValidationOptions::new(true, true, true);
        let mut message = MessageSerialise::from_str(MESSAGE_1).expect("message serialise");

        let certificat = message.get_msg().certificat.as_ref().expect("certificat");
        let enveloppe = validateur.charger_enveloppe(certificat, None, None).await
            .expect("charger_enveloppe");
        message.set_certificat(enveloppe);

        let resultat = verifier_message(
            &mut message,
            validateur.as_ref(),
            Some(&options)
        );

        debug!("Resultat : {:?}", resultat);

        let resultat = resultat.expect("resultat");
        assert_eq!(Some(true), resultat.hachage_valide);
        assert_eq!(true, resultat.regles_valides);
        assert_eq!(true, resultat.signature_valide);
        assert_eq!(true, resultat.certificat_valide, "Certificat valide");

    }
}
