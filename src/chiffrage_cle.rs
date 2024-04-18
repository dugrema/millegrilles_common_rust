use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex};
use async_compression::Level::Default;

use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use blake2::{Blake2s256, Digest};
use chrono::{DateTime, Utc};
use log::{debug, error, info};
use millegrilles_cryptographie::chiffrage::{FormatChiffrage, formatchiffragestr};
use millegrilles_cryptographie::chiffrage_cles::{CleChiffrageHandler, CleDechiffrageX25519Impl};
use millegrilles_cryptographie::heapless;
use millegrilles_cryptographie::maitredescles::SignatureDomaines;
use millegrilles_cryptographie::messages_structs::{DechiffrageInterMillegrilleOwned, MessageMilleGrillesOwned, MessageMilleGrillesRef};
use millegrilles_cryptographie::x25519::{CleSecreteX25519, dechiffrer_asymmetrique_ed25519};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use openssl::pkey::{Id, PKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bson::Document;
use crate::certificats::{ordered_map, VerificateurPermissions};
use crate::constantes::*;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::recepteur_messages::TypeMessage;
use crate::signatures::{signer_identite, signer_message, verifier_message};
use crate::error::Error as CommonError;

/// Nombre maximal de certificats de maitre des cles dans le cache de chiffrage
const CONST_MAX_CACHE_CHIFFRAGE: usize = 16;
const CONST_EXPIRATION_CACHE_CHIFFRAGE_SECS: i64 = 900;

/// Effectue une requete pour charger des cles a partir du maitre des cles
pub async fn requete_charger_cles<M>(middleware: &M, hachage_bytes: &Vec<String>)
    -> Result<ReponseDechiffrageCles, crate::error::Error>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE, vec![Securite::L1Public])
        .build();

    let requete = json!({"liste_hachage_bytes": hachage_bytes});

    match middleware.transmettre_requete(routage, &requete).await? {
        Some(inner) => match inner {
            TypeMessage::Valide(r) => {
                let message_ref = r.message.parse()?;
                let message_contenu = match message_ref.contenu() {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("chiffrage_cle.requete_charger_cles Erreur contenu() {:?}", e))?
                };
                match message_contenu.deserialize() {
                    Ok(r) => Ok(r),
                    Err(e) => Err(format!("chiffrage_cle.requete_charger_cles Erreur mapping REponseDechiffrageCles: {:?}", e))?
                }
                // match r.message.parsed.map_contenu() {
                //     Ok(r) => Ok(r),
                //     Err(e) => Err(format!("chiffrage_cle.requete_charger_cles Erreur mapping REponseDechiffrageCles: {:?}", e))
                // }
            },
            _ => Err(format!("chiffrage_cles.requete_charger_cles Mauvais type de reponse pour les cles"))?
        },
        None => Err(format!("chiffrage_cles.requete_charger_cles Aucune reponse pour les cles"))?
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseDechiffrageCles {
    pub acces: String,
    pub cles: Option<HashMap<String, InformationCle>>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformationCle {
    pub cle: String,
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub identificateurs_document: Option<HashMap<String, String>>,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
    // pub signature_identite: String,
}

impl TryInto<CleDechiffrageX25519Impl> for &InformationCle {
    type Error = CommonError;

    fn try_into(self) -> Result<CleDechiffrageX25519Impl, Self::Error> {
        Ok(CleDechiffrageX25519Impl {
            cle_chiffree: self.cle.clone(),
            cle_secrete: None,
            format: self.format.as_str().try_into()?,
            nonce: match self.header.clone() { Some(inner) => Some(inner), None => self.iv.clone() },
            verification: match self.tag.clone() { Some(inner) => Some(inner), None => Some(self.hachage_bytes.clone()) },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaInformationCle {
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub identificateurs_document: Option<HashMap<String, String>>,
    pub iv: Option<String>,
    pub tag: Option<String>,
    pub header: Option<String>,
    // pub signature_identite: String,
}

impl From<InformationCle> for MetaInformationCle {
    fn from(value: InformationCle) -> Self {
        MetaInformationCle {
            domaine: value.domaine,
            format: value.format,
            hachage_bytes: value.hachage_bytes,
            identificateurs_document: value.identificateurs_document,
            iv: value.iv,
            tag: value.tag,
            header: value.header,
            // signature_identite: value.signature_identite,
        }
    }
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    pub fingerprint: String,
    pub cle_chiffree: String,
}

pub trait CleChiffrageCache {
    fn entretien_cle_chiffrage(&self);
    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), crate::error::Error>;
}

/// Conserve un certificat de Maitre des cles pour rechiffrage de cle secrete.
#[derive(Clone)]
struct CleChiffrage {
    certificat: Arc<EnveloppeCertificat>,
    derniere_presence: DateTime<Utc>,
}

pub struct CleChiffrageHandlerImpl {
    cles_chiffrage: Mutex<HashMap<String, CleChiffrage>>
}

impl CleChiffrageHandlerImpl {
    pub fn new() -> Self {
        Self {
            cles_chiffrage: Mutex::new(HashMap::new())
        }
    }
}

impl CleChiffrageCache for CleChiffrageHandlerImpl {

    /// Retire les certificats de Maitre des cles expires.
    fn entretien_cle_chiffrage(&self) {
        let expiration = match chrono::Duration::new(CONST_EXPIRATION_CACHE_CHIFFRAGE_SECS, 0) {
            Some(inner) => inner,
            None => {
                error!("Erreur Duration::new() pour expiration certificats");
                return
            }
        };
        let date_expiree = Utc::now() - expiration;
        let mut guard = self.cles_chiffrage.lock().expect("lock");
        let fingerprints_expires: Vec<String> = guard.iter()
            .filter(|c| c.1.derniere_presence < date_expiree)
            .map(|c| c.0.clone())
            .collect();
        for fingerprint in fingerprints_expires {
            info!("CleChiffrageHandlerImpl.entretien Expirer certificat de chiffrage {}", fingerprint);
            guard.remove(&fingerprint);
        }
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), crate::error::Error> {
        // Verifier que le certificat est pour le maitre des cles
        if ! certificat.verifier_domaines(vec![DOMAINE_NOM_MAITREDESCLES.to_string()])? {
            Err(crate::error::Error::Str("Certificat n'a pas le domaine Maitre des cles"))?
        }
        if ! certificat.verifier_exchanges(vec![Securite::L3Protege, Securite::L4Secure])? {
            Err(crate::error::Error::Str("Certificat n'a pas le niveau de securite 3.protege ou 4.secure"))?
        }

        let mut guard = self.cles_chiffrage.lock().expect("lock");
        let fingerprint = certificat.fingerprint()?;
        match guard.get_mut(fingerprint.as_str()) {
            Some(inner) => {
                // Le certificat est deja dans le cache. Faire un touch.
                inner.derniere_presence = Utc::now();
                Ok(())
            },
            None => {
                if guard.len() < CONST_MAX_CACHE_CHIFFRAGE {
                    let cle = CleChiffrage { certificat, derniere_presence: Utc::now() };
                    guard.insert(fingerprint, cle);
                    Ok(())
                } else {
                    Err(crate::error::Error::Str("Cache de certificats de chiffrage plein"))
                }
            }
        }
    }
}

impl CleChiffrageHandler for CleChiffrageHandlerImpl {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        let guard = self.cles_chiffrage.lock().expect("lock");
        guard.values().map(|v| v.certificat.clone()).collect()
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeSauvegarderCle {
    // Identite de la cle
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    // pub signature_identite: String,

    // Cles chiffrees
    #[serde(serialize_with = "ordered_map")]
    pub cles: HashMap<String, String>,

    // Information de dechiffrage
    #[serde(with = "formatchiffragestr")]
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,

    /// Partitions de maitre des cles (fingerprint certs). Utilise pour routage de la commande.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_partitions: Option<Vec<String>>
}

/// Converti en Document Bson pour sauvegarder dans MongoDB
impl Into<Document> for CommandeSauvegarderCle {
    fn into(self) -> Document {
        let val = serde_json::to_value(self).expect("value");
        serde_json::from_value(val).expect("bson")
    }
}

impl CommandeSauvegarderCle {

    pub fn from_message_chiffre(
        message: &MessageMilleGrillesOwned,
        identificateurs_document: HashMap<String, String>
    ) -> Result<Self, CommonError> {

        let dechiffrage = match message.dechiffrage.as_ref() {
            Some(inner) => inner,
            None => Err(CommonError::Str("CommandeSauvegarderCle.from_message_chiffre Message sans section dechiffrage"))?
        };

        let cles: HashMap<String, String> = match dechiffrage.cles.as_ref() {
            Some(inner) => inner.iter().map(|(k,v)| (k.to_string(), v.to_string())).collect(),
            None => Err(CommonError::Str("CommandeSauvegarderCle.from_message_chiffre Message sans cles de chiffrage"))?
        };

        let hachage_bytes = match dechiffrage.cle_id.as_ref() {
            Some(inner) => inner.to_string(),
            None => match dechiffrage.hachage.as_ref() {
                Some(inner) => inner.to_string(),
                None => Err(CommonError::Str("CommandeSauvegarderCle.from_message_chiffre Message sans cle_id/hachage_bytes"))?
            }
        };

        let header = match dechiffrage.header.as_ref() {
            Some(inner) => Some(inner.to_string()),
            None => None
        };

        let fingerprint_partitions: Vec<String> = cles.iter().map(|(k,_)| k.to_owned()).collect();
        // Prendre une cle au hasard pour la partition de routage du message
        let partition = match fingerprint_partitions.get(0) {
            Some(inner) => Some(inner.to_string()),
            None => None
        };

        let routage = match message.routage.as_ref() {
            Some(inner) => inner,
            None => Err(CommonError::Str("CommandeSauvegarderCle.from_message_chiffre Message sans routage"))?
        };

        let domaine = match routage.domaine.as_ref() {
            Some(inner) => inner.to_string(),
            None => Err(CommonError::Str("CommandeSauvegarderCle.from_message_chiffre Message sans domaine"))?
        };

        let commande = Self {
            hachage_bytes,
            domaine,
            identificateurs_document,
            cles,
            iv: None,
            tag: None,
            header,
            format: dechiffrage.format.as_str().try_into()?,
            partition,
            fingerprint_partitions: Some(fingerprint_partitions),
        };

        Ok(commande)
    }

}

/// Commande pour ajouter une nouvelle cle pour des domaines.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeAjouterCleDomaine {
    /// Cles chiffrees pour differents destinataires.
    /// Key : fingerprint hex, Value: cle chiffree base64
    pub cles: HashMap<String, String>,

    /// Signature du domaine. Permet de garantir que seuls les domaines predefinis
    /// auront acces a cette cle. La commande get_cle_ref() permet aussi de recuperer un
    /// identificateur cryptographique unique pour cette cle.
    pub signature: SignatureDomaines,
}

impl CommandeAjouterCleDomaine {
    pub fn verifier_signature<B>(&self, cle_secrete: B) -> Result<(), crate::error::Error>
        where B: AsRef<[u8]>
    {
        Ok(self.signature.verifier_derivee(cle_secrete)?)
    }

    pub fn get_cle_ref(&self) -> Result<heapless::String<96>, crate::error::Error> {
        Ok(self.signature.get_cle_ref()?)
    }

    pub fn get_cle_secrete(&self, enveloppe_privee: &EnveloppePrivee)
        -> Result<CleSecreteX25519, crate::error::Error>
    {
        // Trouver la cle chiffree correspondant a la cle privee.
        let fingerprint = enveloppe_privee.fingerprint()?;
        let cle_chiffree = match self.cles.get(fingerprint.as_str()) {
            Some(inner) => inner,
            None => Err(crate::error::Error::String(format!("into_cle_dechiffrage Cle {} absente", fingerprint)))?
        };

        // Dechiffrer la cle
        let cle_chiffree_bytes = base64_nopad.decode(cle_chiffree)?;
        Ok(dechiffrer_asymmetrique_ed25519(
            cle_chiffree_bytes.as_slice(), &enveloppe_privee.cle_privee)?)
    }
}


// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct IdentiteCle {
//     pub hachage_bytes: String,
//     pub domaine: String,
//     #[serde(serialize_with = "ordered_map")]
//     pub identificateurs_document: HashMap<String, String>,
//     #[serde(skip_serializing)]
//     pub signature_identite: String,
// }

// impl From<CommandeSauvegarderCle> for IdentiteCle {
//     fn from(value: CommandeSauvegarderCle) -> Self {
//         IdentiteCle {
//             hachage_bytes: value.hachage_bytes,
//             domaine: value.domaine,
//             identificateurs_document: value.identificateurs_document,
//             signature_identite: value.signature_identite
//         }
//     }
// }

// impl IdentiteCle {
//
//     /// Verifie la signature de l'identite avec la cle secrete
//     pub fn verifier(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
//         // Hacher la cle secrete, va servir de cle privee Ed25519
//         let mut hasher = Blake2s256::new();
//         hasher.update(&cle_secrete.0);
//         let cle_privee_bytes = hasher.finalize();
//
//         // Obtenir la cle publique Ed25519 qui correspond au seed prive
//         let private_ed25519 = match PKey::private_key_from_raw_bytes(&cle_privee_bytes.as_slice(), Id::ED25519) {
//             Ok(s) => s,
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur preparation secret key : {:?}", e))?
//         };
//         let public_bytes = match private_ed25519.raw_public_key() {
//             Ok(p) => p,
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur private_ed25519.raw_public_key : {:?}", e))?
//         };
//         let public_ed25519 = match PKey::public_key_from_raw_bytes(public_bytes.as_slice(), Id::ED25519) {
//             Ok(p) => p,
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur PKey::public_key_from_raw_bytes : {:?}", e))?
//         };
//
//         // Preparer le message
//         let value_ordered: Map<String, Value> = match MessageMilleGrille::serialiser_contenu(self) {
//             Ok(v) => v,
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur mapping values : {:?}", e))?
//         };
//         let message_string = match serde_json::to_string(&value_ordered) {
//             Ok(m) => m,
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur conversion en string : {:?}", e))?
//         };
//         debug!("IdentiteCle.verifier Message string a verifier {}", message_string);
//
//         // Verifier la signature
//         match verifier_message(&public_ed25519, message_string.as_bytes(), self.signature_identite.as_str()) {
//             Ok(r) => Ok(r),
//             Err(e) => Err(format!("IdentiteCle.verifier Erreur verification message : {:?}", e))?
//         }
//     }
//
//     /// Signe l'identite avec la cle secrete (sert de cle privee Ed25519).
//     fn signer(&self, cle_secrete: &CleSecrete) -> Result<String, String> {
//
//         // Hacher la cle secrete, va servir de cle privee Ed25519
//         let mut hasher = Blake2s256::new();
//         hasher.update(&cle_secrete.0);
//         let cle_privee_bytes = hasher.finalize();
//
//         let private_ed25519 = match PKey::private_key_from_raw_bytes(cle_privee_bytes.as_slice(), Id::ED25519) {
//             Ok(s) => s,
//             Err(e) => Err(format!("IdentiteCle.signer Erreur preparation secret key : {:?}", e))?
//         };
//         let value_ordered: Map<String, Value> = match MessageMilleGrille::serialiser_contenu(self) {
//             Ok(v) => v,
//             Err(e) => Err(format!("IdentiteCle.signer Erreur mapping values : {:?}", e))?
//         };
//         let message_string = match serde_json::to_string(&value_ordered) {
//             Ok(m) => m,
//             Err(e) => Err(format!("IdentiteCle.signer Erreur conversion en string : {:?}", e))?
//         };
//         debug!("Message string a signer {}", message_string);
//         match signer_identite(&private_ed25519, message_string.as_bytes()) {
//             Ok(s) => Ok(s),
//             Err(e) => Err(format!("IdentiteCle.signer Erreur signature identite cle : {:?}", e))
//         }
//     }
//
// }

// pub struct CleDechiffree {
//     pub cle: String,
//     pub cle_secrete: CleSecrete,
//     pub domaine: String,
//     pub format: String,
//     pub hachage_bytes: String,
//     pub identificateurs_document: Option<HashMap<String, String>>,
//     pub iv: Option<String>,
//     pub tag: Option<String>,
//     pub header: Option<String>,
//     // pub signature_identite: String,
// }
//
// impl CleDechiffree {
//     pub fn dechiffrer_information_cle(enveloppe_privee: &EnveloppePrivee, information_cle: InformationCle) -> Result<Self, Box<dyn Error>> {
//         let (_, cle_bytes) = multibase::decode(&information_cle.cle)?;
//         let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes[..], &enveloppe_privee.cle_privee)?;
//
//         Ok(Self {
//             cle: information_cle.cle,
//             cle_secrete,
//             domaine: information_cle.domaine,
//             format: information_cle.format,
//             hachage_bytes: information_cle.hachage_bytes,
//             identificateurs_document: information_cle.identificateurs_document,
//             iv: information_cle.iv,
//             tag: information_cle.tag,
//             header: information_cle.header,
//             // signature_identite: information_cle.signature_identite,
//         })
//     }
// }

// #[cfg(test)]
// mod test {
//     use std::error::Error;
//
//     use log::debug;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     fn produire_commande() -> CommandeSauvegarderCle {
//         let mut identificateurs_document = HashMap::new();
//         identificateurs_document.insert("fuuid".to_string(), "fuuid_dummy".to_string());
//
//         CommandeSauvegarderCle {
//             hachage_bytes: "hachage_dummy".to_string(),
//             domaine: "DomaineDummy".to_string(),
//             identificateurs_document,
//             // signature_identite: "".to_string(),
//             cles: Default::default(),
//             format: FormatChiffrage::mgs4,
//             iv: None,
//             tag: None,
//             header: None,
//             partition: None,
//             fingerprint_partitions: None
//         }
//     }
//
//     // #[test]
//     // fn test_signature_identite() -> Result<(), Box<dyn Error>> {
//     //     setup("test_signature_identite");
//     //
//     //     let mut commande = produire_commande();
//     //     let cle_secrete = CleSecrete::generer();
//     //
//     //     // Signer
//     //     commande.signer_identite(&cle_secrete)?;
//     //
//     //     debug!("Commande signee : {:?}", commande);
//     //
//     //     // Verifier
//     //     let resultat = commande.verifier_identite(&cle_secrete)?;
//     //
//     //     assert_eq!(true, resultat);
//     //
//     //     Ok(())
//     // }
//
//     // #[test]
//     // fn test_corruption_identite() -> Result<(), Box<dyn Error>> {
//     //     setup("test_signature_identite");
//     //
//     //     let mut commande = produire_commande();
//     //     let cle_secrete = CleSecrete::generer();
//     //
//     //     // Signer
//     //     commande.signer_identite(&cle_secrete)?;
//     //
//     //     debug!("Commande signee : {:?}", commande);
//     //
//     //     // Corrompre la commande (retirer user_id)
//     //     commande.identificateurs_document.insert("corrupt".to_owned(), "true".to_owned());
//     //
//     //     // Verifier
//     //     let resultat = commande.verifier_identite(&cle_secrete)?;
//     //
//     //     assert_eq!(false, resultat);
//     //
//     //     Ok(())
//     // }
//
// }
//
