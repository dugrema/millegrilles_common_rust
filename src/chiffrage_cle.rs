use std::collections::HashMap;
use log::debug;
use blake2::{Blake2s256, Digest};
use openssl::pkey::{Id, PKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use crate::bson::Document;
use crate::chiffrage::{CleSecrete, FormatChiffrage};

use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::certificats::ordered_map;
use crate::constantes::*;
use crate::recepteur_messages::TypeMessage;
use crate::formatteur_messages::MessageMilleGrille;
use crate::signatures::{signer_message, verifier_message};

/// Effectue une requete pour charger des cles a partir du maitre des cles
pub async fn requete_charger_cles<M>(middleware: &M, hachage_bytes: &Vec<String>)
    -> Result<ReponseDechiffrageCles, String>
    where M: GenerateurMessages
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .build();

    let requete = json!({"liste_hachage_bytes": hachage_bytes});

    match middleware.transmettre_requete(routage, &requete).await? {
        TypeMessage::Valide(r) => {
            match r.message.parsed.map_contenu(None) {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("chiffrage_cle.requete_charger_cles Erreur mapping REponseDechiffrageCles: {:?}", e))
            }
        },
        _ => Err(format!("chiffrage_cles.requete_charger_cles Mauvais type de reponse pour les cles"))
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
    pub iv: String,
    pub tag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaInformationCle {
    pub domaine: String,
    pub format: String,
    pub hachage_bytes: String,
    pub identificateurs_document: Option<HashMap<String, String>>,
    pub iv: String,
    pub tag: Option<String>,
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
        }
    }
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    pub fingerprint: String,
    pub cle_chiffree: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeSauvegarderCle {
    // Identite de la cle
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    pub signature_identite: String,

    // Cles chiffrees
    #[serde(serialize_with = "ordered_map")]
    pub cles: HashMap<String, String>,

    // Information de dechiffrage
    pub format: FormatChiffrage,
    pub iv: Option<String>,
    pub tag: Option<String>,
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

    pub fn signer_identite(&mut self, cle_secrete: &CleSecrete) -> Result<(), String> {
        let identite = IdentiteCle::from(self.clone());
        let signature_identite = identite.signer(cle_secrete)?;
        self.signature_identite = signature_identite;
        Ok(())
    }

    pub fn verifier_identite(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
        let identite = IdentiteCle::from(self.clone());
        Ok(identite.verifier(cle_secrete)?)
    }

}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentiteCle {
    pub hachage_bytes: String,
    pub domaine: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    #[serde(skip_serializing)]
    pub signature_identite: String,
}

impl From<CommandeSauvegarderCle> for IdentiteCle {
    fn from(value: CommandeSauvegarderCle) -> Self {
        IdentiteCle {
            hachage_bytes: value.hachage_bytes,
            domaine: value.domaine,
            identificateurs_document: value.identificateurs_document,
            signature_identite: value.signature_identite
        }
    }
}

impl IdentiteCle {

    /// Verifie la signature de l'identite avec la cle secrete
    pub fn verifier(&self, cle_secrete: &CleSecrete) -> Result<bool, String> {
        // Hacher la cle secrete, va servir de cle privee Ed25519
        let mut hasher = Blake2s256::new();
        hasher.update(&cle_secrete.0);
        let cle_privee_bytes = hasher.finalize();

        // Obtenir la cle publique Ed25519 qui correspond au seed prive
        let private_ed25519 = match PKey::private_key_from_raw_bytes(&cle_privee_bytes.as_slice(), Id::ED25519) {
            Ok(s) => s,
            Err(e) => Err(format!("IdentiteCle.signer Erreur preparation secret key : {:?}", e))?
        };
        let public_bytes = match private_ed25519.raw_public_key() {
            Ok(p) => p,
            Err(e) => Err(format!("IdentiteCle.signer Erreur private_ed25519.raw_public_key : {:?}", e))?
        };
        let public_ed25519 = match PKey::public_key_from_raw_bytes(public_bytes.as_slice(), Id::ED25519) {
            Ok(p) => p,
            Err(e) => Err(format!("IdentiteCle.signer Erreur PKey::public_key_from_raw_bytes : {:?}", e))?
        };

        // Preparer le message
        let value_ordered: Map<String, Value> = match MessageMilleGrille::serialiser_contenu(self) {
            Ok(v) => v,
            Err(e) => Err(format!("IdentiteCle.signer Erreur mapping values : {:?}", e))?
        };
        let message_string = match serde_json::to_string(&value_ordered) {
            Ok(m) => m,
            Err(e) => Err(format!("IdentiteCle.signer Erreur conversion en string : {:?}", e))?
        };
        debug!("Message string a verifier {}", message_string);

        // Verifier la signature
        match verifier_message(&public_ed25519, message_string.as_bytes(), self.signature_identite.as_str()) {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("IdentiteCle.verifier Erreur verification message : {:?}", e))?
        }
    }

    /// Signe l'identite avec la cle secrete (sert de cle privee Ed25519).
    fn signer(&self, cle_secrete: &CleSecrete) -> Result<String, String> {

        // Hacher la cle secrete, va servir de cle privee Ed25519
        let mut hasher = Blake2s256::new();
        hasher.update(&cle_secrete.0);
        let cle_privee_bytes = hasher.finalize();

        let private_ed25519 = match PKey::private_key_from_raw_bytes(cle_privee_bytes.as_slice(), Id::ED25519) {
            Ok(s) => s,
            Err(e) => Err(format!("IdentiteCle.signer Erreur preparation secret key : {:?}", e))?
        };
        let value_ordered: Map<String, Value> = match MessageMilleGrille::serialiser_contenu(self) {
            Ok(v) => v,
            Err(e) => Err(format!("IdentiteCle.signer Erreur mapping values : {:?}", e))?
        };
        let message_string = match serde_json::to_string(&value_ordered) {
            Ok(m) => m,
            Err(e) => Err(format!("IdentiteCle.signer Erreur conversion en string : {:?}", e))?
        };
        debug!("Message string a signer {}", message_string);
        match signer_message(&private_ed25519, message_string.as_bytes()) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("IdentiteCle.signer Erreur signature identite cle : {:?}", e))
        }
    }

}

#[cfg(test)]
mod test {
    use std::error::Error;
    use log::debug;
    use openssl::pkey::{Id, PKey};
    use crate::test_setup::setup;
    use super::*;

    fn produire_commande() -> CommandeSauvegarderCle {
        let mut identificateurs_document = HashMap::new();
        identificateurs_document.insert("fuuid".to_string(), "fuuid_dummy".to_string());

        CommandeSauvegarderCle {
            hachage_bytes: "hachage_dummy".to_string(),
            domaine: "DomaineDummy".to_string(),
            identificateurs_document,
            signature_identite: "".to_string(),
            cles: Default::default(),
            format: FormatChiffrage::mgs4,
            iv: None,
            tag: None,
            header: None,
            partition: None,
            fingerprint_partitions: None
        }
    }

    #[test]
    fn test_signature_identite() -> Result<(), Box<dyn Error>> {
        setup("test_signature_identite");

        let mut commande = produire_commande();
        let cle_secrete = CleSecrete::generer();

        // Signer
        commande.signer_identite(&cle_secrete)?;

        debug!("Commande signee : {:?}", commande);

        // Verifier
        let resultat = commande.verifier_identite(&cle_secrete)?;

        assert_eq!(true, resultat);

        Ok(())
    }

    #[test]
    fn test_corruption_identite() -> Result<(), Box<dyn Error>> {
        setup("test_signature_identite");

        let mut commande = produire_commande();
        let cle_secrete = CleSecrete::generer();

        // Signer
        commande.signer_identite(&cle_secrete)?;

        debug!("Commande signee : {:?}", commande);

        // Corrompre la commande (retirer user_id)
        commande.identificateurs_document.insert("corrupt".to_owned(), "true".to_owned());

        // Verifier
        let resultat = commande.verifier_identite(&cle_secrete)?;

        assert_eq!(false, resultat);

        Ok(())
    }

}

