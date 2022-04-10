use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;

use async_trait::async_trait;
use multibase::Base;
use openssl::pkey::{Id, PKey, Private, Public};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::bson::Document;
use crate::certificats::{EnveloppeCertificat, FingerprintCertPublicKey, ordered_map};
use crate::chiffrage_aesgcm::{CipherMgs2, Mgs2CipherKeys};
use crate::chiffrage_chacha20poly1305::{CipherMgs3, Mgs3CipherKeys};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use crate::chiffrage_rsa::{chiffrer_asymetrique as chiffrer_asymetrique_aesgcm, dechiffrer_asymetrique as dechiffrer_asymetrique_aesgcm};
use crate::formatteur_messages::MessageSerialise;
use crate::middleware::IsConfigurationPki;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FormatChiffrage { mgs2, mgs3 }

/// Struct qui efface la cle secrete en memoire sur drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CleSecrete(pub [u8; 32]);

impl PartialEq for CleSecrete {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Rechiffre une cle asymetrique pour une nouvelle cle publique
pub fn rechiffrer_asymetrique_multibase(private_key: &PKey<Private>, public_key: &PKey<Public>, cle: &str)
    -> Result<String, Box<dyn Error>>
{
    let cle_rechiffree = {
        let (_, cle_bytes): (_, Vec<u8>) = multibase::decode(cle)?;

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => {
                // Err(String::from("Fix me"))?
                let cle_secrete = dechiffrer_asymmetrique_ed25519(&cle_bytes[..], private_key)?;
                let cle_rechiffree = chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], public_key)?;
                Ok(cle_rechiffree.to_vec())
            },
            Id::RSA => {
                let cle_secrete = dechiffrer_asymetrique_aesgcm(private_key, cle_bytes.as_slice())?;
                chiffrer_asymetrique_aesgcm(public_key, &cle_secrete.0[..])
            },
            _ => Err(format!("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    }?;

    Ok(multibase::encode(Base::Base64, &cle_rechiffree[..]))
}

/// Dechiffrer une cle secrete
pub fn dechiffrer_asymetrique_multibase(private_key: &PKey<Private>, cle: &str)
    -> Result<CleSecrete, Box<dyn Error>>
{
    let cle_rechiffree = {
        let (_, cle_bytes): (_, Vec<u8>) = multibase::decode(cle)?;

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => {
                dechiffrer_asymmetrique_ed25519(&cle_bytes[..], private_key)?
            },
            Id::RSA => {
                dechiffrer_asymetrique_aesgcm(private_key, cle_bytes.as_slice())?
            },
            _ => Err(format!("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    };

    Ok(cle_rechiffree)
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    pub fingerprint: String,
    pub cle_chiffree: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeSauvegarderCle {
    #[serde(serialize_with = "ordered_map")]
    pub cles: HashMap<String, String>,
    pub domaine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    pub format: FormatChiffrage,
    pub hachage_bytes: String,
    #[serde(serialize_with = "ordered_map")]
    pub identificateurs_document: HashMap<String, String>,
    pub iv: String,
    pub tag: String,

    /// Partitions de maitre des cles (fingerprint certs). Utilise pour routage de la commande.
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

pub trait MgsCipherData {
    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>>;
}

pub trait MgsCipherKeys {
    fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>
    ) -> CommandeSauvegarderCle;

    /// Retourne la valeur chiffree de la cle de millegrille
    /// Note : pour Ed25519, retourne la cle peer publique.
    fn get_cle_millegrille(&self) -> Option<String>;
}

pub trait CipherMgs<K: MgsCipherKeys> {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String>;
    fn finalize(self, out: &mut [u8]) -> Result<(usize, K), String>;
    // fn get_cipher_keys(&self) -> Result<K, String>;
}

pub trait DecipherMgs<M: MgsCipherData> {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String>;
    fn finalize(self, out: &mut [u8]) -> Result<usize, String>;
}

/// Permet de recuperer un Cipher deja initalise avec les certificats de MaitreDesCles.
#[async_trait]
pub trait Chiffreur<C: CipherMgs<K>, K: MgsCipherKeys> {
    /// Retourne les certificats qui peuvent etre utilises pour chiffrer une cle secrete.
    /// Devrait inclure le certificat de MilleGrille avec flag est_cle_millegrille==true.
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey>;

    /// Recupere un cipher initialise avec les cles publiques
    fn get_cipher(&self) -> Result<C, Box<dyn Error>>;

    /// Recycle les certificats de chiffrage - fait une requete pour obtenir les certs courants
    async fn charger_certificats_chiffrage(&self, cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>>;

    /// Recoit un certificat de chiffrage
    async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>>;
}

/// Permet de recuperer un Decipher deja initialise pour une cle
#[async_trait]
pub trait Dechiffreur<D: DecipherMgs<M>, M: MgsCipherData>: IsConfigurationPki + Send + Sync {
    /// Appel au MaitreDesCles pour une version dechiffrable de la cle
    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<M, Box<dyn Error>>;

    /// Cle privee locale pour dechiffrage
    // fn get_enveloppe_privee_dechiffrage(&self) -> Arc<EnveloppePrivee>;

    /// Retourne une instance de Decipher pleinement initialisee et prete a dechiffrer
    async fn get_decipher(&self, hachage_bytes: &str) -> Result<D, Box<dyn Error>>;
}

/// Genere un Vec de nb_bytes aleatoires.
pub fn random_vec(nb_bytes: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.reserve(nb_bytes);

    let mut rnd = rand::thread_rng();

    // Extraire bytes par groupe de taille max (32)
    let nb_loops = nb_bytes / 32;
    let restant = nb_bytes - (nb_loops * 32);
    for _ in 0..nb_loops {
        let rnd_bytes: [u8; 32] = rnd.gen();
        v.extend_from_slice(&rnd_bytes[0..32]);
    }

    // Ajouter bytes manquants
    if restant > 0 {
        for _ in 0..restant {
            let byte: u8 = rnd.gen();
            v.push(byte);
        }
    }

    v
}

pub type ChiffreurMgs2 = dyn Chiffreur<CipherMgs2, Mgs2CipherKeys>;
pub type ChiffreurMgs3 = dyn Chiffreur<CipherMgs3, Mgs3CipherKeys>;
