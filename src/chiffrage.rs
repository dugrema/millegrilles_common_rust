use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};

use aead::{NewAead, AeadMut, Payload};
use async_trait::async_trait;
use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::derive::Deriver;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use dryoc::classic::{crypto_sign_ed25519, crypto_sign_ed25519::{PublicKey, SecretKey}};
use x509_parser::nom::Parser;

use crate::bson::Document;
use crate::certificats::{EnveloppeCertificat, FingerprintCertPublicKey, ordered_map};
use crate::chacha20poly1305_incremental::ChaCha20Poly1305;
use crate::formatteur_messages::MessageSerialise;
use crate::hachages::{Hacheur, hacher_bytes_vu8};
use crate::middleware::IsConfigurationPki;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FormatChiffrage {
    mgs2,
}

/**
Derive une cle secrete a partir d'une cle publique. Utiliser avec cle publique du cert CA.
*/
pub fn deriver_asymetrique_ed25519(public_key: &PKey<Public>) -> Result<([u8; 32], String), Box<dyn Error>> {

    if public_key.id() != Id::ED25519 {
        Err(String::from("deriver_asymetrique_ed25519 Mauvais type de cle publique, doit etre ED25519"))?
    }

    let cle_peer = PKey::generate_x25519()?;
    let public_peer = String::from_utf8(cle_peer.public_key_to_pem()?)?;

    // Convertir cle CA publique Ed25519 en X25519
    let cle_public_x25519 = convertir_public_ed25519_to_x25519(public_key)?;

    let mut deriver = Deriver::new(&cle_peer)?;
    deriver.set_peer(cle_public_x25519.as_ref())?;
    let mut cle_secrete = [0u8; 32];
    deriver.derive(&mut cle_secrete)?;

    // Hacher la cle avec blake2s-256
    let cle_hachee = hacher_bytes_vu8(&cle_secrete, Some(Code::Blake2s256));
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok((cle_secrete, public_peer))
}

/**
Rederive une cle secrete a partir d'une cle publique et cle privee.
*/
pub fn deriver_asymetrique_ed25519_peer(peer_x25519: &PKey<Public>, private_key_in: &PKey<Private>) -> Result<[u8; 32], Box<dyn Error>> {

    if peer_x25519.id() != Id::X25519 {
        Err(String::from("deriver_asymetrique_ed25519_peer Mauvais type de cle publique, doit etre X25519"))?
    }

    // Convertir cle privee en format X25519
    let cle_privee_pkey = match private_key_in.id() {
        Id::X25519 => private_key_in.to_owned(),
        Id::ED25519 => convertir_private_ed25519_to_x25519(private_key_in)?,
        _ => Err(String::from("deriver_asymetrique_ed25519_peer Mauvais type de cle private, doit etre ED25519 ou X25519"))?
    };

    let mut deriver = Deriver::new(&cle_privee_pkey)?;
    deriver.set_peer(peer_x25519)?;
    let mut cle_secrete = [0u8; 32];
    deriver.derive(&mut cle_secrete)?;

    // Hacher la cle avec blake2s-256
    let cle_hachee = hacher_bytes_vu8(&cle_secrete, Some(Code::Blake2s256));
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok(cle_secrete)
}

pub fn chiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_publique: &PKey<Public>) -> Result<[u8; 80], Box<dyn Error>> {

    let cle_publique_x25519 = convertir_public_ed25519_to_x25519(cle_publique)?;
    let cle_peer = PKey::generate_x25519()?;
    let cle_peer_public_raw = cle_peer.raw_public_key()?;

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_publique_x25519, &cle_peer)?;

    debug!("Cle secrete intermediaire : {:?} \nCle peer public : {:?}", cle_secrete_intermediaire, cle_peer_public_raw);

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire[..].into());

    // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage
    let cle_secrete_chiffree_tag = match aead.encrypt(cle_peer_public_raw[0..12].into(), cle_secrete.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("millegrilles_common chiffrer_asymmetrique_ed25519 encrypt error {:?}", e))?
    };

    let mut vec_resultat = Vec::new();
    vec_resultat.extend_from_slice(&cle_peer_public_raw[..]);  // 32 bytes cle publique peer
    vec_resultat.extend_from_slice(&cle_secrete_chiffree_tag[..]);  // 32 cle secrete chiffree + 16 bytes auth tag

    let mut resultat = [0u8; 80];
    resultat.copy_from_slice(&vec_resultat[..]);

    Ok(resultat)
}

pub fn dechiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_privee: &PKey<Private>) -> Result<[u8; 32], Box<dyn Error>> {

    if cle_secrete.len() != 80 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvaise taille de cle secrete, doit etre 80 bytes"))?
    }
    if cle_privee.id() != Id::ED25519 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvais type de cle privee, doit etre ED25519"))?
    }

    // let cle_privee_x25519 = convertir_private_ed25519_to_x25519(cle_privee)?;
    let cle_peer_public_raw = &cle_secrete[0..32];
    let cle_peer_intermediaire = PKey::public_key_from_raw_bytes(cle_peer_public_raw, Id::X25519)?;
    let cle_secrete_chiffree_tag = &cle_secrete[32..80];

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, &cle_privee)?;

    debug!("Cle secrete intermediaire : {:?} \nCle peer public : {:?}", cle_secrete_intermediaire, cle_peer_public_raw);

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire[..].into());

    // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage
    let cle_secrete_dechiffree = match aead.decrypt(cle_peer_public_raw[0..12].into(), cle_secrete_chiffree_tag.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("millegrilles_common chiffrer_asymmetrique_ed25519 encrypt error {:?}", e))?
    };

    let mut resultat = [0u8; 32];
    resultat.copy_from_slice(&cle_secrete_dechiffree[..]);

    Ok(resultat)
}

// pub fn rechiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_privee: &PKey<Private>, cle_publique: &PKey<Public>) -> Result<[u8; 80], Box<dyn Error>> {
//     let peer_x25519_bytes = &cle_secrete[0..32];
//     let cle_secrete_chiffree_tag = &cle_secrete[32..80];
//
//     let peer_public_pkey = PKey::public_key_from_raw_bytes(&cle_publique_x25519, Id::X25519)?;
//
//     // Trouver cle secrete de dechiffrage de la cle privee
//     let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&peer_public_pkey, cle_privee)?;
//
//     // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
//     let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire[..].into());
//
//     let message = match aead.decrypt(nonce[..].into(), cle_secrete_chiffree_tag.as_ref()) {
//         Ok(m) => m,
//         Err(e) => Err(format!("WASM chacha20poly1305_decrypt encrypt error {:?}", e))?
//     };
//
//     let reponse = [0u8; 80]
// }

pub fn chiffrer_asymetrique(public_key: &PKey<Public>, cle_symmetrique: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const SIZE_MAX: usize = 4096/8;
    if public_key.size() > SIZE_MAX {
        panic!("Taille de la cle ({}) est trop grande pour le buffer ({})", public_key.size(), SIZE_MAX);
    }

    let mut cle_chiffree = [0u8; SIZE_MAX];

    let mut encrypter = Encrypter::new(public_key)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    let size = encrypter.encrypt(cle_symmetrique, &mut cle_chiffree)?;

    let mut buffer_ajuste = Vec::new();
    buffer_ajuste.extend_from_slice(&cle_chiffree[..size]);

    Ok(buffer_ajuste)
}

pub fn dechiffrer_asymetrique(private_key: &PKey<Private>, cle_chiffree_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cle_dechiffree = [0u8; 512];  // Cle max 4096 bits (512 bytes)

    let mut decrypter = Decrypter::new(private_key)?;

    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.decrypt(cle_chiffree_bytes, &mut cle_dechiffree)?;

    let cle_dechiffree = &cle_dechiffree[..32];
    Ok(cle_dechiffree.to_vec().to_owned())
}

/// Rechiffre une cle asymetrique pour une nouvelle cle publique
pub fn rechiffrer_asymetrique_multibase(private_key: &PKey<Private>, public_key: &PKey<Public>, cle: &str)
    -> Result<String, Box<dyn Error>>
{
    let cle_rechiffree = {
        let (_, cle_bytes): (_, Vec<u8>) = multibase::decode(cle)?;
        let cle_secrete = dechiffrer_asymetrique(private_key, cle_bytes.as_slice())?;
        chiffrer_asymetrique(public_key, cle_secrete.as_slice())
    }?;

    Ok(multibase::encode(Base::Base64, cle_rechiffree.as_slice()))
}

trait CipherMillegrille {

}

pub struct CipherMgs2 {
    encrypter: Crypter,
    iv: String,
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    fp_cle_millegrille: Option<String>,
    hacheur: Hacheur,
    hachage_bytes: Option<String>,
    tag: Option<String>,
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    fingerprint: String,
    cle_chiffree: String,
}

impl CipherMgs2 {
    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Result<Self, Box<dyn Error>> {
        let mut buffer_random = [0u8; 44];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");

        let cle = &buffer_random[0..32];
        let iv = &buffer_random[32..44];

        // Chiffrer la cle avec cle publique
        let mut fp_cles = Vec::new();
        let mut fp_cle_millegrille: Option<String> = None;
        for fp_pk in public_keys {
            let cle_chiffree = chiffrer_asymetrique(&fp_pk.public_key, &cle)?;
            let cle_chiffree_str = encode(Base::Base64, cle_chiffree);
            fp_cles.push(FingerprintCleChiffree {
                fingerprint: fp_pk.fingerprint.clone(),
                cle_chiffree: cle_chiffree_str}
            );
            if fp_pk.est_cle_millegrille {
                fp_cle_millegrille = Some(fp_pk.fingerprint.clone());
            }
        }

        let encrypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Encrypt,
            cle,
            Some(iv)
        ).unwrap();

        let hacheur = Hacheur::builder()
            .digester(Code::Sha2_512)
            .base(Base::Base58Btc)
            .build();

        Ok(CipherMgs2 {
            encrypter,
            iv: encode(Base::Base64, iv),
            cles_chiffrees: fp_cles,
            fp_cle_millegrille,
            hacheur,
            hachage_bytes: None,
            tag: None,
        })
    }

    pub fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        match self.encrypter.update(data, out) {
            Ok(s) => {
                self.hacheur.update(&out[..s]);  // Calculer hachage output
                Ok(s)
            },
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, String> {

        if self.tag.is_some() {
            Err("Deja finalise")?;
        }

        match self.encrypter.finalize(out) {
            Ok(s) => {
                self.hacheur.update(&out[..s]);  // Calculer hachage output

                // Calculer et conserver hachage
                let hachage_bytes = self.hacheur.finalize();
                self.hachage_bytes = Some(hachage_bytes);

                // Conserver le compute tag
                let mut tag = [0u8; 16];
                let tag_b64 = match self.encrypter.get_tag(&mut tag) {
                    Ok(()) => Ok(encode(Base::Base64, &tag)),
                    Err(e) => Err(format!("Erreur tag : {:?}", e)),
                }?;
                self.tag = Some(tag_b64);

                Ok(s)
            },
            Err(e) => Err(format!("Erreur update : {:?}", e)),
        }
    }

    pub fn get_cipher_keys(&self) -> Result<Mgs2CipherKeys, String> {

        let hachage_bytes = match &self.hachage_bytes {
            Some(t) => Ok(t.to_owned()),
            None => Err(String::from("Hachage_bytes pas encore calcule")),
        }?;

        let tag = match &self.tag {
            Some(t) => Ok(t.to_owned()),
            None => Err(String::from("Tag pas encore calcule")),
        }?;

        let mut cipher_keys = Mgs2CipherKeys::new(
            self.cles_chiffrees.clone(),
            self.iv.clone(),
            tag,
            hachage_bytes,
        );
        cipher_keys.fingerprint_cert_millegrille = self.fp_cle_millegrille.clone();

        Ok(cipher_keys)
    }

}

pub struct DecipherMgs2 {
    decrypter: Crypter,
}

impl DecipherMgs2 {

    // pub fn new(private_key: &PKey<Private>, cle_chiffree: &str, iv: &str, tag: &str) -> Result<Self, String> {
    pub fn new(decipher_data: &Mgs2CipherData) -> Result<Self, String> {

        // let (_, tag_bytes) = decode(tag).expect("tag");
        // let (_, iv_bytes) = decode(iv).expect("tag");
        // let (_, cle_chiffree_bytes) = decode(cle_chiffree).expect("cle_chiffree");
        // println!("tag {:?}\niv {:?}\ncle chiffree bytes {:?}", tag_bytes, iv_bytes, cle_chiffree_bytes);

        // Chiffrer la cle avec cle publique
        // let cle_dechiffree = dechiffrer_asymetrique(private_key, &cle_chiffree_bytes);

        // println!("cle dechiffree bytes base64: {}, bytes: {:?}", encode(Base::Base64, &cle_dechiffree), cle_dechiffree);

        let cle_dechiffree = match &decipher_data.cle_dechiffree {
            Some(c) => c,
            None => Err("Cle n'est pas dechiffree")?,
        };

        let mut decrypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            cle_dechiffree,
            Some(&decipher_data.iv)
        ).unwrap();

        match decrypter.set_tag(decipher_data.tag.as_slice()) {
            Ok(()) => (),
            Err(e) => Err(format!("Erreur set tag : {:?}", e))?
        }

        Ok(DecipherMgs2 {
            decrypter
        })
    }

    pub fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String>{
        match self.decrypter.update(data, out) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, String> {
        match self.decrypter.finalize(out) {
            Ok(s) => Ok(s),
            Err(e) => {
                debug!("Erreur finalize {:?}", e);
                Err(format!("Erreur finalize : {:?}", e))
            },
        }
    }

}

impl Debug for DecipherMgs2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecipherMgs2")
    }
}

#[derive(Clone, Debug)]
pub struct Mgs2CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    pub iv: String,
    pub tag: String,
    pub fingerprint_cert_millegrille: Option<String>,
    pub hachage_bytes: String,
}

impl Mgs2CipherKeys {
    pub fn new(cles_chiffrees: Vec<FingerprintCleChiffree>, iv: String, tag: String, hachage_bytes: String) -> Self {
        Mgs2CipherKeys { cles_chiffrees, iv, tag, fingerprint_cert_millegrille: None, hachage_bytes }
    }

    pub fn set_fingerprint_cert_millegrille(&mut self, fingerprint_cert_millegrille: &str) {
        self.fingerprint_cert_millegrille = Some(fingerprint_cert_millegrille.into());
    }

    pub fn get_cipher_data(&self, fingerprint: &str) -> Result<Mgs2CipherData, Box<dyn Error>> {
        let mut cle = self.cles_chiffrees.iter().filter(|c| c.fingerprint == fingerprint);
        match cle.next() {
            Some(c) => {
                Ok(Mgs2CipherData::new(&c.cle_chiffree, &self.iv, &self.tag)?)
            },
            None => Err(format!("Cle introuvable : {}", fingerprint))?,
        }
    }

    pub fn get_format(&self) -> String {
        String::from("mgs2")
    }

    pub fn cles_to_map(&self) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        for cle in &self.cles_chiffrees {
            map.insert(cle.fingerprint.clone(), cle.cle_chiffree.clone());
        }
        map
    }

    pub fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>
    ) -> CommandeSauvegarderCle {

        let fingerprint_partitions = self.get_fingerprint_partitions();

        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes.clone(),
            cles: self.cles_to_map(),
            iv: self.iv.clone(),
            tag: self.tag.clone(),
            format: FormatChiffrage::mgs2,
            domaine: domaine.to_owned(),
            partition,
            identificateurs_document,
            fingerprint_partitions: Some(fingerprint_partitions),
        }
    }

    pub fn get_cle_millegrille(&self) -> Option<String> {
        // println!("info chiffrage : {:?}", self);
        match &self.fingerprint_cert_millegrille {
            Some(fp) => {
                match self.cles_chiffrees.iter().filter(|cle| cle.fingerprint == fp.as_str()).last() {
                    Some(cle) => {
                        Some(cle.cle_chiffree.to_owned())
                    },
                    None => None,
                }
            },
            None => None,
        }
    }

    /// Retourne une des partitions presentes dans la liste de cles
    pub fn get_fingerprint_partitions(&self) -> Vec<String> {
        match &self.fingerprint_cert_millegrille {
            Some(fp) => {
                self.cles_chiffrees.iter()
                    .filter(|c| c.fingerprint.as_str() != fp.as_str())
                    .map(|c| c.fingerprint.to_owned())
                    .collect()
            },
            None => {
                self.cles_chiffrees.iter()
                    .map(|c| c.fingerprint.to_owned())
                    .collect()
            }
        }
    }
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

#[derive(Clone)]
pub struct Mgs2CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<Vec<u8>>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl Mgs2CipherData {
    pub fn new(cle_chiffree: &str, iv: &str, tag: &str) -> Result<Self, Box<dyn Error>> {
        let cle_chiffree_bytes: Vec<u8> = decode(cle_chiffree)?.1;
        let iv_bytes: Vec<u8> = decode(iv)?.1;
        let tag_bytes: Vec<u8> = decode(tag)?.1;

        Ok(Mgs2CipherData {
            cle_chiffree: cle_chiffree_bytes,
            cle_dechiffree: None,
            iv: iv_bytes,
            tag: tag_bytes
        })
    }

    pub fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>> {
        let cle_dechiffree = dechiffrer_asymetrique(cle_privee, self.cle_chiffree.as_slice())?;
        self.cle_dechiffree = Some(cle_dechiffree);

        Ok(())
    }
}

impl Debug for Mgs2CipherData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs2CipherData iv: {:?}, tag: {:?}", self.iv, self.tag).as_str())
    }
}

/// Permet de recuperer un Cipher deja initalise avec les certificats de MaitreDesCles.
#[async_trait]
pub trait Chiffreur {
    /// Retourne les certificats qui peuvent etre utilises pour chiffrer une cle secrete.
    /// Devrait inclure le certificat de MilleGrille avec flag est_cle_millegrille==true.
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey>;

    /// Recupere un cipher initialise avec les cles publiques
    fn get_cipher(&self) -> Result<CipherMgs2, Box<dyn Error>> {
        let fp_public_keys = self.get_publickeys_chiffrage();
        Ok(CipherMgs2::new(&fp_public_keys)?)
    }

    /// Recycle les certificats de chiffrage - fait une requete pour obtenir les certs courants
    async fn charger_certificats_chiffrage(&self, cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>>;

    /// Recoit un certificat de chiffrage
    async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>>;

}

/// Permet de recuperer un Decipher deja initialise pour une cle
#[async_trait]
pub trait Dechiffreur: IsConfigurationPki + Send + Sync {
    /// Appel au MaitreDesCles pour une version dechiffrable de la cle
    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs2CipherData, Box<dyn Error>>;

    /// Cle privee locale pour dechiffrage
    // fn get_enveloppe_privee_dechiffrage(&self) -> Arc<EnveloppePrivee>;

    /// Retourne une instance de Decipher pleinement initialisee et prete a dechiffrer
    async fn get_decipher(&self, hachage_bytes: &str) -> Result<DecipherMgs2, Box<dyn Error>> {
        let mut info_cle = self.get_cipher_data(hachage_bytes).await?;
        let env_privee = self.get_enveloppe_privee();
        let cle_privee = env_privee.cle_privee();
        info_cle.dechiffrer_cle(cle_privee)?;

        Ok(DecipherMgs2::new(&info_cle)?)
    }
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

fn convertir_public_ed25519_to_x25519(public_key: &PKey<Public>) -> Result<PKey<Public>, Box<dyn Error>> {
    let cle_publique_bytes = public_key.raw_public_key()?;
    let mut cle_public_ref: PublicKey = [0u8; 32];
    cle_public_ref.clone_from_slice(&cle_publique_bytes[0..32]);
    let mut cle_publique_x25519: PublicKey = [0u8; 32];
    crypto_sign_ed25519::crypto_sign_ed25519_pk_to_curve25519(
        &mut cle_publique_x25519,
        &cle_public_ref
    )?;

    Ok(PKey::public_key_from_raw_bytes(&cle_publique_x25519, Id::X25519)?)
}

fn convertir_private_ed25519_to_x25519(ca_key: &PKey<Private>) -> Result<PKey<Private>, Box<dyn Error>> {
    let cle_privee_ca = ca_key.raw_private_key()?;
    debug!("Cle privee CA: {:?}", cle_privee_ca);
    // let cle_publique_ca = ca_key.raw_public_key()?;
    let mut cle_privee_ca_sk: SecretKey = [0u8; 64];
    cle_privee_ca_sk[0..32].copy_from_slice(&cle_privee_ca[..]);
    // cle_privee_ca_sk[32..64].copy_from_slice(&cle_publique_ca[..]);
    let mut cle_privee_ca_x25519 = [0u8; 32];
    crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519(
        &mut cle_privee_ca_x25519,
        &cle_privee_ca_sk
    );

    Ok(PKey::private_key_from_raw_bytes(&cle_privee_ca_x25519, Id::X25519)?)
}

#[cfg(test)]
mod backup_tests {
    use std::error::Error;
    use std::fs::read_to_string;
    use std::path::PathBuf;

    use openssl::pkey::{PKey, Private, Public};
    use openssl::rsa::Rsa;
    use openssl::x509::X509;

    use super::*;

    const PATH_CLE: &str = "/home/mathieu/mgdev/certs/pki.domaines.key";
    const PATH_CERT: &str = "/home/mathieu/mgdev/certs/pki.domaines.cert";

    fn charger_cles() -> (PKey<Public>, PKey<Private>) {
        // Cle privee
        let pem_cle = read_to_string(PathBuf::from(PATH_CLE)).unwrap();
        let cle_privee = Rsa::private_key_from_pem(pem_cle.as_bytes()).unwrap();
        let cle_privee: PKey<Private> = PKey::from_rsa(cle_privee).unwrap();

        // Cle publique
        let pem_cert = read_to_string(PathBuf::from(PATH_CERT)).unwrap();
        let stack = X509::stack_from_pem(pem_cert.as_bytes()).unwrap();
        let cert = stack.get(0).unwrap();
        let cle_publique = cert.public_key().unwrap();

        (cle_publique, cle_privee)
    }

    #[test]
    fn chiffrage_asymetrique() {
        // Cles
        let (cle_publique, cle_privee) = charger_cles();

        let mut buffer_random = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
        // println!("Buffer random : {:?}", encode(Base::Base64, &buffer_random));

        let ciphertext = chiffrer_asymetrique(&cle_publique, &buffer_random).expect("chiffrer");
        // println!("Ciphertext asymetrique : {:?}", encode(Base::Base64, &ciphertext));

        let buffer_dechiffre = dechiffrer_asymetrique(&cle_privee, &ciphertext).expect("dechiffrer");
        // println!("Buffer dechiffre : {:?}", encode(Base::Base64, &buffer_dechiffre));

        assert_eq!(buffer_random, buffer_dechiffre.as_slice());
    }

    #[test]
    fn roundtrip_chiffrage() {
        // Cles
        let (cle_publique, cle_privee) = charger_cles();
        let fp_cles = vec![FingerprintCertPublicKey::new(String::from("dummy"), cle_publique, true)];
        let mut cipher = CipherMgs2::new(&fp_cles).expect("cipher");

        // Chiffrer
        // println!("Crypter avec info\niv: {}\ncle chiffree: {}", cipher.iv, cipher.cle_chiffree);
        let input = b"Data en input";
        let mut output = [0u8; 13];

        let len_output = cipher.update(input, &mut output).expect("output");
        assert_eq!(len_output, input.len());

        let _ = cipher.finalize(&mut output).expect("finalize");
        let tag = cipher.tag.as_ref().expect("tag").to_owned();
        assert_eq!(tag.len(), 23);

        // println!("Output tag: {}\nCiphertext: {}", tag, encode(Base::Base64, output));

        // Dechiffrer
        let cipher_keys = cipher.get_cipher_keys().expect("keys");
        let mut cipher_data = cipher_keys.get_cipher_data("dummy").expect("cle dummy");
        // let mut cipher_data = Mgs2CipherData::new(
        //     &cipher.cle_chiffree,
        //     &cipher.iv,
        //     &tag,
        // ).expect("cipher_data");
        cipher_data.dechiffrer_cle(&cle_privee).expect("Dechiffrer cle");
        let mut dechiffreur = DecipherMgs2::new(&cipher_data).expect("dechiffreur");

        let mut dechiffrer_out= [0u8; 13];
        let _ = dechiffreur.update(&output, &mut dechiffrer_out).expect("dechiffrer");
        assert_eq!(&dechiffrer_out, input);

        let vec_out = dechiffrer_out.to_vec();
        let _ = String::from_utf8(vec_out).expect("str out");
        // println!("Contenu dechiffre : {:?} (len {})", dechiffre_str, len_decipher);

    }

}
