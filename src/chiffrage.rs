use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::io::Write;
use std::iter::Map;
use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, encrypt, Mode};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ordered_map};
use crate::hachages::Hacheur;
use crate::middleware::IsConfigurationPki;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FormatChiffrage {
    mgs2,
}

fn chiffrer_asymetrique(public_key: &PKey<Public>, cle_symmetrique: &[u8]) -> Vec<u8> {
    const SIZE_MAX: usize = 4096/8;
    if public_key.size() > SIZE_MAX {
        panic!("Taille de la cle ({}) est trop grande pour le buffer ({})", public_key.size(), SIZE_MAX);
    }

    let mut cle_chiffree = [0u8; SIZE_MAX];

    let mut encrypter = Encrypter::new(public_key).expect("encrypter");
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).expect("padding");
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).expect("mgf1");
    encrypter.set_rsa_oaep_md(MessageDigest::sha256()).expect("oaep");
    let size = encrypter.encrypt(cle_symmetrique, &mut cle_chiffree).expect("encrypt PK");

    let mut buffer_ajuste = Vec::new();
    buffer_ajuste.extend_from_slice(&cle_chiffree[..size]);

    buffer_ajuste
}

fn dechiffrer_asymetrique(private_key: &PKey<Private>, cle_chiffree_bytes: &[u8]) -> Vec<u8> {
    let mut cle_dechiffree = [0u8; 512];  // Cle max 4096 bits (512 bytes)

    let mut decrypter = Decrypter::new(private_key).expect("decrypter");

    decrypter.set_rsa_padding(Padding::PKCS1_OAEP).expect("padding");
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256()).expect("mgf1");
    decrypter.set_rsa_oaep_md(MessageDigest::sha256()).expect("oaep");
    decrypter.decrypt(cle_chiffree_bytes, &mut cle_dechiffree).expect("encrypt PK");

    let cle_dechiffree = &cle_dechiffree[..32];
    cle_dechiffree.to_vec().to_owned()
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
    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Self {
        let mut buffer_random = [0u8; 44];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");

        let cle = &buffer_random[0..32];
        let iv = &buffer_random[32..44];

        // Chiffrer la cle avec cle publique
        let mut fp_cles = Vec::new();
        let mut fp_cle_millegrille: Option<String> = None;
        for fp_pk in public_keys {
            let cle_chiffree = chiffrer_asymetrique(&fp_pk.public_key, &cle);
            let cle_chiffree_str = encode(Base::Base64, cle_chiffree);
            fp_cles.push(FingerprintCleChiffree {
                fingerprint: fp_pk.fingerprint.clone(),
                cle_chiffree: cle_chiffree_str}
            );
            if fp_pk.est_cle_millegrille {
                fp_cle_millegrille = Some(fp_pk.fingerprint.clone());
            }
        }

        let mut encrypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Encrypt,
            cle,
            Some(iv)
        ).unwrap();

        let hacheur = Hacheur::builder()
            .digester(Code::Sha2_512)
            .base(Base::Base58Btc)
            .build();

        CipherMgs2 {
            encrypter,
            iv: encode(Base::Base64, iv),
            cles_chiffrees: fp_cles,
            fp_cle_millegrille,
            hacheur,
            hachage_bytes: None,
            tag: None,
        }
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

        decrypter.set_tag(decipher_data.tag.as_slice());

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
        CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes.clone(),
            cles: self.cles_to_map(),
            iv: self.iv.clone(),
            tag: self.tag.clone(),
            format: FormatChiffrage::mgs2,
            domaine: domaine.to_owned(),
            partition,
            identificateurs_document,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandeSauvegarderCle {
    #[serde(serialize_with = "ordered_map")]
    cles: HashMap<String, String>,
    domaine: String,
    partition: Option<String>,
    format: FormatChiffrage,
    pub hachage_bytes: String,
    #[serde(serialize_with = "ordered_map")]
    identificateurs_document: HashMap<String, String>,
    iv: String,
    tag: String,
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
        let cle_dechiffree = dechiffrer_asymetrique(cle_privee, self.cle_chiffree.as_slice());
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
pub trait Chiffreur {
    /// Retourne les certificats qui peuvent etre utilises pour chiffrer une cle secrete.
    /// Devrait inclure le certificat de MilleGrille avec flag est_cle_millegrille==true.
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey>;

    /// Recupere un cipher initialise avec les cles publiques
    fn get_cipher(&self) -> CipherMgs2 {
        let fp_public_keys = self.get_publickeys_chiffrage();
        CipherMgs2::new(&fp_public_keys)
    }
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
    let mut rnd_bytes = [0u8; 32];
    for i in 0..nb_loops {
        rnd_bytes = rnd.gen();
        v.extend_from_slice(&rnd_bytes[0..32]);
    }

    // Ajouter bytes manquants
    if restant > 0 {
        for i in 0..restant {
            let byte: u8 = rnd.gen();
            v.push(byte);
        }
    }

    v
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

        let ciphertext = chiffrer_asymetrique(&cle_publique, &buffer_random);
        // println!("Ciphertext asymetrique : {:?}", encode(Base::Base64, &ciphertext));

        let buffer_dechiffre = dechiffrer_asymetrique(&cle_privee, &ciphertext);
        // println!("Buffer dechiffre : {:?}", encode(Base::Base64, &buffer_dechiffre));

        assert_eq!(buffer_random, buffer_dechiffre.as_slice());
    }

    #[test]
    fn roundtrip_chiffrage() {
        // Cles
        let (cle_publique, cle_privee) = charger_cles();
        let fp_cles = vec![FingerprintCertPublicKey::new(String::from("dummy"), cle_publique, true)];
        let mut cipher = CipherMgs2::new(&fp_cles);

        // Chiffrer
        // println!("Crypter avec info\niv: {}\ncle chiffree: {}", cipher.iv, cipher.cle_chiffree);
        let input = b"Data en input";
        let mut output = [0u8; 13];

        let len_output = cipher.update(input, &mut output).expect("output");
        assert_eq!(len_output, input.len());

        let len_output = cipher.finalize(&mut output).expect("finalize");
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
        let len_decipher = dechiffreur.update(&output, &mut dechiffrer_out).expect("dechiffrer");
        assert_eq!(&dechiffrer_out, input);

        let vec_out = dechiffrer_out.to_vec();
        let dechiffre_str = String::from_utf8(vec_out).expect("str out");
        // println!("Contenu dechiffre : {:?} (len {})", dechiffre_str, len_decipher);

    }

}
