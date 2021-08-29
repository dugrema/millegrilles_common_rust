use rand::Rng;
use openssl::symm::{encrypt, Cipher, Crypter, Mode};
use openssl::pkey::{Public, PKey, Private};
use openssl::rsa::{Padding, Rsa};
use multibase::{Base, encode, decode};
use std::io::Write;
use std::cmp::min;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use std::fmt::{Debug, Formatter};
use std::error::Error;
use crate::FingerprintCertPublicKey;

#[derive(Clone, Debug)]
pub enum FormatChiffrage {
    Mgs2,
}

fn chiffrer_asymetrique(public_key: &PKey<Public>, cle_symmetrique: &[u8]) -> [u8; 256] {
    let mut cle_chiffree = [0u8; 256];

    let mut encrypter = Encrypter::new(public_key).expect("encrypter");
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP);
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256());
    encrypter.set_rsa_oaep_md(MessageDigest::sha256());
    encrypter.encrypt(cle_symmetrique, &mut cle_chiffree).expect("encrypt PK");

    cle_chiffree
}

fn dechiffrer_asymetrique(private_key: &PKey<Private>, cle_chiffree_bytes: &[u8]) -> Vec<u8> {
    let mut cle_dechiffree = [0u8; 256];

    let mut decrypter = Decrypter::new(private_key).expect("decrypter");

    decrypter.set_rsa_padding(Padding::PKCS1_OAEP);
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256());
    decrypter.set_rsa_oaep_md(MessageDigest::sha256());
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
}

// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug)]
pub struct FingerprintCleChiffree {
    fingerprint: String,
    cle_chiffree: String,
}

impl CipherMgs2 {
    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Self {
        let mut buffer_random = [0u8; 44];
        openssl::rand::rand_bytes(&mut buffer_random);

        let cle = &buffer_random[0..32];
        let iv = &buffer_random[32..44];

        // Chiffrer la cle avec cle publique
        let mut fp_cles = Vec::new();
        for fp_pk in public_keys {
            let cle_chiffree = chiffrer_asymetrique(&fp_pk.public_key, &cle);
            let cle_chiffree_str = encode(Base::Base64, cle_chiffree);
            fp_cles.push(FingerprintCleChiffree {
                fingerprint: fp_pk.fingerprint.clone(),
                cle_chiffree: cle_chiffree_str}
            );
        }

        let mut encrypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Encrypt,
            cle,
            Some(iv)
        ).unwrap();

        CipherMgs2 {
            encrypter,
            iv: encode(Base::Base64, iv),
            cles_chiffrees: fp_cles,
        }
    }

    pub fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        match self.encrypter.update(data, out) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    pub fn finalize(&mut self, out: &mut [u8]) -> Result<usize, String> {
        match self.encrypter.finalize(out) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("Erreur update : {:?}", e)),
        }
    }

    pub fn get_tag(&self) -> Result<String, String> {
        let mut tag = [0u8; 16];
        match self.encrypter.get_tag(&mut tag) {
            Ok(()) => {
                Ok(encode(Base::Base64, &tag))
            },
            Err(e) => Err(format!("Erreur tag : {:?}", e)),
        }
    }

    pub fn get_cipher_keys(&self) -> Result<Mgs2CipherKeys, String> {
        Ok(Mgs2CipherKeys::new(
            self.cles_chiffrees.clone(),
            self.iv.clone(),
            self.get_tag()?.clone(),
        ))
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

        let decrypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            cle_dechiffree,
            Some(&decipher_data.iv)
        ).unwrap();

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
            Err(e) => Err(format!("Erreur update : {:?}", e)),
        }
    }

}

#[derive(Clone, Debug)]
pub struct Mgs2CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    iv: String,
    tag: String,
}

impl Mgs2CipherKeys {
    pub fn new(cles_chiffrees: Vec<FingerprintCleChiffree>, iv: String, tag: String) -> Self {
        Mgs2CipherKeys { cles_chiffrees, iv, tag }
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
}

#[derive(Clone)]
pub struct Mgs2CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<Vec<u8>>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl Mgs2CipherData {
    pub fn new(cle_chiffree: &String, iv: &String, tag: &String) -> Result<Self, Box<dyn Error>> {
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

#[cfg(test)]
mod backup_tests {
    use super::*;
    use std::fs::read_to_string;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::x509::X509;
    use std::error::Error;
    use std::path::PathBuf;
    use openssl::rsa::Rsa;

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
        openssl::rand::rand_bytes(&mut buffer_random);
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
        let fp_cles = vec![FingerprintCertPublicKey::new(String::from("dummy"), cle_publique)];
        let mut cipher = CipherMgs2::new(&fp_cles);

        // Chiffrer
        // println!("Crypter avec info\niv: {}\ncle chiffree: {}", cipher.iv, cipher.cle_chiffree);
        let input = b"Data en input";
        let mut output = [0u8; 13];

        let len_output = cipher.update(input, &mut output).expect("output");
        assert_eq!(len_output, input.len());

        let len_output = cipher.finalize(&mut output).expect("finalize");
        let tag = cipher.get_tag().expect("tag");
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
