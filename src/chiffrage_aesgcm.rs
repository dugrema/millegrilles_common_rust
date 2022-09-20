/// Implementation mgs2
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};

use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::pkey::{PKey, Private};
use openssl::symm::{Cipher, Crypter, Mode};

use crate::certificats::FingerprintCertPublicKey;
use crate::chiffrage::{CipherMgs, DecipherMgs, FormatChiffrage, MgsCipherData, MgsCipherKeys};
use crate::chiffrage_cle::{CommandeSauvegarderCle, FingerprintCleChiffree};
use crate::chiffrage_rsa::*;
use crate::hachages::Hacheur;

pub struct CipherMgs2 {
    encrypter: Crypter,
    iv: String,
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    fp_cle_millegrille: Option<String>,
    hacheur: Hacheur,
    hachage_bytes: Option<String>,
    tag: Option<String>,
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
}

impl CipherMgs<Mgs2CipherKeys> for CipherMgs2 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        match self.encrypter.update(data, out) {
            Ok(s) => {
                self.hacheur.update(&out[..s]);  // Calculer hachage output
                Ok(s)
            },
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<(usize, Mgs2CipherKeys), String> {

        if self.tag.is_some() {
            Err("Deja finalise")?;
        }

        match self.encrypter.finalize(out) {
            Ok(s) => {
                self.hacheur.update(&out[..s]);  // Calculer hachage output

                // Calculer et conserver hachage
                let hachage_bytes = self.hacheur.finalize();

                // Conserver le compute tag
                let mut tag = [0u8; 16];
                let tag_b64 = match self.encrypter.get_tag(&mut tag) {
                    Ok(()) => Ok(encode(Base::Base64, &tag)),
                    Err(e) => Err(format!("Erreur tag : {:?}", e)),
                }?;

                let mut cipher_keys = Mgs2CipherKeys::new(
                    self.cles_chiffrees.clone(),
                    self.iv.clone(),
                    tag_b64,
                    hachage_bytes,
                );
                cipher_keys.fingerprint_cert_millegrille = self.fp_cle_millegrille.clone();

                Ok((s, cipher_keys))
            },
            Err(e) => Err(format!("Erreur update : {:?}", e)),
        }
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

}

impl DecipherMgs<Mgs2CipherData> for DecipherMgs2 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        match self.decrypter.update(data, out) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<usize, String> {
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

impl MgsCipherKeys for Mgs2CipherKeys {

    fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>
    ) -> CommandeSauvegarderCle {

        let fingerprint_partitions = self.get_fingerprint_partitions();

        todo!("Calculer signature identite")
        // CommandeSauvegarderCle {
        //     hachage_bytes: self.hachage_bytes.clone(),
        //     domaine: domaine.to_owned(),
        //     identificateurs_document,
        //     user_id,
        //     signature_identite: ,
        //
        //     cles: self.cles_to_map(),
        //
        //     format: FormatChiffrage::mgs2,
        //     iv: Some(self.iv.clone()),
        //     tag: Some(self.tag.clone()),
        //     header: None,
        //
        //     partition,
        //     fingerprint_partitions: Some(fingerprint_partitions),
        // }
    }

    fn get_cle_millegrille(&self) -> Option<String> {
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
}

impl MgsCipherData for Mgs2CipherData {

    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>> {
        let cle_dechiffree = dechiffrer_asymetrique(cle_privee, self.cle_chiffree.as_slice())?;
        self.cle_dechiffree = Some(cle_dechiffree.0.into());

        Ok(())
    }

}

impl Debug for Mgs2CipherData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs2CipherData iv: {:?}, tag: {:?}", self.iv, self.tag).as_str())
    }
}

#[cfg(test)]
mod chiffrage_tests {
    use std::fs::read_to_string;
    use std::path::PathBuf;

    use openssl::pkey::{PKey, Private, Public};
    use openssl::rsa::Rsa;
    use openssl::x509::X509;

    use crate::test_setup::setup;

    use super::*;

    const PATH_CLE: &str = "/home/mathieu/mgdev/certs/pki.web.key";
    const PATH_CERT: &str = "/home/mathieu/mgdev/certs/pki.web.cert";

    fn charger_cles() -> (PKey<Public>, PKey<Private>) {
        setup("charger_cles");

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

    // #[test]
    // fn chiffrage_asymetrique() {
    //     setup("chiffrage_asymetrique");
    //
    //     // Cles
    //     let (cle_publique, cle_privee) = charger_cles();
    //
    //     let mut buffer_random = [0u8; 32];
    //     openssl::rand::rand_bytes(&mut buffer_random).expect("rand");
    //     debug!("Buffer random : {:?}", encode(Base::Base64, &buffer_random));
    //
    //     let ciphertext = chiffrer_asymetrique(&cle_publique, &buffer_random).expect("chiffrer");
    //     debug!("Ciphertext asymetrique : {:?}", encode(Base::Base64, &ciphertext));
    //
    //     let buffer_dechiffre = dechiffrer_asymetrique(&cle_privee, &ciphertext).expect("dechiffrer");
    //     debug!("Buffer dechiffre : {:?}", encode(Base::Base64, &buffer_dechiffre));
    //
    //     assert_eq!(buffer_random, buffer_dechiffre.as_slice());
    // }

    #[test]
    fn roundtrip_chiffrage() {
        // Cles
        let (cle_publique, cle_privee) = charger_cles();
        let fp_cles = vec![FingerprintCertPublicKey::new(String::from("dummy"), cle_publique, true)];
        let mut cipher = CipherMgs2::new(&fp_cles).expect("cipher");

        // Chiffrer
        debug!("Crypter avec info\niv: {}\ncle chiffree: {:?}", cipher.iv, cipher.cles_chiffrees);
        let input = b"Data en input";
        let mut output = [0u8; 13];

        let len_output = cipher.update(input, &mut output).expect("output");
        assert_eq!(len_output, input.len());

        let (_outlen, cipher_keys) = cipher.finalize(&mut output).expect("finalize");
        let tag = cipher_keys.tag.clone();
        assert_eq!(tag.len(), 23);

        debug!("Output tag: {}\nCiphertext: {}", tag, encode(Base::Base64, output));

        // Dechiffrer
        let mut cipher_data = cipher_keys.get_cipher_data("dummy").expect("cle dummy");
        cipher_data.dechiffrer_cle(&cle_privee).expect("Dechiffrer cle");
        let mut dechiffreur = DecipherMgs2::new(&cipher_data).expect("dechiffreur");

        let mut dechiffrer_out= [0u8; 13];
        let _ = dechiffreur.update(&output, &mut dechiffrer_out).expect("dechiffrer");
        assert_eq!(&dechiffrer_out, input);

        let vec_out = dechiffrer_out.to_vec();
        let str_out = String::from_utf8(vec_out).expect("str out");
        debug!("Contenu dechiffre : {:?} (len {})", str_out, str_out.len());

    }

}
