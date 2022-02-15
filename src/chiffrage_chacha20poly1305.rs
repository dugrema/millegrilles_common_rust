use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};

use aead::NewAead;
use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::pkey::{PKey, Private};

use crate::certificats::FingerprintCertPublicKey;
use crate::chacha20poly1305_incremental::{ChaCha20Poly1305, AeadUpdate};
use crate::chiffrage::{CipherMgs, CleSecrete, CommandeSauvegarderCle, DecipherMgs, FingerprintCleChiffree, FormatChiffrage, MgsCipherData, MgsCipherKeys};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519};
use crate::hachages::Hacheur;

pub struct CipherMgs3 {
    encrypter: ChaCha20Poly1305,
    iv: String,
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    fp_cle_millegrille: Option<String>,
    hacheur: Hacheur,
    hachage_bytes: Option<String>,
    tag: Option<String>,
}

impl CipherMgs3 {

    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Result<Self, Box<dyn Error>> {

        let mut buffer_random = [0u8; 12];
        openssl::rand::rand_bytes(&mut buffer_random).expect("rand");

        let nonce = &buffer_random[0..12];

        // Deriver une cle secrete avec la cle publique de millegrille
        let mut fp_cles = Vec::new();
        let cle_millegrille = {
            let mut cle_millegrille_v: Vec<&FingerprintCertPublicKey> = public_keys.iter()
                .filter(|k| k.est_cle_millegrille).collect();
            match cle_millegrille_v.pop() {
                Some(c) => c,
                None => Err(format!("CipherMgs3::new Cle de millegrille manquante"))?
            }
        };
        // Deriver cle secrete
        let cle_derivee = deriver_asymetrique_ed25519(&cle_millegrille.public_key)?;

        // Conserver cle peer pour la cle de millegrille. Permet de deriver a nouveau la cle
        // secrete en utilisant la cle privee du certificat de millegrille.
        fp_cles.push(FingerprintCleChiffree {
            fingerprint: cle_millegrille.fingerprint.clone(),
            cle_chiffree: multibase::encode(Base::Base64, cle_derivee.public_peer)
        });

        // Rechiffrer la cle derivee pour toutes les cles publiques
        for fp_pk in public_keys {
            if fp_pk.est_cle_millegrille { continue; }  // Skip cle de millegrille, deja faite
            let cle_chiffree = chiffrer_asymmetrique_ed25519(&cle_derivee.secret.0, &fp_pk.public_key)?;
            let cle_str = multibase::encode(Base::Base64, cle_chiffree);
            fp_cles.push(FingerprintCleChiffree {
                fingerprint: fp_pk.fingerprint.clone(),
                cle_chiffree: cle_str
            });
        }

        let mut encrypter = ChaCha20Poly1305::new(&cle_derivee.secret.0.into());
        encrypter.set_nonce(nonce.into());

        let hacheur = Hacheur::builder()
            .digester(Code::Blake2b512)
            .base(Base::Base58Btc)
            .build();

        Ok(CipherMgs3 {
            encrypter,
            iv: encode(Base::Base64, nonce),
            cles_chiffrees: fp_cles,
            fp_cle_millegrille: Some(cle_millegrille.fingerprint.clone()),
            hacheur,
            hachage_bytes: None,
            tag: None,
        })
    }
}

impl CipherMgs<Mgs3CipherKeys> for CipherMgs3 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {

        // Deplacer source dans buffer out. Chiffrage fait "in place".
        let out_len = if data.is_empty() {
            debug!("!!!1 Data Empty!");
            out.len()
        } else {
            debug!("!!!1 Data pas empty!, taille {}", data.len());
            out.copy_from_slice(data);
            data.len()
        };

        match self.encrypter.encrypt_update(out) {
            Ok(()) => {
                self.hacheur.update(&out[..]);  // Calculer hachage output

                // Stream encryption, le nombre de bytes chiffres est le meme que bytes en entree
                Ok(out_len)
            },
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    fn finalize(mut self, _out: &mut [u8]) -> Result<(usize, Mgs3CipherKeys), String> {

        if self.tag.is_some() {
            Err("Deja finalise")?;
        }

        match self.encrypter.encrypt_finalize() {
            Ok(tag) => {
                // Calculer et conserver hachage
                let hachage_bytes = self.hacheur.finalize();

                // Conserver le compute tag
                let tag_b64 = encode(Base::Base64, &tag);

                let mut cipher_keys = Mgs3CipherKeys::new(
                    self.cles_chiffrees.clone(),
                    self.iv.clone(),
                    tag_b64,
                    hachage_bytes,
                );
                cipher_keys.fingerprint_cert_millegrille = self.fp_cle_millegrille.clone();

                Ok((0, cipher_keys))
            },
            Err(e) => Err(format!("Erreur update : {:?}", e)),
        }
    }

}


pub struct DecipherMgs3 {
    decrypter: ChaCha20Poly1305,
    tag: [u8; 16],
}

impl DecipherMgs3 {

    // pub fn new(private_key: &PKey<Private>, cle_chiffree: &str, iv: &str, tag: &str) -> Result<Self, String> {
    pub fn new(decipher_data: &Mgs3CipherData) -> Result<Self, String> {

        // let (_, tag_bytes) = decode(tag).expect("tag");
        // let (_, iv_bytes) = decode(iv).expect("tag");
        // let (_, cle_chiffree_bytes) = decode(cle_chiffree).expect("cle_chiffree");
        // println!("tag {:?}\niv {:?}\ncle chiffree bytes {:?}", tag_bytes, iv_bytes, cle_chiffree_bytes);

        // Dechiffrer la cle avec cle privee
        // let cle_dechiffree = dechiffrer_asymetrique(private_key, &cle_chiffree_bytes)?;

        // println!("cle dechiffree bytes base64: {}, bytes: {:?}", encode(Base::Base64, &cle_dechiffree), cle_dechiffree);

        let cle_dechiffree = match &decipher_data.cle_dechiffree {
            Some(c) => c,
            None => Err("Cle n'est pas dechiffree")?,
        };

        let mut decrypter = ChaCha20Poly1305::new(&cle_dechiffree.0.into());
        decrypter.set_nonce(decipher_data.iv[..].into());

        // let hacheur = Hacheur::builder()
        //     .digester(Code::Blake2b512)
        //     .base(Base::Base58Btc)
        //     .build();

        // let mut decrypter = Crypter::new(
        //     Cipher::aes_256_gcm(),
        //     Mode::Decrypt,
        //     cle_dechiffree,
        //     Some(&decipher_data.iv)
        // ).unwrap();

        // match decrypter.set_tag(decipher_data.tag.as_slice()) {
        //     Ok(()) => (),
        //     Err(e) => Err(format!("Erreur set tag : {:?}", e))?
        // }

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&decipher_data.tag[0..16]);

        Ok(DecipherMgs3 { decrypter, tag })
    }

}

impl DecipherMgs<Mgs3CipherData> for DecipherMgs3 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {

        let out_len = if data.is_empty() {
            // Input data vide, on assume que le data a dechiffrer
            // est deja dans out (dechiffrage "in place")
            out.len()
        } else {
            // Copier data vers out, dechiffrage se fait "in place"
            out.copy_from_slice(data);
            data.len()
        };

        match self.decrypter.decrypt_update(out) {
            Ok(()) => Ok(out_len),
            Err(e) => Err(format!("Erreur update : {:?}", e))
        }
    }

    fn finalize(self, _out: &mut [u8]) -> Result<usize, String> {
        match self.decrypter.decrypt_finalize(self.tag[0..16].into()) {
            Ok(()) => Ok(0),
            Err(e) => Err(format!("Erreur finalize : {:?}", e))
        }
    }

}

impl Debug for DecipherMgs3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecipherMgs3")
    }
}






#[derive(Clone, Debug)]
pub struct Mgs3CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    pub iv: String,
    pub tag: String,
    pub fingerprint_cert_millegrille: Option<String>,
    pub hachage_bytes: String,
}

impl Mgs3CipherKeys {
    pub fn new(cles_chiffrees: Vec<FingerprintCleChiffree>, iv: String, tag: String, hachage_bytes: String) -> Self {
        Mgs3CipherKeys { cles_chiffrees, iv, tag, fingerprint_cert_millegrille: None, hachage_bytes }
    }

    pub fn set_fingerprint_cert_millegrille(&mut self, fingerprint_cert_millegrille: &str) {
        self.fingerprint_cert_millegrille = Some(fingerprint_cert_millegrille.into());
    }

    pub fn get_cipher_data(&self, fingerprint: &str) -> Result<Mgs3CipherData, Box<dyn Error>> {
        let mut cle = self.cles_chiffrees.iter().filter(|c| c.fingerprint == fingerprint);
        match cle.next() {
            Some(c) => {
                Ok(Mgs3CipherData::new(&c.cle_chiffree, &self.iv, &self.tag)?)
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

impl MgsCipherKeys for Mgs3CipherKeys {

    fn get_commande_sauvegarder_cles(
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
            format: FormatChiffrage::mgs3,
            domaine: domaine.to_owned(),
            partition,
            identificateurs_document,
            fingerprint_partitions: Some(fingerprint_partitions),
        }
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

pub struct Mgs3CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<CleSecrete>,
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl Mgs3CipherData {
    pub fn new(cle_chiffree: &str, iv: &str, tag: &str) -> Result<Self, Box<dyn Error>> {
        let cle_chiffree_bytes: Vec<u8> = decode(cle_chiffree)?.1;
        let iv_bytes: Vec<u8> = decode(iv)?.1;
        let tag_bytes: Vec<u8> = decode(tag)?.1;

        Ok(Mgs3CipherData {
            cle_chiffree: cle_chiffree_bytes,
            cle_dechiffree: None,
            iv: iv_bytes,
            tag: tag_bytes
        })
    }
}

impl MgsCipherData for Mgs3CipherData {

    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>> {
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(self.cle_chiffree.as_slice(), cle_privee)?;
        self.cle_dechiffree = Some(cle_dechiffree);

        Ok(())
    }

}

impl Debug for Mgs3CipherData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs2CipherData iv: {:?}, tag: {:?}", self.iv, self.tag).as_str())
    }
}

#[cfg(test)]
mod test {
    use openssl::pkey::{Id, PKey};
    use crate::test_setup::setup;
    use super::*;

    #[test]
    fn test_cipher3_vide() -> Result<(), Box<dyn Error>> {
        setup("test_cipher3_vide");

        // Generer deux cles
        let cle_millegrille = PKey::generate_ed25519()?;
        let cle_millegrille_public = PKey::public_key_from_raw_bytes(
            &cle_millegrille.raw_public_key()?, Id::ED25519)?;
        let cle_maitrecles1 = PKey::generate_ed25519()?;
        let cle_maitrecles1_public = PKey::public_key_from_raw_bytes(
            &cle_maitrecles1.raw_public_key()?, Id::ED25519)?;

        let mut fpkeys = Vec::new();
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "CleMillegrille".into(),
            public_key: cle_millegrille_public,
            est_cle_millegrille: true,
        });
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "MaitreCles1".into(),
            public_key: cle_maitrecles1_public,
            est_cle_millegrille: false,
        });

        // Chiffrer contenu "vide"
        let cipher = CipherMgs3::new(&fpkeys)?;
        debug!("Nouveau cipher info : iv = {:?}\nCles chiffrees: {:?}", cipher.iv, cipher.cles_chiffrees);
        let (out_len, info_keys) = cipher.finalize(&mut [0u8])?;
        debug!("Output keys : {:?}", info_keys);

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs3CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.iv.as_str(), info_keys.tag.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs3::new(&decipher_data)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage CleMillegrille : {}.", out_len);
                assert_eq!(out_len, 0);
            } else if key.fingerprint.as_str() == "MaitreCles1" {
                // Test dechiffrage avec cle de MaitreDesCles (cle chiffree est 80 bytes : 32 bytes peer public, 32 bytes chiffre, 16 bytes tag)
                debug!("Test dechiffrage avec MaitreCles1");
                let mut decipher_data = Mgs3CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.iv.as_str(), info_keys.tag.as_str())?;
                decipher_data.dechiffrer_cle(&cle_maitrecles1)?;
                let mut decipher = DecipherMgs3::new(&decipher_data)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage MaitreCles1 : {}.", out_len);
                assert_eq!(out_len, 0);
            }
        }

        Ok(())
    }

    #[test]
    fn test_cipher3_message_court() -> Result<(), Box<dyn Error>> {
        setup("test_cipher3_message_court");

        // Generer cle
        let cle_millegrille = PKey::generate_ed25519()?;
        let cle_millegrille_public = PKey::public_key_from_raw_bytes(
            &cle_millegrille.raw_public_key()?, Id::ED25519)?;

        let mut fpkeys = Vec::new();
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "CleMillegrille".into(),
            public_key: cle_millegrille_public,
            est_cle_millegrille: true,
        });

        // Chiffrer contenu "vide"
        const MESSAGE_COURT: &[u8] = b"Ceci est un msg";  // Message 15 bytes
        let mut output_chiffre = MESSAGE_COURT.to_owned();
        let mut output_buffer = output_chiffre.as_mut_slice();
        let mut cipher = CipherMgs3::new(&fpkeys)?;
        debug!("Chiffrer message de {} bytes", output_buffer.len());
        let taille_chiffree = cipher.update(&[0u8][0..0], output_buffer)?;
        let (out_len, info_keys) = cipher.finalize(&mut [0u8])?;
        debug!("Output chiffrage (confirmation taille: {}): {:?}.", taille_chiffree, output_buffer);

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs3CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.iv.as_str(), info_keys.tag.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs3::new(&decipher_data)?;

                // Dechiffrer message
                decipher.update(&[0u8][0..0], output_buffer)?;

                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output dechiffrage CleMillegrille : {:?}.", String::from_utf8(output_buffer.to_vec()));
                assert_eq!(out_len, 0);
                assert_eq!(MESSAGE_COURT, output_buffer);
            }

        }

        Ok(())
    }

    #[test]
    fn test_cipher3_message_1mb() -> Result<(), Box<dyn Error>> {
        setup("test_cipher3_message_1mb");

        // Generer cle
        let cle_millegrille = PKey::generate_ed25519()?;
        let cle_millegrille_public = PKey::public_key_from_raw_bytes(
            &cle_millegrille.raw_public_key()?, Id::ED25519)?;

        let mut fpkeys = Vec::new();
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "CleMillegrille".into(),
            public_key: cle_millegrille_public,
            est_cle_millegrille: true,
        });

        // Message 10MB, valeur 5 partout
        let mut message_long = Vec::new();
        message_long.reserve(1024*1024);
        message_long.resize(1024*1024, 0x5);  // 1 MB
        let mut output_buffer = message_long.as_mut_slice();

        let mut cipher = CipherMgs3::new(&fpkeys)?;
        debug!("Chiffrer message de {} bytes", output_buffer.len());
        let taille_chiffree = cipher.update(&[0u8][0..0], output_buffer)?;
        let (out_len, info_keys) = cipher.finalize(&mut [0u8])?;
        debug!("Output chiffrage (confirmation taille: {}).", taille_chiffree);

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs3CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.iv.as_str(), info_keys.tag.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs3::new(&decipher_data)?;

                // Dechiffrer message
                decipher.update(&[0u8][0..0], output_buffer)?;

                let out_len = decipher.finalize(&mut [0u8])?;
                assert_eq!(out_len, 0);
                for val in output_buffer.iter() {
                    assert_eq!(*val, 0x5);
                }
                debug!("Output dechiffrage CleMillegrille message long OK");
            }

        }

        Ok(())
    }

}
