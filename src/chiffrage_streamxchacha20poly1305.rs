use std::collections::HashMap;
use std::error::Error;
use core::fmt::Formatter;
use std::fmt::Debug;
use multibase::{Base, decode};
use openssl::pkey::{PKey, Private};

use crate::certificats::FingerprintCertPublicKey;
use crate::chiffrage::{CipherMgs, CleSecrete, CommandeSauvegarderCle, DecipherMgs, FingerprintCleChiffree, FormatChiffrage, MgsCipherData, MgsCipherKeys};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519};
use crate::hachages::Hacheur;

/// Implementation mgs4
pub struct CipherMgs4 {
    // encrypter: ChaCha20Poly1305,
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    fp_cle_millegrille: Option<String>,
    hacheur: Hacheur,
    hachage_bytes: Option<String>,
    header: Option<String>,
}

impl CipherMgs4 {

    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Result<Self, Box<dyn Error>> {

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

        todo!("fix me")
        // let mut encrypter = ChaCha20Poly1305::new(&cle_derivee.secret.0.into());
        // encrypter.set_nonce(nonce.into());
        //
        // let hacheur = Hacheur::builder()
        //     .digester(Code::Blake2b512)
        //     .base(Base::Base58Btc)
        //     .build();
        //
        // Ok(CipherMgs3 {
        //     encrypter,
        //     iv: encode(Base::Base64, nonce),
        //     cles_chiffrees: fp_cles,
        //     fp_cle_millegrille: Some(cle_millegrille.fingerprint.clone()),
        //     hacheur,
        //     hachage_bytes: None,
        //     tag: None,
        // })
    }
}

impl CipherMgs<Mgs4CipherKeys> for CipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        todo!("fix me")
        // // Deplacer source dans buffer out. Chiffrage fait "in place".
        // let out_len = if data.is_empty() {
        //     0
        // } else {
        //     out[0..data.len()].copy_from_slice(data);
        //     data.len()
        // };
        //
        // match self.encrypter.encrypt_update(&mut out[0..data.len()]) {
        //     Ok(()) => {
        //         self.hacheur.update(&out[0..data.len()]);  // Calculer hachage output
        //
        //         // Stream encryption, le nombre de bytes chiffres est le meme que bytes en entree
        //         Ok(out_len)
        //     },
        //     Err(e) => Err(format!("Erreur update : {:?}", e))
        // }
    }

    fn finalize(mut self, _out: &mut [u8]) -> Result<(usize, Mgs4CipherKeys), String> {
        todo!("fix me")
        // if self.tag.is_some() {
        //     Err("Deja finalise")?;
        // }
        //
        // match self.encrypter.encrypt_finalize() {
        //     Ok(tag) => {
        //         // Calculer et conserver hachage
        //         let hachage_bytes = self.hacheur.finalize();
        //
        //         // Conserver le compute tag
        //         let tag_b64 = encode(Base::Base64, &tag);
        //
        //         let mut cipher_keys = Mgs3CipherKeys::new(
        //             self.cles_chiffrees.clone(),
        //             self.iv.clone(),
        //             tag_b64,
        //             hachage_bytes,
        //         );
        //         cipher_keys.fingerprint_cert_millegrille = self.fp_cle_millegrille.clone();
        //
        //         Ok((0, cipher_keys))
        //     },
        //     Err(e) => Err(format!("Erreur update : {:?}", e)),
        // }
    }

}

pub struct DecipherMgs4 {
    // decrypter: ChaCha20Poly1305,
    header: [u8; 24],
}

impl DecipherMgs4 {
    pub fn new(decipher_data: &Mgs4CipherData) -> Result<Self, String> {
        todo!("fix me")

        // let cle_dechiffree = match &decipher_data.cle_dechiffree {
        //     Some(c) => c,
        //     None => Err("Cle n'est pas dechiffree")?,
        // };
        //
        // let mut decrypter = ChaCha20Poly1305::new(&cle_dechiffree.0.into());
        // decrypter.set_nonce(decipher_data.iv[..].into());
        //
        // let mut tag = [0u8; 16];
        // tag.copy_from_slice(&decipher_data.tag[0..16]);
        //
        // Ok(DecipherMgs4 { decrypter, tag })
    }
}

impl DecipherMgs<Mgs4CipherData> for DecipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        todo!("fix me")
        // let out_len = if data.is_empty() {
        //     // Input data vide, on assume que le data a dechiffrer
        //     // est deja dans out (dechiffrage "in place")
        //     0
        // } else {
        //     // Copier data vers out, dechiffrage se fait "in place"
        //     out[0..data.len()].copy_from_slice(data);
        //     data.len()
        // };
        //
        // match self.decrypter.decrypt_update(&mut out[0..out_len]) {
        //     Ok(()) => Ok(out_len),
        //     Err(e) => Err(format!("Erreur update : {:?}", e))
        // }
    }

    fn finalize(self, _out: &mut [u8]) -> Result<usize, String> {
        todo!("fix me")
        // match self.decrypter.decrypt_finalize(self.tag[0..16].into()) {
        //     Ok(()) => Ok(0),
        //     Err(e) => Err(format!("Erreur finalize : {:?}", e))
        // }
    }

}

#[derive(Clone, Debug)]
pub struct Mgs4CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    pub header: String,
    pub fingerprint_cert_millegrille: Option<String>,
    pub hachage_bytes: String,
}

impl Mgs4CipherKeys {
    pub fn new(cles_chiffrees: Vec<FingerprintCleChiffree>, header: String, hachage_bytes: String) -> Self {
        Mgs4CipherKeys { cles_chiffrees, header, fingerprint_cert_millegrille: None, hachage_bytes }
    }

    pub fn set_fingerprint_cert_millegrille(&mut self, fingerprint_cert_millegrille: &str) {
        self.fingerprint_cert_millegrille = Some(fingerprint_cert_millegrille.into());
    }

    pub fn get_cipher_data(&self, fingerprint: &str) -> Result<Mgs4CipherData, Box<dyn Error>> {
        let mut cle = self.cles_chiffrees.iter().filter(|c| c.fingerprint == fingerprint);
        match cle.next() {
            Some(c) => {
                Ok(Mgs4CipherData::new(&c.cle_chiffree, &self.header)?)
            },
            None => Err(format!("Cle introuvable : {}", fingerprint))?,
        }
    }

    pub fn get_format(&self) -> String {
        String::from("mgs4")
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

impl MgsCipherKeys for Mgs4CipherKeys {

    fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>,
        user_id: Option<String>
    ) -> CommandeSauvegarderCle {

        let fingerprint_partitions = self.get_fingerprint_partitions();

        todo!("Fix me - signature identite")

        // CommandeSauvegarderCle {
        //     hachage_bytes: self.hachage_bytes.clone(),
        //     domaine: domaine.to_owned(),
        //     identificateurs_document,
        //     user_id: self.user_id.clone(),
        //     signature_identite: self.signature_identite.clone(),
        //     cles: self.cles_to_map(),
        //     iv: Some(self.iv.clone()),
        //     tag: Some(self.tag.clone()),
        //     header: None,
        //     format: FormatChiffrage::mgs4,
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

pub struct Mgs4CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<CleSecrete>,
    header: Vec<u8>,
}

impl Mgs4CipherData {
    pub fn new(cle_chiffree: &str, header: &str) -> Result<Self, Box<dyn Error>> {
        let cle_chiffree_bytes: Vec<u8> = decode(cle_chiffree)?.1;
        let header_bytes: Vec<u8> = decode(header)?.1;

        Ok(Mgs4CipherData {
            cle_chiffree: cle_chiffree_bytes,
            cle_dechiffree: None,
            header: header_bytes,
        })
    }
}

impl MgsCipherData for Mgs4CipherData {

    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>> {
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(self.cle_chiffree.as_slice(), cle_privee)?;
        self.cle_dechiffree = Some(cle_dechiffree);

        Ok(())
    }

}

impl Debug for Mgs4CipherData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs4CipherData header: {:?}", self.header).as_str())
    }
}

#[cfg(test)]
mod test {
    use log::debug;
    use openssl::pkey::{Id, PKey};
    use crate::test_setup::setup;
    use super::*;

    #[test]
    fn test_cipher4_vide() -> Result<(), Box<dyn Error>> {
        setup("test_cipher4_vide");

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
        let cipher = CipherMgs4::new(&fpkeys)?;
        debug!("Nouveau cipher info : Cles chiffrees: {:?}", cipher.cles_chiffrees);
        let (out_len, info_keys) = cipher.finalize(&mut [0u8])?;
        debug!("Output header: keys : {:?}", info_keys);

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage CleMillegrille : {}.", out_len);
                assert_eq!(out_len, 0);
            } else if key.fingerprint.as_str() == "MaitreCles1" {
                // Test dechiffrage avec cle de MaitreDesCles (cle chiffree est 80 bytes : 32 bytes peer public, 32 bytes chiffre, 16 bytes tag)
                debug!("Test dechiffrage avec MaitreCles1");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_maitrecles1)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage MaitreCles1 : {}.", out_len);
                assert_eq!(out_len, 0);
            }
        }

        Ok(())
    }

}