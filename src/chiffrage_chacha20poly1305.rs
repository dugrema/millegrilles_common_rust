use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};

use aead::{NewAead, AeadMut, Payload};
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::pkey::{PKey, Private};

use crate::certificats::FingerprintCertPublicKey;
use crate::chacha20poly1305_incremental::{ChaCha20Poly1305, Key, Nonce, AeadUpdate, Tag};
use crate::chiffrage::{CipherMgs, CommandeSauvegarderCle, FingerprintCleChiffree, FormatChiffrage, MgsCipherData, MgsCipherKeys};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519};
use crate::chiffrage_rsa::dechiffrer_asymetrique;
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
        out.copy_from_slice(data);

        match self.encrypter.encrypt_update(out) {
            Ok(()) => {
                self.hacheur.update(&out[..]);  // Calculer hachage output

                // Stream encryption, le nombre de bytes chiffres est le meme que bytes en entree
                Ok(data.len())
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

#[derive(Clone)]
pub struct Mgs3CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<Vec<u8>>,
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
        let mut cle_vec = Vec::new();
        cle_vec.extend_from_slice(&cle_dechiffree);
        self.cle_dechiffree = Some(cle_vec);

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
    fn test_cipher3_new() -> Result<(), Box<dyn Error>> {
        setup("test_cipher3_new");

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

        let cipher = CipherMgs3::new(&fpkeys)?;


        Ok(())
    }
}
