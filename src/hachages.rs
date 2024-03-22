use std::convert::TryFrom;
use std::error::Error;

use log::debug;
use multibase::{Base, decode, encode};
use multihash::{Code, Multihash, MultihashDigest, Sha2_256, Sha2_512, Blake2b512, Blake2s256, StatefulHasher};
use serde::Serialize;
use uuid::Uuid;
use substring::Substring;

pub fn hacher_message(contenu: &str) -> String {
    hacher_bytes(contenu.as_bytes(), Some(Code::Sha2_256), Some(Base::Base64))
}

pub fn hacher_serializable<S>(s: &S) -> Result<String, Box<dyn Error>>
where S: Serialize
{
    let value = serde_json::to_value(s)?;
    let ser_bytes = serde_json::to_vec(&value)?;
    Ok(hacher_bytes(ser_bytes.as_slice(), Some(Code::Blake2b512), Some(Base::Base64)))
}

pub fn hacher_bytes(contenu: &[u8], code: Option<Code>, base: Option<Base>) -> String {
    let digester: Code;
    match code {
        Some(inner) => digester = inner,
        None => digester = Code::Blake2b512,
    }

    // Digest direct (une passe)
    let mh_digest = digester.digest(contenu);
    let mh_bytes = mh_digest.to_bytes();

    let base_mb: Base;
    match base {
        Some(inner) => base_mb = inner,
        None => base_mb = Base::Base64,
    }
    let valeur_hachee = encode(base_mb, mh_bytes);

    valeur_hachee
}

pub fn hacher_bytes_vu8(contenu: &[u8], code: Option<Code>) -> Vec<u8> {
    let digester: Code;
    match code {
        Some(inner) => digester = inner,
        None => digester = Code::Blake2b512,
    }

    // Digest direct (une passe)
    let mh_digest = digester.digest(contenu);

    let digest_vec: Vec<u8> = mh_digest.digest().into();

    debug!("hachage_bytes_vu8 Digest : {:?}", digest_vec);

    digest_vec
}

pub fn verifier_hachage_serializable<S>(hachage: &[u8], code: Code, s: &S) -> Result<bool, crate::error::Error>
    where S: Serialize
{
    let value = serde_json::to_value(s)?;

    let ser_bytes = serde_json::to_vec(&value)?;
    debug!("Verification hachage message {}", String::from_utf8(ser_bytes.clone()).expect("string"));

    let mh_digest = code.digest(ser_bytes.as_slice());
    let hachage_calcule: &[u8] = mh_digest.digest(); // to_bytes();

    // Enlever 2 premiers bytes (multibase et multihash)
    // let hachage_calcule = mh_bytes.as_slice();  //[2..];

    debug!("Hachage comparaison recu/calcule\n{:?}\n{:?}", hachage, hachage_calcule);

    Ok(hachage_calcule == hachage)
}

pub fn verifier_multihash(hachage: &str, contenu: &[u8]) -> Result<bool, Box<dyn Error>> {
    // let mb = "mEiDhIyaO8TdBnmXKWeih9o+ASND5t8VgZfqDjLan8lT7xg";
    debug!("Verifier multihash {}", hachage);

    // Extraire multihash bytes de l'input string en multibase
    let mb_bytes = decode(hachage)?;

    // Extraire le code et digest du multihash
    let mh = Multihash::from_bytes(&mb_bytes.1)?;
    let digest = mh.digest();
    let code = mh.code();
    debug!("Chargement multihash, code {:x}, \ndigest: {:02x?}", code, digest);

    // Recalculer le digest avec le contenu
    let digester = Code::try_from(code)?;

    debug!("Type de digest {:?}", digester);

    let digest_calcule = digester.digest(contenu);
    let digest_bytes = digest_calcule.digest();

    debug!("Resultat digest recalcule : \ndigest: {:02x?}", digest_bytes);

    let correspond = digest == digest_bytes;

    Ok(correspond)
}

pub struct Hacheur {
    hacheur_interne: Box<dyn HacheurInterne>,
    digester: Code,
    base: Base,
    pub hachage_bytes: Option<String>,
}

impl Hacheur {
    pub fn builder() -> HacheurBuilder {
        HacheurBuilder::new()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hacheur_interne.update(data)
    }

    pub fn finalize(&mut self) -> String {
        match &self.hachage_bytes {
            Some(h) => h.clone(),
            None => {
                let mh_bytes = self.hacheur_interne.finalize();
                let hachage_bytes = encode(self.base, mh_bytes);
                self.hachage_bytes = Some(hachage_bytes.clone());

                hachage_bytes
            }
        }
    }
}

pub struct HacheurBuilder {
    digester: Code,
    base: Base,
}

impl HacheurBuilder {
    pub fn new() -> Self {
        HacheurBuilder {
            digester: Code::Sha2_512,
            base: Base::Base64,
        }
    }

    pub fn digester(mut self, digester: Code) -> Self {
        self.digester = digester;
        self
    }

    pub fn base(mut self, base: Base) -> Self {
        self.base = base;
        self
    }

    pub fn build(self) -> Hacheur {

        let hacheur_interne: Box<dyn HacheurInterne> = match u64::from(self.digester) {
            0x12 => Box::new(HacheurSha2_256{hacheur: Sha2_256::default()}),
            0x13 => Box::new(HacheurSha2_512{hacheur: Sha2_512::default()}),
            0xb240 => Box::new(HacheurBlake2b_512{hacheur: Blake2b512::default()}),
            0xb260 => Box::new(HacheurBlake2s_256{hacheur: Blake2s256::default()}),
            _ => panic!("Type hacheur inconnu")
        };

        Hacheur{
            hacheur_interne,
            digester: self.digester,
            base: self.base,
            hachage_bytes: None,
        }
    }
}

trait HacheurInterne: Send {
    fn new() -> Self where Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

#[derive(Debug)]
struct HacheurSha2_256 { hacheur: Sha2_256 }
impl HacheurInterne for HacheurSha2_256 {
    fn new() -> Self { HacheurSha2_256{hacheur: Sha2_256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize(&mut self) -> Vec<u8> {
        let digest = self.hacheur.finalize();
        let mh = Code::multihash_from_digest(&digest);
        mh.to_bytes().to_owned()
    }
}

#[derive(Debug)]
struct HacheurSha2_512 { hacheur: Sha2_512 }
impl HacheurInterne for HacheurSha2_512 {
    fn new() -> Self { HacheurSha2_512{hacheur: Sha2_512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize(&mut self) -> Vec<u8> {
        let digest = self.hacheur.finalize();
        let mh = Code::multihash_from_digest(&digest);
        mh.to_bytes().to_owned()
    }
}

#[derive(Debug)]
struct HacheurBlake2b_512 { hacheur: Blake2b512 }
impl HacheurInterne for HacheurBlake2b_512 {
    fn new() -> Self { HacheurBlake2b_512{hacheur: Blake2b512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize(&mut self) -> Vec<u8> {
        let digest = self.hacheur.finalize();
        let mh = Code::multihash_from_digest(&digest);
        mh.to_bytes().to_owned()
    }
}

#[derive(Debug)]
struct HacheurBlake2s_256 { hacheur: Blake2s256 }
impl HacheurInterne for HacheurBlake2s_256 {
    fn new() -> Self { HacheurBlake2s_256{hacheur: Blake2s256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize(&mut self) -> Vec<u8> {
        let digest = self.hacheur.finalize();
        let mh = Code::multihash_from_digest(&digest);
        mh.to_bytes().to_owned()
    }
}

/// Hachage d'un UUID format string - extrait UUID en bytes pour hacher
pub fn hacher_uuid<S>(uuid_in: S, len_bytes: Option<u8>) -> Result<String, uuid::Error>
    where S: AsRef<str>
{
    let uuid_str = uuid_in.as_ref();
    let uuid_val = Uuid::parse_str(uuid_str)?;
    let uuid_bytes = uuid_val.as_bytes();

    let len_hachage = match len_bytes {
        Some(l) => l,
        None => 12
    };

    // let hachage_str = hacher_bytes(
    //     uuid_bytes, Some(Code::Sha2_256), Some(Base::Base64));

    let mut hacheur = Sha2_256::default();
    hacheur.update(uuid_bytes);
    let hachage = hacheur.finalize();
    let hachage_str: String = multibase::encode(Base::Base58Btc, hachage.as_ref());
    debug!("hacher_uuid str : {}", hachage_str);

    Ok(String::from(hachage_str.substring(1, (len_hachage+1) as usize)))
}

#[cfg(test)]
mod backup_tests {
    use super::*;
    use crate::test_setup::setup;

    #[test]
    fn hacheur_update() {
        setup("hacheur_update");
        let hacheur_interne = Box::new(HacheurSha2_256::new());

        let mut hacheur = Hacheur {
            hacheur_interne,
            digester: Code::Sha2_512,
            base: Base::Base64,
            hachage_bytes: None,
        };

        hacheur.update("Allo le test".as_bytes());
        let resultat = hacheur.finalize();
        assert_eq!(resultat.as_str(), "mEiB2fjCnlWgbSIH3MOHXtLAENCoUAzQFgb3O92tPbbrIVA")
    }

    #[test]
    fn hacheur_build_default() {
        setup("hacheur_build_default");
        let mut hacheur = Hacheur::builder().build();
        hacheur.update("Allo tout le monde".as_bytes());
        let mh = hacheur.finalize();
        assert_eq!(mh, "mE0A4KylJttHdgCNk1BJfIzkfy50q9F3jbZTOVcOfvXZ3hk3AsI0ZZx1z+hViSAlZtX929MfrXYVdNiuRsRb5+pp3");
    }

    #[test]
    fn hacheur_build_params() {
        setup("hacheur_build_params");
        let mut hacheur = Hacheur::builder()
            .digester(Code::Sha2_256)
            .base(Base::Base58Btc)
            .build();
        hacheur.update("Allo encore".as_bytes());
        hacheur.update(" une fois".as_bytes());
        let mh = hacheur.finalize();
        assert_eq!(mh, "zQmcT37HrJ3zm5qMVDcMaZLamdGUZFUkbCV5c9VoUGDpEFF");
    }

    #[test]
    fn hacher_uuid_test() {
        setup("hacher_uuid_test");
        const UUID_STR: &str = "7a2764fa-c457-4f25-af0d-0fc915439b21";
        let valeur_hachee = hacher_uuid(UUID_STR, None).expect("uuid");
        debug!("hachage_uuid_test : {}", valeur_hachee);

    }
}