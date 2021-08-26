use std::convert::TryFrom;
use std::error::Error;
use std::io::ErrorKind;

use log::{debug, error, info};
use multibase::{Base, decode, encode};
use multicodec::MultiCodec;
use multihash::{Code, Multihash, MultihashDigest, Sha2_256, Sha2_512, Sha2Digest, Sha3_256, Size, StatefulHasher};

pub fn hacher_message(contenu: &str) -> String {
    hacher_bytes(contenu.as_bytes(), Some(Code::Sha2_256), Some(Base::Base64))
}

pub fn hacher_bytes(contenu: &[u8], code: Option<Code>, base: Option<Base>) -> String {
    let mut digester: Code;
    match code {
        Some(inner) => digester = inner,
        None => digester = Code::Sha2_512,
    }

    // Digest direct (une passe)
    let mh_digest = digester.digest(contenu);
    let mh_bytes = mh_digest.to_bytes();

    let mut base_mb: Base;
    match base {
        Some(inner) => base_mb = inner,
        None => base_mb = Base::Base64,
    }
    let valeur_hachee = encode(base_mb, mh_bytes);

    valeur_hachee
}

pub fn verifier_multihash(hachage: &str, contenu: &[u8]) -> Result<bool, Box<dyn Error>> {
    // let mb = "mEiDhIyaO8TdBnmXKWeih9o+ASND5t8VgZfqDjLan8lT7xg";
    debug!("Verifier multihash {}", hachage);

    // Extraire multihash bytes de l'input string en multibase
    let mb_bytes = decode(hachage).unwrap();

    // Extraire le code et digest du multihash
    let mh = Multihash::from_bytes(&mb_bytes.1).unwrap();
    let digest = mh.digest();
    let code = mh.code();
    debug!("Chargement multihash, code {:x}, \ndigest: {:02x?}", code, digest);

    // Recalculer le digest avec le contenu
    let digester = Code::try_from(code).unwrap();

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
}

impl Hacheur {
    pub fn builder() -> HacheurBuilder {
        HacheurBuilder::new()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hacheur_interne.update(data)
    }

    pub fn finalize(&mut self) -> String {
        let mh_bytes = self.hacheur_interne.finalize();
        encode(self.base, mh_bytes)
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
            _ => panic!("Type hacheur inconnu")
        };

        Hacheur{
            hacheur_interne,
            digester: self.digester,
            base: self.base,
        }
    }
}

trait HacheurInterne {
    fn new() -> Self where Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> Vec<u8>;
}

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

#[cfg(test)]
mod backup_tests {
    use super::*;

    #[test]
    fn hacheur_update() {
        let hacheur_interne = Box::new(HacheurSha2_256::new());

        let mut hacheur = Hacheur {
            hacheur_interne,
            digester: Code::Sha2_512,
            base: Base::Base64,
        };

        hacheur.update("Allo le test".as_bytes());
        let resultat = hacheur.finalize();
        assert_eq!(resultat.as_str(), "mEiB2fjCnlWgbSIH3MOHXtLAENCoUAzQFgb3O92tPbbrIVA")
    }

    #[test]
    fn hacheur_build_default() {
        let mut hacheur = Hacheur::builder().build();
        hacheur.update("Allo tout le monde".as_bytes());
        let mh = hacheur.finalize();
        assert_eq!(mh, "mE0A4KylJttHdgCNk1BJfIzkfy50q9F3jbZTOVcOfvXZ3hk3AsI0ZZx1z+hViSAlZtX929MfrXYVdNiuRsRb5+pp3");
    }

    #[test]
    fn hacheur_build_params() {
        let mut hacheur = Hacheur::builder()
            .digester(Code::Sha2_256)
            .base(Base::Base58Btc)
            .build();
        hacheur.update("Allo encore".as_bytes());
        hacheur.update(" une fois".as_bytes());
        let mh = hacheur.finalize();
        assert_eq!(mh, "zQmcT37HrJ3zm5qMVDcMaZLamdGUZFUkbCV5c9VoUGDpEFF");
    }
}