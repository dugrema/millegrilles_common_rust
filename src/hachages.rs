use std::convert::TryFrom;
use std::fmt::Error;

use log::{debug, error, info};
use multibase::{Base, decode, encode};
use multicodec::MultiCodec;
use multihash::{Code, Multihash, MultihashDigest};
use openssl::error::ErrorStack;

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

pub fn verifier_multihash(hachage: &str, contenu: &[u8]) -> Result<bool, ErrorStack> {
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
