use crate::chiffrage::{CleSecrete, FingerprintCleChiffree};
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

pub struct DecipherMgs4 {
    // decrypter: ChaCha20Poly1305,
    header: [u8; 24],
}

#[derive(Clone, Debug)]
pub struct Mgs4CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    pub header: String,
    pub fingerprint_cert_millegrille: Option<String>,
    pub hachage_bytes: String,
}

pub struct Mgs4CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<CleSecrete>,
    header: Vec<u8>,
}
