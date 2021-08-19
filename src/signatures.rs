use std::os::raw::c_int;

use log::{debug, error, info};
use multibase::{Base, Base::Base64, decode, encode};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};

pub const SALT_LENGTH: c_int = 64;
pub const VERSION_1: u8 = 0x1;

pub fn signer_message(private_key: &PKey<Private>, message: &[u8]) -> Result<String, ErrorStack> {
    let key_size = private_key.size();
    let mut to_bytes: [u8; 257] = [0u8; 257];
    to_bytes[0] = 0x1;  // Version 1 de la signature MilleGrilles

    let mut signer = Signer::new(MessageDigest::sha512(), &private_key).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH)).unwrap();
    signer.set_rsa_mgf1_md(MessageDigest::sha512()).unwrap();

    signer.update(message).unwrap();
    let resultat = signer.sign(&mut to_bytes[1..]);

    match resultat {
        Ok(len) => {
            let signature_base64 = encode(Base64, to_bytes);
            debug!("Ok, taille signature {}\nSignature : {}\n{:02x?}", len, signature_base64, to_bytes);
            Ok(signature_base64)
        },
        Err(e) => {
            debug!("Erreur, stack {}", e);
            Err(e)
        },
    }
}
