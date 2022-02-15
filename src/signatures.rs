use std::error::Error;

use log::debug;
use multibase::{Base::Base64, decode, encode};
use multihash::Code;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use crate::hachages::hacher_bytes_vu8;

// pub const SALT_LENGTH: c_int = 64;
// pub const VERSION_1: u8 = 0x1;
pub const VERSION_2: u8 = 0x2;

pub fn signer_message(private_key: &PKey<Private>, message: &[u8]) -> Result<String, ErrorStack> {
    // let key_size = private_key.size();
    let mut to_bytes: [u8; 65] = [0u8; 65];
    to_bytes[0] = VERSION_2;  // Version 2 de la signature MilleGrilles (ed25519)

    let message_hache = hacher_bytes_vu8(message, Some(Code::Blake2b512));

    let mut signer = Signer::new_without_digest(&private_key).unwrap();

    let _resultat = signer.sign_oneshot(&mut to_bytes[1..], &message_hache[..])?;

    let signature_base64 = encode(Base64, to_bytes);
    debug!("Ok, taille signature {}\nSignature : {}\n{:02x?}", to_bytes.len(), signature_base64, to_bytes);
    Ok(signature_base64)
}

pub fn verifier_message(public_key: &PKey<Public>, message: &[u8], signature: &str) -> Result<bool, Box<dyn Error>> {

    let (_, sign_bytes): (_, Vec<u8>) = decode(signature)?;
    let type_sign = &sign_bytes[0];
    let signature_bytes = &sign_bytes[1..];

    debug!("Verifier signature type {:?} / {:?} avec public key {:?}", type_sign, signature_bytes, public_key);

    if *type_sign != VERSION_2 {
        debug!("Version signature est {:?}, devrait etre 2", type_sign);
        Err(format!("La version de la signature n'est pas 2"))?;
    }

    let message_hache = hacher_bytes_vu8(message, Some(Code::Blake2b512));

    let mut verifier = Verifier::new_without_digest(&public_key)?;
    // let resultat = verifier.verify_oneshot(signature_bytes, &message[0..10])?;
    let resultat = verifier.verify_oneshot(signature_bytes, &message_hache[..])?;

    Ok(resultat)
}

// pub fn signer_message(private_key: &PKey<Private>, message: &[u8]) -> Result<String, ErrorStack> {
//     let key_size = private_key.size();
//     let mut to_bytes: [u8; 257] = [0u8; 257];
//     to_bytes[0] = 0x1;  // Version 1 de la signature MilleGrilles
//
//     let mut signer = Signer::new(MessageDigest::sha512(), &private_key).unwrap();
//     signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
//     signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(SALT_LENGTH)).unwrap();
//     signer.set_rsa_mgf1_md(MessageDigest::sha512()).unwrap();
//
//     signer.update(message).unwrap();
//     let resultat = signer.sign(&mut to_bytes[1..]);
//
//     match resultat {
//         Ok(len) => {
//             let signature_base64 = encode(Base64, to_bytes);
//             debug!("Ok, taille signature {}\nSignature : {}\n{:02x?}", len, signature_base64, to_bytes);
//             Ok(signature_base64)
//         },
//         Err(e) => {
//             debug!("Erreur, stack {}", e);
//             Err(e)
//         },
//     }
// }
