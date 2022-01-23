use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};

use aead::{NewAead, AeadMut, Payload};
use async_trait::async_trait;
use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::derive::Deriver;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use dryoc::classic::{crypto_sign_ed25519, crypto_sign_ed25519::{PublicKey, SecretKey}};
use x509_parser::nom::Parser;

use crate::bson::Document;
use crate::certificats::{EnveloppeCertificat, FingerprintCertPublicKey, ordered_map};
use crate::chacha20poly1305_incremental::ChaCha20Poly1305;
use crate::formatteur_messages::MessageSerialise;
use crate::hachages::{Hacheur, hacher_bytes_vu8};
use crate::middleware::IsConfigurationPki;

/**
Derive une cle secrete a partir d'une cle publique. Utiliser avec cle publique du cert CA.
*/
pub fn deriver_asymetrique_ed25519(public_key: &PKey<Public>) -> Result<([u8; 32], String), Box<dyn Error>> {

    if public_key.id() != Id::ED25519 {
        Err(String::from("deriver_asymetrique_ed25519 Mauvais type de cle publique, doit etre ED25519"))?
    }

    let cle_peer = PKey::generate_x25519()?;
    let public_peer = String::from_utf8(cle_peer.public_key_to_pem()?)?;

    // Convertir cle CA publique Ed25519 en X25519
    let cle_public_x25519 = convertir_public_ed25519_to_x25519(public_key)?;

    let mut deriver = Deriver::new(&cle_peer)?;
    deriver.set_peer(cle_public_x25519.as_ref())?;
    let mut cle_secrete = [0u8; 32];
    deriver.derive(&mut cle_secrete)?;

    // Hacher la cle avec blake2s-256
    let cle_hachee = hacher_bytes_vu8(&cle_secrete, Some(Code::Blake2s256));
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok((cle_secrete, public_peer))
}

/**
Rederive une cle secrete a partir d'une cle publique et cle privee.
*/
pub fn deriver_asymetrique_ed25519_peer(peer_x25519: &PKey<Public>, private_key_in: &PKey<Private>) -> Result<[u8; 32], Box<dyn Error>> {

    if peer_x25519.id() != Id::X25519 {
        Err(String::from("deriver_asymetrique_ed25519_peer Mauvais type de cle publique, doit etre X25519"))?
    }

    // Convertir cle privee en format X25519
    let cle_privee_pkey = match private_key_in.id() {
        Id::X25519 => private_key_in.to_owned(),
        Id::ED25519 => convertir_private_ed25519_to_x25519(private_key_in)?,
        _ => Err(String::from("deriver_asymetrique_ed25519_peer Mauvais type de cle private, doit etre ED25519 ou X25519"))?
    };

    let mut deriver = Deriver::new(&cle_privee_pkey)?;
    deriver.set_peer(peer_x25519)?;
    let mut cle_secrete = [0u8; 32];
    deriver.derive(&mut cle_secrete)?;

    // Hacher la cle avec blake2s-256
    let cle_hachee = hacher_bytes_vu8(&cle_secrete, Some(Code::Blake2s256));
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok(cle_secrete)
}

pub fn chiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_publique: &PKey<Public>) -> Result<[u8; 80], Box<dyn Error>> {

    let cle_publique_x25519 = convertir_public_ed25519_to_x25519(cle_publique)?;
    let cle_peer = PKey::generate_x25519()?;
    let cle_peer_public_raw = cle_peer.raw_public_key()?;

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_publique_x25519, &cle_peer)?;

    debug!("Cle secrete intermediaire : {:?} \nCle peer public : {:?}", cle_secrete_intermediaire, cle_peer_public_raw);

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire[..].into());

    // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage
    let cle_secrete_chiffree_tag = match aead.encrypt(cle_peer_public_raw[0..12].into(), cle_secrete.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("millegrilles_common chiffrer_asymmetrique_ed25519 encrypt error {:?}", e))?
    };

    let mut vec_resultat = Vec::new();
    vec_resultat.extend_from_slice(&cle_peer_public_raw[..]);  // 32 bytes cle publique peer
    vec_resultat.extend_from_slice(&cle_secrete_chiffree_tag[..]);  // 32 cle secrete chiffree + 16 bytes auth tag

    let mut resultat = [0u8; 80];
    resultat.copy_from_slice(&vec_resultat[..]);

    Ok(resultat)
}

pub fn dechiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_privee: &PKey<Private>) -> Result<[u8; 32], Box<dyn Error>> {

    if cle_secrete.len() != 80 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvaise taille de cle secrete, doit etre 80 bytes"))?
    }
    if cle_privee.id() != Id::ED25519 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvais type de cle privee, doit etre ED25519"))?
    }

    // let cle_privee_x25519 = convertir_private_ed25519_to_x25519(cle_privee)?;
    let cle_peer_public_raw = &cle_secrete[0..32];
    let cle_peer_intermediaire = PKey::public_key_from_raw_bytes(cle_peer_public_raw, Id::X25519)?;
    let cle_secrete_chiffree_tag = &cle_secrete[32..80];

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, &cle_privee)?;

    debug!("Cle secrete intermediaire : {:?} \nCle peer public : {:?}", cle_secrete_intermediaire, cle_peer_public_raw);

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire[..].into());

    // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage
    let cle_secrete_dechiffree = match aead.decrypt(cle_peer_public_raw[0..12].into(), cle_secrete_chiffree_tag.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(format!("millegrilles_common chiffrer_asymmetrique_ed25519 encrypt error {:?}", e))?
    };

    let mut resultat = [0u8; 32];
    resultat.copy_from_slice(&cle_secrete_dechiffree[..]);

    Ok(resultat)
}

fn convertir_public_ed25519_to_x25519(public_key: &PKey<Public>) -> Result<PKey<Public>, Box<dyn Error>> {
    let cle_publique_bytes = public_key.raw_public_key()?;
    let mut cle_public_ref: PublicKey = [0u8; 32];
    cle_public_ref.clone_from_slice(&cle_publique_bytes[0..32]);
    let mut cle_publique_x25519: PublicKey = [0u8; 32];
    crypto_sign_ed25519::crypto_sign_ed25519_pk_to_curve25519(
        &mut cle_publique_x25519,
        &cle_public_ref
    )?;

    Ok(PKey::public_key_from_raw_bytes(&cle_publique_x25519, Id::X25519)?)
}

fn convertir_private_ed25519_to_x25519(ca_key: &PKey<Private>) -> Result<PKey<Private>, Box<dyn Error>> {
    let cle_privee_ca = ca_key.raw_private_key()?;
    debug!("Cle privee CA: {:?}", cle_privee_ca);
    // let cle_publique_ca = ca_key.raw_public_key()?;
    let mut cle_privee_ca_sk: SecretKey = [0u8; 64];
    cle_privee_ca_sk[0..32].copy_from_slice(&cle_privee_ca[..]);
    // cle_privee_ca_sk[32..64].copy_from_slice(&cle_publique_ca[..]);
    let mut cle_privee_ca_x25519 = [0u8; 32];
    crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519(
        &mut cle_privee_ca_x25519,
        &cle_privee_ca_sk
    );

    Ok(PKey::private_key_from_raw_bytes(&cle_privee_ca_x25519, Id::X25519)?)
}
