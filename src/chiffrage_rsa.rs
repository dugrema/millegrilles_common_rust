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

pub fn chiffrer_asymetrique(public_key: &PKey<Public>, cle_symmetrique: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    const SIZE_MAX: usize = 4096/8;
    if public_key.size() > SIZE_MAX {
        panic!("Taille de la cle ({}) est trop grande pour le buffer ({})", public_key.size(), SIZE_MAX);
    }

    let mut cle_chiffree = [0u8; SIZE_MAX];

    let mut encrypter = Encrypter::new(public_key)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    encrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    let size = encrypter.encrypt(cle_symmetrique, &mut cle_chiffree)?;

    let mut buffer_ajuste = Vec::new();
    buffer_ajuste.extend_from_slice(&cle_chiffree[..size]);

    Ok(buffer_ajuste)
}

pub fn dechiffrer_asymetrique(private_key: &PKey<Private>, cle_chiffree_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cle_dechiffree = [0u8; 512];  // Cle max 4096 bits (512 bytes)

    let mut decrypter = Decrypter::new(private_key)?;

    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.decrypt(cle_chiffree_bytes, &mut cle_dechiffree)?;

    let cle_dechiffree = &cle_dechiffree[..32];
    Ok(cle_dechiffree.to_vec().to_owned())
}
