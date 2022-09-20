use std::error::Error;
use std::fmt::{Debug, Formatter};

use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng}, ChaCha20Poly1305, Nonce};
use dryoc::classic::{crypto_sign_ed25519, crypto_sign_ed25519::{PublicKey, SecretKey}};
use log::debug;
use multihash::Code;
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};

// use crate::chacha20poly1305_incremental::ChaCha20Poly1305;
use crate::chiffrage::CleSecrete;
use crate::hachages::hacher_bytes_vu8;

pub struct CleDerivee {
    pub secret: CleSecrete,
    pub public_peer: [u8; 32],
}

impl Debug for CleDerivee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Secret : [hidden], Public peer : {:?}", self.public_peer).as_str())
    }
}

/**
Derive une cle secrete a partir d'une cle publique. Utiliser avec cle publique du cert CA.
Retourne : (secret key, public peer)
*/
pub fn deriver_asymetrique_ed25519(public_key: &PKey<Public>) -> Result<CleDerivee, Box<dyn Error>> {

    if public_key.id() != Id::ED25519 {
        Err(String::from("deriver_asymetrique_ed25519 Mauvais type de cle publique, doit etre ED25519"))?
    }

    let cle_peer = PKey::generate_x25519()?;
    let public_peer = {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&cle_peer.raw_public_key()?[..]);
        pk
    };

    // Convertir cle CA publique Ed25519 en X25519
    let cle_public_x25519 = convertir_public_ed25519_to_x25519(public_key)?;

    let mut deriver = Deriver::new(&cle_peer)?;
    deriver.set_peer(cle_public_x25519.as_ref())?;
    let mut cle_secrete = [0u8; 32];
    deriver.derive(&mut cle_secrete)?;

    // Hacher la cle avec blake2s-256
    let cle_hachee = hacher_bytes_vu8(&cle_secrete, Some(Code::Blake2s256));
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok(CleDerivee {secret: CleSecrete(cle_secrete), public_peer})
}

/**
Rederive une cle secrete a partir d'une cle publique et cle privee.
*/
pub fn deriver_asymetrique_ed25519_peer(peer_x25519: &PKey<Public>, private_key_in: &PKey<Private>) -> Result<CleSecrete, Box<dyn Error>> {

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

    Ok(CleSecrete(cle_secrete))
}

pub fn chiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_publique: &PKey<Public>) -> Result<[u8; 80], Box<dyn Error>> {

    let cle_publique_x25519 = convertir_public_ed25519_to_x25519(cle_publique)?;
    let cle_peer = PKey::generate_x25519()?;
    let cle_peer_public_raw = cle_peer.raw_public_key()?;

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_publique_x25519, &cle_peer)?;

    debug!("Cle peer public : {:?}", cle_peer_public_raw);

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire.0[..].into());

    // Note : on utilise la cle publique du peer (valeur random) hachee en blake2s comme nonce (12 bytes) pour le chiffrage
    let nonce = hacher_bytes_vu8(&cle_peer_public_raw[..], Some(Code::Blake2s256));
    let cle_secrete_chiffree_tag = match aead.encrypt(nonce[0..12].into(), cle_secrete.as_ref()) {
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

pub fn dechiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_privee: &PKey<Private>) -> Result<CleSecrete, Box<dyn Error>> {

    // Verifier si la cle est 32 bytes (dechiffrage avec cle de millegrille) ou 80 bytes (standard)
    if cle_secrete.len() != 32 && cle_secrete.len() != 80 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvaise taille de cle secrete, doit etre 80 bytes"))?
    }
    if cle_privee.id() != Id::ED25519 {
        Err(String::from("dechiffrer_asymmetrique_ed25519 Mauvais type de cle privee, doit etre ED25519"))?
    }

    // let cle_privee_x25519 = convertir_private_ed25519_to_x25519(cle_privee)?;
    let cle_peer_public_raw = &cle_secrete[0..32];
    let cle_peer_intermediaire = PKey::public_key_from_raw_bytes(cle_peer_public_raw, Id::X25519)?;
    debug!("Cle peer public : {:?}", cle_peer_public_raw);


    let cle_secrete_dechiffree = if cle_secrete.len() == 32 {
        deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, cle_privee)?
    } else {
        // Dechiffage de la cle secrete avec ChaCha20Poly1305
        let cle_secrete_chiffree_tag = &cle_secrete[32..80];
        // Trouver cle secrete de dechiffrage de la cle privee
        let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, &cle_privee)?;
        // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
        let mut aead = ChaCha20Poly1305::new(cle_secrete_intermediaire.0[..].into());
        // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage

        let nonce = hacher_bytes_vu8(&cle_peer_public_raw[..], Some(Code::Blake2s256));
        match aead.decrypt(nonce[0..12].into(), cle_secrete_chiffree_tag.as_ref()) {
            Ok(m) => {
                let mut cle_secrete_dechiffree = CleSecrete([0u8; 32]);
                cle_secrete_dechiffree.0.copy_from_slice(&m[..]);

                cle_secrete_dechiffree
            },
            Err(e) => Err(format!("millegrilles_common chiffrer_asymmetrique_ed25519 encrypt error {:?}", e))?
        }
    };

    Ok(cle_secrete_dechiffree)
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

#[cfg(test)]
mod test {
    use crate::test_setup::setup;

    use super::*;

    #[test]
    fn test_chiffrage_asymmetrique() -> Result<(), Box<dyn Error>> {
        setup("test_chiffrage_asymmetrique");
        debug!("Chiffrer cle secrete");

        // Creer ensemble de cles
        let cle_ca = PKey::generate_ed25519()?;
        let cle_ca_public = PKey::public_key_from_raw_bytes(&cle_ca.raw_public_key()?[..], Id::ED25519)?;

        // Chiffrer cle secrete
        let derived_key = deriver_asymetrique_ed25519(&cle_ca_public)?;
        debug!("Peer:\n{:?}", derived_key);

        // Recalculer avec cle publique peer et cle privee ca
        let peer_x25519 = PKey::public_key_from_raw_bytes(&derived_key.public_peer, Id::X25519)?;
        debug!("Peer x25519 lu : {:?}", peer_x25519);
        let cle_secrete_rederivee = deriver_asymetrique_ed25519_peer(&peer_x25519, &cle_ca)?;

        assert_eq!(derived_key.secret.0, cle_secrete_rederivee.0);
        debug!{"Cle secretes match OK!"};

        Ok(())
    }

    #[test]
    fn chiffrer_cle_secrete() -> Result<(), Box<dyn Error>> {

        // Generer une cle publique pour chiffrer
        let cle_ed25519 = PKey::generate_ed25519()?;
        let cle_ed25519_publique = PKey::public_key_from_raw_bytes(
            &cle_ed25519.raw_public_key()?, Id::ED25519)?;

        // Generer une cle secrete de 32 bytes
        let cle_secrete = [4u8; 32];  // Cle secrete, val 0x04 sur 32 bytes

        let cle_chiffree = chiffrer_asymmetrique_ed25519(&cle_secrete, &cle_ed25519_publique)?;
        debug!("Cle chiffree: {:?}", cle_chiffree);

        // Tenter de dechiffrer la cle secrete avec la cle privee
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(&cle_chiffree[..], &cle_ed25519)?;
        debug!("Cle dechiffree: {:?}", cle_dechiffree.0);

        assert_eq!(cle_secrete, cle_dechiffree.0);
        debug!("Cle secrete dechiffree OK");

        Ok(())
    }
}
