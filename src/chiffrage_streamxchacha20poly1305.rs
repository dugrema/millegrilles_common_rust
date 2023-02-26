use core::fmt::Formatter;
use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Write};

use dryoc::classic::crypto_secretstream_xchacha20poly1305::*;
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE
};
use log::debug;
use multibase::{Base, decode, encode};
use multihash::Code;
use openssl::pkey::{PKey, Private};

use crate::certificats::FingerprintCertPublicKey;
use crate::chiffrage::{CipherMgs, CleSecrete, DecipherMgs, FormatChiffrage, MgsCipherData, MgsCipherKeys};
use crate::chiffrage_cle::{CleDechiffree, CommandeSauvegarderCle, FingerprintCleChiffree, IdentiteCle};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519, deriver_asymetrique_ed25519};
use crate::hachages::Hacheur;

const CONST_TAILLE_BLOCK_MGS4: usize = 64 * 1024;

/// Implementation mgs4
pub struct CipherMgs4 {
    state: State,
    header: String,
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    fp_cle_millegrille: Option<String>,
    hacheur: Hacheur,
    hachage_bytes: Option<String>,
    buffer: [u8; CONST_TAILLE_BLOCK_MGS4-CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],  // Buffer de chiffrage
    position_buffer: usize,
    cle_secrete: CleSecrete,
}

impl CipherMgs4 {

    pub fn new(public_keys: &Vec<FingerprintCertPublicKey>) -> Result<Self, Box<dyn Error>> {

        // Deriver une cle secrete avec la cle publique de millegrille
        let mut fp_cles = Vec::new();
        let cle_millegrille = {
            let mut cle_millegrille_v: Vec<&FingerprintCertPublicKey> = public_keys.iter()
                .filter(|k| k.est_cle_millegrille).collect();
            match cle_millegrille_v.pop() {
                Some(c) => c,
                None => {
                    debug!("CipherMgs3::new Cle de millegrille manquante, cles presentes : {:?}", public_keys);
                    Err(format!("CipherMgs3::new Cle de millegrille manquante"))?
                }
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

        let mut state = State::new();
        let mut header = Header::default();
        let key = Key::from(cle_derivee.secret.0);
        crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);
        let cle_secrete = CleSecrete(key);

        let hacheur = Hacheur::builder()
            .digester(Code::Blake2b512)
            .base(Base::Base58Btc)
            .build();

        Ok(Self {
            state,
            header: encode(Base::Base64, header),
            cles_chiffrees: fp_cles,
            fp_cle_millegrille: Some(cle_millegrille.fingerprint.clone()),
            hacheur,
            hachage_bytes: None,
            buffer: [0u8; CONST_TAILLE_BLOCK_MGS4-CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
            position_buffer: 0,
            cle_secrete
        })
    }
}

impl CipherMgs<Mgs4CipherKeys> for CipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {
        let mut position_data: usize = 0;
        let mut position_output: usize = 0;

        // Taille du block de lecture de data (enlever 17 bytes overhead au block cipher)
        const TAILLE_BLOCK_DATA: usize = CONST_TAILLE_BLOCK_MGS4 - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        while position_data < data.len() {
            // Dechiffrer un block de donnees
            let taille_data_restante = data.len() - position_data;
            debug!("CipherMgs<Mgs4CipherKeys>.update position_data {}, data.len {}, taille_data_restante {}", position_data, data.len(), taille_data_restante);

            // Copier chunk dans le buffer
            let taille_max = TAILLE_BLOCK_DATA - self.position_buffer;  // Max espace restant dans buffer
            let taille_chunk = min(taille_data_restante, taille_max);
            self.buffer[self.position_buffer..self.position_buffer+taille_chunk].copy_from_slice(&data[position_data..position_data+taille_chunk]);
            self.position_buffer += taille_chunk;
            position_data += taille_chunk;

            // Verifier si on fait un output
            if self.position_buffer == TAILLE_BLOCK_DATA {
                let slice_output = &mut out[position_output..position_output+CONST_TAILLE_BLOCK_MGS4];

                let result = crypto_secretstream_xchacha20poly1305_push(
                    &mut self.state, slice_output, &self.buffer, None, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);

                // Error handling
                if let Err(e) = result {
                    return Err(format!("CipherMgs4.finalize Erreur chiffrage : {:?}", e))
                }

                self.position_buffer = 0;  // Reset position buffer
                position_output += CONST_TAILLE_BLOCK_MGS4;
            }

        }

        if position_output > 0 {
            self.hacheur.update(&out[..position_output]);
        }

        Ok(position_output)
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<(usize, Mgs4CipherKeys), String> {

        let taille_output = self.position_buffer + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        debug!("CipherMgs4.finalize Output buffer len {}", out.len());

        {
            let slice_output = &mut out[..taille_output];

            let resultat = crypto_secretstream_xchacha20poly1305_push(
                &mut self.state,
                slice_output,
                &self.buffer[..self.position_buffer],
                None,
                CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            );

            if let Err(e) = resultat {
                Err(format!("CipherMgs4.finalize Erreur crypto_secretstream_xchacha20poly1305_push {:?}", e))?
            }

            self.hacheur.update(slice_output);
        }

        if self.hachage_bytes.is_some() {
            Err("Deja finalise")?;
        }

        // Calculer et conserver hachage
        let hachage_bytes = self.hacheur.finalize();

        let mut cipher_keys = Mgs4CipherKeys::new(
            self.cles_chiffrees.clone(),
            self.header.clone(),
            hachage_bytes,
            Some(self.cle_secrete),
        );
        cipher_keys.fingerprint_cert_millegrille = self.fp_cle_millegrille.clone();

        Ok((taille_output, cipher_keys))
    }

}

pub struct DecipherMgs4 {
    state: State,
    header: [u8; 24],
    buffer: [u8; CONST_TAILLE_BLOCK_MGS4],
    position_buffer: usize,
}

impl DecipherMgs4 {
    pub fn new(decipher_data: &Mgs4CipherData) -> Result<Self, String> {

        let cle_dechiffree = match &decipher_data.cle_dechiffree {
            Some(c) => c,
            None => Err("Cle n'est pas dechiffree")?,
        };

        let mut state = State::new();
        let key = Key::from(cle_dechiffree.0);
        let mut header: Header = Header::default();
        header.copy_from_slice(&decipher_data.header[0..24]);
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);

        Ok(DecipherMgs4 { state, header, buffer: [0u8; CONST_TAILLE_BLOCK_MGS4], position_buffer: 0 })
    }
}

impl DecipherMgs<Mgs4CipherData> for DecipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String> {

        let mut position_data: usize = 0;
        let mut position_output: usize = 0;

        while position_data < data.len() {

            // Dechiffrer un block de donnees
            let taille_data_restante = data.len() - position_data;

            // Copier chunk dans le buffer
            let taille_max = CONST_TAILLE_BLOCK_MGS4 - self.position_buffer;  // Max espace restant dans buffer
            let taille_chunk = min(taille_data_restante, taille_max);
            self.buffer[self.position_buffer..self.position_buffer+taille_chunk].copy_from_slice(&data[position_data..position_data+taille_chunk]);
            self.position_buffer += taille_chunk;
            position_data += taille_chunk;

            // Verifier si on fait un output
            if self.position_buffer == CONST_TAILLE_BLOCK_MGS4 {
                const TAILLE_OUTPUT: usize = CONST_TAILLE_BLOCK_MGS4 - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
                let slice_output = &mut out[position_output..position_output+TAILLE_OUTPUT];
                let mut output_tag = 0u8;

                let result = crypto_secretstream_xchacha20poly1305_pull(
                    &mut self.state, slice_output, &mut output_tag, &self.buffer, None);

                // Error handling
                if let Err(e) = result {
                    return Err(format!("DecipherMgs4.finalize Erreur dechiffrage : {:?}", e))
                }

                if output_tag != CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE {
                    return Err(format!("DecipherMgs4.finalize Erreur block final mauvais tag"))
                }

                self.position_buffer = 0;  // Reset position buffer
                position_output += TAILLE_OUTPUT;
            }

        }

        Ok(position_output)
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<usize, String> {

        if self.position_buffer < CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
            return Err(format!("DecipherMgs4.finalize Erreur block final < 17 bytes"))
        }

        let taille_output = self.position_buffer - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        {
            let mut output_tag = 0u8;

            let ciphertext = &self.buffer[0..self.position_buffer];
            debug!("Finalize dechiffrage de ciphertext {:?}", ciphertext);

            // Dechiffrer
            let result = crypto_secretstream_xchacha20poly1305_pull(
                &mut self.state, out, &mut output_tag, ciphertext, None);

            // Error handling
            if let Err(e) = result {
                return Err(format!("DecipherMgs4.finalize Erreur dechiffrage : {:?}", e))
            }
            if output_tag != CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL {
                return Err(format!("DecipherMgs4.finalize Erreur block final mauvais tag"))
            }
        }

        Ok(taille_output)
    }

}

pub struct Mgs4CipherKeys {
    cles_chiffrees: Vec<FingerprintCleChiffree>,
    pub header: String,
    pub fingerprint_cert_millegrille: Option<String>,
    pub hachage_bytes: String,
    pub cle_secrete: Option<CleSecrete>,
}

impl Debug for Mgs4CipherKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs4CipherKeys {}", self.hachage_bytes).as_str())
    }
}

impl Clone for Mgs4CipherKeys {
    fn clone(&self) -> Self {
        Self {
            cles_chiffrees: self.cles_chiffrees.clone(),
            header: self.header.clone(),
            fingerprint_cert_millegrille: self.fingerprint_cert_millegrille.clone(),
            hachage_bytes: self.hachage_bytes.clone(),
            cle_secrete: None,  // Retirer cle secrete
        }
    }
}

impl Mgs4CipherKeys {
    pub fn new(cles_chiffrees: Vec<FingerprintCleChiffree>, header: String, hachage_bytes: String, cle_secrete: Option<CleSecrete>) -> Self {
        Mgs4CipherKeys { cles_chiffrees, header, fingerprint_cert_millegrille: None, hachage_bytes, cle_secrete }
    }

    pub fn set_fingerprint_cert_millegrille(&mut self, fingerprint_cert_millegrille: &str) {
        self.fingerprint_cert_millegrille = Some(fingerprint_cert_millegrille.into());
    }

    pub fn get_cipher_data(&self, fingerprint: &str) -> Result<Mgs4CipherData, Box<dyn Error>> {
        let mut cle = self.cles_chiffrees.iter().filter(|c| c.fingerprint == fingerprint);
        match cle.next() {
            Some(c) => {
                Ok(Mgs4CipherData::new(&c.cle_chiffree, &self.header)?)
            },
            None => Err(format!("Cle introuvable : {}", fingerprint))?,
        }
    }

    pub fn get_format(&self) -> String {
        String::from("mgs4")
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

impl MgsCipherKeys for Mgs4CipherKeys {

    fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>
    ) -> Result<CommandeSauvegarderCle, String> {

        let cle_secrete = match &self.cle_secrete {
            Some(c) => c,
            None => Err(format!("Mgs4CipherKeys.get_commande_sauvegarder_cles CleSecrete None"))?
        };

        let fingerprint_partitions = self.get_fingerprint_partitions();

        let mut commande = CommandeSauvegarderCle {
            hachage_bytes: self.hachage_bytes.clone(),
            domaine: domaine.to_owned(),
            identificateurs_document,
            signature_identite: "".into(),
            cles: self.cles_to_map(),
            iv: None,
            tag: None,
            header: Some(self.header.clone()),
            format: FormatChiffrage::mgs4,
            partition,
            fingerprint_partitions: Some(fingerprint_partitions),
        };

        commande.signer_identite(cle_secrete)?;

        Ok(commande)
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

pub struct Mgs4CipherData {
    cle_chiffree: Vec<u8>,
    cle_dechiffree: Option<CleSecrete>,
    header: Vec<u8>,
}

impl Mgs4CipherData {
    pub fn new(cle_chiffree: &str, header: &str) -> Result<Self, Box<dyn Error>> {
        let cle_chiffree_bytes: Vec<u8> = decode(cle_chiffree)?.1;
        let header_bytes: Vec<u8> = decode(header)?.1;

        Ok(Mgs4CipherData {
            cle_chiffree: cle_chiffree_bytes,
            cle_dechiffree: None,
            header: header_bytes,
        })
    }
}

impl TryFrom<CleDechiffree> for Mgs4CipherData {
    type Error = Box<dyn Error>;

    fn try_from(value: CleDechiffree) -> Result<Self, Self::Error> {
        let cle_chiffree_bytes: Vec<u8> = decode(value.cle)?.1;
        let header_bytes: Vec<u8> = match value.header {
            Some(inner) => decode(inner)?.1,
            None => Err(format!("TryFrom<CleDechiffree> header manquant de la cle"))?
        };
        Ok(Self {
            cle_chiffree: cle_chiffree_bytes,
            cle_dechiffree: Some(value.cle_secrete),
            header: header_bytes,
        })
    }
}

impl MgsCipherData for Mgs4CipherData {

    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>> {
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(self.cle_chiffree.as_slice(), cle_privee)?;
        self.cle_dechiffree = Some(cle_dechiffree);

        Ok(())
    }

}

impl Debug for Mgs4CipherData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Mgs4CipherData header: {:?}", self.header).as_str())
    }
}

#[cfg(test)]
mod test {
    use log::debug;
    use openssl::pkey::{Id, PKey};

    use crate::test_setup::setup;

    use super::*;

    #[test]
    fn test_cipher4_vide() -> Result<(), Box<dyn Error>> {
        setup("test_cipher4_vide");

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

        // Chiffrer contenu "vide"
        let cipher = CipherMgs4::new(&fpkeys)?;
        debug!("Nouveau cipher info : Cles chiffrees: {:?}", cipher.cles_chiffrees);
        let mut output_chiffrage_final = [0u8; 17];
        let (_out_len, info_keys) = cipher.finalize(&mut output_chiffrage_final)?;
        debug!("Output header: keys : {:?}, output final : {:?}", info_keys, output_chiffrage_final);

        let mut out_dechiffre = [0u8; 0];

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;
                decipher.update(&output_chiffrage_final, &mut out_dechiffre)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage CleMillegrille : {}.", out_len);
                assert_eq!(0, out_len);
            } else if key.fingerprint.as_str() == "MaitreCles1" {
                // Test dechiffrage avec cle de MaitreDesCles (cle chiffree est 80 bytes : 32 bytes peer public, 32 bytes chiffre, 16 bytes tag)
                debug!("Test dechiffrage avec MaitreCles1");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_maitrecles1)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;
                decipher.update(&output_chiffrage_final, &mut out_dechiffre)?;
                let out_len = decipher.finalize(&mut [0u8])?;
                debug!("Output len dechiffrage MaitreCles1 : {}", out_len);
                assert_eq!(0, out_len);
            }
        }

        Ok(())
    }

    #[test]
    fn test_cipher4_message_court() -> Result<(), Box<dyn Error>> {
        setup("test_cipher4_message_court");

        // Generer cle
        let cle_millegrille = PKey::generate_ed25519()?;
        let cle_millegrille_public = PKey::public_key_from_raw_bytes(
            &cle_millegrille.raw_public_key()?, Id::ED25519)?;

        let mut fpkeys = Vec::new();
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "CleMillegrille".into(),
            public_key: cle_millegrille_public,
            est_cle_millegrille: true,
        });

        // Chiffrer contenu "vide"
        const MESSAGE_COURT: &[u8] = b"Ceci est un msg";  // Message 15 bytes

        let (ciphertext, info_keys) = {
            let mut ciphertext = Vec::new();
            // ciphertext.reserve(MESSAGE_COURT.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            ciphertext.extend([0u8; MESSAGE_COURT.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES]);

            let mut cipher = CipherMgs4::new(&fpkeys)?;
            debug!("Chiffrer message de {} bytes", MESSAGE_COURT.len());

            let mut output_buffer = ciphertext.as_mut_slice();
            let taille_chiffree = cipher.update(&MESSAGE_COURT, &mut output_buffer)?;
            debug!("Output taille message chiffree (update) : {}", taille_chiffree);
            let (out_len, info_keys) = cipher.finalize(&mut output_buffer[taille_chiffree..])?;
            debug!("Output chiffrage (confirmation taille: {}): {:?}.", out_len, output_buffer);

            (ciphertext, info_keys)
        };

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;

                // Dechiffrer message
                let mut output_vec = Vec::new();
                // output_vec.reserve(MESSAGE_COURT.len());
                output_vec.extend([0u8; MESSAGE_COURT.len()]);
                decipher.update(&ciphertext.as_slice(), &mut [0u8; 0])?;

                let out_len = decipher.finalize(output_vec.as_mut_slice())?;
                assert_eq!(MESSAGE_COURT.len(), out_len);
                assert_eq!(MESSAGE_COURT, output_vec.as_slice());
            }

        }

        Ok(())
    }

    #[test]
    fn test_cipher4_message_split() -> Result<(), Box<dyn Error>> {
        setup("test_cipher4_message_split");

        // Generer cle
        let cle_millegrille = PKey::generate_ed25519()?;
        let cle_millegrille_public = PKey::public_key_from_raw_bytes(
            &cle_millegrille.raw_public_key()?, Id::ED25519)?;

        let mut fpkeys = Vec::new();
        fpkeys.push(FingerprintCertPublicKey {
            fingerprint: "CleMillegrille".into(),
            public_key: cle_millegrille_public,
            est_cle_millegrille: true,
        });

        // Chiffrer contenu "vide"
        let message = [1u8; 65537];

        let (ciphertext, info_keys) = {
            let mut ciphertext = Vec::new();
            ciphertext.reserve(message.len() + 2*CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            ciphertext.extend(std::iter::repeat(1u8).take(message.len() + 2*CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES));

            let mut cipher = CipherMgs4::new(&fpkeys)?;
            debug!("Chiffrer message de {} bytes", message.len());

            let mut output_buffer = ciphertext.as_mut_slice();
            let taille_chiffree = cipher.update(&message, &mut output_buffer)?;
            debug!("Output taille message chiffree (update) : {}", taille_chiffree);
            let (out_len, info_keys) = cipher.finalize(&mut output_buffer[taille_chiffree..])?;
            debug!("Output chiffrage (confirmation taille: {})", out_len);

            (ciphertext, info_keys)
        };

        // Dechiffrer contenu "vide"
        for key in &info_keys.cles_chiffrees {

            if key.fingerprint.as_str() == "CleMillegrille" {
                // Test dechiffrage avec cle de millegrille (cle chiffree est 32 bytes)
                debug!("Test dechiffrage avec CleMillegrille");
                let mut decipher_data = Mgs4CipherData::new(
                    key.cle_chiffree.as_str(), info_keys.header.as_str())?;
                decipher_data.dechiffrer_cle(&cle_millegrille)?;
                let mut decipher = DecipherMgs4::new(&decipher_data)?;

                // Dechiffrer message
                let mut output_vec = Vec::new();
                output_vec.reserve(message.len());
                output_vec.extend(std::iter::repeat(0u8).take(message.len()));
                let out_len_msg = decipher.update(&ciphertext.as_slice(), output_vec.as_mut_slice())?;

                let out_len_final = decipher.finalize(&mut output_vec.as_mut_slice()[out_len_msg..])?;
                debug!("Output dechiffrage CleMillegrille : len {}.", out_len_msg + out_len_final);
                assert_eq!(message.len(), out_len_msg + out_len_final);
                assert_eq!(&message, output_vec.as_slice());
            }

        }

        Ok(())
    }
}