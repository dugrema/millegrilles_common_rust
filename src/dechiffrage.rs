use base64::{engine::general_purpose::STANDARD as base64, engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use futures_util::AsyncReadExt;
use jwt_simple::prelude::{Deserialize, Serialize};
use log::debug;
use millegrilles_cryptographie::chiffrage_cles::{CleDechiffrageX25519, CleDechiffrageX25519Impl, Decipher};
use millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_cryptographie::chiffrage_mgs4::DecipherMgs4;
use millegrilles_cryptographie::x25519::{dechiffrer_asymmetrique_ed25519, CleSecreteX25519};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::collections::HashMap;
use std::io::Read;

use multibase::decode;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::chiffrage_cle::ReponseDechiffrageCles;
use crate::common_messages::DataDechiffre;
use crate::constantes::*;
use crate::error::Error;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::recepteur_messages::TypeMessage;

pub async fn dechiffrer_documents<M,S>(middleware: &M, data_chiffre: DataChiffre, domaine: Option<S>)
    -> Result<DataDechiffre, Error>
    where M: GenerateurMessages, S: Into<String>
{
    let mut liste_hachage_bytes = Vec::new();
    if let Some(inner) = data_chiffre.ref_hachage_bytes.as_ref() {
        liste_hachage_bytes.push(inner.as_str())
    }
    let mut cles_dechiffrees = get_cles_dechiffrees(middleware, liste_hachage_bytes, domaine).await?;

    if let Some(hachage_bytes) = data_chiffre.ref_hachage_bytes.as_ref() {
        if let Some(cle) = cles_dechiffrees.remove(hachage_bytes) {
            return Ok(dechiffrer_data(cle, data_chiffre)?)
        }
    }

    Err(Error::Str("dechiffrer_documents Erreur recuperation cles (ref inconnu)"))
}

pub async fn get_cles_rechiffrees<M,S,T>(
    middleware: &M, liste_hachage_bytes: &Vec<S>, certificat_rechiffrage_pem: Option<&EnveloppeCertificat>,
    domaine: Option<T>
)
    -> Result<ReponseDechiffrageCles, Error>
    where M: GenerateurMessages, S: AsRef<str>, T: Into<String>
{
    let domaine_str = match domaine {
        Some(d) => Some(d.into()),
        None => None
    };

    let requete_cles = match certificat_rechiffrage_pem {
        Some(inner) => {
            // Utiliser certificat du message client (requete) pour demande de rechiffrage
            let pem_rechiffrage = inner.chaine_pem()?;

            json!({
                MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
                "certificat_rechiffrage": pem_rechiffrage,
                "domaine": domaine_str,
            })
        },
        None => json!({
            MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
            "domaine": domaine_str,
        })
    };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE, vec![Securite::L3Protege])
        .build();

    debug!("dechiffrer_documents Requete cles config notifications : {:?}", requete_cles);
    if let Some(TypeMessage::Valide(reponse)) = middleware.transmettre_requete(routage, &requete_cles).await? {
        let message_ref = reponse.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        match message_contenu.deserialize() {
            Ok(inner) => Ok(inner),
            Err(e) => Err(format!("dechiffrage.get_cles_dechiffrees Erreur mapping reponse rechiffrage {:?} : {:?}", reponse.type_message, e))?
        }
    } else {
        Err(format!("dechiffrage.get_cles_dechiffrees Message reponse invalide"))?
    }

    // let reponse_cles: ReponseDechiffrageCles = match middleware.transmettre_requete(routage, &requete_cles).await? {
    //     TypeMessage::Valide(inner) => {
    //         let message_ref = inner.message.parse()?;
    //         let message_contenu = message_ref.contenu()?;
    //         match message_contenu.deserialize() {
    //         // match inner.message.parsed.map_contenu() {
    //             Ok(inner) => inner,
    //             Err(e) => Err(format!("dechiffrage.get_cles_dechiffrees Erreur mapping reponse rechiffrage {:?} : {:?}", inner, e))?
    //         }
    //     },
    //     _ => Err(format!("dechiffrage.get_cles_dechiffrees Message reponse invalide"))?
    // };

    // Ok(reponse_cles)
}

pub async fn get_cles_dechiffrees<M,S,T>(middleware: &M, liste_hachage_bytes: Vec<S>, domaine: Option<T>)
    -> Result<HashMap<String, CleDechiffrageX25519Impl>, Error>
    where M: GenerateurMessages, S: AsRef<str>, T: Into<String>
{
    let reponse_cles = get_cles_rechiffrees(
        middleware, &liste_hachage_bytes, None, domaine
    ).await?;

    debug!("dechiffrer_documents Reponse cles dechiffrer config notifications : {:?}", reponse_cles);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let mut cles = HashMap::new();
    if let Some(inner) = reponse_cles.cles {
        for (hachage_bytes, information_cle) in inner {
            let mut cle_dechiffree: CleDechiffrageX25519Impl = (&information_cle).try_into()?;
            cle_dechiffree.dechiffrer_x25519(&enveloppe_privee.cle_privee)?;
            cles.insert(hachage_bytes, cle_dechiffree);
        }
    }

    if cles.len() != liste_hachage_bytes.len() {
        Err(format!("Certaines cles refusees, liste recue : {:?}", cles.keys()))?;
    }

    Ok(cles)
}

pub fn dechiffrer_data(mut cle: CleDechiffrageX25519Impl, data: DataChiffre) -> Result<DataDechiffre, Error> {
    // let mut decipher_data = data.to_cle_dechiffrage_x25519(cle);

    if let Some(header) = data.header.as_ref() {
        // Remplacer le header par celui du data (requis lors de reutilisation de cles)
        cle.nonce = Some(header.clone())
    }

    // match &data.header {
    //     Some(header) => {
    //         decipher_data.nonce = match decode(header) {
    //             Ok(inner) => inner,
    //             Err(e) => Err(format!("dechiffrer_data Erreur multibase.decode decipher_data.header {} : {:?}", header, e))?
    //         }.1
    //     },
    //     None => ()
    // }

    let mut decipher = DecipherMgs4::new(&cle)?;
    let data_dechiffre = decipher.gz_to_vec(data.data_chiffre.as_bytes())?;

    // // Dechiffrer message
    // let data_dechiffre = {
    //     let mut output_vec = Vec::new();
    //     let data_chiffre_vec: Vec<u8> = match decode(data.data_chiffre.as_str()) {
    //         Ok(inner) => inner,
    //         Err(e) => Err(format!("dechiffrer_data Erreur multibase.decode data.data_chiffre {} : {:?}", data.data_chiffre, e))?
    //     }.1;
    //     debug!("dechiffrer_data Dechiffrer {}", data_chiffre_vec.len());
    //     // output_vec.reserve(data_chiffre_vec.len());
    //     output_vec.extend(std::iter::repeat(0).take(data_chiffre_vec.len()));
    //     let len = decipher.update(data_chiffre_vec.as_slice(), &mut output_vec[..])?;
    //     let out_len = decipher.finalize(&mut output_vec[len..])?;
    //     debug!("dechiffrer_data Output len {}, finalize len {}", len, out_len);
    //
    //     let mut data_dechiffre = Vec::new();
    //     data_dechiffre.extend_from_slice(&output_vec[..(len + out_len)]);
    //
    //     data_dechiffre
    // };

    // Decompresser data
    debug!("dechiffrer_data Decompresser data dechiffre");
    // let mut decoder = GzDecoder::new(&data_dechiffre[..]);
    // let mut data_decompresse = Vec::new();
    // let resultat = decoder.read_to_end(&mut data_dechiffra)?;

    Ok(DataDechiffre {
        ref_hachage_bytes: data.ref_hachage_bytes,
        data_dechiffre,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffreBorrow<'a> {
    #[serde(borrow)]
    pub data_chiffre: &'a str,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub cle_id: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub format: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub nonce: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub verification: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub header: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub ref_hachage_bytes: Option<&'a str>,

    #[serde(borrow, skip_serializing_if="Option::is_none")]
    pub hachage_bytes: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataChiffre {
    /// Contenu chiffre
    pub data_chiffre: String,

    // Format du chiffrage
    pub format: Option<String>,

    /// Id de la cle de dechiffrage
    #[serde(skip_serializing_if="Option::is_none")]
    pub cle_id: Option<String>,

    /// Nonce / iv de dechiffrage (depend du format)
    #[serde(skip_serializing_if="Option::is_none")]
    pub nonce: Option<String>,

    /// Methode de verification (depend du format)
    #[serde(skip_serializing_if="Option::is_none")]
    pub verification: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub header: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub ref_hachage_bytes: Option<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub hachage_bytes: Option<String>,
}

impl DataChiffre {

    /// Retourne une identite de cle.
    pub fn get_cle_id(&self) -> Result<&str, Error> {
        match self.cle_id.as_ref() {
            Some(inner) => Ok(inner.as_str()),
            None => match self.ref_hachage_bytes.as_ref() {
                Some(inner) => Ok(inner.as_str()),
                None => match self.hachage_bytes.as_ref() {
                    Some(inner) => Ok(inner.as_str()),
                    None => Err(Error::Str("Aucune identite disponible"))
                }
            }
        }
    }

}

impl<'a> From<DataChiffreBorrow<'a>> for DataChiffre {
    fn from(value: DataChiffreBorrow) -> Self {
        Self {
            data_chiffre: value.data_chiffre.to_owned(),
            header: match value.header { Some(inner) => Some(inner.to_owned()), None => None},
            ref_hachage_bytes: match value.ref_hachage_bytes { Some(inner) => Some(inner.to_owned()), None => None},
            hachage_bytes: match value.hachage_bytes { Some(inner) => Some(inner.to_owned()), None => None},
            format: match value.format { Some(inner) => Some(inner.to_owned()), None => None},
            cle_id: match value.cle_id { Some(inner) => Some(inner.to_owned()), None => None},
            nonce: match value.nonce { Some(inner) => Some(inner.to_owned()), None => None},
            verification: match value.verification { Some(inner) => Some(inner.to_owned()), None => None},
        }
    }
}

pub fn decrypt_document<M,D>(middleware: &M, document: EncryptedDocument) -> Result<D, Error>
    where M: GenerateurMessages, D: DeserializeOwned
{
    let cle_secrete = match document.cle.as_ref() {
        Some(inner) => match inner.cles.as_ref() {
            Some(inner) => {
                // Trouver la cle qui correspond au fingerprint de notre certificat
                let enveloppe_signature = middleware.get_enveloppe_signature();
                let fingerprint = enveloppe_signature.fingerprint()?;
                match inner.get(fingerprint.as_str()) {
                    Some(cle_dechiffrage) => {
                        // Decoder de base64, copier dans CleSecrete
                        let cle_chiffree = match base64_nopad.decode(cle_dechiffrage) {
                            Ok(inner) => inner,
                            Err(_e) => base64.decode(cle_dechiffrage)?  // Try with padding
                        };
                        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(cle_chiffree.as_slice(), &enveloppe_signature.cle_privee)?;
                        cle_dechiffree
                    },
                    None => Err("Aucunes cles de dechiffrage ne correspond a la cle privee locale")?
                }
            },
            None => Err("Aucunes cles de dechiffrage du document fournies (1)")?
        },
        None => Err("Aucunes cles de dechiffrage du document fournies (2)")?
    };

    let document_cles = document.decrypt_with_secret(&cle_secrete)?;
    Ok(serde_json::from_slice(document_cles.as_slice())?)
}

// #[cfg(test)]
// mod test {
//     use dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
//     use log::debug;
//     use multibase::{Base, encode};
//     use openssl::pkey::{Id, PKey, Private};
//     use crate::certificats::FingerprintCertPublicKey;
//     use crate::chiffrage::{CipherMgs, CleSecrete, FormatChiffrage};
//     use crate::chiffrage_streamxchacha20poly1305::{CipherMgs4, Mgs4CipherKeys};
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     #[test]
//     fn test_decipher_court() -> Result<(), Box<dyn Error>> {
//         setup("test_cipher4_vide");
//
//         let (cle, fps) = generer_cles()?;
//         const MESSAGE_COURT: &[u8] = b"Ceci est un msg";  // Message 15 bytes
//         let (ciphertext, cles) = chiffrer(fps, MESSAGE_COURT)?;
//         debug!("Message chiffre : {:?}", ciphertext);
//         let ciphertext_string = encode(Base::Base64, ciphertext);
//         debug!("Message chiffre string : {:?}", ciphertext_string);
//
//         let cle_secrete = cles.cle_secrete.as_ref().expect("cle secrete");
//         let cle_bytes = cle_secrete.0;
//         let cle_secrete = CleSecrete ( cle_bytes );
//
//         let cle_dechiffree = CleDechiffree {
//             cle: String::from("mXoCusx6NjjuVRI4Rjb4Y/8/wJtQAIWCxT3ykEDA2VS0"),
//             cle_secrete: CleSecrete ( cle_bytes ),
//             domaine: String::from("DUMMY"),
//             format: cles.get_format(),
//             hachage_bytes: cles.hachage_bytes.clone(),
//             identificateurs_document: None,
//             iv: None,
//             tag: None,
//             header: Some(cles.header.clone()),
//         };
//
//         let data_chiffre = DataChiffre {
//             ref_hachage_bytes: Some(cles.hachage_bytes),
//             data_chiffre: ciphertext_string,
//             format: FormatChiffrage::mgs4,
//             header: Some(cles.header),
//             tag: None,
//         };
//
//         let resultat = dechiffrer_data(cle_dechiffree, data_chiffre)?;
//         let resultat_string = String::from_utf8(resultat.data_dechiffre);
//         debug!("Data dechiffre : {:?}", resultat_string);
//
//         Ok(())
//     }
//
//     fn generer_cles() -> Result<(PKey<Private>, Vec<FingerprintCertPublicKey>), Box<dyn Error>> {
//         // Generer cle
//         let cle_millegrille = PKey::generate_ed25519()?;
//         let cle_millegrille_public = PKey::public_key_from_raw_bytes(
//             &cle_millegrille.raw_public_key()?, Id::ED25519)?;
//
//         let mut fpkeys = Vec::new();
//         fpkeys.push(FingerprintCertPublicKey {
//             fingerprint: "CleMillegrille".into(),
//             public_key: cle_millegrille_public,
//             est_cle_millegrille: true,
//         });
//
//         Ok((cle_millegrille, fpkeys))
//     }
//
//     fn chiffrer(fpkeys: Vec<FingerprintCertPublicKey>, message: &[u8]) -> Result<(Vec<u8>, Mgs4CipherKeys), Box<dyn Error>>{
//         let mut ciphertext = Vec::new();
//
//         // Extend pour taille du message + ABYTES
//         ciphertext.extend(std::iter::repeat(0).take(message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES));
//
//         let mut cipher = CipherMgs4::new(&fpkeys)?;
//         debug!("Chiffrer message de {} bytes", message.len());
//
//         let mut output_buffer = ciphertext.as_mut_slice();
//         let taille_chiffree = cipher.update(message, &mut output_buffer)?;
//         debug!("Output taille message chiffree (update) : {}", taille_chiffree);
//         let (out_len, info_keys) = cipher.finalize(&mut output_buffer[taille_chiffree..])?;
//         debug!("Output chiffrage (confirmation taille: {}): {:?}.", out_len, output_buffer);
//
//         Ok((ciphertext, info_keys))
//     }
// }