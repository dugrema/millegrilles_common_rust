use std::collections::HashMap;
use std::error::Error;
use log::debug;
use multibase::decode;
use serde_json::json;
use crate::certificats::EnveloppeCertificat;
use crate::chiffrage::{DecipherMgs, MgsCipherData};
use crate::chiffrage_cle::{CleDechiffree, ReponseDechiffrageCles};
use crate::chiffrage_streamxchacha20poly1305::{DecipherMgs4, Mgs4CipherData};
use crate::common_messages::{DataChiffre, DataDechiffre};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use crate::constantes::*;
use crate::recepteur_messages::TypeMessage;

pub async fn dechiffrer_documents<M>(middleware: &M, liste_data_chiffre: Vec<DataChiffre>)
    -> Result<Vec<DataDechiffre>, Box<dyn Error>>
    where M: GenerateurMessages
{
    let mut liste_hachage_bytes = Vec::new();
    for d in &liste_data_chiffre {
        if let Some(inner) = d.ref_hachage_bytes.as_ref() {
            liste_hachage_bytes.push(inner.as_str())
        }
    }
    let mut cles_dechiffrees = get_cles_dechiffrees(middleware, liste_hachage_bytes).await?;

    let mut data_dechiffre = Vec::new();
    for d in liste_data_chiffre {
        if let Some(hachage_bytes) = d.ref_hachage_bytes.as_ref() {
            if let Some(cle) = cles_dechiffrees.remove(hachage_bytes) {
                let data = dechiffrer_data(cle, d)?;
                data_dechiffre.push(data);
            }
        }
    }

    Ok(data_dechiffre)
}

pub async fn get_cles_rechiffrees<M,S>(middleware: &M, liste_hachage_bytes: &Vec<S>, certificat_rechiffrage_pem: Option<&EnveloppeCertificat>)
    -> Result<ReponseDechiffrageCles, Box<dyn Error>>
    where M: GenerateurMessages, S: AsRef<str>
{
    let requete_cles = match certificat_rechiffrage_pem {
        Some(inner) => {
            // Utiliser certificat du message client (requete) pour demande de rechiffrage
            let pem_rechiffrage: Vec<String> = match inner {
                Some(c) => {
                    let fp_certs = c.get_pem_vec();
                    fp_certs.into_iter().map(|cert| cert.pem).collect()
                },
                None => Err(format!("Erreur formattage certificat en PEM"))?
            };

            json!({
                MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
                "certificat_rechiffrage": pem_rechiffrage,
            })
        },
        None => json!({
            MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
        })
    };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L3Protege])
        .build();

    debug!("dechiffrer_documents Requete cles config notifications : {:?}", requete_cles);
    let reponse_cles: ReponseDechiffrageCles = match middleware.transmettre_requete(routage, &requete_cles).await? {
        TypeMessage::Valide(inner) => {
            inner.message.parsed.map_contenu(None)?
        },
        _ => Err(format!("dechiffrage.get_cles_dechiffrees Message reponse invalide"))?
    };

    Ok(reponse_cles)
}

pub async fn get_cles_dechiffrees<M,S>(middleware: &M, liste_hachage_bytes: Vec<S>)
    -> Result<HashMap<String, CleDechiffree>, Box<dyn Error>>
    where M: GenerateurMessages, S: AsRef<str>
{
    // let requete_cles = json!({
    //     MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage_bytes.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
    // });
    // let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
    //     .exchanges(vec![Securite::L3Protege])
    //     .build();
    // debug!("dechiffrer_documents Requete cles config notifications : {:?}", requete_cles);
    // let reponse_cles: ReponseDechiffrageCles = match middleware.transmettre_requete(routage, &requete_cles).await? {
    //     TypeMessage::Valide(inner) => {
    //         inner.message.parsed.map_contenu(None)?
    //     },
    //     _ => Err(format!("dechiffrage.get_cles_dechiffrees Message reponse invalide"))?
    // };

    let reponse_cles = get_cles_rechiffrees(middleware, &liste_hachage_bytes, None).await?;

    debug!("dechiffrer_documents Reponse cles dechiffrer config notifications : {:?}", reponse_cles);
    let enveloppe_privee = middleware.get_enveloppe_signature();
    let mut cles = HashMap::new();
    if let Some(inner) = reponse_cles.cles {
        for (hachage_bytes, information_cle) in inner {
            let cle_dechiffree = CleDechiffree::dechiffrer_information_cle(enveloppe_privee.as_ref(), information_cle)?;
            cles.insert(hachage_bytes, cle_dechiffree);
        }
    }

    if cles.len() != liste_hachage_bytes.len() {
        Err(format!("Certaines cles refusees, liste recue : {:?}", cles.keys()))?;
    }

    Ok(cles)
}

pub fn dechiffrer_data(cle: CleDechiffree, data: DataChiffre) -> Result<DataDechiffre, Box<dyn Error>> {
    let mut decipher_data = Mgs4CipherData::try_from(cle)?;

    // Remplacer le header par celui du data (requis lors de reutilisation de cles)
    match &data.header {
        Some(inner) => decipher_data.header = decode(inner) ?.1,
        None => ()
    }

    let mut decipher = DecipherMgs4::new(&decipher_data)?;

    // Dechiffrer message
    let mut output_vec = Vec::new();
    let data_chiffre_vec: Vec<u8> = decode(data.data_chiffre)?.1;
    debug!("dechiffrer_data Dechiffrer {:?}", data_chiffre_vec);
    // output_vec.reserve(data_chiffre_vec.len());
    output_vec.extend(std::iter::repeat(0).take(data_chiffre_vec.len()));
    let len = decipher.update(data_chiffre_vec.as_slice(), &mut output_vec[..])?;
    let out_len = decipher.finalize(&mut output_vec[len..])?;
    debug!("dechiffrer_data Output len {}, finalize len {}", len, out_len);

    let mut data_dechiffre = Vec::new();
    data_dechiffre.extend_from_slice(&output_vec[..(len + out_len)]);

    Ok(DataDechiffre {
        ref_hachage_bytes: data.ref_hachage_bytes,
        data_dechiffre,
    })
}

#[cfg(test)]
mod test {
    use dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
    use log::debug;
    use multibase::{Base, encode};
    use openssl::pkey::{Id, PKey, Private};
    use crate::certificats::FingerprintCertPublicKey;
    use crate::chiffrage::{CipherMgs, CleSecrete, FormatChiffrage};
    use crate::chiffrage_streamxchacha20poly1305::{CipherMgs4, Mgs4CipherKeys};

    use crate::test_setup::setup;

    use super::*;

    #[test]
    fn test_decipher_court() -> Result<(), Box<dyn Error>> {
        setup("test_cipher4_vide");

        let (cle, fps) = generer_cles()?;
        const MESSAGE_COURT: &[u8] = b"Ceci est un msg";  // Message 15 bytes
        let (ciphertext, cles) = chiffrer(fps, MESSAGE_COURT)?;
        debug!("Message chiffre : {:?}", ciphertext);
        let ciphertext_string = encode(Base::Base64, ciphertext);
        debug!("Message chiffre string : {:?}", ciphertext_string);

        let cle_secrete = cles.cle_secrete.as_ref().expect("cle secrete");
        let cle_bytes = cle_secrete.0;
        let cle_secrete = CleSecrete ( cle_bytes );

        let cle_dechiffree = CleDechiffree {
            cle: String::from("mXoCusx6NjjuVRI4Rjb4Y/8/wJtQAIWCxT3ykEDA2VS0"),
            cle_secrete: CleSecrete ( cle_bytes ),
            domaine: String::from("DUMMY"),
            format: cles.get_format(),
            hachage_bytes: cles.hachage_bytes.clone(),
            identificateurs_document: None,
            iv: None,
            tag: None,
            header: Some(cles.header.clone()),
            signature_identite: String::from("DUMMY"),
        };

        let data_chiffre = DataChiffre {
            ref_hachage_bytes: Some(cles.hachage_bytes),
            data_chiffre: ciphertext_string,
            format: FormatChiffrage::mgs4,
            header: Some(cles.header),
            tag: None,
        };

        let resultat = dechiffrer_data(cle_dechiffree, data_chiffre)?;
        let resultat_string = String::from_utf8(resultat.data_dechiffre);
        debug!("Data dechiffre : {:?}", resultat_string);

        Ok(())
    }

    fn generer_cles() -> Result<(PKey<Private>, Vec<FingerprintCertPublicKey>), Box<dyn Error>> {
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

        Ok((cle_millegrille, fpkeys))
    }

    fn chiffrer(fpkeys: Vec<FingerprintCertPublicKey>, message: &[u8]) -> Result<(Vec<u8>, Mgs4CipherKeys), Box<dyn Error>>{
        let mut ciphertext = Vec::new();

        // Extend pour taille du message + ABYTES
        ciphertext.extend(std::iter::repeat(0).take(message.len() + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES));

        let mut cipher = CipherMgs4::new(&fpkeys)?;
        debug!("Chiffrer message de {} bytes", message.len());

        let mut output_buffer = ciphertext.as_mut_slice();
        let taille_chiffree = cipher.update(message, &mut output_buffer)?;
        debug!("Output taille message chiffree (update) : {}", taille_chiffree);
        let (out_len, info_keys) = cipher.finalize(&mut output_buffer[taille_chiffree..])?;
        debug!("Output chiffrage (confirmation taille: {}): {:?}.", out_len, output_buffer);

        Ok((ciphertext, info_keys))
    }
}