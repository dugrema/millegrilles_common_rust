use std::error::Error;
use std::path::Path;

use multibase::Base;
use multihash::Code;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio_stream::{Iter, StreamExt};
use xz2::stream;

use crate::{CipherMgs2, FingerprintCertPublicKey, Hacheur, Mgs2CipherKeys};
use crate::constantes::*;

pub struct FichierWriter<'a> {
    path_fichier: &'a Path,
    fichier: Box<tokio::fs::File>,
    xz_encodeur: stream::Stream,
    hacheur: Hacheur,
    chiffreur: Option<CipherMgs2>,
}

impl<'a> FichierWriter<'a> {

    const BUFFER_SIZE: usize = 64 * 1024;

    pub async fn new(path_fichier: &'a Path, certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>) -> Result<FichierWriter<'a>, Box<dyn Error>> {
        let output_file = tokio::fs::File::create(path_fichier).await?;
        // let xz_encodeur = XzEncoder::new(output_file, 9);
        let xz_encodeur = stream::Stream::new_easy_encoder(9, stream::Check::Crc64).expect("stream");
        let hacheur = Hacheur::builder().digester(Code::Sha2_512).base(Base::Base58Btc).build();

        let chiffreur = match certificats_chiffrage {
            Some(c) => {
                Some(CipherMgs2::new(&c))
            },
            None => None,
        };

        Ok(FichierWriter {
            path_fichier,
            fichier: Box::new(output_file),
            xz_encodeur,
            hacheur,
            chiffreur,
        })
    }

    pub async fn write(&mut self, contenu: &[u8]) -> Result<usize, Box<dyn Error>> {

        let chunks = contenu.chunks(FichierWriter::BUFFER_SIZE);
        let mut chunks = tokio_stream::iter(chunks);

        // Preparer vecteur pour recevoir data compresse (avant chiffrage) pour output vers fichier
        let mut buffer_chiffre = [0u8; FichierWriter::BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(FichierWriter::BUFFER_SIZE);

        let mut count_bytes = 0usize;

        while let Some(chunk) = chunks.next().await {
            let status = self.xz_encodeur.process_vec(chunk, &mut buffer, stream::Action::Run)?;
            if status != stream::Status::Ok {
                Err(format!("Erreur compression transaction, status {:?}", status))?;
            }

            let buffer_output = match &mut self.chiffreur {
                Some(c) => {
                    let len = c.update(buffer.as_slice(), &mut buffer_chiffre)?;
                    &buffer_chiffre[..len]
                },
                None => buffer.as_slice()
            };

            // Ajouter au hachage
            self.hacheur.update(buffer_output);

            // Ecrire dans fichier
            self.fichier.write_all(buffer_output).await?;

            count_bytes += buffer_output.len();
        }

        Ok(count_bytes)
    }

    pub async fn fermer(mut self) -> Result<(String, Option<Mgs2CipherKeys>), Box<dyn Error>> {
        let mut buffer_chiffre = [0u8; FichierWriter::BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(FichierWriter::BUFFER_SIZE);

        // Flush xz
        while let status = self.xz_encodeur.process_vec(&EMPTY_ARRAY, &mut buffer, stream::Action::Finish)? {

            let buffer_output = match &mut self.chiffreur {
                Some(c) => {
                    let len = c.update(buffer.as_slice(), &mut buffer_chiffre)?;
                    &buffer_chiffre[..len]
                },
                None => buffer.as_slice()
            };

            self.hacheur.update(buffer_output);
            self.fichier.write_all(buffer_output).await?;

            if status != stream::Status::Ok {
                if status == stream::Status::MemNeeded {
                    Err("Erreur generique de creation fichier .xz")?;
                }
                break
            }
        }

        // Flusher chiffrage (si applicable)
        match &mut self.chiffreur {
            Some(c) => {
                let len = c.finalize(&mut buffer_chiffre)?;
                if len > 0 {
                    // Finaliser output
                    let slice_buffer = &buffer_chiffre[..len];
                    self.hacheur.update(slice_buffer);
                    self.fichier.write_all(slice_buffer).await?;
                }
            },
            None => ()
        }

        // Passer dans le hachage et finir l'ecriture du fichier
        let hachage = self.hacheur.finalize();
        self.fichier.flush().await?;

        let cipher_data = match &self.chiffreur {
            Some(c) => Some(c.get_cipher_keys()?),
            None => None,
        };

        Ok((hachage, cipher_data))
    }

}

#[cfg(test)]
mod fichiers_tests {

    use super::*;
    use std::path::PathBuf;

    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
    use std::collections::HashMap;

    const HASH_FICHIER_TEST: &str = "z8Vts2By1ww2kJBtEGeitMTrLgKLhYCxV3ZREi66F8g73Jo8U96dKYMrRKKzwGpBR6kFUgmMAZZcYaPVU3NW6TQ8duk";
    const BYTES_TEST: &[u8] = b"des bytes a ecrire";

    #[tokio::test]
    async fn ecrire_bytes_writer() {
        println!("Test async fichiers");

        let path_fichier = PathBuf::from("/tmp/fichier_tests.1.xz");
        let mut writer = FichierWriter::new(path_fichier.as_path(), None).await.expect("writer");
        writer.write(BYTES_TEST).await.expect("write");
        let (mh, _) = writer.fermer().await.expect("finish");

        assert_eq!(HASH_FICHIER_TEST, mh.as_str());
    }

    #[tokio::test]
    async fn ecrire_bytes_chiffres_writer() {
        println!("Test async fichiers");

        let (validateur, enveloppe) = charger_enveloppe_privee_env();

        let fp_certs = vec!(FingerprintCertPublicKey::new(
            String::from("dummy"),
            enveloppe.certificat().public_key().clone().expect("cle")
        ));

        let path_fichier = PathBuf::from("/tmp/fichier_tests.2.xz.mgs2");
        let mut writer = FichierWriter::new(path_fichier.as_path(), Some(fp_certs)).await.expect("writer");
        writer.write(BYTES_TEST).await.expect("write");
        let (mh, cipher_keys) = writer.fermer().await.expect("finish");

        assert_ne!(HASH_FICHIER_TEST, mh.as_str());
        println!("cipher_keys : {:?}", cipher_keys);

        let mut id_docs: HashMap<String, String> = HashMap::new();
        id_docs.insert(String::from("dummy_id"), String::from("dummy_valeur"));
        let commande_cles = cipher_keys
            .expect("cles")
            .get_commande_sauvegarder_cles(mh.as_str(), "dummy", id_docs);

        println!("Commande cles : {:?}", commande_cles);
    }

}
