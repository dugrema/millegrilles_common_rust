use std::error::Error;
use std::path::Path;

use async_recursion::async_recursion;
use async_tar::{Archive, Entry};
use futures::Stream;
use log::{debug, error, info, warn};
use multibase::Base;
use multihash::Code;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio_stream::{Iter, StreamExt};
use tokio_util::codec::{BytesCodec, FramedRead};
use xz2::stream;
use async_std::io::ReadExt;
use bytes::BufMut;

use crate::{CipherMgs2, FingerprintCertPublicKey, Hacheur, Mgs2CipherKeys, TransactionReader, ValidateurX509};
use crate::constantes::*;
use xz2::stream::Status;
use crate::backup::CatalogueHoraire;
use async_trait::async_trait;

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

/// Compresse des bytes, retourne un Vec
pub struct CompresseurBytes {
    xz_encodeur: stream::Stream,
    hacheur: Hacheur,
    contenu: Vec<u8>,
}

impl CompresseurBytes {
    const BUFFER_SIZE: usize = 64 * 1024;

    pub fn new() -> Result<CompresseurBytes, Box<dyn Error>> {
        let xz_encodeur = stream::Stream::new_easy_encoder(9, stream::Check::Crc64).expect("stream");
        let hacheur = Hacheur::builder().digester(Code::Sha2_512).base(Base::Base58Btc).build();

        Ok(CompresseurBytes {
            xz_encodeur,
            hacheur,
            contenu: Vec::new(),
        })
    }

    pub async fn write(&mut self, contenu: &[u8]) -> Result<usize, Box<dyn Error>> {

        let chunks = contenu.chunks(CompresseurBytes::BUFFER_SIZE);
        let mut chunks = tokio_stream::iter(chunks);

        // Preparer vecteur pour recevoir data compresse (avant chiffrage) pour output vers fichier
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(CompresseurBytes::BUFFER_SIZE);

        let mut count_bytes = 0usize;

        while let Some(chunk) = chunks.next().await {
            let status = self.xz_encodeur.process_vec(chunk, &mut buffer, stream::Action::Run)?;
            if status != stream::Status::Ok {
                Err(format!("Erreur compression transaction, status {:?}", status))?;
            }

            // Ajouter au hachage
            self.hacheur.update(&mut buffer);

            // Ecrire dans contenu
            self.contenu.append(&mut buffer);

            count_bytes += buffer.len();
        }

        Ok(count_bytes)
    }

    pub fn fermer(mut self) -> Result<(Vec<u8>, String), Box<dyn Error>> {
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(CompresseurBytes::BUFFER_SIZE);

        // Flush xz
        while let status = self.xz_encodeur.process_vec(&EMPTY_ARRAY, &mut buffer, stream::Action::Finish)? {

            self.hacheur.update(&buffer);
            self.contenu.append(&mut buffer);

            if status != stream::Status::Ok {
                if status == stream::Status::MemNeeded {
                    Err("Erreur generique de creation fichier .xz")?;
                }
                break
            }
        }

        // Passer dans le hachage et finir l'ecriture du fichier
        let hachage = self.hacheur.finalize();

        Ok((self.contenu, hachage))
    }

}

pub struct DecompresseurBytes {
    xz_decoder: stream::Stream,
    output: Vec<u8>,
}

impl DecompresseurBytes {

    const BUFFER_SIZE: usize = 65535;

    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut xz_decoder = stream::Stream::new_stream_decoder(u64::MAX, stream::TELL_NO_CHECK)?;
        Ok(DecompresseurBytes {
            xz_decoder,
            output: Vec::new(),
        })
    }

    pub fn update_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        debug!("Decompresser bytes : {:?}", data);
        let mut xz_output = Vec::new();
        xz_output.reserve(data.len()*10);
        let status = self.xz_decoder.process_vec(data, &mut xz_output, stream::Action::Run).expect("xz-output");
        if status != stream::Status::Ok && status != stream::Status::StreamEnd {
            Err(format!("Erreur traitement stream : {:?}", status))?;
        }

        self.output.append(&mut xz_output);

        Ok(())
    }

    pub async fn update<'a>(&mut self, data: &mut (impl AsyncRead + Unpin + 'a)) -> Result<(), Box<dyn Error>> {
        let mut buffer = [0u8; DecompresseurBytes::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(DecompresseurBytes::BUFFER_SIZE);

        loop {
            let len = data.read(&mut buffer).await.expect("lecture");
            if len == 0 {break}

            let traiter_bytes = &buffer[..len];

            let status = self.xz_decoder.process_vec(traiter_bytes, &mut xz_output, stream::Action::Run).expect("xz-output");
            if status != stream::Status::Ok && status != stream::Status::StreamEnd {
                Err(format!("Erreur traitement stream : {:?}", status))?;
            }

            self.output.append(&mut xz_output);
        }

        Ok(())
    }

    pub async fn update_std<'a>(&mut self, data: &mut (impl futures::io::AsyncRead + Unpin + 'a)) -> Result<(), Box<dyn Error>> {
        let mut buffer = [0u8; DecompresseurBytes::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(DecompresseurBytes::BUFFER_SIZE);

        loop {
            let len = data.read(&mut buffer).await.expect("lecture");
            if len == 0 {break}

            let traiter_bytes = &buffer[..len];

            let status = self.xz_decoder.process_vec(traiter_bytes, &mut xz_output, stream::Action::Run).expect("xz-output");
            if status != stream::Status::Ok && status != stream::Status::StreamEnd {
                Err(format!("Erreur traitement stream : {:?}", status))?;
            }

            self.output.append(&mut xz_output);
        }

        Ok(())
    }

    pub fn finish(mut self) -> Result<Vec<u8>, Box<dyn Error>> {

        let mut xz_output = Vec::new();
        xz_output.reserve(DecompresseurBytes::BUFFER_SIZE);

        loop {
            let traiter_bytes = [0u8;0];

            let status = self.xz_decoder.process_vec(&traiter_bytes[0..0], &mut xz_output, stream::Action::Finish).expect("xz-output");
            self.output.append(&mut xz_output);
            if status != stream::Status::Ok {
                if status != stream::Status::StreamEnd {
                    Err("Erreur decompression xz")?;
                }
                break
            }
        }

        Ok(self.output)
    }

}

// pub async fn parse(&mut self, stream: impl tokio::io::AsyncRead+Send+Sync+Unpin) -> Result<(), Box<dyn Error>> {
pub async fn parse_tar(middleware: &impl ValidateurX509, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut(impl TraiterFichier)) -> Result<(), Box<dyn Error>> {
    let mut reader = Archive::new(stream);

    let mut entries = reader.entries().expect("entries");
    while let Some(entry) = entries.next().await {
        debug!("Entry! : {:?}", entry);
        let mut file = entry.expect("file");
        let file_path = file.path().expect("path").into_owned();

        // Process tar or other file type
        match file_path.extension() {
            Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
                "tar" => parse_tar1(middleware, &mut file, processeur).await?,
                _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
            },
            None => {
                warn!("Fichier de type inconnu, on skip : {:?}", file_path)
            }
        }
    }

    Ok(())
}

// todo : Fix parse_tar recursion async
pub async fn parse_tar1(middleware: &impl ValidateurX509, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut(impl TraiterFichier)) -> Result<(), Box<dyn Error>> {
    let mut reader = Archive::new(stream);

    let mut entries = reader.entries().expect("entries");
    while let Some(entry) = entries.next().await {
        let mut file = entry.expect("file");
        let file_path = file.path().expect("path").into_owned();

        // Process tar or other file type
        match file_path.extension() {
            Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
                "tar" => parse_tar2(middleware, &mut file, processeur).await?,
                _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
            },
            None => {
                warn!("Fichier de type inconnu, on skip : {:?}", file_path)
            }
        }
    }

    Ok(())
}

// todo : Fix parse_tar recursion async
pub async fn parse_tar2(middleware: &impl ValidateurX509, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut(impl TraiterFichier)) -> Result<(), Box<dyn Error>> {
    let mut reader = Archive::new(stream);

    let mut entries = reader.entries().expect("entries");
    while let Some(entry) = entries.next().await {
        let mut file = entry.expect("file");
        let file_path = file.path().expect("path").into_owned();

        // Process tar or other file type
        match file_path.extension() {
            Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
                "tar" => parse_tar3(middleware, &mut file, processeur).await?,
                _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
            },
            None => {
                warn!("Fichier de type inconnu, on skip : {:?}", file_path)
            }
        }
    }

    Ok(())
}

// todo : Fix parse_tar recursion async
pub async fn parse_tar3(middleware: &impl ValidateurX509, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut(impl TraiterFichier)) -> Result<(), Box<dyn Error>> {
    let mut reader = Archive::new(stream);

    let mut entries = reader.entries().expect("entries");
    while let Some(entry) = entries.next().await {
        let mut file = entry.expect("file");
        let file_path = file.path().expect("path").into_owned();

        // Process tar or other file type
        match file_path.extension() {
            Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
                "tar" => panic!("Recursion niveau 3 .tar non supporte"),
                _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
            },
            None => {
                warn!("Fichier de type inconnu, on skip : {:?}", file_path)
            }
        }
    }

    Ok(())
}

#[async_trait]
pub trait TraiterFichier {
    async fn traiter_fichier(&mut self, middleware: &impl ValidateurX509, nom_fichier: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>;
}

#[cfg(test)]
mod fichiers_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use tokio_util::codec::{BytesCodec, FramedRead};

    use crate::test_setup::setup;
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;

    use super::*;
    use async_std::future::Future;
    use crate::ValidateurX509;

    const HASH_FICHIER_TEST: &str = "z8Vts2By1ww2kJBtEGeitMTrLgKLhYCxV3ZREi66F8g73Jo8U96dKYMrRKKzwGpBR6kFUgmMAZZcYaPVU3NW6TQ8duk";
    const BYTES_TEST: &[u8] = b"des bytes a ecrire";

    struct DummyTraiterFichier{}
    #[async_trait]
    impl TraiterFichier for DummyTraiterFichier {
        async fn traiter_fichier(
            &mut self,
            middleware: &impl ValidateurX509,
            nom_fichier: &async_std::path::Path,
            stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)
        ) -> Result<(), Box<dyn Error>> {
            debug!("Traiter fichier {:?}", nom_fichier);

            Ok(())
        }
    }

    #[tokio::test]
    async fn ecrire_bytes_writer() {
        setup("ecrire_bytes_writer");

        let path_fichier = PathBuf::from("/tmp/fichier_tests.1.xz");
        let mut writer = FichierWriter::new(path_fichier.as_path(), None).await.expect("writer");
        writer.write(BYTES_TEST).await.expect("write");
        let (mh, _) = writer.fermer().await.expect("finish");

        assert_eq!(HASH_FICHIER_TEST, mh.as_str());
    }

    #[tokio::test]
    async fn decompresser_reader() {
        setup("decompresser_reader");

        let path_fichier = PathBuf::from("/tmp/output.xz");
        let mut fichier = File::open(path_fichier.as_path()).await.expect("fichier");

        let mut decompresseur = DecompresseurBytes::new().expect("decompresseur");
        decompresseur.update(&mut fichier).await.expect("update");
        let mut resultat = decompresseur.finish().expect("decompresseur");
        let resultat_str = String::from_utf8(resultat).expect("utf8");
        debug!("Resultat decompresse : {}", resultat_str);
    }

    #[tokio::test]
    async fn ecrire_bytes_chiffres_writer() {
        setup("ecrire_bytes_chiffres_writer");

        let (validateur, enveloppe) = charger_enveloppe_privee_env();

        let fp_certs = vec!(FingerprintCertPublicKey::new(
            String::from("dummy"),
            enveloppe.certificat().public_key().clone().expect("cle"),
            true
        ));

        let path_fichier = PathBuf::from("/tmp/fichier_tests.2.xz.mgs2");
        let mut writer = FichierWriter::new(path_fichier.as_path(), Some(fp_certs)).await.expect("writer");
        writer.write(BYTES_TEST).await.expect("write");
        let (mh, cipher_keys) = writer.fermer().await.expect("finish");

        assert_ne!(HASH_FICHIER_TEST, mh.as_str());
        debug!("cipher_keys : {:?}", cipher_keys);

        let mut id_docs: HashMap<String, String> = HashMap::new();
        id_docs.insert(String::from("dummy_id"), String::from("dummy_valeur"));
        let commande_cles = cipher_keys
            .expect("cles")
            .get_commande_sauvegarder_cles(mh.as_str(), "dummy", id_docs);

        debug!("Commande cles : {:?}", commande_cles);
    }

    #[tokio::test]
    async fn tar_parse() {
        setup("Test tar_parse");
        let (validateur, _) = charger_enveloppe_privee_env();

        let file: async_std::fs::File = async_std::fs::File::open(PathBuf::from("/tmp/download.tar")).await.expect("open");
        let mut traiter_fichier: DummyTraiterFichier = DummyTraiterFichier{};

        parse_tar(validateur.as_ref(), file, &mut traiter_fichier).await.expect("parse");
    }

    #[tokio::test]
    async fn tar_tar_parse() {
        setup("tar_tar_parse");
        let (validateur, _) = charger_enveloppe_privee_env();

        let file = async_std::fs::File::open(PathBuf::from("/tmp/download_tar.tar")).await.expect("open");
        let mut traiter_fichier = DummyTraiterFichier{};

        parse_tar(validateur.as_ref(), file, &mut traiter_fichier).await.expect("parse");
    }

}
