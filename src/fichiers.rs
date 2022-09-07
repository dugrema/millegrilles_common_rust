use std::error::Error;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use async_std::io::ReadExt;
use async_tar::Archive;
use async_trait::async_trait;
use log::{debug, warn};
use multibase::Base;
use multihash::Code;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use xz2::stream;

use crate::certificats::ValidateurX509;
use crate::chiffrage::{ChiffrageFactory, Chiffreur, CipherMgs, Dechiffreur, MgsCipherKeys};
use crate::chiffrage_chacha20poly1305::{DecipherMgs3, Mgs3CipherData};
use crate::chiffrage_streamxchacha20poly1305::{CipherMgs4, Mgs4CipherKeys};
use crate::constantes::*;
use crate::generateur_messages::GenerateurMessages;
use crate::hachages::Hacheur;
use crate::middleware::ChiffrageFactoryTrait;
use crate::verificateur::VerificateurMessage;

const PRESET_COMPRESSION_XZ: u32 = 6;
const BUFFER_SIZE: usize = 64 * 1024;

pub struct FichierWriter<K, M>
    where M: CipherMgs<K>,
          K: MgsCipherKeys
{
    _path_fichier: PathBuf,
    fichier: Box<tokio::fs::File>,
    xz_encodeur: stream::Stream,
    hacheur: Hacheur,
    chiffreur: Option<M>,
    _keys: PhantomData<K>,
}

impl FichierWriter<Mgs4CipherKeys, CipherMgs4> {

    pub async fn new<C,P>(path_fichier: P, chiffrage_factory: Option<&C>) -> Result<FichierWriter<Mgs4CipherKeys, CipherMgs4>, Box<dyn Error>>
    where
        C: ChiffrageFactory,
        P: Into<PathBuf>
    {
        let path_fichier_buf = path_fichier.into();

        let output_file = tokio::fs::File::create(&path_fichier_buf).await?;
        // let xz_encodeur = XzEncoder::new(output_file, 9);
        // Utilisation preset 6 (<20MB RAM) - avec 9, utilise plus de 40MB de RAM.
        let xz_encodeur = stream::Stream::new_easy_encoder(PRESET_COMPRESSION_XZ, stream::Check::Crc64).expect("stream");
        let hacheur = Hacheur::builder().digester(Code::Blake2b512).base(Base::Base58Btc).build();

        let chiffreur = match chiffrage_factory {
            Some(c) => {
                debug!("Activer chiffrage pour fichier  : {:?}", path_fichier_buf);
                Some(c.get_chiffreur()?)
            },
            None => None,
        };

        Ok(FichierWriter {
            _path_fichier: path_fichier_buf,
            fichier: Box::new(output_file),
            xz_encodeur,
            hacheur,
            chiffreur,
            _keys: PhantomData,
        })
    }

    pub async fn write(&mut self, contenu: &[u8]) -> Result<usize, Box<dyn Error>> {

        let chunks = contenu.chunks(BUFFER_SIZE);
        let mut chunks = tokio_stream::iter(chunks);

        // Preparer vecteur pour recevoir data compresse (avant chiffrage) pour output vers fichier
        let mut buffer_chiffre = [0u8; BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(BUFFER_SIZE);

        let mut count_bytes = 0usize;

        while let Some(chunk) = chunks.next().await {
            let status = self.xz_encodeur.process_vec(chunk, &mut buffer, stream::Action::Run)?;
            if status != stream::Status::Ok {
                Err(format!("Erreur compression transaction, status {:?}", status))?;
            }

            // debug!("Ecriture transaction bytes : {:?}", buffer);

            let buffer_output = match &mut self.chiffreur {
                Some(c) => {
                    let len = c.update(buffer.as_slice(), &mut buffer_chiffre)?;
                    // debug!("Ecriture data chiffre {:?}", &buffer_chiffre[0..len]);
                    &buffer_chiffre[0..len]
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

    pub async fn fermer(mut self) -> Result<(String, Option<Mgs4CipherKeys>), Box<dyn Error>> {
        let mut buffer_chiffre = [0u8; BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(BUFFER_SIZE);

        // Flush xz
        loop {
            let status = self.xz_encodeur.process_vec(&EMPTY_ARRAY, &mut buffer, stream::Action::Finish)?;
            // debug!("Ecriture finale transaction bytes status {:?} : {:?}", status, buffer);

            let buffer_output = match &mut self.chiffreur {
                Some(c) => {
                    let len = c.update(buffer.as_slice(), &mut buffer_chiffre)?;
                    // debug!("Ecriture finale data chiffre {:?}", &buffer_chiffre[0..len]);
                    &buffer_chiffre[0..len]
                },
                None => buffer.as_slice()
            };

            self.hacheur.update(buffer_output);
            self.fichier.write_all(buffer_output).await?;

            debug!("Status ecriture : {:?}", status);

            if status != stream::Status::Ok {
                if status == stream::Status::MemNeeded {
                    Err("Erreur generique de creation fichier .xz")?;
                }
                break
            }
        }

        // Flusher chiffrage (si applicable)
        let cipher_data = match self.chiffreur {
            Some(c) => {
                let (len, cipher_data) = c.finalize(&mut buffer_chiffre)?;
                debug!("Finalization fichier chiffre, taille restante {}", len);
                if len > 0 {
                    // Finaliser output
                    let slice_buffer = &buffer_chiffre[0..len];
                    self.hacheur.update(slice_buffer);
                    self.fichier.write_all(slice_buffer).await?;
                }

                Some(cipher_data)
            },
            None => None
        };

        // Passer dans le hachage et finir l'ecriture du fichier
        let hachage = self.hacheur.finalize();
        self.fichier.flush().await?;

        // let cipher_data = match self.chiffreur {
        //     Some(c) => Some(c.get_cipher_keys()?),
        //     None => None,
        // };

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
        loop {
            let status = self.xz_encodeur.process_vec(&EMPTY_ARRAY, &mut buffer, stream::Action::Finish)?;

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
        let xz_decoder = stream::Stream::new_stream_decoder(u64::MAX, stream::TELL_NO_CHECK)?;
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

            let traiter_bytes = &buffer[0..len];

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

            let traiter_bytes = &buffer[0..len];

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
pub async fn parse_tar<M>(middleware: &M, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut impl TraiterFichier) -> Result<(), Box<dyn Error>>
where M: GenerateurMessages + ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage {
    let reader = Archive::new(stream);

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
pub async fn parse_tar1<M>(middleware: &M, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut impl TraiterFichier) -> Result<(), Box<dyn Error>>
where M: GenerateurMessages + ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage
{
    let reader = Archive::new(stream);

    let mut entries = reader.entries().expect("entries");
    while let Some(entry) = entries.next().await {
        let mut file = entry.expect("file");
        let file_path = file.path().expect("path").into_owned();

        // Process tar or other file type
        match file_path.extension() {
            Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
                "tar" => panic!("Recursion niveau 2 .tar non supporte"),  // parse_tar2(middleware, &mut file, processeur).await?,
                _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
            },
            None => {
                warn!("Fichier de type inconnu, on skip : {:?}", file_path)
            }
        }
    }

    Ok(())
}

// // todo : Fix parse_tar recursion async
// pub async fn parse_tar2<M>(middleware: &M, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut impl TraiterFichier) -> Result<(), Box<dyn Error>>
// where M: ValidateurX509 + Dechiffreur + VerificateurMessage
// {
//     let reader = Archive::new(stream);
//
//     let mut entries = reader.entries().expect("entries");
//     while let Some(entry) = entries.next().await {
//         let mut file = entry.expect("file");
//         let file_path = file.path().expect("path").into_owned();
//
//         // Process tar or other file type
//         match file_path.extension() {
//             Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
//                 "tar" => parse_tar3(middleware, &mut file, processeur).await?,
//                 _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
//             },
//             None => {
//                 warn!("Fichier de type inconnu, on skip : {:?}", file_path)
//             }
//         }
//     }
//
//     Ok(())
// }
//
// // todo : Fix parse_tar recursion async
// pub async fn parse_tar3<M>(middleware: &M, stream: impl futures::io::AsyncRead+Send+Sync+Unpin, processeur: &mut impl TraiterFichier) -> Result<(), Box<dyn Error>>
// where M: ValidateurX509 + Dechiffreur + VerificateurMessage
// {
//     let reader = Archive::new(stream);
//
//     let mut entries = reader.entries().expect("entries");
//     while let Some(entry) = entries.next().await {
//         let mut file = entry.expect("file");
//         let file_path = file.path().expect("path").into_owned();
//
//         // Process tar or other file type
//         match file_path.extension() {
//             Some(e) => match e.to_ascii_lowercase().to_str().expect("str") {
//                 "tar" => panic!("Recursion niveau 3 .tar non supporte"),
//                 _ => processeur.traiter_fichier( middleware, file_path.as_path(), &mut file).await?
//             },
//             None => {
//                 warn!("Fichier de type inconnu, on skip : {:?}", file_path)
//             }
//         }
//     }
//
//     Ok(())
// }

#[async_trait]
pub trait TraiterFichier {
    async fn traiter_fichier<M>(&mut self, middleware: &M, nom_fichier: &async_std::path::Path, stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)) -> Result<(), Box<dyn Error>>
    where M: GenerateurMessages + ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData> + VerificateurMessage;
}

#[cfg(test)]
pub mod fichiers_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use async_std::future::Future;
    use tokio_util::codec::{BytesCodec, FramedRead};

    //use crate::{MiddlewareDbPki, ValidateurX509};
    use crate::certificats::{ValidateurX509, FingerprintCertPublicKey, EnveloppeCertificat};
    use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
    use crate::test_setup::setup;

    use super::*;
    use tokio::fs::File;
    use crate::formatteur_messages::MessageSerialise;
    use crate::middleware_db::MiddlewareDb;

    const HASH_FICHIER_TEST: &str = "z8Vts2By1ww2kJBtEGeitMTrLgKLhYCxV3ZREi66F8g73Jo8U96dKYMrRKKzwGpBR6kFUgmMAZZcYaPVU3NW6TQ8duk";
    const BYTES_TEST: &[u8] = b"des bytes a ecrire";

    struct DummyTraiterFichier{}
    #[async_trait]
    impl TraiterFichier for DummyTraiterFichier {
        async fn traiter_fichier<M>(
            &mut self,
            middleware: &M,
            nom_fichier: &async_std::path::Path,
            stream: &mut (impl futures::io::AsyncRead+Send+Sync+Unpin)
        ) -> Result<(), Box<dyn Error>>
        where M: ValidateurX509 + Dechiffreur<DecipherMgs3, Mgs3CipherData>
        {
            debug!("Traiter fichier {:?}", nom_fichier);

            Ok(())
        }
    }

    pub struct ChiffreurDummy {
        pub public_keys: Vec<FingerprintCertPublicKey>,
    }

    // #[async_trait]
    // impl Chiffreur<CipherMgs2, Mgs2CipherKeys> for ChiffreurDummy {
    //     fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
    //         self.public_keys.clone()
    //     }
    //
    //     async fn charger_certificats_chiffrage(&self, _cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>> {
    //         todo!()
    //     }
    //
    //     async fn recevoir_certificat_chiffrage<'a>(&'a self, message: &MessageSerialise) -> Result<(), Box<dyn Error + 'a>> {
    //         todo!()
    //     }
    // }

    #[tokio::test]
    async fn ecrire_bytes_writer() {
        setup("ecrire_bytes_writer");

        let path_fichier = PathBuf::from("/tmp/fichier_tests.1.xz");
        let mut writer = FichierWriter::new(path_fichier.as_path(), None::<&MiddlewareDb>).await.expect("writer");
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

    // #[tokio::test]
    // async fn ecrire_bytes_chiffres_writer() {
    //     setup("ecrire_bytes_chiffres_writer");
    //
    //     let (validateur, enveloppe) = charger_enveloppe_privee_env();
    //
    //     let fp_certs = vec!(FingerprintCertPublicKey::new(
    //         String::from("dummy"),
    //         enveloppe.certificat().public_key().clone().expect("cle"),
    //         true
    //     ));
    //
    //     let path_fichier = PathBuf::from("/tmp/fichier_tests.2.xz.mgs2");
    //     let chiffreur = ChiffreurDummy {public_keys: fp_certs};
    //     let mut writer = FichierWriter::new(path_fichier.as_path(), Some(&chiffreur)).await.expect("writer");
    //     writer.write(BYTES_TEST).await.expect("write");
    //     let (mh, cipher_keys) = writer.fermer().await.expect("finish");
    //
    //     assert_ne!(HASH_FICHIER_TEST, mh.as_str());
    //     debug!("cipher_keys : {:?}", cipher_keys);
    //
    //     let mut id_docs: HashMap<String, String> = HashMap::new();
    //     id_docs.insert(String::from("dummy_id"), String::from("dummy_valeur"));
    //     let commande_cles = cipher_keys
    //         .expect("cles")
    //         .get_commande_sauvegarder_cles("dummy", None, id_docs);
    //
    //     debug!("Commande cles : {:?}", commande_cles);
    // }

    // #[tokio::test]
    // async fn tar_parse() {
    //     setup("Test tar_parse");
    //     let (validateur, _) = charger_enveloppe_privee_env();
    //
    //     let file: async_std::fs::File = async_std::fs::File::open(PathBuf::from("/tmp/download.tar")).await.expect("open");
    //     let mut traiter_fichier: DummyTraiterFichier = DummyTraiterFichier{};
    //
    //     parse_tar(validateur.as_ref(), file, &mut traiter_fichier).await.expect("parse");
    // }
    //
    // #[tokio::test]
    // async fn tar_tar_parse() {
    //     setup("tar_tar_parse");
    //     let (validateur, _) = charger_enveloppe_privee_env();
    //
    //     let file = async_std::fs::File::open(PathBuf::from("/tmp/download_tar.tar")).await.expect("open");
    //     let mut traiter_fichier = DummyTraiterFichier{};
    //
    //     parse_tar(validateur.as_ref(), file, &mut traiter_fichier).await.expect("parse");
    // }

}
