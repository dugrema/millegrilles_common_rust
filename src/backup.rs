// use std::fs::File;
use std::{io, io::Write};
use std::cmp::min;
use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bson::Document;
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{debug, error, info, warn};
use mongodb::bson::doc;
use mongodb::Cursor;
use mongodb::options::{AggregateOptions, FindOptions, Hint};
use multibase::Base;
use multihash::Code;
use openssl::pkey::{PKey, Private};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio_stream::{Iter, StreamExt};
use uuid::Uuid;
use xz2::stream;

use crate::{CipherMgs2, CollectionCertificatsPem, DateEpochSeconds, DecipherMgs2, Entete, EnveloppeCertificat, FormatChiffrage, Hacheur, Mgs2CipherData, MongoDao, FingerprintCertPublicKey, Mgs2CipherKeys};
use crate::certificats::EnveloppePrivee;
use crate::constantes::*;

const EMPTY_ARRAY: [u8; 0] = [0u8; 0];

pub async fn backup(middleware: &impl MongoDao, nom_collection: &str) -> Result<(), Box<dyn Error>> {

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempfile::tempdir()?;

    let info_backup = BackupInformation::new(
        "domaine_dummy",
        nom_collection,
        None,
        Some(workdir.path().to_owned())
    )?;

    // Generer liste builders domaine/heures
    let builders = grouper_backups(middleware, &info_backup).await?;

    for mut builder in builders {
        // Creer fichier de transactions
        let mut path_fichier_transactions = info_backup.workpath.clone();
        path_fichier_transactions.push(PathBuf::from("transactions.xz"));

        let mut curseur = requete_transactions(middleware, &info_backup, &builder).await?;
        serialiser_transactions(&mut curseur, &mut builder, path_fichier_transactions.as_path()).await?;

        let catalogue_horaire = uploader_backup(builder).await?;

        // Soumettre catalogue horaire sous forme de transaction (domaine Backup)
        todo!("soumettre catalogue horaire");

        // Marquer transactions du backup comme completees
        marquer_transaction_backup_complete(middleware, &catalogue_horaire).await?;
    }

    Ok(())
}

/// Identifie les sousdomaines/heures a inclure dans le backup.
async fn grouper_backups(middleware: &impl MongoDao, backup_information: &BackupInformation) -> Result<Vec<CatalogueHoraireBuilder>, Box<dyn Error>> {

    let nom_collection = &backup_information.nom_collection_transactions;

    let collection = middleware.get_collection(nom_collection)?;
    let pipeline = vec! [
        doc! {"$match": {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true},
            TRANSACTION_CHAMP_BACKUP_FLAG: false,
            TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        }},

        // Grouper par domaines et heure
        doc! {"$group": {
            "_id": {
                "domaine": "$en-tete.domaine",
                "sousdomaine": {"$slice": [
                    {"$split": ["$en-tete.domaine", "."]},
                    {"$add": [{"$size": {"$split": ["$en-tete.domaine", "."]}}, -1]}
                ]},
                "heure": {
                    "year": {"$year": "$_evenements.transaction_traitee"},
                    "month": {"$month": "$_evenements.transaction_traitee"},
                    "day": {"$dayOfMonth": "$_evenements.transaction_traitee"},
                    "hour": {"$hour": "$_evenements.transaction_traitee"},
                }
            },
            "sousdomaine": {
                "$addToSet": {
                    "$slice": [
                        {"$split": ["$en-tete.domaine", "."]},
                        {"$add": [{"$size": {"$split": ["$en-tete.domaine", "."]}}, -1]}
                    ]
                }
            },
        }},

        // Trier par heure
        doc! {"$sort": {"_id.heure": 1}},
    ];

    let mut options = AggregateOptions::builder()
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let mut curseur = collection.aggregate(pipeline, options).await?;

    let mut builders = Vec::new();

    while let Some(entree) = curseur.next().await {
        println!("Entree aggregation : {:?}", entree);
        let tmp_id = entree?;
        let info_id = tmp_id.get("_id").expect("id").as_document().expect("doc id");

        let sousdomaine = info_id.get("sousdomaine").expect("domaine").as_array().expect("array");
        let sousdomaines_str = sousdomaine.iter().map(|d| d.as_str().expect("str"));
        let mut sousdomaine_vec = Vec::new();
        for s in sousdomaines_str {
            sousdomaine_vec.push(s)
        }
        let sousdomaine_str = sousdomaine_vec.as_slice().join(".");
        println!("Resultat : {:?}", sousdomaine_str);

        let doc_heure = info_id.get("heure").expect("heure").as_document().expect("doc heure");
        let annee = doc_heure.get("year").expect("year").as_i32().expect("i32");
        let mois = doc_heure.get("month").expect("month").as_i32().expect("i32") as u32;
        let jour = doc_heure.get("day").expect("day").as_i32().expect("i32") as u32;
        let heure = doc_heure.get("hour").expect("hour").as_i32().expect("i32") as u32;

        let date = DateEpochSeconds::from_heure(annee, mois, jour, heure);

        let builder = CatalogueHoraireBuilder::new(date, sousdomaine_str.to_owned(), backup_information.uuid_backup.clone());
        builders.push(builder);
    }

    Ok(builders)
}

async fn requete_transactions(middleware: &impl MongoDao, info: &BackupInformation, builder: &CatalogueHoraireBuilder) -> Result<Cursor, Box<dyn Error>> {
    let nom_collection = &info.nom_collection_transactions;
    let collection = middleware.get_collection(nom_collection)?;

    let debut_heure = builder.heure.get_datetime();
    let fin_heure = debut_heure.clone() + chrono::Duration::hours(1);

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$gte": debut_heure, "$lt": &fin_heure},
    };

    let sort = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
    let find_options = FindOptions::builder()
        .sort(sort)
        .hint(Hint::Name(String::from("backup_transactions")))
        .build();

    let curseur = collection.find(filtre, find_options).await?;

    Ok(curseur)
}

async fn serialiser_transactions(
    curseur: &mut Cursor,
    builder: &mut CatalogueHoraireBuilder,
    path_transactions: &Path
) -> Result<(String, Option<Mgs2CipherKeys>), Box<dyn Error>> {

    // Creer i/o stream lzma pour les transactions (avec chiffrage au besoin)
    let mut transaction_writer = TransactionWriter::new(path_transactions, None).await?;

    // Obtenir curseur sur transactions en ordre chronologique de flag complete
    while let Some(Ok(d)) = curseur.next().await {
        let entete = d.get("en-tete").expect("en-tete").as_document().expect("document");
        let uuid_transaction = entete.get("uuid_transaction").expect("uuid-transaction").to_string();

        // Serialiser transaction
        transaction_writer.write_bson_line(&d).await?;

        // Ajouter uuid_transaction dans info
        builder.ajouter_transaction(uuid_transaction);
    }

    transaction_writer.fermer().await
}

async fn uploader_backup(builder: CatalogueHoraireBuilder) -> Result<CatalogueHoraire, Box<dyn Error>> {
    let catalogue = builder.build();

    // Conserver hachage transactions dans info

    // Build et serialiser catalogue + transaction maitre des cles

    // Uploader backup

    todo!();
    Ok(catalogue)
}

async fn marquer_transaction_backup_complete(middleware: &dyn MongoDao, catalogue_horaire: &CatalogueHoraire) -> Result<(), Box<dyn Error>> {
    todo!()
}

trait BackupHandler {
    fn run() -> Result<(), String>;
}

/// Struct de backup
#[derive(Debug)]
struct BackupInformation {
    /// Nom du domaine
    nom_domaine: String,
    /// Nom complet de la collection de transactions mongodb
    nom_collection_transactions: String,
    /// Options de chiffrage
    chiffrage: Option<FormatChiffrage>,
    /// Path de travail pour conserver les fichiers temporaires de chiffrage
    workpath: PathBuf,
    /// Identificateur unique du backup (collateur)
    uuid_backup: String,
    /// Repertoire temporaire qui est supprime automatiquement apres le backup.
    tmp_workdir: Option<TempDir>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogueHoraire {
    /// Heure du backup (minutes = 0, secs = 0)
    heure: DateEpochSeconds,
    /// Nom du domaine ou sous-domaine
    domaine: String,
    /// Identificateur unique du groupe de backup (collateur)
    uuid_backup: String,

    /// Collection des certificats presents dans les transactions du backup
    certificats: CollectionCertificatsPem,

    pub catalogue_nomfichier: String,
    pub transactions_nomfichier: String,
    pub transactions_hachage: String,
    pub uuid_transactions: Vec<String>,

    // #[serde(rename = "en-tete")]
    // entete: Entete,

    /// Enchainement backup precedent
    backup_precedent: Option<String>,  // todo mettre bon type

    /// Cle chiffree avec la cle de MilleGrille (si backup chiffre)
    cle: Option<String>,

    /// IV du contenu chiffre
    iv: Option<String>,

    /// Compute tag du contenu chiffre
    tag: Option<String>,

    /// Format du chiffrage
    format: Option<String>,
}

#[derive(Clone, Debug)]
struct CatalogueHoraireBuilder {
    heure: DateEpochSeconds,
    nom_domaine: String,
    uuid_backup: String,

    certificats: CollectionCertificatsPem,
    uuid_transactions: Vec<String>,
    transactions_hachage: String,
}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new(
        nom_domaine: &str,
        nom_collection_transactions: &str,
        chiffrage: Option<FormatChiffrage>,
        workpath: Option<PathBuf>
    ) -> Result<BackupInformation, Box<dyn Error>> {

        let (workpath_inner, tmp_workdir): (PathBuf, Option<TempDir>) = match workpath {
            Some(wp) => (wp, None),
            None => {
                let tmp_workdir = tempdir()?;
                let path_tmp = tmp_workdir.path().to_owned();

                (path_tmp, Some(tmp_workdir))
            },
        };

        let uuid_backup = Uuid::new_v4().to_string();

        Ok(BackupInformation {
            nom_domaine: nom_domaine.to_owned(),
            nom_collection_transactions: nom_collection_transactions.to_owned(),
            chiffrage,
            workpath: workpath_inner,
            uuid_backup,
            tmp_workdir,
        })
    }

}

impl BackupHandler for BackupInformation {
    fn run() -> Result<(), String> {
        info!("Demarrage backup");
        Ok(())
    }
}

impl CatalogueHoraire {
    fn builder(heure: DateEpochSeconds, nom_domaine: String, uuid_backup: String) -> CatalogueHoraireBuilder {
        CatalogueHoraireBuilder::new(heure, nom_domaine, uuid_backup)
    }
}

impl CatalogueHoraireBuilder {

    fn new(heure: DateEpochSeconds, nom_domaine: String, uuid_backup: String) -> Self {
        CatalogueHoraireBuilder {
            heure, nom_domaine, uuid_backup,
            certificats: CollectionCertificatsPem::new(),
            uuid_transactions: Vec::new(),
            transactions_hachage: "".to_owned(),
        }
    }

    fn ajouter_certificat(&mut self, certificat: EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat).expect("certificat");
    }

    fn ajouter_transaction(&mut self, uuid_transaction: String) {
        self.uuid_transactions.push(uuid_transaction);
    }

    fn transactions_hachage(&mut self, hachage: String) {
        self.transactions_hachage = hachage;
    }

    fn build(self) -> CatalogueHoraire {

        let date_str = self.heure.format_ymdh();

        // Build collections de certificats
        let transactions_hachage = self.transactions_hachage;
        let transactions_nomfichier = format!("{}_{}.jsonl.xz", &self.nom_domaine, date_str);
        let catalogue_nomfichier = format!("{}_{}.json.xz", &self.nom_domaine, date_str);

        CatalogueHoraire {
            heure: self.heure,
            domaine: self.nom_domaine,
            uuid_backup: self.uuid_backup,
            catalogue_nomfichier,

            certificats: self.certificats,

            transactions_hachage,
            transactions_nomfichier,
            uuid_transactions: self.uuid_transactions,

            backup_precedent: None,  // todo mettre bon type
            cle: None,
            iv: None,

            tag: None,
            format: None,
        }
    }

}

struct TransactionWriter<'a> {
    path_fichier: &'a Path,
    fichier: Box<tokio::fs::File>,
    xz_encodeur: stream::Stream,
    hacheur: Hacheur,
    chiffreur: Option<CipherMgs2>,
}

impl<'a> TransactionWriter<'a> {

    const BUFFER_SIZE: usize = 64 * 1024;

    pub async fn new(path_fichier: &'a Path, certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>) -> Result<TransactionWriter<'a>, Box<dyn Error>> {
        let output_file = tokio::fs::File::create(path_fichier).await?;
        // let xz_encodeur = XzEncoder::new(output_file, 9);
        let xz_encodeur = stream::Stream::new_easy_encoder(9, stream::Check::Crc64).expect("stream");
        let hacheur = Hacheur::builder().digester(Code::Sha2_512).base(Base::Base64).build();

        let chiffreur = match certificats_chiffrage {
            Some(c) => {
                Some(CipherMgs2::new(&c))
            },
            None => None,
        };

        Ok(TransactionWriter {
            path_fichier,
            fichier: Box::new(output_file),
            xz_encodeur,
            hacheur,
            chiffreur,
        })
    }

    pub async fn write_bytes(&mut self, contenu: &[u8]) -> Result<usize, Box<dyn Error>> {

        let chunks = contenu.chunks(TransactionWriter::BUFFER_SIZE);
        let mut chunks = tokio_stream::iter(chunks);

        // Preparer vecteur pour recevoir data compresse (avant chiffrage) pour output vers fichier
        let mut buffer_chiffre = [0u8; TransactionWriter::BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(TransactionWriter::BUFFER_SIZE);

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
            let file_bytes = self.fichier.write(buffer_output).await?;
            count_bytes += file_bytes;
        }

        Ok(count_bytes)
    }

    /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
    pub async fn write_json_line(&mut self, contenu: &Value) -> Result<usize, Box<dyn Error>> {
        // Convertir value en bytes
        let mut contenu_bytes = serde_json::to_string(contenu)?.as_bytes().to_owned();

        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);

        // Write dans le fichier
        self.write_bytes(contenu_bytes.as_slice()).await
    }

    pub async fn write_bson_line(&mut self, contenu: &Document) -> Result<usize, Box<dyn Error>> {
        let mut value = serde_json::to_value(contenu)?;

        // S'assurer qu'on a un document (map)
        // Retirer le champ _id si present
        match value.as_object_mut() {
            Some(mut doc) => {
                doc.remove("_id");
                self.write_json_line(&value).await
            },
            None => {
                warn!("Valeur bson fournie en backup n'est pas un _Document_, on l'ignore : {:?}", contenu);
                Ok((0))
            }
        }
    }

    pub async fn fermer(mut self) -> Result<(String, Option<Mgs2CipherKeys>), Box<dyn Error>> {
        let mut buffer_chiffre = [0u8; TransactionWriter::BUFFER_SIZE];
        let mut buffer : Vec<u8> = Vec::new();
        buffer.reserve(TransactionWriter::BUFFER_SIZE);

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
            self.fichier.write(buffer_output).await?;

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
                    self.fichier.write(slice_buffer).await?;
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

    // fn get_cipher_data(&self) -> Result<Mgs2CipherData, String> {
    //     match &self.chiffreur {
    //         Some(c) => Ok(c.get_cipher_data()?),
    //         None => Err(String::from("Chiffrage n'est pas active")),
    //     }
    // }
}

struct TransactionReader<'a> {
    data: Box<dyn AsyncRead + Unpin + 'a>,
    xz_decoder: stream::Stream,
    // hacheur: Hacheur,
    dechiffreur: Option<DecipherMgs2>,
}

impl<'a> TransactionReader<'a> {

    pub fn new(data: Box<impl AsyncRead + Unpin + 'a>, decipher_data: Option<&Mgs2CipherData>) -> Result<Self, Box<dyn Error>> {

        let mut xz_decoder = stream::Stream::new_stream_decoder(u64::MAX, stream::TELL_NO_CHECK).expect("stream");

        let dechiffreur = match decipher_data {
            Some(cd) => {
                let mut dechiffreur = DecipherMgs2::new(cd)?;
                Some(dechiffreur)
            },
            None => None,
        };

        Ok(TransactionReader {
            data,
            xz_decoder,
            // hacheur,
            dechiffreur,
        })
    }

    /// todo Les transactions sont lues en memoire avant d'etre traitees - changer pour iterator async
    pub async fn read_transactions(&mut self) -> Result<Vec<Value>, Box<dyn Error>> {
        let mut buffer = [0u8; TransactionWriter::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(TransactionWriter::BUFFER_SIZE);

        let mut dechiffrage_output = [0u8; TransactionWriter::BUFFER_SIZE];

        let mut output_complet = Vec::new();

        loop {
            let mut reader = &mut self.data;
            let len = reader.read(&mut buffer).await.expect("lecture");
            if len == 0 {break}

            // let traiter_bytes = &buffer[..len];

            let traiter_bytes = match &mut self.dechiffreur {
                Some(d) => {
                    d.update(&buffer[..len], &mut dechiffrage_output);
                    &dechiffrage_output[..len]
                },
                None => &buffer[..len],
            };

            // println!("Lu {}\n{:?}", len, traiter_bytes);
            let status = self.xz_decoder.process_vec(traiter_bytes, &mut xz_output, stream::Action::Run).expect("xz-output");
            // println!("Status xz : {:?}\n{:?}", status, xz_output);

            output_complet.append(&mut xz_output);
        }

        loop {
            let traiter_bytes = [0u8;0];

            let status = self.xz_decoder.process_vec(&traiter_bytes[0..0], &mut xz_output, stream::Action::Run).expect("xz-output");
            output_complet.append(&mut xz_output);
            if status != stream::Status::Ok {
                if status != stream::Status::StreamEnd {
                    Err("Erreur decompression xz")?;
                }
                break
            }
        }

        // Verifier si a on a un newline dans le buffer pour separer les transactions
        // println!("Output complet : {:?}", output_complet);

        let index_nl = output_complet.as_slice().split(|n| n == &NEW_LINE_BYTE);

        let mapper = index_nl.map(|t| {
            match String::from_utf8(t.to_vec()) {
                Ok(ts) => {
                    match serde_json::from_str::<Value>(ts.as_str()) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(format!("Erreur {:?}", e)),
                    }
                },
                Err(e) => Err(format!("Erreur {:?}", e)),
            }
        });

        let mut transactions = Vec::new();
        for t in mapper {
            match t {
                Ok(tt) => transactions.push(tt),
                Err(e) => error!("Erreur lecture : {:?}", e)
            }
        }

        Ok(transactions)
    }

}

#[cfg(test)]
mod backup_tests {
    use serde_json::json;

    use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};

    use super::*;

    const NOM_DOMAINE_BACKUP: &str = "Domaine.test";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    #[test]
    fn init_backup_information() {
        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP,
            NOM_COLLECTION_BACKUP,
            None,
            None
        ).expect("init");

        let workpath = info.workpath.to_str().unwrap();

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        assert_eq!(info.chiffrage.is_none(), true);
        assert_eq!(workpath.starts_with("/tmp/."), true);
    }

    #[test]
    fn init_backup_horaire_builder() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup);

        assert_eq!(catalogue_builder.heure.get_datetime().timestamp(), heure.get_datetime().timestamp());
        assert_eq!(&catalogue_builder.nom_domaine, NOM_DOMAINE_BACKUP);
    }

    #[test]
    fn build_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        assert_eq!(catalogue.heure, heure);
        assert_eq!(&catalogue.uuid_backup, uuid_backup);
        assert_eq!(&catalogue.catalogue_nomfichier, "Domaine.test_2021080105.json.xz");
        assert_eq!(&catalogue.transactions_nomfichier, "Domaine.test_2021080105.jsonl.xz");
    }

    #[test]
    fn build_catalogue_params() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let transactions_hachage = "zABCD1234";

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        catalogue_builder.transactions_hachage(transactions_hachage.to_owned());

        let catalogue = catalogue_builder.build();

        assert_eq!(&catalogue.transactions_hachage, transactions_hachage);
    }

    #[test]
    fn serialiser_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");

        // println!("Valeur catalogue : {:?}", value);
    }

    #[test]
    fn catalogue_to_json() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");
        let catalogue_str = serde_json::to_string(&value).expect("json");
        // println!("Json catalogue : {:?}", catalogue_str);

        assert_eq!(catalogue_str.find("1627794000"), Some(9));
        assert_eq!(catalogue_str.find(NOM_DOMAINE_BACKUP), Some(31));
        assert_eq!(catalogue_str.find(uuid_backup), Some(60));
    }

    #[test]
    fn build_catalogue_1certificat() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let mut catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let certificat = prep_enveloppe(CERT_DOMAINES);
        // println!("!!! Enveloppe : {:?}", certificat);

        catalogue_builder.ajouter_certificat(certificat);

        let catalogue = catalogue_builder.build();
        // println!("!!! Catalogue : {:?}", catalogue);
        assert_eq!(catalogue.certificats.len(), 1);
    }

    #[tokio::test]
    async fn ecrire_bytes_writer() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer.txt.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), None).await.expect("writer");

        writer.write_bytes("Du contenu a ecrire".as_bytes()).await.expect("write");

        let file = writer.fermer().await.expect("fermer");
        // println!("File du writer : {:?}", file);
    }

    #[tokio::test]
    async fn roundtrip_json() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions.jsonl.xz");

        let mut writer = TransactionWriter::new(path_fichier.as_path(), None).await.expect("writer");
        let doc_json = json!({
            "contenu": "Du contenu a encoder",
            "valeur": 1234,
            // "date": Utc.timestamp(1629464027, 0),
        });
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");
        writer.write_json_line(&doc_json).await.expect("write");

        let file = writer.fermer().await.expect("fermer");
        // println!("File du writer : {:?}", file);

        let fichier_cs = Box::new(tokio::fs::File::open(path_fichier.as_path()).await.expect("open read"));
        let mut reader = TransactionReader::new(fichier_cs, None).expect("reader");
        let transactions = reader.read_transactions().await.expect("transactions");
        for t in transactions {
            // println!("Transaction : {:?}", t);
            assert_eq!(&doc_json, &t);
        }

    }

    fn get_doc_reference() -> (String, Document) {
        let doc_bson = doc! {
            "_id": "Un ID dummy qui doit etre retire",
            "contenu": "Du contenu BSON (Document) a encoder",
            "valeur": 5678,
            "date": Utc.timestamp(1629464026, 0),
        };

        (String::from("mE0AISSkaUPMWlq3Zfka8+OHsgO3rTXLdzxFPI9hXRC3G3gnloGR6Ai4xapbdXCY+psL3RinjZQsUnYNrxCENkTXn"), doc_bson)
    }

    #[tokio::test]
    async fn ecrire_transactions_writer_bson() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), None).await.expect("writer");

        let (mh_reference, doc_bson) = get_doc_reference();
        writer.write_bson_line(&doc_bson).await.expect("write");

        let (mh, decipher_data) = writer.fermer().await.expect("fermer");
        // println!("File du writer : {:?}, multihash: {}", file, mh);

        assert_eq!(mh.as_str(), &mh_reference);
    }

    #[tokio::test]
    async fn chiffrer_roundtrip_backup() {
        let (validateur, enveloppe) = charger_enveloppe_privee_env();

        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz.mgs2");
        let fp_certs = vec!(FingerprintCertPublicKey::new(
            String::from("dummy"),
            enveloppe.certificat().public_key().clone().expect("cle")
        ));

        let mut writer = TransactionWriter::new(
            path_fichier.as_path(),
            Some(fp_certs)
        ).await.expect("writer");

        let (mh_reference, doc_bson) = get_doc_reference();
        writer.write_bson_line(&doc_bson).await.expect("write chiffre");
        let (mh, mut decipher_data_option) = writer.fermer().await.expect("fermer");

        let decipher_keys = decipher_data_option.expect("decipher data");
        let mut decipher_key = decipher_keys.get_cipher_data("dummy").expect("cle");

        // Verifier que le hachage n'est pas egal au hachage de la version non chiffree
        assert_ne!(mh.as_str(), &mh_reference);

        decipher_key.dechiffrer_cle(enveloppe.cle_privee()).expect("dechiffrer");

        let fichier_cs = Box::new(tokio::fs::File::open(path_fichier.as_path()).await.expect("open read"));
        let mut reader = TransactionReader::new(fichier_cs, Some(&decipher_key)).expect("reader");
        let transactions = reader.read_transactions().await.expect("transactions");

        for t in transactions {
            // println!("Transaction dechiffree : {:?}", t);
            let valeur_chiffre = t.get("valeur").expect("valeur").as_i64().expect("val");
            assert_eq!(valeur_chiffre, 5678);
        }

    }
}

#[cfg(test)]
mod test_integration {
    use std::sync::Arc;

    use crate::{charger_transaction, MiddlewareDbPki};
    use crate::middleware::preparer_middleware_pki;
    use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};

    use super::*;

    #[tokio::test]
    async fn grouper_transactions() {
        // Connecter mongo
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(tokio::spawn(async move {

            // Test
            let info = BackupInformation::new("Pki", "Pki.rust", None, None).expect("info");

            let workdir = tempfile::tempdir().expect("tmpdir");
            let groupes = grouper_backups(
                middleware.as_ref(),
                &info
            ).await.expect("groupes");

            println!("Groupes : {:?}", groupes);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn serialiser_transactions_compressees() {

        // let workdir = tempfile::tempdir().expect("tmpdir");
        let workdir = PathBuf::from("/tmp");

        // Connecter mongo
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(tokio::spawn(async move {

            // Test
            let info = BackupInformation::new("Pki", "Pki.rust", None, None).expect("info");
            let heure = DateEpochSeconds::from_heure(2021, 08, 20, 12);
            let mut builder = CatalogueHoraire::builder(heure, "Pki".into(), "Pki.rust".into());

            let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");

            let mut path_transactions = workdir.clone();
            path_transactions.push("extraire_transactions.jsonl.xz");
            println!("Sauvegarde transactions sous : {:?}", path_transactions);
            let resultat = serialiser_transactions(
                &mut transactions,
                &mut builder,
                path_transactions.as_path()
            ).await.expect("serialiser");

            println!("Resultat extraction transactions : {:?}", resultat);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn serialiser_transactions_chiffrage() {

        // let workdir = tempfile::tempdir().expect("tmpdir");
        let workdir = PathBuf::from("/tmp");
        let (validateur, enveloppe) = charger_enveloppe_privee_env();

        // Connecter mongo
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(tokio::spawn(async move {

            // Test
            let info = BackupInformation::new(
                "Pki",
                "Pki.rust",
                None,
                None
            ).expect("info");
            let heure = DateEpochSeconds::from_heure(2021, 08, 20, 12);
            let mut builder = CatalogueHoraire::builder(heure, "Pki".into(), "Pki.rust".into());

            let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");

            let mut path_transactions = workdir.clone();
            path_transactions.push("extraire_transactions.jsonl.xz.mgs2");
            println!("Sauvegarde transactions sous : {:?}", path_transactions);
            let resultat = serialiser_transactions(
                &mut transactions,
                &mut builder,
                path_transactions.as_path()
            ).await.expect("serialiser");

            println!("Resultat extraction transactions : {:?}", resultat);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }
}
