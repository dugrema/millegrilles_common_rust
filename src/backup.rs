use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::{io, io::Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use log::{debug, error, info, warn};
use mongodb::bson::doc;
use mongodb::Cursor;
use mongodb::options::FindOptions;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio_stream::StreamExt;
use uuid::Uuid;
use xz2::write::XzEncoder;

use crate::{CollectionCertificatsPem, DateEpochSeconds, Entete, EnveloppeCertificat, FormatChiffrage, MongoDao};
use crate::certificats::EnveloppePrivee;
use crate::constantes::*;
use bson::Document;

pub async fn backup(middleware: &impl MongoDao, nom_collection: &str) -> Result<(), Box<dyn Error>> {

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempfile::tempdir()?;

    let info_backup = BackupInformation::new(
        "domaine_dummy".to_owned(),
        nom_collection.to_owned(),
        None,
        Some(workdir.path().to_owned())
    )?;

    // Generer liste builders domaine/heures
    let builders = grouper_backups(middleware, nom_collection, &workdir)?;

    for builder in builders {
        // Creer fichier de transactions
        let mut path_fichier_transactions = info_backup.workpath.clone();
        path_fichier_transactions.push(PathBuf::from("transactions.xz"));

        let mut curseur = requete_transactions(middleware, nom_collection, &builder).await?;
        serialiser_transactions(&mut curseur, &builder, path_fichier_transactions.as_path()).await?;

        let catalogue_horaire = uploader_backup(builder).await?;

        // Soumettre catalogue horaire sous forme de transaction (domaine Backup)
        todo!("soumettre catalogue horaire");

        // Marquer transactions du backup comme completees
        marquer_transaction_backup_complete(middleware, &catalogue_horaire).await?;
    }

    Ok(())
}

fn grouper_backups(middleware: &impl MongoDao, nom_collection: &str, workdir: &TempDir) -> Result<Vec<CatalogueHoraireBuilder>, Box<dyn Error>> {

    let collection = middleware.get_collection(nom_collection)?;
    let pipeline = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
    };

    // let curseur = collection.aggregate(pipeline, None)?;

    let builders = Vec::new();

    todo!("Separer sous-domaines");

    Ok(builders)
}

async fn requete_transactions(middleware: &impl MongoDao, nom_collection: &str, builder: &CatalogueHoraireBuilder) -> Result<Cursor, Box<dyn Error>> {
    let collection = middleware.get_collection(nom_collection)?;

    let debut_heure = builder.heure.get_datetime();
    let fin_heure = debut_heure.clone() + chrono::Duration::hours(1);

    todo!("Separer sous-domaines");

    let filtre = doc! {
        TRANSACTION_CHAMP_BACKUP_FLAG: false,
        TRANSACTION_CHAMP_EVENEMENT_COMPLETE: true,
        TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$gte": debut_heure, "$lt": &fin_heure},
    };

    let sort = doc! {TRANSACTION_CHAMP_EVENEMENT_PERSISTE: 1};
    let find_options = FindOptions::builder().sort(sort).build();

    let curseur = collection.find(filtre, find_options).await?;

    Ok(curseur)
}

async fn serialiser_transactions(curseur: &mut Cursor, builder: &CatalogueHoraireBuilder, path_transactions: &Path) -> Result<(), Box<dyn Error>> {
    // Creer i/o stream lzma pour les transactions (avec chiffrage au besoin)
    let mut transaction_writer = TransactionWriter::new(path_transactions, false)?;

    // Obtenir curseur sur transactions en ordre chronologique de flag complete
    while let Some(Ok(d)) = curseur.next().await {
        // Serialiser transaction

        // Ajouter uuid_transaction dans info
    }

    Ok(())
}

async fn serialiser_transaction(document: Document, builder: &CatalogueHoraireBuilder) {

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
        nom_domaine: String,
        nom_collection_transactions: String,
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
            nom_domaine,
            nom_collection_transactions,
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
    xz_encodeur: XzEncoder<File>,
    // chiffreur: Option<...>,
}

impl TransactionWriter<'_> {

    pub fn new(path_fichier: &Path, chiffrer: bool) -> Result<TransactionWriter, Box<dyn Error>> {
        let output_file = File::create(path_fichier)?;
        let xz_encodeur = XzEncoder::new(output_file, 9);

        Ok(TransactionWriter {
            path_fichier,
            xz_encodeur,
        })
    }

    pub fn write_bytes(&mut self, contenu: &[u8]) -> io::Result<usize> {
        self.xz_encodeur.write(contenu)

        // Ajouter au hachage du fichier
    }

    /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
    pub fn write_json_line(&mut self, contenu: &Value) -> io::Result<usize> {
        // Convertir value en bytes
        let mut contenu_bytes = serde_json::to_string(contenu)?.as_bytes().to_owned();

        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);

        // Write dans le fichier
        self.write_bytes(contenu_bytes.as_slice())
    }

    pub fn write_bson_line(&mut self, contenu: &Document) -> io::Result<usize> {
        let mut value = serde_json::to_value(contenu)?;

        // S'assurer qu'on a un document (map)
        // Retirer le champ _id si present
        match value.as_object_mut() {
            Some(mut doc) => {
                doc.remove("_id");
                self.write_json_line(&value)
            },
            None => {
                warn!("Valeur bson fournie en backup n'est pas un _Document_, on l'ignore : {:?}", contenu);
                Ok((0))
            }
        }
    }

    pub fn fermer(mut self) -> io::Result<File> {
        // Completer chiffrage au besoin

        // Fermer XZ encodeur et retourner le fichier
        self.xz_encodeur.finish()
    }
}

#[cfg(test)]
mod backup_tests {
    use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, prep_enveloppe};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use serde_json::json;

    const NOM_DOMAINE_BACKUP: &str = "Domaine.test";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    #[test]
    fn init_backup_information() {
        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP.to_owned(),
            NOM_COLLECTION_BACKUP.to_owned(),
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

    #[test]
    fn ecrire_bytes_writer() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer.txt.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), false).expect("writer");

        writer.write_bytes("Du contenu a ecrire".as_bytes()).expect("write");

        let file = writer.fermer().expect("fermer");
        println!("File du writer : {:?}", file);
    }

    #[test]
    fn ecrire_transactions_writer_json() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions.jsonl.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), false).expect("writer");

        let doc_json = json!({
            "contenu": "Du contenu a encoder",
            "valeur": 1234,
        });
        writer.write_json_line(&doc_json).expect("write");

        let file = writer.fermer().expect("fermer");
        println!("File du writer : {:?}", file);
    }

    #[test]
    fn ecrire_transactions_writer_bson() {
        let path_fichier = PathBuf::from("/tmp/fichier_writer_transactions_bson.jsonl.xz");
        let mut writer = TransactionWriter::new(path_fichier.as_path(), false).expect("writer");

        let doc_bson = doc! {
            "_id": "Un ID dummy qui doit etre retire",
            "contenu": "Du contenu BSON (Document) a encoder",
            "valeur": 5678,
            "date": Utc::now(),
        };
        writer.write_bson_line(&doc_bson).expect("write");

        let file = writer.fermer().expect("fermer");
        println!("File du writer : {:?}", file);
    }
}
