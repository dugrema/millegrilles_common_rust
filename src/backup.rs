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

use crate::{CipherMgs2, CollectionCertificatsPem, DateEpochSeconds, DecipherMgs2, Entete, EnveloppeCertificat, FingerprintCertPublicKey, FormatChiffrage, Hacheur, Mgs2CipherData, Mgs2CipherKeys, MongoDao, FingerprintCleChiffree, CommandeSauvegarderCle, ValidateurX509, FichierWriter};
use crate::certificats::EnveloppePrivee;
use crate::constantes::*;
use std::iter::Map;

/// Lance un backup complet de la collection en parametre.
pub async fn backup(middleware: &(impl MongoDao + ValidateurX509), nom_collection: &str) -> Result<(), Box<dyn Error>> {

    // Creer repertoire temporaire de travail pour le backup
    let workdir = tempfile::tempdir()?;

    let info_backup = BackupInformation::new(
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
        let cipher_keys = serialiser_transactions(middleware, &mut curseur, &mut builder, path_fichier_transactions.as_path(), None).await?;

        let transaction_maitredescles = match cipher_keys {
            Some(k) => {
                let mut identificateurs_document = HashMap::new();
                identificateurs_document.insert(String::from("domaine"), builder.nom_domaine.clone());
                identificateurs_document.insert(String::from("heure"), String::from("...heure..."));

                let commande = k.get_commande_sauvegarder_cles(
                    builder.transactions_hachage.as_str(),
                    "Backup",
                    identificateurs_document
                );
                Some(commande)
            },
            None => None,
        };

        // Generer catalogue
        let catalogue_horaire = builder.build();

        let catalogue_horaire = uploader_backup(catalogue_horaire, transaction_maitredescles).await?;

        // Soumettre catalogue horaire sous forme de transaction (domaine Backup)
        todo!("soumettre catalogue horaire");

        // Marquer transactions du backup comme completees
        marquer_transaction_backup_complete(
            middleware,
            info_backup.nom_collection_transactions.as_str(),
            &catalogue_horaire
        ).await?;
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
        // println!("Entree aggregation : {:?}", entree);
        let tmp_id = entree?;
        let info_id = tmp_id.get("_id").expect("id").as_document().expect("doc id");

        let sousdomaine = info_id.get("sousdomaine").expect("domaine").as_array().expect("array");
        let sousdomaines_str = sousdomaine.iter().map(|d| d.as_str().expect("str"));
        let mut sousdomaine_vec = Vec::new();
        for s in sousdomaines_str {
            sousdomaine_vec.push(s)
        }
        let sousdomaine_str = sousdomaine_vec.as_slice().join(".");
        // println!("Resultat : {:?}", sousdomaine_str);

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
    middleware: &(impl ValidateurX509),
    curseur: &mut Cursor,
    builder: &mut CatalogueHoraireBuilder,
    path_transactions: &Path,
    certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>
) -> Result<Option<Mgs2CipherKeys>, Box<dyn Error>> {

    // Creer i/o stream lzma pour les transactions (avec chiffrage au besoin)
    let mut transaction_writer = TransactionWriter::new(
        path_transactions,
        certificats_chiffrage
    ).await?;

    // Obtenir curseur sur transactions en ordre chronologique de flag complete
    while let Some(Ok(d)) = curseur.next().await {
        let entete = d.get("en-tete").expect("en-tete").as_document().expect("document");
        let uuid_transaction = entete.get(TRANSACTION_CHAMP_UUID_TRANSACTION).expect("uuid-transaction").as_str().expect("str");
        let fingerprint_certificat = entete.get(TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT).expect("fingerprint certificat").as_str().expect("str");

        // Trouver certificat et ajouter au catalogue
        match middleware.get_certificat(fingerprint_certificat).await {
            Some(c) => {
                // println!("OK Certificat ajoute : {}", fingerprint_certificat);
                builder.ajouter_certificat(c.as_ref())
            },
            None => {
                // println!("Warn certificat {} inconnu", fingerprint_certificat)
            },
        }

        // Serialiser transaction
        transaction_writer.write_bson_line(&d).await?;

        // Ajouter uuid_transaction dans catalogue
        builder.ajouter_transaction(uuid_transaction);
    }

    let (hachage, cipher_keys) = transaction_writer.fermer().await?;

    builder.transactions_hachage = hachage;

    Ok(cipher_keys)
}

async fn uploader_backup(catalogue: CatalogueHoraire, commande_cles: Option<CommandeSauvegarderCle>) -> Result<CatalogueHoraire, Box<dyn Error>> {
    // Conserver hachage transactions dans info

    // Build et serialiser catalogue + transaction maitre des cles

    // Uploader backup

    todo!();
    Ok(catalogue)
}

async fn marquer_transaction_backup_complete(middleware: &dyn MongoDao, nom_collection: &str, catalogue_horaire: &CatalogueHoraire) -> Result<(), Box<dyn Error>> {
    let collection = middleware.get_collection(nom_collection)?;
    let filtre = doc! {
        TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: {"$in": &catalogue_horaire.uuid_transactions}
    };
    let ops = doc! {
        "$set": {TRANSACTION_CHAMP_BACKUP_FLAG: true},
        "$currentDate": {TRANSACTION_CHAMP_BACKUP_HORAIRE: true},
    };

    let r= collection.update_many(filtre, ops, None).await?;
    if r.matched_count as usize != catalogue_horaire.uuid_transactions.len() {
        Err(format!(
            "Erreur mismatch nombre de transactions maj apres backup : {:?} dans le backup != {:?} mises a jour",
            catalogue_horaire.uuid_transactions.len(),
            r.matched_count
        ))?;
    }

    Ok(())
}

trait BackupHandler {
    fn run() -> Result<(), String>;
}

/// Struct de backup
#[derive(Debug)]
struct BackupInformation {
    /// Nom complet de la collection de transactions mongodb
    nom_collection_transactions: String,
    /// Options de chiffrage
    certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>,
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
    cles: Option<Mgs2CipherKeys>,
}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new(
        nom_collection_transactions: &str,
        certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>,
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
            nom_collection_transactions: nom_collection_transactions.to_owned(),
            certificats_chiffrage,
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
            cles: None,
        }
    }

    fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat).expect("certificat");
    }

    fn ajouter_transaction(&mut self, uuid_transaction: &str) {
        self.uuid_transactions.push(String::from(uuid_transaction));
    }

    fn transactions_hachage(&mut self, hachage: String) {
        self.transactions_hachage = hachage;
    }

    fn set_cles(&mut self, cles: &Mgs2CipherKeys) {
        self.cles = Some(cles.clone());
    }

    fn build(self) -> CatalogueHoraire {

        let date_str = self.heure.format_ymdh();

        // Build collections de certificats
        let transactions_hachage = self.transactions_hachage;
        let transactions_nomfichier = format!("{}_{}.jsonl.xz", &self.nom_domaine, date_str);
        let catalogue_nomfichier = format!("{}_{}.json.xz", &self.nom_domaine, date_str);

        let (format, cle, iv, tag) = match(self.cles) {
            Some(cles) => {
                (Some(cles.get_format()), cles.get_cle_millegrille(), Some(cles.iv), Some(cles.tag))
            },
            None => (None, None, None, None)
        };

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
            cle,
            iv,
            tag,
            format,
        }
    }

}

struct TransactionWriter<'a> {
    fichier_writer: FichierWriter<'a>,
}

impl<'a> TransactionWriter<'a> {

    pub async fn new(path_fichier: &'a Path, certificats_chiffrage: Option<Vec<FingerprintCertPublicKey>>) -> Result<TransactionWriter<'a>, Box<dyn Error>> {
        let fichier_writer = FichierWriter::new(path_fichier, certificats_chiffrage).await?;
        Ok(TransactionWriter{fichier_writer})
    }

    /// Serialise un objet Json (Value) dans le fichier. Ajouter un line feed (\n).
    pub async fn write_json_line(&mut self, contenu: &Value) -> Result<usize, Box<dyn Error>> {
        // Convertir value en bytes
        let mut contenu_bytes = serde_json::to_string(contenu)?.as_bytes().to_owned();

        // Ajouter line feed (\n)
        contenu_bytes.push(NEW_LINE_BYTE);

        // Write dans le fichier
        self.fichier_writer.write(contenu_bytes.as_slice()).await
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
        self.fichier_writer.fermer().await
    }

}

struct TransactionReader<'a> {
    data: Box<dyn AsyncRead + Unpin + 'a>,
    xz_decoder: stream::Stream,
    // hacheur: Hacheur,
    dechiffreur: Option<DecipherMgs2>,
}

impl<'a> TransactionReader<'a> {

    const BUFFER_SIZE: usize = 65535;

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
        let mut buffer = [0u8; TransactionReader::BUFFER_SIZE/2];
        let mut xz_output = Vec::new();
        xz_output.reserve(TransactionReader::BUFFER_SIZE);

        let mut dechiffrage_output = [0u8; TransactionReader::BUFFER_SIZE];

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
            NOM_COLLECTION_BACKUP,
            None,
            None
        ).expect("init");

        let workpath = info.workpath.to_str().unwrap();

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        // assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        assert_eq!(info.certificats_chiffrage.is_none(), true);
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

        catalogue_builder.ajouter_certificat(&certificat);

        let catalogue = catalogue_builder.build();
        // println!("!!! Catalogue : {:?}", catalogue);
        assert_eq!(catalogue.certificats.len(), 1);
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

        (String::from("z8Vsx9FQ9pnTXuQT41WtY9TBh4a3zDoN7HZXf1c2Q4c8tuhR4TnWn8GCEmoMbRXWdgcXujYWz4M3zdEytDikQKsTE2i"), doc_bson)
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
            enveloppe.certificat().public_key().clone().expect("cle"),
            true
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

    use crate::{charger_transaction, MiddlewareDbPki, Formatteur, MessageJson};
    use crate::certificats::certificats_tests::{CERT_DOMAINES, CERT_FICHIERS, charger_enveloppe_privee_env, prep_enveloppe};
    use crate::middleware::preparer_middleware_pki;

    use super::*;

    #[tokio::test]
    async fn grouper_transactions() {
        // Connecter mongo
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(tokio::spawn(async move {

            // Test
            let info = BackupInformation::new("Pki.rust", None, None).expect("info");

            let workdir = tempfile::tempdir().expect("tmpdir");
            let groupes = grouper_backups(
                middleware.as_ref(),
                &info
            ).await.expect("groupes");

            // println!("Groupes : {:?}", groupes);

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
            let info = BackupInformation::new("Pki.rust", None, None).expect("info");
            let heure = DateEpochSeconds::from_heure(2021, 08, 20, 12);
            let mut builder = CatalogueHoraire::builder(heure, "Pki".into(), "Pki.rust".into());

            let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");

            let mut path_transactions = workdir.clone();
            path_transactions.push("extraire_transactions.jsonl.xz");
            // println!("Sauvegarde transactions sous : {:?}", path_transactions);
            let resultat = serialiser_transactions(
                middleware.as_ref(),
                &mut transactions,
                &mut builder,
                path_transactions.as_path(),
                None
            ).await.expect("serialiser");

            // println!("Resultat extraction transactions : {:?}", resultat);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn serialiser_transactions_chiffrage() {

        // let workdir = tempfile::tempdir().expect("tmpdir");
        let workdir = PathBuf::from("/tmp");
        let (validateur, enveloppe) = charger_enveloppe_privee_env();

        let certificats_chiffrage = vec! [
            FingerprintCertPublicKey::new(
                String::from("dummy"),
                enveloppe.cle_publique().clone(),
                true
            )
        ];

        // Connecter mongo
        let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
        futures.push(tokio::spawn(async move {

            // Test
            let info = BackupInformation::new(
                "Pki.rust",
                Some(certificats_chiffrage.clone()),
                None
            ).expect("info");
            let heure = DateEpochSeconds::from_heure(2021, 08, 20, 12);
            let mut builder = CatalogueHoraire::builder(heure, "Pki".into(), "Pki.rust".into());

            let mut transactions = requete_transactions(middleware.as_ref(), &info, &builder).await.expect("transactions");

            let mut path_transactions = workdir.clone();
            path_transactions.push("extraire_transactions.jsonl.xz.mgs2");
            // println!("Sauvegarde transactions sous : {:?}", path_transactions);
            let cles = serialiser_transactions(
                middleware.as_ref(),
                &mut transactions,
                &mut builder,
                path_transactions.as_path(),
                Some(certificats_chiffrage)
            ).await.expect("serialiser").expect("cles");

            builder.set_cles(&cles);

            // println!("Resultat extraction transactions : {:?}\nCatalogue: {:?}", resultat, builder);

            // Signer et serialiser catalogue
            let catalogue = builder.build();
            let catalogue_value = serde_json::to_value(catalogue).expect("value");
            let message_json = MessageJson::new(catalogue_value);
            let catalogue_signe = middleware.formatter_value(&message_json, Some("Backup")).expect("signature");

            let mut path_catalogue = workdir.clone();
            path_catalogue.push("extraire_transactions_catalogue.json.xz");
            let mut writer_catalogue = FichierWriter::new(path_catalogue.as_path(), None)
                .await.expect("write catalogue");
            writer_catalogue.write(catalogue_signe.message.as_bytes()).await.expect("write");
            let (mh_catalogue, _) = writer_catalogue.fermer().await.expect("fermer catalogue writer");
            println!("Hachage catalogue {}", mh_catalogue);

        }));
        // Execution async du test
        futures.next().await.expect("resultat").expect("ok");
    }

    #[tokio::test]
    async fn uploader_backup_horaire() {
        let (validateur, enveloppe) = charger_enveloppe_privee_env();
        let ca_cert_pem = enveloppe.chaine_pem().last().expect("last");

        let root_ca = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).expect("ca x509");

        let identity = reqwest::Identity::from_pem(enveloppe.clecert_pem.as_bytes()).expect("identity");

        let client = reqwest::Client::builder()
            .add_root_certificate(root_ca)
            .identity(identity)
            .https_only(true)
            .use_rustls_tls()
            .build().expect("client");

        // let res = client.get("https://mg-dev4:3021/backup/listeDomaines")
        //     //.body("the exact body that is sent")
        //     .send()
        //     .await.expect("put");
        //
        // println!("Response : {:?}", res);
        // let resultat = res.bytes().await.expect("bytes");
        // let value: Value = serde_json::from_slice(resultat.as_ref()).expect("to_json");
        // println!("Resultat : {:?}", value);



    }

}
