use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use uuid::Uuid;

use crate::{EnveloppeCertificat, FormatChiffrage, DateEpochSeconds, Entete, CollectionCertificatsPem};
use crate::certificats::EnveloppePrivee;
use serde_json::Value;
use serde::{Serialize, Deserialize};

const PATH_BACKUP_DEFAUT: &str = "/tmp/backup_millegrille";

trait BackupHandler {
    fn run() -> Result<(), String>;
}

/// Struct de backup
#[derive(Clone, Debug)]
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

    catalogue_nomfichier: String,
    transactions_nomfichier: String,
    transactions_hachage: String,
    uuid_transactions: Vec<String>,

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
}

impl BackupInformation {

    /// Creation d'une nouvelle structure de backup
    pub fn new(
        nom_domaine: String,
        nom_collection_transactions: String,
        chiffrage: Option<FormatChiffrage>,
        workpath: Option<PathBuf>
    ) -> BackupInformation {

        let workpath_inner = match workpath {
            Some(wp) => wp,
            None => PathBuf::from(PATH_BACKUP_DEFAUT),
        };

        let uuid_backup = Uuid::new_v4().to_string();

        BackupInformation {
            nom_domaine,
            nom_collection_transactions,
            chiffrage,
            workpath: workpath_inner,
            uuid_backup,
        }
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
        }
    }

    fn ajouter_certificat(mut self, certificat: EnveloppeCertificat) {
        self.certificats.ajouter_certificat(certificat);
    }

    fn ajouter_transaction(mut self, uuid_transaction: String) {
        self.uuid_transactions.push(uuid_transaction);
    }

    fn build(self) -> CatalogueHoraire {

        // Build collections de certificats
        let certificats = CollectionCertificatsPem::new();

        let transactions_hachage = "".to_owned();
        let transactions_nomfichier = "".to_owned();
        let catalogue_nomfichier = "".to_owned();

        CatalogueHoraire {
            heure: self.heure,
            domaine: self.nom_domaine,
            uuid_backup: self.uuid_backup,
            catalogue_nomfichier,

            certificats,

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

#[cfg(test)]
mod backup_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    const NOM_DOMAINE_BACKUP: &str = "Domaine.test";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    #[test]
    fn init_backup_information() {
        let info = BackupInformation::new(
            NOM_DOMAINE_BACKUP.to_owned(),
            NOM_COLLECTION_BACKUP.to_owned(),
            None,
            None
        );

        assert_eq!(&info.nom_collection_transactions, NOM_COLLECTION_BACKUP);
        assert_eq!(&info.nom_domaine, NOM_DOMAINE_BACKUP);
        assert_eq!(info.chiffrage.is_none(), true);
        assert_eq!(info.workpath.to_str().unwrap(), PATH_BACKUP_DEFAUT);
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
    }

    #[test]
    fn serialiser_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

        let value = serde_json::to_value(catalogue).expect("value");

        println!("Valeur catalogue : {:?}", value);
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
        println!("Json catalogue : {:?}", catalogue_str);

        assert_eq!(catalogue_str.find("1627794000"), Some(9));
        assert_eq!(catalogue_str.find(NOM_DOMAINE_BACKUP), Some(31));
        assert_eq!(catalogue_str.find(uuid_backup), Some(60));
    }

    #[test]
    fn build_catalogue_() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 5);
        let uuid_backup = "1cf5b0a8-11d8-4ff2-aa6f-1a605bd17336";

        let catalogue_builder = CatalogueHoraireBuilder::new(
            heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup.to_owned());

        let catalogue = catalogue_builder.build();

    }
}
