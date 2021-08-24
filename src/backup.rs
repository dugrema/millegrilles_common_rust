use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use uuid::Uuid;

use crate::{EnveloppeCertificat, FormatChiffrage, DateEpochSeconds};
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

#[derive(Clone, Debug, Serialize)]
struct CatalogueHoraire {
    /// Heure du backup (minutes = 0, secs = 0)
    heure: DateEpochSeconds,
    /// Nom du domaine ou sous-domaine
    nom_domaine: String,
    /// Collection des certificats presents dans les transactions du backup
    //certificats: HashMap<String, EnveloppeCertificat>,
    /// Identificateur unique du groupe de backup (collateur)
    uuid_backup: String,
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
    fn new(heure: DateEpochSeconds, nom_domaine: String, uuid_backup: String) -> CatalogueHoraire {
        CatalogueHoraire {
            heure,
            nom_domaine,
            //certificats: HashMap::new(),
            uuid_backup,
        }
    }

    fn ajouter_certificat(certificat: EnveloppeCertificat) {

    }

}

#[cfg(test)]
mod backup_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use chrono::Timelike;

    const NOM_DOMAINE_BACKUP: &str = "Domaine.test";
    const NOM_COLLECTION_BACKUP: &str = "CollectionBackup";

    #[test]
    fn init_catalogue() {
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
    fn init_backup_horaire() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue = CatalogueHoraire::new(heure.clone(), NOM_DOMAINE_BACKUP.to_owned(), uuid_backup);

        assert_eq!(catalogue.heure.get_datetime().timestamp(), heure.get_datetime().timestamp());
        assert_eq!(&catalogue.nom_domaine, NOM_DOMAINE_BACKUP);
    }

    #[test]
    fn marshall_catalogue() {
        let heure = DateEpochSeconds::from_heure(2021, 08, 01, 0);
        let uuid_backup = Uuid::new_v4().to_string();

        let catalogue = CatalogueHoraire::new(heure, NOM_DOMAINE_BACKUP.to_owned(), uuid_backup);

    }

}
