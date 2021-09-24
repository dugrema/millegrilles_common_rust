use crate::constantes::Securite::{L1Public, L2Prive, L3Protege, L4Secure};
use std::collections::HashSet;
use std::cmp::Eq;
use std::convert::TryFrom;
use std::error::Error;

// Differents formats pour le niveau de securite
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Securite {
    L1Public,
    L2Prive,
    L3Protege,
    L4Secure,
}
impl Into<&str> for Securite {
    fn into(self) -> &'static str {
        securite_str(&self)
    }
}
impl Into<String> for Securite {
    fn into(self) -> String {
        String::from(securite_str(&self))
    }
}
impl TryFrom<&str> for Securite {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        securite_enum(value)
    }
}
impl TryFrom<String> for Securite {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        securite_enum(value.as_str())
    }
}

pub const SECURITE_1_PUBLIC: &str = "1.public";
pub const SECURITE_2_PRIVE: &str = "2.prive";
pub const SECURITE_3_PROTEGE: &str = "3.protege";
pub const SECURITE_4_SECURE: &str = "4.secure";

pub fn securite_enum(securite: &str) -> Result<Securite, String> {
    match securite {
        SECURITE_1_PUBLIC => Ok(L1Public),
        SECURITE_2_PRIVE => Ok(L2Prive),
        SECURITE_3_PROTEGE => Ok(L3Protege),
        SECURITE_4_SECURE => Ok(L4Secure),
        _ => Err(format!("Type non supporte {}", securite))
    }
}

pub fn securite_rank(securite: Securite) -> i32 {
    match securite {
        Securite::L1Public => 1,
        Securite::L2Prive => 2,
        Securite::L3Protege => 3,
        Securite::L4Secure => 4,
    }
}

pub fn securite_str(securite: &Securite) -> &'static str {
    match securite {
        Securite::L1Public => SECURITE_1_PUBLIC,
        Securite::L2Prive => SECURITE_2_PRIVE,
        Securite::L3Protege => SECURITE_3_PROTEGE,
        Securite::L4Secure => SECURITE_4_SECURE,
    }
}

/// Retourne une liste des niveaux de securite de 1.public jusqu'au niveau specifie
pub fn securite_cascade_public(securite: &Securite) -> HashSet<Securite> {
    let mut set: HashSet<Securite> = HashSet::new();
    match securite {
        Securite::L1Public => {set.insert(Securite::L1Public);},
        Securite::L2Prive => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive);},
        Securite::L3Protege => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive); set.insert(Securite::L3Protege);},
        Securite::L4Secure => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive); set.insert(Securite::L3Protege); set.insert(Securite::L4Secure);},
    }
    set
}

// Roles (types de certificats serveur)
pub const ROLE_NOEUD_PROTEGE: &str = "protege";
pub const ROLE_NOEUD_PRIVE: &str = "prive";
pub const ROLE_WEB_PROTEGE: &str = "web_protege";
pub const ROLE_WEB_PRIVE: &str = "web_prive";

pub enum RolesCertificats {
    NoeudProtege,
    NoeudPrive,
    WebProtege,
    WebPrive,
}
impl Into<&str> for RolesCertificats {
    fn into(self) -> &'static str {
        match self {
            RolesCertificats::NoeudProtege => ROLE_NOEUD_PROTEGE,
            RolesCertificats::NoeudPrive => ROLE_NOEUD_PRIVE,
            RolesCertificats::WebProtege => ROLE_WEB_PROTEGE,
            RolesCertificats::WebPrive => ROLE_WEB_PRIVE,
        }
    }
}
impl Into<String> for RolesCertificats {
    fn into(self) -> String {
        let str_static: &str = self.into();
        String::from(str_static)
    }
}

// Global

pub const NEW_LINE_BYTE: u8 = 0x0A;
pub const EMPTY_ARRAY: [u8; 0] = [0u8; 0];

// Domaines tiers
pub const DOMAINE_SERVICE_MONITOR: &str = "servicemonitor";

// Evenements/commandes globaux
pub const EVENEMENT_PRESENCE_DOMAINE: &str = "evenement.presence.domaine";
pub const EVENEMENT_GLOBAL_CEDULE: &str = "evenement.global.cedule";
pub const COMMANDE_GLOBAL_BACKUP_HORAIRE: &str = "commande.global.declencherBackupHoraire";
pub const COMMANDE_GLOBAL_RESTAURER_TRANSACTIONS: &str = "commande.global.restaurerTransactions";
pub const COMMANDE_GLOBAL_RESET_BACKUP: &str = "commande.global.resetBackup";

// Transactions
pub const EVENEMENT_TRANSACTION_PERSISTEE: &str = "transaction_persistee";
pub const EVENEMENT_CEDULE: &str = "cedule";

pub const TRANSACTION_CHAMP_ENTETE: &str = "en-tete";
pub const TRANSACTION_CHAMP_UUID_TRANSACTION: &str = "uuid_transaction";
pub const TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: &str = "en-tete.uuid_transaction";
pub const TRANSACTION_CHAMP_ENTETE_PARTITION: &str = "en-tete.partition";
pub const TRANSACTION_CHAMP_DOMAINE: &str = "domaine";
pub const TRANSACTION_CHAMP_ACTION: &str = "action";
pub const TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT: &str = "fingerprint_certificat";
pub const TRANSACTION_CHAMP_EVENEMENTS: &str = "_evenements";
pub const TRANSACTION_CHAMP_IDMG: &str = "idmg";
pub const TRANSACTION_CHAMP_ESTAMPILLE: &str = "estampille";
pub const TRANSACTION_CHAMP_COMPLETE: &str = "transaction_complete";
pub const TRANSACTION_CHAMP_SIGNATURE: &str = "_signature";
pub const TRANSACTION_CHAMP_CERTIFICAT: &str = "_certificat";

pub const TRANSACTION_CHAMP_EVENEMENT_PERSISTE: &str = "_evenements.document_persiste";
pub const TRANSACTION_CHAMP_EVENEMENT_COMPLETE: &str = "_evenements.transaction_complete";
pub const TRANSACTION_CHAMP_ERREUR_TRAITEMENT: &str = "_evenements.erreur_traitement";
pub const TRANSACTION_CHAMP_DATE_RESOUMISE: &str = "_evenements.resoumise";
pub const TRANSACTION_CHAMP_COMPTE_RESOUMISE: &str = "_evenements.compte_resoumise";
pub const TRANSACTION_CHAMP_ERREUR_RESOUMISSION: &str = "_evenements.erreur_resoumission";
pub const TRANSACTION_CHAMP_BACKUP_FLAG: &str = "_evenements.backup_flag";
pub const TRANSACTION_CHAMP_TRANSACTION_TRAITEE: &str = "_evenements.transaction_traitee";
pub const TRANSACTION_CHAMP_BACKUP_HORAIRE: &str = "_evenements.backup_horaire";
pub const TRANSACTION_CHAMP_TRANSACTION_RESTAUREE: &str = "_evenements.transaction_restauree";
pub const TRANSACTION_LIMITE_RESOUMISSION: i32 = 4;

// Documents
pub const CHAMP_CREATION: &str = "_mg-creation";
pub const CHAMP_MODIFICATION: &str = "_mg-derniere-modification";

// Certificats, PKI
// pub const PKI_DOMAINE_LEGACY_NOM: &str = "Pki";
// pub const PKI_DOMAINE_NOM: &str = "CorePki";
// // pub const PKI_DOMAINE_CERTIFICAT_NOM: &str = "certificat";
// pub const PKI_COLLECTION_TRANSACTIONS_NOM: &str = PKI_DOMAINE_NOM;
// pub const PKI_COLLECTION_CERTIFICAT_NOM: &str = "CorePki/certificat";
//
// pub const PKI_EVENEMENT_CERTIFICAT: &str = "certificat.infoCertificat";
//
// pub const PKI_REQUETE_CERTIFICAT: &str = "infoCertificat";
// pub const PKI_REQUETE_CERTIFICAT_PAR_PK: &str = "certificatParPk";
//
// pub const PKI_COMMANDE_SAUVEGARDER_CERTIFICAT: &str = "certificat";
pub const PKI_COMMANDE_NOUVEAU_CERTIFICAT: &str = "nouveauCertificat";
//
pub const PKI_TRANSACTION_NOUVEAU_CERTIFICAT: &str = PKI_COMMANDE_NOUVEAU_CERTIFICAT;
//
pub const PKI_DOCUMENT_CHAMP_FINGERPRINT: &str = "fingerprint";
// pub const PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const PKI_DOCUMENT_CHAMP_CERTIFICAT: &str = "certificat";


// Maitre des cles
pub const MAITREDESCLES_COMMANDE_NOUVELLE_CLE: &str = "MaitreDesCles.nouvelleCle";

pub const MAITREDESCLES_CHAMP_HACHAGE_BYTES: &str = "hachage_bytes";
pub const MAITREDESCLES_CHAMP_CLES: &str = "cles";


// Backup
pub const BACKUP_NOM_DOMAINE: &str = "Backup";

pub const BACKUP_TRANSACTION_CATALOGUE_HORAIRE: &str = "catalogueHoraire";

pub const BACKUP_CHAMP_FUUID_GROSFICHIERS: &str = "fuuid_grosfichiers";
pub const BACKUP_CHAMP_BACKUP_TRANSACTIONS: &str = "backup_transactions";

pub const COMMANDE_BACKUP_HORAIRE: &str = "declencherBackupHoraire";
pub const COMMANDE_RESTAURER_TRANSACTIONS: &str = "restaurerTransactions";
pub const COMMANDE_RESET_BACKUP: &str = "resetBackup";
