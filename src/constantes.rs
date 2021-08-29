// Differents formats pour le niveau de securite
#[derive(Clone, Debug)]
pub enum Securite {
    L1Public,
    L2Prive,
    L3Protege,
    L4Secure,
}

pub const SECURITE_1_PUBLIC: &str = "1.public";
pub const SECURITE_2_PRIVE: &str = "2.prive";
pub const SECURITE_3_PROTEGE: &str = "3.protege";
pub const SECURITE_4_SECURE: &str = "4.secure";

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

// Global

pub const NEW_LINE_BYTE: u8 = 0x0A;

// Evenements globaux
pub const EVENEMENT_PRESENCE_DOMAINE: &str = "evenement.presence.domaine";

// Transactions
pub const EVENEMENT_TRANSACTION_PERSISTEE: &str = "transaction_persistee";

pub const TRANSACTION_CHAMP_ENTETE: &str = "en-tete";
pub const TRANSACTION_CHAMP_UUID_TRANSACTION: &str = "uuid_transaction";
pub const TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: &str = "en-tete.uuid_transaction";
pub const TRANSACTION_CHAMP_DOMAINE: &str = "domaine";
pub const TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT: &str = "fingerprint_certificat";
pub const TRANSACTION_CHAMP_EVENEMENTS: &str = "_evenements";
pub const TRANSACTION_CHAMP_IDMG: &str = "idmg";
pub const TRANSACTION_CHAMP_ESTAMPILLE: &str = "estampille";

pub const TRANSACTION_CHAMP_EVENEMENT_PERSISTE: &str = "_evenements.document_persiste";
pub const TRANSACTION_CHAMP_EVENEMENT_COMPLETE: &str = "_evenements.transaction_complete";
pub const TRANSACTION_CHAMP_ERREUR_TRAITEMENT: &str = "_evenements.erreur_traitement";
pub const TRANSACTION_CHAMP_DATE_RESOUMISE: &str = "_evenements.resoumise";
pub const TRANSACTION_CHAMP_COMPTE_RESOUMISE: &str = "_evenements.compte_resoumise";
pub const TRANSACTION_CHAMP_ERREUR_RESOUMISSION: &str = "_evenements.erreur_resoumission";
pub const TRANSACTION_CHAMP_BACKUP_FLAG: &str = "_evenements.backup_flag";
pub const TRANSACTION_CHAMP_TRANSACTION_TRAITEE: &str = "_evenements.transaction_traitee";
pub const TRANSACTION_CHAMP_BACKUP_HORAIRE: &str = "_evenements.backup_horaire";
pub const TRANSACTION_LIMITE_RESOUMISSION: i32 = 4;

// Certificats, PKI
pub const PKI_DOMAINE_NOM: &str = "Pki";
pub const PKI_DOMAINE_CERTIFICAT_NOM: &str = "certificat";
pub const PKI_COLLECTION_TRANSACTIONS_NOM: &str = "Pki.rust";
pub const PKI_COLLECTION_CERTIFICAT_NOM: &str = "Pki.rust/certificat";

pub const PKI_EVENEMENT_CERTIFICAT: &str = "evenement.certificat.infoCertificat";

pub const PKI_REQUETE_CERTIFICAT: &str = "infoCertificat";
pub const PKI_REQUETE_CERTIFICAT_PAR_PK: &str = "certificatParPk";

pub const PKI_COMMANDE_SAUVEGARDER_CERTIFICAT: &str = "certificat";
pub const PKI_COMMANDE_NOUVEAU_CERTIFICAT: &str = "nouveauCertificat";

pub const PKI_TRANSACTION_NOUVEAU_CERTIFICAT: &str = PKI_COMMANDE_NOUVEAU_CERTIFICAT;

pub const PKI_DOCUMENT_CHAMP_FINGERPRINT: &str = "fingerprint";
pub const PKI_DOCUMENT_CHAMP_FINGERPRINT_PK: &str = "fingerprint_pk";
pub const PKI_DOCUMENT_CHAMP_CERTIFICAT: &str = "certificat";
