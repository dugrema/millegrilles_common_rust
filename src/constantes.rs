use std::borrow::Borrow;
use crate::constantes::Securite::{L1Public, L2Prive, L3Protege, L4Secure};
use std::collections::HashSet;
use std::cmp::Eq;
use std::convert::TryFrom;
use std::error::Error;
use crate::rabbitmq_dao::TypeMessageOut;

// Differents formats pour le niveau de securite
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Securite {
    L1Public,
    L2Prive,
    L3Protege,
    L4Secure,
}
impl Securite {
    pub fn get_rank(&self) -> i32 {
        securite_rank(self)
    }
    pub fn get_str(&self) -> &'static str {
        securite_str(self)
    }
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
pub fn securite_vec_to_sec<S, V>(vec_sec: V) -> Result<Vec<Securite>, Box<dyn Error>>
    where S: AsRef<str>,
          V: AsRef<Vec<S>>
{
    let vec_sec_ref = vec_sec.as_ref();
    let mut vec_securite = Vec::new();
    for e in vec_sec_ref {
        let e_string = e.as_ref();
        let e_sec: Securite = Securite::try_from(e_string)?;
        vec_securite.push(e_sec);
    }

    Ok(vec_securite)
}

pub const SECURITE_1_PUBLIC: &str = "1.public";
pub const SECURITE_2_PRIVE: &str = "2.prive";
pub const SECURITE_3_PROTEGE: &str = "3.protege";
pub const SECURITE_4_SECURE: &str = "4.secure";

pub fn securite_enum<S>(securite: S) -> Result<Securite, String>
    where S: AsRef<str>
{
    let s = securite.as_ref();
    match s {
        SECURITE_1_PUBLIC => Ok(L1Public),
        SECURITE_2_PRIVE => Ok(L2Prive),
        SECURITE_3_PROTEGE => Ok(L3Protege),
        SECURITE_4_SECURE => Ok(L4Secure),
        _ => Err(format!("Type non supporte {:?}", s))
    }
}

pub fn securite_rank<S>(securite: S) -> i32
    where S: Borrow<Securite>
{
    let s = securite.borrow();
    match s {
        Securite::L1Public => 1,
        Securite::L2Prive => 2,
        Securite::L3Protege => 3,
        Securite::L4Secure => 4,
    }
}

pub fn securite_str<S>(securite: S) -> &'static str
    where S: Borrow<Securite>
{
    let s = securite.borrow();
    match s {
        Securite::L1Public => SECURITE_1_PUBLIC,
        Securite::L2Prive => SECURITE_2_PRIVE,
        Securite::L3Protege => SECURITE_3_PROTEGE,
        Securite::L4Secure => SECURITE_4_SECURE,
    }
}

/// Retourne une liste des niveaux de securite de 1.public jusqu'au niveau specifie
pub fn securite_cascade_public<S>(securite: S) -> HashSet<Securite>
    where S: Borrow<Securite>
{
    let mut set: HashSet<Securite> = HashSet::new();

    let s = securite.borrow();
    match s {
        Securite::L1Public => {set.insert(Securite::L1Public);},
        Securite::L2Prive => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive);},
        Securite::L3Protege => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive); set.insert(Securite::L3Protege);},
        Securite::L4Secure => {set.insert(Securite::L1Public); set.insert(Securite::L2Prive); set.insert(Securite::L3Protege); set.insert(Securite::L4Secure);},
    }

    set
}

#[derive(Clone)]
pub enum MessageKind {
    Document,
    Requete,
    Commande,
    Transaction,
    Reponse,
    Evenement,
    ReponseChiffree,
    TransactionMigree,
    CommandeInterMillegrille,
}

pub const KIND_DOCUMENT: u16 = 0;
pub const KIND_REQUETE: u16 = 1;
pub const KIND_COMMANDE: u16 = 2;
pub const KIND_TRANSACTION: u16 = 3;
pub const KIND_REPONSE: u16 = 4;
pub const KIND_EVENEMENT: u16 = 5;
pub const KIND_REPONSE_CHIFFREE: u16 = 6;
pub const KIND_TRANSACTION_MIGREE: u16 = 7;
pub const KIND_COMMANDE_INTER_MILLEGRILLE: u16 = 8;

pub fn kind_rank<S>(kind: S) -> u16
    where S: Borrow<MessageKind>
{
    let s = kind.borrow();
    match s {
        MessageKind::Document => KIND_DOCUMENT,
        MessageKind::Requete => KIND_REQUETE,
        MessageKind::Commande => KIND_COMMANDE,
        MessageKind::Transaction => KIND_TRANSACTION,
        MessageKind::Reponse => KIND_REPONSE,
        MessageKind::Evenement => KIND_EVENEMENT,
        MessageKind::ReponseChiffree => KIND_REPONSE_CHIFFREE,
        MessageKind::TransactionMigree => KIND_TRANSACTION_MIGREE,
        MessageKind::CommandeInterMillegrille => KIND_COMMANDE_INTER_MILLEGRILLE,
    }
}

impl From<TypeMessageOut> for MessageKind {
    fn from(value: TypeMessageOut) -> Self {
        match value {
            TypeMessageOut::Requete(_) => MessageKind::Requete,
            TypeMessageOut::Commande(_) => MessageKind::Commande,
            TypeMessageOut::Transaction(_) => MessageKind::Transaction,
            TypeMessageOut::Reponse(_) => MessageKind::Reponse,
            TypeMessageOut::Evenement(_) => MessageKind::Evenement,
        }
    }
}

impl Into<u16> for MessageKind {
    fn into(self) -> u16 {
        kind_rank(&self)
    }
}

// Roles (types de certificats serveur)
pub const ROLE_NOEUD_PROTEGE: &str = "protege";
pub const ROLE_NOEUD_PRIVE: &str = "prive";
pub const ROLE_NOEUD_PUBLIC: &str = "public";
pub const ROLE_MAITRE_COMPTES: &str = "maitrecomptes";
pub const ROLE_WEB_AUTH: &str = "webauth";
pub const ROLE_MONITOR: &str = "monitor";
pub const ROLE_MAITRE_DES_CLES: &str = "maitredescles";
pub const ROLE_MAITRE_DES_CLES_CONNEXION: &str = "maitredescles_connexion";
pub const ROLE_MAITRE_DES_CLES_VOLATIL: &str = "maitredescles_volatil";
pub const ROLE_FICHIERS: &str = "fichiers";
pub const ROLE_COMPTE_PRIVE: &str = "compte_prive";
pub const ROLE_CORE: &str = "core";
pub const ROLE_MEDIA: &str = "media";
pub const ROLE_INSTANCE: &str = "instance";
pub const ROLE_STREAM: &str = "stream";
pub const ROLE_POSTMASTER: &str = "postmaster";
pub const ROLE_SOLR_RELAI: &str = "solrrelai";
pub const ROLE_BACKUP: &str = "backup";

pub enum RolesCertificats {
    NoeudProtege,
    NoeudPrive,
    NoeudPublic,
    MaitreComptes,
    WebAuth,
    Monitor,  // Deprecated, devenu instance
    MaitreDesCles,           // Certificat de connexion (4.secure) et gestion de cles
    MaitreDesClesConnexion,  // Certificat de connexion sans droit de gestion de cles
    MaitreDesClesVolatil,    // Certificat de gestion de cles sans droit de connexion
    Fichiers,  // ConsignationFichiers
    ComptePrive,
    Core,
    Media,
    Instance,
    Stream,
    Postmaster,
    SolrRelai,
    Backup,
}
impl Into<&str> for RolesCertificats {
    fn into(self) -> &'static str {
        match self {
            RolesCertificats::NoeudProtege => ROLE_NOEUD_PROTEGE,
            RolesCertificats::NoeudPrive => ROLE_NOEUD_PRIVE,
            RolesCertificats::NoeudPublic => ROLE_NOEUD_PUBLIC,
            RolesCertificats::MaitreComptes => ROLE_MAITRE_COMPTES,
            RolesCertificats::WebAuth => ROLE_WEB_AUTH,
            RolesCertificats::Monitor => ROLE_MONITOR,
            RolesCertificats::MaitreDesCles => ROLE_MAITRE_DES_CLES,
            RolesCertificats::MaitreDesClesConnexion => ROLE_MAITRE_DES_CLES_CONNEXION,
            RolesCertificats::MaitreDesClesVolatil => ROLE_MAITRE_DES_CLES_VOLATIL,
            RolesCertificats::Fichiers => ROLE_FICHIERS,
            RolesCertificats::ComptePrive => ROLE_COMPTE_PRIVE,
            RolesCertificats::Core => ROLE_CORE,
            RolesCertificats::Media => ROLE_MEDIA,
            RolesCertificats::Instance => ROLE_INSTANCE,
            RolesCertificats::Stream => ROLE_STREAM,
            RolesCertificats::Postmaster => ROLE_POSTMASTER,
            RolesCertificats::SolrRelai => ROLE_SOLR_RELAI,
            RolesCertificats::Backup => ROLE_BACKUP,
        }
    }
}
impl Into<String> for RolesCertificats {
    fn into(self) -> String {
        let str_static: &str = self.into();
        String::from(str_static)
    }
}

// Delegations
pub const DELEGATION_GLOBALE_PROPRIETAIRE: &str = "proprietaire";


// Global

pub const NEW_LINE_BYTE: u8 = 0x0A;
pub const EMPTY_ARRAY: [u8; 0] = [0u8; 0];
pub const DEFAULT_Q_TTL: u32 = 300000;

// Domaines tiers
pub const DOMAINE_APPLICATION_INSTANCE: &str = "instance";
pub const DOMAINE_SERVICE_MONITOR: &str = DOMAINE_APPLICATION_INSTANCE;
pub const DOMAINE_FICHIERS: &str = "fichiers";
pub const DOMAINE_BACKUP: &str = "backup";
pub const DOMAINE_RELAIWEB: &str = "relaiweb";
pub const DOMAINE_TOPOLOGIE: &str = "CoreTopologie";
pub const DOMAINE_PKI: &str = "CorePki";

// Evenements/commandes globaux
pub const DOMAINE_GLOBAL: &str = "evenement.global.cedule";
pub const EVENEMENT_PRESENCE_DOMAINE: &str = "presenceDomaine";
pub const EVENEMENT_GLOBAL_CEDULE: &str = "evenement.global.cedule";
pub const COMMANDE_GLOBAL_BACKUP_HORAIRE: &str = "commande.global.declencherBackupHoraire";
pub const COMMANDE_GLOBAL_RESTAURER_TRANSACTIONS: &str = "commande.global.restaurerTransactions";
pub const COMMANDE_GLOBAL_RESET_BACKUP: &str = "commande.global.resetBackup";
pub const COMMANDE_GLOBAL_REGENERER: &str = "commande.global.regenerer";
// pub const COMMANDE_BACKUP_ROTATION: &str = "rotationBackupTransactions";
pub const COMMANDE_SAUVEGARDER_CERTIFICAT: &str = "certificat";

// Evenements
pub const EVENEMENT_TRANSACTION_PERSISTEE: &str = "transaction_persistee";
pub const EVENEMENT_CEDULE: &str = "cedule";
pub const EVENEMENT_BACKUP_DECLENCHER: &str = "declencherBackup";
pub const EVENEMENT_RESTAURER_TRANSACTION: &str = "restaurerTransaction";
pub const EVENEMENT_REGENERATION_MAJ: &str = "regenerationMaj";

// Requetes
pub const REQUETE_NOMBRE_TRANSACTIONS: &str = "getNombreTransactions";

// Transactions
pub const TRANSACTION_CHAMP_ID: &str = "id";
pub const TRANSACTION_CHAMP_PUBKEY: &str = "pubkey";
// pub const TRANSACTION_CHAMP_ENTETE: &str = "en-tete";
// pub const TRANSACTION_CHAMP_UUID_TRANSACTION: &str = "uuid_transaction";
// pub const TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION: &str = "en-tete.uuid_transaction";
// pub const TRANSACTION_CHAMP_ENTETE_PARTITION: &str = "en-tete.partition";
pub const TRANSACTION_CHAMP_DOMAINE: &str = "domaine";
pub const TRANSACTION_CHAMP_ACTION: &str = "action";
// pub const TRANSACTION_CHAMP_FINGERPRINT_CERTIFICAT: &str = "fingerprint_certificat";
pub const TRANSACTION_CHAMP_EVENEMENTS: &str = "_evenements";
pub const TRANSACTION_CHAMP_IDMG: &str = "idmg";
pub const TRANSACTION_CHAMP_ESTAMPILLE: &str = "estampille";
pub const TRANSACTION_CHAMP_COMPLETE: &str = "transaction_complete";
pub const TRANSACTION_CHAMP_SIGNATURE: &str = "sig";
pub const TRANSACTION_CHAMP_CERTIFICAT: &str = "certificat";

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
pub const CHAMP_SECURITE: &str = "securite";

// Certificats, PKI
// pub const PKI_DOMAINE_LEGACY_NOM: &str = "Pki";
pub const PKI_DOMAINE_NOM: &str = "CorePki";
pub const PKI_DOMAINE_CERTIFICAT_NOM: &str = "certificat";
// pub const PKI_COLLECTION_TRANSACTIONS_NOM: &str = PKI_DOMAINE_NOM;
// pub const PKI_COLLECTION_CERTIFICAT_NOM: &str = "CorePki/certificat";
//
// pub const PKI_EVENEMENT_CERTIFICAT: &str = "certificat.infoCertificat";
//
pub const PKI_REQUETE_CERTIFICAT: &str = "infoCertificat";
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

// Maitre des comptes
pub const DOMAINE_NOM_MAITREDESCOMPTES: &str = "CoreMaitreDesComptes";
pub const ACTION_GET_LISTE_PROPRIETAIRES: &str = "getListeProprietaires";

// Maitre des cles
pub const DOMAINE_NOM_MAITREDESCLES: &str = "MaitreDesCles";
pub const MAITREDESCLES_COMMANDE_NOUVELLE_CLE: &str = "nouvelleCle";
pub const MAITREDESCLES_REQUETE_DECHIFFRAGE: &str = "dechiffrage";
pub const MAITREDESCLES_REQUETE_DECHIFFRAGE_V2: &str = "dechiffrageV2";
pub const MAITREDESCLES_REQUETE_DECHIFFRAGE_MESSAGE: &str = "dechiffrageMessage";

pub const MAITREDESCLES_CHAMP_HACHAGE_BYTES: &str = "hachage_bytes";
pub const MAITREDESCLES_CHAMP_CLES: &str = "cles";
pub const MAITREDESCLES_CHAMP_LISTE_HACHAGE_BYTES: &str = "liste_hachage_bytes";

pub const COMMANDE_SAUVEGARDER_CLE: &str = "sauvegarderCle";
pub const COMMANDE_AJOUTER_CLE_DOMAINES: &str = "ajouterCleDomaines";
pub const REQUETE_CERT_MAITREDESCLES: &str = "certMaitreDesCles";
pub const COMMANDE_CERT_MAITREDESCLES: &str = REQUETE_CERT_MAITREDESCLES;
pub const COMMANDE_TRANSFERT_CLE: &str = "transfertCle";
pub const COMMANDE_TRANSFERT_CLE_CA: &str = "transfertCleCa";
pub const EVENEMENT_CLES_RECHIFFRAGE: &str = "clesRechiffrage";
pub const COMMANDE_ROTATION_CERTIFICAT: &str = "rotationCertificat";
pub const COMMANDE_DECHIFFRER_CLE: &str = "dechiffrerCle";

// Messagerie
pub const DOMAINE_NOM_MESSAGERIE: &str = "Messagerie";
pub const DOMAINE_NOM_GROSFICHIERS: &str = "GrosFichiers";
pub const ACTION_NOTIFIER: &str = "notifier";

// Backup
pub const BACKUP_NOM_DOMAINE: &str = "CoreBackup";
pub const BACKUP_NOM_DOMAINE_GLOBAL: &str = "backup";

pub const BACKUP_TRANSACTION_CATALOGUE_QUOTIDIEN: &str = "catalogueQuotidien";
pub const BACKUP_TRANSACTION_CATALOGUE_HORAIRE: &str = "catalogueHoraire";

pub const BACKUP_REQUETE_DERNIER_HORAIRE: &str = "backupDernierHoraire";

pub const BACKUP_CHAMP_FUUID_GROSFICHIERS: &str = "fuuid_grosfichiers";
pub const BACKUP_CHAMP_BACKUP_TRANSACTIONS: &str = "backup_transactions";

pub const COMMANDE_BACKUP_HORAIRE: &str = "declencherBackupHoraire";
// pub const COMMANDE_BACKUP_QUOTIDIEN: &str = "declencherBackupQuotidien";
pub const COMMANDE_RESTAURER_TRANSACTION: &str = "restaurerTransaction";
pub const COMMANDE_RESTAURER_TRANSACTIONS: &str = "restaurerTransactions";
pub const COMMANDE_RESET_BACKUP: &str = "resetBackup";
pub const COMMANDE_REGENERER: &str = "regenerer";

// Commande RelaiWeb
pub const COMMANDE_RELAIWEB_GET: &str = "get";
pub const COMMANDE_RELAIWEB_POST: &str = "post";

pub const BACKUP_EVENEMENT_MAJ: &str = "backupMaj";

pub const TOPOLOGIE_NOM_DOMAINE: &str = DOMAINE_TOPOLOGIE;
// pub const EVENEMENT_PRESENCE_DOMAINE: &str = "presenceDomaine";


// Messages tiers
pub const COMMANDE_FICHIERS_REACTIVER: &str = "reactiverFuuids";

pub const PATH_REGLES_VALIDATION: &str = "/var/opt/millegrilles/configuration/idmg_validation.json";
