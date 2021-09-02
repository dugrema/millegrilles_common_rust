use std::fs::{File, Permissions, read_to_string};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use log::{debug, error, info};
use multibase;
use openssl::pkcs12::{Pkcs12, Pkcs12Builder};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::X509;
use rand::Rng;

use crate::certificats::{build_store_path, charger_enveloppe, charger_enveloppe_privee, EnveloppePrivee, ValidateurX509, ValidateurX509Impl};

pub trait ConfigMessages: Send + Sync {
    fn get_configuration_mq(&self) -> &ConfigurationMq;
    fn get_configuration_pki(&self) -> &ConfigurationPki;
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud;
}

pub trait ConfigDb: Send + Sync {
    fn get_configuraiton_mongo(&self) -> &ConfigurationMongo;
}

pub struct ConfigurationMessages {
    mq: ConfigurationMq,
    pki: ConfigurationPki,
    noeud: ConfigurationNoeud,
}

pub struct ConfigurationMessagesDb {
    configuration_messages: ConfigurationMessages,
    mongo: ConfigurationMongo,
}

impl ConfigMessages for ConfigurationMessages {
    fn get_configuration_mq(&self) -> &ConfigurationMq { &self.mq }
    fn get_configuration_pki(&self) -> &ConfigurationPki { &self.pki }
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud { &self.noeud }
}

impl ConfigMessages for ConfigurationMessagesDb {
    fn get_configuration_mq(&self) -> &ConfigurationMq { &self.configuration_messages.mq }
    fn get_configuration_pki(&self) -> &ConfigurationPki { &self.configuration_messages.pki }
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud { &self.configuration_messages.noeud }
}

impl ConfigDb for ConfigurationMessagesDb {
    fn get_configuraiton_mongo(&self) -> &ConfigurationMongo { &self.mongo }
}

pub fn charger_configuration() -> Result<ConfigurationMessages, String> {

    let pki = charger_configuration_pki()?;
    let noeud = charger_configuration_noeud()?;
    let mq = charger_configuration_mq(&pki)?;

    Ok(ConfigurationMessages { mq, pki, noeud })
}

pub fn charger_configuration_avec_db() -> Result<ConfigurationMessagesDb, String> {

    let pki = charger_configuration_pki()?;
    let noeud = charger_configuration_noeud()?;
    let mq = charger_configuration_mq(&pki)?;
    let mongo = charger_configuration_mongo(&pki)?;

    let configuration_messages = ConfigurationMessages { pki, mq, noeud };

    Ok(ConfigurationMessagesDb { configuration_messages, mongo })
}

fn charger_configuration_mq(pki: &ConfigurationPki) -> Result<ConfigurationMq, String> {

    // Generer fichier p12 avec cle et certificat pour la connexion ssl
    let (p12_keycert, p12_password) = pki.exporter_p12_certfile();

    let _ = pki.exporter_clecert()?;

    let port: u16 = match std::env::var("MG_MQ_PORT") {
        Ok(p) => p.parse().unwrap(),
        Err(_) => 5673,
    };

    Ok(ConfigurationMq {
        host: std::env::var("MG_MQ_HOST").unwrap_or_else(|_| "mq".into()),
        port,
        exchange_default: std::env::var("MG_MQ_EXCHANGE_DEFAUT").unwrap_or_else(|_| "3.protege".into()),
        p12_keycert,
        p12_password,
    })
}

fn charger_configuration_mongo(pki: &ConfigurationPki) -> Result<ConfigurationMongo, String> {

    let port: u16 = match std::env::var("MG_MONGO_PORT") {
        Ok(p) => p.parse().unwrap(),
        Err(_) => 27017,
    };

    let keycert_file = pki.exporter_clecert().expect("Erreur chargement cle/cert pour Mongo");

    Ok(ConfigurationMongo {
        host: std::env::var("MG_MONGO_HOST").unwrap_or_else(|_| "mongo".into()),
        port,
        keycert_file,
    })
}

fn charger_configuration_pki() -> Result<ConfigurationPki, String> {

    let ca_certfile = PathBuf::from(std::env::var("CAFILE").unwrap_or_else(|_| "/run/secrets/pki.millegrille".into()));
    let validateur: Arc<ValidateurX509Impl> = Arc::new(build_store_path(ca_certfile.as_path()).expect("Erreur chargement store X509"));

    let keyfile = PathBuf::from(std::env::var("KEYFILE").unwrap_or_else(|_| "/run/secrets/key.pem".into()));
    let certfile = PathBuf::from(std::env::var("CERTFILE").unwrap_or_else(|_| "/run/secrets/cert.pem".into()));

    // Preparer enveloppe privee
    let enveloppe_privee = Arc::new(
        charger_enveloppe_privee(
            certfile.as_path(),
            keyfile.as_path(),
            validateur.clone()
        ).expect("Erreur chargement cle ou certificat")
    );

    Ok(ConfigurationPki {
        keyfile,
        certfile,
        ca_certfile,
        validateur,
        enveloppe_privee,
    })
}

fn charger_configuration_noeud() -> Result<ConfigurationNoeud, String> {
    let noeud_id = match std::env::var("MG_NOEUD_ID") {
        Ok(v) => Some(v),
        Err(e) => None,
    };
    Ok(ConfigurationNoeud{
        noeud_id,
    })
}

#[derive(Clone, Debug)]
pub struct ConfigurationMq {
    pub host: String,
    pub port: u16,
    pub p12_keycert: Vec<u8>,
    pub p12_password: String,
    pub exchange_default: String,
}

#[derive(Clone, Debug)]
pub struct ConfigurationMongo {
    pub host: String,
    pub port: u16,
    pub keycert_file: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ConfigurationNoeud {
    pub noeud_id: Option<String>,
}

#[derive(Debug)]
pub struct ConfigurationPki {
    pub keyfile: PathBuf,
    pub certfile: PathBuf,
    pub ca_certfile: PathBuf,
    validateur: Arc<ValidateurX509Impl>,
    enveloppe_privee: Arc<EnveloppePrivee>,
}

impl ConfigurationPki {

    pub fn get_validateur(&self) -> Arc<ValidateurX509Impl> {
        self.validateur.clone()
    }

    pub fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.enveloppe_privee.clone()
    }

    // Exporter la cle et le certificat en format p12
    pub fn exporter_p12_certfile(&self) -> (Vec<u8>, String) {
        debug!("Preparer cle/certificat format p12 pour lapin");

        let validateur = &self.validateur;
        let enveloppe_privee = &self.enveloppe_privee;

        // Preparer cle, cert, pass
        let password: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>();
        let password: String = multibase::encode(multibase::Base::Base64, password);
        // let enveloppe_privee = charger_enveloppe_privee(
        //     self.certfile.as_path(), self.keyfile.as_path(), validateur)
        //     .expect("Erreur chargement cle ou certificat");

        let cle_privee = enveloppe_privee.cle_privee();
        let certificat = enveloppe_privee.certificat();

        // Preparer CA
        let ca_cert = validateur.ca_cert();
        let mut ca_stack: Stack<X509> = Stack::new().unwrap();

        for c in enveloppe_privee.intermediaire() {
            ca_stack.push(c.to_owned()).unwrap();
        }
        ca_stack.push(ca_cert.to_owned()).unwrap();

        let mut builder = Pkcs12::builder();
        builder.ca(ca_stack);
        let cert_p12 = builder.build(password.as_str(), "Mon cert", cle_privee, certificat)
            .expect("Erreur creation cle/certificat p12");

        // Sauvegarder certificat p12 dans un fichier temporaire
        let der_format = cert_p12.to_der().expect("Erreur creation format p12");

        (der_format, password)
    }

    pub fn exporter_clecert(&self) -> Result<PathBuf, String> {

        // let key_pem: String = read_to_string(&self.keyfile).expect("Erreur lecture cle PEM");

        // Convertir la cle privee en format RSA
        let cle_privee: Rsa<Private> = self.enveloppe_privee.cle_privee().rsa().unwrap();
        let cle_privee: Vec<u8> = cle_privee.private_key_to_pem().expect("Conversion cle privee en PKCS8");;

        let cert_pem: String = read_to_string(&self.certfile).expect("Erreur lecture cert PEM");

        let nom_fichier = PathBuf::from("/tmp/clecert.pem");
        {
            let mut file = File::create(nom_fichier.as_path()).expect("Erreur creation fichier temporaire clecert");
            file.write_all(cle_privee.as_slice()).unwrap();
            file.write_all(cert_pem.as_bytes()).unwrap();

            let mut permissions: Permissions = file.metadata().unwrap().permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions).unwrap();
        }
        debug!("Fichier clecert temporaire cree {:?}", &nom_fichier);

        Ok(nom_fichier)
    }

}