use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::io::Write;
use std::sync::{Arc, Mutex};
use base64::{Engine as _, engine::general_purpose};

use async_trait::async_trait;
use base64_url::base64;
use flate2::Compression;
use flate2::write::GzEncoder;
use log::{debug, error, info};
use multibase::Base;
use openssl::pkey::{Id, PKey, Private, Public};
use rand::Rng;
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::bson::Bson;

use crate::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, VerificateurPermissions};
use crate::chiffrage_aesgcm::{CipherMgs2, Mgs2CipherKeys};
use crate::chiffrage_cle::CommandeSauvegarderCle;
// use crate::chiffrage_chacha20poly1305::{CipherMgs3, Mgs3CipherKeys};
use crate::chiffrage_ed25519::{chiffrer_asymmetrique_ed25519, dechiffrer_asymmetrique_ed25519};
use crate::chiffrage_rsa::{chiffrer_asymetrique as chiffrer_asymetrique_aesgcm, dechiffrer_asymetrique as dechiffrer_asymetrique_aesgcm};
use crate::chiffrage_streamxchacha20poly1305::{CipherMgs4, Mgs4CipherData, Mgs4CipherKeys};
use crate::common_messages::DataChiffre;
use crate::configuration::ConfigMessages;
use crate::constantes::RolesCertificats;
use crate::formatteur_messages::{DechiffrageInterMillegrille, MessageSerialise};
use crate::generateur_messages::GenerateurMessages;
use crate::middleware::{ChiffrageFactoryTrait, IsConfigurationPki};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FormatChiffrage { mgs2, mgs3, mgs4 }

impl Into<&str> for FormatChiffrage {
    fn into(self) -> &'static str {
        match self {
            Self::mgs2 => "mgs2",
            Self::mgs3 => "mgs3",
            Self::mgs4 => "mgs4",
        }
    }
}

impl Into<Bson> for FormatChiffrage {
    fn into(self) -> Bson {
        match self {
            Self::mgs2 => Bson::String("mgs2".to_string()),
            Self::mgs3 => Bson::String("mgs3".to_string()),
            Self::mgs4 => Bson::String("mgs4".to_string()),
        }
    }
}

impl TryFrom<&str> for FormatChiffrage {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valeur = match value {
            "mgs2" => FormatChiffrage::mgs2,
            "mgs3" => FormatChiffrage::mgs3,
            "mgs4" => FormatChiffrage::mgs4,
            _ => Err(format!("Format inconnu"))?
        };

        Ok(valeur)
    }
}

/// Struct qui efface la cle secrete en memoire sur drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CleSecrete(pub [u8; 32]);

impl PartialEq for CleSecrete {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl CleSecrete {
    pub fn generer() -> Self {
        let mut buffer = [0u8; 32];
        openssl::rand::rand_bytes(&mut buffer).expect("openssl::random::rand_bytes");
        CleSecrete (buffer)
    }
}

/// Rechiffre une cle asymetrique pour une nouvelle cle publique
pub fn rechiffrer_asymetrique_multibase(private_key: &PKey<Private>, public_key: &PKey<Public>, cle: &str)
    -> Result<String, Box<dyn Error>>
{
    let cle_rechiffree = {
        let cle_secrete = extraire_cle_secrete(private_key, cle)?;

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], public_key)?.to_vec(),
            Id::RSA => chiffrer_asymetrique_aesgcm(public_key, &cle_secrete.0[..])?,
            _ => Err(format!("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    };

    Ok(multibase::encode(Base::Base64, &cle_rechiffree[..]))
}

pub fn chiffrer_asymetrique_multibase(cle_secrete: CleSecrete, public_key: &PKey<Public>)
    -> Result<String, Box<dyn Error>>
{
    let cle_rechiffree = {
        // Determiner le type de cle. Supporte RSA et ED25519.
        match public_key.id() {
            Id::ED25519 => chiffrer_asymmetrique_ed25519(&cle_secrete.0[..], public_key)?.to_vec(),
            Id::RSA => chiffrer_asymetrique_aesgcm(public_key, &cle_secrete.0[..])?,
            _ => Err(format!("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    };

    Ok(multibase::encode(Base::Base64, &cle_rechiffree[..]))
}

pub fn extraire_cle_secrete(private_key: &PKey<Private>, cle: &str)
    -> Result<CleSecrete, Box<dyn Error>>
{
    let cle_secrete = {
        let cle_bytes: Vec<u8> = multibase::decode(cle)?.1;

        // Determiner le type de cle. Supporte RSA et ED25519.
        match private_key.id() {
            Id::ED25519 => dechiffrer_asymmetrique_ed25519(&cle_bytes[..], private_key),
            Id::RSA => dechiffrer_asymetrique_aesgcm(private_key, cle_bytes.as_slice()),
            _ => Err(format!("Unsupported key format - only Ed25519 and RSA are supported"))?
        }
    }?;

    Ok(cle_secrete)
}

pub trait MgsCipherData {
    fn dechiffrer_cle(&mut self, cle_privee: &PKey<Private>) -> Result<(), Box<dyn Error>>;
}

pub trait MgsCipherKeys {

    fn get_dechiffrage(&self, enveloppe_demandeur: Option<&EnveloppeCertificat>)
        -> Result<DechiffrageInterMillegrille, String>;

    fn get_commande_sauvegarder_cles(
        &self,
        domaine: &str,
        partition: Option<String>,
        identificateurs_document: HashMap<String, String>,
    ) -> Result<CommandeSauvegarderCle, String>;

    /// Retourne la valeur chiffree de la cle de millegrille
    /// Note : pour Ed25519, retourne la cle peer publique.
    fn get_cle_millegrille(&self) -> Option<String>;
}

pub trait CipherMgs<K: MgsCipherKeys> {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String>;
    fn finalize(self, out: &mut [u8]) -> Result<(usize, K), String>;
    // fn get_cipher_keys(&self) -> Result<K, String>;
}

pub trait DecipherMgs<M: MgsCipherData> {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, String>;
    fn finalize(self, out: &mut [u8]) -> Result<usize, String>;
}

#[async_trait]
pub trait CleChiffrageHandler {
    /// Retourne les certificats qui peuvent etre utilises pour chiffrer une cle secrete.
    /// Devrait inclure le certificat de MilleGrille avec flag est_cle_millegrille==true.
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey>;

    /// Recycle les certificats de chiffrage - fait une requete pour obtenir les certs courants
    async fn charger_certificats_chiffrage<M>(&self, middleware: &M)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages;

    /// Recoit un certificat de chiffrage
    async fn recevoir_certificat_chiffrage<M>(&self, middleware: &M, message: &MessageSerialise) -> Result<(), String>
        where M: ConfigMessages;
}

/// Permet de recuperer un Cipher deja initalise avec les certificats de MaitreDesCles.
#[async_trait]
pub trait Chiffreur<C: CipherMgs<K>, K: MgsCipherKeys>: CleChiffrageHandler {
    /// Recupere un cipher initialise avec les cles publiques
    fn get_cipher(&self) -> Result<C, Box<dyn Error>>;
}

/// Permet de recuperer un Decipher deja initialise pour une cle
#[async_trait]
pub trait Dechiffreur<D: DecipherMgs<M>, M: MgsCipherData>: IsConfigurationPki + Send + Sync {
    /// Appel au MaitreDesCles pour une version dechiffrable de la cle
    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<M, Box<dyn Error>>;

    /// Cle privee locale pour dechiffrage
    // fn get_enveloppe_privee_dechiffrage(&self) -> Arc<EnveloppePrivee>;

    /// Retourne une instance de Decipher pleinement initialisee et prete a dechiffrer
    async fn get_decipher(&self, hachage_bytes: &str) -> Result<D, Box<dyn Error>>;
}

pub trait ChiffrageFactory {
    /// Retourne le chiffreur recommande courant
    fn get_chiffreur(&self) -> Result<CipherMgs4, String>;

    // Toutes les versions supportees (requis pour le dechiffrage)

    fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String>;
    // fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String>;
    fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String>;
}

/// Structure qui implemente tous les ciphers disponibles (utilise par middleware)
pub struct ChiffrageFactoryImpl {
    pub cles_chiffrage: Mutex<HashMap<String, FingerprintCertPublicKey>>,
    enveloppe_privee: Arc<EnveloppePrivee>,
}

impl ChiffrageFactoryImpl {
    pub fn new(cles_chiffrage: HashMap<String, FingerprintCertPublicKey>, enveloppe_privee: Arc<EnveloppePrivee>) -> Self {
        ChiffrageFactoryImpl {
            cles_chiffrage: Mutex::new(cles_chiffrage),
            enveloppe_privee
        }
    }
}

impl ChiffrageFactory for ChiffrageFactoryImpl {
    fn get_chiffreur(&self) -> Result<CipherMgs4, String> {
        self.get_chiffreur_mgs4()
    }

    fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String> {
        let fp_public_keys = self.get_publickeys_chiffrage();
        match CipherMgs2::new(&fp_public_keys) {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("ChiffrageFactoryImpl.get_chiffreur_mgs2 Erreur {:?}", e))
        }
    }

    // fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String> {
    //     let fp_public_keys = self.get_publickeys_chiffrage();
    //     match CipherMgs3::new(&fp_public_keys) {
    //         Ok(c) => Ok(c),
    //         Err(e) => Err(format!("ChiffrageFactoryImpl.get_chiffreur_mgs2 Erreur {:?}", e))
    //     }
    // }

    fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String> {
        let fp_public_keys = self.get_publickeys_chiffrage();
        match CipherMgs4::new(&fp_public_keys) {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("ChiffrageFactoryImpl.get_chiffreur_mgs2 Erreur {:?}", e))
        }
    }
}

#[async_trait]
impl CleChiffrageHandler for ChiffrageFactoryImpl {

    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }

    async fn charger_certificats_chiffrage<M>(&self, middleware: &M)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages
    {
        debug!("Charger les certificats de maitre des cles pour chiffrage");

        // Reset certificats maitredescles. Reinserer cert millegrille immediatement.
        {
            let mut guard = self.cles_chiffrage.lock().expect("lock");
            guard.clear();

            // Reinserer certificat de millegrille
            let env_privee = middleware.get_enveloppe_signature();
            let mut fingerprint_cert = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA").pop().expect("fingerprint key CA");
            fingerprint_cert.est_cle_millegrille = true;  // S'assurer d'avoir le flag CA
            let fingerprint = fingerprint_cert.fingerprint.clone();
            guard.insert(fingerprint, fingerprint_cert);

            debug!("charger_certificats_chiffrage Reload certificats maitre des cles, presentement CA : {:?}", *guard);
        }

        emettre_commande_certificat_maitredescles(middleware).await?;

        // Donner une chance aux certificats de rentrer
        tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        // Verifier si on a au moins un certificat
        let nb_certs = self.cles_chiffrage.lock().expect("lock").len();
        if nb_certs <= 1 {  // 1 => le cert millegrille est deja charge
            Err(format!("Echec, aucuns certificats de maitre des cles recus"))?
        } else {
            debug!("On a {} certificats de maitre des cles valides", nb_certs);
        }

        Ok(())
    }

    async fn recevoir_certificat_chiffrage<M>(&self, middleware: &M, message: &MessageSerialise) -> Result<(), String>
        where M: ConfigMessages
    {
        let cert_chiffrage = match &message.certificat {
            Some(c) => c.clone(),
            None => {
                error!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait");
                Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
            }
        };

        // Valider le certificat
        if ! cert_chiffrage.presentement_valide {
            error!("recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete");
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
        }

        if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
            error!("recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete");
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
        }

        info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());

        // Stocker cles chiffrage du maitre des cles
        {
            let fps = match cert_chiffrage.fingerprint_cert_publickeys() {
                Ok(f) => f,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cert_chiffrage.fingerprint_cert_publickeys: {:?}", e))?
            };
            let mut guard = match self.cles_chiffrage.lock() {
                Ok(g) => g,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cles_chiffrage.lock(): {:?}", e))?
            };
            for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
                guard.insert(fp.fingerprint.clone(), fp.clone());
            }

            // S'assurer d'avoir le certificat de millegrille local
            let enveloppe_privee = middleware.get_configuration_pki().get_enveloppe_privee();
            let enveloppe_ca = &enveloppe_privee.enveloppe_ca;
            let public_keys_ca = match enveloppe_ca.fingerprint_cert_publickeys() {
                Ok(p) => p,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur enveloppe_ca.fingerprint_cert_publickeys: {:?}", e))?
            }.pop();
            if let Some(mut pk_ca) = public_keys_ca {
                pk_ca.est_cle_millegrille = true;
                guard.insert(pk_ca.fingerprint.clone(), pk_ca);
            }

            debug!("Certificats chiffrage maj {:?}", guard);
        }

        Ok(())
    }
}

/// Genere un Vec de nb_bytes aleatoires.
pub fn random_vec(nb_bytes: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.reserve(nb_bytes);

    let mut rnd = rand::thread_rng();

    // Extraire bytes par groupe de taille max (32)
    let nb_loops = nb_bytes / 32;
    let restant = nb_bytes - (nb_loops * 32);
    for _ in 0..nb_loops {
        let rnd_bytes: [u8; 32] = rnd.gen();
        v.extend_from_slice(&rnd_bytes[0..32]);
    }

    // Ajouter bytes manquants
    if restant > 0 {
        for _ in 0..restant {
            let byte: u8 = rnd.gen();
            v.push(byte);
        }
    }

    v
}

pub type ChiffreurMgs2 = dyn Chiffreur<CipherMgs2, Mgs2CipherKeys>;
// pub type ChiffreurMgs3 = dyn Chiffreur<CipherMgs3, Mgs3CipherKeys>;
pub type ChiffreurMgs4 = dyn Chiffreur<CipherMgs4, Mgs4CipherKeys>;

pub type ChiffreurMgsCurrent = ChiffreurMgs4;
pub type CipherMgsCurrent = CipherMgs4;
pub type MgsCipherKeysCurrent = Mgs4CipherKeys;
pub type MgsCipherDataCurrent = Mgs4CipherData;

const MAXLEN_DATA_CHIFFRE: usize = 1024 * 1024 * 3;

// Chiffrer data avec une cle secrete
pub fn chiffrer_data<M,S>(middleware: &M, data_dechiffre: S) -> Result<(DataChiffre, DechiffrageInterMillegrille), Box<dyn Error>>
    where M: ChiffrageFactoryTrait, S: Serialize
{
    let mut buf_output = [0u8; MAXLEN_DATA_CHIFFRE];  // 1MB

    // Extraire bytes, compresser
    let data_vec = {
        let data_vec = serde_json::to_vec(&data_dechiffre)?;
        let mut compressor = GzEncoder::new(Vec::new(), Compression::default());
        compressor.write_all(&data_vec[..])?;
        compressor.finish()?
    };

    if data_vec.len() > MAXLEN_DATA_CHIFFRE {
        Err(format!("Data depasse limite buffer ({} bytes)", MAXLEN_DATA_CHIFFRE))?
    }

    // Compresser les donnees
    let mut chiffreur = middleware.get_chiffrage_factory().get_chiffreur_mgs4()?;
    let taille_output = chiffreur.update(&data_vec[..], &mut buf_output[..])?;
    let (output_final, keys) = chiffreur.finalize(&mut buf_output[taille_output..])?;

    let data_chiffre = general_purpose::STANDARD_NO_PAD.encode(&buf_output[..taille_output+output_final]);

    let data_output = DataChiffre {
        ref_hachage_bytes: Some(keys.hachage_bytes.clone()),
        data_chiffre,
        format: FormatChiffrage::mgs4,
        header: Some(keys.header.clone()),
        tag: None,
    };

    let dechiffrage = keys.get_dechiffrage(None)?;

    Ok((data_output, dechiffrage))
}
