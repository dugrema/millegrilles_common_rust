use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use mongodb::{bson::{Bson, Document, doc, to_bson}, Collection};
use mongodb::bson as bson;
use mongodb::options::UpdateOptions;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use futures::stream::FuturesUnordered;
use openssl::x509::store::X509Store;
use openssl::x509::X509;

use crate::backup::BackupStarter;
use crate::certificats::{charger_enveloppe, emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use crate::chiffrage::{ChiffrageFactoryImpl, Chiffreur, ChiffrageFactory, CleChiffrageHandler, Dechiffreur, MgsCipherData, ChiffreurMgs4, ChiffreurMgs2, MgsCipherDataCurrent};
use crate::chiffrage_aesgcm::CipherMgs2;
// use crate::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::configuration::{charger_configuration, charger_configuration_avec_db, ConfigMessages, ConfigurationMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::domaines::GestionnaireDomaine;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageAction, RoutageMessageReponse};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl, verifier_erreur_duplication_mongo};
use crate::rabbitmq_dao::{Callback, EventMq, NamedQueue, QueueType, RabbitMqExecutor, run_rabbitmq, TypeMessageOut};
use crate::redis_dao::RedisDao;
use crate::transactions::{EtatTransaction, marquer_transaction, Transaction, TransactionImpl, transmettre_evenement_persistance};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};
use crate::recepteur_messages::{MessageValideAction, recevoir_messages, /*task_requetes_certificats, */ TypeMessage};

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareMessage>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

pub trait RedisTrait {
    fn get_redis(&self) -> &RedisDao;
}

pub trait ChiffrageFactoryTrait: CleChiffrageHandler {
    fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl;
}

/// Super-trait pour tous les traits implementes par Middleware
pub trait MiddlewareMessages:
    ValidateurX509 + GenerateurMessages + ConfigMessages + IsConfigurationPki +
    IsConfigNoeud + FormatteurMessage + EmetteurCertificat +
    VerificateurMessage + RedisTrait + ChiffrageFactoryTrait
    // + Chiffreur<CipherMgs3, Mgs3CipherKeys> + Dechiffreur<DecipherMgs3, Mgs3CipherData>
{}

pub trait Middleware:
    MiddlewareMessages + MongoDao + BackupStarter
{}

pub trait IsConfigurationPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;
}

pub struct MiddlewareRessources {
    pub configuration: Arc<Box<ConfigurationMessagesDb>>,
    pub validateur: Arc<ValidateurX509Impl>,
    pub rabbitmq: Arc<RabbitMqExecutor>,
    pub generateur_messages: Arc<GenerateurMessagesImpl>
}

pub fn configurer() -> MiddlewareRessources {
    let configuration = Arc::new(Box::new(charger_configuration_avec_db().expect("charger_configuration_avec_db")));

    let pki = configuration.get_configuration_pki();
    let securite = match pki.get_enveloppe_privee().get_exchanges().expect("exchanges") {
        Some(exchanges) => {
            if exchanges.contains(&SECURITE_4_SECURE.to_string()) { Securite::L4Secure }
            else if exchanges.contains(&SECURITE_3_PROTEGE.to_string()) { Securite::L3Protege }
            else if exchanges.contains(&SECURITE_2_PRIVE.to_string()) { Securite::L2Prive }
            else if exchanges.contains(&SECURITE_1_PUBLIC.to_string()) { Securite::L1Public }
            else {
                panic!("Niveau de securite non-supporte")
            }
        },
        None => panic!("Certificat sans exchanges, aucun acces a MQ")
    };

    // Preparer instances utils
    let validateur = pki.get_validateur();

    // Connecter au middleware mongo et MQ
    let rabbitmq = Arc::new(RabbitMqExecutor::new(securite.into()));

    let generateur_messages = Arc::new(GenerateurMessagesImpl::new(
        configuration.get_configuration_pki(),
        rabbitmq.clone()
    ));

    MiddlewareRessources { configuration, validateur, rabbitmq, generateur_messages }
}

// pub fn configurer_messages(
//     queues: Vec<QueueType>,
//     listeners: Option<Mutex<Callback<'static, EventMq>>>,
//     securite: Securite
// ) -> (Arc<ConfigurationMessages>, Arc<ValidateurX509Impl>, RabbitMqExecutorConfig, GenerateurMessagesImpl) {
//     let configuration = Arc::new(charger_configuration().expect("Erreur configuration"));
//
//     let pki = configuration.get_configuration_pki();
//
//     // Preparer instances utils
//     let validateur = pki.get_validateur();
//
//     todo!("fix me")
//     // Connecter au middleware MQ
//     // let mq_executor_config = executer_mq(
//     //     configuration.clone(),
//     //     Some(queues),
//     //     listeners,
//     //     securite
//     // ).expect("Erreur demarrage MQ");
//     //
//     // let generateur_messages = GenerateurMessagesImpl::new(
//     //     configuration.get_configuration_pki(),
//     //     &mq_executor_config.executor
//     // );
//     //
//     // (configuration, validateur, mq_executor_config, generateur_messages)
// }

// pub fn configurer(
//     queues: Vec<QueueType>,
//     listeners: Option<Mutex<Callback<'static, EventMq>>>
// ) -> (Arc<ConfigurationMessagesDb>, Arc<ValidateurX509Impl>, Arc<MongoDaoImpl>, RabbitMqExecutorConfig, GenerateurMessagesImpl) {
//     let configuration = Arc::new(charger_configuration_avec_db().expect("Erreur configuration"));
//
//     let pki = configuration.get_configuration_pki();
//
//     // Preparer instances utils
//     let validateur = pki.get_validateur();
//
//     // Connecter au middleware mongo et MQ
//     let mongo: Arc<MongoDaoImpl> = Arc::new(initialiser_mongodb(configuration.as_ref()).expect("Erreur connexion MongoDB"));
//     let mq_executor_config = executer_mq(
//         configuration.clone(),
//         Some(queues),
//         listeners,
//         Securite::L3Protege
//     ).expect("Erreur demarrage MQ");
//
//     let generateur_messages = GenerateurMessagesImpl::new(
//         configuration.get_configuration_pki(),
//         &mq_executor_config.executor
//     );
//
//     (configuration, validateur, mongo, mq_executor_config, generateur_messages)
// }

// Middleware de base avec validateur et generateur de messages
pub struct MiddlewareMessage {
    ressources: MiddlewareRessources,
    redis: RedisDao,
    chiffrage_factory: Arc<ChiffrageFactoryImpl>,
}

impl MiddlewareMessages for MiddlewareMessage {}

impl RedisTrait for MiddlewareMessage {
    fn get_redis(&self) -> &RedisDao {
        &self.redis
    }
}

#[async_trait]
impl ValidateurX509 for MiddlewareMessage {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        let enveloppe = self.ressources.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Conserver dans redis (reset TTL)
        match self.redis.save_certificat(&enveloppe).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, usize) {
        let (enveloppe, compteur) = self.ressources.validateur.cacher(certificat).await;
        if compteur == 0 {
            // Le certificat n'etait pas dans le cache, on s'assure qu'il existe dans redis
            match self.redis.save_certificat(enveloppe.as_ref()).await {
                Ok(()) => debug!("Certificat {} sauvegarde dans redis", enveloppe.fingerprint()),
                Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint(), e)
            }
        }

        (enveloppe, compteur)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.ressources.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Tenter de le charger de redis
                match charger_certificat_redis(self, fingerprint).await {
                    Some(c) => Some(c),
                    None => {
                        // Dernier recours, tenter de charger certificat via MQ
                        todo!("charger certificat via MQ")
                    }
                }
            }
        }
    }

    fn idmg(&self) -> &str {
        self.ressources.validateur.idmg()
    }

    fn ca_pem(&self) -> &str {
        self.ressources.validateur.ca_pem()
    }

    fn ca_cert(&self) -> &X509 {
        self.ressources.validateur.ca_cert()
    }

    fn store(&self) -> &X509Store {
        self.ressources.validateur.store()
    }

    fn store_notime(&self) -> &X509Store {
        self.ressources.validateur.store_notime()
    }

    async fn entretien_validateur(&self) {
        self.ressources.validateur.entretien_validateur().await;
    }
}

pub async fn charger_certificat_redis<M>(middleware: &M, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>>
    where M: RedisTrait + ValidateurX509
{
    let redis = middleware.get_redis();
    let redis_certificat = match redis.get_certificat(fingerprint).await {
        Ok(c) => match c {
            Some(c) => c,
            None => return None
        },
        Err(e) => {
            warn!("MiddlewareDbPki.get_certificat (2) Erreur acces certificat via redis : {:?}", e);
            return None
        }
    };

    // Le certificat est dans redis, on le sauvegarde localement en chargeant l'enveloppe
    let ca_pem = match &redis_certificat.ca {
        Some(c) => Some(c.as_str()),
        None => None
    };

    match middleware.charger_enveloppe(&redis_certificat.pems, None, ca_pem).await {
        Ok(c) => Some(c),
        Err(e) => {
            warn!("MiddlewareDbPki.get_certificat (1) Erreur acces certificat via redis : {:?}", e);
            None
        }
    }
}

impl IsConfigurationPki for MiddlewareMessage {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.ressources.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl FormatteurMessage for MiddlewareMessage {}

#[async_trait]
impl GenerateurMessages for MiddlewareMessage {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool {
        self.ressources.generateur_messages.mq_disponible()
    }

    fn set_regeneration(&self) {
        self.ressources.generateur_messages.set_regeneration();
    }

    fn reset_regeneration(&self) {
        self.ressources.generateur_messages.reset_regeneration();
    }

    fn get_mode_regeneration(&self) -> bool {
        self.ressources.generateur_messages.as_ref().get_mode_regeneration()
    }

    fn get_securite(&self) -> &Securite {
        self.ressources.generateur_messages.get_securite()
    }
}

// #[async_trait]
// impl CleChiffrageHandler for MiddlewareMessage {
//
//     fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
//         let guard = self.cles_chiffrage.lock().expect("lock");
//
//         // Copier les cles (extraire du mutex), retourner dans un vecteur
//         let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();
//
//         vals
//     }
//
//     async fn charger_certificats_chiffrage(&self, cert_local: &EnveloppeCertificat) -> Result<(), Box<dyn Error>> {
//         debug!("Charger les certificats de maitre des cles pour chiffrage");
//
//         // Reset certificats maitredescles. Reinserer cert millegrille immediatement.
//         {
//             let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
//             let mut guard = self.cles_chiffrage.lock().expect("lock");
//             guard.clear();
//
//             // Reinserer certificat de millegrille
//             let env_privee = self.get_enveloppe_privee();
//             let fingerprint_cert = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
//             let fingerprint = fingerprint_cert[0].fingerprint.clone();
//             guard.insert(fingerprint, fingerprint_cert[0].clone());
//         }
//
//         emettre_commande_certificat_maitredescles(self).await?;
//
//         // Donner une chance aux certificats de rentrer
//         tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;
//
//         // Verifier si on a au moins un certificat
//         let nb_certs = self.cles_chiffrage.lock().expect("lock").len();
//         if nb_certs <= 1 {  // 1 => le cert millegrille est deja charge
//             Err(format!("Echec, aucuns certificats de maitre des cles recus"))?
//         } else {
//             debug!("On a {} certificats de maitre des cles valides", nb_certs);
//         }
//
//         Ok(())
//     }
//
//     async fn recevoir_certificat_chiffrage(&self, message: &MessageSerialise) -> Result<(), String> {
//         let cert_chiffrage = match &message.certificat {
//             Some(c) => c.clone(),
//             None => {
//                 Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
//             }
//         };
//
//         // Valider le certificat
//         if ! cert_chiffrage.presentement_valide {
//             Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
//         }
//
//         if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
//             Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
//         }
//
//         info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());
//
//         // Stocker cles chiffrage du maitre des cles
//         {
//             let fps = match cert_chiffrage.fingerprint_cert_publickeys() {
//                 Ok(f) => f,
//                 Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cert_chiffrage.fingerprint_cert_publickeys: {:?}", e))?
//             };
//             let mut guard = match self.cles_chiffrage.lock() {
//                 Ok(g) => g,
//                 Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cles_chiffrage.lock(): {:?}", e))?
//             };
//             for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
//                 guard.insert(fp.fingerprint.clone(), fp.clone());
//             }
//
//             // S'assurer d'avoir le certificat de millegrille local
//             let enveloppe_privee = self.configuration.get_configuration_pki().get_enveloppe_privee();
//             let enveloppe_ca = &enveloppe_privee.enveloppe_ca;
//             let public_keys_ca = match enveloppe_ca.fingerprint_cert_publickeys() {
//                 Ok(p) => p,
//                 Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur enveloppe_ca.fingerprint_cert_publickeys: {:?}", e))?
//             }.pop();
//             if let Some(pk_ca) = public_keys_ca {
//                 guard.insert(pk_ca.fingerprint.clone(), pk_ca);
//             }
//
//             debug!("Certificats chiffrage maj {:?}", guard);
//         }
//
//         Ok(())
//     }
// }

// #[async_trait]
// impl Chiffreur<CipherMgs3, Mgs3CipherKeys> for MiddlewareMessage {
//
//     fn get_cipher(&self) -> Result<CipherMgs3, Box<dyn Error>> {
//         let fp_public_keys = self.get_publickeys_chiffrage();
//         Ok(CipherMgs3::new(&fp_public_keys)?)
//     }
//
// }
//
// #[async_trait]
// impl Dechiffreur<DecipherMgs3, Mgs3CipherData> for MiddlewareMessage {
//
//     async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs3CipherData, Box<dyn Error>> {
//         let requete = {
//             let mut liste_hachage_bytes = Vec::new();
//             liste_hachage_bytes.push(hachage_bytes);
//             json!({
//                 "liste_hachage_bytes": liste_hachage_bytes,
//             })
//         };
//         let routage = RoutageMessageAction::new("MaitreDesCles", "dechiffrage");
//         let reponse_cle_rechiffree = self.transmettre_requete(routage, &requete).await?;
//
//         error!("Reponse reechiffrage cle : {:?}", reponse_cle_rechiffree);
//
//         let contenu_dechiffrage = match reponse_cle_rechiffree {
//             TypeMessage::Valide(m) => m.message.get_msg().map_contenu::<ReponseDechiffrageCle>(None)?,
//             _ => Err(format!("Mauvais type de reponse : {:?}", reponse_cle_rechiffree))?
//         };
//
//         contenu_dechiffrage.to_cipher_data()
//     }
//
//     async fn get_decipher(&self, hachage_bytes: &str) -> Result<DecipherMgs3, Box<dyn Error>> {
//         let mut info_cle = self.get_cipher_data(hachage_bytes).await?;
//         let env_privee = self.get_enveloppe_privee();
//         let cle_privee = env_privee.cle_privee();
//         info_cle.dechiffrer_cle(cle_privee)?;
//
//         Ok(DecipherMgs3::new(&info_cle)?)
//     }
//
// }

impl ConfigMessages for MiddlewareMessage {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.ressources.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.ressources.configuration.get_configuration_pki()
    }
}

impl IsConfigNoeud for MiddlewareMessage {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.ressources.configuration.get_configuration_noeud()
    }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareMessage {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;
        let exchanges: Vec<Securite> = securite_cascade_public(
            generateur_message.get_securite()).iter().map(|s| s.to_owned())
            .collect();

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat")
            .exchanges(exchanges)
            .build();

        // Sauvegarder dans redis
        match self.redis.save_certificat(enveloppe_certificat).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDb.emettre_certificat Erreur sauvegarde certificat local sous redis : {:?}", e)
        }

        match generateur_message.emettre_evenement(routage, &message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e)),
        }
    }
}

impl VerificateurMessage for MiddlewareMessage {
    fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
        verifier_message(message, self, options)
    }
}

impl ChiffrageFactoryTrait for MiddlewareMessage {
    fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
        self.chiffrage_factory.as_ref()
    }
}

#[async_trait]
impl CleChiffrageHandler for MiddlewareMessage {
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        self.chiffrage_factory.get_publickeys_chiffrage()
    }

    async fn charger_certificats_chiffrage<M>(&self, middleware: &M, cert_local: &EnveloppeCertificat, env_privee: Arc<EnveloppePrivee>)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages
    {
        self.chiffrage_factory.charger_certificats_chiffrage(middleware, cert_local, env_privee).await
    }

    async fn recevoir_certificat_chiffrage<M>(&self, middleware: &M, message: &MessageSerialise) -> Result<(), String>
        where M: ConfigMessages
    {
        self.chiffrage_factory.recevoir_certificat_chiffrage(middleware, message).await
    }
}

impl ChiffrageFactory for MiddlewareMessage {
    fn get_chiffreur(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur()
    }

    fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String> {
        self.chiffrage_factory.get_chiffreur_mgs2()
    }

    // fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String> {
    //     self.chiffrage_factory.get_chiffreur_mgs3()
    // }

    fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur_mgs4()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseCertificatMaitredescles {
    certificat: Vec<String>,
    // certificat_millegrille: String,
}

impl ReponseCertificatMaitredescles {
    pub async fn get_enveloppe_maitredescles<V>(&self, validateur: &V) -> Result<Arc<EnveloppeCertificat>, Box<dyn Error>>
    where
        V: ValidateurX509,
    {
        Ok(validateur.charger_enveloppe(&self.certificat, None, None).await?)
    }
}

// #[derive(Clone, Debug, Deserialize)]
// pub struct ReponseDechiffrageCle {
//     acces: String,
//     pub cles: Option<HashMap<String, ReponseDechiffrageCleInfo>>,
// }
//
// #[derive(Clone, Debug, Deserialize)]
// pub struct ReponseDechiffrageCleInfo {
//     acces: Option<String>,
//     cle: String,
//     domaine: String,
//     format: String,
//     hachage_bytes: Option<String>,
//     identificateurs_document: Option<HashMap<String, String>>,
//     header: String,
// }
//
// impl ReponseDechiffrageCle {
//     pub fn to_cipher_data(&self) -> Result<Mgs3CipherData, Box<dyn Error>> {
//         match &self.cles {
//             Some(cles) => {
//                 if cles.len() == 1 {
//                     let (_, cle) = cles.iter().next().expect("cle");
//                     cle.to_cipher_data()
//                 } else {
//                     Err(String::from("Plusieurs cles presentes"))?
//                 }
//             },
//             None => {
//                 Err(String::from("Aucunes cles presentes"))?
//             }
//         }
//     }
// }
//
// impl ReponseDechiffrageCleInfo {
//     pub fn to_cipher_data(&self) -> Result<MgsCipherDataCurrent, Box<dyn Error>> {
//         Mgs3CipherData::new(&self.cle, &self.header)
//     }
// }

pub async fn upsert_certificat(enveloppe: &EnveloppeCertificat, collection: Collection<Document>, dirty: Option<bool>) -> Result<Option<String>, String> {
    let fingerprint = enveloppe.fingerprint();

    let filtre = doc! { "fingerprint": fingerprint };

    let certificat = enveloppe.certificat();
    let (idmg, est_ca) = match enveloppe.est_ca()? {
        true => {
            debug!("Certificat self-signed, on ajout marqueurs de millegrille");
            (enveloppe.calculer_idmg()?, true)
        },
        false => (enveloppe.idmg()?, false)
    };

    // Separer les fingerprint et pems de la chaine.
    let fp_certs = enveloppe.get_pem_vec();
    let mut certs = Vec::new();
    let mut chaine = Vec::new();
    for fp_cert in fp_certs {
        chaine.push(fp_cert.fingerprint);
        certs.push(fp_cert.pem);
    }

    let date_courante = chrono::Utc::now();

    let mut doc_sujet = bson::document::Document::new();
    for (key, value) in enveloppe.subject().expect("map sujet") {
        doc_sujet.insert(key, value);
    }

    let mut set_on_insert = doc! {
        "fingerprint": fingerprint,
        "fingerprint_pk": enveloppe.fingerprint_pk().expect("Erreur fingerprint_pk"),
        "certificat": certs,
        "chaine": chaine,
        "not_valid_after": enveloppe.not_valid_after().expect("Erreur not_valid_after"),
        "not_valid_before": enveloppe.not_valid_before().expect("Erreur not_valid_before"),
        "sujet": doc_sujet,
        "_mg-creation": date_courante,
        "est_ca": est_ca,
        "idmg": idmg,
    };

    // Inserer extensions millegrilles
    if let Some(exchanges) = enveloppe.get_exchanges().expect("Erreur lecture exchanges") {
        set_on_insert.insert("exchanges", to_bson(exchanges).expect("Erreur conversion exchanges"));
    }
    if let Some(domaines) = enveloppe.get_domaines().expect("Erreur lecture domaines") {
        set_on_insert.insert("domaines", to_bson(domaines).expect("Erreur conversion domaines"));
    }
    if let Some(roles) = enveloppe.get_roles().expect("Erreur lecture roles") {
        set_on_insert.insert("roles", to_bson(roles).expect("Erreur conversion roles"));
    }
    if let Some(user_id) = enveloppe.get_user_id().expect("Erreur lecture user_id") {
        set_on_insert.insert("user_id", to_bson(user_id).expect("Erreur conversion user_id"));
    }
    if let Some(delegation_globale) = enveloppe.get_delegation_globale().expect("Erreur lecture delegation_globale") {
        set_on_insert.insert("delegation_globale", to_bson(delegation_globale).expect("Erreur conversion delegation_globale"));
    }
    if let Some(delegation_domaines) = enveloppe.get_delegation_domaines().expect("Erreur lecture delegation_domaines") {
        set_on_insert.insert("delegation_domaines", to_bson(delegation_domaines).expect("Erreur conversion delegation_domaines"));
    }
    if let Some(c) = enveloppe.get_pem_ca()? {
        set_on_insert.insert("ca", to_bson(&c).expect("Erreur conversion certificat CA"));
    }

    let mut set = doc! {};

    match dirty {
        Some(b) => {
            set.insert("dirty", Bson::Boolean(b));
        },
        None => {
            set_on_insert.insert("dirty", Bson::Boolean(true));
        },
    };

    let ops = doc! {
        "$set": set,
        "$setOnInsert": set_on_insert,
        "$currentDate": { "_mg-derniere-modification": true },
    };
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();

    let update_result = collection.update_one(filtre, ops, options).await;
    match update_result {
        Ok(r) => {
            debug!("Update result : {:?}", r);
            match r.upserted_id {
                Some(upserted_id) => {
                    let uid = upserted_id.as_object_id().expect("object_id").to_hex();
                    Ok(Some(uid))
                },
                None => Ok(None),
            }
        },
        Err(e) => {
            Err(format!("Erreur sauvegarde enveloppe certificat : {:?}", e))
        }
    }
}

pub async fn emettre_presence_domaine(middleware: &(impl ValidateurX509 + GenerateurMessages + ConfigMessages), nom_domaine: &str) -> Result<(), Box<dyn Error>> {

    let instance_id = match &middleware.get_configuration_noeud().instance_id {
        Some(n) => Some(n.clone()),
        None => None,
    };

    let message = json!({
        // "idmg": middleware.idmg(),
        "instance_id": instance_id,
        "domaine": nom_domaine,
        "sous_domaines": None::<String>,
        "exchanges_routing": None::<String>,
        // "exchanges_routing": {
        //     "1.public": ["requete.Principale.test"],
        //     "2.prive": ["requete.Principale.test"],
        //     "3.protege": ["requete.Principale.test"],
        // },
        "primaire": true,
    });

    let routage = RoutageMessageAction::builder(nom_domaine, EVENEMENT_PRESENCE_DOMAINE)
        .exchanges(vec![Securite::L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &message).await?)
}

pub async fn thread_emettre_presence_domaine<M>(middleware: Arc<M>, nom_domaine: String)
    where M: ConfigMessages + GenerateurMessages + ValidateurX509 + 'static
{
    info!("middleware.thread_emettre_presence_domaine : Debut thread");

    // Attente initiale
    tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
    loop {
        match emettre_presence_domaine(middleware.as_ref(), nom_domaine.as_str()).await {
            Ok(()) => (),
            Err(e) => warn!("Erreur emission presence du domaine : {}", e),
        };
        tokio::time::sleep(tokio::time::Duration::new(120, 0)).await;
    }

    // info!("middleware.thread_emettre_presence_domaine : Fin thread");
}

#[async_trait]
pub trait EmetteurCertificat: Send + Sync {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String>;
}

#[async_trait]
impl EmetteurCertificat for ValidateurX509Impl {
    async fn emettre_certificat(&self, _: &impl GenerateurMessages) -> Result<(), String> {
        todo!()
    }
}

pub fn formatter_message_certificat(enveloppe: &EnveloppeCertificat) -> Result<ReponseEnveloppe, String> {
    let pem_vec = enveloppe.get_pem_vec();
    let mut pems = Vec::new();
    for cert in pem_vec {
        pems.push(cert.pem);
    };

    // let reponse = json! ({
    //     "chaine_pem": pems,
    //     "fingerprint": enveloppe.fingerprint(),
    // });
    //
    // reponse

    let reponse = ReponseEnveloppe {
        chaine_pem: pems,
        fingerprint: enveloppe.fingerprint().to_owned(),
        ca_pem: enveloppe.get_pem_ca()?,
    };

    Ok(reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseEnveloppe {
    pub chaine_pem: Vec<String>,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

/// Sauvegarde une nouvelle transaction et de la traite immediatement
pub async fn sauvegarder_traiter_transaction<M, G>(middleware: &M, m: MessageValideAction, gestionnaire: &G)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        G: GestionnaireDomaine
{
    let nom_collection_transactions = match gestionnaire.get_collection_transactions() {
        Some(n) => n,
        None => {
            return Err(format!("middleware.sauvegarder_traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))
        }
    };

    let doc_transaction = match sauvegarder_transaction(middleware, &m, nom_collection_transactions.as_str()).await {
        Ok(d) => Ok(d),
        Err(e) => Err(format!("middleware.sauvegarder_traiter_transaction Erreur sauvegarde transaction : {:?}", e))
    }?;

    // Convertir message en format transaction
    let transaction = TransactionImpl::new(doc_transaction, m.message.certificat);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();

    // Traiter transaction
    let reponse = gestionnaire.aiguillage_transaction(middleware, transaction).await?;

    marquer_transaction(
        middleware,
        &nom_collection_transactions,
        uuid_transaction,
        EtatTransaction::Complete
    ).await?;

    Ok(reponse)
}

pub async fn sauvegarder_transaction_recue<M, C>(middleware: &M, m: MessageValideAction, nom_collection: C) -> Result<(), String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        C: AsRef<str>
{
    let entete = m.message.get_entete();

    match sauvegarder_transaction(middleware, &m, nom_collection.as_ref()).await {
        Ok(_) => (),
        Err(e) => Err(format!("Erreur sauvegarde transaction : {:?}", e))?
    }

    if let Some(domaine) = entete.domaine.as_ref() {
        if let Some(action) = entete.action.as_ref() {

            if let Some(c) = m.correlation_id.as_ref() {
                debug!("Transaction recue, trigger qui va repondre vers : {:?}/{:?}", m.reply_q.as_ref(), c);
            }

            transmettre_evenement_persistance(
                middleware,
                entete.uuid_transaction.as_str(),
                domaine.as_str(),
                action.as_str(),
                entete.partition.as_ref(),
                m.reply_q.as_ref(),
                m.correlation_id.as_ref()
            ).await?;
        }
    }

    Ok(())
}

pub async fn sauvegarder_transaction<M>(middleware: &M, m: &MessageValideAction, nom_collection: &str) -> Result<Document, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("Sauvegarder transaction avec document {:?}", &m.message);
    let msg = m.message.get_msg();

    // Serialiser le message en serde::Value - permet de convertir en Document bson
    let mut contenu_doc = match map_msg_to_bson(msg) {
        Ok(d) => d,
        Err(e) => Err(format!("Erreur conversion doc vers bson : {:?}", e))?
    };

    debug!("Transaction en format bson : {:?}", contenu_doc);

    let date_courante = chrono::Utc::now();
    let entete = &msg.entete;
    let uuid_transaction = entete.uuid_transaction.as_str();
    let estampille = &entete.estampille;
    let _ = match entete.domaine.as_ref() {
        Some(d) => d.as_str(),
        None => Err(format!("Domaine absent de la transaction {}", uuid_transaction))?,
    };
    let _ = match entete.action.as_ref() {
        Some(a) => a.as_str(),
        None => Err(format!("Action absente de la transaction {}", uuid_transaction))?,
    };
    let _ = match entete.partition.as_ref() {
        Some(p) => Some(p.as_str()),
        None => None,
    };

    let params_evenements = doc! {
        "document_persiste": date_courante,
        "_estampille": estampille.get_datetime(),
        "transaction_complete": false,
        "backup_flag": false,
        "signature_verifiee": date_courante,
    };

    debug!("evenements tags : {:?}", params_evenements);

    // let mut contenu_doc_mut = contenu_doc.as_document_mut().expect("mut");
    contenu_doc.insert("_evenements", params_evenements);

    contenu_doc.remove("_certificat");

    debug!("Inserer nouvelle transaction\n:{:?}", contenu_doc);

    let collection = middleware.get_collection(nom_collection)?;
    match collection.insert_one(&contenu_doc, None).await {
        Ok(_) => {
            debug!("Transaction sauvegardee dans collection de reception");
            Ok(())
        },
        Err(e) => {
            error!("Erreur sauvegarde transaction dans MongoDb : {:?}", e);
            //let kind = *e.kind.clone();
            let erreur_duplication = verifier_erreur_duplication_mongo(&*e.kind);
            if erreur_duplication {
                // Ok, duplicate. On peut traiter la transaction (si ce n'est pas deja fait).
                warn!("Transaction dupliquee (on va la traiter quand meme) : {:?}", uuid_transaction);
                Ok(())
            } else {
                Err(format!("Erreur sauvegarde transaction dans MongoDb : {:?}", &e))
            }
        }
    }?;

    Ok(contenu_doc)
}

pub fn map_msg_to_bson(msg: &MessageMilleGrille) -> Result<Document, Box<dyn Error>> {
    let val = match serde_json::to_value(msg) {
        Ok(v) => match v.as_object() {
            Some(o) => o.to_owned(),
            None => Err(format!("Erreur sauvegarde transaction, mauvais type objet JSON"))?,
        },
        Err(e) => Err(format!("Erreur sauvegarde transaction, conversion : {:?}", e))?,
    };

    let contenu_doc = match Document::try_from(val) {
        Ok(c) => Ok(c),
        Err(e) => {
            error!("Erreur conversion json -> bson\n{:?}", e.to_string());
            Err(format!("Erreur sauvegarde transaction, conversion json -> bson : {:?}", e))
        },
    }?;

    Ok(contenu_doc)
}

pub fn map_serializable_to_bson<S>(val_serializable: &S) -> Result<Document, Box<dyn Error>>
    where S: Serialize
{
    let val = match serde_json::to_value(val_serializable) {
        Ok(v) => match v.as_object() {
            Some(o) => o.to_owned(),
            None => Err(format!("Erreur sauvegarde transaction, mauvais type objet JSON"))?,
        },
        Err(e) => Err(format!("Erreur sauvegarde transaction, conversion : {:?}", e))?,
    };

    let contenu_doc = match Document::try_from(val) {
        Ok(c) => Ok(c),
        Err(e) => {
            error!("Erreur conversion json -> bson\n{:?}", e.to_string());
            Err(format!("Erreur sauvegarde transaction, conversion json -> bson : {:?}", e))
        },
    }?;

    Ok(contenu_doc)
}

/// Version speciale du middleware avec un acces a MongoDB
// pub fn preparer_middleware_message(
//     queues: Vec<QueueType>,
//     listeners: Option<Mutex<Callback<'static, EventMq>>>,
//     securite: Securite
// ) -> MiddlewareMessagesHooks {
//     let (
//         configuration,
//         validateur,
//         mq_executor_config,
//         generateur_messages
//     ) = configurer_messages(queues, listeners, securite);
//
//     let generateur_messages_arc = Arc::new(generateur_messages);
//
//     // Extraire le cert millegrille comme base pour chiffrer les cles secretes
//     let chiffrage_factory = {
//         let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
//         let cert_local = env_privee.enveloppe.as_ref();
//         let mut fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
//         let list_fp_ca = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
//         fp_certs.extend(list_fp_ca);
//
//         let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
//
//         for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
//             map.insert(f.fingerprint.clone(), f);
//         }
//
//         debug!("Map cles chiffrage : {:?}", map);
//
//         Arc::new(ChiffrageFactoryImpl::new(map, env_privee))
//     };
//
//     // let redis_url = match configuration.get_configuration_noeud().redis_url.as_ref() {
//     //     Some(u) => Some(u.as_str()),
//     //     None => None,
//     // };
//
//     let redis_dao = RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis");
//
//     let middleware = Arc::new(MiddlewareMessage {
//         configuration,
//         validateur: validateur.clone(),
//         generateur_messages: generateur_messages_arc.clone(),
//         // cles_chiffrage: Mutex::new(cles_chiffrage),
//         redis: redis_dao,
//         chiffrage_factory,
//     });
//
//     let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(1);
//     let (tx_messages_verif_reply, rx_messages_verif_reply) = mpsc::channel(1);
//     let (tx_triggers, rx_triggers) = mpsc::channel(1);
//
//     let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);
//
//     let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
//
//     let mq_executor = mq_executor_config.executor;  // Move
//     let mq_executor_rx = mq_executor_config.rx_queues;
//
//     futures.push(tokio::spawn(recevoir_messages(
//         middleware.clone(),
//         mq_executor_rx.rx_messages,
//         tx_messages_verifies.clone(),
//         tx_certificats_manquants.clone()
//     )));
//
//     futures.push(tokio::spawn(recevoir_messages(
//         middleware.clone(),
//         mq_executor_rx.rx_reply,
//         tx_messages_verif_reply.clone(),
//         tx_certificats_manquants.clone()
//     )));
//
//     futures.push(tokio::spawn(recevoir_messages(
//         middleware.clone(),
//         mq_executor_rx.rx_triggers,
//         tx_triggers,
//         tx_certificats_manquants.clone()
//     )));
//
//     // Thread requete certificats manquants
//     futures.push(tokio::spawn(task_requetes_certificats(
//         middleware.clone(),
//         rx_certificats_manquants,
//         mq_executor.tx_reply.clone(),
//         false
//     )));
//
//     MiddlewareMessagesHooks {
//         middleware, mq_executor,
//         rx_messages_verifies, rx_messages_verif_reply, rx_triggers, tx_certificats_manquants,
//         futures
//     }
// }

pub fn preparer_middleware_message() -> MiddlewareHooks {
    let ressources = configurer();

    let configuration = ressources.configuration.clone();

    // Extraire le cert millegrille comme base pour chiffrer les cles secretes
    let chiffrage_factory = {
        let env_privee = configuration.get_configuration_pki().get_enveloppe_privee();
        let cert_local = env_privee.enveloppe.as_ref();
        let mut fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
        let list_fp_ca = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
        fp_certs.extend(list_fp_ca);

        let mut map: HashMap<String, FingerprintCertPublicKey> = HashMap::new();
        for f in fp_certs.iter().filter(|c| c.est_cle_millegrille).map(|c| c.to_owned()) {
            map.insert(f.fingerprint.clone(), f);
        }

        debug!("Map cles chiffrage : {:?}", map);

        Arc::new(ChiffrageFactoryImpl::new(map, env_privee))
    };

    let redis_dao = RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis");

    let middleware = Arc::new(MiddlewareMessage {
        ressources,
        redis: redis_dao,
        chiffrage_factory,
    });

//     let middleware = Arc::new(MiddlewareMessage {
//         configuration,
//         validateur: validateur.clone(),
//         generateur_messages: generateur_messages_arc.clone(),
//         // cles_chiffrage: Mutex::new(cles_chiffrage),
//         redis: redis_dao,
//         chiffrage_factory,
//     });

    // Preparer threads execution
    let rabbitmq = middleware.ressources.rabbitmq.clone();
    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq, configuration)));

    MiddlewareHooks { middleware, futures }
}

/// Requete pour obtenir un certificat a partir du domaine PKI
pub async fn requete_certificat<M,S>(middleware: &M, fingerprint: S) -> Result<Option<Arc<EnveloppeCertificat>>, Box<dyn Error>>
    where
        M: ValidateurX509 + GenerateurMessages,
        S: AsRef<str>
{
    let fingerprint_str = fingerprint.as_ref();
    debug!("requete_certificat {}", fingerprint_str);

    let requete = json!({"fingerprint": fingerprint_str});
    let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM, "infoCertificat").build();
    let reponse_requete = middleware.transmettre_requete(routage, &requete).await?;
    debug!("requete_certificat Reponse : {:?}", reponse_requete);
    let reponse: ReponseEnveloppe = match reponse_requete {
        TypeMessage::Valide(m) => {
            match m.message.parsed.map_contenu(None) {
                Ok(m) => m,
                Err(e) => {
                    error!("requete_certificat Erreur requete certificat {} : mauvais type reponse ou inconnu : {:?}", fingerprint_str, e);
                    return Ok(None)
                }
            }
        },
        TypeMessage::Certificat(m) => {
            let enveloppe = m.enveloppe_certificat;
            let pem_ca = enveloppe.get_pem_ca()?;
            let pems: Vec<String> = enveloppe.get_pem_vec().into_iter().map(|f| f.pem).collect();
            ReponseEnveloppe { chaine_pem: pems, fingerprint: enveloppe.fingerprint, ca_pem: pem_ca }
        },
        _ => Err(format!("requete_certificat Erreur requete certificat {} : mauvais type reponse", fingerprint_str))?
    };

    let ca_pem = match &reponse.ca_pem {
        Some(c) => Some(c.as_str()),
        None => None
    };

    Ok(Some(middleware.charger_enveloppe(&reponse.chaine_pem, Some(reponse.fingerprint.as_str()), ca_pem).await?))
}

// #[cfg(test)]
// pub mod serialization_tests {
//     use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
//     use crate::test_setup::setup;
//     use futures::stream::FuturesUnordered;
//     use tokio::{sync::{mpsc, mpsc::{Receiver, Sender}}, time::{Duration as DurationTokio, timeout}};
//     use crate::recepteur_messages::TypeMessage;
//     use tokio::task::JoinHandle;
//     use tokio_stream::StreamExt;
//     use crate::middleware_db::{MiddlewareDb, preparer_middleware_db};
//
//     use super::*;
//
//     pub async fn build() -> (Arc<MiddlewareDb>, FuturesUnordered<JoinHandle<()>>, Sender<TypeMessage>, Sender<TypeMessage>) {
//         // Preparer configuration
//         let queues = Vec::new();
//
//         let (tx, rx) = mpsc::channel(1);
//
//         let listeners = {
//             let mut callbacks: Callback<EventMq> = Callback::new();
//             callbacks.register(Box::new(move |event| {
//                 debug!("Ceci est un test de callback sur connexion, event : {:?}", event);
//                 // tx.blocking_send(event).expect("Event connexion MQ");
//                 let tx_ref = tx.clone();
//                 let _ = tokio::spawn(async move{
//                     match tx_ref.send(event).await {
//                         Ok(_) => (),
//                         Err(e) => error!("Erreur queuing via callback : {:?}", e)
//                     }
//                 });
//             }));
//
//             Some(Mutex::new(callbacks))
//         };
//
//         let (
//             middleware,
//             rx_messages_verifies,
//             rx_triggers,
//             rx_messages_verif_reply,
//             future_recevoir_messages,
//         ) = preparer_middleware_db(queues, listeners);
//
//         // Demarrer threads
//         let mut futures : FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
//
//         // Thread consommation
//         let (tx_messages, rx_messages) = mpsc::channel::<TypeMessage>(1);
//         let (tx_triggers, rx_pki_triggers) = mpsc::channel::<TypeMessage>(1);
//
//         let mut map_senders: HashMap<String, Sender<TypeMessage>> = HashMap::new();
//         // map_senders.insert(String::from("Core"), tx_pki_messages.clone());
//         // map_senders.insert(String::from("certificat"), tx_pki_messages.clone());
//         // map_senders.insert(String::from("Core/triggers"), tx_pki_triggers.clone());
//         futures.push(tokio::spawn(consommer( middleware.clone(), rx_messages_verifies, map_senders.clone())));
//         futures.push(tokio::spawn(consommer( middleware.clone(), rx_triggers, map_senders.clone())));
//
//         // Thread d'entretien
//         //futures.push(tokio::spawn(entretien(middleware.clone(), rx)));
//
//         // Thread ecoute et validation des messages
//         for f in future_recevoir_messages {
//             futures.push(f);
//         }
//
//         futures.push(tokio::spawn(consommer_messages(middleware.clone(), rx_messages)));
//         futures.push(tokio::spawn(consommer_messages(middleware.clone(), rx_pki_triggers)));
//
//         // debug!("domaines_middleware: Demarrage traitement domaines middleware");
//         // let arret = futures.next().await;
//         // debug!("domaines_middleware: Fermeture du contexte, task daemon terminee : {:?}", arret);
//
//         (middleware, futures, tx_messages, tx_triggers)
//     }
//
//     async fn consommer(
//         _middleware: Arc<impl ValidateurX509 + GenerateurMessages + MongoDao>,
//         mut rx: Receiver<TypeMessage>,
//         map_senders: HashMap<String, Sender<TypeMessage>>
//     ) {
//         while let Some(message) = rx.recv().await {
//             match &message {
//                 TypeMessage::Valide(m) => {
//                     debug!("traiter_messages_valides: Message valide sans routing key/action : {:?}", m.message);
//                 },
//                 TypeMessage::ValideAction(m) => {
//                     let contenu = &m.message;
//                     let rk = &m.routing_key;
//                     let action = &m.action;
//                     debug!("domaines_middleware.consommer: Traiter message valide (action: {}, rk: {}): {:?}", action, rk, contenu);
//
//                     // match map_senders.get(m.domaine.as_str()) {
//                     //     Some(sender) => {sender.send(message).await.expect("send message vers sous-domaine")},
//                     //     None => error!("Message de domaine inconnu {}, on le drop", m.domaine),
//                     // }
//                 },
//                 TypeMessage::Certificat(_) => (),  // Rien a faire
//                 TypeMessage::Regeneration => (),   // Rien a faire
//             }
//         }
//
//         debug!("Fin consommer");
//     }
//
//     pub async fn consommer_messages(middleware: Arc<MiddlewareDb>, mut rx: Receiver<TypeMessage>) {
//         while let Some(message) = rx.recv().await {
//             debug!("Message PKI recu : {:?}", message);
//
//             match message {
//                 TypeMessage::ValideAction(inner) => {debug!("Message ValideAction recu : {:?}", inner)},
//                 TypeMessage::Valide(_inner) => {warn!("Recu MessageValide sur thread consommation"); todo!()},
//                 TypeMessage::Certificat(_inner) => {warn!("Recu MessageCertificat sur thread consommation"); todo!()},
//                 TypeMessage::Regeneration => {continue}, // Rien a faire, on boucle
//             };
//
//         }
//
//         debug!("Fin consommer_messages");
//     }
//
//     // #[tokio::test]
//     // async fn connecter_middleware_pki() {
//     //     setup("connecter_middleware_pki");
//     //
//     //     // Connecter mongo
//     //     //let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//     //     let (
//     //         middleware,
//     //         mut futures,
//     //         mut tx_messages,
//     //         mut tx_triggers
//     //     ) = build().await;
//     //     futures.push(tokio::spawn(async move {
//     //         debug!("Cles chiffrage initial (millegrille uniquement) : {:?}", middleware.cles_chiffrage);
//     //
//     //         debug!("Sleeping");
//     //         tokio::time::sleep(tokio::time::Duration::new(3, 0)).await;
//     //         debug!("Fin sleep");
//     //
//     //         middleware.charger_certificats_chiffrage().await;
//     //
//     //         debug!("Cles chiffrage : {:?}", middleware.cles_chiffrage);
//     //         let cles = middleware.cles_chiffrage.lock().expect("lock");
//     //         assert_eq!(true, cles.len() > 1);
//     //
//     //     }));
//     //     // Execution async du test
//     //     futures.next().await.expect("resultat").expect("ok");
//     // }
//     //
//     // /// Test d'acces au MaitreDesCles. Doit creer une cle secrete, la chiffrer avec les certificats
//     // /// recus, emettre la cle puis recuperer une version dechiffrable localement.
//     // #[tokio::test]
//     // async fn roundtrip_cle_secrete() {
//     //     setup("connecter_middleware_pki");
//     //
//     //     // Connecter mongo
//     //     //let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//     //     let (
//     //         middleware,
//     //         mut futures,
//     //         mut tx_messages,
//     //         mut tx_triggers
//     //     ) = build().await;
//     //     futures.push(tokio::spawn(async move {
//     //         debug!("Cles chiffrage initial (millegrille uniquement) : {:?}", middleware.cles_chiffrage);
//     //
//     //         debug!("Sleeping");
//     //         tokio::time::sleep(tokio::time::Duration::new(4, 0)).await;
//     //         debug!("Fin sleep");
//     //         middleware.charger_certificats_chiffrage().await;
//     //
//     //         debug!("Cles chiffrage : {:?}", middleware.cles_chiffrage);
//     //
//     //         const VALEUR_TEST: &[u8] = b"Du data a chiffrer";
//     //
//     //         let (vec_output, cipher_keys) = {
//     //             let mut vec_output: Vec<u8> = Vec::new();
//     //             let mut cipher = middleware.get_cipher().expect("cipher");
//     //             let mut output = [0u8; 40];
//     //             let len_output = cipher.update(b"Du data a chiffrer", &mut output).expect("update");
//     //             vec_output.extend_from_slice(&output[..len_output]);
//     //             let len_output = cipher.finalize(&mut output).expect("finalize");
//     //             debug!("Finalize cipher : {:?}", &output[..len_output]);
//     //             vec_output.extend_from_slice(&output[..len_output]);
//     //
//     //             (vec_output, cipher.get_cipher_keys().expect("cipher keys"))
//     //         };
//     //
//     //         debug!("Data chiffre : {:?}\nCipher keys : {:?}", vec_output, cipher_keys);
//     //
//     //         let mut id_docs = HashMap::new();
//     //         id_docs.insert(String::from("test"), String::from("dummy"));
//     //         let commande = cipher_keys.get_commande_sauvegarder_cles("Test", None, id_docs);
//     //         let hachage_bytes = commande.hachage_bytes.clone();
//     //         debug!("Commande sauvegarder cles : {:?}", commande);
//     //
//     //         let routage_sauvegarde = RoutageMessageAction::new("MaitreDesCles", "sauvegarderCle");
//     //         let reponse_sauvegarde = middleware.transmettre_commande(routage_sauvegarde, &commande, true)
//     //             .await.expect("reponse");
//     //
//     //         debug!("Reponse sauvegarde cle : {:?}", reponse_sauvegarde);
//     //
//     //         let requete = {
//     //             let mut liste_hachage_bytes = Vec::new();
//     //             liste_hachage_bytes.push(hachage_bytes.clone());
//     //             json!({
//     //                 "liste_hachage_bytes": liste_hachage_bytes,
//     //             })
//     //         };
//     //         let routage_rechiffrer = RoutageMessageAction::new("MaitreDesCles", "dechiffrage");
//     //         let reponse_cle_rechiffree = middleware.transmettre_requete(routage_rechiffrer, &requete).await
//     //             .expect("requete cle");
//     //         debug!("Reponse cle rechiffree : {:?}", reponse_cle_rechiffree);
//     //
//     //         let mut decipher = middleware.get_decipher(&hachage_bytes).await.expect("decipher");
//     //         let mut vec_buffer = {
//     //             let mut buffer_output = [0u8; 40];
//     //             let len_dechiffre = decipher.update(vec_output.as_slice(), &mut buffer_output).expect("update");
//     //             let mut vec_buffer = Vec::new();
//     //             vec_buffer.extend(&buffer_output[..len_dechiffre]);
//     //
//     //             vec_buffer
//     //         };
//     //
//     //         assert_eq!(VALEUR_TEST, vec_buffer.as_slice());
//     //
//     //         let message_dechiffre = String::from_utf8(vec_buffer).expect("utf-8");
//     //         debug!("Data dechiffre : {}", message_dechiffre);
//     //         {
//     //             let mut buffer_output = [0u8; 0];
//     //             let output = decipher.finalize(&mut buffer_output).expect("finalize dechiffrer");
//     //             assert_eq!(0, output);
//     //         }
//     //
//     //     }));
//     //     // Execution async du test
//     //     futures.next().await.expect("resultat").expect("ok");
//     // }
// }