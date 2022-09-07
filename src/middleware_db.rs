use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, info, warn, error};
use mongodb::Database;
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::Serialize;
use serde_json::json;
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::task::JoinHandle;
use crate::backup::{BackupStarter, CommandeBackup, thread_backup};

use crate::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use crate::chiffrage::{ChiffrageFactory, ChiffrageFactoryImpl, Chiffreur, CleChiffrageHandler, Dechiffreur, MgsCipherData};
use crate::chiffrage_aesgcm::CipherMgs2;
use crate::chiffrage_chacha20poly1305::{CipherMgs3, DecipherMgs3, Mgs3CipherData, Mgs3CipherKeys};
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::configuration::{ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{configurer, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, Middleware, MiddlewareMessage, MiddlewareMessages, ReponseDechiffrageCle, RedisTrait, ChiffrageFactoryTrait};
use crate::mongo_dao::{MongoDao, MongoDaoImpl};
use crate::rabbitmq_dao::{Callback, EventMq, QueueType, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::{recevoir_messages, RequeteCertificatInterne, task_requetes_certificats, TypeMessage};
use crate::redis_dao::RedisDao;
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};

// Middleware avec MongoDB
pub struct MiddlewareDb {
    configuration: Arc<ConfigurationMessagesDb>,
    mongo: Arc<MongoDaoImpl>,
    validateur: Arc<ValidateurX509Impl>,
    generateur_messages: Arc<GenerateurMessagesImpl>,
    // pub cles_chiffrage: Mutex<HashMap<String, FingerprintCertPublicKey>>,
    redis: RedisDao,
    tx_backup: Sender<CommandeBackup>,
    chiffrage_factory: Arc<ChiffrageFactoryImpl>,
}

impl MiddlewareDb {
}

impl MiddlewareMessages for MiddlewareDb {
}

impl Middleware for MiddlewareDb {
}

impl RedisTrait for MiddlewareDb {
    fn get_redis(&self) -> &RedisDao {
        &self.redis
    }
}

#[async_trait]
impl ValidateurX509 for MiddlewareDb {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Conserver dans redis (reset TTL)
        match self.redis.save_certificat(&enveloppe).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        match self.redis.save_certificat(&certificat).await {
            Ok(()) => debug!("Certificat {} sauvegarde dans redis", &certificat.fingerprint),
            Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", certificat.fingerprint(), e)
        }
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Cas special, certificat inconnu a PKI. Tenter de le charger de redis
                let redis_certificat = match self.redis.get_certificat(fingerprint).await {
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
                match self.validateur.charger_enveloppe(&redis_certificat.pems, None, ca_pem).await {
                    Ok(c) => Some(c),
                    Err(e) => {
                        warn!("MiddlewareDbPki.get_certificat (1) Erreur acces certificat via redis : {:?}", e);
                        None
                    }
                }
            }
        }
    }

    fn idmg(&self) -> &str {
        self.validateur.idmg()
    }

    fn ca_pem(&self) -> &str {
        self.validateur.ca_pem()
    }

    fn ca_cert(&self) -> &X509 {
        self.validateur.ca_cert()
    }

    fn store(&self) -> &X509Store {
        self.validateur.store()
    }

    fn store_notime(&self) -> &X509Store {
        self.validateur.store_notime()
    }

    async fn entretien_validateur(&self) {
        self.validateur.entretien_validateur().await;
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDb {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool {
        self.generateur_messages.mq_disponible()
    }

    fn set_regeneration(&self) {
        self.generateur_messages.set_regeneration();
    }

    fn reset_regeneration(&self) {
        self.generateur_messages.reset_regeneration();
    }

    fn get_mode_regeneration(&self) -> bool {
        self.generateur_messages.as_ref().get_mode_regeneration()
    }

    fn get_securite(&self) -> &Securite {
        self.generateur_messages.get_securite()
    }
}

impl IsConfigurationPki for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl ConfigMessages for MiddlewareDb {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.configuration.get_configuration_pki()
    }
}

impl FormatteurMessage for MiddlewareDb {}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl IsConfigNoeud for MiddlewareDb {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.configuration.get_configuration_noeud()
    }
}

#[async_trait]
impl CleChiffrageHandler for MiddlewareDb {

    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        let guard = self.chiffrage_factory.cles_chiffrage.lock().expect("lock");

        // Copier les cles (extraire du mutex), retourner dans un vecteur
        let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();

        vals
    }

    async fn charger_certificats_chiffrage<M>(&self, middleware: &M, cert_local: &EnveloppeCertificat, env_privee: Arc<EnveloppePrivee>)
        -> Result<(), Box<dyn Error>>
        where M: GenerateurMessages
    {
        debug!("Charger les certificats de maitre des cles pour chiffrage");

        // Reset certificats maitredescles. Reinserer cert millegrille immediatement.
        {
            let fp_certs = cert_local.fingerprint_cert_publickeys().expect("public keys");
            let mut guard = self.chiffrage_factory.cles_chiffrage.lock().expect("lock");
            guard.clear();

            // Reinserer certificat de millegrille
            let fingerprint_cert = env_privee.enveloppe_ca.fingerprint_cert_publickeys().expect("public keys CA");
            let fingerprint = fingerprint_cert[0].fingerprint.clone();
            guard.insert(fingerprint, fingerprint_cert[0].clone());
        }

        emettre_commande_certificat_maitredescles(middleware).await?;

        // Donner une chance aux certificats de rentrer
        tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

        let certs = self.chiffrage_factory.cles_chiffrage.lock().expect("lock").clone();
        debug!("charger_certificats_chiffrage Certificats de chiffrage recus : {:?}", certs);

        // Verifier si on a au moins un certificat
        let nb_certs = self.chiffrage_factory.cles_chiffrage.lock().expect("lock").len();
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
                Err(format!("recevoir_certificat_chiffrage Message de certificat de MilleGrille recu, certificat n'est pas extrait"))?
            }
        };

        // Valider le certificat
        if ! cert_chiffrage.presentement_valide {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'est pas presentement valide - rejete"))?;
        }

        if ! cert_chiffrage.verifier_roles(vec![RolesCertificats::MaitreDesCles]) {
            Err(format!("middleware_db.recevoir_certificat_chiffrage Certificat de maitre des cles recu n'a pas le role MaitreCles' - rejete"))?;
        }

        info!("Certificat maitre des cles accepte {}", cert_chiffrage.fingerprint());

        // Stocker cles chiffrage du maitre des cles
        {
            let fps = match cert_chiffrage.fingerprint_cert_publickeys() {
                Ok(f) => f,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage cert_chiffrage.fingerprint_cert_publickeys : {:?}", e))?
            };
            let mut guard = match self.chiffrage_factory.cles_chiffrage.lock() {
                Ok(g) => g,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage Erreur cles_chiffrage.lock() : {:?}", e))?
            };
            for fp in fps.iter().filter(|f| ! f.est_cle_millegrille) {
                guard.insert(fp.fingerprint.clone(), fp.clone());
            }

            // S'assurer d'avoir le certificat de millegrille local
            let enveloppe_privee = middleware.get_configuration_pki().get_enveloppe_privee();
            let enveloppe_ca = &enveloppe_privee.enveloppe_ca;
            let public_keys_ca = match enveloppe_ca.fingerprint_cert_publickeys() {
                Ok(p) => p,
                Err(e) => Err(format!("middleware_db.recevoir_certificat_chiffrage enveloppe_ca.fingerprint_cert_publickeys : {:?}", e))?
            }.pop();
            if let Some(pk_ca) = public_keys_ca {
                guard.insert(pk_ca.fingerprint.clone(), pk_ca);
            }

            debug!("Certificats chiffrage maj {:?}", guard);
        }

        Ok(())
    }

}

#[async_trait]
impl Chiffreur<CipherMgs3, Mgs3CipherKeys> for MiddlewareDb {

    fn get_cipher(&self) -> Result<CipherMgs3, Box<dyn Error>> {
        let fp_public_keys = self.get_publickeys_chiffrage();
        Ok(CipherMgs3::new(&fp_public_keys)?)
    }

}

#[async_trait]
impl Dechiffreur<DecipherMgs3, Mgs3CipherData> for MiddlewareDb {

    async fn get_cipher_data(&self, hachage_bytes: &str) -> Result<Mgs3CipherData, Box<dyn Error>> {
        let requete = {
            let mut liste_hachage_bytes = Vec::new();
            liste_hachage_bytes.push(hachage_bytes);
            json!({
                "liste_hachage_bytes": liste_hachage_bytes,
            })
        };
        let routage = RoutageMessageAction::new("MaitreDesCles", "dechiffrage");
        let reponse_cle_rechiffree = self.transmettre_requete(routage, &requete).await?;

        error!("Reponse reechiffrage cle : {:?}", reponse_cle_rechiffree);

        let contenu_dechiffrage = match reponse_cle_rechiffree {
            TypeMessage::Valide(m) => m.message.get_msg().map_contenu::<ReponseDechiffrageCle>(None)?,
            _ => Err(format!("Mauvais type de reponse : {:?}", reponse_cle_rechiffree))?
        };

        contenu_dechiffrage.to_cipher_data()
    }

    async fn get_decipher(&self, hachage_bytes: &str) -> Result<DecipherMgs3, Box<dyn Error>> {
        let mut info_cle = self.get_cipher_data(hachage_bytes).await?;
        let env_privee = self.get_enveloppe_privee();
        let cle_privee = env_privee.cle_privee();
        info_cle.dechiffrer_cle(cle_privee)?;

        Ok(DecipherMgs3::new(&info_cle)?)
    }

}

impl VerificateurMessage for MiddlewareDb {
    fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
        verifier_message(message, self, options)
    }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDb {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;
        let exchanges: Vec<Securite> = securite_cascade_public(
            generateur_message.get_securite()).iter().map(|s| s.to_owned())
            .collect();
        // let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

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

#[async_trait]
impl BackupStarter for MiddlewareDb {
    fn get_tx_backup(&self) -> Sender<CommandeBackup> {
        self.tx_backup.clone()
    }
}

impl ChiffrageFactoryTrait for MiddlewareDb {
    fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl {
        self.chiffrage_factory.as_ref()
    }
}

impl ChiffrageFactory for MiddlewareDb {
    fn get_chiffreur(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur()
    }

    fn get_chiffreur_mgs2(&self) -> Result<CipherMgs2, String> {
        self.chiffrage_factory.get_chiffreur_mgs2()
    }

    fn get_chiffreur_mgs3(&self) -> Result<CipherMgs3, String> {
        self.chiffrage_factory.get_chiffreur_mgs3()
    }

    fn get_chiffreur_mgs4(&self) -> Result<CipherMgs4, String> {
        self.chiffrage_factory.get_chiffreur_mgs4()
    }
}

/// Version speciale du middleware avec un acces a MongoDB
pub fn preparer_middleware_db(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> MiddlewareHooks {
    let (
        configuration,
        validateur,
        mongo,
        mq_executor_config,
        generateur_messages
    ) = configurer(queues, listeners);

    let generateur_messages_arc = Arc::new(generateur_messages);

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

    // let redis_url = match configuration.get_configuration_noeud().redis_url.as_ref() {
    //     Some(u) => Some(u.as_str()),
    //     None => None,
    // };
    let redis_dao = RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis");

    let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);

    let middleware = Arc::new(MiddlewareDb {
        configuration,
        mongo,
        validateur: validateur.clone(),
        generateur_messages: generateur_messages_arc.clone(),
        // cles_chiffrage: Mutex::new(cles_chiffrage),
        redis: redis_dao,
        tx_backup,
        chiffrage_factory,
    });

    let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(1);
    let (tx_messages_verif_reply, rx_messages_verif_reply) = mpsc::channel(1);
    let (tx_triggers, rx_triggers) = mpsc::channel(1);

    let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);

    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();

    let mq_executor = mq_executor_config.executor;  // Move
    let mq_executor_rx = mq_executor_config.rx_queues;

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_messages,
        tx_messages_verifies.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_reply,
        tx_messages_verif_reply.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor_rx.rx_triggers,
        tx_triggers,
        tx_certificats_manquants.clone()
    )));

    // Thread requete certificats manquants
    futures.push(tokio::spawn(task_requetes_certificats(
        middleware.clone(),
        rx_certificats_manquants,
        mq_executor.tx_reply.clone(),
        false
    )));

    futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));

    MiddlewareHooks {
        middleware, mq_executor,
        rx_messages_verifies, rx_messages_verif_reply, rx_triggers, tx_certificats_manquants,
        futures
    }
}

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareMessagesHooks {
    pub middleware: Arc<MiddlewareMessage>,
    pub mq_executor: RabbitMqExecutor,
    pub rx_messages_verifies: Receiver<TypeMessage>,
    pub rx_messages_verif_reply: Receiver<TypeMessage>,
    pub rx_triggers: Receiver<TypeMessage>,
    pub tx_certificats_manquants: Sender<RequeteCertificatInterne>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareDb>,
    pub mq_executor: RabbitMqExecutor,
    pub rx_messages_verifies: Receiver<TypeMessage>,
    pub rx_messages_verif_reply: Receiver<TypeMessage>,
    pub rx_triggers: Receiver<TypeMessage>,
    pub tx_certificats_manquants: Sender<RequeteCertificatInterne>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}
