use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, info, warn};
use mongodb::Database;
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::Serialize;
use tokio::sync::{mpsc, mpsc::Sender, Notify};
use tokio::task::JoinHandle;

use crate::backup::{BackupStarter, CommandeBackup, thread_backup};
use crate::certificats::{emettre_commande_certificat_maitredescles, EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, VerificateurPermissions};
use crate::chiffrage::{ChiffrageFactory, ChiffrageFactoryImpl, CleChiffrageHandler};
use crate::chiffrage_aesgcm::CipherMgs2;
use crate::chiffrage_streamxchacha20poly1305::CipherMgs4;
use crate::configuration::{ConfigMessages, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{charger_certificat_redis, ChiffrageFactoryTrait, configurer as configurer_messages, EmetteurCertificat, formatter_message_certificat, IsConfigurationPki, Middleware, MiddlewareMessages, MiddlewareRessources, RabbitMqTrait, RedisTrait};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};
use crate::rabbitmq_dao::{NamedQueue, run_rabbitmq, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::redis_dao::RedisDao;
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};

// Middleware avec MongoDB
pub struct MiddlewareDb {
    pub ressources: MiddlewareDbRessources,
    pub redis: RedisDao,
    tx_backup: Sender<CommandeBackup>,
    pub chiffrage_factory: Arc<ChiffrageFactoryImpl>,
}

impl MiddlewareMessages for MiddlewareDb {}
impl Middleware for MiddlewareDb {}
impl FormatteurMessage for MiddlewareDb {
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
        self.ressources.ressources.generateur_messages.get_enveloppe_signature()
    }

    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
        self.ressources.ressources.generateur_messages.set_enveloppe_signature(enveloppe)
    }
}

impl RabbitMqTrait for MiddlewareDb {
    fn ajouter_named_queue<S>(&self, queue_name: S, named_queue: NamedQueue) where S: Into<String> {
        self.ressources.ressources.rabbitmq.ajouter_named_queue(queue_name, named_queue)
    }

    fn est_connecte(&self) -> bool { self.ressources.ressources.rabbitmq.est_connecte() }
    fn notify_attendre_connexion(&self) -> Arc<Notify> { self.ressources.ressources.rabbitmq.notify_attendre_connexion() }
}

impl IsConfigurationPki for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> { self.ressources.ressources.configuration.get_configuration_pki().get_enveloppe_privee() }
}

impl ConfigMessages for MiddlewareDb {
    fn get_configuration_mq(&self) -> &ConfigurationMq { self.ressources.ressources.configuration.get_configuration_mq() }
    fn get_configuration_pki(&self) -> &ConfigurationPki { self.ressources.ressources.configuration.get_configuration_pki() }
}

impl RedisTrait for MiddlewareDb {
    fn get_redis(&self) -> &RedisDao { &self.redis }
}

impl IsConfigNoeud for MiddlewareDb {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud { self.ressources.ressources.configuration.get_configuration_noeud() }
}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, String> { self.ressources.mongo.get_database() }
}

#[async_trait]
impl BackupStarter for MiddlewareDb {
    fn get_tx_backup(&self) -> Sender<CommandeBackup> { self.tx_backup.clone() }
}

impl VerificateurMessage for MiddlewareDb {
    fn verifier_message(&self, message: &mut MessageSerialise, options: Option<&ValidationOptions>) -> Result<ResultatValidation, Box<dyn Error>> {
        verifier_message(message, self, options)
    }
}

#[async_trait]
impl ValidateurX509 for MiddlewareDb {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        let enveloppe = self.ressources.ressources.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Conserver dans redis (reset TTL)
        match self.redis.save_certificat(&enveloppe).await {
            Ok(()) => (),
            Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, usize) {
        let (enveloppe, compteur) = self.ressources.ressources.validateur.cacher(certificat).await;

        // Donner une chance de sauvegarder le certificat dans redis 2 fois (e.g. si cache durant reception _certificat)
        if compteur < 2 {
            match self.redis.save_certificat(enveloppe.as_ref()).await {
                Ok(()) => debug!("Certificat {} sauvegarde dans redis", enveloppe.fingerprint),
                Err(e) => warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint, e)
            }
        }

        (enveloppe, compteur)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.ressources.ressources.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Tenter de le charger de redis
                match charger_certificat_redis(self, fingerprint).await {
                    Some(c) => Some(c),
                    None => {
                        // Certificat absent de redis, charger directement de
                        // la base de donnees MongoDB
                        todo!("Charger certificat via mongodb - et si absent, charger avec broadcast MQ")
                    }
                }
            }
        }
    }

    fn idmg(&self) -> &str { self.ressources.ressources.validateur.idmg() }

    fn ca_pem(&self) -> &str { self.ressources.ressources.validateur.ca_pem() }

    fn ca_cert(&self) -> &X509 { self.ressources.ressources.validateur.ca_cert() }

    fn store(&self) -> &X509Store { self.ressources.ressources.validateur.store() }

    fn store_notime(&self) -> &X509Store { self.ressources.ressources.validateur.store_notime() }

    async fn entretien_validateur(&self) { self.ressources.ressources.validateur.entretien_validateur().await; }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDb {

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<TypeMessage, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.soumettre_transaction(routage, message, blocking).await
    }

    async fn transmettre_commande<M>(&self, routage: RoutageMessageAction, message: &M, blocking: bool)
        -> Result<Option<TypeMessage>, String>
        where M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.transmettre_commande(routage, message, blocking).await
    }

    async fn repondre(&self, routage: RoutageMessageReponse, message: MessageMilleGrille) -> Result<(), String> {
        self.ressources.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message(&self, routage: RoutageMessageAction, type_message: TypeMessageOut, message: &str, blocking: bool)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.ressources.generateur_messages.emettre_message(routage, type_message, message,  blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String>
    {
        self.ressources.ressources.generateur_messages.emettre_message_millegrille(routage, blocking, type_message, message).await
    }

    fn mq_disponible(&self) -> bool { self.ressources.ressources.generateur_messages.mq_disponible() }

    fn set_regeneration(&self) { self.ressources.ressources.generateur_messages.set_regeneration(); }

    fn reset_regeneration(&self) { self.ressources.ressources.generateur_messages.reset_regeneration(); }

    fn get_mode_regeneration(&self) -> bool { self.ressources.ressources.generateur_messages.as_ref().get_mode_regeneration() }

    fn get_securite(&self) -> &Securite { self.ressources.ressources.generateur_messages.get_securite() }
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
impl EmetteurCertificat for MiddlewareDb {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.ressources.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
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

impl ChiffrageFactoryTrait for MiddlewareDb {
    fn get_chiffrage_factory(&self) -> &ChiffrageFactoryImpl { self.chiffrage_factory.as_ref() }
}

impl ChiffrageFactory for MiddlewareDb {
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

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareDb>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

pub struct MiddlewareDbRessources {
    ressources: MiddlewareRessources,
    mongo: Arc<MongoDaoImpl>,
}

pub fn configurer() -> MiddlewareDbRessources
{
    let middeware_ressources = configurer_messages();
    let configuration = middeware_ressources.configuration.as_ref().as_ref();

    // Connecter au middleware mongo et MQ
    let mongo= Arc::new(initialiser_mongodb(configuration).expect("initialiser_mongodb"));

    MiddlewareDbRessources { ressources: middeware_ressources, mongo }
}

/// Version speciale du middleware avec un acces a MongoDB
pub fn preparer_middleware_db() -> MiddlewareHooks {
    let ressources = configurer();

    let configuration = ressources.ressources.configuration.clone();

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

    let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);

    let middleware = Arc::new(MiddlewareDb {
        ressources,
        redis: redis_dao,
        tx_backup,
        chiffrage_factory,
    });

    // Preparer threads execution
    let rabbitmq = middleware.ressources.ressources.rabbitmq.clone();
    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));
    futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq, configuration)));

    MiddlewareHooks { middleware, futures }
}
