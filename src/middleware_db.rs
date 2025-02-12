use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, warn};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesRef, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee};
use mongodb::{ClientSession, Database};
use mongodb::options::{Acknowledgment, SessionOptions, TransactionOptions, WriteConcern};
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::Serialize;
use tokio::sync::{mpsc, mpsc::Sender, Notify};
use tokio::task::JoinHandle;

use crate::backup::{BackupStarter, CommandeBackup, thread_backup};
use crate::certificats::{emettre_commande_certificat_maitredescles, ValidateurX509, VerificateurPermissions};
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};
use crate::configuration::{ConfigMessages, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::error::Error as CommonError;
use crate::formatteur_messages::FormatteurMessage;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageAction, RoutageMessageReponse};
use crate::middleware::{charger_certificat_redis, configurer as configurer_messages, EmetteurCertificat, EmetteurNotificationsTrait, formatter_message_certificat, IsConfigurationPki, Middleware, MiddlewareMessage, MiddlewareMessages, MiddlewareRessources, RabbitMqTrait, RedisTrait, requete_certificat, verifier_expiration_certs};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};
use crate::notifications::NotificationMessageInterne;
use crate::rabbitmq_dao::{NamedQueue, run_rabbitmq, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::redis_dao::RedisDao;

// Middleware avec MongoDB
pub struct MiddlewareDb {
    pub ressources: MiddlewareDbRessources,
    pub redis: Option<RedisDao>,
    pub tx_backup: Sender<CommandeBackup>,
    pub cle_chiffrage_handler: CleChiffrageHandlerImpl,
}

impl MiddlewareMessages for MiddlewareDb {}
impl Middleware for MiddlewareDb {}

impl CleChiffrageHandler for MiddlewareDb {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.cle_chiffrage_handler.get_publickeys_chiffrage()
    }
}

impl CleChiffrageCache for MiddlewareDb {
    fn entretien_cle_chiffrage(&self) {
        self.cle_chiffrage_handler.entretien_cle_chiffrage();
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), crate::error::Error> {
        self.cle_chiffrage_handler.ajouter_certificat_chiffrage(certificat)
    }
}

#[async_trait]
impl EmetteurNotificationsTrait for MiddlewareDb {
    async fn emettre_notification_proprietaire(
        &self, contenu: NotificationMessageInterne, niveau: &str, expiration: Option<i64>, destinataires: Option<Vec<String>>
    )
        -> Result<(), crate::error::Error>
    {
        self.ressources.ressources.emetteur_notifications.emettre_notification_proprietaire(
            self, contenu, niveau, expiration, destinataires).await
    }

    async fn emettre_notification_usager<D,S,N> (
        &self,
        user_id: S,
        contenu: NotificationMessageInterne,
        niveau: N,
        domaine: D,
        expiration: Option<i64>,
        // cle_dechiffree: Option<CleDechiffree>
    ) -> Result<String, crate::error::Error>
        where D: AsRef<str> + Send, S: AsRef<str> + Send, N: AsRef<str> + Send
    {
        todo!("fix me")
        // self.ressources.ressources.emetteur_notifications.emettre_notification_usager(
        //     self, user_id, contenu, niveau, domaine, expiration, cle_dechiffree).await
    }
}

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
    fn get_redis(&self) -> Option<&RedisDao> { self.redis.as_ref() }
}

impl IsConfigNoeud for MiddlewareDb {
    fn get_configuration_noeud(&self) -> &ConfigurationNoeud { self.ressources.ressources.configuration.get_configuration_noeud() }
}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, CommonError> { self.ressources.mongo.get_database() }

    fn get_admin_database(&self) -> Result<Database, CommonError> { self.ressources.mongo.get_admin_database() }

    fn get_db_name(&self) -> &str { self.ressources.mongo.get_db_name() }

    async fn get_session(&self) -> Result<ClientSession, CommonError> { self.ressources.mongo.get_session().await }

    async fn get_session_rebuild(&self) -> Result<ClientSession, CommonError> {
        self.ressources.mongo.get_session_rebuild().await
    }
}

#[async_trait]
impl BackupStarter for MiddlewareDb {
    fn get_tx_backup(&self) -> Sender<CommandeBackup> { self.tx_backup.clone() }
}

#[async_trait]
impl ValidateurX509 for MiddlewareDb {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, crate::error::Error>
    {
        let enveloppe = self.ressources.ressources.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        // Conserver dans redis (reset TTL)
        match self.redis.as_ref() {
            Some(redis) => {
                match redis.save_certificat(&enveloppe).await {
                    Ok(()) => (),
                    Err(e) => warn!("MiddlewareDbPki.charger_enveloppe Erreur sauvegarde certificat dans redis : {:?}", e)
                }
            },
            None => ()
        }

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Result<(Arc<EnveloppeCertificat>, bool), crate::error::Error> {
        let (enveloppe, persiste) = self.ressources.ressources.validateur.cacher(certificat).await?;

        // Sauvegarder le certificat dans redis au besoin
        let persiste = if ! persiste {
            match self.redis.as_ref() {
                Some(redis) => {
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => {
                            let fingerprint = enveloppe.fingerprint()?;
                            debug!("Certificat {} sauvegarde dans redis", fingerprint);
                            self.ressources.ressources.validateur.set_flag_persiste(fingerprint.as_str());
                            true
                        },
                        Err(e) => {
                            warn!("Erreur cache certificat {} dans redis : {:?}", enveloppe.fingerprint()?, e);
                            false
                        }
                    }
                },
                None => false
            }
        } else {
            persiste
        };

        /// Retourne le certificat et indicateur qu'il a ete persiste
        Ok((enveloppe, persiste))
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        self.ressources.ressources.validateur.set_flag_persiste(fingerprint)
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.ressources.ressources.validateur.get_certificat(fingerprint).await {
            Some(c) => Some(c),
            None => {
                // Tenter de le charger de redis
                match charger_certificat_redis(self, fingerprint).await {
                    Some(c) => Some(c),
                    None => {
                        // Certificat absent de redis, via MQ
                        debug!("get_certificat Certificat inconnu, effectuer requete pour fingerprint {:?}", fingerprint);
                        match requete_certificat(self, fingerprint).await {
                            Ok(c) => c,
                            Err(e) => {
                                error!("ValidateurX509.get_certificat Erreur chargement certificat {} : {:?}", fingerprint, e);
                                None
                            }
                        }
                    }
                }
            }
        }
    }

    fn est_cache(&self, fingerprint: &str) -> bool {
        self.ressources.ressources.validateur.est_cache(fingerprint)
    }

    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.ressources.ressources.validateur.certificats_persister()
    }

    fn idmg(&self) -> &str { self.ressources.ressources.validateur.idmg() }

    fn ca_pem(&self) -> &str { self.ressources.ressources.validateur.ca_pem() }

    fn ca_cert(&self) -> &X509 { self.ressources.ressources.validateur.ca_cert() }

    fn store(&self) -> &X509Store { self.ressources.ressources.validateur.store() }

    fn store_notime(&self) -> &X509Store { self.ressources.ressources.validateur.store_notime() }

    async fn entretien_validateur(&self) {
        {
            let enveloppe_privee = self.get_enveloppe_privee();
            let certificat_local = self.get_enveloppe_signature();
            if verifier_expiration_certs(enveloppe_privee.as_ref(), certificat_local.as_ref()) == true {
                panic!("Certificat expire");
            }
        }

        if let Some(redis) = self.redis.as_ref() {
            // Conserver les certificats qui n'ont pas encore ete persistes
            for certificat in self.ressources.ressources.validateur.certificats_persister().iter() {
                match certificat.fingerprint() {
                    Ok(fingerprint) => {
                        debug!("entretien_validateur Persister {}", fingerprint);
                        match redis.save_certificat(certificat).await {
                            Ok(()) => self.set_flag_persiste(fingerprint.as_str()),
                            Err(e) => warn!("entretien_validateur Erreur sauvegarde certificat {:?}", e)
                        }
                    },
                    Err(e) => warn!("entretien_validateur Erreur sauvegarde certificat {:?}", e)
                }
            }
        }

        self.ressources.ressources.validateur.entretien_validateur().await;
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDb {

    async fn emettre_evenement<R,M>(&self, routage: R, message: M)
                                    -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<R,M>(&self, routage: R, message: M)
                                      -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M)
                                        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.soumettre_transaction(routage, message).await
    }

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
                                       -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.ressources.generateur_messages.transmettre_commande(routage, message).await
    }

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync {
        self.ressources.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M)
                                -> Result<Option<TypeMessage>, crate::error::Error>
        where M: Into<MessageMilleGrillesBufferDefault> + Send
    {
        self.ressources.ressources.generateur_messages.emettre_message(type_message, message).await
    }

    fn mq_disponible(&self) -> bool { self.ressources.ressources.generateur_messages.mq_disponible() }

    fn set_regeneration(&self) { self.ressources.ressources.generateur_messages.set_regeneration(); }

    fn reset_regeneration(&self) { self.ressources.ressources.generateur_messages.reset_regeneration(); }

    fn get_mode_regeneration(&self) -> bool { self.ressources.ressources.generateur_messages.as_ref().get_mode_regeneration() }

    fn get_securite(&self) -> &Securite { self.ressources.ressources.generateur_messages.get_securite() }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDb {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), crate::error::Error> {
        let enveloppe_privee = self.ressources.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe_pub.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;
        let exchanges: Vec<Securite> = securite_cascade_public(
            generateur_message.get_securite()).iter().map(|s| s.to_owned())
            .collect();
        // let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        let routage = RoutageMessageAction::builder("certificat", "infoCertificat", exchanges)
            .build();

        // Sauvegarder dans redis
        match self.redis.as_ref() {
            Some(redis) => {
                match redis.save_certificat(enveloppe_certificat).await {
                    Ok(()) => (),
                    Err(e) => warn!("MiddlewareDb.emettre_certificat Erreur sauvegarde certificat local sous redis : {:?}", e)
                }
            },
            None => ()
        }

        match generateur_message.emettre_evenement(routage, &message).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e))?
        }
    }

    async fn repondre_certificat<S, T>(&self, reply_q: S, correlation_id: T) -> Result<(), crate::error::Error>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        todo!()
    }
}

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareDb>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

pub struct MiddlewareDbRessources {
    pub ressources: MiddlewareRessources,
    pub mongo: Arc<MongoDaoImpl>,
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

    // Charger redis (optionnel)
    let redis_dao = match configuration.get_configuration_noeud().redis_password {
        Some(_) => {
            info!("Initialisation Redis");
            Some(RedisDao::new(configuration.get_configuration_noeud().clone()).expect("connexion redis"))
        },
        None => {
            info!("Redis desactive");
            None
        }
    };

    let (tx_backup, rx_backup) = mpsc::channel::<CommandeBackup>(5);

    let middleware = Arc::new(MiddlewareDb {
        ressources,
        redis: redis_dao,
        tx_backup,
        cle_chiffrage_handler: CleChiffrageHandlerImpl::new(),
    });

    // Preparer threads execution
    let rabbitmq = middleware.ressources.ressources.rabbitmq.clone();
    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    futures.push(tokio::spawn(thread_backup(middleware.clone(), rx_backup)));
    futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq, configuration)));

    MiddlewareHooks { middleware, futures }
}
