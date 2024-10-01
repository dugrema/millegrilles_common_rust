use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::str::from_utf8;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, warn};
use millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_cryptographie::deser_message_buffer;
use millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageMilleGrillesRef, MessageMilleGrillesRefDefault};
use millegrilles_cryptographie::x509::{EnveloppeCertificat, EnveloppePrivee, FingerprintPem};
use mongodb::{bson::{Bson, doc, Document, to_bson}, Collection};
use mongodb::bson as bson;
use mongodb::options::UpdateOptions;
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use base64::{Engine as _, engine::general_purpose};

use crate::backup::BackupStarter;
use crate::certificats::{emettre_commande_certificat_maitredescles, ValidateurX509, ValidateurX509Impl, VerificateurPermissions};
use crate::chiffrage_cle::{CleChiffrageCache, CleChiffrageHandlerImpl};
use crate::configuration::{charger_configuration_avec_db, ConfigMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::domaines::GestionnaireDomaine;
use crate::domaines_traits::{AiguillageTransactions, GestionnaireDomaineV2};
use crate::error::Error as CommonError;
use crate::formatteur_messages::{build_message_action, build_reponse, FormatteurMessage};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageAction, RoutageMessageReponse};
use crate::mongo_dao::{MongoDao, verifier_erreur_duplication_mongo};
use crate::notifications::{EmetteurNotifications, NotificationMessageInterne};
use crate::rabbitmq_dao::{NamedQueue, RabbitMqExecutor, run_rabbitmq, TypeMessageOut};
use crate::recepteur_messages::{MessageValide, TypeMessage};
use crate::redis_dao::RedisDao;
use crate::transactions::{EtatTransaction, marquer_transaction, Transaction, transmettre_evenement_persistance};
use crate::transactions_v2::marquer_transaction_v2;

/// Structure avec hooks interne de preparation du middleware
pub struct MiddlewareHooks {
    pub middleware: Arc<MiddlewareMessage>,
    pub futures: FuturesUnordered<JoinHandle<()>>,
}

pub trait RedisTrait {
    fn get_redis(&self) -> Option<&RedisDao>;
}

pub trait RabbitMqTrait {
    fn ajouter_named_queue<S>(&self, queue_name: S, named_queue: NamedQueue) where S: Into<String>;
    fn est_connecte(&self) -> bool;
    fn notify_attendre_connexion(&self)-> Arc<Notify>;
}

#[async_trait]
pub trait EmetteurNotificationsTrait: GenerateurMessages + ValidateurX509 {
    async fn emettre_notification_proprietaire(
        &self,
        contenu: NotificationMessageInterne,
        niveau: &str,
        expiration: Option<i64>,
        destinataires: Option<Vec<String>>
    ) -> Result<(), crate::error::Error>;

    async fn emettre_notification_usager<D,S,N>(
        &self,
        user_id: S,
        contenu: NotificationMessageInterne,
        niveau: N,
        domaine: D,
        expiration: Option<i64>,
        // cle_dechiffree: Option<CleDechiffree>
    ) -> Result<String, crate::error::Error> where D: AsRef<str> + Send, S: AsRef<str> + Send, N: AsRef<str> + Send;
}

/// Super-trait pour tous les traits implementes par Middleware
pub trait MiddlewareMessages:
    ValidateurX509 + GenerateurMessages + ConfigMessages + IsConfigurationPki +
    IsConfigNoeud + FormatteurMessage + EmetteurCertificat +
    // VerificateurMessage + ChiffrageFactoryTrait +
    RedisTrait + RabbitMqTrait +
    EmetteurNotificationsTrait + CleChiffrageHandler + CleChiffrageCache
    // + Chiffreur<CipherMgs3, Mgs3CipherKeys> + Dechiffreur<DecipherMgs3, Mgs3CipherData>
{}

pub trait Middleware:
    MiddlewareMessages + MongoDao + BackupStarter
{}

pub trait IsConfigurationPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;
}

#[derive(Clone)]
pub struct MiddlewareRessources {
    pub configuration: Arc<Box<ConfigurationMessagesDb>>,
    pub validateur: Arc<ValidateurX509Impl>,
    pub rabbitmq: Arc<RabbitMqExecutor>,
    pub generateur_messages: Arc<GenerateurMessagesImpl>,
    pub emetteur_notifications: Arc<EmetteurNotifications>,
}

pub fn configurer() -> MiddlewareRessources {
    let configuration = Arc::new(Box::new(charger_configuration_avec_db().expect("charger_configuration_avec_db")));

    let pki = configuration.get_configuration_pki();
    let securite = match pki.get_enveloppe_privee().enveloppe_pub.get_extensions().expect("extensions certificat") {
        Some(extensions) => {
            match extensions.exchanges {
                Some(exchanges) => {
                    if exchanges.contains(&SECURITE_4_SECURE.to_string()) { Securite::L4Secure } else if exchanges.contains(&SECURITE_3_PROTEGE.to_string()) { Securite::L3Protege } else if exchanges.contains(&SECURITE_2_PRIVE.to_string()) { Securite::L2Prive } else if exchanges.contains(&SECURITE_1_PUBLIC.to_string()) { Securite::L1Public } else {
                        panic!("Niveau de securite non-supporte")
                    }
                },
                None => panic!("Certificat sans exchanges, aucun acces a MQ")
            }
        },
        None => panic!("Aucunes extensions pour le certificat public")
    };

    // Preparer instances utils
    let validateur = pki.get_validateur();

    // Connecter au middleware mongo et MQ
    let rabbitmq = Arc::new(RabbitMqExecutor::new(securite.into()));

    let generateur_messages = Arc::new(GenerateurMessagesImpl::new(
        configuration.get_configuration_pki(),
        rabbitmq.clone()
    ));

    let enveloppe_privee = pki.get_enveloppe_privee();
    let extensions = enveloppe_privee.enveloppe_pub.get_extensions().expect("extensions Ok").expect("extensions Some");
    let roles = &extensions.roles;
    let identitie_from = match roles {
        Some(r) => format!("{:?}", r),
        None => {
            let subject = enveloppe_privee.enveloppe_pub.subject().expect("subject");
            match subject.get("commonName") {
                Some(cn) => cn.to_owned(),
                None => enveloppe_privee.fingerprint().expect("fingerprint Ok").to_owned()
            }
        }
    };

    let emetteur_notifications = Arc::new(EmetteurNotifications::new(
        &enveloppe_privee.enveloppe_ca, Some(identitie_from)).expect("EmetteurNotifications.new"));

    MiddlewareRessources { configuration, validateur, rabbitmq, generateur_messages, emetteur_notifications }
}

// Middleware de base avec validateur et generateur de messages
pub struct MiddlewareMessage {
    ressources: MiddlewareRessources,
    redis: Option<RedisDao>,
    // chiffrage_factory: Arc<ChiffrageFactoryImpl>,
    cle_chiffrage_handler: CleChiffrageHandlerImpl,
}

impl MiddlewareMessages for MiddlewareMessage {}

impl CleChiffrageHandler for MiddlewareMessage {
    fn get_publickeys_chiffrage(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.cle_chiffrage_handler.get_publickeys_chiffrage()
    }
}

impl CleChiffrageCache for MiddlewareMessage {
    fn entretien_cle_chiffrage(&self) {
        self.cle_chiffrage_handler.entretien_cle_chiffrage();
    }

    fn ajouter_certificat_chiffrage(&self, certificat: Arc<EnveloppeCertificat>) -> Result<(), CommonError> {
        self.cle_chiffrage_handler.ajouter_certificat_chiffrage(certificat)
    }
}

#[async_trait]
impl EmetteurNotificationsTrait for MiddlewareMessage {
    async fn emettre_notification_proprietaire(
        &self, contenu: NotificationMessageInterne, niveau: &str, expiration: Option<i64>, destinataires: Option<Vec<String>>
    )
        -> Result<(), crate::error::Error>
    {
        self.ressources.emetteur_notifications.emettre_notification_proprietaire(
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
        // self.ressources.emetteur_notifications.emettre_notification_usager(
        //     self, user_id, contenu, niveau, domaine, expiration, cle_dechiffree).await
    }
}

impl RabbitMqTrait for MiddlewareMessage {
    fn ajouter_named_queue<S>(&self, queue_name: S, named_queue: NamedQueue) where S: Into<String> {
        self.ressources.rabbitmq.ajouter_named_queue(queue_name, named_queue)
    }

    fn est_connecte(&self) -> bool { self.ressources.rabbitmq.est_connecte() }
    fn notify_attendre_connexion(&self) -> Arc<Notify> { self.ressources.rabbitmq.notify_attendre_connexion() }
}

impl RedisTrait for MiddlewareMessage {
    fn get_redis(&self) -> Option<&RedisDao> {
        self.redis.as_ref()
    }
}

#[async_trait]
impl ValidateurX509 for MiddlewareMessage {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
        -> Result<Arc<EnveloppeCertificat>, crate::error::Error>
    {
        let enveloppe = self.ressources.validateur.charger_enveloppe(chaine_pem, fingerprint, ca_pem).await?;

        match self.redis.as_ref() {
            Some(redis) => {
                // Conserver dans redis (reset TTL)
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
        let (enveloppe, persiste) = self.ressources.validateur.cacher(certificat).await?;

        let persiste = if ! persiste {
            match self.redis.as_ref() {
                Some(redis) => {
                    match redis.save_certificat(enveloppe.as_ref()).await {
                        Ok(()) => {
                            let fingerprint = enveloppe.fingerprint()?;
                            debug!("Certificat {} sauvegarde dans redis", fingerprint);
                            self.ressources.validateur.set_flag_persiste(fingerprint.as_str());
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
        self.ressources.validateur.set_flag_persiste(fingerprint)
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
        self.ressources.validateur.est_cache(fingerprint)
    }

    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        self.ressources.validateur.certificats_persister()
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
        {
            let enveloppe_privee = self.get_enveloppe_privee();
            let certificat_local = self.get_enveloppe_signature();
            if verifier_expiration_certs(enveloppe_privee.as_ref(), certificat_local.as_ref()) == true {
                panic!("Certificat expire");
            }
        }

        if let Some(redis) = self.redis.as_ref() {
            // Conserver les certificats qui n'ont pas encore ete persistes
            for certificat in self.ressources.validateur.certificats_persister().iter() {
                let fingerprint = certificat.fingerprint().expect("fingerprint Ok");
                debug!("entretien_validateur Persister {}", fingerprint);
                match redis.save_certificat(certificat).await {
                    Ok(()) => self.set_flag_persiste(certificat.fingerprint().expect("fingerprint Ok").as_str()),
                    Err(e) => warn!("entretien_validateur Erreur sauvegarde certificat {:?}", e)
                }
            }
        }

        self.ressources.validateur.entretien_validateur().await;
    }
}


pub fn verifier_expiration_certs(enveloppe_privee: &EnveloppePrivee, certificat_local: &EnveloppePrivee) -> bool {
    // Valider le certificat local
    let date_courante = Utc::now();

    let enveloppe_public = &enveloppe_privee.enveloppe_pub;

    debug!("Verifier expiration enveloppe privee : {:?}", enveloppe_public.not_valid_after());
    if let Ok(exp_prive) = enveloppe_public.not_valid_after() {
        if exp_prive < date_courante {
            error!("Certificat local expire (enveloppe privee)");
            return true;
        }
    }
    debug!("Verifier expiration enveloppe signature : {:?}", enveloppe_public.not_valid_after());
    if let Ok(exp_sign) = enveloppe_public.not_valid_after() {
        if exp_sign < date_courante {
            error!("Certificat local expire (enveloppe signature)");
            return true;
        }
    }

    false
}


pub async fn charger_certificat_redis<M>(middleware: &M, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>>
    where M: RedisTrait + ValidateurX509
{
    let redis_certificat = match middleware.get_redis() {
        Some(redis) => match redis.get_certificat(fingerprint).await {
            Ok(c) => match c {
                Some(c) => c,
                None => return None
            },
            Err(e) => {
                warn!("MiddlewareDbPki.get_certificat (2) Erreur acces certificat via redis : {:?}", e);
                return None
            }
        },
        None => return None
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

impl FormatteurMessage for MiddlewareMessage {
    fn get_enveloppe_signature(&self) -> Arc<EnveloppePrivee> {
        self.ressources.generateur_messages.get_enveloppe_signature()
    }

    fn set_enveloppe_signature(&self, enveloppe: Arc<EnveloppePrivee>) {
        self.ressources.generateur_messages.set_enveloppe_signature(enveloppe)
    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareMessage {

    async fn emettre_evenement<R,M>(&self, routage: R, message: M)
                                    -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.emettre_evenement( routage, message).await
    }

    async fn transmettre_requete<R,M>(&self, routage: R, message: M)
                                      -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_requete(routage, message).await
    }

    async fn soumettre_transaction<R,M>(&self, routage: R, message: M)
                                        -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.soumettre_transaction(routage, message).await
    }

    async fn transmettre_commande<R,M>(&self, routage: R, message: M)
                                       -> Result<Option<TypeMessage>, crate::error::Error>
        where R: Into<RoutageMessageAction> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.transmettre_commande(routage, message).await
    }

    async fn repondre<R,M>(&self, routage: R, message: M) -> Result<(), crate::error::Error>
        where R: Into<RoutageMessageReponse> + Send, M: Serialize + Send + Sync
    {
        self.ressources.generateur_messages.repondre(routage, message).await
    }

    async fn emettre_message<M>(&self, type_message: TypeMessageOut, message: M)
                                -> Result<Option<TypeMessage>, crate::error::Error>
        where M: Into<MessageMilleGrillesBufferDefault> + Send
    {
        self.ressources.generateur_messages.emettre_message(type_message, message).await
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
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), crate::error::Error> {
        let enveloppe_privee = self.ressources.configuration.get_configuration_pki().get_enveloppe_privee();
        let enveloppe_certificat = enveloppe_privee.enveloppe_pub.as_ref();
        let message = formatter_message_certificat(enveloppe_certificat)?;

        let routage = RoutageMessageAction::builder("certificat", PKI_REQUETE_CERTIFICAT, vec![Securite::L1Public])
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
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e))?,
        }
    }

    async fn repondre_certificat<S,T>(&self, reply_q: S, correlation_id: T) -> Result<(), crate::error::Error>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        repondre_certificat(self, reply_q, correlation_id).await
    }
}

pub async fn repondre_certificat<M,S,T>(middleware: &M, reply_q: S, correlation_id: T) -> Result<(), crate::error::Error>
    where M: ConfigMessages + GenerateurMessages,
          S: AsRef<str> + Send, T: AsRef<str> + Send
{
    let reply_q = reply_q.as_ref();
    let correlation_id = correlation_id.as_ref();

    let enveloppe_privee = middleware.get_configuration_pki().get_enveloppe_privee();
    let enveloppe_certificat = enveloppe_privee.enveloppe_pub.as_ref();
    let message = formatter_message_certificat(enveloppe_certificat)?;

    let routage = RoutageMessageReponse::new(reply_q, correlation_id);

    match middleware.repondre(routage, message).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("middleware.repondre_certificat Erreur emettre_certificat: {:?}", e))?,
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseCertificatMaitredescles {
    certificat: Vec<String>,
}

impl ReponseCertificatMaitredescles {
    pub async fn get_enveloppe_maitredescles<V>(&self, validateur: &V) -> Result<Arc<EnveloppeCertificat>, Box<dyn Error>>
    where
        V: ValidateurX509,
    {
        Ok(validateur.charger_enveloppe(&self.certificat, None, None).await?)
    }
}

pub async fn upsert_certificat(enveloppe: &EnveloppeCertificat, collection: Collection<Document>, dirty: Option<bool>)
    -> Result<Option<String>, crate::error::Error>
{
    let fingerprint = enveloppe.fingerprint()?;

    let filtre = doc! { "fingerprint": &fingerprint };

    let (idmg, est_ca) = match enveloppe.est_ca()? {
        true => {
            debug!("Certificat self-signed, on ajout marqueurs de millegrille");
            (enveloppe.calculer_idmg()?, true)
        },
        false => (enveloppe.idmg()?, false)
    };

    // Separer les fingerprint et pems de la chaine.
    let fp_certs = enveloppe.chaine_fingerprint_pem()?;
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
    if let Some(extensions) = enveloppe.get_extensions()? {
        if let Some(exchanges) = &extensions.exchanges {
            set_on_insert.insert("exchanges", to_bson(exchanges).expect("Erreur conversion exchanges"));
        }
        if let Some(domaines) = &extensions.domaines {
            set_on_insert.insert("domaines", to_bson(domaines).expect("Erreur conversion domaines"));
        }
        if let Some(roles) = &extensions.roles {
            set_on_insert.insert("roles", to_bson(roles).expect("Erreur conversion roles"));
        }
        if let Some(user_id) = &extensions.user_id {
            set_on_insert.insert("user_id", to_bson(user_id).expect("Erreur conversion user_id"));
        }
        if let Some(delegation_globale) = &extensions.delegation_globale {
            set_on_insert.insert("delegation_globale", to_bson(delegation_globale).expect("Erreur conversion delegation_globale"));
        }
        if let Some(delegation_domaines) = &extensions.delegation_domaines {
            set_on_insert.insert("delegation_domaines", to_bson(delegation_domaines).expect("Erreur conversion delegation_domaines"));
        }
    }
    if let Some(c) = enveloppe.ca_pem()? {
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
            Err(format!("Erreur sauvegarde enveloppe certificat : {:?}", e))?
        }
    }
}

pub async fn emettre_presence_domaine(
    middleware: &(impl ValidateurX509 + GenerateurMessages + ConfigMessages), nom_domaine: &str, reclame_fuuids: bool)
    -> Result<(), Box<dyn Error>>
{

    let instance_id = match &middleware.get_configuration_noeud().instance_id {
        Some(n) => Some(n.clone()),
        None => None,
    };

    let message = json!({
        "instance_id": instance_id,
        "domaine": nom_domaine,
        "sous_domaines": None::<String>,
        "exchanges_routing": None::<String>,
        "primaire": true,
        "reclame_fuuids": reclame_fuuids,
    });

    let routage = RoutageMessageAction::builder(nom_domaine, EVENEMENT_PRESENCE_DOMAINE, vec![Securite::L3Protege])
        .build();

    Ok(middleware.emettre_evenement(routage, &message).await?)
}

pub async fn thread_emettre_presence_domaine<M>(middleware: Arc<M>, nom_domaine: String, reclame_fuuids: bool)
    where M: ConfigMessages + GenerateurMessages + ValidateurX509 + 'static
{
    info!("middleware.thread_emettre_presence_domaine : Debut thread");

    // Attente initiale
    tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
    loop {
        match emettre_presence_domaine(middleware.as_ref(), nom_domaine.as_str(), reclame_fuuids).await {
            Ok(()) => (),
            Err(e) => warn!("Erreur emission presence du domaine : {}", e),
        };
        tokio::time::sleep(tokio::time::Duration::new(120, 0)).await;
    }
}

#[async_trait]
pub trait EmetteurCertificat: Send + Sync {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), crate::error::Error>;
    async fn repondre_certificat<S,T>(&self, reply_q: S, correlation_id: T) -> Result<(), crate::error::Error>
        where S: AsRef<str> + Send, T: AsRef<str> + Send;
}

#[async_trait]
impl EmetteurCertificat for ValidateurX509Impl {
    async fn emettre_certificat(&self, _: &impl GenerateurMessages) -> Result<(), crate::error::Error> {
        todo!()
    }

    async fn repondre_certificat<S, T>(&self, reply_q: S, correlation_id: T) -> Result<(), crate::error::Error>
        where S: AsRef<str> + Send, T: AsRef<str> + Send
    {
        todo!()
    }
}

pub fn formatter_message_certificat(enveloppe: &EnveloppeCertificat) -> Result<ReponseEnveloppe, crate::error::Error> {
    let pem_vec = enveloppe.chaine_fingerprint_pem()?;
    let mut pems = Vec::new();
    for cert in pem_vec {
        pems.push(cert.pem);
    };

    let reponse = ReponseEnveloppe {
        chaine_pem: pems,
        fingerprint: enveloppe.fingerprint()?.to_owned(),
        ca_pem: enveloppe.ca_pem()?,
    };

    Ok(reponse)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseCertificat {
    pub ok: Option<bool>,
    pub chaine_pem: Option<Vec<String>>,
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

impl TryInto<ReponseEnveloppe> for ReponseCertificat {
    type Error = crate::error::Error;

    fn try_into(self) -> Result<ReponseEnveloppe, Self::Error> {
        let chaine_pem = match self.chaine_pem { Some(inner) => inner, None => Err(crate::error::Error::Str("ReponseCertificat chaine_pem manquant"))?};
        let fingerprint = match self.fingerprint { Some(inner) => inner, None => Err(crate::error::Error::Str("ReponseCertificat fingerprint manquant"))?};
        Ok(ReponseEnveloppe {
            chaine_pem,
            fingerprint,
            ca_pem: self.ca_pem,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReponseEnveloppe {
    pub chaine_pem: Vec<String>,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

pub async fn thread_charger_certificats_chiffrage<M>(middleware: &M)
where M: GenerateurMessages + ValidateurX509 + ConfigMessages + CleChiffrageHandler + CleChiffrageCache + 'static
{
    info!("middleware.thread_charger_certificats_chiffrage : Debut thread");

    // Attente initiale
    tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

    let mut certificats_charges = false;
    loop {
        match charger_certificats_chiffrage(middleware).await {
            Ok(()) => {
                certificats_charges = true;
            },
            Err(e) => warn!("thread_charger_certificats_chiffrage Erreur chargement certificats de chiffrage : {}", e),
        };

        let attente = match certificats_charges {
            true => 900,  // Certificats charges, attendre 15 minutes pour refresh
            false => 20,  // Certificats absents, reessayer regulierement
        };
        tokio::time::sleep(tokio::time::Duration::new(attente, 0)).await;
    }
}

pub async fn thread_entretien_validateur<M>(middleware: &M)
where M: ValidateurX509 + 'static
{
    info!("middleware.thread_entretien_validateur : Debut thread");
    loop {
        tokio::time::sleep(tokio::time::Duration::new(180, 0)).await;
        middleware.entretien_validateur().await;
    }
}

pub async fn sauvegarder_traiter_transaction_serializable<M,G,S>(middleware: &M, valeur: &S, gestionnaire: &G, domaine: &str, action: &str)
    -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
        G: GestionnaireDomaine,
        S: Serialize + Send + Sync
{
    let mut routage = RoutageMessageAction::builder(domaine, action, vec![Securite::L3Protege]).build();

    // Batir message
    let (message, message_id, certificat) = {
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let (message, message_id) = build_message_action(
            millegrilles_cryptographie::messages_structs::MessageKind::Transaction,
            routage.clone(), valeur, enveloppe_privee.as_ref())?;
        let certificat = enveloppe_privee.enveloppe_pub.clone();
        (message, message_id, certificat)
    };

    // Completer routage avec nouveau correlation_id
    routage.correlation_id = Some(message_id);
    let type_message_out = TypeMessageOut::Transaction(routage);
    let message_valide = MessageValide { message, type_message: type_message_out, certificat };

    Ok(sauvegarder_traiter_transaction(middleware, message_valide, gestionnaire).await?)
}

/// Sauvegarde une nouvelle transaction et de la traite immediatement
pub async fn sauvegarder_traiter_transaction<M, G>(
    middleware: &M, message: MessageValide, gestionnaire: &G
)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        G: GestionnaireDomaine
{
    let nom_collection_transactions = match gestionnaire.get_collection_transactions() {
        Some(n) => n,
        None => {
            Err(format!("middleware.sauvegarder_traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))?
        }
    };

    // let doc_transaction =
    match sauvegarder_transaction(middleware, &message, nom_collection_transactions.as_str()).await {
        Ok(d) => Ok(d),
        Err(e) => Err(format!("middleware.sauvegarder_traiter_transaction Erreur sauvegarde transaction : {:?}", e))
    }?;

    let message_id = {
        let message_ref = message.message.parse()?;
        message_ref.id.to_owned()
    };

    // Traiter transaction
    let reponse = gestionnaire.aiguillage_transaction(middleware, message.try_into()?).await?;

    debug!("middleware.sauvegarder_traiter_transaction Transaction {} traitee", message_id);

    marquer_transaction(
        middleware,
        &nom_collection_transactions,
        message_id,
        EtatTransaction::Complete
    ).await?;

    Ok(reponse)
}

/// Serialize et conserve une nouvelle transaction.
/// Retourne la reponse (Option) et le message_id (String).
pub async fn sauvegarder_traiter_transaction_serializable_v2<M,G,S>(middleware: &M, valeur: &S, gestionnaire: &G, domaine: &str, action: &str)
                                                                 -> Result<(Option<MessageMilleGrillesBufferDefault>, String), crate::error::Error>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/,
        G: GestionnaireDomaineV2 + AiguillageTransactions,
        S: Serialize + Send + Sync
{
    if middleware.get_mode_regeneration() {
        Err("Regeneration en cours")?
    }

    let mut routage = RoutageMessageAction::builder(domaine, action, vec![Securite::L3Protege]).build();

    // Batir message
    let (message, message_id, certificat) = {
        let enveloppe_privee = middleware.get_enveloppe_signature();
        let (message, message_id) = build_message_action(
            millegrilles_cryptographie::messages_structs::MessageKind::Transaction,
            routage.clone(), valeur, enveloppe_privee.as_ref())?;
        let certificat = enveloppe_privee.enveloppe_pub.clone();
        (message, message_id, certificat)
    };

    // Completer routage avec nouveau correlation_id
    routage.correlation_id = Some(message_id.clone());
    let type_message_out = TypeMessageOut::Transaction(routage);
    let message_valide = MessageValide { message, type_message: type_message_out, certificat };

    Ok((sauvegarder_traiter_transaction_v2(middleware, message_valide, gestionnaire).await?, message_id))
}

/// Sauvegarde une nouvelle transaction et de la traite immediatement
pub async fn sauvegarder_traiter_transaction_v2<M, G>(
    middleware: &M, message: MessageValide, gestionnaire: &G
)
    -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        G: GestionnaireDomaineV2 + AiguillageTransactions
{
    if middleware.get_mode_regeneration() {
        Err("Regeneration en cours")?
    }

    let message_id = {
        let message_ref = message.message.parse()?;
        message_ref.id.to_owned()
    };
    let bid_complete = hex::decode(message_id.as_str())?;
    let bid_truncated = &bid_complete[0..16];
    let bid_truncated_base64 = general_purpose::STANDARD.encode(bid_truncated);
    let bid_truncated_bson = Bson::Binary(bson::Binary::from_base64(bid_truncated_base64, None)
        .expect("bid_truncated_bson base64"));

    let nom_collection_transactions = match gestionnaire.get_collection_transactions() {
        Some(n) => n,
        None => {
            Err(format!("middleware.sauvegarder_traiter_transaction_v2 Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))?
        }
    };

    // Detecter duplication via index unique sur bid_truncated
    let doc_transaction_traitee = doc!{
        "bid_truncated": bid_truncated_bson,
        TRANSACTION_CHAMP_ID: &message_id,
        "date_traitement": None::<&str>,
        "ok": None::<bool>,
    };
    let collection_transactions_traitees = middleware.get_collection(format!("{}/transactions_traitees", nom_collection_transactions))?;
    if let Err(e) = collection_transactions_traitees.insert_one(doc_transaction_traitee, None).await {
        if verifier_erreur_duplication_mongo(&e.kind) {
            // Transaction dupliquee deja recu. On repond Ok immediatement avec code duplication.
            return Ok(Some(middleware.reponse_ok(Some(1001), Some("Transaction dupliquee"))?))
        } else {
            Err(format!("middleware.sauvegarder_traiter_transaction_v2 Erreur sauvegarde transactions_traitees : {:?}", e))?
        }
    }

    // let doc_transaction =
    match sauvegarder_transaction(middleware, &message, nom_collection_transactions.as_str()).await {
        Ok(d) => Ok(d),
        Err(e) => Err(format!("middleware.sauvegarder_traiter_transaction_v2 Erreur sauvegarde transaction : {:?}", e))
    }?;

    let message_id = {
        let message_ref = message.message.parse()?;
        message_ref.id.to_owned()
    };

    // Traiter transaction
    let reponse = gestionnaire.aiguillage_transaction(middleware, message.try_into()?).await?;

    debug!("middleware.sauvegarder_traiter_transaction_v2 Transaction {} traitee", message_id);

    marquer_transaction_v2(
        middleware,
        &nom_collection_transactions,
        message_id,
        EtatTransaction::Complete,
        Some(true)
    ).await?;

    Ok(reponse)
}


pub async fn sauvegarder_transaction<M>(middleware: &M, m: &MessageValide, nom_collection: &str)
    -> Result<(), crate::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let mut message_ref = m.message.parse()?;

    // Fix deserialization contenu en utilisant une version owned
    let mut message_owned: MessageMilleGrillesOwned = serde_json::from_slice(m.message.buffer.as_slice())?;

    // Retirer les attachements si presents
    message_owned.attachements = None;

    // Serialiser le message en serde::Value - permet de convertir en Document bson
    let mut contenu_doc = match map_msg_to_bson(message_owned) {
        Ok(d) => d,
        Err(e) => Err(format!("sauvegarder_transaction Erreur conversion doc vers bson : {:?}", e))?
    };

    debug!("sauvegarder_transaction Transaction en format bson : {:?}", contenu_doc);

    let date_courante = chrono::Utc::now();
    let uuid_transaction = message_ref.id;
    let estampille = &message_ref.estampille;
    let routage = message_ref.routage.as_ref();
    match routage {
        Some(inner) => {
            if inner.domaine.is_none() {
                Err(format!("sauvegarder_transaction Domaine absent de la transaction {}", uuid_transaction))?;
            };
            if inner.action.is_none() {
                Err(format!("sauvegarder_transaction Action absente de la transaction {}", uuid_transaction))?;
            };
        },
        None => Err(format!("sauvegarder_transaction Routage absent de la transaction {}", uuid_transaction))?,
    }

    let params_evenements = doc! {
        "document_persiste": date_courante,
        "_estampille": estampille,
        "transaction_complete": false,
        "backup_flag": false,
        "signature_verifiee": date_courante,
    };

    debug!("sauvegarder_transaction evenements tags : {:?}", params_evenements);
    contenu_doc.insert("_evenements", params_evenements);
    debug!("sauvegarder_transaction Inserer nouvelle transaction\n:{:?}", contenu_doc);

    let collection = middleware.get_collection(nom_collection)?;
    match collection.insert_one(&contenu_doc, None).await {
        Ok(_) => {
            debug!("sauvegarder_transaction Transaction sauvegardee dans collection de reception");
            Ok(())
        },
        Err(e) => {
            //let kind = *e.kind.clone();
            let erreur_duplication = verifier_erreur_duplication_mongo(&*e.kind);
            if erreur_duplication {
                // Ok, duplicate. On peut traiter la transaction (si ce n'est pas deja fait).
                info!("sauvegarder_transaction Transaction dupliquee (on va la traiter quand meme) : {:?}", uuid_transaction);
                Ok(())
            } else {
                error!("sauvegarder_transaction Erreur sauvegarde transaction dans MongoDb : {:?}", e);
                Err(format!("sauvegarder_transaction Erreur sauvegarde transaction dans MongoDb : {:?}", &e))
            }
        }
    }?;

    Ok(())
}

pub fn map_msg_to_bson(msg: MessageMilleGrillesOwned) -> Result<Document, Box<dyn Error>> {
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

pub fn preparer_middleware_message() -> MiddlewareHooks {
    let ressources = configurer();

    let configuration = ressources.configuration.clone();

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

    let middleware = Arc::new(MiddlewareMessage {
        ressources,
        redis: redis_dao,
        cle_chiffrage_handler: CleChiffrageHandlerImpl::new()
    });

    // Preparer threads execution
    let rabbitmq = middleware.ressources.rabbitmq.clone();
    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();
    futures.push(tokio::spawn(run_rabbitmq(middleware.clone(), rabbitmq, configuration)));

    MiddlewareHooks { middleware, futures }
}

/// Requete pour obtenir un certificat a partir du domaine PKI
pub async fn requete_certificat<M,S>(middleware: &M, fingerprint: S) -> Result<Option<Arc<EnveloppeCertificat>>, crate::error::Error>
    where
        M: ValidateurX509 + GenerateurMessages,
        S: AsRef<str>
{
    let fingerprint_str = fingerprint.as_ref();
    debug!("requete_certificat {}", fingerprint_str);

    let requete = json!({"fingerprint": fingerprint_str});
    let routage = RoutageMessageAction::builder(PKI_DOMAINE_NOM, PKI_REQUETE_CERTIFICAT, vec![Securite::L1Public])
        .build();
    let reponse_requete = middleware.transmettre_requete(routage, &requete).await?;
    debug!("requete_certificat Reponse : {:?}", reponse_requete);
    let reponse: ReponseEnveloppe = match reponse_requete {
        Some(inner) => match inner {
            TypeMessage::Valide(m) => {
                debug!("requete_certificat Message certificat recu : {}", from_utf8(m.message.buffer.as_slice())?);
                let reponse_certificat: ReponseCertificat = deser_message_buffer!(m.message);
                if let Some(false) = reponse_certificat.ok {
                    Err(crate::error::Error::String(format!("Certificat {} inconnu par CorePki", fingerprint_str)))?
                } else {
                    reponse_certificat.try_into()?
                }
            },
            TypeMessage::Certificat(m) => {
                let enveloppe = m.enveloppe_certificat;
                let pem_ca = enveloppe.ca_pem()?;
                let pems: Vec<String> = enveloppe.chaine_fingerprint_pem()?.into_iter().map(|f| f.pem).collect();
                ReponseEnveloppe { chaine_pem: pems, fingerprint: enveloppe.fingerprint()?, ca_pem: pem_ca }
            },
            _ => Err(format!("requete_certificat Erreur requete certificat {} : mauvais type reponse", fingerprint_str))?
        },
        None => Err(format!("requete_certificat Erreur requete certificat {} : aucune reponse", fingerprint_str))?
    };

    let ca_pem = match &reponse.ca_pem {
        Some(c) => Some(c.as_str()),
        None => None
    };

    Ok(Some(middleware.charger_enveloppe(&reponse.chaine_pem, Some(reponse.fingerprint.as_str()), ca_pem).await?))
}

pub async fn charger_certificats_chiffrage<M>(middleware: &M)
    -> Result<(), crate::error::Error>
    where M: GenerateurMessages + ValidateurX509 + ConfigMessages + CleChiffrageHandler + CleChiffrageCache
{
    debug!("Charger les certificats de maitre des cles pour chiffrage");

    if let Some(TypeMessage::Valide(message)) = emettre_commande_certificat_maitredescles(middleware).await {
        let certificat = message.certificat;
        if let Err(e) = middleware.ajouter_certificat_chiffrage(certificat) {
            error!("Erreur reception certificat chiffrage : {:?}", e);
        }
    }

    // Donner une chance aux certificats de rentrer
    tokio::time::sleep(tokio::time::Duration::new(5, 0)).await;

    // Verifier si on a au moins un certificat
    let nb_certs = middleware.get_publickeys_chiffrage().len();
    if nb_certs == 0 {
        Err(format!("Echec, aucuns certificats de maitre des cles recus"))?
    } else {
        warn!("On a {} certificats de maitre des cles valides", nb_certs);
    }

    Ok(())
}
