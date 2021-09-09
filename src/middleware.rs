use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bson::{Bson, Document};
use futures::stream::FuturesUnordered;
use lapin::message::Delivery;
use log::{debug, error, info, warn};
use mongodb::{bson::{doc, to_bson}, Client, Collection, Database, Cursor};
use mongodb::options::{AuthMechanism, ClientOptions, Credential, TlsOptions, UpdateOptions, FindOptions, Hint};
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, ValidateurX509, ValidateurX509Impl};
use crate::configuration::{charger_configuration_avec_db, ConfigMessages, ConfigurationMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki};
use crate::constantes::*;
use crate::formatteur_messages::FormatteurMessage;
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};

use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl};
use crate::rabbitmq_dao::{Callback, ConfigQueue, ConfigRoutingExchange, EventMq, executer_mq, MessageOut, QueueType, RabbitMqExecutor};
use crate::recepteur_messages::{ErreurVerification, MessageCertificat, MessageValide, MessageValideAction, recevoir_messages, task_requetes_certificats, TypeMessage};
use crate::{MessageSerialise, VerificateurMessage, ValidationOptions, ResultatValidation, verifier_message, MessageMilleGrille, TypeMessageOut};
use std::error::Error;
use serde::Serialize;

/// Version speciale du middleware avec un acces direct au sous-domaine Pki dans MongoDB
pub fn preparer_middleware_pki(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<MiddlewareDbPki>, Receiver<TypeMessage>, Receiver<TypeMessage>, FuturesUnordered<JoinHandle<()>>) {
    let (
        configuration,
        validateur,
        mongo,
        mq_executor,
        generateur_messages
    ) = configurer(queues, listeners);

    let generateur_messages_arc = Arc::new(generateur_messages);

    let validateur_db = Arc::new(ValidateurX509Database::new(
        mongo.clone(),
        validateur.clone(),
        generateur_messages_arc.clone(),
    ));

    let middleware = Arc::new(MiddlewareDbPki {
        configuration,
        mongo,
        validateur: validateur_db.clone(),
        generateur_messages: generateur_messages_arc.clone(),
    });

    let (tx_messages_verifies, rx_messages_verifies) = mpsc::channel(3);
    let (tx_triggers, rx_triggers) = mpsc::channel(3);

    let (tx_certificats_manquants, rx_certificats_manquants) = mpsc::channel(10);

    let futures: FuturesUnordered<JoinHandle<()>> = FuturesUnordered::new();

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_messages,
        tx_messages_verifies.clone(),
        tx_certificats_manquants.clone()
    )));

    futures.push(tokio::spawn(recevoir_messages(
        middleware.clone(),
        mq_executor.rx_triggers,
        tx_triggers,
        tx_certificats_manquants.clone()
    )));

    // Thread requete certificats manquants
    futures.push(tokio::spawn(task_requetes_certificats(
        middleware.clone(),
        rx_certificats_manquants,
        mq_executor.tx_interne.clone()
    )));

    (middleware, rx_messages_verifies, rx_triggers, futures)
}

fn configurer(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<ConfigurationMessagesDb>, Arc<ValidateurX509Impl>, Arc<MongoDaoImpl>, RabbitMqExecutor, GenerateurMessagesImpl) {
    let configuration = Arc::new(charger_configuration_avec_db().expect("Erreur configuration"));

    let pki = configuration.get_configuration_pki();

    // let pki = match configuration.as_ref() {
    //     TypeConfiguration::ConfigurationMessages { mq: _mq, pki } => pki,
    //     TypeConfiguration::ConfigurationMessagesDb { mq: _mq, mongo: _mongo, pki } => pki,
    // };

    // Preparer instances utils
    let validateur = pki.get_validateur();
    // let enveloppe_privee = pki.get_enveloppe_privee();
    // let formatteur_message: Arc<FormatteurMessage> = Arc::new(FormatteurMessage::new(validateur.clone(), enveloppe_privee));

    // Connecter au middleware mongo et MQ
    let mongo: Arc<MongoDaoImpl> = Arc::new(initialiser_mongodb(configuration.as_ref()).expect("Erreur connexion MongoDB"));
    let mq_executor = executer_mq(
        configuration.clone(),
        Some(queues),
        listeners,
    ).expect("Erreur demarrage MQ");

    let generateur_messages = GenerateurMessagesImpl::new(
        configuration.get_configuration_pki(),
        &mq_executor
    );

    (configuration, validateur, mongo, mq_executor, generateur_messages)
}

// Middleware de base avec validateur et generateur de messages
pub struct MiddlewareMessage {
    configuration: Arc<ConfigurationMessages>,
    validateur: Arc<Box<ValidateurX509Impl>>,
    generateur_messages: GenerateurMessagesImpl
}

// Middleware avec MongoDB
pub struct MiddlewareDb {
    configuration: Arc<ConfigurationMessagesDb>,
    mongo: Arc<MongoDaoImpl>,
    validateur: Arc<Box<ValidateurX509Impl>>,
    generateur_messages: GenerateurMessagesImpl
}

// Middleware avec MongoDB et validateur X509 lie a la base de donnees
pub struct MiddlewareDbPki {
    configuration: Arc<ConfigurationMessagesDb>,
    pub mongo: Arc<MongoDaoImpl>,
    pub validateur: Arc<ValidateurX509Database>,
    pub generateur_messages: Arc<GenerateurMessagesImpl>,
}

pub trait IsConfigurationPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;
}

#[async_trait]
impl ValidateurX509 for MiddlewareDbPki {
    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        self.validateur.charger_enveloppe(chaine_pem, fingerprint).await
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        self.validateur.get_certificat(fingerprint).await
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

    async fn entretien(&self) {

        self.validateur.entretien().await;

        match emettre_presence_domaine(self, PKI_DOMAINE_NOM).await {
            Ok(()) => (),
            Err(e) => warn!("Erreur emission presence du domaine : {}", e),
        };

    }
}

#[async_trait]
impl GenerateurMessages for MiddlewareDbPki {

    async fn emettre_evenement(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchanges: Option<Vec<Securite>>) -> Result<(), String> {
        self.generateur_messages.emettre_evenement( domaine, message, exchanges).await
    }

    async fn transmettre_requete(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>) -> Result<TypeMessage, String> {
        self.generateur_messages.transmettre_requete(domaine, message, exchange).await
    }

    async fn soumettre_transaction(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.soumettre_transaction(domaine, message, exchange, blocking).await
    }

    async fn transmettre_commande(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<TypeMessage, String> {
        self.generateur_messages.transmettre_commande(domaine, message, exchange, blocking).await
    }

    async fn repondre(&self, message: &(impl Serialize + Send + Sync), reply_q: &str, correlation_id: &str) -> Result<(), String> {
        self.generateur_messages.repondre(message, reply_q, correlation_id).await
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
}

impl FormatteurMessage for MiddlewareDbPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

#[async_trait]
impl MongoDao for MiddlewareDbPki {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl ConfigMessages for MiddlewareDbPki {
    fn get_configuration_mq(&self) -> &ConfigurationMq {
        self.configuration.get_configuration_mq()
    }

    fn get_configuration_pki(&self) -> &ConfigurationPki {
        self.configuration.get_configuration_pki()
    }

    fn get_configuration_noeud(&self) -> &ConfigurationNoeud {
        self.configuration.get_configuration_noeud()
    }
}


/// Validateur X509 backe par une base de donnees (Mongo)
/// Permet de charger les certificats et generer les transactions pour les certificats inconnus.
pub struct ValidateurX509Database {
    mongo_dao: Arc<MongoDaoImpl>,
    validateur: Arc<ValidateurX509Impl>,
    generateur_messages: Arc<GenerateurMessagesImpl>
}

impl ValidateurX509Database {

    pub fn new(mongo_dao: Arc<MongoDaoImpl>, validateur: Arc<ValidateurX509Impl>, generateur_messages: Arc<GenerateurMessagesImpl>) -> ValidateurX509Database {
        ValidateurX509Database {
            mongo_dao,
            validateur,
            generateur_messages
        }
    }

    pub async fn entretien(&self) {
        debug!("ValidateurX509Database: Entretien ValidateurX509Database");
        self.validateur.entretien().await;
    }

    async fn upsert_enveloppe(&self, enveloppe: &EnveloppeCertificat) -> Result<(), String> {
        debug!("Upserting enveloppe");

        let db = self.mongo_dao.get_database()?;
        let collection = db.collection(PKI_COLLECTION_CERTIFICAT_NOM);

        match upsert_certificat(enveloppe, collection, None).await? {
            Some(upserted_id) => {
                debug!("Certificat upserted, creer transaction pour sauvegarde permanente");
                let domaine_action = format!("{}.{}", PKI_DOMAINE_NOM, PKI_TRANSACTION_NOUVEAU_CERTIFICAT);

                let fingerprint_certs = enveloppe.get_pem_vec();
                let mut pem_vec = Vec::new();
                for fp_cert in fingerprint_certs {
                    pem_vec.push(fp_cert.pem);
                }
                let pems = pem_vec.join("\n");

                let contenu = json!({
                    "pem": pems
                });
                // let message = self.generateur_messages.formatter_message(
                //     contenu,
                //     Some(&domaine_action),
                //     None
                // );

                match self.generateur_messages.soumettre_transaction(
                    &domaine_action,
                    &contenu,
                    Some(Securite::L3Protege),
                    false
                ).await {
                    Ok(t) => (),
                    Err(e) => error!("Erreur soumission transaction pour nouveau certificat : {}", e),
                };

                // Meme si la transaction echoue, le certificat est deja sauvegarde (dirty=true).
                Ok(())
            },
            None => Ok(()),
        }
    }

}

#[async_trait]
impl ValidateurX509 for ValidateurX509Database {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        debug!("ValidateurX509Database: charger_enveloppe!");
        // let resultat = self.charger_cert_db();

        let enveloppe = self.validateur.charger_enveloppe(chaine_pem, fingerprint).await?;

        // Verifier si le certificat existe dans la base de donnes, creer transaction au besoin
        self.upsert_enveloppe(&enveloppe).await?;

        Ok(enveloppe)
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        debug!("ValidateurX509Database: cacher!");
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        debug!("ValidateurX509Database: get_certificat {}", fingerprint);
        match self.validateur.get_certificat(fingerprint).await {
            Some(enveloppe) => Some(enveloppe),
            None => {
                // Tenter de charger a partir de la base de donnes
                match self.mongo_dao.get_database() {
                    Ok(db) => {

                        let collection = db.collection::<Document>(PKI_COLLECTION_CERTIFICAT_NOM);
                        let filtre = doc! {
                            PKI_DOCUMENT_CHAMP_FINGERPRINT: fingerprint,
                        };
                        let result = collection.find_one(filtre, None).await;
                        match result {
                            Ok(option) => match option {
                                Some(document) => {
                                    match document.get(PKI_DOCUMENT_CHAMP_CERTIFICAT) {
                                        Some(chaine_pem) => {
                                            let mut vec_pems = Vec::new();
                                            for pem in chaine_pem.as_array().expect("pems") {
                                                vec_pems.push(String::from(pem.as_str().expect("un pem")));
                                            }
                                            match self.validateur.charger_enveloppe(&vec_pems, None).await {
                                                Ok(enveloppe) => {
                                                    debug!("Certificat {} charge de la DB", fingerprint);
                                                    Some(enveloppe)
                                                },
                                                Err(t) => None,
                                            }
                                        },
                                        None => None,
                                    }
                                },
                                None => {
                                    debug!("Certificat inconnu (pas dans la DB) {:?}", fingerprint);
                                    None
                                },
                            },
                            Err(e) => {
                                debug!("Erreur!!! {:?}", e);
                                None
                            },
                        }
                    },
                    Err(e) => {
                        debug!("Erreur!!! {:?}", e);
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

    /// Pas invoque
    async fn entretien(&self) {
        self.validateur.entretien().await;
    }

}

#[async_trait]
impl ValidateurX509 for MiddlewareDb {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String> {
        self.validateur.charger_enveloppe(chaine_pem, fingerprint).await
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> Arc<EnveloppeCertificat> {
        self.validateur.cacher(certificat).await
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        self.validateur.get_certificat(fingerprint).await
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

    /// Pas invoque
    async fn entretien(&self) {
        self.validateur.entretien().await;
    }

}

#[async_trait]
impl GenerateurMessages for MiddlewareDb {

    async fn emettre_evenement(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchanges: Option<Vec<Securite>>) -> Result<(), String> {
        self.generateur_messages.emettre_evenement(domaine, message, exchanges).await
    }

    async fn transmettre_requete(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>) -> Result<TypeMessage, String> {
        self.generateur_messages.transmettre_requete(domaine, message, exchange).await
    }

    async fn soumettre_transaction(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<Option<TypeMessage>, String> {
        self.generateur_messages.soumettre_transaction(domaine, message, exchange, blocking).await
    }

    async fn transmettre_commande(&self, domaine: &str, message: &(impl Serialize + Send + Sync), exchange: Option<Securite>, blocking: bool) -> Result<TypeMessage, String> {
        self.generateur_messages.transmettre_commande(domaine, message, exchange, blocking).await
    }

    async fn repondre(&self, message: &(impl Serialize + Send + Sync), reply_q: &str, correlation_id: &str) -> Result<(), String> {
        self.generateur_messages.repondre(message, reply_q, correlation_id).await
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
        self.generateur_messages.get_mode_regeneration()
    }

}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl FormatteurMessage for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        self.configuration.get_configuration_pki().get_enveloppe_privee()
    }
}

impl IsConfigurationPki for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {

        let pki = self.configuration.get_configuration_pki();
        pki.get_enveloppe_privee()

        // match self.configuration.as_ref() {
        //     TypeConfiguration::ConfigurationMessages {mq: _mq, pki} => {
        //         pki.get_enveloppe_privee().clone()
        //     },
        //     TypeConfiguration::ConfigurationMessagesDb {mq: _mq, mongo: _mongo, pki} => {
        //         pki.get_enveloppe_privee().clone()
        //     }
        // }
    }
}

// impl VerificateurMessage for MiddlewareDb {
//     fn verifier_message(
//         message: &MessageJson,
//         options: Option<ValidationOptions>
//     ) -> Result<ResultatValidation, Box<dyn std::error::Error>> {
//         Ok(verifier_message(message, certificat, idmg_local, options)?)
//     }
// }

impl IsConfigurationPki for MiddlewareDbPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {

        let pki = self.configuration.get_configuration_pki();
        pki.get_enveloppe_privee()

        // match self.configuration.as_ref() {
        //     TypeConfiguration::ConfigurationMessages {mq: _mq, pki} => {
        //         pki.get_enveloppe_privee().clone()
        //     },
        //     TypeConfiguration::ConfigurationMessagesDb {mq: _mq, mongo: _mongo, pki} => {
        //         pki.get_enveloppe_privee().clone()
        //     }
        // }
    }
}

#[async_trait]
impl EmetteurCertificat for MiddlewareDbPki {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        let enveloppe_privee = self.configuration.get_configuration_pki().get_enveloppe_privee();
        let message = formatter_message_certificat(enveloppe_privee.enveloppe.as_ref());
        let exchanges = vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege);

        match generateur_message.emettre_evenement(PKI_EVENEMENT_CERTIFICAT, &message, Some(exchanges)).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Erreur emettre_certificat: {:?}", e)),
        }
    }
}

// impl FormatteurMessage for MiddlewareDbPki {
//     fn get_enveloppe_privee(&self) -> &EnveloppePrivee {
//         self.configuration.get_configuration_pki().get_enveloppe_privee().as_ref()
//     }
// }


// impl VerificateurMessage for MiddlewareDbPki {
//     fn verifier_message(
//         &self,
//         message: &MessageJson,
//         options: Option<ValidationOptions>
//     ) -> Result<ResultatValidation, Box<dyn std::error::Error>> {
//
//         let entete = message.get_entete()?;
//         let validateur_x509 = self.configuration.get_configuration_pki().get_validateur();
//         let idmg_local = validateur_x509.idmg().as_str();
//         let certificat_message = message.get_message().get("_certificat");
//
//         Ok(verifier_message(message, certificat, idmg_local, options)?)
//     }
// }

pub async fn upsert_certificat(enveloppe: &EnveloppeCertificat, collection: Collection<Document>, dirty: Option<bool>) -> Result<Option<String>, String> {
    let fingerprint = enveloppe.fingerprint();

    let filtre = doc! { "fingerprint": fingerprint };

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

    let noeud_id = match &middleware.get_configuration_noeud().noeud_id {
        Some(n) => Some(n.clone()),
        None => None,
    };

    let message = json!({
        "idmg": middleware.idmg(),
        "noeud_id": noeud_id,
        "domaine": nom_domaine,
        "sous_domaines": None::<String>,
        "echanges_routing": None::<String>,
        // "exchanges_routing": {
        //     "1.public": ["requete.Principale.test"],
        //     "2.prive": ["requete.Principale.test"],
        //     "3.protege": ["requete.Principale.test"],
        // },
        "primaire": true,
    });

    Ok(middleware.emettre_evenement(
        EVENEMENT_PRESENCE_DOMAINE,
        &message,
        Some(vec!(Securite::L3Protege))
    ).await?)
}

#[async_trait]
pub trait EmetteurCertificat: Send + Sync {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String>;
}

#[async_trait]
impl EmetteurCertificat for ValidateurX509Impl {
    async fn emettre_certificat(&self, generateur_message: &impl GenerateurMessages) -> Result<(), String> {
        todo!()
    }
}

// pub fn formatter_message_enveloppe_privee(enveloppe: &EnveloppePrivee) -> MessageJson {
//     // PKI_EVENEMENT_CERTIFICAT
//     formatter_message_certificat(&enveloppe.enveloppe)
// }

pub fn formatter_message_certificat(enveloppe: &EnveloppeCertificat) -> Value {
    let pem_vec = enveloppe.get_pem_vec();
    let mut pems = Vec::new();
    for cert in pem_vec {
        pems.push(cert.pem);
    };
    let reponse = json! ({
        "chaine_pem": pems,
        "fingerprint": enveloppe.fingerprint(),
    });

    reponse
}

pub async fn regenerer<M, T>(middleware: &M, nom_collection_transactions: &str, noms_collections_docs: Vec<String>, processor: &T) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TraiterTransaction,
{
    // Supprimer contenu des collections
    for nom_collection in noms_collections_docs {
        let collection = middleware.get_collection(nom_collection.as_str())?;
        let resultat_delete = collection.delete_many(doc! {}, None).await?;
        debug!("Delete collection {} documents : {:?}", nom_collection, resultat_delete);
    }

    // Creer curseur sur les transactions en ordre de traitement
    let mut resultat_transactions = {
        let filtre = doc! {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true},
        };
        let sort = doc! {
            TRANSACTION_CHAMP_TRANSACTION_TRAITEE: 1,
        };

        let options = FindOptions::builder()
            .sort(sort)
            .hint(Hint::Name(String::from("backup_transactions")))
            .build();

        let collection_transactions = middleware.get_collection(nom_collection_transactions)?;
        collection_transactions.find(filtre, options).await
    }?;

    middleware.set_regeneration(); // Desactiver emission de messages

    // Executer toutes les transactions du curseur en ordre
    let resultat = regenerer_transactions(middleware, &mut resultat_transactions, processor).await;

    middleware.reset_regeneration(); // Reactiver emission de messages

    resultat
}

async fn regenerer_transactions<M, T>(middleware: &M, curseur: &mut Cursor<Document>, processor: &T) -> Result<(), Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
    T: TraiterTransaction,
{
    while let Some(result) = curseur.next().await {
        let transaction = result?;
        debug!("Transaction a charger : {:?}", transaction);

        let message = MessageSerialise::from_serializable(transaction)?;

        let (uuid_transaction, domaine, action) = match message.get_entete().domaine.as_ref() {
            Some(inner_d) => {
                let entete = message.get_entete();
                let uuid_transaction = entete.uuid_transaction.to_owned();
                let mut d_split = inner_d.split(".");
                let domaine: String = d_split.next().expect("Domaine manquant de la RK").into();
                let action: String = d_split.last().expect("Action manquante de la RK").into();
                (uuid_transaction, domaine, action)
            },
            None => {
                warn!("Transaction sans domaine - invalide: {:?}", message);
                continue  // Skip
            }
        };

        let transaction_prep = MessageValideAction {
            message,
            reply_q: None,
            correlation_id: Some(uuid_transaction.to_owned()),
            routing_key: String::from("regeneration"),
            domaine,
            action,
            exchange: None,
            type_message: TypeMessageOut::Transaction,
        };

        processor.traiter_transaction("Pki", middleware, transaction_prep).await?;
    }

    Ok(())
}

#[async_trait]
pub trait TraiterTransaction {
    async fn traiter_transaction<M>(&self, domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao;
}
