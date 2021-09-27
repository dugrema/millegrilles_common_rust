use std::collections::HashMap;
use std::convert::TryFrom;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use lapin::message::Delivery;
use log::{debug, error, info, warn};
use mongodb::{bson::{doc, to_bson}, Client, Collection, Cursor, Database};
use mongodb::bson::{Bson, Document};
use mongodb::bson as bson;
use mongodb::options::{AuthMechanism, ClientOptions, Credential, FindOptions, Hint, TlsOptions, UpdateOptions};
use openssl::x509::store::X509Store;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use crate::certificats::{EnveloppeCertificat, EnveloppePrivee, FingerprintCertPublicKey, ValidateurX509, ValidateurX509Impl};
use crate::chiffrage::{Chiffreur, CipherMgs2, Dechiffreur, Mgs2CipherData};
use crate::configuration::{charger_configuration_avec_db, ConfigMessages, ConfigurationMessages, ConfigurationMessagesDb, ConfigurationMq, ConfigurationNoeud, ConfigurationPki, IsConfigNoeud};
use crate::constantes::*;
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, GenerateurMessagesImpl, RoutageMessageReponse, RoutageMessageAction};
use crate::mongo_dao::{initialiser as initialiser_mongodb, MongoDao, MongoDaoImpl};
use crate::rabbitmq_dao::{Callback, ConfigQueue, ConfigRoutingExchange, EventMq, executer_mq, MessageOut, QueueType, RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::{ErreurVerification, MessageCertificat, MessageValide, MessageValideAction, recevoir_messages, TypeMessage, valider_message};
use crate::transactions::{transmettre_evenement_persistance, TransactionImpl};
use crate::verificateur::{ResultatValidation, ValidationOptions, VerificateurMessage, verifier_message};

/// Super-trait pour tous les traits implementes par Middleware
pub trait Middleware:
    ValidateurX509 + GenerateurMessages + MongoDao + ConfigMessages + IsConfigurationPki +
    IsConfigNoeud + FormatteurMessage + Chiffreur + Dechiffreur + EmetteurCertificat + VerificateurMessage
{
}

pub fn configurer(
    queues: Vec<QueueType>,
    listeners: Option<Mutex<Callback<'static, EventMq>>>
) -> (Arc<ConfigurationMessagesDb>, Arc<ValidateurX509Impl>, Arc<MongoDaoImpl>, RabbitMqExecutor, GenerateurMessagesImpl) {
    let configuration = Arc::new(charger_configuration_avec_db().expect("Erreur configuration"));

    let pki = configuration.get_configuration_pki();

    // Preparer instances utils
    let validateur = pki.get_validateur();

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

pub trait IsConfigurationPki {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee>;
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseCertificatMaitredescles {
    certificat: Vec<String>,
    certificat_millegrille: String,
}
impl ReponseCertificatMaitredescles {
    pub async fn get_enveloppe_maitredescles<V>(&self, validateur: &V) -> Result<Arc<EnveloppeCertificat>, Box<dyn Error>>
    where
        V: ValidateurX509,
    {
        Ok(validateur.charger_enveloppe(&self.certificat, None).await?)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrageCle {
    acces: String,
    pub cles: Option<HashMap<String, ReponseDechiffrageCleInfo>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReponseDechiffrageCleInfo {
    acces: String,
    cle: String,
    domaine: String,
    format: String,
    identificateurs_document: Option<HashMap<String, String>>,
    iv: String,
    tag: String,
}

impl ReponseDechiffrageCle {
    pub fn to_cipher_data(&self) -> Result<Mgs2CipherData, Box<dyn Error>> {
        match &self.cles {
            Some(cles) => {
                if cles.len() == 1 {
                    let (_, cle) = cles.iter().next().expect("cle");
                    cle.to_cipher_data()
                } else {
                    Err(String::from("Plusieurs cles presentes"))?
                }
            },
            None => {
                Err(String::from("Aucunes cles presentes"))?
            }
        }
    }
}

impl ReponseDechiffrageCleInfo {
    pub fn to_cipher_data(&self) -> Result<Mgs2CipherData, Box<dyn Error>> {
        Mgs2CipherData::new(&self.cle, &self.iv, &self.tag)
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

    async fn emettre_evenement<M>(&self, routage: RoutageMessageAction, message: &M)
        -> Result<(), String>
        where M: Serialize + Send + Sync
    {
        self.generateur_messages.emettre_evenement(routage, message).await
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
        self.generateur_messages.emettre_message(routage, type_message, message, blocking).await
    }

    async fn emettre_message_millegrille(&self, routage: RoutageMessageAction, blocking: bool, type_message: TypeMessageOut, message: MessageMilleGrille)
        -> Result<Option<TypeMessage>, String> {
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
        self.generateur_messages.get_mode_regeneration()
    }

}

#[async_trait]
impl MongoDao for MiddlewareDb {
    fn get_database(&self) -> Result<Database, String> {
        self.mongo.get_database()
    }
}

impl FormatteurMessage for MiddlewareDb {}

impl IsConfigurationPki for MiddlewareDb {
    fn get_enveloppe_privee(&self) -> Arc<EnveloppePrivee> {
        let pki = self.configuration.get_configuration_pki();
        pki.get_enveloppe_privee()
    }
}

impl Chiffreur for MiddlewareDb {
    fn get_publickeys_chiffrage(&self) -> Vec<FingerprintCertPublicKey> {
        todo!("Pas implemente")
        // let guard = self.cles_chiffrage.lock().expect("lock");
        //
        // // Copier les cles (extraire du mutex), retourner dans un vecteur
        // let vals: Vec<FingerprintCertPublicKey> = guard.iter().map(|v| v.1.to_owned()).collect();
        //
        // vals
    }
}

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
        "exchanges_routing": None::<String>,
        // "exchanges_routing": {
        //     "1.public": ["requete.Principale.test"],
        //     "2.prive": ["requete.Principale.test"],
        //     "3.protege": ["requete.Principale.test"],
        // },
        "primaire": true,
    });

    let routage = RoutageMessageAction::builder("presence", "domaine")
        .exchanges(vec!(Securite::L3Protege))
        .build();

    // todo Reactiver emettre presence quand modules transactions va etre desactive
    // Ok(middleware.emettre_evenement(routage, &message).await?)

    Ok(())
}

pub async fn thread_emettre_presence_domaine<M>(middleware: Arc<M>, nom_domaine: &str)
    where M: ConfigMessages + GenerateurMessages + ValidateurX509 + 'static
{
    // Attente initiale
    tokio::time::sleep(tokio::time::Duration::new(15, 0)).await;
    loop {
        match emettre_presence_domaine(middleware.as_ref(), nom_domaine).await {
            Ok(()) => (),
            Err(e) => warn!("Erreur emission presence du domaine : {}", e),
        };
        tokio::time::sleep(tokio::time::Duration::new(120, 0)).await;
    }
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

// pub async fn regenerer<M, T>(middleware: &M, nom_collection_transactions: &str, noms_collections_docs: Vec<String>, processor: &T) -> Result<(), Box<dyn Error>>
// where
//     M: ValidateurX509 + GenerateurMessages + MongoDao,
//     T: TraiterTransaction,
// {
//     // Supprimer contenu des collections
//     for nom_collection in noms_collections_docs {
//         let collection = middleware.get_collection(nom_collection.as_str())?;
//         let resultat_delete = collection.delete_many(doc! {}, None).await?;
//         debug!("Delete collection {} documents : {:?}", nom_collection, resultat_delete);
//     }
//
//     // Creer curseur sur les transactions en ordre de traitement
//     let mut resultat_transactions = {
//         let filtre = doc! {
//             TRANSACTION_CHAMP_TRANSACTION_TRAITEE: {"$exists": true},
//         };
//         let sort = doc! {
//             TRANSACTION_CHAMP_TRANSACTION_TRAITEE: 1,
//         };
//
//         let options = FindOptions::builder()
//             .sort(sort)
//             .hint(Hint::Name(String::from("backup_transactions")))
//             .build();
//
//         let collection_transactions = middleware.get_collection(nom_collection_transactions)?;
//         collection_transactions.find(filtre, options).await
//     }?;
//
//     middleware.set_regeneration(); // Desactiver emission de messages
//
//     // Executer toutes les transactions du curseur en ordre
//     let resultat = regenerer_transactions(middleware, &mut resultat_transactions, processor).await;
//
//     middleware.reset_regeneration(); // Reactiver emission de messages
//
//     resultat
// }
//
// async fn regenerer_transactions<M, T>(middleware: &M, curseur: &mut Cursor<Document>, processor: &T) -> Result<(), Box<dyn Error>>
// where
//     M: ValidateurX509 + GenerateurMessages + MongoDao,
//     T: TraiterTransaction,
// {
//     while let Some(result) = curseur.next().await {
//         let transaction = result?;
//         debug!("Transaction a charger : {:?}", transaction);
//
//         let message = MessageSerialise::from_serializable(transaction)?;
//
//         let (uuid_transaction, domaine, action) = match message.get_entete().domaine.as_ref() {
//             Some(inner_d) => {
//                 let entete = message.get_entete();
//                 let uuid_transaction = entete.uuid_transaction.to_owned();
//                 let mut d_split = inner_d.split(".");
//                 let domaine: String = d_split.next().expect("Domaine manquant de la RK").into();
//                 let action: String = d_split.last().expect("Action manquante de la RK").into();
//                 (uuid_transaction, domaine, action)
//             },
//             None => {
//                 warn!("Transaction sans domaine - invalide: {:?}", message);
//                 continue  // Skip
//             }
//         };
//
//         let transaction_prep = MessageValideAction {
//             message,
//             reply_q: None,
//             correlation_id: Some(uuid_transaction.to_owned()),
//             routing_key: String::from("regeneration"),
//             domaine,
//             action,
//             exchange: None,
//             type_message: TypeMessageOut::Transaction,
//         };
//
//         processor.traiter_transaction("Pki", middleware, transaction_prep).await?;
//     }
//
//     Ok(())
// }

pub async fn sauvegarder_transaction_recue<M>(middleware: &M, m: MessageValideAction, nom_collection: &str) -> Result<(), String>
    where M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    let entete = m.message.get_entete();

    match sauvegarder_transaction(middleware, &m, nom_collection).await {
        Ok(()) => (),
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

pub async fn sauvegarder_transaction<M>(middleware: &M, m: &MessageValideAction, nom_collection: &str) -> Result<(), Box<dyn Error>>
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
    let domaine = match entete.domaine.as_ref() {
        Some(d) => d.as_str(),
        None => Err(format!("Domaine absent de la transaction {}", uuid_transaction))?,
    };
    let action = match entete.action.as_ref() {
        Some(a) => a.as_str(),
        None => Err(format!("Action absente de la transaction {}", uuid_transaction))?,
    };
    let partition = match entete.partition.as_ref() {
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
    match collection.insert_one(contenu_doc, None).await {
        Ok(_) => {
            debug!("Transaction sauvegardee dans collection de reception");
            Ok(())
        },
        Err(e) => {
            error!("Erreur sauvegarde transaction dans MongoDb : {:?}", e);
            Err(format!("Erreur sauvegarde transaction dans MongoDb : {:?}", e))
        }
    }?;

    Ok(())
}

pub fn map_msg_to_bson(msg: &MessageMilleGrille) -> Result<Document, Box<dyn Error>> {
    let val = match serde_json::to_value(msg) {
        Ok(v) => match v.as_object() {
            Some(o) => o.to_owned(),
            None => Err(format!("Erreur sauvegarde transaction, mauvais type objet JSON"))?,
        },
        Err(e) => Err(format!("Erreur sauvegarde transaction, conversion : {:?}", e))?,
    };

    let mut contenu_doc = match Document::try_from(val) {
        Ok(c) => Ok(c),
        Err(e) => {
            error!("Erreur conversion json -> bson\n{:?}", e.to_string());
            Err(format!("Erreur sauvegarde transaction, conversion json -> bson : {:?}", e))
        },
    }?;

    Ok(contenu_doc)
}

// #[async_trait]
// pub trait TraiterTransaction {
//     // async fn sauvegarder_transaction<M>(&self, middleware: &M, m: MessageValideAction, domaine: &str, nom_collection: &str) -> Result<(), String>
//     //     where M: ValidateurX509 + GenerateurMessages + MongoDao;
//     async fn traiter_transaction<M>(&self, domaine: &str, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
//         where M: ValidateurX509 + GenerateurMessages + MongoDao;
// }

// #[cfg(test)]
// pub mod serialization_tests {
//     use crate::certificats::certificats_tests::charger_enveloppe_privee_env;
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     pub async fn build() -> (Arc<MiddlewareDbPki>, FuturesUnordered<JoinHandle<()>>, Sender<TypeMessage>, Sender<TypeMessage>) {
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
//             future_recevoir_messages
//         ) = preparer_middleware_pki(queues, listeners);
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
//     pub async fn consommer_messages(middleware: Arc<MiddlewareDbPki>, mut rx: Receiver<TypeMessage>) {
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
//     #[tokio::test]
//     async fn connecter_middleware_pki() {
//         setup("connecter_middleware_pki");
//
//         // Connecter mongo
//         //let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//         let (
//             middleware,
//             mut futures,
//             mut tx_messages,
//             mut tx_triggers
//         ) = build().await;
//         futures.push(tokio::spawn(async move {
//             debug!("Cles chiffrage initial (millegrille uniquement) : {:?}", middleware.cles_chiffrage);
//
//             debug!("Sleeping");
//             tokio::time::sleep(tokio::time::Duration::new(3, 0)).await;
//             debug!("Fin sleep");
//
//             middleware.charger_certificats_chiffrage().await;
//
//             debug!("Cles chiffrage : {:?}", middleware.cles_chiffrage);
//             let cles = middleware.cles_chiffrage.lock().expect("lock");
//             assert_eq!(2, cles.len());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     /// Test d'acces au MaitreDesCles. Doit creer une cle secrete, la chiffrer avec les certificats
//     /// recus, emettre la cle puis recuperer une version dechiffrable localement.
//     #[tokio::test]
//     async fn roundtrip_cle_secrete() {
//         setup("connecter_middleware_pki");
//
//         // Connecter mongo
//         //let (middleware, _, _, mut futures) = preparer_middleware_pki(Vec::new(), None);
//         let (
//             middleware,
//             mut futures,
//             mut tx_messages,
//             mut tx_triggers
//         ) = build().await;
//         futures.push(tokio::spawn(async move {
//             debug!("Cles chiffrage initial (millegrille uniquement) : {:?}", middleware.cles_chiffrage);
//
//             debug!("Sleeping");
//             tokio::time::sleep(tokio::time::Duration::new(4, 0)).await;
//             debug!("Fin sleep");
//             middleware.charger_certificats_chiffrage().await;
//
//             debug!("Cles chiffrage : {:?}", middleware.cles_chiffrage);
//
//             const VALEUR_TEST: &[u8] = b"Du data a chiffrer";
//
//             let (vec_output, cipher_keys) = {
//                 let mut vec_output: Vec<u8> = Vec::new();
//                 let mut cipher = middleware.get_cipher();
//                 let mut output = [0u8; 40];
//                 let len_output = cipher.update(b"Du data a chiffrer", &mut output).expect("update");
//                 vec_output.extend_from_slice(&output[..len_output]);
//                 let len_output = cipher.finalize(&mut output).expect("finalize");
//                 debug!("Finalize cipher : {:?}", &output[..len_output]);
//                 vec_output.extend_from_slice(&output[..len_output]);
//
//                 (vec_output, cipher.get_cipher_keys().expect("cipher keys"))
//             };
//
//             debug!("Data chiffre : {:?}\nCipher keys : {:?}", vec_output, cipher_keys);
//
//             let mut id_docs = HashMap::new();
//             id_docs.insert(String::from("test"), String::from("dummy"));
//             let commande = cipher_keys.get_commande_sauvegarder_cles("Test", id_docs);
//             let hachage_bytes = commande.hachage_bytes.clone();
//             debug!("Commande sauvegarder cles : {:?}", commande);
//
//             let reponse_sauvegarde = middleware.transmettre_commande(
//                 "MaitreDesCles.sauvegarderCle", "sauvegarderCle", None, &commande, None, true)
//                 .await.expect("reponse");
//
//             debug!("Reponse sauvegarde cle : {:?}", reponse_sauvegarde);
//
//             let requete = {
//                 let mut liste_hachage_bytes = Vec::new();
//                 liste_hachage_bytes.push(hachage_bytes.clone());
//                 json!({
//                     "liste_hachage_bytes": liste_hachage_bytes,
//                 })
//             };
//             let reponse_cle_rechiffree = middleware.transmettre_requete(
//                 "MaitreDesCles.dechiffrage", "dechiffrage", None, &requete, None).await.expect("requete cle");
//             debug!("Reponse cle rechiffree : {:?}", reponse_cle_rechiffree);
//
//             let mut decipher = middleware.get_decipher(&hachage_bytes).await.expect("decipher");
//             let mut vec_buffer = {
//                 let mut buffer_output = [0u8; 40];
//                 let len_dechiffre = decipher.update(vec_output.as_slice(), &mut buffer_output).expect("update");
//                 let mut vec_buffer = Vec::new();
//                 vec_buffer.extend(&buffer_output[..len_dechiffre]);
//
//                 vec_buffer
//             };
//
//             assert_eq!(VALEUR_TEST, vec_buffer.as_slice());
//
//             let message_dechiffre = String::from_utf8(vec_buffer).expect("utf-8");
//             debug!("Data dechiffre : {}", message_dechiffre);
//             {
//                 let mut buffer_output = [0u8; 0];
//                 let output = decipher.finalize(&mut buffer_output).expect("finalize dechiffrer");
//                 assert_eq!(0, output);
//             }
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
// }