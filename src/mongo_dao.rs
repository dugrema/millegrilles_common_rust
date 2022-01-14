use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, error, info};
use mongodb::{bson::doc, Client, Collection, Database};
use mongodb::bson::Bson;
use mongodb::bson::document::Document;
use mongodb::error::Result as ResultMongo;
use mongodb::options::{AuthMechanism, ClientOptions, Credential, ServerAddress, TlsOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigDb, ConfigMessages, ConfigurationMongo, ConfigurationPki};
use crate::constantes::*;
use serde::de::DeserializeOwned;
use std::error::Error;
use std::time::Duration;

#[async_trait]
pub trait MongoDao: Send + Sync {
    fn get_database(&self) -> Result<Database, String>;
    fn get_collection(&self, nom_collection: &str) -> Result<Collection<Document>, String> {
        let database = self.get_database()?;
        Ok(database.collection(nom_collection))
    }

    async fn create_index(&self, nom_collection: &str, champs_index: Vec<ChampIndex>, options: Option<IndexOptions>) -> Result<(), String> {
        let database = self.get_database()?;
        create_index(&database, nom_collection, champs_index, options).await
    }
}

pub struct MongoDaoImpl {
    client: Client,
    db_name: String,
}

impl MongoDao for MongoDaoImpl {
    fn get_database(&self) -> Result<Database, String> {
        Ok(self.client.database(&self.db_name))
    }
}

pub fn initialiser(configuration: &(impl ConfigMessages + ConfigDb)) -> Result<MongoDaoImpl, String> {
    debug!("Initialiser connexion a MongoDB");

    let pki = configuration.get_configuration_pki();
    let mongo = configuration.get_configuraiton_mongo();

    // let (pki, mongo): (&ConfigurationPki, &ConfigurationMongo) = match configuration.as_ref() {
    //     ConfigurationMessages{mq: _mq, pki: _pki} => return Err("Mauvais type de configuration (MQ seulement)".into()),
    //     ConfigurationMessagesDb{mq: _mq, mongo, pki} => (pki, mongo),
    // };

    let client: Client = connecter(pki, mongo).expect("Erreur connexion a MongoDB");
    let idmg: String = pki.get_validateur().idmg().to_owned();

    Ok(MongoDaoImpl{
        client,
        db_name: idmg.to_owned(),
    })
}

fn connecter(pki: &ConfigurationPki, mongo_configuration: &ConfigurationMongo) -> ResultMongo<Client> {

    // Note : Convertir cle PKCS8 en format RSA

    let tls_options = TlsOptions::builder()
        .ca_file_path(Some(PathBuf::from(pki.ca_certfile.to_str().expect("Erreur conversion path CA"))))
        .cert_key_file_path(Some(PathBuf::from(mongo_configuration.keycert_file.to_str().expect("Erreur conversion key/cert path"))))
        .allow_invalid_certificates(false)
        .build();

    let credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbX509)
        .build();

    let options = ClientOptions::builder()
        .hosts(vec![
            ServerAddress::Tcp {
                host: mongo_configuration.host.to_owned(),
                port: Some(mongo_configuration.port),
            }
        ])
        .direct_connection(true)
        .tls(tls_options)
        .credential(credential)
        .server_selection_timeout(Duration::from_secs(5))
        .build();

    Client::with_options(options)
}

async fn create_index(database: &Database, nom_collection: &str, champs_index: Vec<ChampIndex>, options: Option<IndexOptions>) -> Result<(), String> {

    let mut champs = doc! {};
    for champ in champs_index {
        champs.insert(champ.nom_champ, Bson::Int32(champ.direction));
    }

    let mut index = doc! {
        "key": champs,
    };

    if let Some(options_inner) = options {
        if let Some(nom_index) = options_inner.nom_index {
            let _ = index.insert(String::from("name"), Bson::String(nom_index));
        }
        let _ = index.insert(String::from("unique"), Bson::Boolean(options_inner.unique));
    }

    let commande_pki = doc! {
        "createIndexes": nom_collection,
        "indexes": [index],
    };

    match database.run_command(commande_pki, None).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Erreur creation index : {:?}", e))
    }
}

pub struct IndexOptions {
    pub nom_index: Option<String>,
    pub unique: bool,
}

pub struct ChampIndex {
    pub nom_champ: String,
    pub direction: i32,
}

pub fn filtrer_doc_id(mut doc: &mut Document) {
    doc.remove(TRANSACTION_CHAMP_ENTETE);

    let ks: Vec<String> = doc.keys().cloned().collect();
    for k in ks {
        if k.starts_with("_") {
            doc.remove(k);
        }
    }
}

pub fn convertir_bson_value(doc: Document) -> Result<Value, serde_json::Error> {
    Ok(serde_json::from_value(serde_json::to_value(doc)?)?)
}

pub fn convertir_bson_deserializable<D>(doc: Document) -> Result<D, serde_json::Error>
    where D: DeserializeOwned
{
    Ok(serde_json::from_value(serde_json::to_value(doc)?)?)
}

pub fn convertir_to_bson<S>(valeur: S)
    -> Result<Document, Box<dyn Error>>
    where S: Serialize
{
    let bson_doc: Document = serde_json::from_value(serde_json::to_value(valeur)?)?;
    Ok(bson_doc)
}