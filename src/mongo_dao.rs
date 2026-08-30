use crate::bson::Array;
use crate::certificats::ValidateurX509;
use crate::configuration::{ConfigMessages, ConfigurationMongo, ConfigurationPki};
use crate::error::Error as CommonError;
use crate::rabbitmq_dao::emettre_certificat_compte;
use async_trait::async_trait;
use mongodb::bson::Bson;
use mongodb::bson::document::Document;
use mongodb::error::{ErrorKind, Result as ResultMongo, WriteFailure};
use mongodb::options::{AuthMechanism, ClientOptions, Credential, ServerAddress, TlsOptions, WriteModel};
use mongodb::{Client, ClientSession, Collection, Cursor, Database, bson::doc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use std::vec::IntoIter;
use tokio_stream::StreamExt;
use tracing::{debug, error, info};

#[async_trait]
pub trait MongoDao: Send + Sync {
    fn get_database(&self) -> Result<Database, CommonError>;
    fn get_admin_database(&self) -> Result<Database, CommonError>;
    fn get_db_name(&self) -> &str;
    fn get_path_backup(&self) -> &PathBuf;
    async fn get_session(&self) -> Result<ClientSession, CommonError>;
    async fn get_session_rebuild(&self) -> Result<ClientSession, CommonError>;

    fn get_collection(&self, nom_collection: &str) -> Result<Collection<Document>, CommonError> {
        let database = self.get_database()?;
        Ok(database.collection(nom_collection.as_ref()))
    }

    async fn create_index(
        &self,
        configuration: &dyn ConfigMessages,
        nom_collection: &str,
        champs_index: Vec<ChampIndex>,
        options: Option<IndexOptions>
    ) -> Result<(), CommonError>;

    async fn rename_collection(&self, source: &str, destination: &str, drop_target: bool) -> Result<(), CommonError> {
        let db_name = self.get_db_name();
        let command = doc!{
            "renameCollection": format!("{}.{}", db_name, source),
            "to": format!("{}.{}", db_name, destination),
            "dropTarget": drop_target,
        };
        let database = self.get_admin_database()?;
        match database.run_command(command).await {
            Ok(_) => Ok(()),
            Err(e) => Err(CommonError::String(format!("rename_collection Error {:?}", e))),
        }
    }

    async fn bulk_write(&self, models: Vec<WriteModel>, session: Option<&mut ClientSession>, ordered: bool) -> Result<(), CommonError>;

}

pub trait MongoDaoTyped: MongoDao {
    fn get_collection_typed<T>(&self, nom_collection: &str) -> Result<Collection<T>, CommonError> where T: Send + Sync {
        let database = self.get_database()?;
        Ok(database.collection::<T>(nom_collection))
    }
}

pub struct MongoDaoImpl {
    client: Client,
    db_name: String,
    path_backup: PathBuf,
}

#[async_trait]
impl MongoDao for MongoDaoImpl {
    fn get_database(&self) -> Result<Database, CommonError> {
        Ok(self.client.database(&self.db_name))
    }

    fn get_admin_database(&self) -> Result<Database, CommonError> {
        Ok(self.client.database("admin"))
    }

    fn get_db_name(&self) -> &str {self.db_name.as_str()}

    fn get_path_backup(&self) -> &PathBuf {
        &self.path_backup
    }

    async fn get_session(&self) -> Result<ClientSession, CommonError> {
        // let write_concern = WriteConcern::builder()
        //     .journal(true)
        //     .w(Acknowledgment::Majority)
        //     .build();
        // let transaction_options = TransactionOptions::builder()
        //     .read_concern(ReadConcern::majority())
        //     .write_concern(write_concern)
        //     .build();
        // let options = SessionOptions::builder()
        //     .default_transaction_options(transaction_options).build();
        // Ok(self.client.start_session(options).await?)
        Ok(self.client.start_session().await?)
    }

    async fn get_session_rebuild(&self) -> Result<ClientSession, CommonError> {
        // let write_concern = WriteConcern::builder()
        //     .journal(true)
        //     .w(Acknowledgment::Nodes(1))
        //     .build();
        // let transaction_options = TransactionOptions::builder()
        //     .read_concern(ReadConcern::LOCAL)
        //     .write_concern(write_concern)
        //     .build();
        // let options = SessionOptions::builder().default_transaction_options(transaction_options).build();
        // Ok(self.client.start_session(options).await?)
        Ok(self.client.start_session().await?)
    }

    async fn create_index(&self, configuration: &dyn ConfigMessages, nom_collection: &str, champs_index: Vec<ChampIndex>, options: Option<IndexOptions>) -> Result<(), CommonError> {
        let database = self.get_database()?;
        create_index(configuration, &database, nom_collection, champs_index, options).await
    }

    async fn bulk_write(&self, models: Vec<WriteModel>, session: Option<&mut ClientSession>, ordered: bool) -> Result<(), CommonError> {
        let mut writer = self.client
            .bulk_write(models)
            .ordered(ordered);

        // Session is optional, e.g. on rebuild
        if let Some(session) = session {
            writer = writer.session(session)
        }

        // Run the operations
        writer.await?;

        Ok(())
    }
}

impl MongoDaoTyped for MongoDaoImpl {}

pub fn initialiser(config_pki: &ConfigurationPki, config_db: &ConfigurationMongo) -> Result<MongoDaoImpl, String> {
    debug!("Initialiser connexion a MongoDB");

    // let (pki, mongo): (&ConfigurationPki, &ConfigurationMongo) = match configuration.as_ref() {
    //     ConfigurationMessages{mq: _mq, pki: _pki} => return Err("Mauvais type de configuration (MQ seulement)".into()),
    //     ConfigurationMessagesDb{mq: _mq, mongo, pki} => (pki, mongo),
    // };

    let client: Client = connecter(config_pki, config_db).expect("Erreur connexion a MongoDB");
    let idmg: String = config_pki.get_validateur().idmg().to_owned();

    Ok(MongoDaoImpl{
        client,
        db_name: idmg.to_owned(),
        path_backup: config_db.path_backup.to_owned(),
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

async fn create_index(
    configuration: &dyn ConfigMessages,
    database: &Database,
    nom_collection: &str,
    champs_index: Vec<ChampIndex>,
    options: Option<IndexOptions>
) -> Result<(), CommonError> {
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

    match database.run_command(commande_pki).await {
        Ok(_) => Ok(()),
        Err(e) => {
            info!("Erreur connexion Mongo DB, tenter l'inscription du compte");
            if let Err(e) = emettre_certificat_compte(configuration).await {
                error!("create_index Erreur inscription a midcompte : {:?}", e);
            }

            Err(CommonError::String(format!("Erreur connexion MongoDB (initial, creation index) : {:?}", e)))
        }
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

pub fn filtrer_doc_id(doc: &mut Document) {
    // doc.remove(TRANSACTION_CHAMP_ENTETE);

    let ks: Vec<String> = doc.keys().cloned().collect();
    for k in ks {
        if k.as_str() == "_id" {
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
    -> Result<Document, crate::error::Error>
    where S: Serialize
{
    let bson_doc: Document = serde_json::from_value(serde_json::to_value(valeur)?)?;
    Ok(bson_doc)
}

pub fn convertir_to_bson_array<S>(valeur: S)
    -> Result<Array, crate::error::Error>
    where S: Serialize
{
    let bson_array: Array = serde_json::from_value(serde_json::to_value(valeur)?)?;
    Ok(bson_array)
}


/// Return true si l'erreur est une duplication sur insert
pub fn verifier_erreur_duplication_mongo(kind: &ErrorKind) -> bool {
    match kind {
        ErrorKind::Write(f) => {
            match f {
                WriteFailure::WriteError(we) => we.code == 11000,  // true si code de duplication
                _ => false
            }
        },
        ErrorKind::BulkWrite(_f) => true,
        _ => false
    }
}

#[async_trait]
pub trait CurseurStream {
    async fn try_next(&mut self) -> Result<Option<Document>, String>;
    async fn next(&mut self) -> Option<Result<Document, String>>;
}

pub struct CurseurIntoIter { pub data: IntoIter<Document> }

#[async_trait]
impl CurseurStream for CurseurIntoIter {
    async fn try_next(&mut self) -> Result<Option<Document>, String> {
        Ok(self.data.next())
    }
    async fn next(&mut self) -> Option<Result<Document, String>> {
        match self.data.next() {
            Some(v) => Some(Ok(v)),
            None => None
        }
    }
}

pub struct CurseurMongo { pub curseur: Cursor<Document> }

#[async_trait]
impl CurseurStream for CurseurMongo {
    async fn try_next(&mut self) -> Result<Option<Document>, String> {
        match self.curseur.try_next().await {
            Ok(r) => Ok(r),
            Err(e) => Err(format!("CurseurStream.try_next erreur {:?}", e))
        }
    }
    async fn next(&mut self) -> Option<Result<Document, String>> {
        match self.curseur.next().await {
            Some(d) => match d {
                Ok(r) => Some(Ok(r)),
                Err(e) => Some(Err(format!("CurseurStream.next erreur {:?}", e)))
            },
            None => None
        }
    }
}

// Source : https://github.com/mongodb/bson-rust/issues/303
// pub mod opt_chrono_datetime_as_bson_datetime {
//     use chrono::Utc;
//     use mongodb::bson;
//     use serde::{Deserialize, Deserializer, Serialize, Serializer};
//     use serde_with::serde_as;
//     use bson::serde_helpers::datetime::FromChrono04DateTime;
//
//     #[serde_as]
//     #[derive(Serialize, Deserialize)]
//     struct Helper(
//         // #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
//         #[serde_as(as = "FromChrono04DateTime")]
//         chrono::DateTime<Utc>,
//     );
//
//     pub fn serialize<S>(
//         value: &Option<chrono::DateTime<Utc>>,
//         serializer: S,
//     ) -> Result<S::Ok, S::Error>
//         where
//             S: Serializer,
//     {
//         value.map(Helper).serialize(serializer)
//     }
//
//     pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<chrono::DateTime<Utc>>, D::Error>
//         where
//             D: Deserializer<'de>,
//     {
//         let helper: Option<Helper> = Option::deserialize(deserializer)?;
//         Ok(helper.map(|Helper(external)| external))
//     }
// }

// pub mod map_chrono_datetime_as_bson_datetime {
//     use chrono::Utc;
//     use mongodb::bson;
//     use serde::ser::SerializeMap;
//     use serde::{Deserialize, Deserializer, Serialize, Serializer};
//     use std::collections::HashMap;
//     use serde_with::serde_as;
//     use bson::serde_helpers::datetime::FromChrono04DateTime;
//
//     #[serde_as]
//     #[derive(Serialize, Deserialize)]
//     struct Helper(
//         // #[serde(with = "bson::serde_helpers::chrono_datetime_as_bson_datetime")]
//         #[serde_as(as = "FromChrono04DateTime")]
//         chrono::DateTime<Utc>,
//     );
//
//     // MOVE THIS HERE (Module level)
//     impl From<Helper> for chrono::DateTime<Utc> {
//         fn from(helper: Helper) -> Self {
//             helper.0
//         }
//     }
//
//     pub fn serialize<S>(
//         value: &HashMap<String, chrono::DateTime<Utc>>,
//         serializer: S,
//     ) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut map = serializer.serialize_map(Some(value.len()))?;
//         for (k, v) in value.iter() {
//             let helper = Helper(v.to_owned());
//             map.serialize_entry(k, &helper)?;
//         }
//         map.end()
//     }
//
//     pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, chrono::DateTime<Utc>>, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         #[derive(Deserialize)]
//         struct MapHelper(
//             HashMap<String, Helper>,
//         );
//
//         let map_helper: MapHelper = MapHelper::deserialize(deserializer)?;
//         let mut final_map: HashMap<String, chrono::DateTime<Utc>> = HashMap::new();
//         for (k, v) in map_helper.0.into_iter() {
//             final_map.insert(k, v.into());
//         }
//         Ok(final_map)
//     }
// }

// pub mod map_opt_chrono_datetime_as_bson_datetime {
//     use chrono::Utc;
//     use serde::ser::SerializeMap;
//     use serde::{Deserialize, Deserializer, Serialize, Serializer};
//     use std::collections::HashMap;
//
//     #[derive(Serialize, Deserialize)]
//     struct Helper(
//         #[serde(with = "crate::mongo_dao::opt_chrono_datetime_as_bson_datetime")]
//         Option<chrono::DateTime<Utc>>,
//     );
//
//     pub fn serialize<S>(
//         value: &Option<HashMap<String, Option<chrono::DateTime<Utc>>>>,
//         serializer: S,
//     ) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         match value {
//             Some(inner ) => {
//                 let mut map = serializer.serialize_map(Some(inner.len()))?;
//                 for (k, v) in inner.iter() {
//                     let helper = Helper(v.to_owned());
//                     map.serialize_entry(k, &helper)?;
//                 }
//                 map.end()
//             },
//             None => None::<usize>.serialize(serializer)
//         }
//     }
//
//     pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<HashMap<String, Option<chrono::DateTime<Utc>>>>, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//
//         #[derive(Deserialize)]
//         struct OptionalDateHelper(
//             #[serde(with = "crate::mongo_dao::opt_chrono_datetime_as_bson_datetime")]
//             Option<chrono::DateTime<Utc>>,
//         );
//
//         impl Into<Option<chrono::DateTime<Utc>>> for OptionalDateHelper {
//             fn into(self) -> Option<chrono::DateTime<Utc>> {
//                 match self.0 {
//                     Some(inner) => Some(inner),
//                     None => None
//                 }
//             }
//         }
//
//         #[derive(Deserialize)]
//         struct MapHelper(
//             HashMap<String, OptionalDateHelper>,
//         );
//
//         let map_helper: Option<MapHelper> = Option::deserialize(deserializer)?;
//         match map_helper {
//             Some(inner) => {
//                 let mut final_map: HashMap<String, Option<chrono::DateTime<Utc>>> = HashMap::new();
//                 for (k, v) in inner.0.into_iter() {
//                     final_map.insert(k, v.into());
//                 }
//                 Ok(Some(final_map))
//             },
//             None => Ok(None),
//         }
//
//     }
// }


pub async fn start_transaction_regular(session: &mut ClientSession) -> Result<(), CommonError> {
    // let options = TransactionOptions::builder()
    //     .read_concern(ReadConcern::majority())
    //     .write_concern(WriteConcern::builder()
    //         .journal(true)
    //         .w(Acknowledgment::Majority).build())
    //     .build();
    // session.start_transaction(options).await?;
    // TODO - Put parameters back
    session.commit_transaction().await?;
    Ok(())
}

pub async fn start_transaction_regeneration(session: &mut ClientSession) -> Result<(), CommonError> {
    // // Write concern requiring just 1 ACK, journalled
    // let write_concern = WriteConcern::builder()
    //     .journal(true)
    //     // .w(Acknowledgment::Majority)
    //     .w(Acknowledgment::Nodes(1))
    //     .build();
    //
    // let options = TransactionOptions::builder()
    //     .read_concern(ReadConcern::local())
    //     .write_concern(write_concern)
    //     .build();

    // session.start_transaction(options).await?;
    // TODO - Put parameters back
    session.start_transaction().await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::error::Error;

    #[derive(Serialize, Deserialize, Debug)]
    struct TestMap {
        // #[serde(with = "crate::mongo_dao::map_opt_chrono_datetime_as_bson_datetime")]
        ma_map: Option<HashMap<String, Option<DateTime<Utc>>>>
    }

    #[test]
    fn test_encode_map_dates() -> Result<(), Box<dyn Error>> {
        println!("Tada");

        let test_map_vide = TestMap { ma_map: None };
        let map_vide_str = serde_json::to_string(&test_map_vide)?;
        println!("Map vide: {:?}", map_vide_str);

        let mut contenu_map = HashMap::new();
        contenu_map.insert("Date1".to_string(), Some(Utc::now()));
        contenu_map.insert("PasDate".to_string(), None);
        let test_map = TestMap { ma_map: Some(contenu_map) };
        let map_data_str = serde_json::to_string(&test_map)?;
        println!("Map data: {:?}", map_data_str);


        // Deserialize
        let map_vide_rebuilt: TestMap = serde_json::from_str(map_vide_str.as_str())?;
        println!("Map vide deserialized: {:?}", map_vide_rebuilt);
        let map_data_rebuilt: TestMap = serde_json::from_str(map_data_str.as_str())?;
        println!("Map data deserialized: {:?}", map_data_rebuilt);

        Ok(())
    }

}
