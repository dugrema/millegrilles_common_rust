pub mod certificats;
pub mod configuration;
pub mod constantes;
pub mod formatteur_messages;
pub mod generateur_messages;
pub mod hachages;
pub mod middleware;
pub mod mongo_dao;
pub mod rabbitmq_dao;
pub mod recepteur_messages;
pub mod signatures;
pub mod verificateur;
pub mod transactions;
pub mod backup;
pub mod chiffrage;
pub mod fichiers;
pub mod messages_generiques;

//pub use certificats;
pub use configuration::*;
pub use constantes::*;
pub use formatteur_messages::*;
pub use generateur_messages::*;
// pub use hachages::*;
pub use middleware::*;
pub use mongo_dao::*;
pub use rabbitmq_dao::*;
pub use recepteur_messages::*;
pub use signatures::*;
pub use verificateur::*;
pub use transactions::*;
pub use backup::*;
pub use chiffrage::*;
pub use fichiers::*;
pub use messages_generiques::*;

// Re-exports
pub use async_trait;
pub use chrono;
pub use futures;
pub use futures_util;
pub use mongodb::bson as bson;
pub use mongodb;
pub use openssl;
pub use tokio;
pub use tokio_stream;
pub use uuid;
pub use serde;
pub use serde_json;

#[cfg(test)]
mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
