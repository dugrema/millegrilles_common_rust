extern crate core;

pub mod certificats;
pub mod configuration;
pub mod constantes;
pub mod common_messages;
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
pub mod dechiffrage;
pub mod fichiers;
pub mod messages_generiques;
pub mod domaines;
pub mod middleware_db;
pub mod redis_dao;
pub mod chiffrage_ed25519;
pub mod chiffrage_rsa;
pub mod chiffrage_cle;
pub mod backup_restoration;
pub mod chiffrage_streamxchacha20poly1305;
pub mod math;
pub mod notifications;
pub mod jwt_handler;
mod db_structs;

// Re-exports
pub use millegrilles_cryptographie;
pub use async_trait;
pub use base64_url;
pub use bytes;
pub use chrono;
pub use futures;
pub use futures_util;
pub use hex;
pub use mongodb::bson as bson;
pub use mongodb;
pub use multibase;
pub use multihash;
pub use openssl;
pub use rand;
pub use redis;
pub use reqwest;
pub use tokio;
pub use tokio_stream;
pub use tokio_util;
pub use uuid;
pub use serde;
pub use serde_json;
pub use chacha20poly1305;

#[cfg(test)]
mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
