extern crate core;
extern crate fs2;

pub mod certificats;
pub mod configuration;
pub mod constantes;
pub mod common_messages;
pub mod formatteur_messages;
pub mod generateur_messages;
pub mod hachages;
pub mod middleware;
pub mod v3;
pub mod mongo_dao;
pub mod rabbitmq_dao;
pub mod recepteur_messages;
pub mod signatures;
pub mod verificateur;
pub mod transactions;
pub mod backup;
pub mod dechiffrage;
pub mod fichiers;
pub mod messages_generiques;
pub mod domaines;
pub mod middleware_db;
pub mod redis_dao;
pub mod chiffrage_rsa;
pub mod chiffrage_cle;
pub mod chiffrage_streamxchacha20poly1305;
pub mod math;
pub mod notifications;
pub mod jwt_handler;
pub mod db_structs;
pub mod error;

#[macro_use]
mod macros;
pub mod domaines_v2;
pub mod domaines_traits;
pub mod middleware_db_v2;
pub mod backup_v2;
pub mod transactions_v2;
pub mod fiche_systeme;
pub mod mongo_serde;

// pub use millegrilles_cryptographie;
// pub use async_trait;
// pub use base64;
// pub use base64_url;
// pub use bytes;
// pub use chrono;
// pub use futures;
// pub use futures_util;
// pub use hex;
pub use mongodb::bson as bson;
pub use mongodb;
// pub use multibase;
// pub use multihash;
// pub use openssl;
// pub use rand;
// pub use redis;
// pub use reqwest;
// pub use static_cell;
pub use tokio;
// pub use tokio_stream;
// pub use tokio_util;
// pub use uuid;
// pub use serde;
// pub use serde_json;
// pub use serde_helpers;
// pub use chacha20poly1305;
// pub use url;
// pub use flate2;
// pub use jwt_simple;
// pub use tracing;
// pub use tracing_subscriber;
// pub use rustls;

use std::path::PathBuf;
use tracing_subscriber::util::SubscriberInitExt;
use crate::v3::impls::backup_tools::*;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    init_logging();
    eprintln!("Running main");

    // Tool for sorting encrypted backup archives content
    // run_sort_backup_archive().await
    run_verify_backup_file().await
}

const IDMG: &str = "zaSDqKqrvhrGJS6oC2Zo4TtFXAc5FsbsZkcf9ADPx3u1jFepxikpxxjW";

async fn run_sort_backup_archive() {
    let backup_path = PathBuf::from(
        "/home/mathieu/tas/dev/millegrilles/dev1/var/backup/domains/MaitreDesCles/MaitreDesCles_20220914184226381Z_C_kaQsFm1TFmde.mgbak"
    );
    let master_key_path = PathBuf::from(&format!("/home/mathieu/Documents/cles/{}.pem", IDMG));
    let output_dir = PathBuf::from("/home/mathieu/tas/dev/millegrilles/dev1/work");
    let signing_key_path = PathBuf::from("/home/mathieu/tas/dev/millegrilles/dev1/secrets/maitredescles.pem");
    let ca_path = PathBuf::from("/home/mathieu/tas/dev/millegrilles/dev1/etc/millegrille.pem");
    tokio::fs::create_dir_all(&output_dir).await.unwrap();
    sort_backup_file(
        backup_path.as_path(),
        IDMG,
        &signing_key_path,
        &ca_path,
        master_key_path.as_path(),
        output_dir.as_path()
    ).await.unwrap();
}

async fn run_verify_backup_file() {
    let backup_path = PathBuf::from(
        "/home/mathieu/tas/dev/millegrilles/dev1/work/MaitreDesCles_20220914184226381Z_C_kaQsFm1TFmde.mgbak"
    );
    let master_key_path = PathBuf::from(&format!("/home/mathieu/Documents/cles/{}.pem", IDMG));
    tool_verify_backup_file(backup_path.as_path(), IDMG, master_key_path.as_path()).await.unwrap()
}

fn init_logging() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_common_rust=info".to_string());
    // env_logger::init();
    use tracing_subscriber::layer::SubscriberExt;
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();
}
