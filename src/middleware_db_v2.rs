use std::sync::Arc;
use futures_util::stream::FuturesUnordered;
use log::info;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use static_cell::StaticCell;

use crate::backup::{CommandeBackup, thread_backup, thread_backup_v2};
use crate::chiffrage_cle::CleChiffrageHandlerImpl;
use crate::configuration::IsConfigNoeud;
use crate::error::Error;
use crate::middleware_db::{configurer, MiddlewareDb, MiddlewareHooks};
use crate::rabbitmq_dao::{RabbitMqExecutor, run_rabbitmq, run_rabbitmq_v2};
use crate::redis_dao::RedisDao;

static MIDDLEWARE: StaticCell<MiddlewareDb> = StaticCell::new();
// static RABBIT_MQ: StaticCell<RabbitMqExecutor> = StaticCell::new();

pub fn preparer() -> Result<&'static MiddlewareDb, Error> {
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

    let middleware = MiddlewareDb {
        ressources,
        redis: redis_dao,
        tx_backup,
        cle_chiffrage_handler: CleChiffrageHandlerImpl::new(),
    };

    let middleware = MIDDLEWARE.try_init(middleware).expect("StaticCell MIDDLEWARE init");

    // Preparer threads execution

    tokio::spawn(thread_backup_v2(middleware, rx_backup));

    let rabbitmq = middleware.ressources.ressources.rabbitmq.clone();
    tokio::spawn(run_rabbitmq_v2(middleware, rabbitmq, configuration));

    Ok(middleware)
}
