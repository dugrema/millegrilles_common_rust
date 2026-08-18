use crate::certificats::build_store_path_v2;
use crate::chiffrage_cle::CleChiffrageHandlerImpl;
use crate::configuration::{ConfigMessages, ConfigurationMessages, IsConfigNoeud, charger_configuration};
use crate::rabbitmq_dao::RabbitMqExecutor;
use crate::redis_dao::RedisDao;
use crate::v3::impls::config_service::ConfigServiceImpl;
use crate::v3::impls::messaging_service::MessagingServiceImpl;
use crate::v3::impls::security_service::SecurityServiceImpl;
use crate::v3::traits::*;
use log::info;
use millegrilles_cryptographie::x509::EnveloppePrivee;
use std::sync::Arc;
use crate::v3::impls::format_service::FormatServiceImpl;

pub struct PocCompositionRoot {
    pub context: crate::v3::context::MiddlewareContext,
}

impl PocCompositionRoot {
    pub async fn build(config: Option<ConfigurationMessages>) -> Result<Self, Box<dyn std::error::Error>> {

        let config = match config {
            Some(c) => Arc::new(c),
            None => {
                // Build config from env parameters
                Arc::new(charger_configuration()?)
            }
        };

        // 1. Config
        let config_impl = Arc::new(ConfigServiceImpl::new(config, None));

        // 2. Messaging (RabbitMQ)
        let enveloppe_privee = config_impl.get_configuration_pki().get_enveloppe_privee();
        let securite = enveloppe_privee.enveloppe_pub.extensions()?.exchange_top()?.expect("Exchange security level");
        let messaging_impl = Arc::new(MessagingServiceImpl::new(config_impl.clone(), securite));

        // 3. Redis (optional)
        let redis_dao = if config_impl.get_configuration_instance().redis_password.is_some() {
            info!("Redis initialized");
            Some(Arc::new(RedisDao::new(config_impl.get_configuration_instance().clone()).expect("connexion redis")))
        } else {
            info!("Redis not configured");
            None
        };

        // 3. Security
        let validator = Arc::new(build_store_path_v2(&config_impl.get_configuration_pki().ca_certfile)?);
        let security_impl = Arc::new(SecurityServiceImpl::new(
            validator,
            CleChiffrageHandlerImpl::new(),
        ));

        // 5. Format
        let format_impl = Arc::new(FormatServiceImpl {});

        // 6. Context
        let context = crate::v3::context::MiddlewareContext::from_services(
            messaging_impl,
            security_impl.clone(),
            security_impl.clone(),
            config_impl,
            format_impl,
            redis_dao,
        );

        Ok(Self {context})
    }
}
