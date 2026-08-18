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

// Dummy for FormatService since it's required by MiddlewareContext
struct DummyFormatService;
impl FormatService for DummyFormatService {
    fn get_enveloppe_signature(&self) -> EnveloppePrivee {
        unimplemented!("FormatService not needed for PoC")
    }
}

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

        // 1. Messaging (RabbitMQ)
        let enveloppe_privee = config.get_configuration_pki().get_enveloppe_privee();
        let securite = enveloppe_privee.enveloppe_pub.extensions()?.exchange_top()?.expect("Exchange security level");
        let securite_str: &str = securite.into();
        let rabbitmq = Arc::new(RabbitMqExecutor::new(Some(securite_str.try_into()?)));
        let messaging_impl = Arc::new(MessagingServiceImpl::new(rabbitmq, enveloppe_privee, securite));

        // 2. Redis (optional)
        let redis_dao = if config.get_configuration_noeud().redis_password.is_some() {
            info!("Redis initialized");
            Some(Arc::new(RedisDao::new(config.get_configuration_noeud().clone()).expect("connexion redis")))
        } else {
            info!("Redis not configured");
            None
        };

        // 3. Security
        let validator = Arc::new(build_store_path_v2(&config.get_configuration_pki().ca_certfile)?);
        let security_impl = Arc::new(SecurityServiceImpl::new(
            validator,
            CleChiffrageHandlerImpl::new(),
            config.clone(),
        ));

        // 4. Config
        let config_impl = Arc::new(ConfigServiceImpl::new(config, None));

        // 5. Format
        let format_impl = Arc::new(DummyFormatService {});

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
