use crate::certificats::build_store_path_v2;
use crate::chiffrage_cle::CleChiffrageHandlerImpl;
use crate::configuration::{ConfigurationMessages, charger_configuration};
use crate::redis_dao::RedisDao;
use crate::v3::impls::config_service::ConfigServiceImpl;
use crate::v3::impls::format_service::FormatServiceImpl;
use crate::v3::impls::messaging_service::MessagingServiceImpl;
use crate::v3::impls::security_service::SecurityServiceImpl;
use crate::v3::traits::*;
use tracing::info;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use crate::v3::facades::message_inbound::MessageInboundValidator;
use crate::v3::facades::message_outbound::MessageOutboundFacade;

/// Sample context from V3 services, customize as needed.
pub struct MiddlewareContext {
    pub messaging: Arc<dyn MessagingService>,
    pub security: Arc<dyn PkiService>,
    pub encryption: Arc<dyn ChiffrageService>,
    pub config: Arc<dyn ConfigService>,
    pub format: Arc<dyn FormatService>,
    pub redis: Option<Arc<RedisDao>>,
    pub outbound: Arc<MessageOutboundFacade>,
    pub inbound: Arc<MessageInboundValidator>,
}

impl MiddlewareContext {
    fn from_services(
        messaging: Arc<dyn MessagingService>,
        security: Arc<dyn PkiService>,
        encryption: Arc<dyn ChiffrageService>,
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        redis: Option<Arc<RedisDao>>,
        outbound: Arc<MessageOutboundFacade>,
        inbound: Arc<MessageInboundValidator>,
    ) -> Self {
        Self {
            messaging,
            security,
            encryption,
            config,
            format,
            redis,
            outbound,
            inbound,
        }
    }
}

pub struct PocCompositionRoot {
    pub context: MiddlewareContext,
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

        // Config
        let config_impl = Arc::new(ConfigServiceImpl::new(config));

        // Security
        let validator = Arc::new(build_store_path_v2(&config_impl.get_configuration_pki().ca_certfile)?);
        let security_impl = Arc::new(SecurityServiceImpl::new(
            validator,
            CleChiffrageHandlerImpl::new(),
        ));

        // Messaging (RabbitMQ)
        let messaging_impl = Arc::new(MessagingServiceImpl::new(config_impl.clone()));

        // Redis (optional)
        let redis_dao = if config_impl.get_configuration_instance().redis_password.is_some() {
            info!("Redis initialized");
            Some(Arc::new(RedisDao::new(config_impl.get_configuration_instance().clone()).expect("connexion redis")))
        } else {
            info!("Redis not configured");
            None
        };

        // Format
        let format_impl = Arc::new(FormatServiceImpl::new(config_impl.clone()));

        // Helper facades
        let shutdown_token = CancellationToken::new();
        let message_outbound_facade = Arc::new(
            MessageOutboundFacade::new(messaging_impl.clone(), format_impl.clone())
        );
        let message_inbound_validator = Arc::new(
            MessageInboundValidator::new(config_impl.clone(), messaging_impl.clone(), security_impl.clone(), shutdown_token)
        );

        // Context
        let context = MiddlewareContext::from_services(
            messaging_impl.clone(),
            security_impl.clone(),
            security_impl.clone(),
            config_impl,
            format_impl.clone(),
            redis_dao,
            message_outbound_facade,
            message_inbound_validator,
        );

        Ok(Self {context})
    }
}
