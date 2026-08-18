use crate::v3::traits::*;
use crate::middleware::MiddlewareMessage;
use crate::redis_dao::RedisDao;
use std::sync::Arc;

pub struct MiddlewareContext {
    pub messaging: Arc<dyn MessagingService>,
    pub security: Arc<dyn SecurityService>,
    pub certificat: Arc<dyn CertificatService>,
    pub chiffrage: Arc<dyn ChiffrageService>,
    pub config: Arc<dyn ConfigService>,
    pub format: Arc<dyn FormatService>,
    pub backup: Option<Arc<dyn BackupService>>,
    pub database: Option<Arc<dyn DatabaseService>>,
    pub redis: Option<Arc<RedisDao>>,
}

impl MiddlewareContext {
    pub fn from_services(
        messaging: Arc<dyn MessagingService>,
        security: Arc<dyn SecurityService>,
        certificat: Arc<dyn CertificatService>,
        chiffrage: Arc<dyn ChiffrageService>,
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        redis: Option<Arc<RedisDao>>,
    ) -> Self {
        Self {
            messaging,
            security,
            certificat,
            chiffrage,
            config,
            format,
            backup: None,
            database: None,
            redis,
        }
    }
}
