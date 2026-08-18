use crate::redis_dao::RedisDao;
use crate::v3::traits::*;
use std::sync::Arc;

pub struct MiddlewareContext {
    pub messaging: Arc<dyn MessagingService>,
    pub security: Arc<dyn PkiService>,
    pub encryption: Arc<dyn ChiffrageService>,
    pub config: Arc<dyn ConfigService>,
    pub format: Arc<dyn FormatService>,
    pub backup: Option<Arc<dyn BackupService>>,
    pub database: Option<Arc<dyn DatabaseService>>,
    pub redis: Option<Arc<RedisDao>>,
}

impl MiddlewareContext {
    pub fn from_services(
        messaging: Arc<dyn MessagingService>,
        security: Arc<dyn PkiService>,
        encryption: Arc<dyn ChiffrageService>,
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        redis: Option<Arc<RedisDao>>,
    ) -> Self {
        Self {
            messaging,
            security,
            encryption,
            config,
            format,
            backup: None,
            database: None,
            redis,
        }
    }
}
