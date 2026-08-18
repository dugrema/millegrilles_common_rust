use std::sync::Arc;
use crate::v3::traits::ConfigService;
use crate::configuration::{ConfigurationMessagesDb, ConfigMessages, IsConfigNoeud, ConfigurationMongo, ConfigurationMessages};

pub struct ConfigServiceImpl {
    config: Arc<ConfigurationMessages>,
    mongo: Option<Arc<ConfigurationMongo>>,
}

impl ConfigServiceImpl {
    pub fn new(config: Arc<ConfigurationMessages>, mongo: Option<Arc<ConfigurationMongo>>) -> Self {
        Self { config, mongo }
    }
}

impl ConfigService for ConfigServiceImpl {
    fn get_configuration_mq(&self) -> &crate::configuration::ConfigurationMq {
        self.config.get_configuration_mq()
    }
    fn get_configuration_pki(&self) -> &crate::configuration::ConfigurationPki {
        self.config.get_configuration_pki()
    }
    fn get_configuration_instance(&self) -> &crate::configuration::ConfigurationNoeud {
        self.config.get_configuration_noeud()
    }
}
