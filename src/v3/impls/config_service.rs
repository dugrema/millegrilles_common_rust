use crate::configuration::{ConfigDb, ConfigMessages, ConfigurationMessages, ConfigurationMongo, IsConfigNoeud};
use crate::v3::traits::ConfigService;
use std::sync::Arc;

pub struct ConfigServiceImpl {
    config: Arc<ConfigurationMessages>,
    // mongo: Option<Arc<ConfigurationMongo>>,
}

impl ConfigServiceImpl {
    pub fn new(
        config: Arc<ConfigurationMessages>,
        // mongo: Option<Arc<ConfigurationMongo>>
    ) -> Self
    {
        Self {
            config,
            // mongo
        }
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

pub struct ConfigServiceDbImpl {
    config: Arc<ConfigurationMessages>,
    mongo: Arc<ConfigurationMongo>,
}

impl ConfigServiceDbImpl {
    pub fn new(
        config: Arc<ConfigurationMessages>,
        mongo: Arc<ConfigurationMongo>
    ) -> Self
    {
        Self {
            config,
            mongo
        }
    }
}

impl ConfigService for ConfigServiceDbImpl {
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

impl ConfigDb for ConfigServiceDbImpl {
    fn get_configuraiton_mongo(&self) -> &ConfigurationMongo {
        self.mongo.as_ref()
    }
}
