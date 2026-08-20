use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::v3::{ConfigService, FormatService};
use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use serde_json::Value;
use std::sync::Arc;
use crate::formatteur_messages::{build_message_action, build_message_action_chiffre, build_reponse, build_reponse_chiffree};

pub struct FormatServiceImpl {
    config: Arc<dyn ConfigService>,
}

impl FormatServiceImpl {
    pub fn new(config: Arc<dyn ConfigService>) -> Self {
        Self { config }
    }
}


impl FormatService for FormatServiceImpl {
    fn build_response(&self, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        let enveloppe_privee = self.config.get_configuration_pki().get_enveloppe_privee();
        build_reponse(message, enveloppe_privee.as_ref())
    }

    fn build_encrypted_response(&self, message: Value, certificat_demandeur: &EnveloppeCertificat)
        -> Result<(MessageMilleGrillesBufferDefault, String), Error>
    {
        let enveloppe_privee = self.config.get_configuration_pki().get_enveloppe_privee();
        build_reponse_chiffree(message, enveloppe_privee.as_ref(), certificat_demandeur)
    }

    fn build_action_message(&self, type_message: MessageKind, routage: &RoutageMessageAction, message: Value)
        -> Result<(MessageMilleGrillesBufferDefault, String), Error>
    {
        let enveloppe_privee = self.config.get_configuration_pki().get_enveloppe_privee();
        build_message_action(type_message, routage.clone(), message, enveloppe_privee.as_ref())
    }

    fn build_encrypted_action_message(&self, type_message: MessageKind, routage: &RoutageMessageAction,
                                      message: Value, keys: Vec<&EnveloppeCertificat>)
        -> Result<(MessageMilleGrillesBufferDefault, String), Error>
    {
        let enveloppe_privee = self.config.get_configuration_pki().get_enveloppe_privee();
        build_message_action_chiffre(type_message, routage.clone(), message, enveloppe_privee.as_ref(), keys)
    }
}
