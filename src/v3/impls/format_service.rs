use millegrilles_cryptographie::messages_structs::{MessageKind, MessageMilleGrillesBufferDefault};
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use serde_json::Value;
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::v3::FormatService;

pub struct FormatServiceImpl {

}

impl FormatService for FormatServiceImpl {
    fn build_response(&self, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_encrypted_response(&self, message: Value, certificat_demandeur: &EnveloppeCertificat) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }

    fn build_encrypted_action_message(&self, type_message: MessageKind, routage: RoutageMessageAction, message: Value) -> Result<(MessageMilleGrillesBufferDefault, String), Error> {
        todo!()
    }
}
