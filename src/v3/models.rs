use millegrilles_cryptographie::messages_structs::MessageMilleGrillesOwned;
use millegrilles_cryptographie::x509::EnveloppeCertificat;
use std::sync::Arc;

pub struct VerifiedResponseMessage {
    pub message: MessageMilleGrillesOwned,
    pub certificate: Arc<EnveloppeCertificat>,
}
