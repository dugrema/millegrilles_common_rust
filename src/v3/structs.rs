use lapin::message::Delivery;
use crate::recepteur_messages::MessageValide;

pub enum IncomingMessage {
    Verified(MessageValide)
}

pub enum OutgoingMessage {

}

pub struct NamedQueueDelivery {
    /// Queue name
    name: String,
    /// Content
    delivery: Delivery,
}

pub struct TriggerDelivery {
    /// Trigger name
    name: String,
    /// Content
    delivery: Delivery,
}
