use lapin::message::Delivery;

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
