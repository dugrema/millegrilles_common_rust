use crate::error::Error as CommonError;
use crate::v3::impls::rabbitmq_consumer::InboundMessage;
use crate::v3::models::ConfigQueueV3;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

/// Named queue for the registry
struct TopicQueue {
    queue: ConfigQueueV3,
    tx: Sender<InboundMessage>,
    /// Holds rx until a consumer process takes it
    rx: Option<Receiver<InboundMessage>>,
}

impl TopicQueue {
    fn new(config: ConfigQueueV3) -> Self {
        let (tx, rx) = mpsc::channel(1);
        Self {
            queue: config,
            tx,
            rx: Some(rx),
        }
    }
}

/// Internal queue, correlation is done with the messages that used send().
struct ReplyQueue {
    /// The reply_q name is re-generated on each connection
    q_name: Mutex<Option<String>>,
}

impl ReplyQueue {
    fn new() -> Self {
        Self {
            q_name: Mutex::new(None),
        }
    }
}

pub struct RabbitQueueRegistry {
    topic_queues: Mutex<HashMap<String, TopicQueue>>,
    reply_queue: ReplyQueue,
}

impl RabbitQueueRegistry {
    pub fn new() -> Self {
        Self {
            topic_queues: Mutex::new(HashMap::new()),
            reply_queue: ReplyQueue::new(),
        }
    }

    pub fn add_named_queue(&self, config: ConfigQueueV3) -> Result<(), crate::error::Error> {
        let queue = TopicQueue::new(config);
        let q_name: String = match queue.queue.queue_name.clone() {
            Some(q_name) => q_name,
            None => return Err(CommonError::Str("Configuration error - topic queue with no name, use add_exclusive_queue()"))
        };

        let mut guard = self.topic_queues.lock()
            .expect("RabbitQueueRegistry.add_named_queue Lock failed");
        if guard.contains_key(q_name.as_str()) {
            return Err(crate::error::Error::String(format!("RabbitQueueRegistry.add_named_queue Name {} already exists", q_name)));
        }
        guard.insert(q_name, queue);
        Ok(())
    }

    /// Adds an exclusive (anonymous) queue to the registry. The label allows fetching its receiver.
    pub fn add_exclusive_queue(&self, label: String, config: ConfigQueueV3) -> Result<(), crate::error::Error> {
        let queue = TopicQueue::new(config);

        let mut guard = self.topic_queues.lock()
            .expect("RabbitQueueRegistry.add_exclusive_queue Lock failed");
        if guard.contains_key(label.as_str()) {
            return Err(crate::error::Error::String(format!("RabbitQueueRegistry.add_exclusive_queue Label {} already exists", label)));
        }
        guard.insert(label, queue);
        Ok(())
    }

    pub fn get_queue_names(&self) -> Vec<String> {
        let guard = self.topic_queues.lock()
            .expect("RabbitQueueRegistry.get_queue_names Lock failed");
        guard.keys().cloned().collect()
    }

    pub fn set_reply_q_name(&self, q_name: Option<String>) {
        let mut guard = self.reply_queue.q_name.lock()
            .expect("RabbitQueueRegistry.get_reply_q_name Lock failed");
        *guard = q_name;
    }

    pub fn get_reply_q_name(&self) -> Option<String> {
        self.reply_queue.q_name.lock().expect("RabbitQueueRegistry.get_reply_q_name Lock failed").clone()
    }

    pub fn get_named_queue(&self, q_name: &str) -> Result<(ConfigQueueV3, Sender<InboundMessage>), crate::error::Error> {
        let mut guard = self.topic_queues.lock()
            .expect("RabbitQueueRegistry.get_named_queue_tx Lock failed");
        match guard.get_mut(q_name) {
            Some(named_queue) => Ok((named_queue.queue.clone(), named_queue.tx.clone())),
            None => Err(CommonError::String(format!("RabbitQueueRegistry.get_named_queue_tx Name {} unknown", q_name)))
        }
    }

    pub fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<InboundMessage>, crate::error::Error> {
        let mut guard = self.topic_queues.lock()
            .expect("RabbitQueueRegistry.take_named_q_rx Lock failed");

        let named_queue = match guard.get_mut(q_name) {
            Some(named_queue) => named_queue,
            None => {
                return Err(CommonError::String(format!("RabbitQueueRegistry.take_named_q_rx Name {} unknown", q_name)));
            }
        };

        match named_queue.rx.take() {
            Some(rx) => Ok(rx),
            None => Err(CommonError::String(format!("RabbitQueueRegistry.take_named_q_rx Receiver for name {} already taken", q_name)))
        }
    }
}
