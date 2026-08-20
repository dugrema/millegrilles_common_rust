use std::collections::HashMap;
use std::sync::Mutex;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use crate::rabbitmq_dao::ConfigQueue;
use crate::error::Error as CommonError;

/// Named queue for the registry
struct NamedQueue {
    queue: ConfigQueue,
    tx: Sender<MessageMilleGrillesBufferDefault>,
    /// Holds rx until a consumer process takes it
    rx: Option<Receiver<MessageMilleGrillesBufferDefault>>,
}

impl NamedQueue {
    fn new(config: ConfigQueue) -> Self {
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
    named_queues: Mutex<HashMap<String, NamedQueue>>,
    reply_queue: ReplyQueue,
}

impl RabbitQueueRegistry {
    pub fn new() -> Self {
        Self {
            named_queues: Mutex::new(HashMap::new()),
            reply_queue: ReplyQueue::new(),
        }
    }

    pub fn add_named_queue(&self, config: ConfigQueue) -> Result<(), crate::error::Error> {
        let queue = NamedQueue::new(config);
        let q_name = queue.queue.nom_queue.clone();

        let mut guard = self.named_queues.lock()
            .expect("RabbitQueueRegistry.add_named_queue Lock failed");
        if guard.contains_key(q_name.as_str()) {
            return Err(crate::error::Error::String(format!("RabbitQueueRegistry.add_named_queue Name {} already exists", q_name)));
        }
        guard.insert(q_name, queue);
        Ok(())
    }

    pub fn get_queue_names(&self) -> Vec<String> {
        let guard = self.named_queues.lock()
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

    pub fn get_named_queue(&self, q_name: &str) -> Result<(ConfigQueue, Sender<MessageMilleGrillesBufferDefault>), crate::error::Error> {
        let mut guard = self.named_queues.lock()
            .expect("RabbitQueueRegistry.get_named_queue_tx Lock failed");
        match guard.get_mut(q_name) {
            Some(named_queue) => Ok((named_queue.queue.clone(), named_queue.tx.clone())),
            None => Err(CommonError::String(format!("RabbitQueueRegistry.get_named_queue_tx Name {} unknown", q_name)))
        }
    }

    pub fn take_named_q_rx(&self, q_name: &str) -> Result<Receiver<MessageMilleGrillesBufferDefault>, crate::error::Error> {
        let mut guard = self.named_queues.lock()
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
