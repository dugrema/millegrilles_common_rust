use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;
use crate::rabbitmq_dao::{RabbitMqExecutor, TypeMessageOut};
use crate::recepteur_messages::TypeMessage;
use crate::v3::traits::MessagingService;
use async_trait::async_trait;
use millegrilles_cryptographie::securite::Securite;
use millegrilles_cryptographie::x509::EnveloppePrivee;
use serde_json::Value;
use std::sync::Arc;

pub struct MessagingServiceImpl {
    mq: Arc<RabbitMqExecutor>,
    enveloppe_privee: Arc<EnveloppePrivee>,
    securite: Securite,
}

impl MessagingServiceImpl {
    pub fn new(mq: Arc<RabbitMqExecutor>, enveloppe_privee: Arc<EnveloppePrivee>, securite: Securite) -> Self {
        Self { mq, enveloppe_privee, securite }
    }
}

#[async_trait]
impl MessagingService for MessagingServiceImpl {
    async fn emettre_evenement(&self, routage: RoutageMessageAction, value: Value) -> Result<(), Error> {
        todo!()
    }

    async fn transmettre_requete(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
        todo!()
    }

    async fn soumettre_transaction(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
        todo!()
    }

    async fn transmettre_commande(&self, routage: RoutageMessageAction, value: Value) -> Result<Option<TypeMessage>, Error> {
        todo!()
    }

    async fn repondre(&self, routage: RoutageMessageAction, value: Value) -> Result<(), Error> {
        todo!()
    }

    async fn emettre_message(&self, type_message: TypeMessageOut, value: Value) -> Result<Option<TypeMessage>, Error> {
        todo!()
    }

    fn mq_disponible(&self) -> bool {
        todo!()
    }

    fn set_regeneration(&self) {
        todo!()
    }

    fn reset_regeneration(&self) {
        todo!()
    }

    fn get_mode_regeneration(&self) -> bool {
        todo!()
    }

    fn get_securite(&self) -> &Securite {
        todo!()
    }

    fn is_dev(&self) -> bool {
        todo!()
    }
}
