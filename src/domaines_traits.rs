use std::sync::Arc;
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use tokio::sync::mpsc::Receiver;

use crate::middleware::{Middleware, MiddlewareMessages};
use crate::rabbitmq_dao::QueueType;
use crate::recepteur_messages::{MessageValide, TypeMessage};
use crate::transactions::TraiterTransaction;

/// Gestionnaire de connexion au bus MilleGrilles (mq)
// #[async_trait]
pub trait GestionnaireBusMillegrilles: Sized + Send + Sync {

    /// Retourne le nom du domaine
    fn get_nom_domaine(&self) -> String;

    /// Identificateur de partition. Optionnel, par defaut None.
    fn get_partition(&self) -> Result<Option<String>, crate::error::Error> { Ok(None) }

    /// Q pour recevoir les requetes, les commandes et les evenements.
    fn get_q_volatils(&self) -> String;

    /// Retourne la Q utilisee pour les triggers (ping cedule, transactions, etc.)
    fn get_q_triggers(&self) -> String;

    /// Retourne la liste des Q a configurer pour ce domaine
    fn preparer_queues(&self) -> Vec<QueueType>;

    // /// Thread d'entretien, faire un spawn pour la laisser executer en background.
    // async fn entretien<M>(&self, middleware: &'static M) where M: MiddlewareMessages;
    //
    // /// Consomme les messages a partir de MQ.
    // async fn consommer_messages<M>(&self, middleware: &'static M, rx: Receiver<TypeMessage>)
    //     where M: MiddlewareMessages;
}

#[async_trait]
pub trait ConsommateurMessagesBus {

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages;

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages;

}

/// Gestionnaire de domaine. Utilise une base de donnees pour traiter les transactions du domaine.
// #[async_trait]
pub trait GestionnaireDomaineV2: GestionnaireBusMillegrilles + ConsommateurMessagesBus {

    /// Retourne le nom de la collection de transactions
    fn get_collection_transactions(&self) -> Option<String>;

    /// Retourne la liste de collections de documents volatils
    fn get_collections_volatiles(&self) -> Result<Vec<String>, crate::error::Error>;

    /// Retourne true si utilise consignation fichiers avec fuuids
    fn reclame_fuuids(&self) -> bool { false }

}
