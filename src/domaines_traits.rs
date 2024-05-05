use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use crate::certificats::ValidateurX509;
use crate::db_structs::TransactionValide;
use crate::generateur_messages::GenerateurMessages;

use crate::middleware::Middleware;
use crate::mongo_dao::MongoDao;
use crate::rabbitmq_dao::QueueType;
use crate::recepteur_messages::MessageValide;

/// Gestionnaire de connexion au bus MilleGrilles (mq)
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
}

#[async_trait]
pub trait ConsommateurMessagesBus {

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware;

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware;

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

#[async_trait]
pub trait AiguillageTransactions {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao;
}
