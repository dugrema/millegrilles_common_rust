use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
use serde_json::Value;
use tokio::spawn;
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use crate::certificats::ValidateurX509;
use crate::chiffrage::{Chiffreur, Dechiffreur};
use crate::configuration::{IsConfigNoeud, ConfigMessages};
use crate::formatteur_messages::{FormatteurMessage, MessageMilleGrille};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use crate::middleware::{IsConfigurationPki, thread_emettre_presence_domaine, Middleware};
use crate::mongo_dao::{MongoDao, ChampIndex, convertir_bson_value, filtrer_doc_id, IndexOptions};
use crate::rabbitmq_dao::{TypeMessageOut, QueueType};
use crate::recepteur_messages::{MessageValideAction, TypeMessage};
use crate::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction, TriggerTransaction};
use std::fmt::{Debug, Formatter};
use crate::constantes::*;

#[async_trait]
pub trait GestionnaireDomaine: Clone + Send {

    /// Retourne le nom du domaine
    fn get_nom_domaine(&self) -> &str;

    /// Retourne le nom de la collection de transactions
    fn get_collection_transactions(&self) -> &str;

    fn get_q_transactions(&self) -> &str;
    fn get_q_volatils(&self) -> &str;
    fn get_q_triggers(&self) -> &str;

    /// Retourne la liste des Q a configurer pour ce domaine
    fn preparer_queues(&self) -> Vec<QueueType>;

    /// Genere les index du domaine dans MongoDB
    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String>
        where M: MongoDao;

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware;

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware;

    async fn entretien<M>(&self, _middleware: Arc<M>)
       where M: Middleware;

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: Transaction;

    /// Initialise le domaine.
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
        where M: Middleware + 'static
    {
        // Preparer les index MongoDB
        self.preparer_index_mongodb(middleware.as_ref()).await?;

        // Channels pour traiter messages
        let (tx_messages, rx_messages) = mpsc::channel::<TypeMessage>(3);
        let (tx_triggers, rx_triggers) = mpsc::channel::<TypeMessage>(10);

        // Routing map pour le domaine
        let mut routing: HashMap<String, Sender<TypeMessage>> = HashMap::new();

        // Mapping par Q nommee
        routing.insert(String::from(self.get_q_transactions()), tx_messages.clone());
        routing.insert(String::from(self.get_q_volatils()), tx_messages.clone());
        routing.insert(String::from(self.get_q_triggers()), tx_triggers.clone());

        // Mapping par domaine (routing key)
        routing.insert(String::from(self.get_nom_domaine()), tx_messages.clone());

        info!("Domaine {} routing mpsc (interne) : {:?}", self.get_nom_domaine(), routing);

        // Thread consommation
        let futures = FuturesUnordered::new();
        futures.push(spawn(self.consommer_messages(middleware.clone(), rx_messages)));
        futures.push(spawn(self.consommer_messages(middleware.clone(), rx_triggers)));

        // Thread entretien
        futures.push(spawn(self.entretien(middleware.clone())));
        futures.push(spawn(thread_emettre_presence_domaine(middleware.clone(), self.get_nom_domaine())));

        Ok((routing, futures))
    }

    async fn consommer_messages<M>(self: &'static Self, middleware: Arc<M>, mut rx: Receiver<TypeMessage>)
        where M: Middleware
    {
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            let resultat = match message {
                TypeMessage::ValideAction(inner) => self.traiter_message_valide_action(middleware.as_ref(), inner).await,
                TypeMessage::Valide(inner) => {warn!("Recu MessageValide sur thread consommation, skip : {:?}", inner); Ok(())},
                TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner); Ok(())},
                TypeMessage::Regeneration => continue, // Rien a faire, on boucle
            };

            if let Err(e) = resultat {
                error!("Erreur traitement message : {:?}\n", e);
            }
        }
    }

    async fn traiter_message_valide_action<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<(), Box<dyn Error>>
        where M: Middleware
    {

        let correlation_id = match &message.correlation_id {
            Some(inner) => Some(inner.clone()),
            None => None,
        };
        let reply_q = match &message.reply_q {
            Some(inner) => Some(inner.clone()),
            None => None,
        };

        let resultat = match message.type_message {
            TypeMessageOut::Requete => self.consommer_requete(middleware, message).await,
            TypeMessageOut::Commande => self.consommer_commande(middleware, message).await,
            TypeMessageOut::Transaction => self.consommer_transaction(middleware, message).await,
            TypeMessageOut::Reponse => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
            TypeMessageOut::Evenement => self.consommer_evenement(middleware, message).await,
        }?;

        match resultat {
            Some(reponse) => {
                let reply_q = match reply_q {
                    Some(reply_q) => reply_q,
                    None => {
                        debug!("Reply Q manquante pour reponse a {:?}", correlation_id);
                        return Ok(())
                    },
                };
                let correlation_id = match correlation_id {
                    Some(correlation_id) => Ok(correlation_id),
                    None => Err("Correlation id manquant pour reponse"),
                }?;
                info!("Emettre reponse vers reply_q {} correlation_id {}", reply_q, correlation_id);
                let routage = RoutageMessageReponse::new(reply_q, correlation_id);
                middleware.repondre(routage, reponse).await?;
            },
            None => (),  // Aucune reponse
        }

        Ok(())
    }

    /// Traite une transaction en la chargeant, dirigeant vers l'aiguillage puis la marque comme traitee
    async fn traiter_transaction<M>(self: &'static Self, middleware: &M, m: MessageValideAction) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
            Ok(t) => t,
            Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
        };

        let transaction = charger_transaction(middleware, self.get_collection_transactions(), &trigger).await?;
        debug!("Traitement transaction, chargee : {:?}", transaction);

        let uuid_transaction = transaction.get_uuid_transaction().to_owned();
        let reponse = self.aiguillage_transaction(middleware, transaction).await;
        if reponse.is_ok() {
            // Marquer transaction completee
            debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
            marquer_transaction(middleware, self.get_collection_transactions(), &uuid_transaction, EtatTransaction::Complete).await?;
        }

        reponse
    }

    async fn preparer_index_mongodb<M>(&self, middleware: &M) -> Result<(), String>
        where M: MongoDao
    {
        // Index transactions par uuid-transaction
        let options_unique_transactions = IndexOptions {
            nom_index: Some(String::from(TRANSACTION_CHAMP_UUID_TRANSACTION)),
            unique: true
        };
        let champs_index_transactions = vec!(
            ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_ENTETE_UUID_TRANSACTION), direction: 1}
        );
        middleware.create_index(
            self.get_collection_transactions(),
            champs_index_transactions,
            Some(options_unique_transactions)
        ).await?;

        // Index transactions completes
        let options_unique_transactions = IndexOptions {
            nom_index: Some(String::from(TRANSACTION_CHAMP_COMPLETE)),
            unique: false
        };
        let champs_index_transactions = vec!(
            ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1}
        );
        middleware.create_index(
            self.get_collection_transactions(),
            champs_index_transactions,
            Some(options_unique_transactions)
        ).await?;

        // Index backup transactions
        let options_unique_transactions = IndexOptions {
            nom_index: Some(String::from(BACKUP_CHAMP_BACKUP_TRANSACTIONS)),
            unique: false
        };
        let champs_index_transactions = vec!(
            ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_TRANSACTION_TRAITEE), direction: 1},
            ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_BACKUP_FLAG), direction: 1},
            ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_EVENEMENT_COMPLETE), direction: 1},
        );
        middleware.create_index(
            self.get_collection_transactions(),
            champs_index_transactions,
            Some(options_unique_transactions)
        ).await?;

        // Hook pour index custom du domaine
        self.preparer_index_mongodb_custom(middleware).await
    }
}
