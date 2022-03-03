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

use crate::backup::{regenerer_operation, reset_backup_flag, restaurer};
use crate::certificats::ValidateurX509;
use crate::certificats::VerificateurPermissions;
use crate::constantes::*;
use crate::formatteur_messages::{MessageMilleGrille};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use crate::messages_generiques::MessageCedule;
use crate::middleware::{Middleware, MiddlewareMessages, thread_emettre_presence_domaine};
use crate::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::rabbitmq_dao::{QueueType, TypeMessageOut};
use crate::recepteur_messages::{MessageValideAction, TypeMessage};
use crate::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction, TriggerTransaction, TraiterTransaction};

#[async_trait]
pub trait GestionnaireMessages: Clone + Sized + Send + Sync {

    /// Retourne le nom du domaine
    fn get_nom_domaine(&self) -> String;

    /// Identificateur de partition. Optionnel, par defaut None.
    fn get_partition(&self) -> Option<String> { None }

    fn get_q_volatils(&self) -> String;
    fn get_q_triggers(&self) -> String;

    /// Retourne la liste des Q a configurer pour ce domaine
    fn preparer_queues(&self) -> Vec<QueueType>;

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static;

    /// Thread d'entretien specifique a chaque gestionnaire
    async fn entretien<M>(&self, middleware: Arc<M>)
       where M: MiddlewareMessages + 'static;

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: MiddlewareMessages + 'static;

    /// Methode qui peut etre re-implementee dans une impl
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        // Channels pour traiter messages
        let (tx_messages, rx_messages) = mpsc::channel::<TypeMessage>(3);
        let (tx_triggers, rx_triggers) = mpsc::channel::<TypeMessage>(10);

        // Routing map pour le domaine
        let mut routing: HashMap<String, Sender<TypeMessage>> = HashMap::new();

        // Mapping par Q nommee
        let qs = self.preparer_queues();
        for q in qs {
            match q {
                QueueType::ExchangeQueue(c) => {
                    debug!("Ajout mapping tx_messages {:?}", c);
                    routing.insert(c.nom_queue.clone(), tx_messages.clone());
                },
                QueueType::Triggers(t, _s) => {
                    debug!("Ajout mapping tx_triggers {:?}", t);
                    routing.insert(String::from(format!("{}/triggers", &t)), tx_triggers.clone());
                }
                QueueType::ReplyQueue(_) => (),
            }
        }

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
        where M: MiddlewareMessages + 'static
    {
        info!("domaines.consommer_messages : Debut thread {}", self.get_q_volatils());
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            match message {
                TypeMessage::ValideAction(inner) => {
                    let rk = inner.routing_key.clone();  // Pour troubleshooting erreurs
                    match self.traiter_message_valide_action(middleware.clone(), inner).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!("domaines.consommer_messages/ValideAction Erreur traitement message domaine={}, rk={}: {:?}", self.get_nom_domaine(), rk, e);
                        }
                    }
                },
                TypeMessage::Valide(inner) => {warn!("Recu MessageValide sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Regeneration => (), // Rien a faire, on boucle
            };

        }

        info!("domaines.consommer_messages : Fin thread {}", self.get_q_volatils());
    }

    async fn traiter_message_valide_action<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction) -> Result<(), Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        debug!("traiter_message_valide_action domaine {} : {:?}", self.get_nom_domaine(), &message);
        let correlation_id = match &message.correlation_id {
            Some(inner) => Some(inner.clone()),
            None => None,
        };
        let reply_q = match &message.reply_q {
            Some(inner) => Some(inner.clone()),
            None => None,
        };

        let resultat = match message.type_message {
            TypeMessageOut::Requete => self.consommer_requete(middleware.as_ref(), message).await,
            TypeMessageOut::Commande => self.consommer_commande_trait(middleware.clone(), message).await,
            TypeMessageOut::Transaction => Err(format!("domaines.MiddlewareMessages.traiter_message_valide_action Transaction recue, non supporte sur ce type de gestionnaire"))?,
            TypeMessageOut::Reponse => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
            TypeMessageOut::Evenement => self.consommer_evenement_trait(middleware.clone(), message).await,
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
                debug!("Emettre reponse vers reply_q {} correlation_id {}", reply_q, correlation_id);
                let routage = RoutageMessageReponse::new(reply_q, correlation_id);
                middleware.repondre(routage, reponse).await?;
            },
            None => (),  // Aucune reponse
        }

        Ok(())
    }

    async fn consommer_evenement_trait<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        debug!("Consommer evenement trait : {:?}", &message.message);
        // Autorisation : les evenements (triggers) globaux sont de niveau 4
        // Fallback sur les evenements specifiques au domaine
        match message.verifier_exchanges(vec!(Securite::L4Secure)) {
            true => {
                match message.action.as_str() {
                    EVENEMENT_CEDULE => {
                        let trigger: MessageCedule = message.message.get_msg().map_contenu(None)?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    _ => self.consommer_evenement(middleware.as_ref(), message).await
                }
            },
            false => self.consommer_evenement(middleware.as_ref(), message).await
        }
    }

    /// Traite une commande - intercepte les commandes communes a tous les domaines (e.g. backup)
    async fn consommer_commande_trait<M>(&self, middleware: Arc<M>, m: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        debug!("Consommer commande trait : {:?}", &m.message);

        // Autorisation : les commandes globales sont de niveau 3 ou 4
        // Fallback sur les commandes specifiques au domaine
        let autorise_global = match m.verifier_exchanges(vec!(Securite::L4Secure)) {
            true => true,
            false => m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)
        };

        match autorise_global {
            true => {
                match m.action.as_str() {
                    // Commandes specifiques au domaine
                    _ => self.consommer_commande(middleware.as_ref(), m).await
                }
            },
            false => self.consommer_commande(middleware.as_ref(), m).await
        }
    }

}

#[async_trait]
pub trait GestionnaireDomaine: Clone + Sized + Send + Sync + TraiterTransaction {

    /// Retourne le nom du domaine
    fn get_nom_domaine(&self) -> String;

    /// Identificateur de partition. Optionnel, par defaut None.
    fn get_partition(&self) -> Option<String> { None }

    /// Retourne le nom de la collection de transactions
    fn get_collection_transactions(&self) -> String;

    // Retourne la liste de collections de documents
    fn get_collections_documents(&self) -> Vec<String>;

    fn get_q_transactions(&self) -> String;
    fn get_q_volatils(&self) -> String;
    fn get_q_triggers(&self) -> String;

    /// Retourne la liste des Q a configurer pour ce domaine
    fn preparer_queues(&self) -> Vec<QueueType>;

    // Retourne vrai si ce domaine doit chiffrer ses backup
    // Par defaut true.
    fn chiffrer_backup(&self) -> bool { true }

    /// Genere les index du domaine dans MongoDB
    async fn preparer_index_mongodb_custom<M>(&self, middleware: &M) -> Result<(), String>
        where M: MongoDao;

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    /// Thread d'entretien specifique a chaque gestionnaire
    async fn entretien<M>(&self, middleware: Arc<M>)
       where M: Middleware + 'static;

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static;

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: Transaction;

    /// Methode qui peut etre re-implementee dans une impl
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<(HashMap<String, Sender<TypeMessage>>, FuturesUnordered<JoinHandle<()>>), Box<dyn Error>>
        where M: Middleware + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
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
        let qs = self.preparer_queues();
        for q in qs {
            match q {
                QueueType::ExchangeQueue(c) => {
                    debug!("Ajout mapping tx_messages {:?}", c);
                    routing.insert(c.nom_queue.clone(), tx_messages.clone());
                },
                QueueType::Triggers(t, _s) => {
                    debug!("Ajout mapping tx_triggers {:?}", t);
                    routing.insert(String::from(format!("{}/triggers", &t)), tx_triggers.clone());
                }
                QueueType::ReplyQueue(_) => (),
            }
        }
        // routing.insert(String::from(self.get_q_transactions()), tx_messages.clone());
        // routing.insert(String::from(self.get_q_volatils()), tx_messages.clone());
        // routing.insert(String::from(self.get_q_triggers()), tx_triggers.clone());

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
        where M: Middleware + 'static
    {
        info!("domaines.consommer_messages : Debut thread {}", self.get_q_transactions());
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            match message {
                TypeMessage::ValideAction(inner) => {
                    let rk = inner.routing_key.clone();  // Pour troubleshooting erreurs
                    match self.traiter_message_valide_action(middleware.clone(), inner).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!("domaines.consommer_messages/ValideAction Erreur traitement message domaine={}, rk={}: {:?}", self.get_nom_domaine(), rk, e);
                        }
                    }
                },
                TypeMessage::Valide(inner) => {warn!("Recu MessageValide sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Regeneration => (), // Rien a faire, on boucle
            };

        }

        info!("domaines.consommer_messages : Fin thread {}", self.get_q_transactions());
    }

    async fn traiter_message_valide_action<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction) -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("traiter_message_valide_action domaine {} : {:?}", self.get_nom_domaine(), &message);
        let correlation_id = match &message.correlation_id {
            Some(inner) => Some(inner.clone()),
            None => None,
        };
        let reply_q = match &message.reply_q {
            Some(inner) => Some(inner.clone()),
            None => None,
        };

        let resultat = match message.type_message {
            TypeMessageOut::Requete => self.consommer_requete(middleware.as_ref(), message).await,
            TypeMessageOut::Commande => self.consommer_commande_trait(middleware.clone(), message).await,
            TypeMessageOut::Transaction => self.consommer_transaction(middleware.as_ref(), message).await,
            TypeMessageOut::Reponse => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
            TypeMessageOut::Evenement => self.consommer_evenement_trait(middleware.clone(), message).await,
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
                debug!("Emettre reponse vers reply_q {} correlation_id {}", reply_q, correlation_id);
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

        let transaction = charger_transaction(middleware, self.get_collection_transactions().as_str(), &trigger).await?;
        debug!("Traitement transaction, chargee : {:?}", transaction);

        let uuid_transaction = transaction.get_uuid_transaction().to_owned();
        match self.aiguillage_transaction(middleware, transaction).await {
            Ok(r) => {
                // Marquer transaction completee
                debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
                marquer_transaction(middleware, self.get_collection_transactions(), uuid_transaction, EtatTransaction::Complete).await?;

                // Repondre en fonction du contenu du trigger
                if let Some(reponse) = r {
                    if let Some(routage_reponse) = trigger.reply_info() {
                        debug!("Emettre reponse vers {:?} = {:?}", routage_reponse, reponse);
                        if let Err(e) = middleware.repondre(routage_reponse, reponse).await {
                            error!("domaines.traiter_transaction: Erreur emission reponse pour une transaction : {:?}", e);
                        }
                    }
                }

                Ok(None)
            },
            Err(e) => Err(e)
        }
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
            self.get_collection_transactions().as_str(),
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
            self.get_collection_transactions().as_str(),
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
            self.get_collection_transactions().as_str(),
            champs_index_transactions,
            Some(options_unique_transactions)
        ).await?;

        // Hook pour index custom du domaine
        self.preparer_index_mongodb_custom(middleware).await
    }

    async fn consommer_evenement_trait<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("Consommer evenement trait : {:?}", &message.message);
        // Autorisation : les evenements (triggers) globaux sont de niveau 4
        // Fallback sur les evenements specifiques au domaine
        match message.verifier_exchanges(vec!(Securite::L4Secure)) {
            true => {
                match message.action.as_str() {
                    EVENEMENT_TRANSACTION_PERSISTEE => {
                        let reponse = self.traiter_transaction(middleware.as_ref(), message).await?;
                        Ok(reponse)
                    },
                    EVENEMENT_CEDULE => {
                        let trigger: MessageCedule = message.message.get_msg().map_contenu(None)?;
                        self.verifier_backup_cedule(middleware.as_ref(), &trigger).await?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    _ => self.consommer_evenement(middleware.as_ref(), message).await
                }
            },
            false => self.consommer_evenement(middleware.as_ref(), message).await
        }
    }

    async fn verifier_backup_cedule<M>(&self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        if trigger.flag_heure {
            info!("verifier_backup_cedule Demarre backup horaire : {:?}", trigger);
            self.demarrer_backup(middleware).await?;
        }

        Ok(())
    }

    async fn demarrer_backup<M>(&self, middleware: &M)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        middleware.demarrer_backup(
            self.get_nom_domaine().as_str(),
            self.get_collection_transactions().as_str(),
            self.chiffrer_backup()
        ).await?;

        Ok(None)
    }

    /// Traite une commande - intercepte les commandes communes a tous les domaines (e.g. backup)
    async fn consommer_commande_trait<M>(&self, middleware: Arc<M>, m: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("Consommer commande trait : {:?}", &m.message);

        // Autorisation : les commandes globales sont de niveau 3 ou 4
        // Fallback sur les commandes specifiques au domaine
        let autorise_global = match m.verifier_exchanges(vec!(Securite::L4Secure)) {
            true => true,
            false => m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)
        };

        match autorise_global {
            true => {
                match m.action.as_str() {
                    // Commandes standard
                    COMMANDE_BACKUP_HORAIRE => self.demarrer_backup(middleware.as_ref()).await,
                    COMMANDE_RESTAURER_TRANSACTIONS => self.restaurer_transactions(middleware.clone()).await,
                    COMMANDE_REGENERER => self.regenerer_transactions(middleware.clone()).await,
                    COMMANDE_RESET_BACKUP => reset_backup_flag(
                        middleware.as_ref(), self.get_collection_transactions().as_str()).await,

                    // Commandes specifiques au domaine
                    _ => self.consommer_commande(middleware.as_ref(), m).await
                }
            },
            false => self.consommer_commande(middleware.as_ref(), m).await
        }
    }

    async fn restaurer_transactions<M>(&self, middleware: Arc<M>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        let noms_collections_docs = self.get_collections_documents();
        //let processor = self.get_processeur_transactions();

        restaurer(
            middleware.clone(),
            self.get_nom_domaine().as_str(),
            self.get_partition(),
            self.get_collection_transactions().as_str(),
            &noms_collections_docs,
            self
        ).await?;

        Ok(None)
    }

    async fn regenerer_transactions<M>(&self, middleware: Arc<M>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        let noms_collections_docs = self.get_collections_documents();
        //let processor = self.get_processeur_transactions();

        regenerer_operation(
            middleware.clone(),
            self.get_nom_domaine().as_str(),
            self.get_partition(),
            self.get_collection_transactions().as_str(),
            &noms_collections_docs,
            self
        ).await?;

        Ok(None)
    }
}