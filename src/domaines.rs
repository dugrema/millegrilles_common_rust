use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use tokio::spawn;
use tokio::sync::{mpsc, mpsc::{Receiver, Sender}};
use tokio::task::JoinHandle;
use tokio::time::{Duration as DurationTokio, sleep};

use crate::backup::reset_backup_flag;
use crate::certificats::ValidateurX509;
use crate::certificats::VerificateurPermissions;
use crate::constantes::*;
use crate::db_structs::TransactionValide;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use crate::messages_generiques::MessageCedule;
use crate::middleware::{Middleware, MiddlewareMessages, thread_emettre_presence_domaine};
use crate::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::rabbitmq_dao::{emettre_certificat_compte, NamedQueue, QueueType, TypeMessageOut};
use crate::recepteur_messages::{MessageValide, TypeMessage};
use crate::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction, TriggerTransaction, TraiterTransaction, sauvegarder_batch, regenerer as regenerer_operation};
use crate::error::Error as CommonError;

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

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages + 'static;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages + 'static;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages + 'static;

    /// Thread d'entretien specifique a chaque gestionnaire
    async fn entretien<M>(&self, middleware: Arc<M>)
       where M: MiddlewareMessages + 'static;

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), crate::error::Error>
        where M: MiddlewareMessages + 'static;

    /// Methode qui peut etre re-implementee dans une impl
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, crate::error::Error>
        where M: MiddlewareMessages + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, crate::error::Error>
        where M: MiddlewareMessages + 'static
    {
        let mut futures = FuturesUnordered::new();

        // Mapping par Q nommee
        let qs = self.preparer_queues();
        for q in qs {
            let (tx, rx) = mpsc::channel::<TypeMessage>(1);
            let queue_name = match &q {
                QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                QueueType::ReplyQueue(q) => { continue; }  // Skip
                QueueType::Triggers(d, s) => format!("{}.{:?}", d, s)
            };
            let named_queue = NamedQueue::new(q, tx, Some(1), None);
            middleware.ajouter_named_queue(queue_name, named_queue);
            futures.push(spawn(self.consommer_messages(middleware.clone(), rx)));
        }

        // Thread entretien
        futures.push(spawn(self.entretien(middleware.clone())));

        Ok(futures)
    }

    async fn consommer_messages<M>(self: &'static Self, middleware: Arc<M>, mut rx: Receiver<TypeMessage>)
        where M: MiddlewareMessages + 'static
    {
        info!("domaines.consommer_messages : Debut thread {}", self.get_q_volatils());
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            match message {
                TypeMessage::Valide(inner) => {
                    match self.traiter_message_valide_action(middleware.clone(), inner).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!("GestionnaireMessages domaines.consommer_messages/ValideAction Erreur traitement message domaine={} : {:?}", self.get_nom_domaine(), e);
                        }
                    }
                },
                TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Regeneration => (), // Rien a faire, on boucle
            };

        }

        info!("domaines.consommer_messages : Fin thread {}", self.get_q_volatils());
    }

    async fn traiter_message_valide_action<M>(self: &'static Self, middleware: Arc<M>, message: MessageValide) -> Result<(), crate::error::Error>
        where M: MiddlewareMessages + 'static
    {
        debug!("traiter_message_valide_action domaine {} : {:?}", self.get_nom_domaine(), &message);
        let (correlation_id, reply_q) = match &message.type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) => {
                let correlation_id = match &r.correlation_id {
                    Some(inner) => Some(inner.clone()),
                    None => None,
                };
                let reply_q = match &r.reply_to {
                    Some(inner) => Some(inner.clone()),
                    None => None,
                };
                (correlation_id, reply_q)
            }
            TypeMessageOut::Reponse(_) |
            TypeMessageOut::Evenement(_) => (None, None)
        };

        let resultat = match &message.type_message {
            TypeMessageOut::Requete(_) => self.consommer_requete(middleware.as_ref(), message).await,
            TypeMessageOut::Commande(_) => self.consommer_commande_trait(middleware.clone(), message).await,
            TypeMessageOut::Transaction(_) => Err(String::from("domaines.MiddlewareMessages.traiter_message_valide_action Transaction recue, non supporte sur ce type de gestionnaire"))?,
            TypeMessageOut::Reponse(_) => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
            TypeMessageOut::Evenement(_) => self.consommer_evenement_trait(middleware.clone(), message).await,
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
                let message_ref = reponse.parse()?;
                middleware.repondre(routage, message_ref).await?;
            },
            None => (),  // Aucune reponse
        }

        Ok(())
    }

    async fn consommer_evenement_trait<M>(self: &'static Self, middleware: Arc<M>, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages + 'static
    {
        debug!("Consommer evenement trait : {:?}", &m.message);

        let action = {
            let message_ref = m.message.parse()?;
            let routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("consommer_evenement_trait Routage absent du message"))?
            };
            let action = match &routage.action {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_evenement_trait Action absente du message"))?
            };
            action
        };

        // Autorisation : les evenements (triggers) globaux sont de niveau 4
        // Fallback sur les evenements specifiques au domaine
        match m.certificat.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure))? {
            true => {
                match action.as_str() {
                    EVENEMENT_CEDULE => {
                        let message_ref = m.message.parse()?;
                        let message_contenu = message_ref.contenu()?;
                        let trigger: MessageCedule = message_contenu.deserialize()?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    COMMANDE_CERT_MAITREDESCLES => {
                        let type_message = TypeMessage::Valide(m);
                        error!("domaines.GestionnaireMessages.consommer_evenement_trait Fix intercepter certificat maitre des cles");
                        // match middleware.recevoir_certificat_chiffrage(middleware.as_ref(), &type_message).await {
                        //     Ok(_) => (),
                        //     Err(e) => {
                        //         error!("Erreur interception certificat maitre des cles : {:?}", e);
                        //     }
                        // };
                        Ok(None)
                    },
                    _ => self.consommer_evenement(middleware.as_ref(), m).await
                }
            },
            false => self.consommer_evenement(middleware.as_ref(), m).await
        }
    }

    /// Traite une commande - intercepte les commandes communes a tous les domaines (e.g. backup)
    async fn consommer_commande_trait<M>(&self, middleware: Arc<M>, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: MiddlewareMessages + 'static
    {
        debug!("Consommer commande trait : {:?}", &m.message);
        let action = {
            let message_ref = m.message.parse()?;
            let routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("consommer_evenement_trait Routage absent du message"))?
            };
            let action = match &routage.action {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_evenement_trait Action absente du message"))?
            };
            action
        };

        // Autorisation : les commandes globales sont de niveau 3 ou 4
        // Fallback sur les commandes specifiques au domaine
        let autorise_global = match m.certificat.verifier_exchanges(vec!(Securite::L4Secure))? {
            true => true,
            false => m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?
        };

        match autorise_global {
            true => {
                match action.as_str() {
                    // Commandes specifiques au domaine
                    _ => self.consommer_commande(middleware.as_ref(), m).await
                }
            },
            false => self.consommer_commande(middleware.as_ref(), m).await
        }
    }

}

#[derive(Serialize)]
struct ReponseNombreTransactions {
    ok: bool,
    domaine: String,
    nombre_transactions: i64,
}

#[async_trait]
pub trait GestionnaireDomaine: Clone + Sized + Send + Sync + TraiterTransaction {

    /// Retourne le nom du domaine
    fn get_nom_domaine(&self) -> String;

    /// Identificateur de partition. Optionnel, par defaut None.
    fn get_partition(&self) -> Option<String> { None }

    /// Retourne le nom de la collection de transactions
    fn get_collection_transactions(&self) -> Option<String>;

    // Retourne la liste de collections de documents
    fn get_collections_documents(&self) -> Vec<String>;

    fn get_q_transactions(&self) -> Option<String>;
    fn get_q_volatils(&self) -> Option<String>;
    fn get_q_triggers(&self) -> Option<String>;

    /// Retourne la liste des Q a configurer pour ce domaine
    fn preparer_queues(&self) -> Vec<QueueType>;

    // Retourne vrai si ce domaine doit chiffrer ses backup
    // Par defaut true.
    fn chiffrer_backup(&self) -> bool { true }

    /// Retourne true si utilise consignation fichiers avec fuuids
    fn reclame_fuuids(&self) -> bool { false }

    /// Genere les index du domaine dans MongoDB
    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), crate::error::Error>
        where M: Middleware + 'static;

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static;

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static;

    /// Thread d'entretien specifique a chaque gestionnaire
    async fn entretien<M>(self: &'static Self, middleware: Arc<M>)
       where M: Middleware + 'static;

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), crate::error::Error>
        where M: Middleware + 'static;

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao,
            T: TryInto<TransactionValide> + Send;

    /// Methode qui peut etre re-implementee dans une impl
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, crate::error::Error>
        where M: Middleware + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, crate::error::Error>
        where M: Middleware + 'static
    {
        // Attendre pour eviter echec immedia sur connexion (note to do : ajouter event wait sur MQ)
        let duration = DurationTokio::from_millis(3000);
        sleep(duration).await;

        // Preparer les index MongoDB
        self.preparer_index_mongodb(middleware.as_ref()).await?;

        let mut futures = FuturesUnordered::new();

        // Mapping par Q nommee
        let qs = self.preparer_queues();
        for q in qs {
            let (tx, rx) = mpsc::channel::<TypeMessage>(1);
            let queue_name = match &q {
                QueueType::ExchangeQueue(q) => q.nom_queue.clone(),
                QueueType::ReplyQueue(q) => { continue; }  // Skip
                QueueType::Triggers(d, s) => format!("{}.{:?}", d, s)
            };
            let named_queue = NamedQueue::new(q, tx, Some(1), None);
            middleware.ajouter_named_queue(queue_name, named_queue);
            futures.push(spawn(self.consommer_messages(middleware.clone(), rx)));
        }

        futures.push(spawn(self.entretien(middleware.clone())));
        futures.push(spawn(thread_emettre_presence_domaine(
            middleware.clone(), self.get_nom_domaine(), self.reclame_fuuids())));

        Ok(futures)
    }

    async fn consommer_messages<M>(self: &'static Self, middleware: Arc<M>, mut rx: Receiver<TypeMessage>)
        where M: Middleware + 'static
    {
        info!("domaines.consommer_messages : Debut thread {:?}", self.get_nom_domaine());
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            match message {
                TypeMessage::Valide(inner) => {
                    let type_message = inner.type_message.clone();  // Pour message erreur
                    match self.traiter_message_valide_action(middleware.clone(), inner).await {
                        Ok(r) => r,
                        Err(e) => {
                            error!("GestionnaireDomaine domaines.consommer_messages/ValideAction Erreur traitement message domaine={} routage:{:?} : {:?}", self.get_nom_domaine(), type_message, e);
                        }
                    }
                    // warn!("Recu MessageValide sur thread consommation, skip : {:?}", inner)
                },
                TypeMessage::Certificat(inner) => {warn!("Recu MessageCertificat sur thread consommation, skip : {:?}", inner)},
                TypeMessage::Regeneration => (), // Rien a faire, on boucle
            };

        }

        info!("domaines.consommer_messages : Fin thread {:?}", self.get_nom_domaine());
    }

    async fn traiter_message_valide_action<M>(self: &'static Self, middleware: Arc<M>, message: MessageValide)
        -> Result<(), crate::error::Error>
        where M: Middleware + 'static
    {
        debug!("traiter_message_valide_action domaine {} : {:?}", self.get_nom_domaine(), &message);
        let (correlation_id, reply_q) = match &message.type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) => {
                let correlation_id = match &r.correlation_id {
                    Some(inner) => Some(inner.clone()),
                    None => None,
                };
                let reply_q = match &r.reply_to {
                    Some(inner) => Some(inner.clone()),
                    None => None,
                };
                (correlation_id, reply_q)
            }
            TypeMessageOut::Reponse(_) |
            TypeMessageOut::Evenement(_) => (None, None)
        };

        let resultat = match &message.type_message {
            TypeMessageOut::Requete(_) => self.consommer_requete(middleware.as_ref(), message).await,
            TypeMessageOut::Commande(_) => self.consommer_commande_trait(middleware.clone(), message).await,
            TypeMessageOut::Transaction(_) => self.consommer_transaction(middleware.as_ref(), message).await,
            TypeMessageOut::Reponse(_) => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
            TypeMessageOut::Evenement(_) => self.consommer_evenement_trait(middleware.clone(), message).await,
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
                let type_message = TypeMessageOut::Reponse(routage.into());
                middleware.emettre_message(type_message, reponse).await?;
            },
            None => (),  // Aucune reponse
        }
        Ok(())
    }

    /// Traite une transaction en la chargeant, dirigeant vers l'aiguillage puis la marque comme traitee
    async fn traiter_transaction<M>(self: &'static Self, middleware: &M, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
        where M: ValidateurX509 + GenerateurMessages + MongoDao /*+ VerificateurMessage*/
    {
        // let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
        //     Ok(t) => t,
        //     Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
        // };
        let message_ref = match m.message.parse() {
            Ok(inner) => inner,
            Err(e) => Err(format!("traiter_transaction Erreur parse message {}", e))?
        };
        let message_contenu = match message_ref.contenu() {
            Ok(inner) => inner,
            Err(e) => Err(format!("Erreur conversion message contenu {:?} : {:?}", m, e))?
        };
        let trigger: TriggerTransaction = match message_contenu.deserialize() {
            Ok(inner) => inner,
            Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?
        };

        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => {
                Err(format!("domaines.traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))?
            }
        };

        let transaction = charger_transaction(middleware, nom_collection_transactions.as_str(), &trigger).await?;
        debug!("Traitement transaction, chargee : {:?}", transaction.transaction.id);

        let uuid_transaction = transaction.transaction.id.clone();
        match self.aiguillage_transaction(middleware, transaction).await {
            Ok(r) => {
                // Marquer transaction completee
                debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
                let nom_collection_transactions = match self.get_collection_transactions() {
                    Some(n) => n,
                    None => {
                        Err(format!("domaines.traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))?
                    }
                };
                marquer_transaction(middleware, nom_collection_transactions, uuid_transaction, EtatTransaction::Complete).await?;

                // Repondre en fonction du contenu du trigger
                if let Some(reponse) = r {
                    if let Some(routage_reponse) = trigger.reply_info() {
                        debug!("Emettre reponse vers {:?} = {:?}", routage_reponse, reponse);
                        let message_ref = reponse.parse()?;
                        if let Err(e) = middleware.repondre(routage_reponse, message_ref).await {
                            error!("domaines.traiter_transaction: Erreur emission reponse pour une transaction : {:?}", e);
                        }
                    }
                }

                Ok(None)
            },
            Err(e) => Err(e)?
        }
    }

    async fn preparer_index_mongodb<M>(&self, middleware: &M) -> Result<(), crate::error::Error>
        where M: Middleware + 'static
    {
        if let Some(nom_collection_transactions) = self.get_collection_transactions() {

            // Index transactions par uuid-transaction
            let options_unique_transactions = IndexOptions {
                nom_index: Some(String::from("index_champ_id")),
                unique: true
            };
            let champs_index_transactions = vec!(
                ChampIndex {nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1}
            );

            middleware.create_index(
                middleware,
                nom_collection_transactions.as_str(),
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
                middleware,
                nom_collection_transactions.as_str(),
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
                middleware,
                nom_collection_transactions.as_str(),
                champs_index_transactions,
                Some(options_unique_transactions)
            ).await?;

        }

        // Hook pour index custom du domaine
        self.preparer_database(middleware).await
    }

    async fn consommer_requete_trait<M>(self: &'static Self, middleware: Arc<M>, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        debug!("Consommer requete trait : {:?}", &m.message);
        let action = {
            let message_ref = m.message.parse()?;
            let routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("consommer_requete_trait Routage absent du message"))?
            };
            let action = match &routage.action {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_requete_trait Action absente du message"))?
            };
            action
        };

        match m.certificat.verifier_exchanges(vec!(Securite::L2Prive))? &&
            m.certificat.verifier_roles_string(vec![ROLE_BACKUP.to_string()])? {
            true => match action.as_str() {
                REQUETE_NOMBRE_TRANSACTIONS => self.get_nombre_transactions(middleware.as_ref(), m).await,
                _ => self.consommer_requete(middleware.as_ref(), m).await
            },
            false => self.consommer_requete(middleware.as_ref(), m).await
        }
    }

    async fn consommer_evenement_trait<M>(self: &'static Self, middleware: Arc<M>, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        debug!("Consommer evenement trait : {:?}", &m.message);
        let routage_action = match &m.type_message {
            TypeMessageOut::Evenement(r) => r.clone(),
            _ => Err(String::from("consommer_evenement_trait Type de message n'est pas TypeMessage::Evenement"))?
        };
        let (domaine, action) = {
            let message_ref = m.message.parse()?;
            let routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("consommer_requete_trait Routage absent du message"))?
            };
            let domaine = match &routage.domaine {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_requete_trait Domaine absent du message"))?
            };
            let action = match &routage.action {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_requete_trait Action absente du message"))?
            };
            (domaine, action)
        };

        // Autorisation : les evenements triggers globaux sont de niveau 4,
        //                sauf pour le backup (domaine fichiers, niveau 2)
        // Fallback sur les evenements specifiques au domaine
        match m.certificat.verifier_exchanges(vec!(Securite::L4Secure))? {
            true => {
                match action.as_str() {
                    EVENEMENT_TRANSACTION_PERSISTEE => {
                        let reponse = self.traiter_transaction(middleware.as_ref(), m).await?;
                        Ok(reponse)
                    },
                    EVENEMENT_CEDULE => {
                        let message_ref = m.message.parse()?;
                        let message_contenu = message_ref.contenu()?;
                        let trigger: MessageCedule = message_contenu.deserialize()?;
                        // self.verifier_backup_cedule(middleware.as_ref(), &trigger).await?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    COMMANDE_CERT_MAITREDESCLES => {
                        let type_message = TypeMessage::Valide(m);
                        error!("domaines.GestionnaireDomaines.consommer_evenement_trait Fix intercepter certificat maitre des cles");
                        // match middleware.recevoir_certificat_chiffrage(middleware.as_ref(), &type_message).await {
                        //     Ok(_) => (),
                        //     Err(e) => {
                        //         error!("domaines.consommer_evenement_trait Erreur interception certificat maitre des cles : {:?}", e);
                        //     }
                        // };
                        Ok(None)
                    },
                    _ => self.consommer_evenement(middleware.as_ref(), m).await
                }
            },
            false => match m.certificat.verifier_exchanges(vec!(Securite::L2Prive))? {
                true => {
                    match m.certificat.verifier_roles(vec![RolesCertificats::Backup])? {
                        true => match action.as_str() {
                            EVENEMENT_BACKUP_DECLENCHER => self.demarrer_backup(middleware.as_ref(), m).await,
                            _ => self.consommer_evenement(middleware.as_ref(), m).await
                        },
                        _ => self.consommer_evenement(middleware.as_ref(), m).await
                    }
                },
                false => {
                    match m.certificat.verifier_exchanges(vec!(Securite::L1Public))? {
                        true => match domaine.as_str() {
                            PKI_DOCUMENT_CHAMP_CERTIFICAT => match action.as_str() {
                                PKI_REQUETE_CERTIFICAT => {
                                    let reply_q = if let Some(inner) = routage_action.reply_to.as_ref() {
                                        inner
                                    } else {
                                        return self.consommer_evenement(middleware.as_ref(), m).await
                                    };
                                    let correlation_id = if let Some(inner) = routage_action.correlation_id.as_ref() {
                                        inner
                                    } else {
                                        return self.consommer_evenement(middleware.as_ref(), m).await
                                    };
                                    middleware.repondre_certificat(reply_q, correlation_id).await?;
                                    Ok(None)
                                },
                                _ => self.consommer_evenement(middleware.as_ref(), m).await
                            },
                            _ => self.consommer_evenement(middleware.as_ref(), m).await
                        },
                        false => self.consommer_evenement(middleware.as_ref(), m).await
                    }
                }
            }
        }
    }

    async fn get_nombre_transactions<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(inner) => inner,
            None => {
                let reponse = ReponseNombreTransactions { ok: true, domaine: self.get_nom_domaine(), nombre_transactions: 0 };
                return Ok(Some(middleware.build_reponse(reponse)?.0));
            }
        };

        let collection = middleware.get_collection(nom_collection_transactions.as_str())?;
        let nombre_transactions = collection.count_documents(None, None).await? as i64;

        let reponse = ReponseNombreTransactions { ok: true, domaine: self.get_nom_domaine(), nombre_transactions };
        Ok(Some(middleware.build_reponse(reponse)?.0))
    }

    async fn demarrer_backup<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        if middleware.get_mode_regeneration() == true {
            warn!("demarrer_backup Backup annule, regeneration en cours");
            return Ok(None);
        }

        let (correlation_id, reply_q) = match &message.type_message {
            TypeMessageOut::Requete(r) |
            TypeMessageOut::Commande(r) |
            TypeMessageOut::Transaction(r) |
            TypeMessageOut::Evenement(r) => {
                let correlation_id = match r.correlation_id.as_ref() {
                    Some(inner) => inner,
                    None => Err(String::from("GestionnaireDomaine.demarrer_backup Erreur trigger sans correlation_id"))?
                };
                let reply_to = match r.reply_to.as_ref() {
                    Some(inner) => inner,
                    None => Err(String::from("GestionnaireDomaine.demarrer_backup Erreur trigger sans reply_q"))?
                };
                (correlation_id, reply_to)
            }
            TypeMessageOut::Reponse(r) => {
                (&r.correlation_id, &r.reply_to)
            }
        };

        // let correlation_id = match correlation_id {
        //     Some(inner) => inner,
        //     None => Err(format!("GestionnaireDomaine.demarrer_backup Erreur trigger sans correlation_id"))?
        // };
        //
        // let reply_q = match reply_q {
        //     Some(inner) => inner,
        //     None => Err(format!("GestionnaireDomaine.demarrer_backup Erreur trigger sans reply_q"))?
        // };

        let message_ref = message.message.parse()?;

        debug!("GestionnaireDomaine.demarrer_backup {} : {}", self.get_nom_domaine(), message_ref.id);
        let message_contenu = message_ref.contenu()?;
        let message_backup: MessageBackupTransactions = message_contenu.deserialize()?;
        let complet = match message_backup.complet.as_ref() { Some(v) => v.to_owned(), None => false };

        if let Some(nom_collection_transactions) = self.get_collection_transactions() {
            middleware.demarrer_backup(
                self.get_nom_domaine().as_str(),
                nom_collection_transactions.as_str(),
                complet,
                reply_q,
                correlation_id
            ).await?;
        }

        Ok(None)
    }

    async fn reset_backup<M>(&self, middleware: &M)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => Err(format!("domaines.reset_backup Tentative de RESET_BACKUP sur domaine sans collection de transactions"))?
        };
        reset_backup_flag(middleware, nom_collection_transactions.as_str()).await
    }

    /// Sauvegarde une transaction restauree dans la collection du domaine.
    /// Si la transaction existe deja (par en-tete.uuid_transaction), aucun effet.
    async fn restaurer_transaction<M>(&self, middleware: &M, message: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        debug!("restaurer_transaction {:?}", message);
        todo!("fix me")

        // let nom_collection_transactions = match self.get_collection_transactions() {
        //     Some(n) => n,
        //     None => Err(format!("domaines.restaurer_transaction Tentative de restauration sur domaine sans collection de transactions"))?
        // };
        // let message_ref = message.message.parse()?;
        // let message_restauration: MessageRestaurerTransaction = serde_json::from_str(message_ref.contenu)?;
        // let transaction = message_restauration.transaction;
        //
        // if transaction.attachements.is_none() {
        //     error!("Attachements manquants (1) : {}", transaction.id);
        //     return Ok(None)
        // }
        //
        // // let mut message_serialise = MessageSerialise::from_parsed(transaction)?;
        // //
        // // if message_serialise.parsed.attachements.is_none() {
        // //     error!("Attachements manquants (2) : {:?}", message_serialise.parsed);
        // //     return Ok(None)
        // // }
        //
        // // let fingerprint_certificat = message_serialise.parsed.pubkey.as_str();
        // let fingerprint_certificat = transaction.pubkey.as_str();
        // // let certificat: &Vec<String> = match &message_serialise.parsed.certificat {
        // //     Some(c) => c,
        // //     None => Err(format!("Certificat absent de la transaction restauree, ** SKIP **"))?
        // // };
        // // debug!("Certificat message : {:?}", certificat);
        // // let enveloppe = middleware.charger_enveloppe(certificat, Some(fingerprint_certificat), None).await?;
        // let certificat = match middleware.get_certificat(fingerprint_certificat).await {
        //     Some(inner) => inner,
        //     None => Err(format!("Certificat absent de la transaction restauree, ** SKIP **"))?
        // };
        // message_serialise.set_certificat(certificat);
        //
        // let validation_options = ValidationOptions::new(true, true, true);
        // let resultat_verification = middleware.verifier_message(&mut message_serialise, Some(&validation_options))?;
        // debug!("restaurer_transaction Resultat verification : {:?}", resultat_verification);
        //
        // if ! resultat_verification.valide() {
        //     Err(format!("domaines.restaurer_transaction Transaction invalide - ** SKIP **"))?;
        // }
        //
        // // Retirer les attachments (contenu qui n'est pas signe)
        // let mut transaction = TransactionPersistee::try_from(message_serialise.clone())?;
        // // if let Some(mut attachements) = message_serialise.parsed.attachements.take() {
        // //     if let Some(evenements) = attachements.remove("evenements") {
        // //         let map_evenements: HashMap<String, Value> = serde_json::from_value(evenements)?;
        // //         transaction.set_evenements(map_evenements);
        // //     }
        // // }
        //
        // // Conserver la transaction
        // let resultat_batch = sauvegarder_batch(middleware, nom_collection_transactions.as_str(), vec![transaction]).await?;
        // debug!("domaines.restaurer_transaction Resultat batch sauvegarde : {:?}", resultat_batch);
        //
        // match message_restauration.ack {
        //     Some(a) => match a {
        //         true => Ok(middleware.reponse_ok()?),
        //         false => Ok(None)
        //     },
        //     None => Ok(None)
        // }
    }

    /// Traite une commande - intercepte les commandes communes a tous les domaines (e.g. backup)
    async fn consommer_commande_trait<M>(self: &'static Self, middleware: Arc<M>, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        debug!("Consommer commande trait : {:?}", &m.message);
        let action = {
            let message_ref = m.message.parse()?;
            let routage = match &message_ref.routage {
                Some(inner) => inner,
                None => Err(String::from("consommer_commande_trait Routage absent du message"))?
            };
            let action = match &routage.action {
                Some(inner) => inner.to_string(),
                None => Err(String::from("consommer_commande_trait Action absente du message"))?
            };
            action
        };

        // let routage = match m.type_message {
        //     TypeMessageOut::Commande(r) => r,
        //     _ => Err(String::from("consommer_commande_trait Mauvais type de message"))?
        // };

        // Autorisation : les commandes globales sont de niveau 3 ou 4
        // Fallback sur les commandes specifiques au domaine
        let autorise_global = match m.certificat.verifier_exchanges(vec!(Securite::L4Secure))? {
            true => true,
            false => m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?
        };

        let est_backup_service =  m.certificat.verifier_roles_string(vec![ROLE_BACKUP.to_string()])? &&
            m.certificat.verifier_exchanges(vec![Securite::L2Prive])?;

        match autorise_global {
            true => {
                match action.as_str() {
                    // Commandes standard
                    COMMANDE_BACKUP_HORAIRE => {
                        todo!("fix me")
                        // self.demarrer_backup(middleware.as_ref(), m).await
                    },
                    COMMANDE_RESTAURER_TRANSACTIONS => {
                        todo!("fix me")
                        // self.restaurer_transactions(middleware.clone()).await
                    },
                    COMMANDE_RESTAURER_TRANSACTION => {
                        todo!("fix me")
                        // self.restaurer_transaction(middleware.as_ref(), m).await
                    },
                    COMMANDE_REGENERER => {
                        todo!("fix me")
                        // self.regenerer_transactions(middleware.clone()).await
                    },
                    COMMANDE_RESET_BACKUP => {
                        todo!("fix me")
                        // let nom_collection_transactions = match self.get_collection_transactions() {
                        //     Some(n) => n,
                        //     None => Err(format!("domaines.consommer_commande_trait Tentative de RESET_BACKUP sur domaine sans collection de transactions"))?
                        // };
                        // reset_backup_flag(
                        //     middleware.as_ref(), nom_collection_transactions.as_str()).await
                    },

                    // Commandes specifiques au domaine
                    _ => self.consommer_commande(middleware.as_ref(), m).await
                }
            },
            false => match m.certificat.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure))? {
                true => {
                    match action.as_str() {
                        COMMANDE_RESTAURER_TRANSACTION => self.restaurer_transaction(middleware.as_ref(), m).await,
                        COMMANDE_REGENERER => self.regenerer_transactions(middleware.clone()).await,
                        _ => self.consommer_commande(middleware.as_ref(), m).await
                    }
                },
                false => match est_backup_service {
                    true => match action.as_str() {
                        EVENEMENT_BACKUP_DECLENCHER => self.demarrer_backup(middleware.as_ref(), m).await,
                        COMMANDE_RESET_BACKUP => self.reset_backup(middleware.as_ref()).await,
                        _ => self.consommer_commande(middleware.as_ref(), m).await
                    },
                    false => self.consommer_commande(middleware.as_ref(), m).await
                }
            }
        }
    }

    async fn regenerer_transactions<M>(&self, middleware: Arc<M>) -> Result<Option<MessageMilleGrillesBufferDefault>, crate::error::Error>
        where M: Middleware + 'static
    {
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => Err(format!("domaines.regenerer_transactions Tentative de regeneration sur domaine sans collection de transactions"))?
        };

        let nom_domaine = self.get_nom_domaine();
        let noms_collections_docs = self.get_collections_documents();

        regenerer_operation(
            middleware.as_ref(),
            nom_domaine,
            nom_collection_transactions.as_str(),
            &noms_collections_docs,
            self
        ).await?;

        Ok(None)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct MessageBackupTransactions {
    complet: Option<bool>,
}

#[derive(Clone)]
struct MessageRestaurerTransaction {
    transaction: TransactionValide,
    ack: Option<bool>,
}
