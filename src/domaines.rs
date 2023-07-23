use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
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
use crate::formatteur_messages::{MessageMilleGrille, MessageSerialise};
use crate::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use crate::messages_generiques::MessageCedule;
use crate::middleware::{Middleware, MiddlewareMessages, thread_emettre_presence_domaine};
use crate::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::rabbitmq_dao::{emettre_certificat_compte, NamedQueue, QueueType, TypeMessageOut};
use crate::recepteur_messages::{MessageValideAction, TypeMessage};
use crate::transactions::{charger_transaction, EtatTransaction, marquer_transaction, Transaction, TriggerTransaction, TraiterTransaction, sauvegarder_batch, regenerer as regenerer_operation, TransactionImpl, TransactionPersistee};
use crate::verificateur::{ValidationOptions, VerificateurMessage};

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
        -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
        where M: MiddlewareMessages + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
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
        match message.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure)) {
            true => {
                match message.action.as_str() {
                    EVENEMENT_CEDULE => {
                        let trigger: MessageCedule = message.message.get_msg().map_contenu()?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    COMMANDE_CERT_MAITREDESCLES => {
                        match middleware.recevoir_certificat_chiffrage(middleware.as_ref(), &message.message).await {
                            Ok(_) => (),
                            Err(e) => {
                                error!("Erreur interception certificat maitre des cles : {:?}", e);
                            }
                        };
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

    /// Genere les index du domaine dans MongoDB
    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String>
        where M: Middleware + 'static;

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static;

    /// Thread d'entretien specifique a chaque gestionnaire
    async fn entretien<M>(self: &'static Self, middleware: Arc<M>)
       where M: Middleware + 'static;

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
        -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static;

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
        -> Result<Option<MessageMilleGrille>, String>
        where
            M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage,
            T: Transaction;

    /// Methode qui peut etre re-implementee dans une impl
    async fn preparer_threads<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        self.preparer_threads_super(middleware).await
    }

    /// Initialise le domaine.
    async fn preparer_threads_super<M>(self: &'static Self, middleware: Arc<M>)
        -> Result<FuturesUnordered<JoinHandle<()>>, Box<dyn Error>>
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
        futures.push(spawn(thread_emettre_presence_domaine(middleware.clone(), self.get_nom_domaine())));

        Ok(futures)
    }

    async fn consommer_messages<M>(self: &'static Self, middleware: Arc<M>, mut rx: Receiver<TypeMessage>)
        where M: Middleware + 'static
    {
        info!("domaines.consommer_messages : Debut thread {:?}", self.get_nom_domaine());
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

        info!("domaines.consommer_messages : Fin thread {:?}", self.get_nom_domaine());
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
            TypeMessageOut::Requete => self.consommer_requete_trait(middleware.clone(), message).await,
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
        where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
    {
        // let trigger = match serde_json::from_value::<TriggerTransaction>(Value::Object(m.message.get_msg().contenu.clone())) {
        //     Ok(t) => t,
        //     Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?,
        // };
        let trigger: TriggerTransaction = match m.message.parsed.map_contenu() {
            Ok(inner) => inner,
            Err(e) => Err(format!("Erreur conversion message vers Trigger {:?} : {:?}", m, e))?
        };

        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => {
                return Err(format!("domaines.traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))
            }
        };

        let transaction = charger_transaction(middleware, nom_collection_transactions.as_str(), &trigger).await?;
        debug!("Traitement transaction, chargee : {:?}", transaction);

        let uuid_transaction = transaction.get_uuid_transaction().to_owned();
        match self.aiguillage_transaction(middleware, transaction).await {
            Ok(r) => {
                // Marquer transaction completee
                debug!("Transaction traitee {}, marquer comme completee", uuid_transaction);
                let nom_collection_transactions = match self.get_collection_transactions() {
                    Some(n) => n,
                    None => {
                        return Err(format!("domaines.traiter_transaction Tentative de sauvegarde de transaction pour gestionnaire sans collection pour transactions"))
                    }
                };
                marquer_transaction(middleware, nom_collection_transactions, uuid_transaction, EtatTransaction::Complete).await?;

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

    async fn consommer_requete_trait<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("Consommer requete trait : {:?}", &message.message);
        match message.verifier_exchanges(vec!(Securite::L2Prive)) &&
            message.verifier_roles_string(vec![ROLE_BACKUP.to_string()]) {
            true => match message.action.as_str() {
                REQUETE_NOMBRE_TRANSACTIONS => self.get_nombre_transactions(middleware.as_ref(), message).await,
                _ => self.consommer_requete(middleware.as_ref(), message).await
            },
            false => self.consommer_requete(middleware.as_ref(), message).await
        }
    }

    async fn consommer_evenement_trait<M>(self: &'static Self, middleware: Arc<M>, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("Consommer evenement trait : {:?}", &message.message);
        // Autorisation : les evenements triggers globaux sont de niveau 4,
        //                sauf pour le backup (domaine fichiers, niveau 2)
        // Fallback sur les evenements specifiques au domaine
        match message.verifier_exchanges(vec!(Securite::L4Secure)) {
            true => {
                match message.action.as_str() {
                    EVENEMENT_TRANSACTION_PERSISTEE => {
                        let reponse = self.traiter_transaction(middleware.as_ref(), message).await?;
                        Ok(reponse)
                    },
                    EVENEMENT_CEDULE => {
                        let trigger: MessageCedule = message.message.get_msg().map_contenu()?;
                        // self.verifier_backup_cedule(middleware.as_ref(), &trigger).await?;
                        self.traiter_cedule(middleware.as_ref(), &trigger).await?;
                        Ok(None)
                    },
                    COMMANDE_CERT_MAITREDESCLES => {
                        match middleware.recevoir_certificat_chiffrage(middleware.as_ref(), &message.message).await {
                            Ok(_) => (),
                            Err(e) => {
                                error!("domaines.consommer_evenement_trait Erreur interception certificat maitre des cles : {:?}", e);
                            }
                        };
                        Ok(None)
                    },
                    _ => self.consommer_evenement(middleware.as_ref(), message).await
                }
            },
            false => match message.verifier_exchanges(vec!(Securite::L2Prive)) {
                true => {
                    match message.verifier_roles(vec![RolesCertificats::Backup]) {
                        true => match message.action.as_str() {
                            EVENEMENT_BACKUP_DECLENCHER => self.demarrer_backup(middleware.as_ref(), message).await,
                            _ => self.consommer_evenement(middleware.as_ref(), message).await
                        },
                        _ => self.consommer_evenement(middleware.as_ref(), message).await
                    }
                },
                false => {
                    match message.verifier_exchanges(vec!(Securite::L1Public)) {
                        true => match message.domaine.as_str() {
                            PKI_DOCUMENT_CHAMP_CERTIFICAT => match message.action.as_str() {
                                PKI_REQUETE_CERTIFICAT => {
                                    let reply_q = if let Some(inner) = message.reply_q.as_ref() {
                                        inner
                                    } else {
                                        return self.consommer_evenement(middleware.as_ref(), message).await
                                    };
                                    let correlation_id = if let Some(inner) = message.correlation_id.as_ref() {
                                        inner
                                    } else {
                                        return self.consommer_evenement(middleware.as_ref(), message).await
                                    };
                                    middleware.repondre_certificat(reply_q, correlation_id).await?;
                                    Ok(None)
                                },
                                _ => self.consommer_evenement(middleware.as_ref(), message).await
                            },
                            _ => self.consommer_evenement(middleware.as_ref(), message).await
                        },
                        false => self.consommer_evenement(middleware.as_ref(), message).await
                    }
                }
            }
        }
    }

    async fn get_nombre_transactions<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(inner) => inner,
            None => {
                let reponse = ReponseNombreTransactions { ok: true, domaine: self.get_nom_domaine(), nombre_transactions: 0 };
                return Ok(Some(middleware.formatter_reponse(reponse, None)?));
            }
        };

        let collection = middleware.get_collection(nom_collection_transactions.as_str())?;
        let nombre_transactions = collection.count_documents(None, None).await? as i64;

        let reponse = ReponseNombreTransactions { ok: true, domaine: self.get_nom_domaine(), nombre_transactions };
        Ok(Some(middleware.formatter_reponse(reponse, None)?))
    }

    async fn demarrer_backup<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        if middleware.get_mode_regeneration() == true {
            warn!("demarrer_backup Backup annule, regeneration en cours");
            return Ok(None);
        }

        debug!("GestionnaireDomaine.demarrer_backup {} : {:?}", self.get_nom_domaine(), message.message.parsed);
        let message_backup: MessageBackupTransactions = message.message.parsed.map_contenu()?;
        let complet = match message_backup.complet.as_ref() { Some(v) => v.to_owned(), None => false };

        if let Some(nom_collection_transactions) = self.get_collection_transactions() {
            middleware.demarrer_backup(
                self.get_nom_domaine().as_str(),
                nom_collection_transactions.as_str(),
                complet
            ).await?;
        }

        Ok(None)
    }

    async fn reset_backup<M>(&self, middleware: &M)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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
    async fn restaurer_transaction<M>(&self, middleware: &M, message: MessageValideAction)
        -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        debug!("restaurer_transaction {:?}", message);
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => Err(format!("domaines.restaurer_transaction Tentative de restauration sur domaine sans collection de transactions"))?
        };
        let message_restauration: MessageRestaurerTransaction = message.message.parsed.map_contenu()?;
        let transaction = message_restauration.transaction;

        if transaction.attachements.is_none() {
            error!("Attachements manquants (1) : {:?}", transaction);
            return Ok(None)
        }

        let mut message_serialise = MessageSerialise::from_parsed(transaction)?;

        if message_serialise.parsed.attachements.is_none() {
            error!("Attachements manquants (2) : {:?}", message_serialise.parsed);
            return Ok(None)
        }

        let fingerprint_certificat = message_serialise.parsed.pubkey.as_str();
        // let certificat: &Vec<String> = match &message_serialise.parsed.certificat {
        //     Some(c) => c,
        //     None => Err(format!("Certificat absent de la transaction restauree, ** SKIP **"))?
        // };
        // debug!("Certificat message : {:?}", certificat);
        // let enveloppe = middleware.charger_enveloppe(certificat, Some(fingerprint_certificat), None).await?;
        let certificat = match middleware.get_certificat(fingerprint_certificat).await {
            Some(inner) => inner,
            None => Err(format!("Certificat absent de la transaction restauree, ** SKIP **"))?
        };
        message_serialise.set_certificat(certificat);

        let validation_options = ValidationOptions::new(true, true, true);
        let resultat_verification = middleware.verifier_message(&mut message_serialise, Some(&validation_options))?;
        debug!("restaurer_transaction Resultat verification : {:?}", resultat_verification);

        if ! resultat_verification.valide() {
            Err(format!("domaines.restaurer_transaction Transaction invalide - ** SKIP **"))?;
        }

        // Retirer les attachments (contenu qui n'est pas signe)
        let mut transaction = TransactionPersistee::try_from(message_serialise.clone())?;
        // if let Some(mut attachements) = message_serialise.parsed.attachements.take() {
        //     if let Some(evenements) = attachements.remove("evenements") {
        //         let map_evenements: HashMap<String, Value> = serde_json::from_value(evenements)?;
        //         transaction.set_evenements(map_evenements);
        //     }
        // }

        // Conserver la transaction
        let resultat_batch = sauvegarder_batch(middleware, nom_collection_transactions.as_str(), vec![transaction]).await?;
        debug!("domaines.restaurer_transaction Resultat batch sauvegarde : {:?}", resultat_batch);

        match message_restauration.ack {
            Some(a) => match a {
                true => Ok(middleware.reponse_ok()?),
                false => Ok(None)
            },
            None => Ok(None)
        }
    }

    /// Traite une commande - intercepte les commandes communes a tous les domaines (e.g. backup)
    async fn consommer_commande_trait<M>(self: &'static Self, middleware: Arc<M>, m: MessageValideAction)
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

        let est_backup_service =  m.verifier_roles_string(vec![ROLE_BACKUP.to_string()]) &&
            m.verifier_exchanges(vec![Securite::L2Prive]);

        match autorise_global {
            true => {
                match m.action.as_str() {
                    // Commandes standard
                    // COMMANDE_BACKUP_HORAIRE => self.demarrer_backup(middleware.as_ref(), m).await,
                    // COMMANDE_RESTAURER_TRANSACTIONS => self.restaurer_transactions(middleware.clone()).await,
                    COMMANDE_RESTAURER_TRANSACTION => self.restaurer_transaction(middleware.as_ref(), m).await,
                    COMMANDE_REGENERER => self.regenerer_transactions(middleware.clone()).await,
                    // COMMANDE_RESET_BACKUP => {
                    //     let nom_collection_transactions = match self.get_collection_transactions() {
                    //         Some(n) => n,
                    //         None => Err(format!("domaines.consommer_commande_trait Tentative de RESET_BACKUP sur domaine sans collection de transactions"))?
                    //     };
                    //     reset_backup_flag(
                    //         middleware.as_ref(), nom_collection_transactions.as_str()).await
                    // },

                    // Commandes specifiques au domaine
                    _ => self.consommer_commande(middleware.as_ref(), m).await
                }
            },
            false => match m.verifier_exchanges(vec!(Securite::L3Protege, Securite::L4Secure)) {
                true => {
                    match m.action.as_str() {
                        COMMANDE_RESTAURER_TRANSACTION => self.restaurer_transaction(middleware.as_ref(), m).await,
                        COMMANDE_REGENERER => self.regenerer_transactions(middleware.clone()).await,
                        _ => self.consommer_commande(middleware.as_ref(), m).await
                    }
                },
                false => match est_backup_service {
                    true => match m.action.as_str() {
                        EVENEMENT_BACKUP_DECLENCHER => self.demarrer_backup(middleware.as_ref(), m).await,
                        COMMANDE_RESET_BACKUP => self.reset_backup(middleware.as_ref()).await,
                        _ => self.consommer_commande(middleware.as_ref(), m).await
                    },
                    false => self.consommer_commande(middleware.as_ref(), m).await
                }
            }
        }
    }

    async fn regenerer_transactions<M>(&self, middleware: Arc<M>) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
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

#[derive(Clone, Debug, Deserialize)]
struct MessageRestaurerTransaction {
    transaction: MessageMilleGrille,
    ack: Option<bool>,
}
