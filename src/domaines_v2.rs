use std::str::from_utf8;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
use millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use mongodb::options::{CountOptions, Hint};
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

use crate::backup::reset_backup_flag;
use crate::certificats::{ValidateurX509, VerificateurPermissions};
use crate::configuration::ConfigMessages;
use crate::constantes::{BACKUP_CHAMP_BACKUP_TRANSACTIONS, COMMANDE_CERT_MAITREDESCLES, DELEGATION_GLOBALE_PROPRIETAIRE, EVENEMENT_BACKUP_DECLENCHER, EVENEMENT_CEDULE, EVENEMENT_TRANSACTION_PERSISTEE, PKI_DOCUMENT_CHAMP_CERTIFICAT, PKI_REQUETE_CERTIFICAT, REQUETE_NOMBRE_TRANSACTIONS, ROLE_BACKUP, RolesCertificats, Securite, TRANSACTION_CHAMP_BACKUP_FLAG, TRANSACTION_CHAMP_COMPLETE, TRANSACTION_CHAMP_EVENEMENT_COMPLETE, TRANSACTION_CHAMP_ID, TRANSACTION_CHAMP_TRANSACTION_TRAITEE};
use crate::db_structs::TransactionValide;
use crate::domaines::{GestionnaireMessages, MessageBackupTransactions, MessageRestaurerTransaction, ReponseNombreTransactions};
use crate::domaines_traits::GestionnaireDomaineV2;
use crate::error::Error;
use crate::generateur_messages::{GenerateurMessages, RoutageMessageReponse};
use crate::messages_generiques::MessageCedule;
use crate::middleware::{Middleware, MiddlewareMessages};
use crate::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use crate::rabbitmq_dao::{NamedQueue, QueueType, TypeMessageOut};
use crate::recepteur_messages::{MessageValide, TypeMessage};
use crate::transactions::{charger_transaction, EtatTransaction, marquer_transaction, sauvegarder_batch, TriggerTransaction};

#[async_trait]
pub trait GestionnaireDomaineSimple: GestionnaireDomaineV2 {

    async fn initialiser<M>(self: &'static Self, middleware: &'static M)
        -> Result<FuturesUnordered<JoinHandle<()>>, Error>
        where M: Middleware
    {
        self.preparer_database_mongodb(middleware).await.expect("preparer_database_mongodb");
        let futures = self.spawn_threads(middleware).await.expect("spawn_threads");

        Ok(futures)
    }

    async fn spawn_threads<M>(self: &'static Self, middleware: &'static M)
        -> Result<FuturesUnordered<JoinHandle<()>>, Error>
        where M: Middleware
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
            futures.push(spawn(GestionnaireDomaineSimple::consommer_messages(self, middleware, rx)));
        }

        Ok(futures)
    }

    async fn consommer_messages<M>(&self, middleware: &M, mut rx: Receiver<TypeMessage>)
        where M: Middleware
    {
        info!("domaines.consommer_messages : Debut thread {}", self.get_q_volatils());
        while let Some(message) = rx.recv().await {
            trace!("Message {} recu : {:?}", self.get_nom_domaine(), message);

            match message {
                TypeMessage::Valide(inner) => {
                    match self.traiter_message_valide_action(middleware, inner).await {
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

    async fn traiter_message_valide_action<M>(&self, middleware: &M, message: MessageValide)
        -> Result<(), Error>
        where M: Middleware
    {
        debug!("traiter_message_valide_action domaine {} : {:?}", self.get_nom_domaine(), &message.type_message);
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
            TypeMessageOut::Requete(_) => self.consommer_requete_trait(middleware, message).await,
            TypeMessageOut::Commande(_) => self.consommer_commande_trait(middleware, message).await,
            TypeMessageOut::Evenement(_) => self.consommer_evenement_trait(middleware, message).await,
            TypeMessageOut::Transaction(_) => Err(String::from("domaines_v2.MiddlewareMessages.traiter_message_valide_action Transaction recue, non supporte sur ce type de gestionnaire"))?,
            TypeMessageOut::Reponse(_) => Err(String::from("Recu reponse sur thread consommation, drop message"))?,
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

    async fn preparer_database_mongodb<M>(&self, middleware: &M) -> Result<(), Error>
        where M: MongoDao + ConfigMessages
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

        Ok(())
    }

    async fn consommer_requete_trait<M>(&self, middleware: &M, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        consommer_requete_trait(self, middleware, m).await
    }

    async fn consommer_commande_trait<M>(&self, middleware: &M, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        debug!("Consommer commande trait : {:?}", &m.type_message);
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
                    _ => self.consommer_commande(middleware, m).await
                }
            },
            false => self.consommer_commande(middleware, m).await
        }
    }

    async fn consommer_evenement_trait<M>(&self, middleware: &M, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        consommer_evenement_trait(self, middleware, m).await
    }

    /// Traite une transaction en la chargeant, dirigeant vers l'aiguillage puis la marque comme traitee
    async fn traiter_transaction<M>(&self, middleware: &M, m: MessageValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
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

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao;

    async fn get_nombre_transactions<M>(&self, middleware: &M)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: GenerateurMessages + MongoDao
    {
        get_nombre_transactions(self, middleware).await
    }

    /// Invoque a toutes les minutes sur reception du message global du ceduleur
    async fn traiter_cedule<M>(&self, _middleware: &M, _trigger: &MessageCedule)
        -> Result<(), Error>
        where M: MiddlewareMessages
    {
        Ok(())
    }

    async fn demarrer_backup<M>(&self, middleware: &M, message: MessageValide)
                                -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
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
                             -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => Err(Error::Str("domaines.reset_backup Tentative de RESET_BACKUP sur domaine sans collection de transactions"))?
        };
        reset_backup_flag(middleware, nom_collection_transactions.as_str()).await
    }

    /// Sauvegarde une transaction restauree dans la collection du domaine.
    /// Si la transaction existe deja (par id), aucun effet.
    async fn restaurer_transaction<M>(&self, middleware: &M, message: MessageValide)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware
    {
        debug!("restaurer_transaction\n{}", from_utf8(message.message.buffer.as_slice())?);

        let nom_collection_transactions = match self.get_collection_transactions() {
            Some(n) => n,
            None => Err(Error::Str("domaines.restaurer_transaction Tentative de restauration sur domaine sans collection de transactions"))?
        };
        let message_ref = message.message.parse()?;
        let message_contenu = message_ref.contenu()?;
        let message_restauration: MessageRestaurerTransaction = message_contenu.deserialize()?;

        let mut transaction = message_restauration.transaction;
        if let Err(e) = transaction.verifier_signature() {
            Err(format!("restaurer_transaction Erreur verification transaction {}, SKIP", transaction.id))?
        }

        if transaction.evenements.is_none() {
            Err(format!("Evenements transaction manquants (1) : {}", transaction.id))?
        }

        let fingerprint_certificat = transaction.pubkey.as_str();
        if middleware.get_certificat(fingerprint_certificat).await.is_none() {
            Err(Error::Str("Certificat absent de la transaction restauree, ** SKIP **"))?
        };

        // Conserver la transaction
        let resultat_batch = sauvegarder_batch(
            middleware, nom_collection_transactions.as_str(), vec![&mut transaction]).await?;
        debug!("domaines.restaurer_transaction Resultat batch sauvegarde : {:?}", resultat_batch);

        match message_restauration.ack {
            Some(a) => match a {
                true => Ok(Some(middleware.reponse_ok(None, None)?)),
                false => Ok(None)
            },
            None => Ok(None)
        }
    }
}

async fn consommer_requete_trait<M,G>(gestionnaire: &G, middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: Middleware, G: GestionnaireDomaineSimple
{
    debug!("Consommer requete trait : {:?}", &m.type_message);
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
            REQUETE_NOMBRE_TRANSACTIONS => gestionnaire.get_nombre_transactions(middleware).await,
            _ => gestionnaire.consommer_requete(middleware, m).await
        },
        false => gestionnaire.consommer_requete(middleware, m).await
    }
}

async fn consommer_evenement_trait<G,M>(gestionnaire: &G, middleware: &M, m: MessageValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: Middleware, G: GestionnaireDomaineSimple
{
    debug!("Consommer evenement trait : {:?}", &m.type_message);
    let routage_action = match &m.type_message {
        TypeMessageOut::Evenement(r) => r.clone(),
        _ => Err(String::from("consommer_evenement_trait Type de message n'est pas TypeMessage::Evenement"))?
    };
    let (domaine, action) = {
        let message_ref = m.message.parse()?;
        let routage = match &message_ref.routage {
            Some(inner) => inner,
            None => Err(String::from("consommer_evenement_trait Routage absent du message"))?
        };
        let domaine = match &routage.domaine {
            Some(inner) => inner.to_string(),
            None => Err(String::from("consommer_evenement_trait Domaine absent du message"))?
        };
        let action = match &routage.action {
            Some(inner) => inner.to_string(),
            None => Err(String::from("consommer_evenement_trait Action absente du message"))?
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
                    let reponse = gestionnaire.traiter_transaction(middleware, m).await?;
                    Ok(reponse)
                },
                EVENEMENT_CEDULE => {
                    let message_ref = m.message.parse()?;
                    let message_contenu = message_ref.contenu()?;
                    let trigger: MessageCedule = message_contenu.deserialize()?;
                    // self.verifier_backup_cedule(middleware.as_ref(), &trigger).await?;
                    gestionnaire.traiter_cedule(middleware, &trigger).await?;
                    Ok(None)
                },
                COMMANDE_CERT_MAITREDESCLES => {
                    // Le certificat de maitre des cles est attache
                    let certificat = m.certificat;
                    debug!("consommer_evenement_trait Certificat de maitre des cles recu : {}", certificat.fingerprint()?);
                    if let Err(e) = middleware.ajouter_certificat_chiffrage(certificat) {
                        error!("consommer_evenement_trait Erreur reception certificat chiffrage : {:?}", e);
                    }
                    Ok(None)
                },
                _ => gestionnaire.consommer_evenement(middleware, m).await
            }
        },
        false => match m.certificat.verifier_exchanges(vec!(Securite::L2Prive))? {
            true => {
                match m.certificat.verifier_roles(vec![RolesCertificats::Backup])? {
                    true => match action.as_str() {
                        EVENEMENT_BACKUP_DECLENCHER => gestionnaire.demarrer_backup(middleware, m).await,
                        _ => gestionnaire.consommer_evenement(middleware, m).await
                    },
                    _ => gestionnaire.consommer_evenement(middleware, m).await
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
                                    return gestionnaire.consommer_evenement(middleware, m).await
                                };
                                let correlation_id = if let Some(inner) = routage_action.correlation_id.as_ref() {
                                    inner
                                } else {
                                    return gestionnaire.consommer_evenement(middleware, m).await
                                };
                                middleware.repondre_certificat(reply_q, correlation_id).await?;
                                Ok(None)
                            },
                            _ => gestionnaire.consommer_evenement(middleware, m).await
                        },
                        _ => gestionnaire.consommer_evenement(middleware, m).await
                    },
                    false => gestionnaire.consommer_evenement(middleware, m).await
                }
            }
        }
    }
}

async fn get_nombre_transactions<M,G>(gestionnaire: &G, middleware: &M)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao, G: GestionnaireDomaineV2
{
    let nom_collection_transactions = match gestionnaire.get_collection_transactions() {
        Some(inner) => inner,
        None => {
            let reponse = ReponseNombreTransactions { ok: true, domaine: gestionnaire.get_nom_domaine(), nombre_transactions: 0 };
            return Ok(Some(middleware.build_reponse(reponse)?.0));
        }
    };

    let collection = middleware.get_collection(nom_collection_transactions.as_str())?;
    let options = CountOptions::builder().hint(Some(Hint::Name("_id_".to_string()))).build();
    let nombre_transactions = collection.count_documents(None, options).await? as i64;

    let reponse = ReponseNombreTransactions { ok: true, domaine: gestionnaire.get_nom_domaine(), nombre_transactions };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}
