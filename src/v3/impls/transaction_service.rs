use crate::error::Error as CommonError;
use crate::generateur_messages::RoutageMessageAction;
use crate::mongo_dao::MongoDao;
use crate::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use crate::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use async_trait::async_trait;
use millegrilles_cryptographie::messages_structs::MessageKind;
use mongodb::ClientSession;
use serde_json::Value;
use std::sync::Arc;

pub struct TransactionServiceImpl {
    config: Arc<dyn ConfigService>,
    format: Arc<dyn FormatService>,
    mongo: Arc<dyn MongoDao>,
    router: Box<dyn TransactionRouter>,
    redo_table: String,
    tracking_table: String,
}

impl TransactionServiceImpl {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>,
        redo_table: String,
        tracking_table: String,
        router: Box<dyn TransactionRouter>
    ) -> Self {
        Self { config, format, mongo, redo_table, tracking_table, router }
    }
}

#[async_trait]
impl TransactionService for TransactionServiceImpl {
    async fn process_transaction(&self, wrapper: TransactionWrapper) -> Result<(), CommonError> {
        process_transaction(
            self.mongo.as_ref(),
            self.router.as_ref(),
            self.redo_table.as_str(),
            self.tracking_table.as_str(),
            wrapper
        ).await
    }

    async fn process_value(&self, domain: &str, action: &str, value: Value) -> Result<(), CommonError> {
        let wrapper = build_transaction(
            self.config.as_ref(),
            self.format.as_ref(),
            domain,
            action,
            value
        )?;
        self.process_transaction(wrapper).await
    }
}

pub async fn process_transaction(
    mongo: &dyn MongoDao,
    router: &dyn TransactionRouter,
    redo_table: &str,
    tracking_table: &str,
    wrapper: TransactionWrapper,
) -> Result<(), CommonError> {
    // Start a session
    let mut session = mongo.get_session().await?;

    match process_atomic_transaction(mongo, &mut session, redo_table, tracking_table, router, wrapper).await {
        Ok(()) => {
            session.commit_transaction().await?;
            Ok(())
        },
        Err(e) => {
            session.abort_transaction().await?;
            Err(e)
        },
    }
}

async fn process_atomic_transaction(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    redo_table: &str,
    tracking_table: &str,
    router: &dyn TransactionRouter,
    wrapper: TransactionWrapper
) -> Result<(), CommonError> {
    let action = match wrapper.message.routage.as_ref() {
        Some(r) => match r.action.as_ref() {
            Some(a) => a.to_string(),
            None => return Err(CommonError::Str("Transaction with no routing action"))
        },
        None => return Err(CommonError::Str("Transaction with no routing information"))
    };

    // Save the transaction detail in the redo log (transaction table) for the domain
    persist_transaction(mongo, redo_table, tracking_table, &wrapper).await?;

    // Run the domain router to generate MongoDB write operations
    // let operations = ca_transaction_router(action.as_str(), wrapper).await?;
    let operations = router.route(action, wrapper).await?;

    // Run the operations within a database session - will rollback everything on error
    run_transaction_aggregator(mongo, session, operations).await?;

    Ok(())
}

async fn persist_transaction(mongo: &dyn MongoDao, redo_table: &str, tracking_table: &str, wrapper: &TransactionWrapper) -> Result<(), CommonError> {

    // Insert into transaction tracking table (prevents duplicates)

    // Insert into redo-log table to be backed-up.

    todo!();
    Ok(())
}


async fn run_transaction_aggregator(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    ops_aggregator: TransactionOperationAggregator
) -> Result<(), CommonError> {
    // Run batch inserts first
    if let Some(batch_insertions) = ops_aggregator.batch_insertions {
        for batch_insertion in batch_insertions {
            let collection = mongo.get_collection(batch_insertion.collection_name.as_str())?;
            collection.insert_many(batch_insertion.insertions).await?;
        }
    }

    // Run unordered operations
    if let Some(unordered) = ops_aggregator.unordered {
        mongo.bulk_write(unordered, Some(session), false).await?;
    }

    // Ordered operations last
    if let Some(ordered) = ops_aggregator.ordered {
        mongo.bulk_write(ordered, Some(session), true).await?;
    }

    Ok(())
}

fn build_transaction(
    config: &dyn ConfigService,
    formatter: &dyn FormatService,
    domain: &str,
    action: &str,
    value: Value
) -> Result<TransactionWrapper, CommonError> {
    let routing = RoutageMessageAction::builder(domain, action, vec![]).build();
    let (transaction, _id) = formatter.build_action_message(
        MessageKind::Transaction,
        &routing,
        value,
    )?;
    let wrapper = TransactionWrapper {
        message: transaction.parse_to_owned()?,
        certificate: config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.clone(),
        content: None,
    };
    Ok(wrapper)
}
