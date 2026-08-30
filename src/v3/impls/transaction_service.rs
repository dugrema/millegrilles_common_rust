use crate::error::Error as CommonError;
use crate::mongo_dao::MongoDao;
use crate::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use mongodb::ClientSession;
use std::sync::Arc;

pub struct TransactionService<F> {
    mongo: Arc<dyn MongoDao>,
    redo_table: String,
    tracking_table: String,
    router: F
}

impl<F, Fut> TransactionService<F>
where F: Fn(String, TransactionWrapper) -> Fut,
  Fut: Future<Output = Result<TransactionOperationAggregator, CommonError>> + Send
{
    pub fn new(
        mongo: Arc<dyn MongoDao>,
        redo_table: String,
        tracking_table: String,
        router: F
    ) -> Self {
        Self { mongo, redo_table, tracking_table, router }
    }

    pub async fn process_transaction(
        &self,
        wrapper: TransactionWrapper,
    ) -> Result<(), CommonError> {
        process_transaction(
            self.mongo.as_ref(),
            self.redo_table.as_ref(),
            self.tracking_table.as_ref(),
            &self.router,
            wrapper
        ).await
    }
}

pub async fn process_transaction<F, Fut>(
    mongo: &dyn MongoDao,
    redo_table: &str,
    tracking_table: &str,
    router: F,
    wrapper: TransactionWrapper,
) -> Result<(), CommonError>
where F: Fn(String, TransactionWrapper) -> Fut,
      Fut: Future<Output = Result<TransactionOperationAggregator, CommonError>> + Send
{
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

async fn process_atomic_transaction<F, Fut>(
    mongo: &dyn MongoDao,
    session: &mut ClientSession,
    redo_table: &str,
    tracking_table: &str,
    router: F,
    wrapper: TransactionWrapper
) -> Result<(), CommonError>
where F: Fn(String, TransactionWrapper) -> Fut,
      Fut: Future<Output = Result<TransactionOperationAggregator, CommonError>> + Send
{
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
    let operations = router(action, wrapper).await?;

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
