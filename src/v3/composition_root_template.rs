//! This file is a template demonstrating the "Composition Root" pattern 
//! using the V3 decoupled architecture. It is intended for use as a 
//! reference when starting new services or applications.

use std::sync::Arc;
use async_trait::async_trait;

// Import the V3 traits. In a real project, these will be from your library.
use crate::v3::traits::*;
use crate::error::Error;
use crate::generateur_messages::RoutageMessageAction;

// --- 1. DOMAIN MODELS (Placeholders) ---

pub struct AppConfig {
    pub env: String,
    pub database_url: String,
}

// --- 2. RESOURCE LAYER (Low-level Drivers) ---
// In a real app, these are the concrete types that handle I/O.

pub struct DatabaseDriver { pub url: String }
#[async_trait]
impl DatabaseService for DatabaseDriver {
    async fn get_collection(&self, _name: &str) -> Result<mongodb::bson::Document, Error> {
        // Real implementation would use self.url to connect to MongoDB
        Ok(mongodb::bson::Document::new())
    }
}

pub struct MessagingDriver { pub connection_str: String }
#[async_trait]
impl MessagingService for MessagingDriver {
    async fn transmettre_requete_json(&self, _routage: RoutageMessageAction, _message_json: serde_json::Value) -> Result<Option<crate::recepteur_messages::TypeMessage>, Error> {
        Ok(None)
    }
    async fn transmettre_commande_json(&self, _routage: RoutageMessageAction, _message_json: serde_json::Value) -> Result<Option<crate::recepteur_messages::TypeMessage>, Error> {
        Ok(None)
    }
}

// ... Implement other drivers (CertificatService, ConfigService, etc.) ...

// --- 3. COMPOSITION ROOT ---

/// The AppState is the "Service Container".
/// It holds Arc-wrapped trait objects (or concrete types) that represent
/// the business capabilities of your application.
pub struct AppState {
    pub database: Arc<dyn DatabaseService>,
    pub messaging: Arc<dyn MessagingService>,
    // pub certificat: Arc<dyn CertificatService>,
    // pub config: Arc<dyn ConfigService>,
    // ...
}

/// This is the heart of your application startup.
/// It takes raw configuration and low-level resources and 
/// assembles the high-level business services.
pub async fn compose_services(config: AppConfig) -> Result<Arc<AppState>, Error> {
    // A. Initialize low-level drivers
    let db_driver = DatabaseDriver { url: config.database_url };
    let msg_driver = MessagingDriver { connection_str: "amqp://localhost".to_string() };

    // B. Assemble the AppState
    // Note: We wrap each service in Arc so they can be shared across threads/tasks.
    let state = AppState {
        database: Arc::new(db_driver),
        messaging: Arc::new(msg_driver),
    };

    Ok(Arc::new(state))
}

// --- 4. APPLICATION LOGIC (The Business Layer) ---

/// A business function only knows about the interfaces it needs.
/// This makes it incredibly easy to unit test by passing in mocks.
pub async fn process_data(state: Arc<AppState>) -> Result<(), Error> {
    log::info!("Processing data...");
    
    // Use the services via the state
    let _docs = state.database.get_collection("my_collection").await?;
    
    // state.messaging.transmettre_commande_json(...).await?;

    Ok(())
}

// --- 5. ENTRY POINT (main.rs simulation) ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load Config
    let config = AppConfig {
        env: "development".to_string(),
        database_url: "mongodb://localhost:27017".to_string(),
    };

    // 2. Run Composition Root
    let app_state = compose_services(config).await?;

    // 3. Spawn long-running tasks
    let task_state = app_state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_event_loop(task_state).await {
            eprintln!("Event loop error: {:?}", e);
        }
    });

    // Keep alive for demo
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}

async fn run_event_loop(state: Arc<AppState>) -> Result<(), Error> {
    loop {
        process_data(state.clone()).await?;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
