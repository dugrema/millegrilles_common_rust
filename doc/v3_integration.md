# Integration with V3 Service Layer

This document explains how to use the new `v3` decoupled architecture in new projects or services.

## Overview

The `v3` architecture uses **Explicit Dependency Injection** via granular traits. Instead of a monolithic `MiddlewareMessage`, your application should depend on specific service traits (e.g., `DatabaseService`, `MessagingService`, `CertificatService`).

To bridge the existing `MiddlewareMessage` with this new architecture, we use the `MiddlewareContext<'a>` container.

## Setting Up the Environment

In a new application (e.g., a `main.rs`), you will need to:
1.  Initialize the core resources (configuration, database connections, etc.).
2.  Construct the `MiddlewareMessage` (or a mock for testing).
3.  Wrap it in a `MiddlewareContext` when calling service methods.

### Example `main.rs`

```rust
use millegrilles_common_rust::middleware::MiddlewareMessage;
use millegrilles_common_rust::v3::context::MiddlewareContext;
use millegrilles_common_rust::v3::traits::{CertificatService, MessagingService};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the monolith (The "Provider")
    // In a real app, this involves loading config, connecting to DB, etc.
    let middleware = Arc::new(MiddlewareMessage::configure().await?);

    // 2. Usage in a synchronous-looking flow:
    {
        // Create a context that references the middleware
        let context = MiddlewareContext::new(&middleware);
        
        // Use the services via the context
        // context.certificat.emettre_certificat(some_action).await?;
    }

    Ok(())
}
```

## Handling Long-Running Async Processes

Since `MiddlewareContext<'a>` uses lifetime references (`&'a dyn Trait`), it cannot be directly passed into a `tokio::spawn` block because `tokio::spawn` requires the future to have a `'static` lifetime.

### Recommended Pattern: The "Context Factory"

To handle long-running tasks, do not try to pass a `MiddlewareContext` created in `main` into a `tokio::spawn` block. Instead:

1.  Pass an `Arc<MiddlewareMessage>` to the task.
2.  Inside the task, create a local `MiddlewareContext` using the `Arc`.

```rust
use std::sync::Arc;
use millegrilles_common_rust::middleware::MiddlewareMessage;
use millegrilles_common_rust::v3::context::MiddlewareContext;

async fn long_running_task(middleware: Arc<MiddlewareMessage>) {
    loop {
        // Create a short-lived context for this iteration
        // This context is local to this loop iteration and has a lifetime 
        // tied to the 'middleware' Arc which is owned by the task.
        let ctx = MiddlewareContext::new(&middleware);
        
        // Now you can use any V3 service
        // if let Err(e) = ctx.certificat.emettre_certificat(action).await {
        //     eprintln!("Error: {:?}", e);
        // }
        
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

// In main:
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let middleware = Arc::new(MiddlewareMessage::configure().await?);

    // Clone the Arc for the task
    let task_middleware = middleware.clone();
    
    // Spawn the task. The Arc is moved into the task, satisfying 'static requirements.
    tokio::spawn(async move {
        long_running_task(task_middleware).await;
    });

    // Keep main alive for demonstration
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    Ok(())
}
```

This ensures:
- **Memory Safety**: The `MiddlewareContext` lives only as long as the specific operation needs it.
- **Lifetime Compliance**: You avoid `'static` lifetime issues with `tokio::spawn` by creating the context *after* the task has started and owns its dependencies.
- **Decoupling**: The task logic only needs to know about the `MiddlewareContext` interface.

## Summary of V3 Traits

| Trait | Responsibility |
| :--- | :--- |
| `DatabaseService` | Database collection access |
| `MessagingService` | JSON request/command transmission |
| `SecurityService` | Public key retrieval for encryption |
| `CertificatService` | Certificate issuance and management |
| `ChiffrageService` | Key rotation and certificate management for encryption |
| `ConfigService` | Access to MQ, PKI, and Node configurations |
| `FormatService` | Signature envelope management |
| `BackupService` | Backup operations |
