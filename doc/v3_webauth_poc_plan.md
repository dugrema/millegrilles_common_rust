# Plan: Implement v3 Services for Web Auth PoC

## Objective
Provide a functional, decoupled, and lightweight implementation of the `v3` architecture tailored for a Web Authentication PoC. This PoC will focus on **Redis (Session Management)** and **RabbitMQ (User Information Retrieval)**, intentionally omitting database and transaction logic.

## Scope
- **Target Application**: A lightweight web authentication handler.
- **Included Services**:
    - **Configuration Service**: Access to MQ, PKI, and Node configuration.
    - **Messaging Service**: RabbitMQ interaction for retrieving user information.
    - **Redis Service**: Redis interaction for managing user sessions.
    - **Security Service**: Handling public keys and encryption/decryption.
- **Excluded**:
    - Database (MongoDB/SQL).
    - Complex transactions and `MiddlewareDb`.
    - Legacy `middleware.rs` logic.

## Implementation Roadmap

### 1. Service Implementations (`src/v3/impls/`)
We will implement the granular traits defined in `src/v3/traits.rs` using modern, decoupled dependencies.

*   **`config_service.rs`**: 
    *   Implements `ConfigService`.
    *   Dependency: `Arc<ConfigurationMessagesDb>`.
*   **`messaging_service.rs`**: 
    *   Implements `MessagingService`.
    *   Dependency: `lapin::Channel`.
*   **`security_service.rs`**: 
    *   Implements `SecurityService` and `ChiffrageService`.
    *   Dependency: `CleChiffrageHandlerImpl` and `ValidateurX509Impl`.

### 2. PoC Composition Root (`src/v3/composition_root_poc.rs`)
A dedicated entry point to wire these services together for the PoC.
*   **Function `build_poc_context()`**:
    1.  Load `Configuration`.
    2.  Establish RabbitMQ connection (`lapin`).
    3.  Establish Redis connection (`redis`).
    4.  Initialize and wrap services in `Arc`.
    5.  Return a `MiddlewareContext<'a>` that provides the necessary trait objects.

### 3. Verification (`src/v3/poc_test.rs`)
Update or create tests to prove the PoC architecture works:
*   **Session Test**: Store/Retrieve a value from Redis via `RedisService`.
*   **Messaging Test**: Simulate a RabbitMQ request/response flow.
*   **Integration Test**: Use the `MiddlewareContext` from the composition root to run a complete "Auth Check" sequence.

## Technical Constraints
*   **Strict Object Safety**: No generic methods in trait implementations.
*   **Dependency Injection**: Services will receive specific connection handles (e.g., `lapin::Channel`) rather than the entire context.
*   **Asynchronicity**: All implementations must support `async/await` and be `Send + Sync`.
