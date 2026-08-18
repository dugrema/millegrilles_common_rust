# RabbitMQ DAO Refactoring Plan (v3)

This document outlines the refactoring plan for the `rabbitmq_dao.rs` file into the `v3/` directory. The goal is to break down the monolithic `RabbitMqExecutor` into smaller, specialized, and more maintainable components.

## Problem Statement
The current `RabbitMqExecutor` in `src/rabbitmq_dao.rs` is a "god class" that manages multiple responsibilities:
- Connection management and reconnection.
- Message dispatching (outbound and inbound responses).
- Consumer management (named queues and reply queues).
- Queue registry and notification.

This makes the code difficult to test, maintain, and extend.

## Proposed Architecture

The refactored implementation will reside in `src/v3/` and implement the `MessagingService` trait. It will use a "Strangler Fig" pattern where the new implementation is built alongside the old one.

### Core Components

1.  **`MessagingServiceImpl`** (`src/v3/impls/messaging_service.rs`):
    - The public entry point implementing `MessagingService`.
    - Orchestrates the lifecycle of all internal components.

2.  **`RabbitConnectionManager`** (`src/v3/impls/rabbitmq_internal.rs`):
    - Manages the `lapin::Connection`.
    - Handles connection establishment and automatic reconnection.
    - Provides available `lapin::Channel` instances.

3.  **`RabbitMessageDispatcher`** (`src/v3/impls/rabbitmq_internal.rs`):
    - Manages outbound message emission (`tx_out`).
    - Manages inbound response handling (`tx_reply`).
    - Manages the `map_attente` for correlation-based request-response patterns.
    - Handles message routing and payload preparation.

4.  **`RabbitConsumerManager`** (`src/v3/impls/rabbitmq_internal.rs`):
    - Manages the lifecycle of message consumers.
    - Handles both standard consumers and named queue consumers.

5.  **`RabbitQueueRegistry`** (`src/v3/impls/rabbitmq_internal.rs`):
    - Maintains the state of the reply queue.
    - Keeps track of registered named queues and their status.

## Implementation Strategy

1.  **Create `src/v3/impls/rabbitmq_internal.rs`**: This will serve as the private implementation layer.
2.  **Implement Specialized Components**: Port logic from `RabbitMqExecutor` into the new componentized structure.
3.  **Implement `MessagingServiceImpl`**: Connect the components to fulfill the `MessagingService` contract.
4.  **Verification**: Ensure the new implementation correctly handles the core RabbitMQ workflows:
    - Connecting/Reconnecting.
    - Sending messages with correlation IDs.
    - Receiving and dispatching responses.
    - Managing named queues and their consumers.

## Impact
- **Legacy Code**: `src/rabbitmq_dao.rs` remains untouched and fully operational.
- **New Code**: Applications using `v3/` will benefit from a more modular and testable messaging infrastructure.
