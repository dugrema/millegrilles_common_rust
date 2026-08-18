# Migrating from Middleware Monolith to V3 Service Architecture

This document outlines the strategic shift from the legacy `MiddlewareMessage` "God Object" to the new, granular `v3` architecture. It identifies the primary technical pitfalls encountered during this transition and provides specific remediation strategies.

## The Architectural Shift

The legacy architecture relies on a monolithic `MiddlewareMessage` that implements dozens of traits. This creates a "monolithic state" model where every component has access to everything.

The `v3` architecture uses **Explicit Dependency Injection**. Services are granular, atomic, and composed at the application's **Composition Root**.

---

## Primary Pitfalls & Remediation

### 1. The Object Safety Wall
**The Problem:**
To allow `MiddlewareContext<'a>` to hold services as `&'a dyn Trait`, those traits must be **object-safe**. In Rust, a trait is not object-safe if its methods use:
*   Generics (e.g., `fn method<T>(&self, arg: T)`)
*   `impl Trait` in parameters (e.g., `fn method(&self, arg: &impl MyTrait)`)
*   Methods that return `Self` or have generic return types.

If these are present, you cannot use them as `dyn Trait`, and your `MiddlewareContext` will fail to compile.

**The Fix:**
You must convert generic/`impl` signatures into concrete or trait-object signatures.
*   **Instead of:** `fn emettre_certificat(&self, gen: &impl GenerateurMessages)`
*   **Use:** `async fn emettre_certificat(&self, gen: &dyn GenerateurMessages)`
*   **Instead of:** `fn process<S: AsRef<str>>(&self, arg: S)`
*   **Use:** `fn process(&self, arg: &str)`

### 2. The State Encapsulation Trap (The "Reach-Back")
**The Problem:**
During refactoring, there is a tendency to pass the entire `MiddlewareMessage` (or the `MiddlewareContext`) into service methods so the service can "reach back" into the monolith to get additional dependencies (e.g., a service needing the Database, reaching back into the context to get a Redis connection). This creates circular dependencies and defeats the purpose of decoupling.

**The Fix:**
**Constructor-based Dependency Injection.** 
A service must be entirely self-contained. It should only be aware of the specific tools it requires to perform its job.
*   **Wrong:** `CertificatService::issue(&self, context: &MiddlewareContext)`
*   **Right:** `CertificatService::issue(&self, validator: &dyn ValidateurX509, redis: &RedisDao)`

If a service needs more dependencies, you add them to its `struct` definition at creation time, not to the method arguments.

### 3. Orchestration Complexity (The "God Service" Risk)
**The Problem:**
The legacy `middleware.rs` contains "Orchestration Logic"—methods that coordinate multiple high-level actions (e.g., a method that saves a transaction, marks it as complete, and notifies a domain). If you try to replicate these long, multi-step methods inside a single `v3` trait, you have simply created a "God Service" under a new name.

**The Fix:**
Follow the **Atomic Service Pattern** combined with **Domain Services**.
1.  **Atomic Services (v3 Traits):** Keep traits focused on a single domain (e.g., `DatabaseService` only handles storage; `MessagingService` only handles transport).
2.  **Domain Services (Orchestrators):** Create a separate layer of "Domain Services" (e.g., `TransactionManager`) that is composed of several `v3` services. This manager orchestrates the atomic calls to achieve the business goal.

---

## Summary Checklist for Refactoring

- [ ] **Is the trait object-safe?** (No generics/`impl Trait` in method signatures).
- [ ] **Is the service self-contained?** (Does it only depend on the drivers it needs?).
- [ ] **Is the service atomic?** (Does it perform one domain responsibility, or is it orchestrating others?).
- [ ] **Is the orchestration moved to a higher level?** (Are multi-step processes moved to a "Domain Service" instead of a "God Trait"?).
