# Zero-Trust Autonomous Agent Authorization (ZT-AAS)

An in-process capability-authorization and audit library for autonomous-agent hosts.

> **Security boundary:** this crate governs only actions submitted through `SandboxRuntime`. It does not create OS-level process, filesystem, or network isolation and cannot contain code that retains ambient system access. A production host must isolate the agent and route every external operation through this library.

## Overview

ZT-AAS is a zero-trust policy runtime designed to govern autonomous or semi-autonomous agents inside an already isolated host. It operates on the principle that all agents are untrusted, regardless of origin or intent. Every mediated interaction must be explicitly authorized, policy-validated, and auditable.

The system enforces strict capability-based security where agents present subject-bound grants for actions rather than asking permission. The embedding host is responsible for making the runtime the sole path to external systems.

## Architecture

<pre>
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│   Agent     │    │  Capability  │    │   Policy     │
│             │───▶│   Store      │───▶│   Engine     │
└─────────────┘    └──────────────┘    └──────────────┘
       │                   │                  │
       └───────────────────┴──────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │     Sandbox     │
                  │     Runtime     │
                  │                 │
                  │  ┌───────────┐  │
                  │  │ Mediator  │  │
                  │  └───────────┘  │
                  └────────┬────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     ┌──────────────┐          ┌──────────────┐
     │   Audit Log  │          │   External   │
     │              │          │   Systems    │
     └──────────────┘          └──────────────┘
</pre>

## Components

### Policy Runtime  
Authorizes interactions submitted by an embedding host. The host must separately remove direct agent access to external resources.

### Capability System  
Capabilities are first-class objects defining what agents can do. They are subject-bound, runtime-timestamped, time-bounded, constrainable, and atomically revocable between mediated actions. Synchronous dispatch and revocation are serialized; this crate does not cancel an external operation after dispatch has begun.

### Policy Engine  
Enforces authorization rules at both issuance and use time. Validates all capability usage against governance policies before any action proceeds.

### Action Mediator  
Executes actions on behalf of agents after full validation. Production brokers must perform the real operation inside `execute_action_with_executor`; treating an `Allowed` result as permission to perform later I/O reintroduces a revocation race. File brokers must supply a safely resolved, descriptor-backed target in `ActionContext` and use no-follow/descriptor-relative operations.

### Audit Log  
Records an in-memory, hash-chained trace of mediated action outcomes. It is not durable or independently authenticated; production hosts must persist records and anchor or sign the head hash externally.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --features test-utils
```

## Run

```bash
cargo build --release
./target/release/zt-aas # Linux/macOS
.\target\release\zt-aas.exe # Windows
```

The packaged binary is the supervised AIGOS layer process: it emits the canonical startup line and remains alive until the supervisor terminates it.

## Integration

ZT-AAS is not a standalone OS containment service. Integrate `SandboxRuntime` into an OS-isolated supervisor and pass only brokered action requests to it.

## Design Principles

1. **Zero Trust** - No implicit trust. All actions must be proven through explicit capability presentation.
2. **Capability-Based Security** - Agents present tokens, not roles. Authority is scoped, granular, and revocable.
3. **Policy Enforcement** - Rules enforced at both issuance and use time. No deferred validation.
4. **Host-Enforced Containment** - The embedding supervisor removes ambient authority and makes the policy runtime the only external-access path.
5. **Auditability** - Mediated outcomes are hash-chained in memory; durable authenticated storage is an integration responsibility.

## Requirements

- Rust 1.82+
