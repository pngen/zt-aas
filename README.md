# Zero-Trust Autonomous Agent Sandbox (ZT-AAS)

A containment and governance system that enforces capability-based security for autonomous agents, ensuring no action can occur without explicit authorization.

## Overview

ZT-AAS is a zero-trust framework designed to contain and govern autonomous or semi-autonomous agents. It operates on the principle that all agents are untrusted, regardless of origin or intent. Every agent interaction must be explicitly authorized, policy-validated, and auditable.

The system enforces strict capability-based security where agents present tokens for actions rather than asking permission. All external interactions are mediated through a secure runtime environment that logs every action for forensic analysis.

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

### Sandbox Runtime  
Mediates all agent interactions with external systems. No direct access to external resources is permitted; all communication flows through the runtime's controlled execution boundary.

### Capability System  
Capabilities are first-class objects defining what agents can do. They are explicitly granted, time-bounded, constrainable, and revocable mid-execution. No transitive authority or permission inheritance.

### Policy Engine  
Enforces authorization rules at both issuance and use time. Validates all capability usage against governance policies before any action proceeds.

### Action Mediator  
Executes actions on behalf of agents after full validation. Serves as the sole bridge between the sandboxed agent and external resources.

### Audit Log  
Records a complete, tamper-evident execution trace of all agent activities for compliance and forensic analysis. All interactions are logged and replayable.

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
./zt-aas # Linux/macOS

.\zt-aas.exe # Windows
```

## Design Principles

1. **Zero Trust** - No implicit trust. All actions must be proven through explicit capability presentation.
2. **Capability-Based Security** - Agents present tokens, not roles. Authority is scoped, granular, and revocable.
3. **Policy Enforcement** - Rules enforced at both issuance and use time. No deferred validation.
4. **Containment** - No direct access to external systems. The sandbox runtime mediates all interactions.
5. **Auditability** - Complete trace of all agent activities. Tamper-evident, replayable logs.

## Requirements

- Rust 1.56+