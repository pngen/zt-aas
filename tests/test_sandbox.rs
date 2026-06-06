use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zt_aas::*;

const BASE_TS: u64 = 1_000_000;

struct MockTimestampProvider {
    current: AtomicU64,
}

impl MockTimestampProvider {
    fn new(initial: u64) -> Self {
        Self {
            current: AtomicU64::new(initial),
        }
    }

    fn advance(&self, seconds: u64) {
        self.current.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl TimestampProvider for MockTimestampProvider {
    fn now_unix_secs(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }
}

fn make_sandbox() -> SandboxRuntime<MockTimestampProvider> {
    let ts = Arc::new(MockTimestampProvider::new(BASE_TS));
    SandboxRuntime::with_config_and_timestamp(SandboxConfig::default(), ts)
}

fn make_sandbox_with_ts(ts: Arc<MockTimestampProvider>) -> SandboxRuntime<MockTimestampProvider> {
    SandboxRuntime::with_config_and_timestamp(SandboxConfig::default(), ts)
}

#[test]
fn test_register_agent() {
    let sandbox = make_sandbox();
    assert!(sandbox.register_agent("test-agent").is_ok());
    let err = sandbox.register_agent("test-agent").unwrap_err();
    assert!(matches!(err, SandboxError::AgentAlreadyRegistered(_)));
}

#[test]
fn test_issue_capability() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "test-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };

    assert!(sandbox.issue_capability(cap.clone()).is_ok());
    let err = sandbox.issue_capability(cap).unwrap_err();
    assert!(matches!(err, SandboxError::CapabilityAlreadyExists(_)));
}

#[test]
fn test_issue_capability_rejects_disallowed_network_target() {
    let sandbox = make_sandbox();

    let cap = Capability {
        id: "network-cap".to_string(),
        action_type: ActionType::Network,
        target: "evil.example.net".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };

    let err = sandbox.issue_capability(cap).unwrap_err();
    assert!(matches!(err, SandboxError::InvalidCapability(_)));
}

#[test]
fn test_execute_allowed_action() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "read-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    let request = ActionRequest {
        capability_id: "read-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(request).status,
        ActionStatus::Allowed
    );
}

#[test]
fn test_execute_denied_action() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let request = ActionRequest {
        capability_id: "nonexistent".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(sandbox.execute_action(request).status, ActionStatus::Denied);
}

#[test]
fn test_revoke_capability() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "revoke-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    assert!(sandbox.revoke_capability("revoke-cap").unwrap());
    assert!(!sandbox.revoke_capability("nonexistent").unwrap());

    let request = ActionRequest {
        capability_id: "revoke-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    let outcome = sandbox.execute_action(request);
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.error.unwrap().contains("revoked"));
}

#[test]
fn test_scope_enforcement() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "scope-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    // Valid request
    let valid = ActionRequest {
        capability_id: "scope-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };
    assert_eq!(sandbox.execute_action(valid).status, ActionStatus::Allowed);

    // Wrong target
    let bad_target = ActionRequest {
        capability_id: "scope-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/wrong.txt".to_string(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox.execute_action(bad_target).status,
        ActionStatus::Denied
    );

    // Wrong action type
    let bad_action = ActionRequest {
        capability_id: "scope-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Write,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox.execute_action(bad_action).status,
        ActionStatus::Denied
    );
}

#[test]
fn test_capability_expiration() {
    let ts = Arc::new(MockTimestampProvider::new(BASE_TS));
    let sandbox = make_sandbox_with_ts(ts.clone());
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "expiring-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: Some(60),
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    let request = ActionRequest {
        capability_id: "expiring-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(request.clone()).status,
        ActionStatus::Allowed
    );

    // Advance past expiration
    ts.advance(61);

    let outcome = sandbox.execute_action(request);
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.error.unwrap().contains("expired"));
}

#[test]
fn test_quarantine_behavior() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "quarantine-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();
    sandbox.quarantine_agent("test-agent");

    let request = ActionRequest {
        capability_id: "quarantine-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(request).status,
        ActionStatus::Quarantined
    );
}

#[test]
fn test_agent_active_status() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "active-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    let request = ActionRequest {
        capability_id: "active-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(request.clone()).status,
        ActionStatus::Allowed
    );

    sandbox.deactivate_agent("test-agent").unwrap();

    let outcome = sandbox.execute_action(request);
    assert_eq!(outcome.status, ActionStatus::Denied);
}

#[test]
fn test_audit_chain_integrity() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "audit-cap".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();

    for i in 0..5u64 {
        let request = ActionRequest {
            capability_id: "audit-cap".to_string(),
            agent_id: "test-agent".to_string(),
            action_type: ActionType::Read,
            target: "/tmp/test.txt".to_string(),
            timestamp: BASE_TS + i,
        };
        sandbox.execute_action(request);
    }

    let trace = sandbox.get_audit_trace("test-agent");
    assert_eq!(trace.len(), 5);

    for (i, entry) in trace.iter().enumerate() {
        assert_eq!(entry.sequence_number, i as u64);
        assert!(!entry.hash_chain.is_empty());
    }

    assert!(!sandbox.get_audit_head_hash().is_empty());
}

#[test]
fn test_audit_hash_includes_error_details() {
    let request = ActionRequest {
        capability_id: "cap-1".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    let mut first = ActionOutcome {
        request: request.clone(),
        status: ActionStatus::Denied,
        result: None,
        error: Some("first error".to_string()),
        side_effects: vec![],
        resource_usage: HashMap::new(),
        sequence_number: 0,
        hash_chain: String::new(),
    };
    let mut second = ActionOutcome {
        request,
        status: ActionStatus::Denied,
        result: None,
        error: Some("second error".to_string()),
        side_effects: vec![],
        resource_usage: HashMap::new(),
        sequence_number: 0,
        hash_chain: String::new(),
    };

    let mut first_log = AuditLog::new();
    first_log.log(&mut first);
    let mut second_log = AuditLog::new();
    second_log.log(&mut second);

    assert!(first_log.verify_chain());
    assert!(second_log.verify_chain());
    assert_ne!(first.hash_chain, second.hash_chain);
}
