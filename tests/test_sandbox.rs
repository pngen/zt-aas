use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

fn file_context(path: &str) -> ActionContext {
    ActionContext {
        resolved_target: Some(path.to_string()),
        ..ActionContext::default()
    }
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
        agent_id: "test-agent".to_string(),
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
    sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "network-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "read-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
        sandbox
            .execute_action_with_context(&agent, request, file_context("/tmp/test.txt"))
            .status,
        ActionStatus::Allowed
    );
}

#[test]
fn test_execute_denied_action() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let request = ActionRequest {
        capability_id: "nonexistent".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(&agent, request).status,
        ActionStatus::Denied
    );
}

#[test]
fn test_revoke_capability() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "revoke-cap".to_string(),
        agent_id: "test-agent".to_string(),
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

    let outcome = sandbox.execute_action(&agent, request);
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.error.unwrap().contains("revoked"));
}

#[test]
fn test_scope_enforcement() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "scope-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
    assert_eq!(
        sandbox
            .execute_action_with_context(&agent, valid, file_context("/tmp/test.txt"))
            .status,
        ActionStatus::Allowed
    );

    // Wrong target
    let bad_target = ActionRequest {
        capability_id: "scope-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/wrong.txt".to_string(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox.execute_action(&agent, bad_target).status,
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
        sandbox.execute_action(&agent, bad_action).status,
        ActionStatus::Denied
    );
}

#[test]
fn test_capability_expiration() {
    let ts = Arc::new(MockTimestampProvider::new(BASE_TS));
    let sandbox = make_sandbox_with_ts(ts.clone());
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "expiring-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
        sandbox
            .execute_action_with_context(&agent, request.clone(), file_context("/tmp/test.txt"),)
            .status,
        ActionStatus::Allowed
    );

    // Advance past expiration
    ts.advance(61);

    let outcome = sandbox.execute_action(&agent, request);
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.error.unwrap().contains("expired"));
}

#[test]
fn test_quarantine_behavior() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "quarantine-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    sandbox.issue_capability(cap).unwrap();
    sandbox.quarantine_agent("test-agent").unwrap();

    let request = ActionRequest {
        capability_id: "quarantine-cap".to_string(),
        agent_id: "test-agent".to_string(),
        action_type: ActionType::Read,
        target: "/tmp/test.txt".to_string(),
        timestamp: BASE_TS,
    };

    assert_eq!(
        sandbox.execute_action(&agent, request).status,
        ActionStatus::Quarantined
    );
}

#[test]
fn test_agent_active_status() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "active-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
        sandbox
            .execute_action_with_context(&agent, request.clone(), file_context("/tmp/test.txt"),)
            .status,
        ActionStatus::Allowed
    );

    sandbox.deactivate_agent("test-agent").unwrap();

    let outcome = sandbox.execute_action(&agent, request);
    assert_eq!(outcome.status, ActionStatus::Denied);
}

#[test]
fn test_capability_is_bound_to_its_grantee() {
    let sandbox = make_sandbox();
    let _alice = sandbox.register_agent("alice").unwrap();
    let mallory = sandbox.register_agent("mallory").unwrap();
    sandbox
        .issue_capability(Capability {
            id: "alice-read".into(),
            agent_id: "alice".into(),
            action_type: ActionType::Read,
            target: "/tmp/private.txt".into(),
            constraints: HashMap::new(),
            duration: None,
            issued_at: u64::MAX,
            revoked: false,
        })
        .unwrap();

    let outcome = sandbox.execute_action(
        &mallory,
        ActionRequest {
            capability_id: "alice-read".into(),
            agent_id: "alice".into(),
            action_type: ActionType::Read,
            target: "/tmp/private.txt".into(),
            timestamp: BASE_TS,
        },
    );
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.error.unwrap().contains("not granted"));
}

#[test]
fn test_file_policy_covers_read_write_and_file_actions() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    for (index, action_type) in [ActionType::Read, ActionType::Write, ActionType::File]
        .into_iter()
        .enumerate()
    {
        let result = sandbox.issue_capability(Capability {
            id: format!("outside-{index}"),
            agent_id: "test-agent".into(),
            action_type,
            target: "/etc/shadow".into(),
            constraints: HashMap::new(),
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        });
        assert!(matches!(result, Err(SandboxError::InvalidCapability(_))));
    }

    sandbox
        .issue_capability(Capability {
            id: "file-access".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::File,
            target: "/tmp/allowed.txt".into(),
            constraints: HashMap::new(),
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        })
        .unwrap();
    let request = ActionRequest {
        capability_id: "file-access".into(),
        agent_id: "forged".into(),
        action_type: ActionType::File,
        target: "/tmp/allowed.txt".into(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox
            .execute_action_with_context(&agent, request.clone(), file_context("/etc/shadow"))
            .status,
        ActionStatus::Denied
    );
    assert_eq!(
        sandbox
            .execute_action_with_context(&agent, request, file_context("/tmp/allowed.txt"))
            .status,
        ActionStatus::Allowed
    );
}

#[test]
fn test_network_allowlist_rejects_url_suffix_spoofing() {
    let sandbox = make_sandbox();
    sandbox.register_agent("test-agent").unwrap();
    let spoofed = Capability {
        id: "spoofed-network".into(),
        agent_id: "test-agent".into(),
        action_type: ActionType::Network,
        target: "https://evil.invalid/.api.example.com".into(),
        constraints: HashMap::new(),
        duration: None,
        issued_at: BASE_TS,
        revoked: false,
    };
    assert!(matches!(
        sandbox.issue_capability(spoofed),
        Err(SandboxError::InvalidCapability(_))
    ));

    sandbox
        .issue_capability(Capability {
            id: "allowed-network".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Network,
            target: "service.api.example.com".into(),
            constraints: HashMap::new(),
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        })
        .unwrap();
}

#[test]
fn test_constraints_are_typed_and_enforced_fail_closed() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let mut malformed = HashMap::new();
    malformed.insert("max_size".into(), serde_json::json!("10"));
    assert!(matches!(
        sandbox.issue_capability(Capability {
            id: "malformed".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Write,
            target: "/tmp/output.txt".into(),
            constraints: malformed,
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        }),
        Err(SandboxError::InvalidConstraint(_))
    ));

    let mut rate = HashMap::new();
    rate.insert("rate_limit".into(), serde_json::json!(1));
    sandbox
        .issue_capability(Capability {
            id: "one-call".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Call,
            target: "tool".into(),
            constraints: rate,
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        })
        .unwrap();
    let call = ActionRequest {
        capability_id: "one-call".into(),
        agent_id: "test-agent".into(),
        action_type: ActionType::Call,
        target: "tool".into(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox.execute_action(&agent, call.clone()).status,
        ActionStatus::Allowed
    );
    assert_eq!(
        sandbox.execute_action(&agent, call).status,
        ActionStatus::Denied
    );

    let mut constrained = HashMap::new();
    constrained.insert("max_size".into(), serde_json::json!(10));
    constrained.insert("allowed_methods".into(), serde_json::json!(["PUT"]));
    sandbox
        .issue_capability(Capability {
            id: "constrained-write".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Write,
            target: "/tmp/output.txt".into(),
            constraints: constrained,
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        })
        .unwrap();
    let write = ActionRequest {
        capability_id: "constrained-write".into(),
        agent_id: "test-agent".into(),
        action_type: ActionType::Write,
        target: "/tmp/output.txt".into(),
        timestamp: BASE_TS,
    };
    assert_eq!(
        sandbox.execute_action(&agent, write.clone()).status,
        ActionStatus::Denied
    );
    assert_eq!(
        sandbox
            .execute_action_with_context(
                &agent,
                write.clone(),
                ActionContext {
                    payload_size: Some(11),
                    method: Some("PUT".into()),
                    resolved_target: Some("/tmp/output.txt".into()),
                },
            )
            .status,
        ActionStatus::Denied
    );
    assert_eq!(
        sandbox
            .execute_action_with_context(
                &agent,
                write.clone(),
                ActionContext {
                    payload_size: Some(5),
                    method: Some("POST".into()),
                    resolved_target: Some("/tmp/output.txt".into()),
                },
            )
            .status,
        ActionStatus::Denied
    );
    assert_eq!(
        sandbox
            .execute_action_with_context(
                &agent,
                write.clone(),
                ActionContext {
                    payload_size: Some(5),
                    method: Some("put".into()),
                    resolved_target: Some("/tmp/output.txt".into()),
                },
            )
            .status,
        ActionStatus::Denied
    );
    assert_eq!(
        sandbox
            .execute_action_with_context(
                &agent,
                write,
                ActionContext {
                    payload_size: Some(5),
                    method: Some("PUT".into()),
                    resolved_target: Some("/tmp/output.txt".into()),
                },
            )
            .status,
        ActionStatus::Allowed
    );
    let trace = sandbox.get_audit_trace("test-agent");
    let audited = trace.last().unwrap();
    assert_eq!(audited.context.payload_size, Some(5));
    assert_eq!(audited.context.method.as_deref(), Some("PUT"));
}

#[test]
fn test_broker_executor_receives_trusted_identity_and_commits_in_runtime() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();
    sandbox
        .issue_capability(Capability {
            id: "brokered-call".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Call,
            target: "tool".into(),
            constraints: HashMap::new(),
            duration: None,
            issued_at: BASE_TS,
            revoked: false,
        })
        .unwrap();
    let executed = AtomicBool::new(false);
    let outcome = sandbox.execute_action_with_executor(
        &agent,
        ActionRequest {
            capability_id: "brokered-call".into(),
            agent_id: "forged-agent".into(),
            action_type: ActionType::Call,
            target: "tool".into(),
            timestamp: u64::MAX,
        },
        ActionContext::default(),
        |request, _context| {
            assert_eq!(request.agent_id, "test-agent");
            assert_eq!(request.timestamp, BASE_TS);
            executed.store(true, Ordering::SeqCst);
            Ok("committed".into())
        },
    );
    assert!(executed.load(Ordering::SeqCst));
    assert_eq!(outcome.status, ActionStatus::Allowed);
    assert_eq!(outcome.result.as_deref(), Some("committed"));
}

#[test]
fn test_runtime_controls_issuance_and_audit_time_and_exact_expiry() {
    let ts = Arc::new(MockTimestampProvider::new(BASE_TS));
    let sandbox = make_sandbox_with_ts(ts.clone());
    let agent = sandbox.register_agent("test-agent").unwrap();
    sandbox
        .issue_capability(Capability {
            id: "trusted-time".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Read,
            target: "/tmp/time.txt".into(),
            constraints: HashMap::new(),
            duration: Some(60),
            issued_at: u64::MAX,
            revoked: false,
        })
        .unwrap();
    let request = ActionRequest {
        capability_id: "trusted-time".into(),
        agent_id: "test-agent".into(),
        action_type: ActionType::Read,
        target: "/tmp/time.txt".into(),
        timestamp: u64::MAX,
    };
    assert_eq!(
        sandbox
            .execute_action_with_context(&agent, request.clone(), file_context("/tmp/time.txt"),)
            .status,
        ActionStatus::Allowed
    );
    assert_eq!(
        sandbox.get_audit_trace("test-agent")[0].request.timestamp,
        BASE_TS
    );

    ts.advance(60);
    assert_eq!(
        sandbox.execute_action(&agent, request).status,
        ActionStatus::Denied
    );

    assert!(matches!(
        sandbox.issue_capability(Capability {
            id: "overflowing".into(),
            agent_id: "test-agent".into(),
            action_type: ActionType::Call,
            target: "tool".into(),
            constraints: HashMap::new(),
            duration: Some(u64::MAX),
            issued_at: BASE_TS,
            revoked: false,
        }),
        Err(SandboxError::InvalidCapability(_))
    ));
}

#[test]
fn test_audit_chain_integrity() {
    let sandbox = make_sandbox();
    let agent = sandbox.register_agent("test-agent").unwrap();

    let cap = Capability {
        id: "audit-cap".to_string(),
        agent_id: "test-agent".to_string(),
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
        sandbox.execute_action_with_context(&agent, request, file_context("/tmp/test.txt"));
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
        context: ActionContext::default(),
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
        context: ActionContext::default(),
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
