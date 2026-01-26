use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError, Arc};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;

// --- Error Types ---

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Agent '{0}' already registered")]
    AgentAlreadyRegistered(String),
    #[error("Agent '{0}' not found or inactive")]
    AgentNotFound(String),
    #[error("Capability '{0}' already exists")]
    CapabilityAlreadyExists(String),
    #[error("Capability '{0}' not found")]
    CapabilityNotFound(String),
    #[error("Invalid constraint key: {0}")]
    InvalidConstraint(String),
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for SandboxError {
    fn from(e: PoisonError<MutexGuard<'_, T>>) -> Self {
        SandboxError::LockPoisoned(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SandboxError>;

// --- Timestamp Provider (for determinism) ---

pub trait TimestampProvider: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

#[derive(Debug, Clone, Default)]
pub struct SystemTimestampProvider;

impl TimestampProvider for SystemTimestampProvider {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }
}

// --- Core Types ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    Read,
    Write,
    Call,
    Emit,
    Mutate,
    Network,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Allowed,
    Denied,
    Quarantined,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub action_type: ActionType,
    pub target: String,
    pub constraints: HashMap<String, serde_json::Value>,
    pub duration: Option<u64>, // seconds
    pub issued_at: u64,        // Unix timestamp
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub capability_id: String,
    pub agent_id: String,
    pub action_type: ActionType,
    pub target: String,
    pub timestamp: u64, // Unix timestamp
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub request: ActionRequest,
    pub status: ActionStatus,
    pub result: Option<String>,
    pub error: Option<String>,
    pub side_effects: Vec<String>,
    pub resource_usage: HashMap<String, serde_json::Value>,
    pub sequence_number: u64,
    pub hash_chain: String,
}

// --- Sandbox Configuration ---

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub allowed_constraint_keys: Vec<String>,
    pub allowed_network_domains: Vec<String>,
    pub allowed_file_prefixes: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allowed_constraint_keys: vec![
                "max_size".into(), "rate_limit".into(), "allowed_methods".into()
            ],
            allowed_network_domains: vec![
                "api.example.com".into(), "data.example.com".into()
            ],
            allowed_file_prefixes: vec!["/tmp/".into(), "/data/".into()],
        }
    }
}

// --- Core Sandbox Runtime ---

pub struct SandboxRuntime<T: TimestampProvider = SystemTimestampProvider> {
    capabilities: Mutex<HashMap<String, Capability>>,
    config: SandboxConfig,
    audit_log: Mutex<AuditLog>,
    active_agents: Mutex<HashMap<String, bool>>,
    quarantined_agents: Mutex<HashMap<String, bool>>,
    timestamp_provider: Arc<T>,
}

impl SandboxRuntime<SystemTimestampProvider> {
    pub fn new() -> Self {
        Self::with_config_and_timestamp(SandboxConfig::default(), Arc::new(SystemTimestampProvider))
    }
}

impl<T: TimestampProvider> SandboxRuntime<T> {
    pub fn with_config_and_timestamp(config: SandboxConfig, timestamp_provider: Arc<T>) -> Self {
        Self {
            capabilities: Mutex::new(HashMap::new()),
            config,
            audit_log: Mutex::new(AuditLog::new()),
            active_agents: Mutex::new(HashMap::new()),
            quarantined_agents: Mutex::new(HashMap::new()),
            timestamp_provider,
        }
    }

    pub fn register_agent(&self, agent_id: &str) -> Result<()> {
        let mut agents = self.active_agents.lock()?;
        if agents.contains_key(agent_id) {
            return Err(SandboxError::AgentAlreadyRegistered(agent_id.to_string()));
        }
        agents.insert(agent_id.to_string(), true);
        Ok(())
    }

    pub fn issue_capability(&self, capability: Capability) -> Result<()> {
        let mut capabilities = self.capabilities.lock()?;
        if capabilities.contains_key(&capability.id) {
            return Err(SandboxError::CapabilityAlreadyExists(capability.id.clone()));
        }

        for key in capability.constraints.keys() {
            if !self.config.allowed_constraint_keys.contains(key) {
                return Err(SandboxError::InvalidConstraint(key.clone()));
            }
        }

        capabilities.insert(capability.id.clone(), capability);
        Ok(())
    }

    pub fn execute_action(&self, request: ActionRequest) -> ActionOutcome {
        // Acquire all locks with proper error handling
        let (capabilities, agents, quarantined) = match self.acquire_locks() {
            Ok(guards) => guards,
            Err(e) => return self.deny_action_internal(request, &e.to_string()),
        };

        if request.capability_id.is_empty() || request.agent_id.is_empty() || request.target.is_empty() {
            return self.deny_action(request, "Invalid request: missing required fields");
        }

        if quarantined.contains_key(&request.agent_id) {
            return self.quarantine_action(request, "Agent is quarantined");
        }

        match agents.get(&request.agent_id) {
            Some(true) => {}
            _ => return self.deny_action(request, "Agent not registered or inactive"),
        }

        let capability = match capabilities.get(&request.capability_id) {
            Some(cap) => cap.clone(),
            None => return self.deny_action(request, "Capability not found"),
        };

        // Drop locks before proceeding to validation
        drop(capabilities);
        drop(agents);
        drop(quarantined);

        self.execute_with_capability(request, capability)
    }

    fn execute_with_capability(&self, request: ActionRequest, capability: Capability) -> ActionOutcome {
        if capability.revoked {
            return self.deny_action(request, "Capability has been revoked");
        }

        if let Some(duration) = capability.duration {
            let current_time = self.timestamp_provider.now_unix_secs();
            if current_time > capability.issued_at.saturating_add(duration) {
                let _ = self.revoke_capability(&capability.id);
                return self.deny_action(request, "Capability expired");
            }
        }

        if !self.validate_scope(&request, &capability) {
            return self.deny_action(request, "Scope violation: action type or target mismatch");
        }

        let policy_result = self.validate_policy(&request, &capability);
        if let Err(reason) = policy_result {
            return self.deny_action(request, &format!("Policy violation: {}", reason));
        }

        let outcome = self.mediate_action(&request, &capability);
        self.log_outcome(outcome)
    }

    fn acquire_locks(&self) -> Result<(
        MutexGuard<'_, HashMap<String, Capability>>,
        MutexGuard<'_, HashMap<String, bool>>,
        MutexGuard<'_, HashMap<String, bool>>,
    )> {
        let capabilities = self.capabilities.lock()?;
        let agents = self.active_agents.lock()?;
        let quarantined = self.quarantined_agents.lock()?;
        Ok((capabilities, agents, quarantined))
    }
 
    fn log_outcome(&self, mut outcome: ActionOutcome) -> ActionOutcome {
        if let Ok(mut audit_log) = self.audit_log.lock() {
            audit_log.log(&mut outcome);
        }
        outcome
    }

    fn validate_scope(&self, request: &ActionRequest, capability: &Capability) -> bool {
        if request.action_type != capability.action_type {
            return false;
        }
        request.target == capability.target
    }

    fn deny_action(&self, request: ActionRequest, reason: &str) -> ActionOutcome {
        self.log_outcome(ActionOutcome {
            request,
            status: ActionStatus::Denied,
            result: None,
            error: Some(reason.to_string()),
            side_effects: vec![],
            resource_usage: HashMap::new(),
            sequence_number: 0,
            hash_chain: String::new(),
        })
    }

    fn deny_action_internal(&self, request: ActionRequest, reason: &str) -> ActionOutcome {
        ActionOutcome {
            request,
            status: ActionStatus::Denied,
            result: None,
            error: Some(reason.to_string()),
            side_effects: vec![],
            resource_usage: HashMap::new(),
            sequence_number: 0,
            hash_chain: String::new(),
        }
    }

    fn quarantine_action(&self, request: ActionRequest, reason: &str) -> ActionOutcome {
        self.log_outcome(ActionOutcome {
            request,
            status: ActionStatus::Quarantined,
            result: None,
            error: Some(reason.to_string()),
            side_effects: vec![],
            resource_usage: HashMap::new(),
            sequence_number: 0,
            hash_chain: String::new(),
        })
    }

    pub fn revoke_capability(&self, capability_id: &str) -> Result<bool> {
        let mut capabilities = self.capabilities.lock()?;
        if let Some(cap) = capabilities.get_mut(capability_id) {
            cap.revoked = true;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn quarantine_agent(&self, agent_id: &str) {
        if let Ok(mut quarantined) = self.quarantined_agents.lock() {
            quarantined.insert(agent_id.to_string(), true);
        }
    }

    pub fn deactivate_agent(&self, agent_id: &str) -> Result<bool> {
        let mut agents = self.active_agents.lock()?;
        if let Some(active) = agents.get_mut(agent_id) {
            *active = false;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn get_audit_trace(&self, agent_id: &str) -> Vec<ActionOutcome> {
        self.audit_log.lock()
            .map(|log| log.get_trace(agent_id).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_audit_head_hash(&self) -> String {
        self.audit_log.lock()
            .map(|log| log.get_head_hash())
            .unwrap_or_default()
    }

    // --- Policy Validation ---

    fn validate_policy(&self, request: &ActionRequest, capability: &Capability) -> std::result::Result<(), String> {
        if capability.action_type == ActionType::Network {
            if !self.is_network_allowed(&capability.target) {
                return Err("Network access not permitted".into());
            }
        }

        if capability.action_type == ActionType::File {
            if !self.is_file_access_allowed(&capability.target) {
                return Err("File access not permitted".into());
            }
        }

        if let Some(max_size) = capability.constraints.get("max_size") {
            if let Some(size) = max_size.as_u64() {
                if request.action_type == ActionType::Write && (request.target.len() as u64) > size {
                    return Err("Write exceeds size limit".into());
                }
            }
        }

        Ok(())
    }

    fn is_network_allowed(&self, domain: &str) -> bool {
        for allowed in &self.config.allowed_network_domains {
            if domain == allowed || domain.ends_with(&format!(".{}", allowed)) {
                return true;
            }
        }
        false
    }

    fn is_file_access_allowed(&self, path: &str) -> bool {
        // Use lexical normalization to avoid filesystem access
        let normalized = Self::normalize_path_lexical(path);
        for prefix in &self.config.allowed_file_prefixes {
            if normalized.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    fn normalize_path_lexical(path: &str) -> String {
        let mut parts: Vec<&str> = vec![];
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => { parts.pop(); }
                _ => parts.push(part),
            }
        }
        if path.starts_with('/') {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        }
    }


    // --- Action Mediation ---

    fn mediate_action(&self, request: &ActionRequest, _capability: &Capability) -> ActionOutcome {
        let (status, result, error) = match request.action_type {
            ActionType::Read => (ActionStatus::Allowed, Some(format!("Content of {}", request.target)), None),
            ActionType::Write => (ActionStatus::Allowed, Some(format!("Wrote to {}", request.target)), None),
            ActionType::Call => (ActionStatus::Allowed, Some(format!("Called tool {}", request.target)), None),
            ActionType::Network => (ActionStatus::Allowed, Some(format!("Made request to {}", request.target)), None),
            _ => (ActionStatus::Denied, None, Some("Action type not implemented".to_string())),
        };

        ActionOutcome {
            request: request.clone(),
            status,
            result,
            error,
            side_effects: if status == ActionStatus::Allowed {
                vec![format!("Performed {:?} on {}", request.action_type, request.target)]
            } else {
                vec![]
            },
            resource_usage: if status == ActionStatus::Allowed {
                [
                    ("cpu".to_string(), serde_json::json!(0.1)),
                    ("memory".to_string(), serde_json::json!(1024)),
                ].into_iter().collect()
            } else {
                HashMap::new()
            },
            sequence_number: 0,
            hash_chain: String::new(),
        }
    }
}

impl Default for SandboxRuntime<SystemTimestampProvider> {
    fn default() -> Self {
        Self::new()
    }
}

// --- Audit Log ---

#[derive(Debug, Clone)]
pub struct AuditLog {
    entries: Vec<ActionOutcome>,
    sequence_counter: u64,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: vec![],
            sequence_counter: 0,
        }
    }

    pub fn log(&mut self, outcome: &mut ActionOutcome) {
        outcome.sequence_number = self.sequence_counter;
        self.sequence_counter += 1;

        let prev_hash = self.entries.last()
            .map(|e| e.hash_chain.as_str())
            .unwrap_or("");

        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(outcome.sequence_number.to_le_bytes());
        hasher.update(outcome.request.agent_id.as_bytes());
        hasher.update(format!("{:?}", outcome.request.action_type).as_bytes());
        hasher.update(outcome.request.target.as_bytes());
        hasher.update(format!("{:?}", outcome.status).as_bytes());
        hasher.update(outcome.request.timestamp.to_le_bytes());

        outcome.hash_chain = format!("{:x}", hasher.finalize());
        self.entries.push(outcome.clone());
    }

    pub fn get_trace(&self, agent_id: &str) -> Vec<&ActionOutcome> {
        self.entries.iter().filter(|e| e.request.agent_id == agent_id).collect()
    }

    pub fn get_head_hash(&self) -> String {
        self.entries.last().map(|e| e.hash_chain.clone()).unwrap_or_default()
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = String::new();
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.sequence_number != i as u64 {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(entry.sequence_number.to_le_bytes());
            hasher.update(entry.request.agent_id.as_bytes());
            hasher.update(format!("{:?}", entry.request.action_type).as_bytes());
            hasher.update(entry.request.target.as_bytes());
            hasher.update(format!("{:?}", entry.status).as_bytes());
            hasher.update(entry.request.timestamp.to_le_bytes());
            let expected = format!("{:x}", hasher.finalize());
            if entry.hash_chain != expected {
                return false;
            }
            prev_hash = entry.hash_chain.clone();
        }
        true
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::Read => write!(f, "read"),
            ActionType::Write => write!(f, "write"),
            ActionType::Call => write!(f, "call"),
            ActionType::Emit => write!(f, "emit"),
            ActionType::Mutate => write!(f, "mutate"),
            ActionType::Network => write!(f, "network"),
            ActionType::File => write!(f, "file"),
        }
    }
}

impl std::fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionStatus::Allowed => write!(f, "allowed"),
            ActionStatus::Denied => write!(f, "denied"),
            ActionStatus::Quarantined => write!(f, "quarantined"),
            ActionStatus::Terminated => write!(f, "terminated"),
        }
    }
}

// --- Test Helpers ---
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub struct MockTimestampProvider {
        current: AtomicU64,
    }

    impl MockTimestampProvider {
        pub fn new(initial: u64) -> Self {
            Self { current: AtomicU64::new(initial) }
        }

        pub fn advance(&self, seconds: u64) {
            self.current.fetch_add(seconds, Ordering::SeqCst);
        }
    }

    impl TimestampProvider for MockTimestampProvider {
        fn now_unix_secs(&self) -> u64 {
            self.current.load(Ordering::SeqCst)
        }
    }
}
