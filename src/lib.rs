use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
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
    #[error("Invalid capability: {0}")]
    InvalidCapability(String),
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

static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_TARGET_BYTES: usize = 4096;
const MAX_METHOD_BYTES: usize = 64;
const MAX_ALLOWED_METHODS: usize = 64;
const MAX_AUDIT_ENTRIES: usize = 100_000;

// --- Timestamp Provider (for determinism) ---

pub trait TimestampProvider: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

#[derive(Debug, Clone, Default)]
pub struct SystemTimestampProvider;

impl TimestampProvider for SystemTimestampProvider {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
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
    /// Agent that is authorized to present this capability.
    pub agent_id: String,
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

/// Host-observed action metadata required to enforce capability constraints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionContext {
    /// Size of the request or response body governed by `max_size`.
    pub payload_size: Option<u64>,
    /// Method or operation name governed by `allowed_methods`.
    pub method: Option<String>,
    /// Host-resolved canonical path for file-like operations.
    pub resolved_target: Option<String>,
}

/// Opaque proof that a host registered an agent with a particular runtime.
#[derive(Debug, Clone)]
pub struct AgentHandle {
    agent_id: String,
    runtime_id: u64,
}

impl AgentHandle {
    /// Returns the registered agent identifier represented by this handle.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub request: ActionRequest,
    /// Host-observed metadata used for policy evaluation.
    #[serde(default)]
    pub context: ActionContext,
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
                "max_size".into(),
                "rate_limit".into(),
                "allowed_methods".into(),
            ],
            allowed_network_domains: vec!["api.example.com".into(), "data.example.com".into()],
            allowed_file_prefixes: vec!["/tmp/".into(), "/data/".into()],
        }
    }
}

// --- Core Sandbox Runtime ---

type AuthorizationGuards<'a> = (
    MutexGuard<'a, HashMap<String, Capability>>,
    MutexGuard<'a, HashMap<String, bool>>,
    MutexGuard<'a, HashMap<String, bool>>,
    MutexGuard<'a, AuditLog>,
);

pub struct SandboxRuntime<T: TimestampProvider = SystemTimestampProvider> {
    runtime_id: u64,
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
            runtime_id: NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed),
            capabilities: Mutex::new(HashMap::new()),
            config,
            audit_log: Mutex::new(AuditLog::new()),
            active_agents: Mutex::new(HashMap::new()),
            quarantined_agents: Mutex::new(HashMap::new()),
            timestamp_provider,
        }
    }

    pub fn register_agent(&self, agent_id: &str) -> Result<AgentHandle> {
        if agent_id.trim().is_empty() || agent_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(SandboxError::InvalidCapability(
                "agent ID is required and must not exceed 256 bytes".into(),
            ));
        }
        let mut agents = self.active_agents.lock()?;
        if agents.contains_key(agent_id) {
            return Err(SandboxError::AgentAlreadyRegistered(agent_id.to_string()));
        }
        agents.insert(agent_id.to_string(), true);
        Ok(AgentHandle {
            agent_id: agent_id.to_string(),
            runtime_id: self.runtime_id,
        })
    }

    pub fn issue_capability(&self, mut capability: Capability) -> Result<()> {
        if capability.id.trim().is_empty() || capability.id.len() > MAX_IDENTIFIER_BYTES {
            return Err(SandboxError::InvalidCapability(
                "capability ID is required and must not exceed 256 bytes".into(),
            ));
        }
        if capability.agent_id.trim().is_empty() || capability.agent_id.len() > MAX_IDENTIFIER_BYTES
        {
            return Err(SandboxError::InvalidCapability(
                "capability agent ID is required".into(),
            ));
        }
        if capability.target.trim().is_empty() || capability.target.len() > MAX_TARGET_BYTES {
            return Err(SandboxError::InvalidCapability(
                "capability target is required and must not exceed 4096 bytes".into(),
            ));
        }
        if capability.revoked {
            return Err(SandboxError::InvalidCapability(
                "cannot issue a revoked capability".into(),
            ));
        }

        self.validate_constraints(&capability)?;

        let current_time = self.timestamp_provider.now_unix_secs();
        if let Some(duration) = capability.duration {
            if duration == 0 || current_time.checked_add(duration).is_none() {
                return Err(SandboxError::InvalidCapability(
                    "capability duration must be positive and must not overflow".into(),
                ));
            }
        }
        capability.issued_at = current_time;

        match capability.action_type {
            ActionType::Network if !self.is_network_allowed(&capability.target) => {
                return Err(SandboxError::InvalidCapability(format!(
                    "network target '{}' is not permitted",
                    capability.target
                )));
            }
            ActionType::Read | ActionType::Write | ActionType::File
                if !self.is_file_access_allowed(&capability.target) =>
            {
                return Err(SandboxError::InvalidCapability(format!(
                    "file target '{}' is not permitted",
                    capability.target
                )));
            }
            _ => {}
        }

        // Keep the same lock order as action authorization.
        let mut capabilities = self.capabilities.lock()?;
        let agents = self.active_agents.lock()?;
        let quarantined = self.quarantined_agents.lock()?;
        if capabilities.contains_key(&capability.id) {
            return Err(SandboxError::CapabilityAlreadyExists(capability.id.clone()));
        }
        if agents.get(&capability.agent_id) != Some(&true) {
            return Err(SandboxError::AgentNotFound(capability.agent_id.clone()));
        }
        if quarantined.contains_key(&capability.agent_id) {
            return Err(SandboxError::InvalidCapability(format!(
                "agent '{}' is quarantined",
                capability.agent_id
            )));
        }
        capabilities.insert(capability.id.clone(), capability);
        Ok(())
    }

    pub fn execute_action(&self, agent: &AgentHandle, request: ActionRequest) -> ActionOutcome {
        self.execute_action_with_context(agent, request, ActionContext::default())
    }

    /// Executes an action with host-observed metadata used for constraint checks.
    pub fn execute_action_with_context(
        &self,
        agent: &AgentHandle,
        request: ActionRequest,
        context: ActionContext,
    ) -> ActionOutcome {
        self.execute_action_with_executor(agent, request, context, |request, _context| {
            Self::simulate_action(request)
        })
    }

    /// Authorizes and executes a broker operation while the authorization lease
    /// and audit reservation remain held. Production hosts should perform the
    /// real external operation inside `executor`, not after this method returns.
    pub fn execute_action_with_executor<F>(
        &self,
        agent: &AgentHandle,
        mut request: ActionRequest,
        mut context: ActionContext,
        executor: F,
    ) -> ActionOutcome
    where
        F: FnOnce(&ActionRequest, &ActionContext) -> std::result::Result<String, String>,
    {
        request.agent_id = agent.agent_id.clone();
        if agent.runtime_id != self.runtime_id {
            request.timestamp = self.timestamp_provider.now_unix_secs();
            return self.deny_action_internal(
                request,
                &context,
                "Agent handle belongs to a different runtime",
            );
        }
        let (mut capabilities, agents, quarantined, mut audit_log) = match self.acquire_locks() {
            Ok(guards) => guards,
            Err(e) => {
                request.timestamp = self.timestamp_provider.now_unix_secs();
                return self.deny_action_internal(request, &context, &e.to_string());
            }
        };
        request.timestamp = self.timestamp_provider.now_unix_secs();

        let oversized = request.capability_id.len() > MAX_IDENTIFIER_BYTES
            || request.target.len() > MAX_TARGET_BYTES
            || context
                .method
                .as_ref()
                .is_some_and(|method| method.len() > MAX_METHOD_BYTES)
            || context
                .resolved_target
                .as_ref()
                .is_some_and(|target| target.len() > MAX_TARGET_BYTES);
        if oversized {
            if request.capability_id.len() > MAX_IDENTIFIER_BYTES {
                request.capability_id = "<oversized>".into();
            }
            if request.target.len() > MAX_TARGET_BYTES {
                request.target = "<oversized>".into();
            }
            if context
                .method
                .as_ref()
                .is_some_and(|method| method.len() > MAX_METHOD_BYTES)
            {
                context.method = Some("<oversized>".into());
            }
            if context
                .resolved_target
                .as_ref()
                .is_some_and(|target| target.len() > MAX_TARGET_BYTES)
            {
                context.resolved_target = Some("<oversized>".into());
            }
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, "Request exceeds size limits"),
                &context,
            );
        }
        if audit_log.is_full() {
            let mut outcome = Self::denied_outcome(request, "Audit capacity exhausted");
            outcome.context = context;
            return outcome;
        }

        if request.capability_id.is_empty()
            || request.agent_id.is_empty()
            || request.target.is_empty()
        {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, "Invalid request: missing required fields"),
                &context,
            );
        }

        if quarantined.contains_key(&request.agent_id) {
            return Self::record_outcome(
                &mut audit_log,
                Self::quarantined_outcome(request, "Agent is quarantined"),
                &context,
            );
        }

        match agents.get(&request.agent_id) {
            Some(true) => {}
            _ => {
                return Self::record_outcome(
                    &mut audit_log,
                    Self::denied_outcome(request, "Agent not registered or inactive"),
                    &context,
                )
            }
        }

        let capability = match capabilities.get_mut(&request.capability_id) {
            Some(capability) => capability,
            None => {
                return Self::record_outcome(
                    &mut audit_log,
                    Self::denied_outcome(request, "Capability not found"),
                    &context,
                )
            }
        };

        if capability.agent_id != request.agent_id {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, "Capability is not granted to this agent"),
                &context,
            );
        }
        if capability.revoked {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, "Capability has been revoked"),
                &context,
            );
        }
        if request.timestamp < capability.issued_at {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(
                    request,
                    "Runtime clock regressed before capability issuance",
                ),
                &context,
            );
        }

        if let Some(duration) = capability.duration {
            let expires_at = capability.issued_at.checked_add(duration);
            if expires_at.is_none_or(|expires_at| request.timestamp >= expires_at) {
                capability.revoked = true;
                return Self::record_outcome(
                    &mut audit_log,
                    Self::denied_outcome(request, "Capability expired"),
                    &context,
                );
            }
        }

        if !self.validate_scope(&request, capability) {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, "Scope violation: action type or target mismatch"),
                &context,
            );
        }

        if let Err(reason) = self.validate_policy(&request, capability, &context, &audit_log) {
            return Self::record_outcome(
                &mut audit_log,
                Self::denied_outcome(request, &format!("Policy violation: {}", reason)),
                &context,
            );
        }

        let outcome = self.mediate_action(&request, &context, executor);
        Self::record_outcome(&mut audit_log, outcome, &context)
    }

    fn acquire_locks(&self) -> Result<AuthorizationGuards<'_>> {
        let capabilities = self.capabilities.lock()?;
        let agents = self.active_agents.lock()?;
        let quarantined = self.quarantined_agents.lock()?;
        let audit_log = self.audit_log.lock()?;
        Ok((capabilities, agents, quarantined, audit_log))
    }

    fn record_outcome(
        audit_log: &mut AuditLog,
        mut outcome: ActionOutcome,
        context: &ActionContext,
    ) -> ActionOutcome {
        outcome.context = context.clone();
        audit_log.log(&mut outcome);
        outcome
    }

    fn validate_scope(&self, request: &ActionRequest, capability: &Capability) -> bool {
        if request.action_type != capability.action_type {
            return false;
        }
        request.target == capability.target
    }

    fn denied_outcome(request: ActionRequest, reason: &str) -> ActionOutcome {
        ActionOutcome {
            request,
            context: ActionContext::default(),
            status: ActionStatus::Denied,
            result: None,
            error: Some(reason.to_string()),
            side_effects: vec![],
            resource_usage: HashMap::new(),
            sequence_number: 0,
            hash_chain: String::new(),
        }
    }

    fn deny_action_internal(
        &self,
        request: ActionRequest,
        context: &ActionContext,
        reason: &str,
    ) -> ActionOutcome {
        let mut outcome = Self::denied_outcome(request, reason);
        outcome.context = context.clone();
        if let Ok(mut audit_log) = self.audit_log.lock() {
            audit_log.log(&mut outcome);
        }
        outcome
    }

    fn quarantined_outcome(request: ActionRequest, reason: &str) -> ActionOutcome {
        ActionOutcome {
            request,
            context: ActionContext::default(),
            status: ActionStatus::Quarantined,
            result: None,
            error: Some(reason.to_string()),
            side_effects: vec![],
            resource_usage: HashMap::new(),
            sequence_number: 0,
            hash_chain: String::new(),
        }
    }

    pub fn revoke_capability(&self, capability_id: &str) -> Result<bool> {
        let mut capabilities = self.capabilities.lock()?;
        if let Some(cap) = capabilities.get_mut(capability_id) {
            cap.revoked = true;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn quarantine_agent(&self, agent_id: &str) -> Result<()> {
        let mut quarantined = self.quarantined_agents.lock()?;
        quarantined.insert(agent_id.to_string(), true);
        Ok(())
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
        self.audit_log
            .lock()
            .map(|log| log.get_trace(agent_id).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_audit_head_hash(&self) -> String {
        self.audit_log
            .lock()
            .map(|log| log.get_head_hash())
            .unwrap_or_default()
    }

    // --- Policy Validation ---

    fn validate_constraints(&self, capability: &Capability) -> Result<()> {
        for (key, value) in &capability.constraints {
            if !self.config.allowed_constraint_keys.contains(key) {
                return Err(SandboxError::InvalidConstraint(key.clone()));
            }
            match key.as_str() {
                "max_size" | "rate_limit" if value.as_u64().is_none() => {
                    return Err(SandboxError::InvalidConstraint(format!(
                        "{} must be a non-negative integer",
                        key
                    )));
                }
                "allowed_methods" => {
                    let Some(methods) = value.as_array() else {
                        return Err(SandboxError::InvalidConstraint(
                            "allowed_methods must be an array".into(),
                        ));
                    };
                    if methods.is_empty()
                        || methods.len() > MAX_ALLOWED_METHODS
                        || methods.iter().any(|method| {
                            method.as_str().is_none_or(|method| {
                                method.trim().is_empty() || method.len() > MAX_METHOD_BYTES
                            })
                        })
                    {
                        return Err(SandboxError::InvalidConstraint(
                            "allowed_methods must contain non-empty strings".into(),
                        ));
                    }
                }
                "max_size" | "rate_limit" => {}
                _ => return Err(SandboxError::InvalidConstraint(key.clone())),
            }
        }
        Ok(())
    }

    fn validate_policy(
        &self,
        _request: &ActionRequest,
        capability: &Capability,
        context: &ActionContext,
        audit_log: &AuditLog,
    ) -> std::result::Result<(), String> {
        if capability.action_type == ActionType::Network
            && !self.is_network_allowed(&capability.target)
        {
            return Err("Network access not permitted".into());
        }

        if matches!(
            capability.action_type,
            ActionType::Read | ActionType::Write | ActionType::File
        ) {
            if !self.is_file_access_allowed(&capability.target) {
                return Err("File access not permitted".into());
            }
            let resolved_target = context
                .resolved_target
                .as_deref()
                .ok_or_else(|| "Host-resolved file target is required".to_string())?;
            if !self.is_file_access_allowed(resolved_target) {
                return Err("Resolved file target is not permitted".into());
            }
        }

        if let Some(max_size) = capability.constraints.get("max_size") {
            let maximum = max_size
                .as_u64()
                .ok_or_else(|| "Invalid max_size constraint".to_string())?;
            let actual = context
                .payload_size
                .ok_or_else(|| "Payload size is required".to_string())?;
            if actual > maximum {
                return Err("Payload exceeds size limit".into());
            }
        }

        if let Some(rate_limit) = capability.constraints.get("rate_limit") {
            let maximum = rate_limit
                .as_u64()
                .ok_or_else(|| "Invalid rate_limit constraint".to_string())?;
            if audit_log.allowed_uses(&capability.id) >= maximum {
                return Err("Capability rate limit exceeded".into());
            }
        }

        if let Some(allowed_methods) = capability.constraints.get("allowed_methods") {
            let method = context
                .method
                .as_deref()
                .filter(|method| !method.trim().is_empty())
                .ok_or_else(|| "Action method is required".to_string())?;
            let methods = allowed_methods
                .as_array()
                .ok_or_else(|| "Invalid allowed_methods constraint".to_string())?;
            if !methods
                .iter()
                .any(|allowed| allowed.as_str().is_some_and(|allowed| allowed == method))
            {
                return Err(format!("Method '{}' is not allowed", method));
            }
        }

        Ok(())
    }

    fn is_network_allowed(&self, domain: &str) -> bool {
        let Some(domain) = Self::normalize_domain(domain) else {
            return false;
        };
        self.config.allowed_network_domains.iter().any(|allowed| {
            let Some(allowed) = Self::normalize_domain(allowed) else {
                return false;
            };
            domain == allowed
                || domain
                    .strip_suffix(&format!(".{}", allowed))
                    .is_some_and(|prefix| !prefix.is_empty())
        })
    }

    fn normalize_domain(domain: &str) -> Option<String> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty()
            || domain.len() > 253
            || !domain.is_ascii()
            || domain.bytes().any(|byte| {
                matches!(byte, b'/' | b'\\' | b':' | b'@' | b'?' | b'#')
                    || byte.is_ascii_whitespace()
            })
        {
            return None;
        }
        if domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return None;
        }
        Some(domain)
    }

    fn is_file_access_allowed(&self, path: &str) -> bool {
        let Some(normalized) = Self::normalize_path_lexical(path) else {
            return false;
        };
        self.config.allowed_file_prefixes.iter().any(|prefix| {
            let Some(prefix) = Self::normalize_path_lexical(prefix) else {
                return false;
            };
            if prefix == "/" {
                return normalized.starts_with('/');
            }
            let prefix = prefix.trim_end_matches('/');
            normalized == prefix
                || normalized
                    .strip_prefix(prefix)
                    .is_some_and(|remainder| remainder.starts_with('/'))
        })
    }

    fn normalize_path_lexical(path: &str) -> Option<String> {
        if path.trim().is_empty() || path.contains(['\0', '\\']) {
            return None;
        }
        let mut parts: Vec<&str> = vec![];
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                _ => parts.push(part),
            }
        }
        let normalized = if path.starts_with('/') {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        };
        Some(normalized)
    }

    // --- Action Mediation ---

    fn mediate_action<F>(
        &self,
        request: &ActionRequest,
        context: &ActionContext,
        executor: F,
    ) -> ActionOutcome
    where
        F: FnOnce(&ActionRequest, &ActionContext) -> std::result::Result<String, String>,
    {
        let execution =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| executor(request, context)));
        let (status, result, error) = match execution {
            Ok(Ok(result)) => (ActionStatus::Allowed, Some(result), None),
            Ok(Err(error)) => (ActionStatus::Denied, None, Some(error)),
            Err(_) => (
                ActionStatus::Denied,
                None,
                Some("Broker executor panicked".to_string()),
            ),
        };

        ActionOutcome {
            request: request.clone(),
            context: ActionContext::default(),
            status,
            result,
            error,
            side_effects: if status == ActionStatus::Allowed {
                vec![format!(
                    "Performed {:?} on {}",
                    request.action_type, request.target
                )]
            } else {
                vec![]
            },
            resource_usage: if status == ActionStatus::Allowed {
                [
                    ("cpu".to_string(), serde_json::json!(0.1)),
                    ("memory".to_string(), serde_json::json!(1024)),
                ]
                .into_iter()
                .collect()
            } else {
                HashMap::new()
            },
            sequence_number: 0,
            hash_chain: String::new(),
        }
    }

    fn simulate_action(request: &ActionRequest) -> std::result::Result<String, String> {
        match request.action_type {
            ActionType::Read => Ok(format!("Content of {}", request.target)),
            ActionType::Write => Ok(format!("Wrote to {}", request.target)),
            ActionType::Call => Ok(format!("Called tool {}", request.target)),
            ActionType::Network => Ok(format!("Made request to {}", request.target)),
            ActionType::File => Ok(format!("Accessed file {}", request.target)),
            _ => Err("Action type not implemented".to_string()),
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

    fn is_full(&self) -> bool {
        self.entries.len() >= MAX_AUDIT_ENTRIES
    }

    pub fn log(&mut self, outcome: &mut ActionOutcome) {
        if self.is_full() {
            outcome.status = ActionStatus::Denied;
            outcome.result = None;
            outcome.error = Some("Audit capacity exhausted".into());
            outcome.side_effects.clear();
            outcome.resource_usage.clear();
            outcome.sequence_number = self.sequence_counter;
            outcome.hash_chain.clear();
            return;
        }
        outcome.sequence_number = self.sequence_counter;
        self.sequence_counter += 1;

        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash_chain.as_str())
            .unwrap_or("");

        outcome.hash_chain = Self::entry_hash(prev_hash, outcome);
        self.entries.push(outcome.clone());
    }

    pub fn get_trace(&self, agent_id: &str) -> Vec<&ActionOutcome> {
        self.entries
            .iter()
            .filter(|e| e.request.agent_id == agent_id)
            .collect()
    }

    fn allowed_uses(&self, capability_id: &str) -> u64 {
        self.entries
            .iter()
            .filter(|entry| {
                entry.status == ActionStatus::Allowed
                    && entry.request.capability_id == capability_id
            })
            .count() as u64
    }

    pub fn get_head_hash(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash_chain.clone())
            .unwrap_or_default()
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = String::new();
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.sequence_number != i as u64 {
                return false;
            }
            let expected = Self::entry_hash(&prev_hash, entry);
            if entry.hash_chain != expected {
                return false;
            }
            prev_hash = entry.hash_chain.clone();
        }
        true
    }

    fn entry_hash(prev_hash: &str, outcome: &ActionOutcome) -> String {
        let mut resource_keys: Vec<_> = outcome.resource_usage.keys().collect();
        resource_keys.sort();
        let resource_usage: serde_json::Map<String, serde_json::Value> = resource_keys
            .into_iter()
            .map(|key| (key.clone(), outcome.resource_usage[key].clone()))
            .collect();

        let canonical = serde_json::json!({
            "prev_hash": prev_hash,
            "sequence_number": outcome.sequence_number,
            "request": {
                "capability_id": &outcome.request.capability_id,
                "agent_id": &outcome.request.agent_id,
                "action_type": outcome.request.action_type,
                "target": &outcome.request.target,
                "timestamp": outcome.request.timestamp,
            },
            "context": {
                "payload_size": outcome.context.payload_size,
                "method": &outcome.context.method,
                "resolved_target": &outcome.context.resolved_target,
            },
            "status": outcome.status,
            "result": &outcome.result,
            "error": &outcome.error,
            "side_effects": &outcome.side_effects,
            "resource_usage": resource_usage,
        });

        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
        format!("{:x}", hasher.finalize())
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
            Self {
                current: AtomicU64::new(initial),
            }
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
