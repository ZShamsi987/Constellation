//! Deterministic, durable workflow contracts and state transitions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_DEFINITION_BYTES: usize = 1024 * 1024;
const MAX_STEPS: usize = 256;

/// Workflow validation or state-transition failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowError {
    /// The serialized document exceeds the parser bound.
    #[error("workflow definition exceeds the 1 MiB limit")]
    TooLarge,
    /// YAML or JSON syntax is invalid.
    #[error("workflow definition could not be decoded: {0}")]
    Decode(String),
    /// A semantic workflow invariant is violated.
    #[error("invalid workflow definition: {0}")]
    InvalidDefinition(String),
    /// An event is invalid for the current run state.
    #[error("invalid workflow transition: {0}")]
    InvalidTransition(String),
}

/// Stable workflow identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkflowId(pub Uuid);

impl WorkflowId {
    /// Creates a time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for WorkflowId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable workflow-run identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkflowRunId(pub Uuid);

impl WorkflowRunId {
    /// Creates a time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for WorkflowRunId {
    fn default() -> Self {
        Self::new()
    }
}

/// Declarative workflow definition shared by YAML, JSON, and the visual builder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinition {
    /// Schema major version. The current version is one.
    pub version: u16,
    /// Human-facing workflow name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
    /// DAG steps in author-defined display order.
    pub steps: Vec<StepDefinition>,
}

/// One node in a workflow DAG.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepDefinition {
    /// Stable identifier within the definition.
    pub id: String,
    /// Step operation.
    #[serde(flatten)]
    pub action: StepAction,
    /// Dependencies that must become terminal first.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Optional condition evaluated after dependencies finish.
    #[serde(default)]
    pub when: Option<StepCondition>,
    /// Bounded execution deadline.
    #[serde(default = "default_step_timeout")]
    pub timeout_seconds: u32,
    /// Fresh retries before output/artifact publication.
    #[serde(default)]
    pub retry_limit: u8,
}

const fn default_step_timeout() -> u32 {
    300
}

/// Supported durable workflow operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepAction {
    /// Submit one model response using a variable-expanded input template.
    Inference {
        /// Model alias.
        model: String,
        /// Template resolved only at execution time and never logged.
        input: String,
        /// Maximum generated tokens.
        #[serde(default = "default_output_tokens")]
        max_output_tokens: u32,
    },
    /// Execute a named deny-by-default sandboxed tool.
    Tool {
        /// Tool identity registered by an administrator.
        tool: String,
        /// Tool arguments; secrets must use opaque credential references.
        #[serde(default)]
        arguments: Value,
        /// Must remain true for plugin and native tools.
        sandboxed: bool,
    },
    /// Pause until an authorized human approves or denies the run.
    Approval {
        /// Prompt shown to the approver; it must not contain runtime content.
        prompt: String,
        /// Required role (`owner`, `admin`, or `operator`).
        required_role: String,
    },
    /// Materialize a named value as an encrypted artifact.
    Artifact {
        /// Output artifact name.
        name: String,
        /// MIME media type.
        media_type: String,
        /// Template resolved at execution time.
        value: String,
    },
}

const fn default_output_tokens() -> u32 {
    256
}

/// Small, non-Turing-complete conditional language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepCondition {
    /// Run only when a dependency succeeded.
    Succeeded {
        /// Referenced dependency.
        step: String,
    },
    /// Run only when a dependency failed.
    Failed {
        /// Referenced dependency.
        step: String,
    },
    /// Compare a workflow input variable with an exact scalar value.
    InputEquals {
        /// Input variable name.
        key: String,
        /// Exact scalar comparison value.
        value: String,
    },
}

/// Overall run lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Created but not started.
    Pending,
    /// At least one step may execute.
    Running,
    /// Human approval blocks progress.
    WaitingApproval,
    /// Every required step succeeded or was skipped.
    Completed,
    /// A non-retryable step failed.
    Failed,
    /// An operator cancelled the run.
    Cancelled,
}

/// Per-step lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Dependencies have not all completed.
    Pending,
    /// Dependencies and conditions allow execution.
    Ready,
    /// A worker owns the step lease.
    Running,
    /// An approval decision is required.
    WaitingApproval,
    /// Step completed successfully.
    Succeeded,
    /// Step ended unsuccessfully.
    Failed,
    /// Its condition evaluated false.
    Skipped,
    /// Run cancellation stopped this step.
    Cancelled,
}

/// Privacy-safe resource accounting for one attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepAccounting {
    /// Counted model input tokens.
    pub input_tokens: u64,
    /// Counted model output tokens.
    pub output_tokens: u64,
    /// Transport bytes attributed to this step.
    pub network_bytes: u64,
    /// Execution time excluding queue delay.
    pub duration_ms: u64,
    /// Monetary accounting in millionths of the deployment currency.
    pub cost_micros: u64,
}

/// Mutable state for one workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepState {
    /// Lifecycle state.
    pub status: StepStatus,
    /// One-based attempt after execution begins.
    pub attempt: u8,
    /// UTC instant at which the current execution lease began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// Aggregated content-free accounting.
    pub accounting: StepAccounting,
    /// Stable redacted terminal error code.
    pub error_code: Option<String>,
    /// Encrypted artifact identifiers created by this step.
    pub artifacts: Vec<Uuid>,
}

/// Event-reduced workflow run state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRun {
    /// Run identity.
    pub id: WorkflowRunId,
    /// Immutable workflow identity and revision.
    pub workflow_id: WorkflowId,
    /// Definition revision SHA-256.
    pub definition_sha256: String,
    /// Overall status.
    pub status: RunStatus,
    /// Step state by identifier.
    pub steps: BTreeMap<String, StepState>,
    /// Non-secret workflow inputs.
    pub inputs: BTreeMap<String, String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last transition timestamp.
    pub updated_at: DateTime<Utc>,
}

/// State transition recorded in the durable workflow event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowEvent {
    /// Starts a pending run.
    Start,
    /// Acquires a ready step.
    StepStarted {
        /// Step acquiring a lease.
        step_id: String,
    },
    /// Recovers a step whose durable execution lease outlived its deadline.
    StepLeaseExpired {
        /// Step with an abandoned execution lease.
        step_id: String,
    },
    /// Completes a step with privacy-safe accounting and artifact handles.
    StepSucceeded {
        /// Completed step.
        step_id: String,
        /// Privacy-safe resource usage.
        accounting: StepAccounting,
        /// Encrypted artifacts produced by the step.
        artifacts: Vec<Uuid>,
    },
    /// Fails a step using a redacted code.
    StepFailed {
        /// Failed step.
        step_id: String,
        /// Stable redacted failure code.
        error_code: String,
        /// Whether the state machine may start a fresh attempt.
        retryable: bool,
    },
    /// Places an approval step into its explicit wait state.
    ApprovalRequested {
        /// Ready approval step.
        step_id: String,
    },
    /// Records the authorizing principal and succeeds the approval step.
    ApprovalGranted {
        /// Approval step.
        step_id: String,
        /// Authorizing principal recorded in audit history.
        principal_id: String,
    },
    /// Denies approval and fails the run.
    ApprovalDenied {
        /// Approval step.
        step_id: String,
        /// Denying principal recorded in audit history.
        principal_id: String,
    },
    /// Cancels all nonterminal steps.
    Cancel {
        /// Cancelling principal recorded in audit history.
        principal_id: String,
    },
}

/// Encrypted artifact metadata; content lives outside operational records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// Artifact identity.
    pub id: Uuid,
    /// Producing run.
    pub run_id: WorkflowRunId,
    /// Producing step.
    pub step_id: String,
    /// User-facing name.
    pub name: String,
    /// MIME media type.
    pub media_type: String,
    /// Plaintext digest checked after decryption.
    pub sha256: String,
    /// Plaintext byte length.
    pub size_bytes: u64,
    /// Opaque encrypted storage key.
    pub storage_key: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Durable schedule for a workflow revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowSchedule {
    /// Schedule identity.
    pub id: Uuid,
    /// Target workflow.
    pub workflow_id: WorkflowId,
    /// Five-field UTC cron expression.
    pub cron_utc: String,
    /// Disabled schedules never enqueue work.
    pub enabled: bool,
    /// Maximum simultaneous runs started by this schedule.
    pub concurrency_limit: u16,
}

/// Webhook trigger. Only the hash of its bearer secret is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowWebhook {
    /// Trigger identity used in the URL.
    pub id: Uuid,
    /// Target workflow.
    pub workflow_id: WorkflowId,
    /// SHA-256 of a 128-bit-or-stronger secret.
    pub secret_sha256: String,
    /// Disabled triggers fail closed.
    pub enabled: bool,
}

/// Parses and validates a JSON workflow definition.
///
/// # Errors
///
/// Returns bounded decode or semantic validation errors.
pub fn parse_json(input: &[u8]) -> Result<WorkflowDefinition, WorkflowError> {
    if input.len() > MAX_DEFINITION_BYTES {
        return Err(WorkflowError::TooLarge);
    }
    let definition =
        serde_json::from_slice(input).map_err(|error| WorkflowError::Decode(error.to_string()))?;
    validate(&definition)?;
    Ok(definition)
}

/// Parses and validates a YAML workflow definition.
///
/// # Errors
///
/// Returns bounded decode or semantic validation errors.
pub fn parse_yaml(input: &[u8]) -> Result<WorkflowDefinition, WorkflowError> {
    if input.len() > MAX_DEFINITION_BYTES {
        return Err(WorkflowError::TooLarge);
    }
    let definition = serde_yaml_ng::from_slice(input)
        .map_err(|error| WorkflowError::Decode(error.to_string()))?;
    validate(&definition)?;
    Ok(definition)
}

/// Validates DAG, permission, deadline, and condition invariants.
///
/// # Errors
///
/// Returns the first deterministic semantic error.
#[allow(clippy::too_many_lines)] // Keeping invariant order stable makes validation reproducible.
pub fn validate(definition: &WorkflowDefinition) -> Result<(), WorkflowError> {
    if definition.version != 1 {
        return Err(WorkflowError::InvalidDefinition(
            "only schema version 1 is supported".to_owned(),
        ));
    }
    if definition.name.trim().is_empty() || definition.name.len() > 128 {
        return Err(WorkflowError::InvalidDefinition(
            "name must contain 1 to 128 characters".to_owned(),
        ));
    }
    if definition.steps.is_empty() || definition.steps.len() > MAX_STEPS {
        return Err(WorkflowError::InvalidDefinition(
            "workflow must contain between 1 and 256 steps".to_owned(),
        ));
    }
    let mut identifiers = BTreeSet::new();
    for step in &definition.steps {
        if !valid_identifier(&step.id) || !identifiers.insert(step.id.clone()) {
            return Err(WorkflowError::InvalidDefinition(format!(
                "step identifier {} is invalid or duplicated",
                step.id
            )));
        }
        if !(1..=86_400).contains(&step.timeout_seconds) || step.retry_limit > 3 {
            return Err(WorkflowError::InvalidDefinition(format!(
                "step {} timeout or retry limit is outside its bound",
                step.id
            )));
        }
        match &step.action {
            StepAction::Inference {
                model,
                input,
                max_output_tokens,
            } if model.trim().is_empty()
                || input.len() > 262_144
                || !(1..=65_536).contains(max_output_tokens) =>
            {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "inference step {} has invalid model, input, or token limits",
                    step.id
                )));
            }
            StepAction::Tool {
                tool,
                arguments,
                sandboxed,
            } if tool.trim().is_empty()
                || !sandboxed
                || serde_json::to_vec(arguments).map_or(true, |value| value.len() > 262_144) =>
            {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "tool step {} must be bounded and sandboxed",
                    step.id
                )));
            }
            StepAction::Approval {
                prompt,
                required_role,
            } if prompt.trim().is_empty()
                || prompt.len() > 1024
                || !matches!(required_role.as_str(), "owner" | "admin" | "operator") =>
            {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "approval step {} has invalid prompt or role",
                    step.id
                )));
            }
            StepAction::Artifact {
                name,
                media_type,
                value,
            } if name.trim().is_empty()
                || name.len() > 128
                || media_type.trim().is_empty()
                || media_type.len() > 128
                || value.len() > 262_144 =>
            {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "artifact step {} has invalid metadata or value",
                    step.id
                )));
            }
            _ => {}
        }
    }
    for step in &definition.steps {
        for dependency in &step.depends_on {
            if dependency == &step.id || !identifiers.contains(dependency) {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "step {} has an invalid dependency {}",
                    step.id, dependency
                )));
            }
        }
        if let Some(
            StepCondition::Succeeded { step: condition }
            | StepCondition::Failed { step: condition },
        ) = &step.when
            && !step.depends_on.contains(condition)
        {
            return Err(WorkflowError::InvalidDefinition(format!(
                "step {} condition must reference one of its dependencies",
                step.id
            )));
        }
        if let Some(StepCondition::InputEquals { key, value }) = &step.when
            && (!valid_identifier(key) || value.len() > 1024)
        {
            return Err(WorkflowError::InvalidDefinition(format!(
                "step {} input condition is invalid",
                step.id
            )));
        }
    }
    topological_order(definition)?;
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn topological_order(definition: &WorkflowDefinition) -> Result<Vec<String>, WorkflowError> {
    let mut indegree = definition
        .steps
        .iter()
        .map(|step| (step.id.clone(), step.depends_on.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| id.clone())
        .collect::<VecDeque<_>>();
    let mut order = Vec::with_capacity(definition.steps.len());
    while let Some(completed) = ready.pop_front() {
        order.push(completed.clone());
        for step in &definition.steps {
            if step.depends_on.contains(&completed) {
                let Some(count) = indegree.get_mut(&step.id) else {
                    continue;
                };
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push_back(step.id.clone());
                }
            }
        }
    }
    if order.len() != definition.steps.len() {
        return Err(WorkflowError::InvalidDefinition(
            "workflow dependency graph contains a cycle".to_owned(),
        ));
    }
    Ok(order)
}

/// Returns canonical definition SHA-256 used to bind runs to immutable revisions.
///
/// # Errors
///
/// Returns a decode error only when canonical JSON serialization fails.
pub fn definition_sha256(definition: &WorkflowDefinition) -> Result<String, WorkflowError> {
    let bytes =
        serde_json::to_vec(definition).map_err(|error| WorkflowError::Decode(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Creates the initial event-reduced run state.
///
/// # Errors
///
/// Returns validation errors for an invalid definition or input bounds.
pub fn create_run(
    workflow_id: WorkflowId,
    definition: &WorkflowDefinition,
    inputs: BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> Result<WorkflowRun, WorkflowError> {
    validate(definition)?;
    if inputs.len() > 64
        || inputs
            .iter()
            .any(|(key, value)| !valid_identifier(key) || value.len() > 4096)
    {
        return Err(WorkflowError::InvalidDefinition(
            "workflow inputs exceed their bounds".to_owned(),
        ));
    }
    let steps = definition
        .steps
        .iter()
        .map(|step| {
            (
                step.id.clone(),
                StepState {
                    status: if step.depends_on.is_empty() {
                        StepStatus::Ready
                    } else {
                        StepStatus::Pending
                    },
                    attempt: 0,
                    started_at: None,
                    accounting: StepAccounting::default(),
                    error_code: None,
                    artifacts: Vec::new(),
                },
            )
        })
        .collect();
    Ok(WorkflowRun {
        id: WorkflowRunId::new(),
        workflow_id,
        definition_sha256: definition_sha256(definition)?,
        status: RunStatus::Pending,
        steps,
        inputs,
        created_at: now,
        updated_at: now,
    })
}

/// Applies one validated event and derives ready/skipped/terminal states.
///
/// # Errors
///
/// Returns an invalid transition without mutating the supplied run.
#[allow(clippy::too_many_lines)] // Explicit event transitions are security-relevant.
pub fn apply_event(
    run: &mut WorkflowRun,
    definition: &WorkflowDefinition,
    event: &WorkflowEvent,
    now: DateTime<Utc>,
) -> Result<(), WorkflowError> {
    let mut next = run.clone();
    match event {
        WorkflowEvent::Start if next.status == RunStatus::Pending => {
            next.status = RunStatus::Running;
        }
        WorkflowEvent::StepStarted { step_id } if next.status == RunStatus::Running => {
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::Ready {
                return Err(WorkflowError::InvalidTransition(
                    "only a ready step can start".to_owned(),
                ));
            }
            step.status = StepStatus::Running;
            step.attempt = step.attempt.saturating_add(1);
            step.started_at = Some(now);
        }
        WorkflowEvent::StepLeaseExpired { step_id } if next.status == RunStatus::Running => {
            let definition_step = definition
                .steps
                .iter()
                .find(|step| &step.id == step_id)
                .ok_or_else(|| {
                    WorkflowError::InvalidTransition("step does not exist".to_owned())
                })?;
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::Running {
                return Err(WorkflowError::InvalidTransition(
                    "only a running step lease can expire".to_owned(),
                ));
            }
            step.started_at = None;
            step.error_code = Some("lease_expired".to_owned());
            if step.attempt <= definition_step.retry_limit {
                step.status = StepStatus::Ready;
            } else {
                step.status = StepStatus::Failed;
                next.status = RunStatus::Failed;
            }
        }
        WorkflowEvent::StepSucceeded {
            step_id,
            accounting,
            artifacts,
        } if next.status == RunStatus::Running => {
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::Running {
                return Err(WorkflowError::InvalidTransition(
                    "only a running step can succeed".to_owned(),
                ));
            }
            step.status = StepStatus::Succeeded;
            step.started_at = None;
            step.accounting = accounting.clone();
            step.artifacts.clone_from(artifacts);
        }
        WorkflowEvent::StepFailed {
            step_id,
            error_code,
            retryable,
        } if next.status == RunStatus::Running => {
            if error_code.is_empty() || error_code.len() > 64 {
                return Err(WorkflowError::InvalidTransition(
                    "step error code is invalid".to_owned(),
                ));
            }
            let definition_step = definition
                .steps
                .iter()
                .find(|step| &step.id == step_id)
                .ok_or_else(|| {
                    WorkflowError::InvalidTransition("step does not exist".to_owned())
                })?;
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::Running {
                return Err(WorkflowError::InvalidTransition(
                    "only a running step can fail".to_owned(),
                ));
            }
            step.error_code = Some(error_code.clone());
            step.started_at = None;
            if *retryable && step.attempt <= definition_step.retry_limit {
                step.status = StepStatus::Ready;
            } else {
                step.status = StepStatus::Failed;
                next.status = RunStatus::Failed;
            }
        }
        WorkflowEvent::ApprovalRequested { step_id } if next.status == RunStatus::Running => {
            let definition_step = definition
                .steps
                .iter()
                .find(|step| &step.id == step_id)
                .ok_or_else(|| {
                    WorkflowError::InvalidTransition("step does not exist".to_owned())
                })?;
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::Ready
                || !matches!(definition_step.action, StepAction::Approval { .. })
            {
                return Err(WorkflowError::InvalidTransition(
                    "only a ready approval step can request approval".to_owned(),
                ));
            }
            step.status = StepStatus::WaitingApproval;
            next.status = RunStatus::WaitingApproval;
        }
        WorkflowEvent::ApprovalGranted {
            step_id,
            principal_id,
        } if next.status == RunStatus::WaitingApproval => {
            if principal_id.trim().is_empty() || principal_id.len() > 128 {
                return Err(WorkflowError::InvalidTransition(
                    "approval principal is invalid".to_owned(),
                ));
            }
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::WaitingApproval {
                return Err(WorkflowError::InvalidTransition(
                    "approval step is not waiting".to_owned(),
                ));
            }
            step.status = StepStatus::Succeeded;
            step.started_at = None;
            next.status = RunStatus::Running;
        }
        WorkflowEvent::ApprovalDenied {
            step_id,
            principal_id,
        } if next.status == RunStatus::WaitingApproval => {
            if principal_id.trim().is_empty() || principal_id.len() > 128 {
                return Err(WorkflowError::InvalidTransition(
                    "approval principal is invalid".to_owned(),
                ));
            }
            let step = next.steps.get_mut(step_id).ok_or_else(|| {
                WorkflowError::InvalidTransition("step does not exist".to_owned())
            })?;
            if step.status != StepStatus::WaitingApproval {
                return Err(WorkflowError::InvalidTransition(
                    "approval step is not waiting".to_owned(),
                ));
            }
            step.status = StepStatus::Failed;
            step.started_at = None;
            step.error_code = Some("approval_denied".to_owned());
            next.status = RunStatus::Failed;
        }
        WorkflowEvent::Cancel { principal_id }
            if matches!(
                next.status,
                RunStatus::Pending | RunStatus::Running | RunStatus::WaitingApproval
            ) =>
        {
            if principal_id.trim().is_empty() || principal_id.len() > 128 {
                return Err(WorkflowError::InvalidTransition(
                    "cancelling principal is invalid".to_owned(),
                ));
            }
            next.status = RunStatus::Cancelled;
            for step in next.steps.values_mut().filter(|step| {
                matches!(
                    step.status,
                    StepStatus::Pending
                        | StepStatus::Ready
                        | StepStatus::Running
                        | StepStatus::WaitingApproval
                )
            }) {
                step.status = StepStatus::Cancelled;
                step.started_at = None;
            }
        }
        _ => {
            return Err(WorkflowError::InvalidTransition(
                "event is not valid for the current run state".to_owned(),
            ));
        }
    }
    refresh_ready_steps(&mut next, definition);
    if next.status == RunStatus::Running
        && next
            .steps
            .values()
            .all(|step| matches!(step.status, StepStatus::Succeeded | StepStatus::Skipped))
    {
        next.status = RunStatus::Completed;
    }
    next.updated_at = now;
    *run = next;
    Ok(())
}

fn refresh_ready_steps(run: &mut WorkflowRun, definition: &WorkflowDefinition) {
    for definition_step in &definition.steps {
        if run
            .steps
            .get(&definition_step.id)
            .is_none_or(|step| step.status != StepStatus::Pending)
        {
            continue;
        }
        let dependencies_terminal = definition_step.depends_on.iter().all(|dependency| {
            run.steps.get(dependency).is_some_and(|step| {
                matches!(
                    step.status,
                    StepStatus::Succeeded | StepStatus::Failed | StepStatus::Skipped
                )
            })
        });
        if !dependencies_terminal {
            continue;
        }
        let condition = definition_step
            .when
            .as_ref()
            .is_none_or(|condition| match condition {
                StepCondition::Succeeded { step } => run
                    .steps
                    .get(step)
                    .is_some_and(|state| state.status == StepStatus::Succeeded),
                StepCondition::Failed { step } => run
                    .steps
                    .get(step)
                    .is_some_and(|state| state.status == StepStatus::Failed),
                StepCondition::InputEquals { key, value } => run.inputs.get(key) == Some(value),
            });
        if let Some(step) = run.steps.get_mut(&definition_step.id) {
            step.status = if condition {
                StepStatus::Ready
            } else {
                StepStatus::Skipped
            };
        }
    }
}

/// Returns step identifiers that may be leased in parallel, in definition order.
#[must_use]
pub fn ready_steps(run: &WorkflowRun, definition: &WorkflowDefinition) -> Vec<String> {
    definition
        .steps
        .iter()
        .filter(|definition_step| {
            run.steps
                .get(&definition_step.id)
                .is_some_and(|step| step.status == StepStatus::Ready)
        })
        .map(|step| step.id.clone())
        .collect()
}

/// Validates the deliberately small five-field UTC cron syntax.
///
/// # Errors
///
/// Returns invalid definition for unsupported characters or field counts.
pub fn validate_schedule(schedule: &WorkflowSchedule) -> Result<(), WorkflowError> {
    let fields = schedule.cron_utc.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || schedule.concurrency_limit == 0
        || schedule.concurrency_limit > 100
        || parse_cron_fields(&fields).is_err()
    {
        return Err(WorkflowError::InvalidDefinition(
            "schedule must be a bounded five-field UTC cron expression".to_owned(),
        ));
    }
    Ok(())
}

/// Evaluates the supported five-field UTC cron expression at a minute boundary.
///
/// # Errors
///
/// Returns an invalid-definition error for malformed or out-of-range fields.
pub fn schedule_matches(expression: &str, at: DateTime<Utc>) -> Result<bool, WorkflowError> {
    let fields = expression.split_whitespace().collect::<Vec<_>>();
    let parsed = parse_cron_fields(&fields)?;
    let day_of_month = parsed[2].matches(at.day());
    let day_of_week = parsed[4].matches(at.weekday().num_days_from_sunday());
    let day_matches = if parsed[2].wildcard || parsed[4].wildcard {
        day_of_month && day_of_week
    } else {
        day_of_month || day_of_week
    };
    Ok(parsed[0].matches(at.minute())
        && parsed[1].matches(at.hour())
        && day_matches
        && parsed[3].matches(at.month()))
}

/// Finds the next matching UTC minute within a bounded leap-year horizon.
///
/// # Errors
///
/// Returns an invalid-definition error when the expression is malformed or has no occurrence in
/// the next 366 days.
pub fn next_schedule_after(
    expression: &str,
    after: DateTime<Utc>,
) -> Result<DateTime<Utc>, WorkflowError> {
    let start = after
        .with_second(0)
        .and_then(|value| value.with_nanosecond(0))
        .ok_or_else(|| WorkflowError::InvalidDefinition("invalid schedule instant".to_owned()))?;
    let mut candidate = start + Duration::minutes(1);
    for _ in 0..=527_040 {
        if schedule_matches(expression, candidate)? {
            return Ok(candidate);
        }
        candidate += Duration::minutes(1);
    }
    Err(WorkflowError::InvalidDefinition(
        "schedule has no occurrence in the next 366 days".to_owned(),
    ))
}

#[derive(Debug, Clone)]
struct CronField {
    values: BTreeSet<u32>,
    wildcard: bool,
}

impl CronField {
    fn matches(&self, value: u32) -> bool {
        self.values.contains(&value)
    }
}

fn parse_cron_fields(fields: &[&str]) -> Result<[CronField; 5], WorkflowError> {
    if fields.len() != 5 {
        return Err(WorkflowError::InvalidDefinition(
            "schedule must have five UTC cron fields".to_owned(),
        ));
    }
    Ok([
        parse_cron_field(fields[0], 0, 59)?,
        parse_cron_field(fields[1], 0, 23)?,
        parse_cron_field(fields[2], 1, 31)?,
        parse_cron_field(fields[3], 1, 12)?,
        parse_cron_field(fields[4], 0, 6)?,
    ])
}

fn parse_cron_field(field: &str, minimum: u32, maximum: u32) -> Result<CronField, WorkflowError> {
    if field.is_empty()
        || field.len() > 32
        || !field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'*' | b',' | b'-' | b'/'))
    {
        return Err(WorkflowError::InvalidDefinition(
            "cron field contains unsupported syntax".to_owned(),
        ));
    }
    let mut values = BTreeSet::new();
    for item in field.split(',') {
        let (range, step) = item.split_once('/').map_or((item, 1), |(range, step)| {
            (range, step.parse::<u32>().unwrap_or(0))
        });
        if step == 0 {
            return Err(WorkflowError::InvalidDefinition(
                "cron step must be greater than zero".to_owned(),
            ));
        }
        let (start, end) = if range == "*" {
            (minimum, maximum)
        } else if let Some((start, end)) = range.split_once('-') {
            (
                start.parse::<u32>().map_err(|_| {
                    WorkflowError::InvalidDefinition("invalid cron range".to_owned())
                })?,
                end.parse::<u32>().map_err(|_| {
                    WorkflowError::InvalidDefinition("invalid cron range".to_owned())
                })?,
            )
        } else {
            let value = range
                .parse::<u32>()
                .map_err(|_| WorkflowError::InvalidDefinition("invalid cron value".to_owned()))?;
            (value, value)
        };
        if start < minimum || end > maximum || start > end {
            return Err(WorkflowError::InvalidDefinition(
                "cron value is outside its field range".to_owned(),
            ));
        }
        for value in (start..=end).step_by(usize::try_from(step).unwrap_or(usize::MAX)) {
            values.insert(value);
        }
    }
    if values.is_empty() {
        return Err(WorkflowError::InvalidDefinition(
            "cron field selects no values".to_owned(),
        ));
    }
    Ok(CronField {
        values,
        wildcard: field == "*",
    })
}

/// Returns a JSON Schema document for authoring tools.
#[must_use]
pub fn json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://constellation.local/schemas/workflow-v1.json",
        "title": "Constellation Workflow",
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "name", "steps"],
        "properties": {
            "version": {"const": 1},
            "name": {"type": "string", "minLength": 1, "maxLength": 128},
            "description": {"type": "string"},
            "steps": {"type": "array", "minItems": 1, "maxItems": 256, "items": {"$ref": "#/$defs/step"}}
        },
        "$defs": {
            "step": {
                "type": "object",
                "required": ["id", "type"],
                "properties": {
                    "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"},
                    "type": {"enum": ["inference", "tool", "approval", "artifact"]},
                    "depends_on": {"type": "array", "items": {"type": "string"}},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                    "retry_limit": {"type": "integer", "minimum": 0, "maximum": 3}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> WorkflowDefinition {
        WorkflowDefinition {
            version: 1,
            name: "review".to_owned(),
            description: String::new(),
            steps: vec![
                StepDefinition {
                    id: "draft".to_owned(),
                    action: StepAction::Inference {
                        model: "constellation/mock".to_owned(),
                        input: "{{topic}}".to_owned(),
                        max_output_tokens: 128,
                    },
                    depends_on: Vec::new(),
                    when: None,
                    timeout_seconds: 60,
                    retry_limit: 1,
                },
                StepDefinition {
                    id: "approve".to_owned(),
                    action: StepAction::Approval {
                        prompt: "Publish draft?".to_owned(),
                        required_role: "operator".to_owned(),
                    },
                    depends_on: vec!["draft".to_owned()],
                    when: Some(StepCondition::Succeeded {
                        step: "draft".to_owned(),
                    }),
                    timeout_seconds: 3600,
                    retry_limit: 0,
                },
            ],
        }
    }

    #[test]
    fn json_and_yaml_share_the_same_validated_contract() {
        let definition = definition();
        let json = serde_json::to_vec(&definition).unwrap_or_default();
        let yaml = serde_yaml_ng::to_string(&definition).unwrap_or_default();
        assert_eq!(parse_json(&json).ok(), Some(definition.clone()));
        assert_eq!(parse_yaml(yaml.as_bytes()).ok(), Some(definition));
    }

    #[test]
    fn cycles_and_unsandboxed_tools_are_rejected() {
        let mut cycle = definition();
        cycle.steps[0].depends_on.push("approve".to_owned());
        assert!(validate(&cycle).is_err());
        let mut tool = definition();
        tool.steps[0].action = StepAction::Tool {
            tool: "filesystem".to_owned(),
            arguments: json!({}),
            sandboxed: false,
        };
        assert!(validate(&tool).is_err());
    }

    #[test]
    fn state_machine_waits_for_human_approval() {
        let definition = definition();
        let now = Utc::now();
        let mut run = create_run(
            WorkflowId::new(),
            &definition,
            BTreeMap::from([("topic".to_owned(), "privacy".to_owned())]),
            now,
        )
        .unwrap_or_else(|error| panic!("create run: {error}"));
        assert!(apply_event(&mut run, &definition, &WorkflowEvent::Start, now).is_ok());
        assert!(
            apply_event(
                &mut run,
                &definition,
                &WorkflowEvent::StepStarted {
                    step_id: "draft".to_owned(),
                },
                now,
            )
            .is_ok()
        );
        assert!(
            apply_event(
                &mut run,
                &definition,
                &WorkflowEvent::StepSucceeded {
                    step_id: "draft".to_owned(),
                    accounting: StepAccounting::default(),
                    artifacts: Vec::new(),
                },
                now,
            )
            .is_ok()
        );
        assert_eq!(ready_steps(&run, &definition), vec!["approve"]);
        assert!(
            apply_event(
                &mut run,
                &definition,
                &WorkflowEvent::ApprovalRequested {
                    step_id: "approve".to_owned(),
                },
                now,
            )
            .is_ok()
        );
        assert_eq!(run.status, RunStatus::WaitingApproval);
        assert!(
            apply_event(
                &mut run,
                &definition,
                &WorkflowEvent::ApprovalGranted {
                    step_id: "approve".to_owned(),
                    principal_id: "operator-1".to_owned(),
                },
                now,
            )
            .is_ok()
        );
        assert_eq!(run.status, RunStatus::Completed);
    }

    #[test]
    fn abandoned_step_lease_retries_once_then_fails_closed() {
        let definition = definition();
        let now = Utc::now();
        let mut run = create_run(WorkflowId::new(), &definition, BTreeMap::new(), now)
            .unwrap_or_else(|error| panic!("create run: {error}"));
        assert!(apply_event(&mut run, &definition, &WorkflowEvent::Start, now).is_ok());
        for expected_status in [StepStatus::Ready, StepStatus::Failed] {
            assert!(
                apply_event(
                    &mut run,
                    &definition,
                    &WorkflowEvent::StepStarted {
                        step_id: "draft".to_owned(),
                    },
                    now,
                )
                .is_ok()
            );
            assert_eq!(run.steps["draft"].started_at, Some(now));
            assert!(
                apply_event(
                    &mut run,
                    &definition,
                    &WorkflowEvent::StepLeaseExpired {
                        step_id: "draft".to_owned(),
                    },
                    now,
                )
                .is_ok()
            );
            assert_eq!(run.steps["draft"].status, expected_status);
            assert_eq!(run.steps["draft"].started_at, None);
        }
        assert_eq!(run.status, RunStatus::Failed);
    }

    #[test]
    fn utc_cron_is_bounded_and_finds_the_next_occurrence() {
        let schedule = WorkflowSchedule {
            id: Uuid::now_v7(),
            workflow_id: WorkflowId::new(),
            cron_utc: "*/15 9-17 * * 1-5".to_owned(),
            enabled: true,
            concurrency_limit: 1,
        };
        assert!(validate_schedule(&schedule).is_ok());
        let friday = DateTime::parse_from_rfc3339("2026-07-24T16:59:31Z").map_or_else(
            |error| panic!("parse test time: {error}"),
            |value| value.with_timezone(&Utc),
        );
        assert_eq!(
            next_schedule_after(&schedule.cron_utc, friday)
                .map(|value| value.to_rfc3339())
                .ok(),
            Some("2026-07-24T17:00:00+00:00".to_owned())
        );
        let mut invalid = schedule;
        invalid.cron_utc = "60 * * * *".to_owned();
        assert!(validate_schedule(&invalid).is_err());
    }
}
