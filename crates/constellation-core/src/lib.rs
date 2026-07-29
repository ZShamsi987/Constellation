//! Canonical domain types shared by Constellation services.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Stable node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct NodeId(pub Uuid);

impl NodeId {
    /// Creates a time-ordered node identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable workload identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct WorkloadId(pub Uuid);

impl WorkloadId {
    /// Creates a time-ordered workload identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for WorkloadId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable execution-plan identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct PlanId(pub Uuid);

impl PlanId {
    /// Creates a time-ordered plan identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for PlanId {
    fn default() -> Self {
        Self::new()
    }
}

/// Operating-system family reported by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    /// Microsoft Windows.
    Windows,
    /// Apple macOS.
    MacOs,
    /// Linux distribution.
    Linux,
    /// Unrecognized system; remains visible but receives conservative plans.
    Unknown,
}

/// Controller health assessment for a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Inventory exists but initial checks are incomplete.
    Joining,
    /// Node is eligible for work.
    Ready,
    /// Heartbeat is late, but the offline threshold has not elapsed.
    Suspect,
    /// Node is not eligible for new work.
    Offline,
    /// Membership was explicitly revoked.
    Revoked,
    /// Node is draining current work and accepts no new work.
    Draining,
}

/// Normalized accelerator information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Accelerator {
    /// Vendor such as `nvidia`, `amd`, or `apple`.
    pub vendor: String,
    /// User-facing model.
    pub model: String,
    /// Dedicated or usable shared memory in bytes.
    pub memory_bytes: u64,
    /// Runtime backends such as `cuda`, `metal`, or `vulkan`.
    #[serde(default)]
    pub backends: Vec<String>,
}

/// Normalized hardware and runtime summary used by the scheduler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct NodeCapabilities {
    /// CPU model.
    pub cpu_model: String,
    /// Logical CPU count.
    pub logical_cores: u16,
    /// Total system memory in bytes.
    pub memory_total_bytes: u64,
    /// Currently available system memory in bytes.
    pub memory_available_bytes: u64,
    /// Optional accelerator.
    pub accelerator: Option<Accelerator>,
    /// Detected canonical runtime adapter identifiers.
    #[serde(default)]
    pub runtimes: Vec<String>,
    /// Node is currently on battery power.
    #[serde(default)]
    pub on_battery: bool,
    /// Node reports foreground user activity.
    #[serde(default)]
    pub user_active: bool,
    /// Temperature when available.
    pub temperature_celsius: Option<f32>,
    /// Thermal throttling signal when available.
    pub thermal_throttling: Option<bool>,
}

/// Locally enforced resource limits. Remote administrators may only make these stricter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeResourcePolicy {
    /// Minimum system-memory percentage retained for the node owner.
    pub system_memory_reserve_percent: u8,
    /// Minimum system-memory bytes retained for the node owner.
    pub system_memory_reserve_bytes: u64,
    /// Minimum accelerator-memory percentage retained for the node owner.
    pub accelerator_memory_reserve_percent: u8,
    /// Minimum accelerator-memory bytes retained for the node owner.
    pub accelerator_memory_reserve_bytes: u64,
    /// Whether new work is eligible while the node is on battery.
    pub allow_on_battery: bool,
    /// Whether new work is eligible while a foreground user is active.
    pub allow_when_user_active: bool,
    /// Optional hard thermal ceiling.
    pub max_temperature_celsius: Option<u16>,
}

impl NodeResourcePolicy {
    /// Returns true when this policy cannot grant more resources than `baseline`.
    #[must_use]
    pub fn is_at_least_as_strict_as(&self, baseline: &Self) -> bool {
        self.system_memory_reserve_percent >= baseline.system_memory_reserve_percent
            && self.system_memory_reserve_bytes >= baseline.system_memory_reserve_bytes
            && self.accelerator_memory_reserve_percent
                >= baseline.accelerator_memory_reserve_percent
            && self.accelerator_memory_reserve_bytes >= baseline.accelerator_memory_reserve_bytes
            && (!self.allow_on_battery || baseline.allow_on_battery)
            && (!self.allow_when_user_active || baseline.allow_when_user_active)
            && match (
                self.max_temperature_celsius,
                baseline.max_temperature_celsius,
            ) {
                (Some(value), Some(existing)) => value <= existing,
                (Some(_) | None, None) => true,
                (None, Some(_)) => false,
            }
    }

    /// Validates bounded percentages and a plausible thermal threshold.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.system_memory_reserve_percent <= 100
            && self.accelerator_memory_reserve_percent <= 100
            && self
                .max_temperature_celsius
                .is_none_or(|value| (30..=120).contains(&value))
    }
}

impl Default for NodeResourcePolicy {
    fn default() -> Self {
        Self {
            system_memory_reserve_percent: 15,
            system_memory_reserve_bytes: 2 * 1024 * 1024 * 1024,
            accelerator_memory_reserve_percent: 10,
            accelerator_memory_reserve_bytes: 512 * 1024 * 1024,
            allow_on_battery: true,
            allow_when_user_active: true,
            max_temperature_celsius: None,
        }
    }
}

/// A trusted compute node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Node {
    /// Node ID.
    pub id: NodeId,
    /// User-assigned display name.
    pub name: String,
    /// OS family.
    pub os: OperatingSystem,
    /// Architecture such as `x86_64` or `aarch64`.
    pub architecture: String,
    /// Current status.
    pub status: NodeStatus,
    /// Normalized capabilities.
    pub capabilities: NodeCapabilities,
    /// Last controller observation.
    pub last_seen_at: DateTime<Utc>,
}

/// Measurement quality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementKind {
    /// Directly measured.
    Measured,
    /// Derived from related observations.
    Estimated,
    /// Not available on this platform or node.
    Unavailable,
}

/// Compute and network measurements for a node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BenchmarkReport {
    /// Node measured.
    pub node_id: NodeId,
    /// Runtime adapter measured.
    pub runtime: String,
    /// Reference model or deterministic benchmark name.
    pub model: String,
    /// Decode throughput.
    pub tokens_per_second: f64,
    /// Time to first token in milliseconds.
    pub time_to_first_token_ms: f64,
    /// Controller-to-node round-trip latency in milliseconds.
    pub network_latency_ms: f64,
    /// Measured bidirectional bandwidth in megabits per second.
    pub network_bandwidth_mbps: f64,
    /// Jitter in milliseconds.
    pub jitter_ms: f64,
    /// Packet loss fraction from zero to one.
    pub packet_loss: f64,
    /// Number of samples.
    pub sample_count: u32,
    /// Measurement source.
    pub kind: MeasurementKind,
    /// Collection time.
    pub measured_at: DateTime<Utc>,
}

/// Latency/throughput classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadClass {
    /// Latency-sensitive user interaction.
    Interactive,
    /// Throughput-sensitive batch work.
    Batch,
    /// Lower-priority background work.
    Background,
}

/// User-facing scheduling preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingPolicy {
    /// Optimize latency or throughput for the workload class.
    Fastest,
    /// Prefer the controller node and the narrowest data path.
    MostPrivate,
    /// Prefer lower expected energy.
    LowestPower,
    /// Blend performance, reliability, and responsiveness.
    Balanced,
    /// Penalize nodes reporting active users.
    KeepThisComputerResponsive,
}

/// Canonical workload requirements consumed by the scheduler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct WorkloadRequest {
    /// Workload ID.
    pub id: WorkloadId,
    /// Requested model alias.
    pub model: String,
    /// Required runtime adapter ID.
    pub required_runtime: String,
    /// Estimated model and working-set memory.
    pub estimated_memory_bytes: u64,
    /// Workload classification.
    pub class: WorkloadClass,
    /// Scheduling policy.
    pub policy: SchedulingPolicy,
    /// Optional node allowlist.
    #[serde(default)]
    pub allowed_nodes: Vec<NodeId>,
    /// Whether remote nodes may participate. False in the first release.
    #[serde(default)]
    pub allow_remote: bool,
}

/// Decrypted execution lease delivered only over an authenticated worker channel.
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerLease {
    /// Lease identity used for ordered event submission.
    pub id: Uuid,
    /// Durable workload identity.
    pub workload_id: WorkloadId,
    /// Node authorized to execute the lease.
    pub node_id: NodeId,
    /// One-based attempt; interactive work permits at most one pre-output retry.
    pub attempt: u8,
    /// Model alias already validated by the scheduler and worker capability declaration.
    pub model: String,
    /// Canonical request content. This field must never be logged or persisted in plaintext.
    pub input: String,
    /// Maximum output token budget.
    pub maximum_output_tokens: u32,
    /// Immutable execution plan.
    pub plan: ExecutionPlan,
    /// Lease acknowledgement deadline.
    pub expires_at: DateTime<Utc>,
}

/// Ordered runtime event submitted by a worker. Text fields must never enter operational logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerRuntimeEvent {
    /// Runtime or model load progress.
    Loading {
        /// Fraction from zero to one.
        progress: f32,
    },
    /// Prompt prefill completed.
    Prefill {
        /// Prompt processing duration.
        elapsed_ms: u64,
    },
    /// Incremental generated text.
    TextDelta {
        /// Incremental output content.
        text: String,
    },
    /// Successful terminal usage.
    Finished {
        /// Counted canonical-input tokens.
        input_tokens: u32,
        /// Counted output tokens.
        output_tokens: u32,
        /// Runtime finish reason.
        finish_reason: String,
    },
    /// Privacy-safe runtime failure.
    Failure {
        /// Stable machine-readable code.
        code: String,
        /// Redacted diagnostic without content.
        message: String,
        /// Whether a fresh attempt might succeed.
        retryable: bool,
        /// Whether any output delta was emitted.
        output_started: bool,
    },
    /// Cancellation acknowledged.
    Cancelled,
}

impl WorkerRuntimeEvent {
    /// Whether this event ends the lease.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Finished { .. } | Self::Failure { .. } | Self::Cancelled
        )
    }

    /// Whether this event proves response output has started.
    #[must_use]
    pub const fn starts_output(&self) -> bool {
        matches!(
            self,
            Self::TextDelta { .. }
                | Self::Failure {
                    output_started: true,
                    ..
                }
        )
    }
}

/// Capability-gated execution strategies. Availability is proven per adapter and plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStrategy {
    /// Entire workload on one node.
    SingleNode,
    /// Complete independent requests routed among eligible nodes.
    IndependentRouting,
    /// Complete replicas placed on multiple nodes.
    Replicated,
    /// Sequential model stages placed across nodes.
    Pipeline,
    /// One model layer is partitioned across accelerators.
    Tensor,
    /// Prompt prefill and token decoding use distinct placements.
    PrefillDecode,
    /// A draft runtime proposes tokens verified by a target runtime.
    Speculative,
    /// Adapter-validated composition of more than one supported strategy.
    Hybrid,
}

/// Machine-readable rejection considered by the scheduler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RejectedCandidate {
    /// Node considered.
    pub node_id: NodeId,
    /// Stable constraint or score code.
    pub code: String,
    /// Human-readable explanation without sensitive data.
    pub reason: String,
}

/// Planned privacy data path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[allow(clippy::struct_excessive_bools)] // Wire shape mirrors independent privacy facts.
pub struct PrivacyPath {
    /// Node receiving canonical request content.
    pub prompt_nodes: Vec<NodeId>,
    /// Nodes storing or loading weights.
    pub model_weight_nodes: Vec<NodeId>,
    /// Whether a relay participates.
    pub uses_relay: bool,
    /// Whether data leaves the local network.
    pub leaves_local_network: bool,
    /// Whether paid/cloud compute participates.
    pub uses_cloud: bool,
    /// Content logging policy.
    pub content_logged: bool,
}

/// Scheduler output persisted for audit and calibration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ExecutionPlan {
    /// Plan ID.
    pub id: PlanId,
    /// Workload ID.
    pub workload_id: WorkloadId,
    /// Selected strategy.
    pub strategy: ExecutionStrategy,
    /// Ordered selected nodes.
    pub selected_nodes: Vec<NodeId>,
    /// Expected TTFT.
    pub estimated_ttft_ms: f64,
    /// Expected decode throughput.
    pub estimated_tokens_per_second: f64,
    /// Expected memory by node.
    pub estimated_memory_bytes: BTreeMap<String, u64>,
    /// Expected request network traffic.
    pub estimated_network_bytes: u64,
    /// Confidence from zero to one.
    pub confidence: f64,
    /// Plain-language reasons.
    pub reasons: Vec<String>,
    /// Rejected or lower-ranked alternatives.
    pub alternatives: Vec<RejectedCandidate>,
    /// Planned sensitive-data path.
    pub privacy: PrivacyPath,
    /// Conditions requiring a new plan.
    pub replan_triggers: Vec<String>,
    /// Creation time supplied by orchestration, not the pure scheduler.
    pub created_at: DateTime<Utc>,
}

/// Event sent to live clients and persisted in the outbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterEvent {
    /// Monotonic database sequence.
    pub sequence: i64,
    /// Stable event type.
    pub event_type: String,
    /// Redacted JSON payload.
    pub payload: serde_json::Value,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Stable planner failure.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum PlanningError {
    /// No candidate passed hard constraints.
    #[error("no eligible node can satisfy this workload")]
    NoEligibleNode,
    /// Inputs contain an invalid numeric value.
    #[error("invalid scheduler input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::NodeResourcePolicy;

    #[test]
    fn remote_policy_comparison_never_treats_looser_limits_as_stricter() {
        let baseline = NodeResourcePolicy::default();
        let stricter = NodeResourcePolicy {
            system_memory_reserve_bytes: baseline.system_memory_reserve_bytes + 1024,
            allow_on_battery: false,
            ..baseline.clone()
        };
        assert!(stricter.is_at_least_as_strict_as(&baseline));
        assert!(!baseline.is_at_least_as_strict_as(&stricter));
        let invalid = NodeResourcePolicy {
            system_memory_reserve_percent: 101,
            ..baseline
        };
        assert!(!invalid.is_valid());
    }
}
