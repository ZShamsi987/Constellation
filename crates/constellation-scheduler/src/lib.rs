//! Deterministic, topology-aware scheduling core.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Duration, Utc};
use constellation_core::{
    BenchmarkReport, ExecutionPlan, ExecutionStrategy, MeasurementKind, Node, NodeId,
    NodeResourcePolicy, NodeStatus, PlanId, PlanningError, PrivacyPath, RejectedCandidate,
    SchedulingPolicy, WorkloadClass, WorkloadRequest,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// Immutable inputs for a planning decision.
#[derive(Debug, Clone)]
pub struct ClusterSnapshot {
    /// Nodes known to the controller.
    pub nodes: Vec<Node>,
    /// Most recent benchmark by node.
    pub benchmarks: HashMap<NodeId, BenchmarkReport>,
    /// Locally owned policy by node. Missing entries use secure defaults.
    pub policies: HashMap<NodeId, NodeResourcePolicy>,
    /// Node hosting the controller, used by Most Private policy.
    pub controller_node: Option<NodeId>,
    /// Explicit time supplied by orchestration for reproducibility.
    pub observed_at: DateTime<Utc>,
}

/// Adapter-attested strategy support on one node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStrategyCapabilities {
    /// Advertising node.
    pub node_id: NodeId,
    /// Runtime identifier whose versioned adapter validated the strategy.
    pub runtime_id: String,
    /// Strategies proven by adapter capability probing.
    pub strategies: Vec<ExecutionStrategy>,
    /// Maximum participants supported by this adapter build.
    pub maximum_nodes: u8,
    /// Whether the adapter can restore a distributed checkpoint.
    pub checkpoint_recovery: bool,
}

/// Hard requirements for an advanced distributed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedRequirements {
    /// Explicit strategy requested after capability probing.
    pub strategy: ExecutionStrategy,
    /// Number of participating nodes, bounded to two through eight.
    pub node_count: u8,
    /// Estimated activation or collective traffic per generated token.
    pub bytes_per_token: u64,
    /// Hard network budget for the complete request.
    pub maximum_network_bytes: u64,
    /// Adapter evidence by node.
    pub capabilities: Vec<NodeStrategyCapabilities>,
}

/// Deterministic perturbation used by the digital-twin simulator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationScenario {
    /// Stable scenario label.
    pub name: String,
    /// Multiplier applied to plan latency; must be finite and at least one.
    pub latency_multiplier: f64,
    /// Multiplier applied to decode throughput; must be finite and in `(0, 1]`.
    pub throughput_multiplier: f64,
    /// Optional selected node assumed unavailable.
    pub unavailable_node: Option<NodeId>,
}

/// Predicted advanced-plan behavior under one scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulationOutcome {
    /// Scenario label.
    pub name: String,
    /// Whether all placement prerequisites remain available.
    pub feasible: bool,
    /// Predicted first-token latency.
    pub estimated_ttft_ms: f64,
    /// Predicted decode throughput.
    pub estimated_tokens_per_second: f64,
    /// Stable condition requiring replanning, when infeasible.
    pub replan_reason: Option<String>,
}

/// Predicted-versus-observed calibration record without request content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanObservation {
    /// Plan being evaluated.
    pub plan_id: PlanId,
    /// Observed time to first token.
    pub actual_ttft_ms: f64,
    /// Observed decode throughput.
    pub actual_tokens_per_second: f64,
    /// Observed transport traffic.
    pub actual_network_bytes: u64,
    /// Relative TTFT error.
    pub ttft_error_ratio: f64,
    /// Relative throughput error.
    pub throughput_error_ratio: f64,
    /// Whether the miss is large enough to trigger replanning/calibration.
    pub materially_missed: bool,
}

#[derive(Debug, Clone)]
struct Candidate<'a> {
    node: &'a Node,
    score: f64,
    ttft_ms: f64,
    tokens_per_second: f64,
    confidence: f64,
}

/// Produces an advanced distributed plan only when every selected adapter advertises and
/// validates the requested strategy.
///
/// # Errors
///
/// Returns a structured planning error when the strategy is a release-0.1 strategy, capability
/// evidence is absent, a network budget is exceeded, or too few safe nodes remain.
#[allow(clippy::too_many_lines)] // Capability gates and estimate construction remain auditable.
pub fn plan_distributed(
    request: &WorkloadRequest,
    snapshot: &ClusterSnapshot,
    requirements: &DistributedRequirements,
) -> Result<ExecutionPlan, PlanningError> {
    validate_inputs(request, snapshot)?;
    if !matches!(
        requirements.strategy,
        ExecutionStrategy::Pipeline
            | ExecutionStrategy::Tensor
            | ExecutionStrategy::PrefillDecode
            | ExecutionStrategy::Speculative
            | ExecutionStrategy::Hybrid
    ) {
        return Err(PlanningError::InvalidInput(
            "advanced planning requires an advanced execution strategy".to_owned(),
        ));
    }
    if !(2..=8).contains(&requirements.node_count) {
        return Err(PlanningError::InvalidInput(
            "advanced plans require between two and eight nodes".to_owned(),
        ));
    }
    if requirements.bytes_per_token == 0 || requirements.maximum_network_bytes == 0 {
        return Err(PlanningError::InvalidInput(
            "distributed traffic estimates and budgets must be nonzero".to_owned(),
        ));
    }

    let mut accepted = Vec::new();
    let mut alternatives = Vec::new();
    for node in &snapshot.nodes {
        let Some(capability) = requirements
            .capabilities
            .iter()
            .find(|capability| capability.node_id == node.id)
        else {
            alternatives.push(RejectedCandidate {
                node_id: node.id,
                code: "strategy_capability_missing".to_owned(),
                reason: format!(
                    "{} supplied no adapter-attested strategy evidence",
                    node.name
                ),
            });
            continue;
        };
        if capability.runtime_id != request.required_runtime
            || !capability.strategies.contains(&requirements.strategy)
            || capability.maximum_nodes < requirements.node_count
        {
            alternatives.push(RejectedCandidate {
                node_id: node.id,
                code: "strategy_unsupported".to_owned(),
                reason: format!(
                    "{} did not validate {:?} for runtime {} at the requested width",
                    node.name, requirements.strategy, request.required_runtime
                ),
            });
            continue;
        }
        match evaluate_node(request, snapshot, node) {
            Ok(candidate) => accepted.push(candidate),
            Err(rejected) => alternatives.push(rejected),
        }
    }
    let selected_count = usize::from(requirements.node_count);
    if accepted.len() < selected_count {
        return Err(PlanningError::NoEligibleNode);
    }
    accepted.sort_by(|left, right| {
        left.score
            .partial_cmp(&right.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.node.id.0.cmp(&right.node.id.0))
    });
    let selected = &accepted[..selected_count];
    for candidate in accepted.iter().skip(selected_count) {
        alternatives.push(RejectedCandidate {
            node_id: candidate.node.id,
            code: "higher_score".to_owned(),
            reason: format!(
                "{} supports the strategy but has a less favorable estimate",
                candidate.node.name
            ),
        });
    }

    let coordination_edges = match requirements.strategy {
        ExecutionStrategy::Tensor => selected_count.saturating_mul(selected_count - 1),
        ExecutionStrategy::Pipeline | ExecutionStrategy::PrefillDecode => {
            selected_count.saturating_sub(1)
        }
        ExecutionStrategy::Speculative => 2,
        ExecutionStrategy::Hybrid => selected_count.saturating_mul(2),
        ExecutionStrategy::SingleNode
        | ExecutionStrategy::IndependentRouting
        | ExecutionStrategy::Replicated => 0,
    };
    let expected_tokens = 256_u64;
    let estimated_network_bytes = requirements
        .bytes_per_token
        .saturating_mul(expected_tokens)
        .saturating_mul(u64::try_from(coordination_edges).unwrap_or(u64::MAX));
    if estimated_network_bytes > requirements.maximum_network_bytes {
        return Err(PlanningError::InvalidInput(format!(
            "estimated distributed traffic {estimated_network_bytes} exceeds the configured budget {}",
            requirements.maximum_network_bytes
        )));
    }

    let average_latency = selected
        .iter()
        .map(|candidate| candidate.ttft_ms)
        .sum::<f64>()
        / f64::from(requirements.node_count);
    let slowest_throughput = selected
        .iter()
        .map(|candidate| candidate.tokens_per_second)
        .fold(f64::INFINITY, f64::min);
    let efficiency = match requirements.strategy {
        ExecutionStrategy::Pipeline => 0.82,
        ExecutionStrategy::Tensor => 0.70,
        ExecutionStrategy::PrefillDecode => 0.86,
        ExecutionStrategy::Speculative => 1.20,
        ExecutionStrategy::Hybrid => 0.62,
        ExecutionStrategy::SingleNode
        | ExecutionStrategy::IndependentRouting
        | ExecutionStrategy::Replicated => 1.0,
    };
    let selected_nodes = selected
        .iter()
        .map(|candidate| candidate.node.id)
        .collect::<Vec<_>>();
    let shard_memory = request
        .estimated_memory_bytes
        .div_ceil(u64::from(requirements.node_count));
    let estimated_memory_bytes = selected_nodes
        .iter()
        .map(|node_id| {
            let bytes = if matches!(
                requirements.strategy,
                ExecutionStrategy::Pipeline | ExecutionStrategy::Tensor | ExecutionStrategy::Hybrid
            ) {
                shard_memory
            } else {
                request.estimated_memory_bytes
            };
            (node_id.0.to_string(), bytes)
        })
        .collect::<BTreeMap<_, _>>();
    let confidence = selected
        .iter()
        .map(|candidate| candidate.confidence)
        .fold(1.0_f64, f64::min)
        * 0.85;

    Ok(ExecutionPlan {
        id: PlanId::new(),
        workload_id: request.id,
        strategy: requirements.strategy,
        selected_nodes: selected_nodes.clone(),
        estimated_ttft_ms: average_latency
            + f64::from(u32::try_from(coordination_edges).unwrap_or(u32::MAX)) * 2.0,
        estimated_tokens_per_second: slowest_throughput * efficiency,
        estimated_memory_bytes,
        estimated_network_bytes,
        confidence: confidence.clamp(0.1, 0.95),
        reasons: vec![format!(
            "Selected {:?} only after every participating runtime advertised the strategy and width.",
            requirements.strategy
        )],
        alternatives,
        privacy: PrivacyPath {
            prompt_nodes: selected_nodes.clone(),
            model_weight_nodes: selected_nodes,
            uses_relay: false,
            leaves_local_network: request.allow_remote,
            uses_cloud: false,
            content_logged: false,
        },
        replan_triggers: vec![
            "any participant becomes unavailable or withdraws the strategy capability".to_owned(),
            "activation traffic exceeds the hard network budget".to_owned(),
            "observed latency or throughput misses the estimate by more than 25 percent".to_owned(),
        ],
        created_at: snapshot.observed_at,
    })
}

/// Runs deterministic what-if scenarios against a persisted execution plan.
///
/// # Errors
///
/// Returns invalid input for non-finite or out-of-range multipliers.
pub fn simulate_plan(
    plan: &ExecutionPlan,
    scenarios: &[SimulationScenario],
) -> Result<Vec<SimulationOutcome>, PlanningError> {
    scenarios
        .iter()
        .map(|scenario| {
            if scenario.name.trim().is_empty()
                || !scenario.latency_multiplier.is_finite()
                || scenario.latency_multiplier < 1.0
                || !scenario.throughput_multiplier.is_finite()
                || !(0.0..=1.0).contains(&scenario.throughput_multiplier)
                || scenario.throughput_multiplier == 0.0
            {
                return Err(PlanningError::InvalidInput(
                    "simulation scenario multipliers are invalid".to_owned(),
                ));
            }
            let unavailable = scenario
                .unavailable_node
                .is_some_and(|node| plan.selected_nodes.contains(&node));
            Ok(SimulationOutcome {
                name: scenario.name.clone(),
                feasible: !unavailable,
                estimated_ttft_ms: plan.estimated_ttft_ms * scenario.latency_multiplier,
                estimated_tokens_per_second: if unavailable {
                    0.0
                } else {
                    plan.estimated_tokens_per_second * scenario.throughput_multiplier
                },
                replan_reason: unavailable.then(|| "selected_node_unavailable".to_owned()),
            })
        })
        .collect()
}

/// Compares content-free observations with a plan for calibration and dynamic replanning.
///
/// # Errors
///
/// Returns invalid input when observations are non-finite or non-positive.
pub fn observe_plan(
    plan: &ExecutionPlan,
    actual_ttft_ms: f64,
    actual_tokens_per_second: f64,
    actual_network_bytes: u64,
) -> Result<PlanObservation, PlanningError> {
    if !actual_ttft_ms.is_finite()
        || actual_ttft_ms <= 0.0
        || !actual_tokens_per_second.is_finite()
        || actual_tokens_per_second <= 0.0
    {
        return Err(PlanningError::InvalidInput(
            "observed execution metrics must be finite and positive".to_owned(),
        ));
    }
    let ttft_error_ratio =
        (actual_ttft_ms - plan.estimated_ttft_ms) / plan.estimated_ttft_ms.max(0.001);
    let throughput_error_ratio = (actual_tokens_per_second - plan.estimated_tokens_per_second)
        / plan.estimated_tokens_per_second.max(0.001);
    let network_miss = actual_network_bytes
        > plan
            .estimated_network_bytes
            .saturating_add(plan.estimated_network_bytes / 4);
    Ok(PlanObservation {
        plan_id: plan.id,
        actual_ttft_ms,
        actual_tokens_per_second,
        actual_network_bytes,
        ttft_error_ratio,
        throughput_error_ratio,
        materially_missed: ttft_error_ratio.abs() > 0.25
            || throughput_error_ratio.abs() > 0.25
            || network_miss,
    })
}

/// Produces a deterministic execution plan from a snapshot.
///
/// # Errors
///
/// Returns [`PlanningError::InvalidInput`] for non-finite measurements and
/// [`PlanningError::NoEligibleNode`] when hard constraints reject all nodes.
#[allow(clippy::too_many_lines)] // Keeping plan assembly together preserves auditability.
pub fn plan(
    request: &WorkloadRequest,
    snapshot: &ClusterSnapshot,
) -> Result<ExecutionPlan, PlanningError> {
    validate_inputs(request, snapshot)?;

    let mut accepted = Vec::new();
    let mut alternatives = Vec::new();

    for node in &snapshot.nodes {
        match evaluate_node(request, snapshot, node) {
            Ok(candidate) => accepted.push(candidate),
            Err(rejected) => alternatives.push(rejected),
        }
    }

    if accepted.is_empty() {
        return Err(PlanningError::NoEligibleNode);
    }

    accepted.sort_by(|left, right| {
        left.score
            .partial_cmp(&right.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.node.id.0.cmp(&right.node.id.0))
    });

    let selected_count = if request.class == WorkloadClass::Batch && accepted.len() > 1 {
        accepted.len().min(3)
    } else {
        1
    };
    let selected = &accepted[..selected_count];
    let strategy = if selected_count > 1 {
        ExecutionStrategy::IndependentRouting
    } else {
        ExecutionStrategy::SingleNode
    };

    for candidate in accepted.iter().skip(selected_count) {
        alternatives.push(RejectedCandidate {
            node_id: candidate.node.id,
            code: "higher_score".to_owned(),
            reason: format!(
                "{} was eligible but had a less favorable estimated score",
                candidate.node.name
            ),
        });
    }

    let selected_nodes: Vec<NodeId> = selected.iter().map(|candidate| candidate.node.id).collect();
    let estimated_ttft_ms = selected
        .iter()
        .map(|candidate| candidate.ttft_ms)
        .fold(f64::INFINITY, f64::min);
    let estimated_tokens_per_second = selected
        .iter()
        .map(|candidate| candidate.tokens_per_second)
        .sum();
    let selected_count_u32 = u32::try_from(selected_count).unwrap_or(3);
    let confidence = selected
        .iter()
        .map(|candidate| candidate.confidence)
        .sum::<f64>()
        / f64::from(selected_count_u32);
    let estimated_memory_bytes = selected
        .iter()
        .map(|candidate| {
            (
                candidate.node.id.0.to_string(),
                request.estimated_memory_bytes,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut reasons = vec![format!(
        "Selected {} because it satisfies model, runtime, memory, health, and owner-policy constraints.",
        selected
            .iter()
            .map(|candidate| candidate.node.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )];
    match strategy {
        ExecutionStrategy::IndependentRouting => reasons.push(
            "Independent batch requests can run concurrently without transferring model activations between computers."
                .to_owned(),
        ),
        ExecutionStrategy::SingleNode => reasons.push(
            "A single computer avoids distributed coordination and activation-transfer overhead."
                .to_owned(),
        ),
        ExecutionStrategy::Replicated
        | ExecutionStrategy::Pipeline
        | ExecutionStrategy::Tensor
        | ExecutionStrategy::PrefillDecode
        | ExecutionStrategy::Speculative
        | ExecutionStrategy::Hybrid => {}
    }
    if request.policy == SchedulingPolicy::KeepThisComputerResponsive {
        reasons.push(
            "Computers with active users received a strong responsiveness penalty.".to_owned(),
        );
    }

    Ok(ExecutionPlan {
        id: PlanId::new(),
        workload_id: request.id,
        strategy,
        selected_nodes: selected_nodes.clone(),
        estimated_ttft_ms,
        estimated_tokens_per_second,
        estimated_memory_bytes,
        estimated_network_bytes: 64 * 1024 * selected_count as u64,
        confidence,
        reasons,
        alternatives,
        privacy: PrivacyPath {
            prompt_nodes: selected_nodes.clone(),
            model_weight_nodes: selected_nodes,
            uses_relay: false,
            leaves_local_network: false,
            uses_cloud: false,
            content_logged: false,
        },
        replan_triggers: vec![
            "selected node becomes suspect, offline, draining, or revoked".to_owned(),
            "runtime or model availability changes".to_owned(),
            "owner resource policy becomes stricter".to_owned(),
            "measured performance materially misses the estimate".to_owned(),
        ],
        created_at: snapshot.observed_at,
    })
}

fn validate_inputs(
    request: &WorkloadRequest,
    snapshot: &ClusterSnapshot,
) -> Result<(), PlanningError> {
    if request.model.trim().is_empty() || request.required_runtime.trim().is_empty() {
        return Err(PlanningError::InvalidInput(
            "model and required runtime must not be empty".to_owned(),
        ));
    }
    for benchmark in snapshot.benchmarks.values() {
        let values = [
            benchmark.tokens_per_second,
            benchmark.time_to_first_token_ms,
            benchmark.network_latency_ms,
            benchmark.network_bandwidth_mbps,
            benchmark.jitter_ms,
            benchmark.packet_loss,
        ];
        if values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(PlanningError::InvalidInput(
                "benchmark values must be finite and non-negative".to_owned(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Hard constraints and scoring stay visibly ordered.
fn evaluate_node<'a>(
    request: &WorkloadRequest,
    snapshot: &'a ClusterSnapshot,
    node: &'a Node,
) -> Result<Candidate<'a>, RejectedCandidate> {
    let reject = |code: &str, reason: String| RejectedCandidate {
        node_id: node.id,
        code: code.to_owned(),
        reason,
    };

    if node.status != NodeStatus::Ready {
        return Err(reject(
            "node_not_ready",
            format!(
                "{} is {:?} and cannot receive new work",
                node.name, node.status
            ),
        ));
    }
    if !request.allowed_nodes.is_empty() && !request.allowed_nodes.contains(&node.id) {
        return Err(reject(
            "node_not_allowed",
            format!("{} is outside the workload allowlist", node.name),
        ));
    }
    if !node
        .capabilities
        .runtimes
        .iter()
        .any(|runtime| runtime == &request.required_runtime)
    {
        return Err(reject(
            "runtime_unavailable",
            format!(
                "{} does not advertise runtime {}",
                node.name, request.required_runtime
            ),
        ));
    }

    let default_policy = NodeResourcePolicy::default();
    let owner_policy = snapshot.policies.get(&node.id).unwrap_or(&default_policy);
    if node.capabilities.on_battery && !owner_policy.allow_on_battery {
        return Err(reject(
            "owner_policy_battery",
            format!(
                "{} is on battery and its owner disabled new work",
                node.name
            ),
        ));
    }
    if node.capabilities.user_active && !owner_policy.allow_when_user_active {
        return Err(reject(
            "owner_policy_user_active",
            format!(
                "{} has an active user and its owner disabled new work",
                node.name
            ),
        ));
    }
    if let (Some(maximum), Some(observed)) = (
        owner_policy.max_temperature_celsius,
        node.capabilities.temperature_celsius,
    ) && observed > f32::from(maximum)
    {
        return Err(reject(
            "owner_policy_temperature",
            format!(
                "{} exceeds its owner-defined temperature ceiling",
                node.name
            ),
        ));
    }

    let system_usable = usable_system_memory_with_policy(
        node.capabilities.memory_total_bytes,
        node.capabilities.memory_available_bytes,
        owner_policy,
    );
    let accelerator_usable = node
        .capabilities
        .accelerator
        .as_ref()
        .map_or(0, |accelerator| {
            usable_accelerator_memory_with_policy(accelerator.memory_bytes, owner_policy)
        });
    let usable_memory_bytes = system_usable.max(accelerator_usable);
    if request.estimated_memory_bytes > usable_memory_bytes {
        return Err(reject(
            "insufficient_memory",
            format!(
                "{} has {} MiB usable after safety reserves, below the {} MiB estimate",
                node.name,
                usable_memory_bytes / MIB,
                request.estimated_memory_bytes / MIB
            ),
        ));
    }

    let benchmark = snapshot.benchmarks.get(&node.id);
    let ttft_ms = benchmark.map_or(1_500.0, |value| {
        value.time_to_first_token_ms + value.network_latency_ms
    });
    let tokens_per_second = benchmark.map_or_else(
        || f64::from(node.capabilities.logical_cores.max(1)) / 2.0,
        |value| value.tokens_per_second.max(0.1),
    );
    let packet_loss = benchmark.map_or(0.02, |value| value.packet_loss);
    let jitter_ms = benchmark.map_or(10.0, |value| value.jitter_ms);

    let class_score = match request.class {
        WorkloadClass::Interactive => ttft_ms + (1_000.0 / tokens_per_second),
        WorkloadClass::Batch => 10_000.0 / tokens_per_second + ttft_ms * 0.1,
        WorkloadClass::Background => 5_000.0 / tokens_per_second + ttft_ms * 0.25,
    };
    let reliability_penalty = packet_loss * 20_000.0 + jitter_ms * 2.0;
    let mut policy_penalty = 0.0;
    match request.policy {
        SchedulingPolicy::Fastest => {}
        SchedulingPolicy::MostPrivate => {
            if snapshot.controller_node != Some(node.id) {
                policy_penalty += 2_000.0;
            }
        }
        SchedulingPolicy::LowestPower => {
            if node.capabilities.on_battery {
                policy_penalty += 5_000.0;
            }
            if node.capabilities.accelerator.is_some() {
                policy_penalty += 100.0;
            }
        }
        SchedulingPolicy::Balanced => {
            if node.capabilities.on_battery {
                policy_penalty += 2_000.0;
            }
            if node.capabilities.user_active {
                policy_penalty += 500.0;
            }
        }
        SchedulingPolicy::KeepThisComputerResponsive => {
            if node.capabilities.user_active {
                policy_penalty += 10_000.0;
            }
            if snapshot.controller_node == Some(node.id) {
                policy_penalty += 1_000.0;
            }
        }
    }
    if node.capabilities.thermal_throttling == Some(true) {
        policy_penalty += 5_000.0;
    }

    let confidence = estimate_confidence(benchmark, snapshot.observed_at);
    Ok(Candidate {
        node,
        score: class_score + reliability_penalty + policy_penalty,
        ttft_ms,
        tokens_per_second,
        confidence,
    })
}

/// Applies the default system-memory safety reserve.
#[must_use]
pub fn usable_system_memory(total_bytes: u64, available_bytes: u64) -> u64 {
    usable_system_memory_with_policy(total_bytes, available_bytes, &NodeResourcePolicy::default())
}

/// Applies the node owner's system-memory safety reserve.
#[must_use]
pub fn usable_system_memory_with_policy(
    total_bytes: u64,
    available_bytes: u64,
    policy: &NodeResourcePolicy,
) -> u64 {
    let reserve = total_bytes
        .saturating_mul(u64::from(policy.system_memory_reserve_percent))
        .saturating_div(100)
        .max(policy.system_memory_reserve_bytes);
    available_bytes.saturating_sub(reserve)
}

/// Applies the default accelerator-memory safety reserve.
#[must_use]
pub fn usable_accelerator_memory(total_bytes: u64) -> u64 {
    usable_accelerator_memory_with_policy(total_bytes, &NodeResourcePolicy::default())
}

/// Applies the node owner's accelerator-memory safety reserve.
#[must_use]
pub fn usable_accelerator_memory_with_policy(total_bytes: u64, policy: &NodeResourcePolicy) -> u64 {
    let reserve = total_bytes
        .saturating_mul(u64::from(policy.accelerator_memory_reserve_percent))
        .saturating_div(100)
        .max(policy.accelerator_memory_reserve_bytes);
    total_bytes.saturating_sub(reserve)
}

fn estimate_confidence(benchmark: Option<&BenchmarkReport>, observed_at: DateTime<Utc>) -> f64 {
    let Some(benchmark) = benchmark else {
        return 0.4;
    };
    let mut confidence: f64 = match benchmark.kind {
        MeasurementKind::Measured => 0.9,
        MeasurementKind::Estimated => 0.65,
        MeasurementKind::Unavailable => 0.4,
    };
    if benchmark.sample_count < 3 {
        confidence -= 0.1;
    }
    if observed_at - benchmark.measured_at > Duration::hours(24) {
        confidence -= 0.2;
    }
    confidence.clamp(0.1, 0.95)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use constellation_core::{
        BenchmarkReport, MeasurementKind, NodeCapabilities, OperatingSystem, SchedulingPolicy,
        WorkloadId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0)
            .single()
            .unwrap_or_else(Utc::now)
    }

    fn node(name: &str, memory_gib: u64, user_active: bool) -> Node {
        Node {
            id: NodeId::new(),
            name: name.to_owned(),
            os: OperatingSystem::Linux,
            architecture: "x86_64".to_owned(),
            status: NodeStatus::Ready,
            capabilities: NodeCapabilities {
                cpu_model: "test cpu".to_owned(),
                logical_cores: 16,
                memory_total_bytes: memory_gib * GIB,
                memory_available_bytes: memory_gib * GIB,
                accelerator: None,
                runtimes: vec!["mock".to_owned()],
                on_battery: false,
                user_active,
                temperature_celsius: None,
                thermal_throttling: None,
            },
            last_seen_at: now(),
        }
    }

    fn benchmark(node_id: NodeId, tps: f64, ttft: f64) -> BenchmarkReport {
        BenchmarkReport {
            node_id,
            runtime: "mock".to_owned(),
            model: "constellation/mock".to_owned(),
            tokens_per_second: tps,
            time_to_first_token_ms: ttft,
            network_latency_ms: 1.0,
            network_bandwidth_mbps: 1_000.0,
            jitter_ms: 0.2,
            packet_loss: 0.0,
            sample_count: 5,
            kind: MeasurementKind::Measured,
            measured_at: now(),
        }
    }

    fn request(policy: SchedulingPolicy, class: WorkloadClass) -> WorkloadRequest {
        WorkloadRequest {
            id: WorkloadId::new(),
            model: "constellation/mock".to_owned(),
            required_runtime: "mock".to_owned(),
            estimated_memory_bytes: GIB,
            class,
            policy,
            allowed_nodes: Vec::new(),
            allow_remote: false,
        }
    }

    #[test]
    fn fastest_policy_selects_best_measured_node() {
        let slow = node("slow", 16, false);
        let fast = node("fast", 16, false);
        let snapshot = ClusterSnapshot {
            benchmarks: HashMap::from([
                (slow.id, benchmark(slow.id, 5.0, 700.0)),
                (fast.id, benchmark(fast.id, 25.0, 100.0)),
            ]),
            policies: HashMap::new(),
            nodes: vec![slow, fast.clone()],
            controller_node: None,
            observed_at: now(),
        };

        let result = plan(
            &request(SchedulingPolicy::Fastest, WorkloadClass::Interactive),
            &snapshot,
        );
        let plan = result.unwrap_or_else(|error| panic!("planning failed: {error}"));
        assert_eq!(plan.selected_nodes, vec![fast.id]);
        assert_eq!(plan.strategy, ExecutionStrategy::SingleNode);
    }

    #[test]
    fn responsiveness_policy_avoids_active_computer() {
        let active = node("active", 16, true);
        let idle = node("idle", 16, false);
        let snapshot = ClusterSnapshot {
            benchmarks: HashMap::from([
                (active.id, benchmark(active.id, 30.0, 80.0)),
                (idle.id, benchmark(idle.id, 15.0, 200.0)),
            ]),
            policies: HashMap::new(),
            nodes: vec![active, idle.clone()],
            controller_node: None,
            observed_at: now(),
        };

        let result = plan(
            &request(
                SchedulingPolicy::KeepThisComputerResponsive,
                WorkloadClass::Interactive,
            ),
            &snapshot,
        );
        let plan = result.unwrap_or_else(|error| panic!("planning failed: {error}"));
        assert_eq!(plan.selected_nodes, vec![idle.id]);
    }

    #[test]
    fn batch_work_uses_independent_routing() {
        let first = node("first", 16, false);
        let second = node("second", 16, false);
        let snapshot = ClusterSnapshot {
            benchmarks: HashMap::from([
                (first.id, benchmark(first.id, 10.0, 300.0)),
                (second.id, benchmark(second.id, 12.0, 250.0)),
            ]),
            policies: HashMap::new(),
            nodes: vec![first, second],
            controller_node: None,
            observed_at: now(),
        };

        let result = plan(
            &request(SchedulingPolicy::Balanced, WorkloadClass::Batch),
            &snapshot,
        );
        let plan = result.unwrap_or_else(|error| panic!("planning failed: {error}"));
        assert_eq!(plan.strategy, ExecutionStrategy::IndependentRouting);
        assert_eq!(plan.selected_nodes.len(), 2);
    }

    #[test]
    fn rejects_node_below_memory_reserve() {
        let small = node("small", 2, false);
        let snapshot = ClusterSnapshot {
            nodes: vec![small],
            benchmarks: HashMap::new(),
            policies: HashMap::new(),
            controller_node: None,
            observed_at: now(),
        };

        assert_eq!(
            plan(
                &request(SchedulingPolicy::Balanced, WorkloadClass::Interactive),
                &snapshot
            ),
            Err(PlanningError::NoEligibleNode)
        );
    }

    #[test]
    fn owner_policy_is_a_hard_constraint_before_scoring() {
        let active = node("owner-active", 16, true);
        let policy = NodeResourcePolicy {
            allow_when_user_active: false,
            ..NodeResourcePolicy::default()
        };
        let snapshot = ClusterSnapshot {
            nodes: vec![active.clone()],
            benchmarks: HashMap::new(),
            policies: HashMap::from([(active.id, policy)]),
            controller_node: None,
            observed_at: now(),
        };
        assert_eq!(
            plan(
                &request(SchedulingPolicy::Fastest, WorkloadClass::Interactive),
                &snapshot,
            ),
            Err(PlanningError::NoEligibleNode)
        );
    }

    #[test]
    fn distributed_plan_requires_attested_capability_on_every_node() {
        let first = node("first", 16, false);
        let second = node("second", 16, false);
        let snapshot = ClusterSnapshot {
            benchmarks: HashMap::from([
                (first.id, benchmark(first.id, 20.0, 100.0)),
                (second.id, benchmark(second.id, 18.0, 120.0)),
            ]),
            policies: HashMap::new(),
            nodes: vec![first.clone(), second.clone()],
            controller_node: None,
            observed_at: now(),
        };
        let mut requirements = DistributedRequirements {
            strategy: ExecutionStrategy::Pipeline,
            node_count: 2,
            bytes_per_token: 4096,
            maximum_network_bytes: 16 * MIB,
            capabilities: vec![NodeStrategyCapabilities {
                node_id: first.id,
                runtime_id: "mock".to_owned(),
                strategies: vec![ExecutionStrategy::Pipeline],
                maximum_nodes: 2,
                checkpoint_recovery: false,
            }],
        };
        let workload = request(SchedulingPolicy::Balanced, WorkloadClass::Interactive);
        assert_eq!(
            plan_distributed(&workload, &snapshot, &requirements),
            Err(PlanningError::NoEligibleNode)
        );
        requirements.capabilities.push(NodeStrategyCapabilities {
            node_id: second.id,
            runtime_id: "mock".to_owned(),
            strategies: vec![ExecutionStrategy::Pipeline],
            maximum_nodes: 2,
            checkpoint_recovery: false,
        });
        let planned = plan_distributed(&workload, &snapshot, &requirements)
            .unwrap_or_else(|error| panic!("distributed plan failed: {error}"));
        assert_eq!(planned.strategy, ExecutionStrategy::Pipeline);
        assert_eq!(planned.selected_nodes.len(), 2);
        assert!(planned.estimated_network_bytes <= requirements.maximum_network_bytes);
    }

    #[test]
    fn digital_twin_marks_selected_node_loss_infeasible() {
        let selected = NodeId::new();
        let workload = WorkloadId::new();
        let execution = ExecutionPlan {
            id: PlanId::new(),
            workload_id: workload,
            strategy: ExecutionStrategy::Pipeline,
            selected_nodes: vec![selected, NodeId::new()],
            estimated_ttft_ms: 100.0,
            estimated_tokens_per_second: 20.0,
            estimated_memory_bytes: BTreeMap::new(),
            estimated_network_bytes: 1024,
            confidence: 0.8,
            reasons: Vec::new(),
            alternatives: Vec::new(),
            privacy: PrivacyPath {
                prompt_nodes: Vec::new(),
                model_weight_nodes: Vec::new(),
                uses_relay: false,
                leaves_local_network: false,
                uses_cloud: false,
                content_logged: false,
            },
            replan_triggers: Vec::new(),
            created_at: now(),
        };
        let outcomes = simulate_plan(
            &execution,
            &[SimulationScenario {
                name: "node loss".to_owned(),
                latency_multiplier: 2.0,
                throughput_multiplier: 0.5,
                unavailable_node: Some(selected),
            }],
        )
        .unwrap_or_default();
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].feasible);
        assert!(outcomes[0].estimated_tokens_per_second.abs() < f64::EPSILON);
    }

    #[test]
    fn observation_flags_material_prediction_miss() {
        let selected = node("selected", 16, false);
        let snapshot = ClusterSnapshot {
            nodes: vec![selected.clone()],
            benchmarks: HashMap::from([(selected.id, benchmark(selected.id, 20.0, 100.0))]),
            policies: HashMap::new(),
            controller_node: None,
            observed_at: now(),
        };
        let planned = plan(
            &request(SchedulingPolicy::Fastest, WorkloadClass::Interactive),
            &snapshot,
        )
        .unwrap_or_else(|error| panic!("plan failed: {error}"));
        let observation = observe_plan(&planned, planned.estimated_ttft_ms * 2.0, 2.0, 100_000)
            .unwrap_or_else(|error| panic!("observation failed: {error}"));
        assert!(observation.materially_missed);
    }
}
