//! Runtime adapter contract and deterministic mock implementation.

mod exo;
mod llama;

pub use exo::{ExoSidecarAdapter, ExoSidecarConfig, PINNED_EXO_REVISION};
pub use llama::{LlamaServerAdapter, LlamaServerConfig};

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use constellation_core::{ExecutionPlan, WorkloadId};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};

/// Canonical adapter capability declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Capabilities are independent wire-level facts.
pub struct RuntimeCapabilities {
    /// Adapter identifier.
    pub runtime_id: String,
    /// Adapter version.
    pub adapter_version: String,
    /// Model aliases currently available.
    pub models: Vec<String>,
    /// Supports streamed text generation.
    pub streaming: bool,
    /// Supports embeddings.
    pub embeddings: bool,
    /// Supports tool calls.
    pub tool_calling: bool,
    /// Supports schema-constrained output.
    pub structured_output: bool,
    /// Advertised parallel strategies.
    pub parallelism: Vec<String>,
    /// Supports cancellation.
    pub cancellation: bool,
    /// Supports checkpoint recovery.
    pub recovery: bool,
}

/// Runtime health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth {
    /// Ready to accept work.
    Ready,
    /// Loading or otherwise temporarily unavailable.
    Degraded,
    /// Failed health check.
    Unavailable,
}

/// Canonical text-generation input.
#[derive(Debug, Clone)]
pub struct RuntimeRequest {
    /// Workload identity.
    pub workload_id: WorkloadId,
    /// Model alias.
    pub model: String,
    /// Flattened content prepared by the gateway adapter.
    pub input: String,
    /// Maximum output token budget.
    pub max_output_tokens: u32,
    /// Immutable execution plan.
    pub plan: ExecutionPlan,
}

/// Preflight resource and latency estimate returned by an adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEstimate {
    /// Expected resident memory for weights and working state.
    pub memory_bytes: u64,
    /// Expected first-token latency.
    pub time_to_first_token_ms: f64,
    /// Expected decode throughput.
    pub tokens_per_second: f64,
    /// Estimate confidence from zero to one.
    pub confidence: f64,
}

/// Privacy-safe runtime counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMetrics {
    /// Currently active executions.
    pub active_requests: u64,
    /// Executions accepted since process start.
    pub total_requests: u64,
    /// Terminal runtime failures since process start.
    pub failed_requests: u64,
    /// Whether model state is currently loaded.
    pub model_loaded: bool,
}

/// Typed runtime stream item.
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeEvent {
    /// Runtime or model is loading.
    Loading {
        /// Fraction from zero to one.
        progress: f32,
    },
    /// Runtime completed prompt prefill.
    Prefill {
        /// Prompt-processing time in milliseconds.
        elapsed_ms: u64,
    },
    /// Incremental text output.
    TextDelta(String),
    /// Final usage and reason.
    Finished {
        /// Counted input tokens.
        input_tokens: u32,
        /// Counted output tokens.
        output_tokens: u32,
        /// Canonical terminal reason.
        finish_reason: String,
    },
    /// Runtime terminated without a normal completion.
    Failure {
        /// Stable machine-readable reason.
        code: String,
        /// Redacted diagnostic safe for clients and logs.
        message: String,
        /// Whether a fresh attempt may succeed.
        retryable: bool,
        /// Whether any output was already emitted.
        output_started: bool,
    },
    /// Cancellation acknowledged.
    Cancelled,
}

/// Adapter error safe to map into a normalized API error.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Requested model is unavailable.
    #[error("model is unavailable: {0}")]
    ModelUnavailable(String),
    /// Feature is not supported by this adapter.
    #[error("runtime feature is unsupported: {0}")]
    UnsupportedFeature(String),
    /// Adapter is unhealthy.
    #[error("runtime is unavailable")]
    Unavailable,
    /// Execution could not start.
    #[error("runtime execution failed: {0}")]
    Execution(String),
}

/// Versioned inference runtime boundary.
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    /// Detects whether the runtime is installed or embedded.
    async fn detect(&self) -> Result<bool, RuntimeError>;
    /// Returns current adapter capabilities.
    async fn capabilities(&self) -> Result<RuntimeCapabilities, RuntimeError>;
    /// Verifies that a model can be served.
    async fn validate_model(&self, model: &str) -> Result<(), RuntimeError>;
    /// Estimates resources and performance before model load.
    async fn estimate(&self, request: &RuntimeRequest) -> Result<RuntimeEstimate, RuntimeError>;
    /// Loads model state when required.
    async fn load(&self, model: &str) -> Result<(), RuntimeError>;
    /// Starts a typed event stream.
    async fn execute_stream(
        &self,
        request: RuntimeRequest,
    ) -> Result<mpsc::Receiver<RuntimeEvent>, RuntimeError>;
    /// Requests cancellation of an active workload.
    async fn cancel(&self, workload_id: WorkloadId) -> Result<(), RuntimeError>;
    /// Unloads model state.
    async fn unload(&self, model: &str) -> Result<(), RuntimeError>;
    /// Returns current health.
    async fn health(&self) -> RuntimeHealth;
    /// Returns content-free operational counters.
    async fn metrics(&self) -> RuntimeMetrics;
    /// Attempts to recover the supervised runtime after a crash.
    async fn recover(&self) -> Result<(), RuntimeError>;
}

/// Ordered runtime adapter registry. The first adapter advertising a model owns it.
#[derive(Clone, Default)]
pub struct RuntimeRegistry {
    adapters: Arc<Vec<Arc<dyn RuntimeAdapter>>>,
}

impl RuntimeRegistry {
    /// Creates a registry in deterministic precedence order.
    #[must_use]
    pub fn new(adapters: Vec<Arc<dyn RuntimeAdapter>>) -> Self {
        Self {
            adapters: Arc::new(adapters),
        }
    }

    /// Returns an adapter for a model alias.
    ///
    /// # Errors
    ///
    /// Returns `ModelUnavailable` when no healthy configured adapter advertises the alias.
    pub async fn adapter_for_model(
        &self,
        model: &str,
    ) -> Result<Arc<dyn RuntimeAdapter>, RuntimeError> {
        for adapter in self.adapters.iter() {
            let capabilities = adapter.capabilities().await?;
            if capabilities
                .models
                .iter()
                .any(|candidate| candidate == model)
            {
                adapter.validate_model(model).await?;
                return Ok(Arc::clone(adapter));
            }
        }
        Err(RuntimeError::ModelUnavailable(model.to_owned()))
    }

    /// Returns an adapter by its stable runtime identifier.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` when the configured registry has no matching adapter.
    pub async fn adapter_by_id(
        &self,
        runtime_id: &str,
    ) -> Result<Arc<dyn RuntimeAdapter>, RuntimeError> {
        for adapter in self.adapters.iter() {
            if adapter.capabilities().await?.runtime_id == runtime_id {
                return Ok(Arc::clone(adapter));
            }
        }
        Err(RuntimeError::Unavailable)
    }

    /// Returns every configured adapter capability declaration.
    ///
    /// # Errors
    ///
    /// Returns the first adapter capability error.
    pub async fn capabilities(&self) -> Result<Vec<RuntimeCapabilities>, RuntimeError> {
        let mut capabilities = Vec::with_capacity(self.adapters.len());
        for adapter in self.adapters.iter() {
            capabilities.push(adapter.capabilities().await?);
        }
        Ok(capabilities)
    }

    /// Returns true when at least one configured adapter is ready.
    pub async fn any_ready(&self) -> bool {
        for adapter in self.adapters.iter() {
            if adapter.health().await == RuntimeHealth::Ready {
                return true;
            }
        }
        false
    }
}

/// Deterministic test runtime requiring no model or accelerator.
#[derive(Debug, Default)]
pub struct MockRuntime {
    cancelled: Arc<Mutex<HashSet<WorkloadId>>>,
}

impl MockRuntime {
    /// Stable runtime identifier.
    pub const ID: &'static str = "mock";
    /// Stable model alias.
    pub const MODEL: &'static str = "constellation/mock";

    fn response(input: &str, max_output_tokens: u32) -> Vec<String> {
        let normalized = input.split_whitespace().collect::<Vec<_>>().join(" ");
        let body = if normalized.is_empty() {
            "Constellation mock response: ready".to_owned()
        } else {
            format!("Constellation mock response: {normalized}")
        };
        body.split_inclusive(' ')
            .take(max_output_tokens as usize)
            .map(str::to_owned)
            .collect()
    }
}

#[async_trait]
impl RuntimeAdapter for MockRuntime {
    async fn detect(&self) -> Result<bool, RuntimeError> {
        Ok(true)
    }

    async fn capabilities(&self) -> Result<RuntimeCapabilities, RuntimeError> {
        Ok(RuntimeCapabilities {
            runtime_id: Self::ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            models: vec![Self::MODEL.to_owned()],
            streaming: true,
            embeddings: true,
            tool_calling: false,
            structured_output: false,
            parallelism: vec!["single_node".to_owned(), "independent_routing".to_owned()],
            cancellation: true,
            recovery: false,
        })
    }

    async fn validate_model(&self, model: &str) -> Result<(), RuntimeError> {
        if model == Self::MODEL {
            Ok(())
        } else {
            Err(RuntimeError::ModelUnavailable(model.to_owned()))
        }
    }

    async fn estimate(&self, _request: &RuntimeRequest) -> Result<RuntimeEstimate, RuntimeError> {
        Ok(RuntimeEstimate {
            memory_bytes: 64 * 1024 * 1024,
            time_to_first_token_ms: 5.0,
            tokens_per_second: 1_000.0,
            confidence: 1.0,
        })
    }

    async fn load(&self, model: &str) -> Result<(), RuntimeError> {
        self.validate_model(model).await
    }

    async fn execute_stream(
        &self,
        request: RuntimeRequest,
    ) -> Result<mpsc::Receiver<RuntimeEvent>, RuntimeError> {
        self.validate_model(&request.model).await?;
        self.cancelled.lock().await.remove(&request.workload_id);
        let events = Self::response(&request.input, request.max_output_tokens);
        let input_tokens =
            u32::try_from(request.input.split_whitespace().count()).unwrap_or(u32::MAX);
        let output_tokens = u32::try_from(events.len()).unwrap_or(u32::MAX);
        let (sender, receiver) = mpsc::channel(32);
        let cancelled = Arc::clone(&self.cancelled);
        let workload_id = request.workload_id;
        tokio::spawn(async move {
            if sender
                .send(RuntimeEvent::Prefill { elapsed_ms: 5 })
                .await
                .is_err()
            {
                return;
            }
            for event in events {
                tokio::time::sleep(Duration::from_millis(8)).await;
                if cancelled.lock().await.remove(&workload_id) {
                    let _ignored = sender.send(RuntimeEvent::Cancelled).await;
                    return;
                }
                if sender.send(RuntimeEvent::TextDelta(event)).await.is_err() {
                    return;
                }
            }
            let _ignored = sender
                .send(RuntimeEvent::Finished {
                    input_tokens,
                    output_tokens,
                    finish_reason: "stop".to_owned(),
                })
                .await;
        });
        Ok(receiver)
    }

    async fn cancel(&self, workload_id: WorkloadId) -> Result<(), RuntimeError> {
        self.cancelled.lock().await.insert(workload_id);
        Ok(())
    }

    async fn unload(&self, model: &str) -> Result<(), RuntimeError> {
        self.validate_model(model).await
    }

    async fn health(&self) -> RuntimeHealth {
        RuntimeHealth::Ready
    }

    async fn metrics(&self) -> RuntimeMetrics {
        RuntimeMetrics {
            active_requests: 0,
            total_requests: 0,
            failed_requests: 0,
            model_loaded: true,
        }
    }

    async fn recover(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use constellation_core::{ExecutionStrategy, PlanId, PrivacyPath, WorkloadId};

    use super::*;

    fn request() -> RuntimeRequest {
        let workload_id = WorkloadId::new();
        RuntimeRequest {
            workload_id,
            model: MockRuntime::MODEL.to_owned(),
            input: "hello cluster".to_owned(),
            max_output_tokens: 32,
            plan: ExecutionPlan {
                id: PlanId::new(),
                workload_id,
                strategy: ExecutionStrategy::SingleNode,
                selected_nodes: Vec::new(),
                estimated_ttft_ms: 5.0,
                estimated_tokens_per_second: 100.0,
                estimated_memory_bytes: BTreeMap::new(),
                estimated_network_bytes: 0,
                confidence: 1.0,
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
                created_at: Utc::now(),
            },
        }
    }

    #[tokio::test]
    async fn mock_runtime_stream_is_deterministic() {
        let runtime = MockRuntime::default();
        let first_result = runtime.execute_stream(request()).await;
        let second_result = runtime.execute_stream(request()).await;
        let mut first = first_result.unwrap_or_else(|error| panic!("stream failed: {error}"));
        let mut second = second_result.unwrap_or_else(|error| panic!("stream failed: {error}"));
        let mut first_text = String::new();
        let mut second_text = String::new();
        while let Some(event) = first.recv().await {
            if let RuntimeEvent::TextDelta(delta) = event {
                first_text.push_str(&delta);
            }
        }
        while let Some(event) = second.recv().await {
            if let RuntimeEvent::TextDelta(delta) = event {
                second_text.push_str(&delta);
            }
        }
        assert_eq!(first_text, second_text);
        assert_eq!(first_text, "Constellation mock response: hello cluster");
    }

    #[tokio::test]
    async fn mock_runtime_cancellation_stops_before_output() {
        let runtime = MockRuntime::default();
        let request = request();
        let workload_id = request.workload_id;
        let stream = runtime.execute_stream(request).await;
        let mut receiver = stream.unwrap_or_else(|error| panic!("stream failed: {error}"));
        assert!(matches!(
            receiver.recv().await,
            Some(RuntimeEvent::Prefill { .. })
        ));
        assert!(runtime.cancel(workload_id).await.is_ok());
        assert!(matches!(
            receiver.recv().await,
            Some(RuntimeEvent::Cancelled)
        ));
        assert!(receiver.recv().await.is_none());
    }
}
