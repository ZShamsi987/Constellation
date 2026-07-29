//! Pinned EXO HTTP sidecar adapter. No EXO implementation code is linked into Constellation.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use constellation_core::WorkloadId;
use futures_util::StreamExt as _;
use reqwest::Client;
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc};

use crate::{
    RuntimeAdapter, RuntimeCapabilities, RuntimeError, RuntimeEstimate, RuntimeEvent,
    RuntimeHealth, RuntimeMetrics, RuntimeRequest,
};

/// Reviewed upstream revision used for compatibility gating.
pub const PINNED_EXO_REVISION: &str = "b5375f8cee4368d09e1ce96a56b9f81fb0bc81aa";

/// Configuration for an independently installed EXO API sidecar.
#[derive(Debug, Clone)]
pub struct ExoSidecarConfig {
    /// Loopback EXO API origin.
    pub endpoint: String,
    /// Exact upstream Git revision of the installed sidecar.
    pub revision: String,
    /// EXO/Hugging Face model identifier.
    pub model_alias: String,
}

impl ExoSidecarConfig {
    /// Validates loopback isolation and the reviewed upstream revision.
    ///
    /// # Errors
    ///
    /// Returns an execution error for remote endpoints, empty model aliases, or revision drift.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        let endpoint = self.endpoint.trim_end_matches('/');
        if !(endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("http://localhost:"))
        {
            return Err(RuntimeError::Execution(
                "EXO integration is restricted to an explicit loopback sidecar".to_owned(),
            ));
        }
        if self.revision != PINNED_EXO_REVISION {
            return Err(RuntimeError::Execution(format!(
                "EXO revision is not the reviewed pin {PINNED_EXO_REVISION}"
            )));
        }
        if self.model_alias.trim().is_empty() {
            return Err(RuntimeError::ModelUnavailable(self.model_alias.clone()));
        }
        Ok(())
    }
}

/// HTTP translation boundary for a separately installed EXO cluster.
#[derive(Debug)]
pub struct ExoSidecarAdapter {
    config: ExoSidecarConfig,
    client: Client,
    cancelled: Arc<Mutex<HashSet<WorkloadId>>>,
    active_requests: Arc<AtomicU64>,
    total_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
}

impl ExoSidecarAdapter {
    /// Stable runtime identifier.
    pub const ID: &'static str = "exo";

    /// Constructs an adapter after validating its trust boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration is not pinned and loopback-only.
    pub fn new(config: ExoSidecarConfig) -> Result<Self, RuntimeError> {
        config.validate()?;
        Ok(Self {
            config,
            client: Client::new(),
            cancelled: Arc::new(Mutex::new(HashSet::new())),
            active_requests: Arc::new(AtomicU64::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.endpoint.trim_end_matches('/'), path)
    }

    async fn placement_strategies(&self) -> Result<Vec<String>, RuntimeError> {
        let response = self
            .client
            .get(self.endpoint("/instance/previews"))
            .query(&[("model_id", self.config.model_alias.as_str())])
            .send()
            .await
            .map_err(|_| RuntimeError::Unavailable)?;
        if !response.status().is_success() {
            return Err(RuntimeError::Unavailable);
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| RuntimeError::Execution("EXO placement response is invalid".to_owned()))?;
        let mut strategies = Vec::new();
        for preview in body
            .get("previews")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !preview.get("error").is_none_or(Value::is_null) {
                continue;
            }
            let Some(sharding) = preview.get("sharding").and_then(Value::as_str) else {
                continue;
            };
            let normalized = match sharding.to_ascii_lowercase().as_str() {
                "pipeline" => "pipeline",
                "tensor" | "tensorparallel" | "tensor_parallel" => "tensor",
                _ => continue,
            };
            if !strategies.iter().any(|value| value == normalized) {
                strategies.push(normalized.to_owned());
            }
        }
        strategies.sort();
        Ok(strategies)
    }
}

#[async_trait]
impl RuntimeAdapter for ExoSidecarAdapter {
    async fn detect(&self) -> Result<bool, RuntimeError> {
        if cfg!(target_os = "windows") {
            return Ok(false);
        }
        Ok(self.placement_strategies().await.is_ok())
    }

    async fn capabilities(&self) -> Result<RuntimeCapabilities, RuntimeError> {
        let strategies = self.placement_strategies().await?;
        Ok(RuntimeCapabilities {
            runtime_id: Self::ID.to_owned(),
            adapter_version: format!(
                "{}+exo.{}",
                env!("CARGO_PKG_VERSION"),
                &self.config.revision[..12]
            ),
            models: vec![self.config.model_alias.clone()],
            streaming: true,
            embeddings: false,
            tool_calling: false,
            structured_output: false,
            parallelism: strategies,
            cancellation: true,
            recovery: false,
        })
    }

    async fn validate_model(&self, model: &str) -> Result<(), RuntimeError> {
        if model != self.config.model_alias {
            return Err(RuntimeError::ModelUnavailable(model.to_owned()));
        }
        if self.placement_strategies().await?.is_empty() {
            return Err(RuntimeError::ModelUnavailable(model.to_owned()));
        }
        Ok(())
    }

    async fn estimate(&self, request: &RuntimeRequest) -> Result<RuntimeEstimate, RuntimeError> {
        self.validate_model(&request.model).await?;
        Ok(RuntimeEstimate {
            memory_bytes: request.plan.estimated_memory_bytes.values().copied().sum(),
            time_to_first_token_ms: request.plan.estimated_ttft_ms,
            tokens_per_second: request.plan.estimated_tokens_per_second,
            confidence: request.plan.confidence.min(0.8),
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
        let response = self
            .client
            .post(self.endpoint("/v1/chat/completions"))
            .json(&json!({
                "model": request.model,
                "messages": [{"role": "user", "content": request.input}],
                "max_tokens": request.max_output_tokens,
                "stream": true,
            }))
            .send()
            .await
            .map_err(|_| RuntimeError::Unavailable)?;
        if !response.status().is_success() {
            return Err(RuntimeError::Execution(format!(
                "EXO rejected inference with status {}",
                response.status()
            )));
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        let cancelled = Arc::clone(&self.cancelled);
        let active = Arc::clone(&self.active_requests);
        let failed = Arc::clone(&self.failed_requests);
        tokio::spawn(async move {
            translate_exo_stream(response, request.workload_id, &sender, &cancelled, &failed).await;
            active.fetch_sub(1, Ordering::Relaxed);
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
        if self.detect().await.unwrap_or(false) {
            RuntimeHealth::Ready
        } else {
            RuntimeHealth::Unavailable
        }
    }

    async fn metrics(&self) -> RuntimeMetrics {
        RuntimeMetrics {
            active_requests: self.active_requests.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            model_loaded: false,
        }
    }

    async fn recover(&self) -> Result<(), RuntimeError> {
        Err(RuntimeError::UnsupportedFeature(
            "EXO sidecar recovery is owned by its external supervisor".to_owned(),
        ))
    }
}

async fn translate_exo_stream(
    response: reqwest::Response,
    workload_id: WorkloadId,
    sender: &mpsc::Sender<RuntimeEvent>,
    cancelled: &Mutex<HashSet<WorkloadId>>,
    failed: &AtomicU64,
) {
    let mut bytes = response.bytes_stream();
    let mut buffer = String::new();
    let mut output_started = false;
    let mut output_tokens = 0_u32;
    while let Some(chunk) = bytes.next().await {
        if cancelled.lock().await.remove(&workload_id) {
            let _ignored = sender.send(RuntimeEvent::Cancelled).await;
            return;
        }
        let Ok(chunk) = chunk else {
            break;
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        buffer = buffer.replace("\r\n", "\n");
        while let Some(boundary) = buffer.find("\n\n") {
            let frame = buffer[..boundary].to_owned();
            buffer.drain(..boundary + 2);
            for data in frame.lines().filter_map(|line| line.strip_prefix("data: ")) {
                if data == "[DONE]" {
                    let _ignored = sender
                        .send(RuntimeEvent::Finished {
                            input_tokens: 0,
                            output_tokens,
                            finish_reason: "stop".to_owned(),
                        })
                        .await;
                    return;
                }
                let Ok(value) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                if let Some(delta) = value
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    output_started = true;
                    output_tokens = output_tokens.saturating_add(1);
                    if sender
                        .send(RuntimeEvent::TextDelta(delta.to_owned()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
    failed.fetch_add(1, Ordering::Relaxed);
    let _ignored = sender
        .send(RuntimeEvent::Failure {
            code: if output_started {
                "generation_interrupted".to_owned()
            } else {
                "exo_unavailable".to_owned()
            },
            message: "EXO sidecar stream ended unexpectedly".to_owned(),
            retryable: !output_started,
            output_started,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_loopback_and_revision_pinned() {
        let valid = ExoSidecarConfig {
            endpoint: "http://127.0.0.1:52415".to_owned(),
            revision: PINNED_EXO_REVISION.to_owned(),
            model_alias: "example/model".to_owned(),
        };
        assert!(valid.validate().is_ok());
        let mut remote = valid.clone();
        remote.endpoint = "https://exo.example.test".to_owned();
        assert!(remote.validate().is_err());
        let mut drifted = valid;
        drifted.revision = "main".to_owned();
        assert!(drifted.validate().is_err());
    }
}
