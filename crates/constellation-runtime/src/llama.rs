use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use constellation_core::WorkloadId;
use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::{
    RuntimeAdapter, RuntimeCapabilities, RuntimeError, RuntimeEstimate, RuntimeEvent,
    RuntimeHealth, RuntimeMetrics, RuntimeRequest,
};

/// Launch configuration for one isolated `llama-server` model process.
#[derive(Debug, Clone)]
pub struct LlamaServerConfig {
    /// `llama-server` executable or resolvable command name.
    pub binary_path: PathBuf,
    /// Verified materialized GGUF model.
    pub model_path: PathBuf,
    /// Public model alias exposed by Constellation.
    pub model_alias: String,
    /// Private directory for the per-process API-key file.
    pub state_directory: PathBuf,
    /// Runtime context window.
    pub context_size: u32,
    /// Layers requested on the detected accelerator. Zero is CPU-only.
    pub gpu_layers: u32,
    /// Maximum time allowed for initial model load.
    pub startup_timeout: Duration,
}

impl LlamaServerConfig {
    /// Creates a conservative local-only configuration.
    #[must_use]
    pub fn local(
        binary_path: impl Into<PathBuf>,
        model_path: impl Into<PathBuf>,
        model_alias: impl Into<String>,
        state_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary_path: binary_path.into(),
            model_path: model_path.into(),
            model_alias: model_alias.into(),
            state_directory: state_directory.into(),
            context_size: 4_096,
            gpu_layers: 0,
            startup_timeout: Duration::from_mins(3),
        }
    }
}

#[derive(Debug, Clone)]
struct Connection {
    endpoint: String,
    api_key: String,
}

#[derive(Debug, Default)]
struct ProcessState {
    child: Option<Child>,
    connection: Option<Connection>,
    key_file: Option<PathBuf>,
}

/// Supervised `llama-server` adapter bound exclusively to loopback.
#[derive(Debug)]
pub struct LlamaServerAdapter {
    config: LlamaServerConfig,
    client: reqwest::Client,
    process: Mutex<ProcessState>,
    cancelled: Arc<Mutex<HashSet<WorkloadId>>>,
    active_requests: Arc<AtomicU64>,
    total_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
}

impl LlamaServerAdapter {
    /// Stable runtime identifier.
    pub const ID: &'static str = "llama.cpp";

    /// Creates a supervised adapter without starting the child process.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded local HTTP client cannot be constructed.
    pub fn new(config: LlamaServerConfig) -> Result<Self, RuntimeError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_hours(1))
            .build()
            .map_err(|_| RuntimeError::Execution("create local runtime client".to_owned()))?;
        Ok(Self {
            config,
            client,
            process: Mutex::new(ProcessState::default()),
            cancelled: Arc::new(Mutex::new(HashSet::new())),
            active_requests: Arc::new(AtomicU64::new(0)),
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
        })
    }

    async fn ensure_started(&self) -> Result<Connection, RuntimeError> {
        {
            let mut state = self.process.lock().await;
            if let Some(child) = state.child.as_mut() {
                match child.try_wait() {
                    Ok(None) => {
                        if let Some(connection) = state.connection.clone() {
                            return Ok(connection);
                        }
                    }
                    Ok(Some(_)) => clear_stopped_state(&mut state).await,
                    Err(_) => return Err(RuntimeError::Unavailable),
                }
            }
        }

        self.validate_model(&self.config.model_alias).await?;
        fs::create_dir_all(&self.config.state_directory)
            .await
            .map_err(|_| RuntimeError::Execution("prepare runtime state".to_owned()))?;
        let port = reserve_loopback_port().await?;
        let api_key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let key_file = self
            .config
            .state_directory
            .join(format!("llama-{}.key", Uuid::now_v7()));
        write_private_key(&key_file, &api_key).await?;
        let endpoint = format!("http://127.0.0.1:{port}");
        let mut command = Command::new(&self.config.binary_path);
        command
            .arg("--model")
            .arg(&self.config.model_path)
            .arg("--alias")
            .arg(&self.config.model_alias)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--api-key-file")
            .arg(&key_file)
            .arg("--ctx-size")
            .arg(self.config.context_size.to_string())
            .arg("--n-gpu-layers")
            .arg(self.config.gpu_layers.to_string())
            .arg("--metrics")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(child) = command.spawn() else {
            let _cleanup = fs::remove_file(&key_file).await;
            return Err(RuntimeError::Unavailable);
        };
        let connection = Connection { endpoint, api_key };
        {
            let mut state = self.process.lock().await;
            state.child = Some(child);
            state.connection = Some(connection.clone());
            state.key_file = Some(key_file);
        }

        let started = Instant::now();
        loop {
            if self.probe(&connection).await == RuntimeHealth::Ready {
                return Ok(connection);
            }
            if started.elapsed() >= self.config.startup_timeout {
                self.stop().await;
                return Err(RuntimeError::Unavailable);
            }
            {
                let mut state = self.process.lock().await;
                if let Some(child) = state.child.as_mut()
                    && child.try_wait().ok().flatten().is_some()
                {
                    clear_stopped_state(&mut state).await;
                    return Err(RuntimeError::Unavailable);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn probe(&self, connection: &Connection) -> RuntimeHealth {
        match self
            .client
            .get(format!("{}/health", connection.endpoint))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => RuntimeHealth::Ready,
            Ok(response) if response.status() == StatusCode::SERVICE_UNAVAILABLE => {
                RuntimeHealth::Degraded
            }
            Ok(_) | Err(_) => RuntimeHealth::Unavailable,
        }
    }

    async fn stop(&self) {
        let mut state = self.process.lock().await;
        if let Some(mut child) = state.child.take() {
            let _termination = child.kill().await;
            let _wait = child.wait().await;
        }
        if let Some(path) = state.key_file.take() {
            let _cleanup = fs::remove_file(path).await;
        }
        state.connection = None;
    }
}

#[async_trait]
impl RuntimeAdapter for LlamaServerAdapter {
    async fn detect(&self) -> Result<bool, RuntimeError> {
        if fs::metadata(&self.config.model_path).await.is_err() {
            return Ok(false);
        }
        Ok(Command::new(&self.config.binary_path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|status| status.success()))
    }

    async fn capabilities(&self) -> Result<RuntimeCapabilities, RuntimeError> {
        Ok(RuntimeCapabilities {
            runtime_id: Self::ID.to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            models: vec![self.config.model_alias.clone()],
            streaming: true,
            embeddings: false,
            tool_calling: false,
            structured_output: false,
            parallelism: vec!["single_node".to_owned(), "independent_routing".to_owned()],
            cancellation: true,
            recovery: true,
        })
    }

    async fn validate_model(&self, model: &str) -> Result<(), RuntimeError> {
        if model != self.config.model_alias {
            return Err(RuntimeError::ModelUnavailable(model.to_owned()));
        }
        let metadata = fs::metadata(&self.config.model_path)
            .await
            .map_err(|_| RuntimeError::ModelUnavailable(model.to_owned()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(RuntimeError::ModelUnavailable(model.to_owned()));
        }
        Ok(())
    }

    async fn estimate(&self, request: &RuntimeRequest) -> Result<RuntimeEstimate, RuntimeError> {
        self.validate_model(&request.model).await?;
        let size = fs::metadata(&self.config.model_path)
            .await
            .map_err(|_| RuntimeError::ModelUnavailable(request.model.clone()))?
            .len();
        Ok(RuntimeEstimate {
            memory_bytes: size.saturating_add(size / 5),
            time_to_first_token_ms: 800.0,
            tokens_per_second: 10.0,
            confidence: 0.35,
        })
    }

    async fn load(&self, model: &str) -> Result<(), RuntimeError> {
        self.validate_model(model).await?;
        let _connection = self.ensure_started().await?;
        Ok(())
    }

    async fn execute_stream(
        &self,
        request: RuntimeRequest,
    ) -> Result<mpsc::Receiver<RuntimeEvent>, RuntimeError> {
        self.validate_model(&request.model).await?;
        let connection = self.ensure_started().await?;
        self.cancelled.lock().await.remove(&request.workload_id);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(64);
        let client = self.client.clone();
        let cancelled = Arc::clone(&self.cancelled);
        let active = Arc::clone(&self.active_requests);
        let failed = Arc::clone(&self.failed_requests);
        tokio::spawn(async move {
            run_stream(client, connection, request, &sender, &cancelled, &failed).await;
            active.fetch_sub(1, Ordering::Relaxed);
        });
        Ok(receiver)
    }

    async fn cancel(&self, workload_id: WorkloadId) -> Result<(), RuntimeError> {
        self.cancelled.lock().await.insert(workload_id);
        Ok(())
    }

    async fn unload(&self, model: &str) -> Result<(), RuntimeError> {
        self.validate_model(model).await?;
        self.stop().await;
        Ok(())
    }

    async fn health(&self) -> RuntimeHealth {
        let connection = {
            let mut state = self.process.lock().await;
            let Some(child) = state.child.as_mut() else {
                return RuntimeHealth::Unavailable;
            };
            if child.try_wait().ok().flatten().is_some() {
                clear_stopped_state(&mut state).await;
                return RuntimeHealth::Unavailable;
            }
            state.connection.clone()
        };
        match connection {
            Some(value) => self.probe(&value).await,
            None => RuntimeHealth::Unavailable,
        }
    }

    async fn metrics(&self) -> RuntimeMetrics {
        let model_loaded = {
            let mut state = self.process.lock().await;
            state
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_none())
        };
        RuntimeMetrics {
            active_requests: self.active_requests.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            model_loaded,
        }
    }

    async fn recover(&self) -> Result<(), RuntimeError> {
        self.stop().await;
        let _connection = self.ensure_started().await?;
        Ok(())
    }
}

impl Drop for LlamaServerAdapter {
    fn drop(&mut self) {
        if let Ok(mut state) = self.process.try_lock() {
            if let Some(child) = state.child.as_mut() {
                let _termination = child.start_kill();
            }
            if let Some(path) = state.key_file.take() {
                let _cleanup = std::fs::remove_file(path);
            }
        }
    }
}

#[allow(clippy::too_many_lines)] // Keeping SSE terminal-state transitions in one auditable loop avoids split-brain completion handling.
async fn run_stream(
    client: reqwest::Client,
    connection: Connection,
    request: RuntimeRequest,
    sender: &mpsc::Sender<RuntimeEvent>,
    cancelled: &Mutex<HashSet<WorkloadId>>,
    failed_requests: &AtomicU64,
) {
    let input_tokens = u32::try_from(request.input.split_whitespace().count()).unwrap_or(u32::MAX);
    let response = client
        .post(format!("{}/v1/chat/completions", connection.endpoint))
        .bearer_auth(connection.api_key)
        .json(&json!({
            "model": request.model,
            "messages": [{"role": "user", "content": request.input}],
            "max_tokens": request.max_output_tokens,
            "stream": true
        }))
        .send()
        .await;
    let Ok(response) = response else {
        send_failure(sender, failed_requests, false).await;
        return;
    };
    if !response.status().is_success() {
        send_failure(sender, failed_requests, false).await;
        return;
    }
    if sender
        .send(RuntimeEvent::Prefill { elapsed_ms: 0 })
        .await
        .is_err()
    {
        return;
    }

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut output_started = false;
    let mut output_tokens = 0_u32;
    let mut completed = false;
    while let Some(item) = stream.next().await {
        if cancelled.lock().await.remove(&request.workload_id) {
            let _cancelled = sender.send(RuntimeEvent::Cancelled).await;
            return;
        }
        let Ok(bytes) = item else {
            send_failure(sender, failed_requests, output_started).await;
            return;
        };
        buffer.push_str(&String::from_utf8_lossy(&bytes));
        buffer = buffer.replace("\r\n", "\n");
        while let Some(boundary) = buffer.find("\n\n") {
            let frame = buffer[..boundary].to_owned();
            buffer.drain(..boundary + 2);
            for line in frame.lines() {
                let Some(data) = line.strip_prefix("data: ") else {
                    continue;
                };
                if data == "[DONE]" {
                    if !completed {
                        let _finished = sender
                            .send(RuntimeEvent::Finished {
                                input_tokens,
                                output_tokens,
                                finish_reason: "stop".to_owned(),
                            })
                            .await;
                        completed = true;
                    }
                    continue;
                }
                let Ok(value) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                if let Some(delta) = value
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
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
                if let Some(reason) = value
                    .pointer("/choices/0/finish_reason")
                    .and_then(Value::as_str)
                {
                    let _finished = sender
                        .send(RuntimeEvent::Finished {
                            input_tokens,
                            output_tokens,
                            finish_reason: reason.to_owned(),
                        })
                        .await;
                    completed = true;
                }
            }
        }
    }
    if !completed {
        send_failure(sender, failed_requests, output_started).await;
    }
}

async fn send_failure(
    sender: &mpsc::Sender<RuntimeEvent>,
    failed_requests: &AtomicU64,
    output_started: bool,
) {
    failed_requests.fetch_add(1, Ordering::Relaxed);
    let _failure = sender
        .send(RuntimeEvent::Failure {
            code: if output_started {
                "generation_interrupted".to_owned()
            } else {
                "runtime_unavailable".to_owned()
            },
            message: if output_started {
                "generation stopped after partial output".to_owned()
            } else {
                "runtime could not start generation".to_owned()
            },
            retryable: !output_started,
            output_started,
        })
        .await;
}

async fn reserve_loopback_port() -> Result<u16, RuntimeError> {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(|_| RuntimeError::Unavailable)?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| RuntimeError::Unavailable)
}

async fn write_private_key(path: &PathBuf, api_key: &str) -> Result<(), RuntimeError> {
    fs::write(path, api_key)
        .await
        .map_err(|_| RuntimeError::Execution("write runtime credential".to_owned()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|_| RuntimeError::Execution("protect runtime credential".to_owned()))?;
    }
    Ok(())
}

async fn clear_stopped_state(state: &mut ProcessState) {
    state.child = None;
    state.connection = None;
    if let Some(path) = state.key_file.take() {
        let _cleanup = fs::remove_file(path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_config_is_conservative() {
        let config = LlamaServerConfig::local(
            "llama-server",
            "/models/example.gguf",
            "example/model",
            "/runtime",
        );
        assert_eq!(config.context_size, 4_096);
        assert_eq!(config.gpu_layers, 0);
        assert_eq!(config.startup_timeout, Duration::from_mins(3));
    }

    #[tokio::test]
    async fn missing_model_is_not_detected() {
        let config = LlamaServerConfig::local(
            "llama-server-does-not-exist",
            format!("/missing/{}.gguf", Uuid::now_v7()),
            "missing/model",
            std::env::temp_dir(),
        );
        let adapter_result = LlamaServerAdapter::new(config);
        assert!(adapter_result.is_ok());
        let adapter = adapter_result.unwrap_or_else(|error| panic!("adapter: {error}"));
        assert!(matches!(adapter.detect().await, Ok(false)));
    }
}
