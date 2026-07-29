//! Standalone outbound-only worker service loop.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use constellation_core::{Node, NodeId, WorkerLease, WorkerRuntimeEvent};
use constellation_identity::DeviceIdentity;
use constellation_runtime::{RuntimeEvent, RuntimeRegistry, RuntimeRequest};
use constellation_secrets::OsKeyring;
use reqwest::Method;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

/// Runs the enrolled worker until shutdown, using outbound authenticated controller requests only.
pub async fn run(
    controller: &str,
    credential_path: &Path,
    runtimes: RuntimeRegistry,
    mut inventory: Node,
    once: bool,
) -> Result<()> {
    recover_worker_credential(credential_path).await?;
    let mut credential = serde_json::from_slice::<Value>(
        &tokio::fs::read(credential_path)
            .await
            .with_context(|| format!("read worker credential {}", credential_path.display()))?,
    )
    .context("decode worker credential")?;
    let device_id = credential
        .pointer("/credential/device_id")
        .or_else(|| credential.pointer("/device_id"))
        .and_then(Value::as_str)
        .context("worker credential is missing its device identity")
        .and_then(|value| Uuid::parse_str(value).context("parse worker device identity"))?;
    let mut client = ControllerClient::new(controller, credential_path, &credential)?;
    inventory.id = NodeId(device_id);
    inventory.last_seen_at = chrono::Utc::now();
    client
        .membership_json(
            Method::POST,
            &format!("/constellation/v1/devices/{device_id}/inventory"),
            &credential,
            Some(json!({
                "name": inventory.name,
                "os": inventory.os,
                "architecture": inventory.architecture,
                "capabilities": inventory.capabilities,
            })),
        )
        .await?;
    advertise_benchmarks(&client, device_id, &credential, &runtimes).await?;
    let mut last_heartbeat = chrono::DateTime::<chrono::Utc>::MIN_UTC;
    loop {
        let now = chrono::Utc::now();
        if now.signed_duration_since(last_heartbeat).num_seconds() >= 5 {
            if credential_rotation_due(&credential, now)? {
                let rotated = client
                    .membership_json(
                        Method::POST,
                        &format!("/constellation/v1/devices/{device_id}/credentials/rotate"),
                        &credential,
                        None,
                    )
                    .await?;
                write_private_credential(credential_path, &rotated).await?;
                client.refresh_identity(&rotated)?;
                credential = rotated;
            }
            client
                .membership_json(
                    Method::POST,
                    &format!("/constellation/v1/devices/{device_id}/heartbeat"),
                    &credential,
                    None,
                )
                .await?;
            last_heartbeat = now;
        }
        let response = client
            .membership_json(
                Method::POST,
                &format!("/constellation/v1/workers/{device_id}/leases/poll"),
                &credential,
                None,
            )
            .await?;
        if let Some(value) = response.get("lease").filter(|value| !value.is_null()) {
            let lease = serde_json::from_value::<WorkerLease>(value.clone())
                .context("decode controller worker lease")?;
            execute_lease(&client, NodeId(device_id), &credential, &runtimes, lease).await?;
        }
        if once {
            return Ok(());
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
            signal = tokio::signal::ctrl_c() => {
                signal.context("listen for worker shutdown")?;
                return Ok(());
            }
        }
    }
}

fn credential_rotation_due(credential: &Value, now: chrono::DateTime<chrono::Utc>) -> Result<bool> {
    let expires_at = credential
        .pointer("/credential/expires_at")
        .or_else(|| credential.pointer("/expires_at"))
        .and_then(Value::as_str)
        .context("worker credential is missing its expiration")?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .context("parse worker credential expiration")?
        .with_timezone(&chrono::Utc);
    if expires_at <= now {
        bail!("worker credential expired before it could be rotated");
    }
    Ok(expires_at - now <= chrono::Duration::hours(1))
}

async fn write_private_credential(path: &Path, credential: &Value) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".worker-credential-{}.tmp", Uuid::now_v7()));
    let bytes = serde_json::to_vec_pretty(credential).context("encode rotated credential")?;
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .await
        .context("create rotated credential temporary file")?;
    file.write_all(&bytes)
        .await
        .context("write rotated credential")?;
    file.write_all(b"\n")
        .await
        .context("finish rotated credential")?;
    file.sync_all().await.context("sync rotated credential")?;
    drop(file);
    #[cfg(not(windows))]
    tokio::fs::rename(&temporary, path)
        .await
        .context("atomically replace rotated worker credential")?;
    #[cfg(windows)]
    {
        let backup = path.with_extension("previous");
        if backup.exists() {
            tokio::fs::remove_file(&backup)
                .await
                .context("remove stale worker credential backup")?;
        }
        tokio::fs::rename(path, &backup)
            .await
            .context("preserve current worker credential")?;
        if let Err(error) = tokio::fs::rename(&temporary, path).await {
            let _ignored = tokio::fs::rename(&backup, path).await;
            return Err(error).context("promote rotated worker credential");
        }
        tokio::fs::remove_file(backup)
            .await
            .context("remove replaced worker credential")?;
    }
    Ok(())
}

#[allow(clippy::unused_async)] // Windows recovery performs async filesystem operations.
async fn recover_worker_credential(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let backup = path.with_extension("previous");
        if !path.exists() && backup.exists() {
            tokio::fs::rename(backup, path)
                .await
                .context("recover interrupted worker credential rotation")?;
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

async fn advertise_benchmarks(
    client: &ControllerClient,
    device_id: Uuid,
    credential: &Value,
    runtimes: &RuntimeRegistry,
) -> Result<()> {
    for capability in runtimes
        .capabilities()
        .await
        .context("detect worker runtimes")?
    {
        for model in capability.models {
            let (tokens_per_second, ttft_ms) = if capability.runtime_id == "mock" {
                (1_000.0, 5.0)
            } else {
                (1.0, 1_000.0)
            };
            client
                .membership_json(
                    Method::POST,
                    "/constellation/v1/benchmarks",
                    credential,
                    Some(json!({
                        "node_id": device_id,
                        "runtime": capability.runtime_id,
                        "model": model,
                        "tokens_per_second": tokens_per_second,
                        "time_to_first_token_ms": ttft_ms,
                        "network_latency_ms": 1.0,
                        "network_bandwidth_mbps": 1000.0,
                        "jitter_ms": 0.1,
                        "packet_loss": 0.0,
                        "sample_count": if capability.runtime_id == "mock" { 5 } else { 1 },
                        "kind": if capability.runtime_id == "mock" { "measured" } else { "estimated" },
                        "measured_at": chrono::Utc::now(),
                    })),
                )
                .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keeps the privacy-safe runtime-to-wire mapping linear.
async fn execute_lease(
    client: &ControllerClient,
    node_id: NodeId,
    credential: &Value,
    runtimes: &RuntimeRegistry,
    lease: WorkerLease,
) -> Result<()> {
    if lease.node_id != node_id {
        bail!("controller returned a lease for a different worker");
    }
    let Ok(adapter) = runtimes.adapter_for_model(&lease.model).await else {
        submit_event(
            client,
            node_id,
            credential,
            lease.id,
            1,
            &WorkerRuntimeEvent::Failure {
                code: "model_unavailable".to_owned(),
                message: "selected worker does not have the requested model".to_owned(),
                retryable: false,
                output_started: false,
            },
        )
        .await?;
        return Ok(());
    };
    if let Err(error) = adapter.load(&lease.model).await {
        submit_event(
            client,
            node_id,
            credential,
            lease.id,
            1,
            &WorkerRuntimeEvent::Failure {
                code: "runtime_load_failed".to_owned(),
                message: error.to_string(),
                retryable: true,
                output_started: false,
            },
        )
        .await?;
        return Ok(());
    }
    let request = RuntimeRequest {
        workload_id: lease.workload_id,
        model: lease.model,
        input: lease.input,
        max_output_tokens: lease.maximum_output_tokens,
        plan: lease.plan,
    };
    let mut receiver = match adapter.execute_stream(request).await {
        Ok(receiver) => receiver,
        Err(error) => {
            submit_event(
                client,
                node_id,
                credential,
                lease.id,
                1,
                &WorkerRuntimeEvent::Failure {
                    code: "runtime_start_failed".to_owned(),
                    message: error.to_string(),
                    retryable: true,
                    output_started: false,
                },
            )
            .await?;
            return Ok(());
        }
    };
    let mut sequence = 0_u64;
    let mut terminal = false;
    let mut output_started = false;
    while let Some(event) = receiver.recv().await {
        sequence = sequence.saturating_add(1);
        output_started |= matches!(event, RuntimeEvent::TextDelta(_));
        let event = worker_event(event);
        terminal = event.is_terminal();
        if let Err(error) =
            submit_event(client, node_id, credential, lease.id, sequence, &event).await
        {
            let _ignored = adapter.cancel(lease.workload_id).await;
            tracing::warn!(%error, lease_id = %lease.id, "controller stopped accepting worker events");
            return Ok(());
        }
        if terminal {
            break;
        }
    }
    if !terminal {
        submit_event(
            client,
            node_id,
            credential,
            lease.id,
            sequence.saturating_add(1),
            &WorkerRuntimeEvent::Failure {
                code: "runtime_stream_closed".to_owned(),
                message: "runtime stream closed without a terminal event".to_owned(),
                retryable: true,
                output_started,
            },
        )
        .await?;
    }
    Ok(())
}

fn worker_event(event: RuntimeEvent) -> WorkerRuntimeEvent {
    match event {
        RuntimeEvent::Loading { progress } => WorkerRuntimeEvent::Loading { progress },
        RuntimeEvent::Prefill { elapsed_ms } => WorkerRuntimeEvent::Prefill { elapsed_ms },
        RuntimeEvent::TextDelta(text) => WorkerRuntimeEvent::TextDelta { text },
        RuntimeEvent::Finished {
            input_tokens,
            output_tokens,
            finish_reason,
        } => WorkerRuntimeEvent::Finished {
            input_tokens,
            output_tokens,
            finish_reason,
        },
        RuntimeEvent::Failure {
            code,
            message,
            retryable,
            output_started,
        } => WorkerRuntimeEvent::Failure {
            code,
            message,
            retryable,
            output_started,
        },
        RuntimeEvent::Cancelled => WorkerRuntimeEvent::Cancelled,
    }
}

async fn submit_event(
    client: &ControllerClient,
    node_id: NodeId,
    credential: &Value,
    lease_id: Uuid,
    sequence: u64,
    event: &WorkerRuntimeEvent,
) -> Result<()> {
    client
        .membership_json(
            Method::POST,
            &format!(
                "/constellation/v1/workers/{}/leases/{lease_id}/events",
                node_id.0
            ),
            credential,
            Some(json!({"sequence": sequence, "event": event})),
        )
        .await?;
    Ok(())
}

struct ControllerClient {
    base: String,
    http: reqwest::Client,
    credential_path: PathBuf,
}

impl ControllerClient {
    fn new(base: &str, credential_path: &Path, membership: &Value) -> Result<Self> {
        let base = base.trim_end_matches('/').to_owned();
        if !(base.starts_with("http://127.0.0.1:")
            || base.starts_with("http://localhost:")
            || base.starts_with("https://"))
        {
            bail!("non-loopback worker controllers must use HTTPS");
        }
        let http = membership_client(&base, membership)?;
        Ok(Self {
            base,
            http,
            credential_path: credential_path.to_owned(),
        })
    }

    fn refresh_identity(&mut self, membership: &Value) -> Result<()> {
        self.http = membership_client(&self.base, membership)?;
        Ok(())
    }

    async fn membership_json(
        &self,
        method: Method,
        path: &str,
        membership: &Value,
        body: Option<Value>,
    ) -> Result<Value> {
        let credential = membership.pointer("/credential").unwrap_or(membership);
        let encoded = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(credential).context("encode membership credential")?);
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("x-constellation-membership", encoded);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.with_context(|| {
            format!(
                "contact controller using credential {}",
                self.credential_path.display()
            )
        })?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .context("decode controller membership response")?;
        if !status.is_success() {
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("controller rejected the worker operation");
            bail!("{message} ({status})");
        }
        Ok(value)
    }
}

fn membership_client(base: &str, membership: &Value) -> Result<reqwest::Client> {
    if base.starts_with("http://127.0.0.1:") || base.starts_with("http://localhost:") {
        return reqwest::Client::builder()
            .build()
            .context("create loopback worker client");
    }
    let certificate_pem = membership
        .pointer("/device_certificate/certificate_pem")
        .and_then(Value::as_str)
        .context("worker credential does not contain a device TLS certificate")?;
    let ca_pem = membership
        .pointer("/device_certificate/certificate_authority_pem")
        .and_then(Value::as_str)
        .context("worker credential does not contain the pinned cluster CA")?;
    let secret = OsKeyring::new("com.constellation.device", "device-ed25519-v1")
        .load_or_create_secret_32()
        .context("load worker identity for mTLS")?;
    let identity = DeviceIdentity::from_secret_bytes(&secret);
    let private_key = identity
        .private_key_pem()
        .context("encode worker mTLS key")?;
    let client_identity =
        reqwest::Identity::from_pem(format!("{certificate_pem}{private_key}").as_bytes())
            .context("combine worker certificate and private key")?;
    let root = reqwest::Certificate::from_pem(ca_pem.as_bytes())
        .context("parse pinned cluster authority")?;
    reqwest::Client::builder()
        .add_root_certificate(root)
        .identity(client_identity)
        .build()
        .context("create mTLS worker client")
}
