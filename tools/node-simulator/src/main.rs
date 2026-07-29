//! Deterministic heterogeneous node scenario for demos and integration tests.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Parser;
use constellation_core::{
    BenchmarkReport, ExecutionPlan, MeasurementKind, Node, NodeCapabilities, NodeId, NodeStatus,
    OperatingSystem,
};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Simulator settings.
#[derive(Debug, Parser)]
#[command(name = "constellation-node-simulator", version, about)]
struct Args {
    /// Controller HTTP base URL.
    #[arg(long, default_value = "http://127.0.0.1:4317")]
    controller: String,

    /// Optional bearer API key.
    #[arg(long, env = "CONSTELLATION_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Leave the selected node offline after demonstrating failover.
    #[arg(long, default_value_t = false)]
    leave_failed: bool,
}

#[derive(Debug, Clone)]
struct SimulatedNode {
    name: &'static str,
    os: OperatingSystem,
    architecture: &'static str,
    cpu: &'static str,
    cores: u16,
    memory_gib: u64,
    accelerator: Option<Value>,
    tokens_per_second: f64,
    ttft_ms: f64,
    latency_ms: f64,
    user_active: bool,
    on_battery: bool,
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // The scenario is intentionally linear and auditable.
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = Client::builder()
        .user_agent(concat!(
            "constellation-simulator/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("build HTTP client")?;
    let base = args.controller.trim_end_matches('/');
    wait_until_ready(&client, base).await?;

    let mut known: Vec<Node> = send_json(authenticated(
        client.get(format!("{base}/constellation/v1/devices")),
        &args,
    ))
    .await?;
    let mut simulated = Vec::new();
    for spec in scenario_nodes() {
        let node = if let Some(existing) = known.iter().find(|node| node.name == spec.name) {
            set_status(&client, base, &args, existing.id, NodeStatus::Ready).await?;
            let mut ready = existing.clone();
            ready.status = NodeStatus::Ready;
            ready
        } else {
            let created: Node = send_json(authenticated(
                client
                    .post(format!("{base}/constellation/v1/devices"))
                    .json(&registration(&spec)),
                &args,
            ))
            .await?;
            known.push(created.clone());
            created
        };
        let benchmark = BenchmarkReport {
            node_id: node.id,
            runtime: "mock".to_owned(),
            model: "constellation/mock".to_owned(),
            tokens_per_second: spec.tokens_per_second,
            time_to_first_token_ms: spec.ttft_ms,
            network_latency_ms: spec.latency_ms,
            network_bandwidth_mbps: if spec.latency_ms > 20.0 {
                80.0
            } else {
                1_000.0
            },
            jitter_ms: if spec.latency_ms > 20.0 { 8.0 } else { 0.3 },
            packet_loss: if spec.latency_ms > 20.0 { 0.01 } else { 0.0 },
            sample_count: 5,
            kind: MeasurementKind::Measured,
            measured_at: Utc::now(),
        };
        let _: BenchmarkReport = send_json(authenticated(
            client
                .post(format!("{base}/constellation/v1/benchmarks"))
                .json(&benchmark),
            &args,
        ))
        .await?;
        simulated.push(node);
    }

    let initial_plan: ExecutionPlan = send_json(authenticated(
        client
            .post(format!("{base}/constellation/v1/plans/simulate"))
            .json(&json!({
                "model": "constellation/mock",
                "required_runtime": "mock",
                "estimated_memory_bytes": 2_u64 * 1024 * 1024 * 1024,
                "class": "interactive",
                "policy": "keep_this_computer_responsive"
            })),
        &args,
    ))
    .await?;

    let chat: Value = send_json(authenticated(
        client
            .post(format!("{base}/v1/chat/completions"))
            .json(&json!({
                "model": "constellation/mock",
                "messages": [{"role": "user", "content": "verify the private cluster"}],
                "stream": false
            })),
        &args,
    ))
    .await?;

    let failed = initial_plan
        .selected_nodes
        .first()
        .copied()
        .context("initial plan selected no node")?;
    set_status(&client, base, &args, failed, NodeStatus::Offline).await?;
    let failover_plan: ExecutionPlan = send_json(authenticated(
        client
            .post(format!("{base}/constellation/v1/plans/simulate"))
            .json(&json!({
                "model": "constellation/mock",
                "required_runtime": "mock",
                "estimated_memory_bytes": 2_u64 * 1024 * 1024 * 1024,
                "class": "interactive",
                "policy": "keep_this_computer_responsive"
            })),
        &args,
    ))
    .await?;
    if failover_plan.selected_nodes.contains(&failed) {
        bail!("scheduler selected a node after it was marked offline");
    }
    if !args.leave_failed {
        set_status(&client, base, &args, failed, NodeStatus::Ready).await?;
    }

    let batch_plan: ExecutionPlan = send_json(authenticated(
        client
            .post(format!("{base}/constellation/v1/plans/simulate"))
            .json(&json!({
                "model": "constellation/mock",
                "required_runtime": "mock",
                "estimated_memory_bytes": 1024_u64 * 1024 * 1024,
                "class": "batch",
                "policy": "balanced"
            })),
        &args,
    ))
    .await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "simulated_nodes": simulated.iter().map(|node| json!({"id": node.id, "name": node.name, "os": node.os})).collect::<Vec<_>>(),
            "initial_plan": initial_plan,
            "failed_node": failed,
            "failover_plan": failover_plan,
            "batch_plan": batch_plan,
            "chat_response": chat,
            "restored_failed_node": !args.leave_failed
        }))?
    );
    Ok(())
}

fn scenario_nodes() -> Vec<SimulatedNode> {
    vec![
        SimulatedNode {
            name: "Simulated Windows Gaming PC",
            os: OperatingSystem::Windows,
            architecture: "x86_64",
            cpu: "Simulated 16-core x86 CPU",
            cores: 32,
            memory_gib: 64,
            accelerator: Some(json!({
                "vendor": "nvidia", "model": "Simulated RTX-class GPU",
                "memory_bytes": 24_u64 * 1024 * 1024 * 1024,
                "backends": ["cuda", "vulkan"]
            })),
            tokens_per_second: 32.0,
            ttft_ms: 130.0,
            latency_ms: 1.2,
            user_active: true,
            on_battery: false,
        },
        SimulatedNode {
            name: "Simulated Apple Silicon Mac",
            os: OperatingSystem::MacOs,
            architecture: "aarch64",
            cpu: "Simulated Apple Silicon",
            cores: 12,
            memory_gib: 48,
            accelerator: Some(json!({
                "vendor": "apple", "model": "Integrated Apple GPU",
                "memory_bytes": 32_u64 * 1024 * 1024 * 1024,
                "backends": ["metal", "mlx"]
            })),
            tokens_per_second: 24.0,
            ttft_ms: 170.0,
            latency_ms: 1.8,
            user_active: false,
            on_battery: false,
        },
        SimulatedNode {
            name: "Simulated Remote Linux Node",
            os: OperatingSystem::Linux,
            architecture: "x86_64",
            cpu: "Simulated 24-core server CPU",
            cores: 48,
            memory_gib: 128,
            accelerator: None,
            tokens_per_second: 12.0,
            ttft_ms: 500.0,
            latency_ms: 38.0,
            user_active: false,
            on_battery: false,
        },
    ]
}

fn registration(spec: &SimulatedNode) -> Value {
    json!({
        "name": spec.name,
        "os": spec.os,
        "architecture": spec.architecture,
        "capabilities": NodeCapabilities {
            cpu_model: spec.cpu.to_owned(),
            logical_cores: spec.cores,
            memory_total_bytes: spec.memory_gib * 1024 * 1024 * 1024,
            memory_available_bytes: spec.memory_gib * 1024 * 1024 * 1024,
            accelerator: spec.accelerator.as_ref().and_then(|value| serde_json::from_value(value.clone()).ok()),
            runtimes: vec!["mock".to_owned()],
            on_battery: spec.on_battery,
            user_active: spec.user_active,
            temperature_celsius: Some(52.0),
            thermal_throttling: Some(false),
        }
    })
}

async fn set_status(
    client: &Client,
    base: &str,
    args: &Args,
    node_id: NodeId,
    status: NodeStatus,
) -> Result<()> {
    let _: Value = send_json(authenticated(
        client
            .patch(format!(
                "{base}/constellation/v1/devices/{}/status",
                node_id.0
            ))
            .json(&json!({"status": status})),
        args,
    ))
    .await?;
    Ok(())
}

fn authenticated(request: RequestBuilder, args: &Args) -> RequestBuilder {
    if let Some(key) = &args.api_key {
        request.bearer_auth(key)
    } else {
        request
    }
}

async fn send_json<T: DeserializeOwned>(request: RequestBuilder) -> Result<T> {
    let response = request.send().await.context("send controller request")?;
    let status = response.status();
    let body = response.text().await.context("read controller response")?;
    if !status.is_success() {
        bail!("controller returned {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("decode controller response: {body}"))
}

async fn wait_until_ready(client: &Client, base: &str) -> Result<()> {
    for _attempt in 0..20 {
        match client.get(format!("{base}/ready")).send().await {
            Ok(response) if response.status() == StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    }
    bail!("controller did not become ready at {base}")
}
