//! Operator CLI for local and authenticated Constellation controllers.

use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Parser, Subcommand, ValueEnum};
use constellation_core::{WorkerLease, WorkerRuntimeEvent};
use constellation_identity::{ClientEnrollment, DeviceIdentity};
use constellation_plugins::{PluginManifest, PluginPermission};
use constellation_secrets::OsKeyring;
use constellation_teams::{Permission, Role};
use constellation_workflows::{WorkflowDefinition, WorkflowEvent, parse_json, parse_yaml};
use futures_util::StreamExt;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use zeroize::Zeroize as _;

#[derive(Debug, Parser)]
#[command(name = "constellation", version, about)]
struct Args {
    /// Controller base URL.
    #[arg(
        long,
        env = "CONSTELLATION_URL",
        default_value = "http://127.0.0.1:4317"
    )]
    controller: String,

    /// Bearer API key when controller authentication is enabled.
    #[arg(long, env = "CONSTELLATION_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// PEM cluster CA pinned from the administrator's invitation for HTTPS controllers.
    #[arg(long, env = "CONSTELLATION_CA_CERTIFICATE")]
    ca_certificate: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the plain-language cluster summary.
    Status,
    /// List normalized devices and their current availability.
    Inventory,
    /// Revoke a remote device and all of its active membership credentials.
    Revoke { node_id: Uuid },
    /// Send one credential-authenticated worker heartbeat.
    Heartbeat {
        node_id: Uuid,
        /// JSON approval or enrollment response containing the membership credential.
        #[arg(long)]
        credential: PathBuf,
    },
    /// Rotate this node's membership and mTLS certificate before the 24-hour expiry.
    RotateCredentials {
        node_id: Uuid,
        /// Current approved credential bundle.
        #[arg(long)]
        credential: PathBuf,
        /// New credential bundle destination.
        #[arg(long)]
        output: PathBuf,
        /// Preserve an existing destination as a recoverable sibling backup.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// List the latest benchmark for each device.
    Benchmarks,
    /// Export a content-free reproducible benchmark report.
    Report {
        /// JSON report destination.
        output: PathBuf,
        /// Permit replacing an existing report.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Manage the verified local model cache.
    Model {
        #[command(subcommand)]
        command: ModelCommand,
    },
    /// Create, inspect, or approve secure device invitations.
    Invitation {
        #[command(subcommand)]
        command: InvitationCommand,
    },
    /// Join this device using a short code or link secret and wait for approval.
    Enroll {
        /// Invitation identifier shown on the controller.
        invitation_id: Uuid,
        /// Eight-character Base32 code or URL-safe link secret.
        secret: String,
        /// Treat `secret` as the link/QR secret instead of the short code.
        #[arg(long, default_value_t = false)]
        link: bool,
        /// Device display name. Defaults to the operating-system hostname.
        #[arg(long)]
        name: Option<String>,
        /// Maximum seconds to wait for administrator approval; zero returns after proof.
        #[arg(long, default_value_t = 300)]
        wait_seconds: u64,
        /// Use a process-local identity only for loopback integration tests.
        #[arg(long, default_value_t = false)]
        ephemeral_device_identity: bool,
        /// Write the approved membership and certificate bundle with private file permissions.
        #[arg(long)]
        credential_output: Option<PathBuf>,
    },
    /// Stream one private chat completion.
    Chat {
        /// Model alias.
        #[arg(long, default_value = "constellation/mock")]
        model: String,
        /// Prompt content. It is sent only to the configured controller.
        prompt: String,
        /// Maximum generated tokens.
        #[arg(long, default_value_t = 256)]
        max_tokens: u32,
    },
    /// Simulate a scheduler decision without sending prompt content.
    Plan {
        /// Model alias.
        #[arg(long, default_value = "constellation/mock")]
        model: String,
        /// Required runtime adapter.
        #[arg(long, default_value = "mock")]
        runtime: String,
        /// Estimated working-set size in bytes.
        #[arg(long, default_value_t = 1_073_741_824)]
        memory_bytes: u64,
        /// Workload latency class.
        #[arg(long, value_enum, default_value_t = WorkloadClass::Interactive)]
        class: WorkloadClass,
        /// Scheduling preference.
        #[arg(long, value_enum, default_value_t = Policy::Balanced)]
        policy: Policy,
    },
    /// Replay redacted durable cluster events.
    Events {
        /// First sequence is strictly greater than this value.
        #[arg(long, default_value_t = 0)]
        after: i64,
        /// Maximum events returned.
        #[arg(long, default_value_t = 100)]
        limit: i64,
    },
    /// Cancel one running local or remote workload.
    Cancel { workload_id: Uuid },
    /// Download a consistent encrypted-state `SQLite` backup.
    Backup {
        output: PathBuf,
        /// Permit replacing an existing backup file.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Check health, readiness, models, and cluster state without content.
    Diagnostics,
    /// Poll and execute authenticated mock-runtime leases for this enrolled node.
    Worker {
        node_id: Uuid,
        /// Approved membership and mTLS certificate bundle.
        #[arg(long)]
        credential: PathBuf,
        /// Poll once and exit; useful for service health checks and tests.
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    /// Create and operate durable agent workflows.
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommand,
    },
    /// Install, grant, and execute sandboxed component plugins.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Administer human and scoped service principals.
    Principal {
        #[command(subcommand)]
        command: PrincipalCommand,
    },
    /// Administer teams and memberships.
    Team {
        #[command(subcommand)]
        command: TeamCommand,
    },
    /// Store external provider credentials in the local OS credential vault.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SecretCommand {
    /// Read a provider secret from standard input; it is never sent to the controller.
    Store { reference: String },
}

#[derive(Debug, Subcommand)]
enum WorkflowCommand {
    /// List workflow metadata.
    List,
    /// Create a workflow from validated JSON or YAML.
    Create { definition: PathBuf },
    /// Inspect a decrypted workflow definition.
    Get { workflow_id: Uuid },
    /// Start a workflow with an optional JSON input object.
    Run {
        workflow_id: Uuid,
        #[arg(long, default_value = "{}")]
        inputs: String,
    },
    /// Inspect a run and its currently ready parallel steps.
    Inspect { run_id: Uuid },
    /// Apply a JSON-encoded workflow event.
    Event { run_id: Uuid, event: String },
    /// Create a bounded five-field UTC schedule.
    Schedule {
        workflow_id: Uuid,
        cron_utc: String,
        #[arg(long, default_value_t = 1)]
        concurrency_limit: u16,
    },
    /// Create a webhook trigger and show its secret once.
    Webhook { workflow_id: Uuid },
    /// Store an encrypted run artifact from a local file.
    Artifact {
        run_id: Uuid,
        #[arg(long)]
        step_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        media_type: String,
        path: PathBuf,
    },
    /// List reusable workflow templates.
    TemplateList,
    /// Add a workflow to the reusable template catalog.
    TemplateCreate {
        workflow_id: Uuid,
        name: String,
        #[arg(long, default_value = "{}")]
        metadata: String,
    },
    /// Instantiate a template as a separately encrypted workflow.
    TemplateInstantiate {
        template_id: Uuid,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    /// List installed plugin manifests and enablement state.
    List,
    /// Compile and install a component; execution remains disabled.
    Install {
        manifest: PathBuf,
        component: PathBuf,
    },
    /// Approve a JSON array of the plugin's declared permissions.
    Grant {
        plugin_id: String,
        #[arg(long, default_value = "[]")]
        permissions: String,
    },
    /// Execute an enabled tool plugin with a bounded string input.
    Execute { plugin_id: String, input: String },
}

#[derive(Debug, Subcommand)]
enum PrincipalCommand {
    /// List principals without credential hashes.
    List,
    /// Create a principal; service API keys are shown once.
    Create {
        name: String,
        #[arg(long, value_enum)]
        role: PrincipalRole,
        /// JSON array of service permission strings.
        #[arg(long, default_value = "[]")]
        scopes: String,
    },
}

#[derive(Debug, Subcommand)]
enum TeamCommand {
    /// List teams.
    List,
    /// Create a team.
    Create { name: String },
    /// Add or update one member.
    AddMember {
        team_id: Uuid,
        principal_id: Uuid,
        #[arg(long, value_enum)]
        role: PrincipalRole,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PrincipalRole {
    Admin,
    Operator,
    Viewer,
    Service,
}

impl PrincipalRole {
    const fn into_role(self) -> Role {
        match self {
            Self::Admin => Role::Admin,
            Self::Operator => Role::Operator,
            Self::Viewer => Role::Viewer,
            Self::Service => Role::Service,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ModelCommand {
    /// List imported model manifests.
    List,
    /// Import and verify a local model file.
    Import {
        path: PathBuf,
        #[arg(long)]
        alias: String,
        #[arg(long, default_value = "gguf")]
        format: String,
        #[arg(long)]
        quantization: Option<String>,
        /// SPDX identifier or exact upstream license label.
        #[arg(long)]
        license: String,
        /// Required acknowledgement that the supplied license was reviewed and accepted.
        #[arg(long, default_value_t = false)]
        accept_license: bool,
        #[arg(long, default_value_t = false)]
        pin: bool,
    },
    /// Recompute every model digest.
    Verify { alias: String },
    /// Protect or unprotect a model from eviction.
    Pin {
        alias: String,
        #[arg(long, default_value_t = true)]
        pinned: bool,
    },
    /// Remove a model manifest and unreferenced chunks.
    Remove {
        alias: String,
        /// Confirm destructive removal.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Fetch one verified model chunk with a controller-issued peer-transfer ticket.
    TransferChunk {
        #[arg(long)]
        alias: String,
        #[arg(long)]
        chunk_sha256: String,
        #[arg(long)]
        destination_node: Uuid,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum InvitationCommand {
    /// Create a ten-minute single-use invitation.
    Create,
    /// List redacted invitation states.
    List,
    /// Approve a device after it proves possession of the invitation secret.
    Approve { invitation_id: Uuid },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WorkloadClass {
    Interactive,
    Batch,
    Background,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Policy {
    Fastest,
    MostPrivate,
    LowestPower,
    Balanced,
    KeepThisComputerResponsive,
}

impl WorkloadClass {
    const fn as_api(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Batch => "batch",
            Self::Background => "background",
        }
    }
}

impl Policy {
    const fn as_api(self) -> &'static str {
        match self {
            Self::Fastest => "fastest",
            Self::MostPrivate => "most_private",
            Self::LowestPower => "lowest_power",
            Self::Balanced => "balanced",
            Self::KeepThisComputerResponsive => "keep_this_computer_responsive",
        }
    }
}

#[derive(Debug, Clone)]
struct ControllerClient {
    base: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

impl ControllerClient {
    fn new(base: &str, api_key: Option<String>, ca_certificate: Option<&PathBuf>) -> Result<Self> {
        let normalized = base.trim_end_matches('/').to_owned();
        if !(normalized.starts_with("http://127.0.0.1:")
            || normalized.starts_with("http://localhost:")
            || normalized.starts_with("https://"))
        {
            bail!("non-loopback controllers must use HTTPS");
        }
        let mut builder = reqwest::Client::builder();
        if let Some(path) = ca_certificate {
            let pem = std::fs::read(path)
                .with_context(|| format!("read cluster CA {}", path.display()))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .context("parse pinned cluster CA certificate")?;
            builder = builder.add_root_certificate(certificate);
        }
        Ok(Self {
            base: normalized,
            api_key,
            http: builder.build().context("create controller client")?,
        })
    }

    fn membership_client(&self, membership: &Value) -> Result<reqwest::Client> {
        if self.base.starts_with("http://127.0.0.1:") || self.base.starts_with("http://localhost:")
        {
            return Ok(self.http.clone());
        }
        let certificate_pem = membership
            .pointer("/device_certificate/certificate_pem")
            .and_then(Value::as_str)
            .context("credential file does not contain a device TLS certificate")?;
        let ca_pem = membership
            .pointer("/device_certificate/certificate_authority_pem")
            .and_then(Value::as_str)
            .context("credential file does not contain the pinned cluster CA")?;
        let secret = OsKeyring::new("com.constellation.device", "device-ed25519-v1")
            .load_or_create_secret_32()
            .context("load device identity for mTLS")?;
        let identity = DeviceIdentity::from_secret_bytes(&secret);
        let private_key = identity
            .private_key_pem()
            .context("encode device identity for mTLS")?;
        let identity_pem = format!("{certificate_pem}{private_key}");
        let client_identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
            .context("combine device certificate and private key")?;
        let root = reqwest::Certificate::from_pem(ca_pem.as_bytes())
            .context("parse credential cluster CA")?;
        reqwest::Client::builder()
            .add_root_certificate(root)
            .identity(client_identity)
            .build()
            .context("create mTLS membership client")
    }

    async fn json(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut request = self.http.request(method, format!("{}{}", self.base, path));
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }
        if let Some(value) = body {
            request = request.json(&value);
        }
        let response = request.send().await.context("contact controller")?;
        let status = response.status();
        if status == StatusCode::NO_CONTENT {
            return Ok(json!({"status": "ok"}));
        }
        let value = response
            .json::<Value>()
            .await
            .context("decode controller response")?;
        if !status.is_success() {
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("controller rejected the operation");
            bail!("{message} ({status})");
        }
        Ok(value)
    }

    async fn json_with_membership(
        &self,
        method: Method,
        path: &str,
        membership: &Value,
        body: Option<Value>,
    ) -> Result<Value> {
        let credential = membership.pointer("/credential").unwrap_or(membership);
        if credential.is_null() {
            bail!("credential file does not contain an approved membership");
        }
        let encoded = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(credential).context("encode membership credential")?);
        let http = self.membership_client(membership)?;
        let mut request = http
            .request(method, format!("{}{}", self.base, path))
            .header("x-constellation-membership", encoded);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .context("contact controller with membership")?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .context("decode membership response")?;
        if !status.is_success() {
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("controller rejected the membership operation");
            bail!("{message} ({status})");
        }
        Ok(value)
    }

    async fn download_chunk(
        &self,
        chunk_sha256: &str,
        membership: &Value,
        ticket: &Value,
    ) -> Result<Vec<u8>> {
        let credential = membership.pointer("/credential").unwrap_or(membership);
        let membership_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(credential).context("encode membership credential")?);
        let ticket_header =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(ticket).context("encode transfer ticket")?);
        let http = self.membership_client(membership)?;
        let response = http
            .get(format!(
                "{}/constellation/v1/models/chunks/{chunk_sha256}",
                self.base
            ))
            .header("x-constellation-membership", membership_header)
            .header("x-constellation-transfer-ticket", ticket_header)
            .send()
            .await
            .context("download authorized model chunk")?;
        let status = response.status();
        let bytes = response.bytes().await.context("read model chunk")?;
        if !status.is_success() {
            bail!("controller rejected model chunk transfer ({status})");
        }
        if format!("{:x}", Sha256::digest(&bytes)) != chunk_sha256 {
            bail!("downloaded model chunk failed SHA-256 verification");
        }
        Ok(bytes.to_vec())
    }

    async fn stream_chat(&self, model: &str, prompt: &str, max_tokens: u32) -> Result<()> {
        let mut request = self
            .http
            .post(format!("{}/v1/chat/completions", self.base))
            .json(&json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens.clamp(1, 4_096),
                "stream": true
            }));
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }
        let response = request.send().await.context("start chat")?;
        if !response.status().is_success() {
            bail!("controller rejected chat ({})", response.status());
        }
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();
        while let Some(chunk) = stream.next().await {
            buffer.push_str(&String::from_utf8_lossy(
                &chunk.context("read streamed response")?,
            ));
            buffer = buffer.replace("\r\n", "\n");
            while let Some(boundary) = buffer.find("\n\n") {
                let frame = buffer[..boundary].to_owned();
                buffer.drain(..boundary + 2);
                for line in frame.lines() {
                    let Some(data) = line.strip_prefix("data: ") else {
                        continue;
                    };
                    if data == "[DONE]" {
                        continue;
                    }
                    let value =
                        serde_json::from_str::<Value>(data).context("decode streamed event")?;
                    if let Some(delta) = value
                        .pointer("/choices/0/delta/content")
                        .and_then(Value::as_str)
                    {
                        print!("{delta}");
                    }
                    if let Some(message) = value.pointer("/error/message").and_then(Value::as_str) {
                        bail!("{message}");
                    }
                }
            }
        }
        println!();
        Ok(())
    }

    async fn download_backup(&self) -> Result<Vec<u8>> {
        let mut request = self
            .http
            .get(format!("{}/constellation/v1/backup", self.base));
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }
        let response = request.send().await.context("request controller backup")?;
        let status = response.status();
        let bytes = response.bytes().await.context("read controller backup")?;
        if !status.is_success() {
            bail!("controller backup failed ({status})");
        }
        if !bytes.starts_with(b"SQLite format 3\0") {
            bail!("controller returned an invalid backup artifact");
        }
        Ok(bytes.to_vec())
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // Dispatch remains a direct auditable mapping from CLI to API.
async fn main() -> Result<()> {
    let args = Args::parse();
    let client =
        ControllerClient::new(&args.controller, args.api_key, args.ca_certificate.as_ref())?;
    match args.command {
        Command::Status => print_json(
            client
                .json(Method::GET, "/constellation/v1/cluster", None)
                .await?,
        ),
        Command::Inventory => print_json(
            client
                .json(Method::GET, "/constellation/v1/devices", None)
                .await?,
        ),
        Command::Revoke { node_id } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/devices/{node_id}/revoke"),
                    None,
                )
                .await?,
        ),
        Command::Heartbeat {
            node_id,
            credential,
        } => run_heartbeat(&client, node_id, &credential).await?,
        Command::RotateCredentials {
            node_id,
            credential,
            output,
            force,
        } => run_credential_rotation(&client, node_id, &credential, &output, force).await?,
        Command::Benchmarks => print_json(
            client
                .json(Method::GET, "/constellation/v1/benchmarks", None)
                .await?,
        ),
        Command::Report { output, force } => {
            let report = client
                .json(Method::GET, "/constellation/v1/reports/benchmark", None)
                .await?;
            write_json_artifact(&output, &report, force, "report").await?;
            println!("Benchmark report written to {}", output.display());
        }
        Command::Model { command } => run_model_command(&client, command).await?,
        Command::Invitation { command } => run_invitation_command(&client, command).await?,
        Command::Enroll {
            invitation_id,
            secret,
            link,
            name,
            wait_seconds,
            ephemeral_device_identity,
            credential_output,
        } => {
            run_enrollment(
                &client,
                invitation_id,
                &secret,
                link,
                name,
                wait_seconds,
                ephemeral_device_identity,
                credential_output.as_deref(),
            )
            .await?;
        }
        Command::Chat {
            model,
            prompt,
            max_tokens,
        } => client.stream_chat(&model, &prompt, max_tokens).await?,
        Command::Plan {
            model,
            runtime,
            memory_bytes,
            class,
            policy,
        } => print_json(
            client
                .json(
                    Method::POST,
                    "/constellation/v1/plans/simulate",
                    Some(json!({
                        "model": model,
                        "required_runtime": runtime,
                        "estimated_memory_bytes": memory_bytes,
                        "class": class.as_api(),
                        "policy": policy.as_api()
                    })),
                )
                .await?,
        ),
        Command::Events { after, limit } => print_json(
            client
                .json(
                    Method::GET,
                    &format!("/constellation/v1/events?after={after}&limit={limit}"),
                    None,
                )
                .await?,
        ),
        Command::Cancel { workload_id } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/workloads/{workload_id}/cancel"),
                    None,
                )
                .await?,
        ),
        Command::Backup { output, force } => {
            run_backup(&client, &output, force).await?;
        }
        Command::Diagnostics => run_diagnostics(&client).await?,
        Command::Worker {
            node_id,
            credential,
            once,
        } => run_worker(&client, node_id, &credential, once).await?,
        Command::Workflow { command } => run_workflow_command(&client, command).await?,
        Command::Plugin { command } => run_plugin_command(&client, command).await?,
        Command::Principal { command } => run_principal_command(&client, command).await?,
        Command::Team { command } => run_team_command(&client, command).await?,
        Command::Secret { command } => run_secret_command(command)?,
    }
    Ok(())
}

fn run_secret_command(command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Store { reference } => {
            if reference.is_empty()
                || reference.len() > 128
                || !reference
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                bail!("secret reference must be a 1-128 character identifier");
            }
            let mut secret = String::new();
            std::io::stdin()
                .read_to_string(&mut secret)
                .context("read provider secret from standard input")?;
            while secret.ends_with(['\r', '\n']) {
                secret.pop();
            }
            OsKeyring::new("com.constellation.provider", &reference)
                .store_secret_string(&secret)
                .context("store provider secret")?;
            secret.zeroize();
            println!("Stored provider secret reference {reference}");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keeps the workflow command-to-route contract discoverable.
async fn run_workflow_command(client: &ControllerClient, command: WorkflowCommand) -> Result<()> {
    match command {
        WorkflowCommand::List => print_json(
            client
                .json(Method::GET, "/constellation/v1/workflows", None)
                .await?,
        ),
        WorkflowCommand::Create { definition } => {
            let bytes = tokio::fs::read(&definition)
                .await
                .with_context(|| format!("read workflow definition {}", definition.display()))?;
            let parsed: WorkflowDefinition = if definition
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
                }) {
                parse_yaml(&bytes).map_err(|error| anyhow::anyhow!(error))?
            } else {
                parse_json(&bytes).map_err(|error| anyhow::anyhow!(error))?
            };
            print_json(
                client
                    .json(
                        Method::POST,
                        "/constellation/v1/workflows",
                        Some(json!({"definition": parsed})),
                    )
                    .await?,
            );
        }
        WorkflowCommand::Get { workflow_id } => print_json(
            client
                .json(
                    Method::GET,
                    &format!("/constellation/v1/workflows/{workflow_id}"),
                    None,
                )
                .await?,
        ),
        WorkflowCommand::Run {
            workflow_id,
            inputs,
        } => {
            let inputs: Value = serde_json::from_str(&inputs).context("decode workflow inputs")?;
            if !inputs.is_object() {
                bail!("workflow inputs must be a JSON object");
            }
            print_json(
                client
                    .json(
                        Method::POST,
                        &format!("/constellation/v1/workflows/{workflow_id}/runs"),
                        Some(json!({"inputs": inputs})),
                    )
                    .await?,
            );
        }
        WorkflowCommand::Inspect { run_id } => print_json(
            client
                .json(
                    Method::GET,
                    &format!("/constellation/v1/workflow-runs/{run_id}"),
                    None,
                )
                .await?,
        ),
        WorkflowCommand::Event { run_id, event } => {
            let event: WorkflowEvent =
                serde_json::from_str(&event).context("decode workflow event")?;
            print_json(
                client
                    .json(
                        Method::POST,
                        &format!("/constellation/v1/workflow-runs/{run_id}/events"),
                        Some(json!({"event": event})),
                    )
                    .await?,
            );
        }
        WorkflowCommand::Schedule {
            workflow_id,
            cron_utc,
            concurrency_limit,
        } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/workflows/{workflow_id}/schedules"),
                    Some(json!({
                        "cron_utc": cron_utc,
                        "enabled": true,
                        "concurrency_limit": concurrency_limit,
                    })),
                )
                .await?,
        ),
        WorkflowCommand::Webhook { workflow_id } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/workflows/{workflow_id}/webhooks"),
                    None,
                )
                .await?,
        ),
        WorkflowCommand::Artifact {
            run_id,
            step_id,
            name,
            media_type,
            path,
        } => {
            let content = tokio::fs::read(&path)
                .await
                .with_context(|| format!("read artifact {}", path.display()))?;
            print_json(
                client
                    .json(
                        Method::POST,
                        &format!("/constellation/v1/workflow-runs/{run_id}/artifacts"),
                        Some(json!({
                            "step_id": step_id,
                            "name": name,
                            "media_type": media_type,
                            "content_base64": URL_SAFE_NO_PAD.encode(content),
                        })),
                    )
                    .await?,
            );
        }
        WorkflowCommand::TemplateList => print_json(
            client
                .json(Method::GET, "/constellation/v1/workflow-templates", None)
                .await?,
        ),
        WorkflowCommand::TemplateCreate {
            workflow_id,
            name,
            metadata,
        } => {
            let metadata: Value =
                serde_json::from_str(&metadata).context("decode template metadata")?;
            if !metadata.is_object() {
                bail!("template metadata must be a JSON object");
            }
            print_json(
                client
                    .json(
                        Method::POST,
                        "/constellation/v1/workflow-templates",
                        Some(json!({
                            "workflow_id": workflow_id,
                            "name": name,
                            "metadata": metadata,
                        })),
                    )
                    .await?,
            );
        }
        WorkflowCommand::TemplateInstantiate { template_id, name } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/workflow-templates/{template_id}/instantiate"),
                    Some(json!({"name": name})),
                )
                .await?,
        ),
    }
    Ok(())
}

async fn run_plugin_command(client: &ControllerClient, command: PluginCommand) -> Result<()> {
    match command {
        PluginCommand::List => print_json(
            client
                .json(Method::GET, "/constellation/v1/plugins", None)
                .await?,
        ),
        PluginCommand::Install {
            manifest,
            component,
        } => {
            let manifest: PluginManifest = serde_json::from_slice(
                &tokio::fs::read(&manifest)
                    .await
                    .with_context(|| format!("read plugin manifest {}", manifest.display()))?,
            )
            .context("decode plugin manifest")?;
            let component = tokio::fs::read(&component)
                .await
                .with_context(|| format!("read plugin component {}", component.display()))?;
            print_json(
                client
                    .json(
                        Method::POST,
                        "/constellation/v1/plugins/install",
                        Some(json!({
                            "manifest": manifest,
                            "component_base64": URL_SAFE_NO_PAD.encode(component),
                        })),
                    )
                    .await?,
            );
        }
        PluginCommand::Grant {
            plugin_id,
            permissions,
        } => {
            let permissions: Vec<PluginPermission> =
                serde_json::from_str(&permissions).context("decode plugin permissions")?;
            print_json(
                client
                    .json(
                        Method::POST,
                        &format!("/constellation/v1/plugins/{plugin_id}/grant"),
                        Some(json!({"permissions": permissions})),
                    )
                    .await?,
            );
        }
        PluginCommand::Execute { plugin_id, input } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/plugins/{plugin_id}/execute"),
                    Some(json!({"input": input})),
                )
                .await?,
        ),
    }
    Ok(())
}

async fn run_principal_command(client: &ControllerClient, command: PrincipalCommand) -> Result<()> {
    match command {
        PrincipalCommand::List => print_json(
            client
                .json(Method::GET, "/constellation/v1/principals", None)
                .await?,
        ),
        PrincipalCommand::Create { name, role, scopes } => {
            let scopes: Vec<Permission> =
                serde_json::from_str(&scopes).context("decode service scopes")?;
            print_json(
                client
                    .json(
                        Method::POST,
                        "/constellation/v1/principals",
                        Some(json!({
                            "name": name,
                            "role": role.into_role(),
                            "scopes": scopes,
                        })),
                    )
                    .await?,
            );
        }
    }
    Ok(())
}

async fn run_team_command(client: &ControllerClient, command: TeamCommand) -> Result<()> {
    match command {
        TeamCommand::List => print_json(
            client
                .json(Method::GET, "/constellation/v1/teams", None)
                .await?,
        ),
        TeamCommand::Create { name } => print_json(
            client
                .json(
                    Method::POST,
                    "/constellation/v1/teams",
                    Some(json!({"name": name})),
                )
                .await?,
        ),
        TeamCommand::AddMember {
            team_id,
            principal_id,
            role,
        } => print_json(
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/teams/{team_id}/members"),
                    Some(json!({
                        "principal_id": principal_id,
                        "role": role.into_role(),
                    })),
                )
                .await?,
        ),
    }
    Ok(())
}

async fn run_heartbeat(
    client: &ControllerClient,
    node_id: Uuid,
    credential: &std::path::Path,
) -> Result<()> {
    let value: Value = serde_json::from_slice(
        &tokio::fs::read(credential)
            .await
            .with_context(|| format!("read credential {}", credential.display()))?,
    )
    .context("decode credential file")?;
    print_json(
        client
            .json_with_membership(
                Method::POST,
                &format!("/constellation/v1/devices/{node_id}/heartbeat"),
                &value,
                None,
            )
            .await?,
    );
    Ok(())
}

async fn run_worker(
    client: &ControllerClient,
    node_id: Uuid,
    credential_path: &std::path::Path,
    once: bool,
) -> Result<()> {
    let credential: Value = serde_json::from_slice(
        &tokio::fs::read(credential_path)
            .await
            .with_context(|| format!("read credential {}", credential_path.display()))?,
    )
    .context("decode credential file")?;
    client
        .json_with_membership(
            Method::POST,
            "/constellation/v1/benchmarks",
            &credential,
            Some(json!({
                "node_id": node_id,
                "runtime": "mock",
                "model": "constellation/mock",
                "tokens_per_second": 1000.0,
                "time_to_first_token_ms": 5.0,
                "network_latency_ms": 1.0,
                "network_bandwidth_mbps": 1000.0,
                "jitter_ms": 0.1,
                "packet_loss": 0.0,
                "sample_count": 5,
                "kind": "measured",
                "measured_at": chrono::Utc::now(),
            })),
        )
        .await?;
    loop {
        let response = client
            .json_with_membership(
                Method::POST,
                &format!("/constellation/v1/workers/{node_id}/leases/poll"),
                &credential,
                None,
            )
            .await?;
        if let Some(value) = response.get("lease").filter(|value| !value.is_null()) {
            let lease: WorkerLease =
                serde_json::from_value(value.clone()).context("decode worker lease")?;
            execute_mock_lease(client, node_id, &credential, lease).await?;
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

async fn execute_mock_lease(
    client: &ControllerClient,
    node_id: Uuid,
    credential: &Value,
    lease: WorkerLease,
) -> Result<()> {
    if lease.node_id.0 != node_id {
        bail!("controller returned a lease for a different node");
    }
    if lease.model != "constellation/mock" {
        submit_lease_event(
            client,
            node_id,
            credential,
            lease.id,
            1,
            WorkerRuntimeEvent::Failure {
                code: "model_unavailable".to_owned(),
                message: "selected worker does not have the requested model".to_owned(),
                retryable: false,
                output_started: false,
            },
        )
        .await?;
        return Ok(());
    }
    let normalized = lease.input.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = if normalized.is_empty() {
        "Constellation mock response: ready".to_owned()
    } else {
        format!("Constellation mock response: {normalized}")
    };
    let chunks = body
        .split_inclusive(' ')
        .take(lease.maximum_output_tokens as usize)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut sequence = 1_u64;
    submit_lease_event(
        client,
        node_id,
        credential,
        lease.id,
        sequence,
        WorkerRuntimeEvent::Prefill { elapsed_ms: 1 },
    )
    .await?;
    for chunk in &chunks {
        sequence = sequence.saturating_add(1);
        submit_lease_event(
            client,
            node_id,
            credential,
            lease.id,
            sequence,
            WorkerRuntimeEvent::TextDelta {
                text: chunk.clone(),
            },
        )
        .await?;
    }
    sequence = sequence.saturating_add(1);
    submit_lease_event(
        client,
        node_id,
        credential,
        lease.id,
        sequence,
        WorkerRuntimeEvent::Finished {
            input_tokens: u32::try_from(lease.input.split_whitespace().count()).unwrap_or(u32::MAX),
            output_tokens: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            finish_reason: "stop".to_owned(),
        },
    )
    .await
}

async fn submit_lease_event(
    client: &ControllerClient,
    node_id: Uuid,
    credential: &Value,
    lease_id: Uuid,
    sequence: u64,
    event: WorkerRuntimeEvent,
) -> Result<()> {
    client
        .json_with_membership(
            Method::POST,
            &format!("/constellation/v1/workers/{node_id}/leases/{lease_id}/events"),
            credential,
            Some(json!({"sequence": sequence, "event": event})),
        )
        .await?;
    Ok(())
}

async fn run_credential_rotation(
    client: &ControllerClient,
    node_id: Uuid,
    credential: &std::path::Path,
    output: &std::path::Path,
    force: bool,
) -> Result<()> {
    let current: Value = serde_json::from_slice(
        &tokio::fs::read(credential)
            .await
            .with_context(|| format!("read credential {}", credential.display()))?,
    )
    .context("decode credential file")?;
    let rotated = client
        .json_with_membership(
            Method::POST,
            &format!("/constellation/v1/devices/{node_id}/credentials/rotate"),
            &current,
            None,
        )
        .await?;
    write_private_json(output, &rotated, force).await?;
    println!("Credential bundle written to {}", output.display());
    Ok(())
}

async fn run_backup(
    client: &ControllerClient,
    output: &std::path::Path,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        bail!("backup destination exists; pass --force to replace it");
    }
    let bytes = client.download_backup().await?;
    let parent = output.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temporary = parent.join(format!(".constellation-backup-{}.tmp", Uuid::now_v7()));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .await
        .with_context(|| format!("create backup beside {}", output.display()))?;
    file.write_all(&bytes)
        .await
        .context("write backup artifact")?;
    file.sync_all().await.context("sync backup artifact")?;
    drop(file);
    if force && output.exists() {
        tokio::fs::remove_file(output)
            .await
            .with_context(|| format!("replace backup at {}", output.display()))?;
    }
    tokio::fs::rename(&temporary, output)
        .await
        .with_context(|| format!("promote backup to {}", output.display()))?;
    println!("Backup written to {}", output.display());
    Ok(())
}

async fn run_diagnostics(client: &ControllerClient) -> Result<()> {
    let health = client.json(Method::GET, "/health", None).await?;
    let ready = client.json(Method::GET, "/ready", None).await?;
    let cluster = client
        .json(Method::GET, "/constellation/v1/cluster", None)
        .await?;
    let models = client.json(Method::GET, "/v1/models", None).await?;
    print_json(json!({
        "health": health,
        "ready": ready,
        "cluster": cluster,
        "models": models,
        "content_included": false
    }));
    Ok(())
}

async fn run_invitation_command(
    client: &ControllerClient,
    command: InvitationCommand,
) -> Result<()> {
    let value = match command {
        InvitationCommand::Create => {
            client
                .json(Method::POST, "/constellation/v1/invitations", None)
                .await?
        }
        InvitationCommand::List => {
            client
                .json(Method::GET, "/constellation/v1/invitations", None)
                .await?
        }
        InvitationCommand::Approve { invitation_id } => {
            client
                .json(
                    Method::POST,
                    &format!("/constellation/v1/invitations/{invitation_id}/approve"),
                    None,
                )
                .await?
        }
    };
    print_json(value);
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Linear security transcript mirrors independent CLI enrollment controls.
async fn run_enrollment(
    client: &ControllerClient,
    invitation_id: Uuid,
    secret: &str,
    link: bool,
    name: Option<String>,
    wait_seconds: u64,
    ephemeral_device_identity: bool,
    credential_output: Option<&std::path::Path>,
) -> Result<()> {
    if ephemeral_device_identity
        && !(client.base.starts_with("http://127.0.0.1:")
            || client.base.starts_with("http://localhost:"))
    {
        bail!("ephemeral device identity is restricted to loopback tests");
    }
    let identity = if ephemeral_device_identity {
        DeviceIdentity::generate()
    } else {
        let bytes = OsKeyring::new("com.constellation.device", "device-ed25519-v1")
            .load_or_create_secret_32()
            .context("load device identity from OS credential storage")?;
        DeviceIdentity::from_secret_bytes(&bytes)
    };
    let (client_session, client_message) =
        ClientEnrollment::begin(invitation_id, secret.as_bytes());
    let begin = client
        .json(
            Method::POST,
            "/constellation/v1/enrollment/begin",
            Some(json!({
                "invitation_id": invitation_id,
                "method": if link { "link_secret" } else { "short_code" },
                "client_message": URL_SAFE_NO_PAD.encode(client_message),
            })),
        )
        .await?;
    let controller_message = decode_json_base64(&begin, "/controller_message", 256)?;
    let controller_proof = decode_json_array::<32>(&begin, "/controller_proof")?;
    let enrollment_key = client_session
        .finish(&controller_message)
        .map_err(|_| anyhow::anyhow!("controller returned an invalid enrollment transcript"))?;
    if !enrollment_key.verify_proof("controller", invitation_id, &controller_proof) {
        bail!("controller enrollment proof is invalid");
    }
    let public_key = identity.public_key_bytes();
    let digest = Sha256::digest(public_key);
    let mut device_id_bytes = [0_u8; 16];
    device_id_bytes.copy_from_slice(&digest[..16]);
    let device_id = Uuid::from_bytes(device_id_bytes);
    let mut system = System::new_all();
    system.refresh_all();
    let os = match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "mac_os",
        "linux" => "linux",
        _ => "unknown",
    };
    let device_name = name
        .or_else(System::host_name)
        .unwrap_or_else(|| "Constellation worker".to_owned());
    let logical_cores = u16::try_from(system.cpus().len()).unwrap_or(u16::MAX);
    let memory_total_bytes = system.total_memory();
    let memory_available_bytes = if ephemeral_device_identity {
        memory_total_bytes
    } else {
        system.available_memory()
    };
    let cpu_model = system
        .cpus()
        .first()
        .map_or("Unknown CPU", sysinfo::Cpu::brand);
    let confirmed = client
        .json(
            Method::POST,
            "/constellation/v1/enrollment/confirm",
            Some(json!({
                "invitation_id": invitation_id,
                "client_proof": URL_SAFE_NO_PAD.encode(enrollment_key.proof("client", invitation_id)),
                "device_id": device_id,
                "device_public_key": URL_SAFE_NO_PAD.encode(public_key),
                "device": {
                    "name": device_name,
                    "os": os,
                    "architecture": std::env::consts::ARCH,
                    "capabilities": {
                        "cpu_model": cpu_model,
                        "logical_cores": logical_cores,
                        "memory_total_bytes": memory_total_bytes,
                        "memory_available_bytes": memory_available_bytes,
                        "accelerator": null,
                        "runtimes": ["mock"],
                        "on_battery": false,
                        "user_active": false,
                        "temperature_celsius": null,
                        "thermal_throttling": null
                    }
                }
            })),
        )
        .await?;
    if wait_seconds == 0 {
        print_json(confirmed);
        return Ok(());
    }
    let status_proof = URL_SAFE_NO_PAD.encode(enrollment_key.proof("status", invitation_id));
    for _attempt in 0..wait_seconds {
        let response = client
            .json(
                Method::POST,
                "/constellation/v1/enrollment/credential",
                Some(json!({
                    "invitation_id": invitation_id,
                    "status_proof": status_proof,
                })),
            )
            .await?;
        if response
            .pointer("/credential")
            .is_some_and(|value| !value.is_null())
        {
            if let Some(output) = credential_output {
                write_private_json(output, &response, false).await?;
                println!("Credential bundle written to {}", output.display());
            } else {
                print_json(response);
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("device proof succeeded, but administrator approval timed out");
}

async fn write_private_json(path: &std::path::Path, value: &Value, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("credential destination exists; pass --force to preserve and replace it");
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("create credential directory {}", parent.display()))?;
    let temporary = parent.join(format!(".constellation-credential-{}.tmp", Uuid::now_v7()));
    let encoded = serde_json::to_vec_pretty(value).context("encode credential bundle")?;
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .await
        .context("create private credential temporary file")?;
    file.write_all(&encoded)
        .await
        .context("write credential bundle")?;
    file.write_all(b"\n")
        .await
        .context("finish credential bundle")?;
    file.sync_all().await.context("sync credential bundle")?;
    drop(file);
    let mut preserved = None;
    if path.exists() {
        let backup = parent.join(format!(
            ".constellation-credential-backup-{}",
            Uuid::now_v7()
        ));
        tokio::fs::rename(path, &backup)
            .await
            .with_context(|| format!("preserve previous credential at {}", backup.display()))?;
        preserved = Some(backup);
    }
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ignored = tokio::fs::remove_file(&temporary).await;
        if let Some(backup) = preserved {
            let _ignored = tokio::fs::rename(backup, path).await;
        }
        return Err(error).with_context(|| format!("promote credential to {}", path.display()));
    }
    Ok(())
}

async fn write_json_artifact(
    path: &std::path::Path,
    value: &Value,
    force: bool,
    kind: &str,
) -> Result<()> {
    if path.exists() && !force {
        bail!("{kind} destination exists; pass --force to replace it");
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("create {kind} directory {}", parent.display()))?;
    let temporary = parent.join(format!(".constellation-{kind}-{}.tmp", Uuid::now_v7()));
    let encoded = serde_json::to_vec_pretty(value).with_context(|| format!("encode {kind}"))?;
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .await
        .with_context(|| format!("create {kind} beside {}", path.display()))?;
    file.write_all(&encoded)
        .await
        .with_context(|| format!("write {kind}"))?;
    file.write_all(b"\n")
        .await
        .with_context(|| format!("finish {kind}"))?;
    file.sync_all()
        .await
        .with_context(|| format!("sync {kind}"))?;
    drop(file);
    if force && path.exists() {
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("replace {kind} at {}", path.display()))?;
    }
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ignored = tokio::fs::remove_file(&temporary).await;
        return Err(error).with_context(|| format!("promote {kind} to {}", path.display()));
    }
    Ok(())
}

fn decode_json_base64(value: &Value, pointer: &str, max_len: usize) -> Result<Vec<u8>> {
    let encoded = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .context("controller enrollment response is missing data")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .context("controller enrollment response is malformed")?;
    if decoded.is_empty() || decoded.len() > max_len {
        bail!("controller enrollment response has an invalid length");
    }
    Ok(decoded)
}

fn decode_json_array<const N: usize>(value: &Value, pointer: &str) -> Result<[u8; N]> {
    decode_json_base64(value, pointer, N)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller enrollment proof has an invalid length"))
}

async fn run_model_command(client: &ControllerClient, command: ModelCommand) -> Result<()> {
    let value = match command {
        ModelCommand::List => {
            client
                .json(Method::GET, "/constellation/v1/models", None)
                .await?
        }
        ModelCommand::Import {
            path,
            alias,
            format,
            quantization,
            license,
            accept_license,
            pin,
        } => {
            if !accept_license {
                bail!("model import requires --accept-license");
            }
            client
                .json(
                    Method::POST,
                    "/constellation/v1/models/import",
                    Some(json!({
                        "path": path,
                        "alias": alias,
                        "format": format,
                        "quantization": quantization,
                        "license_id": license,
                        "license_accepted": true,
                        "pinned": pin
                    })),
                )
                .await?
        }
        ModelCommand::Verify { alias } => {
            client
                .json(
                    Method::POST,
                    "/constellation/v1/models/verify",
                    Some(json!({"alias": alias})),
                )
                .await?
        }
        ModelCommand::Pin { alias, pinned } => {
            client
                .json(
                    Method::PATCH,
                    "/constellation/v1/models/pin",
                    Some(json!({"alias": alias, "pinned": pinned})),
                )
                .await?
        }
        ModelCommand::Remove { alias, yes } => {
            if !yes {
                bail!("model removal requires --yes");
            }
            client
                .json(
                    Method::POST,
                    "/constellation/v1/models/remove",
                    Some(json!({"alias": alias})),
                )
                .await?
        }
        ModelCommand::TransferChunk {
            alias,
            chunk_sha256,
            destination_node,
            credential,
            output,
        } => {
            return run_model_transfer(
                client,
                &alias,
                &chunk_sha256,
                destination_node,
                &credential,
                &output,
            )
            .await;
        }
    };
    print_json(value);
    Ok(())
}

async fn run_model_transfer(
    client: &ControllerClient,
    alias: &str,
    chunk_sha256: &str,
    destination_node: Uuid,
    credential_path: &std::path::Path,
    output: &std::path::Path,
) -> Result<()> {
    if output.exists() {
        bail!("model chunk destination already exists");
    }
    let credential: Value = serde_json::from_slice(
        &tokio::fs::read(credential_path)
            .await
            .with_context(|| format!("read credential {}", credential_path.display()))?,
    )
    .context("decode credential file")?;
    let ticket = client
        .json_with_membership(
            Method::POST,
            "/constellation/v1/models/transfer-tickets",
            &credential,
            Some(json!({
                "alias": alias,
                "chunk_sha256": chunk_sha256,
                "destination_node": destination_node,
            })),
        )
        .await?;
    let bytes = client
        .download_chunk(chunk_sha256, &credential, &ticket)
        .await?;
    tokio::fs::write(output, bytes)
        .await
        .with_context(|| format!("write model chunk to {}", output.display()))?;
    print_json(json!({
        "status": "verified",
        "chunk_sha256": chunk_sha256,
        "destination_node": destination_node,
        "output": output,
        "ticket_id": ticket.get("id")
    }));
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // CLI commands hand off owned response values for terminal output.
fn print_json(value: Value) {
    match serde_json::to_string_pretty(&value) {
        Ok(encoded) => println!("{encoded}"),
        Err(_) => println!("{{\"error\":\"failed to encode output\"}}"),
    }
}
