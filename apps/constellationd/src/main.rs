//! Constellation controller/worker daemon.

mod api;
mod cloud;
mod enrollment;
mod oidc;
mod repository;
mod worker;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use api::{
    AppState, AuthRateLimiter, ControllerGuard, PasskeyState, local_node, router,
    spawn_workflow_engine,
};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use axum_server_mtls::MtlsAcceptor;
use clap::{Parser, ValueEnum};
use constellation_core::{Accelerator, OperatingSystem};
use constellation_identity::DeviceIdentity;
use constellation_model_store::ModelStore;
use constellation_network::BandwidthLedger;
use constellation_plugins::PluginHost;
use constellation_runtime::{
    ExoSidecarAdapter, ExoSidecarConfig, LlamaServerAdapter, LlamaServerConfig, MockRuntime,
    RuntimeAdapter, RuntimeRegistry,
};
use constellation_secrets::{ContentKeySource, OsKeyring};
use repository::Repository;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use semver::Version;
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;
use webauthn_rs::prelude::WebauthnBuilder;

/// Controller/worker process role.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Role {
    All,
    Controller,
    Worker,
}

/// Command-line settings.
#[derive(Debug, Parser)]
#[command(name = "constellationd", version, about)]
#[allow(clippy::struct_excessive_bools)] // Independent security and service-mode switches.
struct Args {
    /// Controller, worker, or combined role.
    #[arg(long, value_enum, default_value_t = Role::All)]
    role: Role,

    /// Controller origin used only by an outbound standalone worker.
    #[arg(long, env = "CONSTELLATION_CONTROLLER")]
    controller: Option<String>,

    /// Approved enrollment credential bundle used only by an outbound standalone worker.
    #[arg(long, env = "CONSTELLATION_WORKER_CREDENTIAL")]
    credential: Option<PathBuf>,

    /// Poll once and exit after heartbeat/benchmark publication; intended for service checks.
    #[arg(long, default_value_t = false)]
    worker_once: bool,

    /// API listen address. Non-loopback automatically enables cluster TLS 1.3 and requires a key.
    #[arg(long, default_value = "127.0.0.1:4317")]
    bind: SocketAddr,

    /// `SQLite` or `PostgreSQL` connection URL.
    #[arg(
        long,
        env = "CONSTELLATION_DATABASE_URL",
        default_value = "sqlite://constellation.db?mode=rwc"
    )]
    database_url: String,

    /// Exact browser origin permitted to complete passkey ceremonies.
    #[arg(
        long,
        env = "CONSTELLATION_WEBAUTHN_ORIGIN",
        default_value = "http://localhost:5173"
    )]
    webauthn_origin: url::Url,

    /// Local application-data root containing verified model chunks and runtime state.
    #[arg(
        long,
        env = "CONSTELLATION_DATA_DIR",
        default_value = "constellation-data"
    )]
    data_dir: PathBuf,

    /// Optional `llama-server` executable. Requires `--llama-model`.
    #[arg(long, env = "CONSTELLATION_LLAMA_SERVER")]
    llama_server: Option<PathBuf>,

    /// Imported model alias to materialize and serve with llama.cpp.
    #[arg(long, env = "CONSTELLATION_LLAMA_MODEL")]
    llama_model: Option<String>,

    /// Existing loopback EXO API origin. Requires the reviewed revision and model flags.
    #[arg(long, env = "CONSTELLATION_EXO_ENDPOINT")]
    exo_endpoint: Option<String>,

    /// Exact EXO Git revision installed by the external supervisor.
    #[arg(long, env = "CONSTELLATION_EXO_REVISION")]
    exo_revision: Option<String>,

    /// EXO model identifier exposed through the Constellation gateway.
    #[arg(long, env = "CONSTELLATION_EXO_MODEL")]
    exo_model: Option<String>,

    /// Bearer API key. Required for non-loopback binding.
    #[arg(long, env = "CONSTELLATION_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Emit structured JSON logs.
    #[arg(long, default_value_t = false)]
    json_logs: bool,

    /// Use a process-local authority only for loopback tests. Memberships expire on restart.
    #[arg(
        long,
        env = "CONSTELLATION_EPHEMERAL_IDENTITY",
        default_value_t = false
    )]
    ephemeral_identity: bool,

    /// Restore an offline database backup before opening the controller database.
    #[arg(long)]
    restore_from: Option<PathBuf>,

    /// Required acknowledgement that restore replaces the configured database.
    #[arg(long, default_value_t = false)]
    confirm_restore: bool,
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // Startup keeps security-sensitive initialization order explicit.
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.json_logs)?;
    validate_binding(args.bind.ip(), args.api_key.as_deref())?;
    if matches!(args.role, Role::Worker) && args.restore_from.is_some() {
        bail!("a standalone worker cannot restore a controller database");
    }
    if let Some(source) = args.restore_from.as_deref() {
        restore_database(source, &args.database_url, args.confirm_restore).await?;
    }

    let model_store = ModelStore::open(args.data_dir.join("models"))
        .await
        .context("open verified model store")?;
    let mut adapters: Vec<Arc<dyn RuntimeAdapter>> = vec![Arc::new(MockRuntime::default())];
    let mut detected = detect_local_node();
    match (args.llama_server, args.llama_model) {
        (Some(binary), Some(alias)) => {
            let model_path = model_store
                .materialize(&alias)
                .await
                .with_context(|| format!("materialize configured model alias {alias}"))?;
            let config =
                LlamaServerConfig::local(binary, model_path, alias, args.data_dir.join("runtime"));
            let adapter = LlamaServerAdapter::new(config)
                .map_err(|error| anyhow::anyhow!("configure llama.cpp adapter: {error}"))?;
            if !adapter.detect().await.unwrap_or(false) {
                bail!("configured llama.cpp runtime or model is unavailable");
            }
            adapters.push(Arc::new(adapter));
            detected
                .capabilities
                .runtimes
                .push(LlamaServerAdapter::ID.to_owned());
        }
        (None, None) => {}
        _ => bail!("--llama-server and --llama-model must be supplied together"),
    }
    match (args.exo_endpoint, args.exo_revision, args.exo_model) {
        (Some(endpoint), Some(revision), Some(model_alias)) => {
            let adapter = ExoSidecarAdapter::new(ExoSidecarConfig {
                endpoint,
                revision,
                model_alias,
            })
            .map_err(|error| anyhow::anyhow!("configure EXO sidecar adapter: {error}"))?;
            if !adapter.detect().await.unwrap_or(false) {
                bail!("configured EXO sidecar is unavailable or does not validate a placement");
            }
            adapters.push(Arc::new(adapter));
            detected
                .capabilities
                .runtimes
                .push(ExoSidecarAdapter::ID.to_owned());
        }
        (None, None, None) => {}
        _ => bail!("--exo-endpoint, --exo-revision, and --exo-model must be supplied together"),
    }
    let runtimes = RuntimeRegistry::new(adapters);
    if matches!(args.role, Role::Worker) {
        let controller = args
            .controller
            .as_deref()
            .context("--role worker requires --controller")?;
        let credential = args
            .credential
            .as_deref()
            .context("--role worker requires --credential")?;
        if args.api_key.is_some() {
            bail!("standalone workers authenticate with enrollment credentials, not --api-key");
        }
        return worker::run(controller, credential, runtimes, detected, args.worker_once).await;
    }

    if args.controller.is_some() || args.credential.is_some() || args.worker_once {
        bail!("--controller, --credential, and --worker-once require --role worker");
    }
    let repository = Repository::connect(&args.database_url).await?;
    let controller_instance_id = uuid::Uuid::now_v7();
    let initial_controller_lease = repository
        .claim_controller_lease(controller_instance_id, chrono::Utc::now(), 15)
        .await
        .context("claim controller fencing lease")?;
    let controller_guard =
        ControllerGuard::new(controller_instance_id, initial_controller_lease.as_ref());
    let local = if initial_controller_lease.is_some() {
        repository.ensure_local_node(detected).await?
    } else {
        wait_for_initialized_local_node(&repository).await?
    };
    let (event_sender, _event_receiver) = broadcast::channel(1_024);
    let api_key_hash = args
        .api_key
        .as_deref()
        .map(|key| <[u8; 32]>::from(Sha256::digest(key.as_bytes())));
    if args.ephemeral_identity && !args.bind.ip().is_loopback() {
        bail!("ephemeral identity is restricted to loopback test deployments");
    }
    let authority = if args.ephemeral_identity {
        DeviceIdentity::generate()
    } else {
        let authority_secret =
            OsKeyring::new("com.constellation.desktop", "cluster-authority-ed25519-v1")
                .load_or_create_secret_32()
                .context("load cluster authority identity")?;
        DeviceIdentity::from_secret_bytes(&authority_secret)
    };
    let content_keys = if args.ephemeral_identity {
        ContentKeySource::ephemeral()
    } else {
        ContentKeySource::os(OsKeyring::new(
            "com.constellation.desktop",
            "chat-content-key-v1",
        ))
    };
    let now = chrono::Utc::now();
    let mut bandwidth_ledger = BandwidthLedger::default();
    bandwidth_ledger.record(
        local.id.0,
        now,
        repository.network_usage(local.id.0, now).await?,
    );
    let enrollment = enrollment::EnrollmentCoordinator::new(authority);
    let passkeys = build_passkey_state(&args.webauthn_origin, args.bind.ip().is_loopback())?;
    let browser_origin = axum::http::HeaderValue::try_from(args.webauthn_origin.as_str())
        .context("passkey origin cannot be represented as an HTTP Origin header")?;
    let tls_config = if args.bind.ip().is_loopback() {
        None
    } else {
        Some(build_tls_config(enrollment.issue_server_certificate(
            args.bind.ip(),
            chrono::Utc::now(),
        )?)?)
    };
    let state = AppState {
        repository,
        runtimes,
        model_store,
        data_dir: args.data_dir,
        content_keys,
        enrollment,
        bandwidth_ledger: Arc::new(Mutex::new(bandwidth_ledger)),
        remote_kill_switch: Arc::new(AtomicBool::new(false)),
        node_mtls_required: tls_config.is_some(),
        remote_executions: Arc::new(Mutex::new(HashMap::new())),
        plugin_host: Arc::new(
            PluginHost::new(Version::new(1, 0, 0), 10_000_000)
                .map_err(|error| anyhow::anyhow!("initialize plugin sandbox: {error}"))?,
        ),
        passkeys,
        browser_origin,
        oidc: oidc::OidcState::default(),
        auth_rate_limiter: AuthRateLimiter::default(),
        controller_guard,
        controller_node: local.id,
        api_key_hash,
        events: event_sender,
    };
    spawn_controller_lease_monitor(&state);
    spawn_liveness_monitor(&state);
    spawn_workflow_engine(&state);

    tracing::info!(
        address = %args.bind,
        role = ?args.role,
        local_node_id = %local.id.0,
        controller_instance_id = %controller_instance_id,
        active_controller = initial_controller_lease.is_some(),
        "Constellation daemon ready"
    );
    let application = router(state).into_make_service();
    if let Some(config) = tls_config {
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
        let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(config));
        axum_server::bind(args.bind)
            .handle(handle)
            .acceptor(acceptor)
            .serve(application)
            .await
            .context("serve TLS 1.3 Constellation API")?;
    } else {
        let listener = tokio::net::TcpListener::bind(args.bind)
            .await
            .with_context(|| format!("bind daemon to {}", args.bind))?;
        axum::serve(listener, application)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("serve loopback Constellation API")?;
    }
    Ok(())
}

fn build_passkey_state(origin: &url::Url, loopback: bool) -> Result<PasskeyState> {
    let host = origin
        .host_str()
        .context("passkey origin must include a host")?;
    if !loopback && origin.scheme() != "https" {
        bail!("non-loopback passkey origin must use https");
    }
    let builder = WebauthnBuilder::new(host, origin)
        .map_err(|error| anyhow::anyhow!("configure passkey relying party: {error}"))?
        .rp_name("Constellation")
        .allow_any_port(loopback);
    let webauthn = builder
        .build()
        .map_err(|error| anyhow::anyhow!("build passkey relying party: {error}"))?;
    Ok(PasskeyState::new(webauthn))
}

async fn wait_for_initialized_local_node(
    repository: &Repository,
) -> Result<constellation_core::Node> {
    for _ in 0..50 {
        if let Some(node) = repository.local_node().await? {
            return Ok(node);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    bail!("standby controller could not observe the active controller's initialized node")
}

fn build_tls_config(
    material: constellation_identity::ServerCertificateMaterial,
) -> Result<RustlsConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            material.certificate_authority_der.clone(),
        ))
        .context("load cluster CA as mTLS client root")?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(provider.clone()))
            .allow_unauthenticated()
            .build()
            .context("build optional enrollment client verifier")?;
    let certificates = material
        .certificate_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.private_key_der));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("restrict control traffic to TLS 1.3")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .context("configure controller certificate")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

async fn restore_database(
    source: &std::path::Path,
    database_url: &str,
    confirmed: bool,
) -> Result<()> {
    if !confirmed {
        bail!("restore requires --confirm-restore");
    }
    if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
        return restore_postgres_database(source, database_url).await;
    }
    let destination = sqlite_database_path(database_url)?;
    if destination.exists()
        && tokio::fs::canonicalize(source).await.ok()
            == tokio::fs::canonicalize(&destination).await.ok()
    {
        bail!("restore source and destination must be different files");
    }
    let mut source_file = tokio::fs::File::open(source)
        .await
        .with_context(|| format!("read restore source {}", source.display()))?;
    let mut source_header = [0_u8; 16];
    source_file
        .read_exact(&mut source_header)
        .await
        .context("read SQLite restore header")?;
    if source_header != *b"SQLite format 3\0" {
        bail!("restore source is not a SQLite database");
    }
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create restore destination directory")?;
    }
    let recovery_directory = destination
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!(
            ".constellation-pre-restore-{}",
            uuid::Uuid::now_v7()
        ));
    let had_existing = destination.exists();
    if had_existing {
        tokio::fs::create_dir(&recovery_directory)
            .await
            .context("create recoverable pre-restore directory")?;
        for candidate in database_sidecars(&destination) {
            if candidate.exists() {
                let file_name = candidate
                    .file_name()
                    .context("restore database path has no file name")?;
                if let Err(error) =
                    tokio::fs::rename(&candidate, recovery_directory.join(file_name)).await
                {
                    // SQLite may remove a closed WAL or shared-memory sidecar between
                    // the existence check and rename. The database itself must never
                    // disappear from the recovery copy.
                    if candidate != destination && error.kind() == std::io::ErrorKind::NotFound {
                        continue;
                    }
                    return Err(error).with_context(|| {
                        format!(
                            "preserve pre-restore database state from {}",
                            candidate.display()
                        )
                    });
                }
            }
        }
    }
    if let Err(error) = tokio::fs::copy(source, &destination).await {
        if had_existing {
            let _ignored = tokio::fs::remove_file(&destination).await;
            for candidate in database_sidecars(&destination) {
                let Some(file_name) = candidate.file_name() else {
                    continue;
                };
                let preserved = recovery_directory.join(file_name);
                if preserved.exists() {
                    let _ignored = tokio::fs::rename(preserved, candidate).await;
                }
            }
        }
        return Err(error).context("copy restored database");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
            .await
            .context("protect restored database permissions")?;
    }
    if had_existing {
        tracing::warn!(
            recovery_path = %recovery_directory.display(),
            "database restored; previous state remains recoverable"
        );
    }
    Ok(())
}

async fn restore_postgres_database(source: &std::path::Path, database_url: &str) -> Result<()> {
    let mut source_file = tokio::fs::File::open(source)
        .await
        .with_context(|| format!("read restore source {}", source.display()))?;
    let mut source_header = [0_u8; 5];
    source_file
        .read_exact(&mut source_header)
        .await
        .context("read PostgreSQL restore header")?;
    if source_header != *b"PGDMP" {
        bail!("PostgreSQL restore requires a pg_dump custom-format backup");
    }
    let parsed = url::Url::parse(database_url).context("parse PostgreSQL restore URL")?;
    let database_name = percent_encoding::percent_decode_str(parsed.path().trim_start_matches('/'))
        .decode_utf8()
        .context("decode PostgreSQL database name")?;
    if database_name.is_empty() {
        bail!("PostgreSQL restore URL must name a database");
    }
    let mut command = tokio::process::Command::new("pg_restore");
    command
        .args(["--clean", "--if-exists", "--no-owner", "--exit-on-error"])
        .arg("--dbname")
        .arg(database_name.as_ref())
        .arg(source);
    if let Some(host) = parsed.host_str() {
        command.env("PGHOST", host);
    }
    if let Some(port) = parsed.port() {
        command.env("PGPORT", port.to_string());
    }
    if !parsed.username().is_empty() {
        command.env(
            "PGUSER",
            percent_encoding::percent_decode_str(parsed.username())
                .decode_utf8()
                .context("decode PostgreSQL user")?
                .as_ref(),
        );
    }
    if let Some(password) = parsed.password() {
        command.env(
            "PGPASSWORD",
            percent_encoding::percent_decode_str(password)
                .decode_utf8()
                .context("decode PostgreSQL password")?
                .as_ref(),
        );
    }
    for (key, value) in parsed.query_pairs() {
        let environment = match key.as_ref() {
            "sslmode" => Some("PGSSLMODE"),
            "sslrootcert" => Some("PGSSLROOTCERT"),
            "sslcert" => Some("PGSSLCERT"),
            "sslkey" => Some("PGSSLKEY"),
            _ => None,
        };
        if let Some(environment) = environment {
            command.env(environment, value.as_ref());
        }
    }
    let status = command.status().await.context("launch pg_restore")?;
    if !status.success() {
        bail!("pg_restore did not complete successfully");
    }
    Ok(())
}

fn sqlite_database_path(database_url: &str) -> Result<PathBuf> {
    let path = database_url
        .strip_prefix("sqlite://")
        .and_then(|value| value.split('?').next())
        .filter(|value| !value.is_empty() && *value != ":memory:")
        .context("restore requires a file-backed sqlite:// database URL")?;
    Ok(PathBuf::from(path))
}

fn database_sidecars(database: &std::path::Path) -> [PathBuf; 3] {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ]
}

fn spawn_liveness_monitor(state: &AppState) {
    let liveness_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if !liveness_state
                .controller_guard
                .authorize(&liveness_state.repository)
                .await
            {
                continue;
            }
            match liveness_state
                .repository
                .reconcile_liveness(chrono::Utc::now())
                .await
            {
                Ok(events) => {
                    for event in events {
                        let _ignored = liveness_state.events.send(event);
                    }
                }
                Err(error) => tracing::error!(%error, "liveness reconciliation failed"),
            }
            match liveness_state
                .repository
                .reconcile_worker_leases(chrono::Utc::now())
                .await
            {
                Ok(actions) => {
                    for action in actions {
                        let _ignored = liveness_state.events.send(action.event);
                        if action.retried {
                            continue;
                        }
                        let sender = liveness_state
                            .remote_executions
                            .lock()
                            .await
                            .remove(&action.lease_id);
                        if let Some(sender) = sender {
                            let _ignored = sender
                                .send(constellation_runtime::RuntimeEvent::Failure {
                                    code: if action.output_started {
                                        "generation_interrupted".to_owned()
                                    } else {
                                        "worker_unavailable".to_owned()
                                    },
                                    message: if action.output_started {
                                        "generation stopped after partial output".to_owned()
                                    } else {
                                        "worker did not accept the retried lease".to_owned()
                                    },
                                    retryable: !action.output_started,
                                    output_started: action.output_started,
                                })
                                .await;
                        }
                    }
                }
                Err(error) => tracing::error!(%error, "worker lease reconciliation failed"),
            }
        }
    });
}

fn spawn_controller_lease_monitor(state: &AppState) {
    let lease_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            match lease_state
                .repository
                .claim_controller_lease(
                    lease_state.controller_guard.controller_id(),
                    chrono::Utc::now(),
                    15,
                )
                .await
            {
                Ok(lease) => lease_state.controller_guard.update(lease.as_ref()),
                Err(error) => {
                    lease_state.controller_guard.update(None);
                    tracing::error!(%error, "controller fencing lease renewal failed");
                }
            }
        }
    });
}

fn validate_binding(ip: IpAddr, api_key: Option<&str>) -> Result<()> {
    if !ip.is_loopback() && ip.is_unspecified() {
        bail!("non-loopback TLS requires an explicit interface IP instead of a wildcard address");
    }
    if !ip.is_loopback() && api_key.is_none_or(|key| key.len() < 24) {
        bail!("non-loopback binding requires CONSTELLATION_API_KEY with at least 24 characters");
    }
    Ok(())
}

fn init_logging(json: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("constellationd=info,tower_http=info"));
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize JSON logging: {error}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize logging: {error}"))?;
    }
    Ok(())
}

fn detect_local_node() -> constellation_core::Node {
    let mut system = System::new_all();
    system.refresh_all();
    let name = System::host_name().unwrap_or_else(|| "This computer".to_owned());
    let os = match std::env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::MacOs,
        "linux" => OperatingSystem::Linux,
        _ => OperatingSystem::Unknown,
    };
    let cpu_model = system
        .cpus()
        .first()
        .map_or_else(|| "Unknown CPU".to_owned(), |cpu| cpu.brand().to_owned());
    let logical_cores = u16::try_from(system.cpus().len()).unwrap_or(u16::MAX);
    let total_memory = system.total_memory();
    let mut node = local_node(
        name,
        os,
        std::env::consts::ARCH.to_owned(),
        cpu_model.clone(),
        logical_cores,
        total_memory,
        system.available_memory(),
    );
    node.capabilities.accelerator = detect_accelerator(total_memory, &cpu_model);
    node
}

fn detect_accelerator(total_memory_bytes: u64, cpu_model: &str) -> Option<Accelerator> {
    if let Some(accelerator) = detect_nvidia_accelerator() {
        return Some(accelerator);
    }
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Some(Accelerator {
            vendor: "apple".to_owned(),
            model: cpu_model.to_owned(),
            memory_bytes: total_memory_bytes,
            backends: vec!["metal".to_owned()],
        });
    }
    detect_amd_vulkan_accelerator()
}

fn detect_nvidia_accelerator() -> Option<Accelerator> {
    let output = ProcessCommand::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| parse_nvidia_smi(&String::from_utf8_lossy(&output.stdout)))
        .flatten()
}

fn parse_nvidia_smi(output: &str) -> Option<Accelerator> {
    let first = output.lines().find(|line| !line.trim().is_empty())?;
    let (model, memory_mib) = first.split_once(',')?;
    let memory_mib = memory_mib.trim().parse::<u64>().ok()?;
    Some(Accelerator {
        vendor: "nvidia".to_owned(),
        model: model.trim().to_owned(),
        memory_bytes: memory_mib.saturating_mul(1024 * 1024),
        backends: vec!["cuda".to_owned(), "vulkan".to_owned()],
    })
}

#[cfg(target_os = "linux")]
fn detect_amd_vulkan_accelerator() -> Option<Accelerator> {
    let output = ProcessCommand::new("lspci").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| {
            let normalized = line.to_ascii_lowercase();
            (normalized.contains("amd") || normalized.contains("ati"))
                && (normalized.contains("vga") || normalized.contains("display"))
        })?
        .to_owned();
    Some(Accelerator {
        vendor: "amd".to_owned(),
        model: line,
        memory_bytes: 0,
        backends: vec!["vulkan".to_owned()],
    })
}

#[cfg(not(target_os = "linux"))]
const fn detect_amd_vulkan_accelerator() -> Option<Accelerator> {
    None
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install terminate handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use axum::Extension;
    use axum::routing::get;
    use axum_server_mtls::PeerCertificates;

    use super::*;

    #[test]
    fn non_loopback_requires_strong_key() {
        assert!(
            validate_binding(
                "0.0.0.0".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                Some("this-is-at-least-24-characters"),
            )
            .is_err()
        );
        let result = validate_binding(
            "192.0.2.1".parse().unwrap_or(IpAddr::from([192, 0, 2, 1])),
            None,
        );
        assert!(result.is_err());
        let result = validate_binding(
            "192.0.2.1".parse().unwrap_or(IpAddr::from([192, 0, 2, 1])),
            Some("this-is-at-least-24-characters"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn generated_tls_config_accepts_only_tls_thirteen() {
        let identity = DeviceIdentity::generate();
        let material =
            identity.issue_server_certificate(IpAddr::from([192, 0, 2, 1]), chrono::Utc::now());
        assert!(material.is_ok_and(|value| build_tls_config(value).is_ok()));
    }

    #[tokio::test]
    async fn cluster_tls_exposes_a_verified_device_identity() {
        let authority = DeviceIdentity::generate();
        let device = DeviceIdentity::generate();
        let device_id = uuid::Uuid::now_v7();
        let now = chrono::Utc::now();
        let server = authority
            .issue_server_certificate(IpAddr::from([127, 0, 0, 1]), now)
            .unwrap_or_else(|error| panic!("server certificate: {error}"));
        let device_certificate = authority
            .issue_device_certificate(device_id, device.public_key_bytes(), now)
            .unwrap_or_else(|error| panic!("device certificate: {error}"));
        let config = build_tls_config(server).unwrap_or_else(|error| panic!("TLS config: {error}"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("bind test listener: {error}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("configure listener: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("test address: {error}"));
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let application = axum::Router::new().route(
            "/peer",
            get(|Extension(peer): Extension<PeerCertificates>| async move {
                peer.leaf_cn().unwrap_or_else(|| "anonymous".to_owned())
            }),
        );
        let task = tokio::spawn(async move {
            axum_server::from_tcp(listener)
                .unwrap_or_else(|error| panic!("create test server: {error}"))
                .acceptor(MtlsAcceptor::new(RustlsAcceptor::new(config)))
                .handle(server_handle)
                .serve(application.into_make_service())
                .await
        });
        let identity_pem = format!(
            "{}{}",
            device_certificate.certificate_pem,
            device.private_key_pem().unwrap_or_default()
        );
        let client = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    device_certificate.certificate_authority_pem.as_bytes(),
                )
                .unwrap_or_else(|error| panic!("CA: {error}")),
            )
            .identity(
                reqwest::Identity::from_pem(identity_pem.as_bytes())
                    .unwrap_or_else(|error| panic!("identity: {error}")),
            )
            .build()
            .unwrap_or_else(|error| panic!("client: {error}"));
        let response = client
            .get(format!("https://{address}/peer"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("mTLS request: {error}"));
        assert_eq!(
            response.text().await.unwrap_or_default(),
            device_id.to_string()
        );
        handle.shutdown();
        assert!(task.await.is_ok_and(|result| result.is_ok()));
    }

    #[test]
    fn loopback_is_safe_without_key() {
        let result = validate_binding(IpAddr::from([127, 0, 0, 1]), None);
        assert!(result.is_ok());
    }

    #[test]
    fn parses_nvidia_inventory_without_localized_units() {
        let accelerator = parse_nvidia_smi("NVIDIA RTX 4090, 24564\n");
        assert!(accelerator.is_some());
        let accelerator = accelerator.unwrap_or_else(|| panic!("accelerator missing"));
        assert_eq!(accelerator.vendor, "nvidia");
        assert_eq!(accelerator.model, "NVIDIA RTX 4090");
        assert_eq!(accelerator.memory_bytes, 24_564 * 1024 * 1024);
        assert!(accelerator.backends.iter().any(|backend| backend == "cuda"));
    }

    #[tokio::test]
    async fn restore_requires_confirmation_and_preserves_a_recovery_copy() {
        let root =
            std::env::temp_dir().join(format!("constellation-restore-{}", uuid::Uuid::now_v7()));
        assert!(tokio::fs::create_dir(&root).await.is_ok());
        let source = root.join("source.db");
        let destination = root.join("destination.db");
        let source_url = format!("sqlite://{}?mode=rwc", source.display());
        let destination_url = format!("sqlite://{}?mode=rwc", destination.display());
        let source_repository = Repository::connect(&source_url)
            .await
            .unwrap_or_else(|error| panic!("source repository: {error}"));
        source_repository.close().await;
        let destination_repository = Repository::connect(&destination_url)
            .await
            .unwrap_or_else(|error| panic!("destination repository: {error}"));
        destination_repository.close().await;
        assert!(
            restore_database(&source, &destination_url, false)
                .await
                .is_err()
        );
        let restored = restore_database(&source, &destination_url, true).await;
        assert!(restored.is_ok(), "restore failed: {:?}", restored.err());
        let reopened = Repository::connect(&destination_url).await;
        assert!(reopened.is_ok());
        if let Ok(repository) = reopened {
            repository.close().await;
        }
        let entries = std::fs::read_dir(&root)
            .map(|values| {
                values
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(
            entries
                .iter()
                .any(|name| name.starts_with(".constellation-pre-restore-"))
        );
        let _ignored = tokio::fs::remove_dir_all(&root).await;
    }
}
