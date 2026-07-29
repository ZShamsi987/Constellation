//! HTTP, SSE, and WebSocket product surface.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Extension, Path, Query, Request, State, WebSocketUpgrade};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive};
use axum::response::{IntoResponse, Response, Sse};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use axum_server_mtls::PeerCertificates;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use constellation_core::{
    Accelerator, BenchmarkReport, ClusterEvent, ExecutionPlan, ExecutionStrategy, Node,
    NodeCapabilities, NodeId, NodeResourcePolicy, NodeStatus, OperatingSystem, PlanId, PrivacyPath,
    SchedulingPolicy, WorkerLease, WorkerRuntimeEvent, WorkloadClass, WorkloadId, WorkloadRequest,
};
use constellation_identity::{
    DeviceCertificate, IdentityError, InvitationMethod, InvitationPresentation, InvitationStatus,
    MembershipCredential, PeerTransferTicket,
};
use constellation_model_store::{
    ImportOptions, LicenseAcceptance, ModelManifest, ModelStore, ModelStoreError,
};
use constellation_network::{
    BandwidthLedger, NetworkError, NetworkPolicy, TransportCandidate, TransportDecision,
    select_transport,
};
use constellation_plugins::{PluginGrant, PluginHost, PluginKind, PluginManifest, validate_grant};
use constellation_runtime::{MockRuntime, RuntimeEvent, RuntimeRegistry, RuntimeRequest};
use constellation_scheduler::{
    ClusterSnapshot, DistributedRequirements, NodeStrategyCapabilities, SimulationScenario,
    observe_plan, plan, plan_distributed, simulate_plan as simulate_digital_twin,
    usable_system_memory_with_policy,
};
use constellation_secrets::{ContentKeySource, EncryptedContent, OsKeyring, SecretError};
use constellation_teams::{
    AuthProvider, AuthProviderKind, CloudAdapterPolicy, ControllerLease, Permission, Principal,
    Role, TeamMembership, validate_auth_provider, validate_cloud_policy,
};
use constellation_workflows::{
    ArtifactMetadata, RunStatus, StepAccounting, StepAction, StepDefinition, StepStatus,
    WorkflowDefinition, WorkflowEvent, WorkflowId, WorkflowRun, WorkflowRunId, WorkflowSchedule,
    apply_event, create_run, definition_sha256, json_schema, next_schedule_after, ready_steps,
    validate, validate_schedule,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Webauthn,
};

use crate::repository::{ConversationRecord, ExecutionTraceSpan, Repository};

/// Shared API dependencies.
#[derive(Clone)]
pub struct AppState {
    /// Durable state.
    pub repository: Repository,
    /// Ordered runtime adapter registry.
    pub runtimes: RuntimeRegistry,
    /// Verified local model cache.
    pub model_store: ModelStore,
    /// Private application-data root for bounded temporary operational artifacts.
    pub data_dir: PathBuf,
    /// OS-native credential handle used only for encrypted chat persistence.
    pub content_keys: ContentKeySource,
    /// Secret-bearing invitation state and cluster authority.
    pub enrollment: crate::enrollment::EnrollmentCoordinator,
    /// Observed remote byte accounting used before transport selection.
    pub bandwidth_ledger: Arc<Mutex<BandwidthLedger>>,
    /// Process-local emergency remote networking stop.
    pub remote_kill_switch: Arc<AtomicBool>,
    /// Require a CA-validated client certificate matching the membership device ID.
    pub node_mtls_required: bool,
    /// Live consumers for durable remote leases; plaintext remains memory-only.
    pub remote_executions: Arc<Mutex<HashMap<Uuid, mpsc::Sender<RuntimeEvent>>>>,
    /// Sandboxed component host shared by plugin executions.
    pub plugin_host: Arc<PluginHost>,
    /// Relying-party configuration and server-held, single-use passkey ceremonies.
    pub passkeys: PasskeyState,
    /// Exact browser origin admitted by CORS and the `WebAuthn` relying party.
    pub browser_origin: HeaderValue,
    /// Server-held, single-use OIDC authorization ceremonies.
    pub oidc: crate::oidc::OidcState,
    /// Process-wide backstop for expensive browser authentication ceremonies.
    pub auth_rate_limiter: AuthRateLimiter,
    /// Active controller identity and fencing term used to reject standby writes.
    pub controller_guard: ControllerGuard,
    /// Local controller node.
    pub controller_node: NodeId,
    /// Hash of the configured API key; absent only for loopback-local mode.
    pub api_key_hash: Option<[u8; 32]>,
    /// Content-free live events.
    pub events: broadcast::Sender<ClusterEvent>,
}

/// Shared view of the database-backed singleton controller lease.
#[derive(Clone)]
pub struct ControllerGuard {
    controller_id: Uuid,
    term: Arc<AtomicU64>,
    fencing_token: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
}

impl ControllerGuard {
    /// Creates a process identity and applies its initial lease, if acquired.
    #[must_use]
    pub fn new(controller_id: Uuid, lease: Option<&ControllerLease>) -> Self {
        let guard = Self {
            controller_id,
            term: Arc::new(AtomicU64::new(0)),
            fencing_token: Arc::new(AtomicU64::new(0)),
            active: Arc::new(AtomicBool::new(false)),
        };
        guard.update(lease);
        guard
    }

    /// Updates the process-local view only from a freshly committed lease claim.
    pub fn update(&self, lease: Option<&ControllerLease>) {
        if let Some(lease) = lease.filter(|lease| lease.controller_id == self.controller_id) {
            self.term.store(lease.term, Ordering::SeqCst);
            self.fencing_token
                .store(lease.fencing_token, Ordering::SeqCst);
            self.active.store(true, Ordering::SeqCst);
        } else {
            self.active.store(false, Ordering::SeqCst);
        }
    }

    /// Returns this process's stable controller instance identity.
    #[must_use]
    pub const fn controller_id(&self) -> Uuid {
        self.controller_id
    }

    /// Verifies the current database lease immediately before a write boundary.
    pub(crate) async fn authorize(&self, repository: &Repository) -> bool {
        if !self.active.load(Ordering::SeqCst) {
            return false;
        }
        repository
            .controller_lease()
            .await
            .ok()
            .flatten()
            .is_some_and(|lease| {
                lease
                    .authorize_write(
                        self.controller_id,
                        self.term.load(Ordering::SeqCst),
                        self.fencing_token.load(Ordering::SeqCst),
                        Utc::now(),
                    )
                    .is_ok()
            })
    }
}

/// Server-side `WebAuthn` ceremony state. Challenge state is never sent back as a cookie or token.
#[derive(Clone)]
pub struct PasskeyState {
    /// Validated relying-party implementation.
    pub webauthn: Webauthn,
    registrations: Arc<Mutex<HashMap<Uuid, PendingPasskeyRegistration>>>,
    authentications: Arc<Mutex<HashMap<Uuid, PendingPasskeyAuthentication>>>,
}

/// Bounded sliding-window limiter for public authentication endpoints.
#[derive(Clone)]
pub struct AuthRateLimiter {
    attempts: Arc<Mutex<VecDeque<Instant>>>,
    maximum: usize,
    window: std::time::Duration,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(VecDeque::new())),
            maximum: 120,
            window: std::time::Duration::from_mins(1),
        }
    }
}

impl AuthRateLimiter {
    async fn admit(&self) -> bool {
        let mut attempts = self.attempts.lock().await;
        while attempts
            .front()
            .is_some_and(|attempt| attempt.elapsed() >= self.window)
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.maximum {
            return false;
        }
        attempts.push_back(Instant::now());
        true
    }
}

struct PendingPasskeyRegistration {
    principal_id: Uuid,
    name: String,
    created_at: Instant,
    state: PasskeyRegistration,
}

struct PendingPasskeyAuthentication {
    principal_id: Uuid,
    created_at: Instant,
    state: PasskeyAuthentication,
}

impl PasskeyState {
    /// Builds an empty ceremony store around an origin-validated relying party.
    #[must_use]
    pub fn new(webauthn: Webauthn) -> Self {
        Self {
            webauthn,
            registrations: Arc::new(Mutex::new(HashMap::new())),
            authentications: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Clone)]
enum AuthenticatedPrincipal {
    Owner,
    Node(NodeId),
    Human(Principal),
    Service(Principal),
}

/// Builds the complete API router.
#[allow(clippy::too_many_lines)] // Keeping the versioned public route inventory visible aids contract review.
pub fn router(state: AppState) -> Router {
    let configured_browser_origin = state.browser_origin.clone();
    let cors = CorsLayer::new()
        .allow_origin(vec![
            configured_browser_origin,
            HeaderValue::from_static("http://127.0.0.1:5173"),
            HeaderValue::from_static("http://localhost:5173"),
            HeaderValue::from_static("http://tauri.localhost"),
            HeaderValue::from_static("https://tauri.localhost"),
            HeaderValue::from_static("tauri://localhost"),
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-constellation-membership"),
            axum::http::HeaderName::from_static("x-constellation-transfer-ticket"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE]);

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/constellation/v1/cluster", get(cluster_summary))
        .route("/constellation/v1/models", get(list_local_models))
        .route("/constellation/v1/models/import", post(import_local_model))
        .route("/constellation/v1/models/verify", post(verify_local_model))
        .route("/constellation/v1/models/pin", patch(pin_local_model))
        .route("/constellation/v1/models/remove", post(remove_local_model))
        .route("/constellation/v1/backup", get(download_backup))
        .route(
            "/constellation/v1/network/policy",
            get(get_network_policy).patch(update_network_policy),
        )
        .route(
            "/constellation/v1/network/simulate",
            post(simulate_transport),
        )
        .route(
            "/constellation/v1/emergency/remote-disable",
            post(disable_remote_networking),
        )
        .route(
            "/constellation/v1/models/transfer-tickets",
            post(create_transfer_ticket),
        )
        .route(
            "/constellation/v1/models/chunks/{chunk_sha256}",
            get(download_model_chunk),
        )
        .route(
            "/constellation/v1/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/constellation/v1/invitations/{invitation_id}/approve",
            post(approve_invitation),
        )
        .route("/constellation/v1/enrollment/begin", post(begin_enrollment))
        .route(
            "/constellation/v1/enrollment/confirm",
            post(confirm_enrollment),
        )
        .route(
            "/constellation/v1/enrollment/credential",
            post(get_enrollment_credential),
        )
        .route(
            "/constellation/v1/chat/conversations",
            get(list_conversations).post(create_conversation),
        )
        .route(
            "/constellation/v1/chat/conversations/{conversation_id}",
            delete(delete_conversation),
        )
        .route(
            "/constellation/v1/chat/conversations/{conversation_id}/messages",
            get(list_conversation_messages).post(append_conversation_message),
        )
        .route(
            "/constellation/v1/devices",
            get(list_devices).post(register_device),
        )
        .route(
            "/constellation/v1/devices/{node_id}/status",
            patch(update_device_status),
        )
        .route(
            "/constellation/v1/devices/{node_id}/heartbeat",
            post(device_heartbeat),
        )
        .route(
            "/constellation/v1/devices/{node_id}/inventory",
            post(update_device_inventory),
        )
        .route(
            "/constellation/v1/devices/{node_id}/revoke",
            post(revoke_device),
        )
        .route(
            "/constellation/v1/devices/{node_id}/credentials/rotate",
            post(rotate_device_credentials),
        )
        .route(
            "/constellation/v1/workers/{node_id}/leases/poll",
            post(poll_worker_lease),
        )
        .route(
            "/constellation/v1/workers/{node_id}/leases/{lease_id}/events",
            post(submit_worker_event),
        )
        .route(
            "/constellation/v1/devices/{node_id}/policy",
            get(get_device_policy).patch(update_device_policy),
        )
        .route(
            "/constellation/v1/benchmarks",
            get(list_benchmarks).post(submit_benchmark),
        )
        .route(
            "/constellation/v1/reports/benchmark",
            get(export_benchmark_report),
        )
        .route("/constellation/v1/plans/simulate", post(simulate_plan))
        .route(
            "/constellation/v1/plans/distributed/simulate",
            post(simulate_distributed_plan),
        )
        .route(
            "/constellation/v1/plans/workload/{workload_id}",
            get(get_workload_plan),
        )
        .route(
            "/constellation/v1/plans/workload/{workload_id}/digital-twin",
            post(run_digital_twin),
        )
        .route(
            "/constellation/v1/plans/workload/{workload_id}/observations",
            post(record_plan_observation),
        )
        .route(
            "/constellation/v1/traces/workload/{workload_id}",
            get(list_trace_spans).post(record_trace_span),
        )
        .route("/constellation/v1/workflows/schema", get(workflow_schema))
        .route(
            "/constellation/v1/workflows",
            get(list_workflows).post(create_workflow),
        )
        .route(
            "/constellation/v1/workflows/{workflow_id}",
            get(get_workflow),
        )
        .route(
            "/constellation/v1/workflows/{workflow_id}/runs",
            post(start_workflow),
        )
        .route(
            "/constellation/v1/workflows/{workflow_id}/schedules",
            post(create_workflow_schedule),
        )
        .route(
            "/constellation/v1/workflows/{workflow_id}/webhooks",
            post(create_workflow_webhook),
        )
        .route(
            "/constellation/v1/workflow-runs/{run_id}",
            get(get_workflow_run),
        )
        .route(
            "/constellation/v1/workflow-runs/{run_id}/events",
            post(transition_workflow_run),
        )
        .route(
            "/constellation/v1/workflow-runs/{run_id}/artifacts",
            post(create_workflow_artifact),
        )
        .route(
            "/constellation/v1/workflow-artifacts/{artifact_id}",
            get(download_workflow_artifact),
        )
        .route(
            "/constellation/v1/workflow-templates",
            get(list_workflow_templates).post(create_workflow_template),
        )
        .route(
            "/constellation/v1/workflow-templates/{template_id}/instantiate",
            post(instantiate_workflow_template),
        )
        .route(
            "/constellation/v1/workflow-webhooks/{webhook_id}/trigger",
            post(trigger_workflow_webhook),
        )
        .route("/constellation/v1/plugins", get(list_plugins))
        .route("/constellation/v1/plugins/install", post(install_plugin))
        .route(
            "/constellation/v1/plugins/{plugin_id}/grant",
            post(grant_plugin),
        )
        .route(
            "/constellation/v1/plugins/{plugin_id}/execute",
            post(execute_plugin),
        )
        .route(
            "/constellation/v1/principals",
            get(list_principals).post(create_principal),
        )
        .route("/constellation/v1/teams", get(list_teams).post(create_team))
        .route(
            "/constellation/v1/teams/{team_id}/members",
            get(list_team_members).post(put_team_member),
        )
        .route(
            "/constellation/v1/auth/passkeys/registration/begin",
            post(begin_passkey_registration),
        )
        .route(
            "/constellation/v1/auth/passkeys/registration/finish",
            post(finish_passkey_registration),
        )
        .route(
            "/constellation/v1/auth/passkeys/login/begin",
            post(begin_passkey_login),
        )
        .route(
            "/constellation/v1/auth/passkeys/login/finish",
            post(finish_passkey_login),
        )
        .route(
            "/constellation/v1/auth-providers",
            get(list_auth_providers).post(put_auth_provider),
        )
        .route(
            "/constellation/v1/auth-providers/{provider_id}/links",
            post(link_external_identity),
        )
        .route(
            "/constellation/v1/auth/oidc/providers",
            get(list_oidc_login_providers),
        )
        .route(
            "/constellation/v1/auth/oidc/login/begin",
            post(begin_oidc_login),
        )
        .route(
            "/constellation/v1/auth/oidc/login/finish",
            post(finish_oidc_login),
        )
        .route(
            "/constellation/v1/cloud-adapters",
            get(list_cloud_adapters).post(put_cloud_adapter),
        )
        .route(
            "/constellation/v1/control-plane/lease",
            get(get_controller_lease).post(acquire_controller_lease),
        )
        .route(
            "/constellation/v1/workloads/{workload_id}/cancel",
            post(cancel_workload),
        )
        .route("/constellation/v1/events", get(list_events))
        .route("/constellation/v1/events/live", get(live_events))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .layer(cors)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Starts restart-safe workflow dispatch. Ready independent steps are leased before their work is
/// spawned, so branches execute concurrently without duplicating after a daemon restart.
pub fn spawn_workflow_engine(state: &AppState) {
    let engine_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if !engine_state
                .controller_guard
                .authorize(&engine_state.repository)
                .await
            {
                continue;
            }
            if let Err(error) = dispatch_workflow_schedules(&engine_state).await {
                tracing::error!(code = %error.code, "workflow schedule scan failed");
            }
            let run_ids = match engine_state.repository.active_workflow_runs(1_000).await {
                Ok(run_ids) => run_ids,
                Err(error) => {
                    tracing::error!(%error, "workflow recovery scan failed");
                    continue;
                }
            };
            for run_id in run_ids {
                let Ok((run, definition, _)) = load_workflow_run(&engine_state, run_id).await
                else {
                    continue;
                };
                if run.status != RunStatus::Running {
                    continue;
                }
                let now = Utc::now();
                for definition_step in &definition.steps {
                    let Some(step_state) = run.steps.get(&definition_step.id) else {
                        continue;
                    };
                    let expired = step_state.status == StepStatus::Running
                        && step_state.started_at.is_some_and(|started_at| {
                            now.signed_duration_since(started_at).num_seconds()
                                >= i64::from(definition_step.timeout_seconds)
                        });
                    if expired {
                        let event = WorkflowEvent::StepLeaseExpired {
                            step_id: definition_step.id.clone(),
                        };
                        let _ignored =
                            apply_workflow_transition(&engine_state, run_id, &event).await;
                    }
                }
                for step_id in ready_steps(&run, &definition) {
                    let Some(step) = definition
                        .steps
                        .iter()
                        .find(|candidate| candidate.id == step_id)
                        .cloned()
                    else {
                        continue;
                    };
                    if matches!(step.action, StepAction::Approval { .. }) {
                        let event = WorkflowEvent::ApprovalRequested {
                            step_id: step.id.clone(),
                        };
                        let _ignored =
                            apply_workflow_transition(&engine_state, run_id, &event).await;
                        continue;
                    }
                    let started = WorkflowEvent::StepStarted {
                        step_id: step.id.clone(),
                    };
                    if apply_workflow_transition(&engine_state, run_id, &started)
                        .await
                        .unwrap_or(false)
                    {
                        let execution_state = engine_state.clone();
                        tokio::spawn(async move {
                            execute_workflow_step(execution_state, run_id, step).await;
                        });
                    }
                }
            }
        }
    });
}

async fn dispatch_workflow_schedules(state: &AppState) -> Result<(), ApiError> {
    let now = Utc::now();
    let due = state
        .repository
        .due_workflow_schedules(now, 1_000)
        .await
        .map_err(ApiError::internal)?;
    for (schedule, due_at) in due {
        let next_run_at = next_schedule_after(&schedule.cron_utc, due_at)
            .map_err(|error| ApiError::internal(error.into()))?;
        let run_id = WorkflowRunId::new();
        let _claimed = state
            .repository
            .claim_workflow_schedule(schedule.id, due_at, next_run_at, run_id)
            .await
            .map_err(ApiError::internal)?;
    }
    let firings = state
        .repository
        .pending_workflow_schedule_firings(1_000)
        .await
        .map_err(ApiError::internal)?;
    for firing in firings {
        let active = state
            .repository
            .active_schedule_run_count(firing.schedule.id)
            .await
            .map_err(ApiError::internal)?;
        if active >= u32::from(firing.schedule.concurrency_limit) {
            continue;
        }
        start_workflow_run_with_id(
            state,
            firing.schedule.workflow_id,
            BTreeMap::new(),
            Some(firing.run_id),
        )
        .await?;
        state
            .repository
            .mark_workflow_schedule_started(firing.schedule.id, firing.due_at)
            .await
            .map_err(ApiError::internal)?;
    }
    Ok(())
}

async fn apply_workflow_transition(
    state: &AppState,
    run_id: WorkflowRunId,
    event: &WorkflowEvent,
) -> Result<bool, ApiError> {
    for _ in 0..8 {
        let (mut run, definition, expected_nonce) = load_workflow_run(state, run_id).await?;
        let expected_status = run_status_str(run.status).to_owned();
        apply_event(&mut run, &definition, event, Utc::now()).map_err(|error| {
            ApiError::bad_request("invalid_workflow_transition", &error.to_string())
        })?;
        let encrypted = encrypt_workflow_run(state, &run)?;
        let (event_type, step_id, principal_id) = workflow_event_metadata(event);
        let cluster_event = state
            .repository
            .update_workflow_run(
                run_id,
                &expected_status,
                &expected_nonce,
                run_status_str(run.status),
                &encrypted,
                event_type,
                step_id,
                principal_id,
            )
            .await
            .map_err(ApiError::internal)?;
        if let Some(cluster_event) = cluster_event {
            publish(state, cluster_event);
            return Ok(true);
        }
    }
    Ok(false)
}

async fn execute_workflow_step(state: AppState, run_id: WorkflowRunId, step: StepDefinition) {
    let started_at = Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(u64::from(step.timeout_seconds)),
        execute_workflow_action(&state, run_id, &step),
    )
    .await
    .unwrap_or_else(|_| {
        Err(WorkflowActionError {
            code: "deadline_exceeded".to_owned(),
            retryable: true,
        })
    });
    let event = match result {
        Ok((mut accounting, artifacts)) => {
            accounting.duration_ms =
                u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            WorkflowEvent::StepSucceeded {
                step_id: step.id,
                accounting,
                artifacts,
            }
        }
        Err(error) => {
            tracing::warn!(run_id = %run_id.0, step_id = %step.id, code = %error.code, "workflow step failed");
            WorkflowEvent::StepFailed {
                step_id: step.id,
                error_code: error.code,
                retryable: error.retryable,
            }
        }
    };
    let _ignored = apply_workflow_transition(&state, run_id, &event).await;
}

struct WorkflowActionError {
    code: String,
    retryable: bool,
}

#[allow(clippy::too_many_lines)] // Keeps every sandboxed workflow action's content boundary explicit.
async fn execute_workflow_action(
    state: &AppState,
    run_id: WorkflowRunId,
    step: &StepDefinition,
) -> Result<(StepAccounting, Vec<Uuid>), WorkflowActionError> {
    let (run, _, _) = load_workflow_run(state, run_id)
        .await
        .map_err(|_| WorkflowActionError {
            code: "workflow_state_unavailable".to_owned(),
            retryable: true,
        })?;
    match &step.action {
        StepAction::Inference {
            model,
            input,
            max_output_tokens,
        } => {
            let resolved = resolve_workflow_template(input, &run.inputs);
            let execution = prepare_execution(state, model, resolved, *max_output_tokens)
                .await
                .map_err(|_| WorkflowActionError {
                    code: "inference_unavailable".to_owned(),
                    retryable: true,
                })?;
            let result =
                collect_execution(state, execution)
                    .await
                    .map_err(|_| WorkflowActionError {
                        code: "inference_interrupted".to_owned(),
                        retryable: true,
                    })?;
            let artifact_id = store_workflow_artifact(
                state,
                run_id,
                &step.id,
                &format!("{}.txt", step.id),
                "text/plain; charset=utf-8",
                result.text.as_bytes(),
            )
            .await
            .map_err(|_| WorkflowActionError {
                code: "artifact_storage_failed".to_owned(),
                retryable: true,
            })?;
            Ok((
                StepAccounting {
                    input_tokens: u64::from(result.input_tokens),
                    output_tokens: u64::from(result.output_tokens),
                    network_bytes: result.plan.estimated_network_bytes,
                    duration_ms: 0,
                    cost_micros: 0,
                },
                vec![artifact_id],
            ))
        }
        StepAction::Artifact {
            name,
            media_type,
            value,
        } => {
            let resolved = resolve_workflow_template(value, &run.inputs);
            let artifact_id = store_workflow_artifact(
                state,
                run_id,
                &step.id,
                name,
                media_type,
                resolved.as_bytes(),
            )
            .await
            .map_err(|_| WorkflowActionError {
                code: "artifact_storage_failed".to_owned(),
                retryable: true,
            })?;
            Ok((StepAccounting::default(), vec![artifact_id]))
        }
        StepAction::Tool {
            tool, arguments, ..
        } => {
            let installed = state
                .repository
                .plugin(tool)
                .await
                .map_err(|_| WorkflowActionError {
                    code: "tool_registry_unavailable".to_owned(),
                    retryable: true,
                })?
                .filter(|plugin| plugin.enabled && plugin.manifest.kind == PluginKind::Tool)
                .ok_or_else(|| WorkflowActionError {
                    code: "tool_permission_unavailable".to_owned(),
                    retryable: false,
                })?;
            let grant = state
                .repository
                .plugin_grant(tool)
                .await
                .map_err(|_| WorkflowActionError {
                    code: "tool_registry_unavailable".to_owned(),
                    retryable: true,
                })?
                .ok_or_else(|| WorkflowActionError {
                    code: "tool_permission_unavailable".to_owned(),
                    retryable: false,
                })?;
            let component = tokio::fs::read(&installed.component_path)
                .await
                .map_err(|_| WorkflowActionError {
                    code: "tool_component_unavailable".to_owned(),
                    retryable: true,
                })?;
            let plugin_input =
                serde_json::to_string(arguments).map_err(|_| WorkflowActionError {
                    code: "tool_input_invalid".to_owned(),
                    retryable: false,
                })?;
            let host = Arc::clone(&state.plugin_host);
            let manifest = installed.manifest;
            let output = tokio::task::spawn_blocking(move || {
                host.execute(&manifest, &grant, &component, &plugin_input)
            })
            .await
            .map_err(|_| WorkflowActionError {
                code: "tool_host_unavailable".to_owned(),
                retryable: true,
            })?
            .map_err(|_| WorkflowActionError {
                code: "tool_execution_failed".to_owned(),
                retryable: false,
            })?;
            let artifact_id = store_workflow_artifact(
                state,
                run_id,
                &step.id,
                &format!("{}.json", step.id),
                "application/json",
                output.as_bytes(),
            )
            .await
            .map_err(|_| WorkflowActionError {
                code: "artifact_storage_failed".to_owned(),
                retryable: true,
            })?;
            Ok((StepAccounting::default(), vec![artifact_id]))
        }
        StepAction::Approval { .. } => Err(WorkflowActionError {
            code: "approval_dispatch_error".to_owned(),
            retryable: false,
        }),
    }
}

async fn store_workflow_artifact(
    state: &AppState,
    run_id: WorkflowRunId,
    step_id: &str,
    name: &str,
    media_type: &str,
    content: &[u8],
) -> Result<Uuid, ApiError> {
    if content.len() > 16 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "workflow_artifact_too_large",
            "workflow artifact exceeds the 16 MiB limit",
        ));
    }
    let artifact_id = Uuid::now_v7();
    let encrypted = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .seal(
            workflow_artifact_ad(artifact_id, run_id).as_bytes(),
            content,
        )
        .map_err(ApiError::secret)?;
    let metadata = ArtifactMetadata {
        id: artifact_id,
        run_id,
        step_id: step_id.to_owned(),
        name: name.to_owned(),
        media_type: media_type.to_owned(),
        sha256: format!("{:x}", Sha256::digest(content)),
        size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
        storage_key: artifact_id.to_string(),
        created_at: Utc::now(),
    };
    let event = state
        .repository
        .put_workflow_artifact(&metadata, &encrypted)
        .await
        .map_err(ApiError::internal)?;
    publish(state, event);
    Ok(artifact_id)
}

fn resolve_workflow_template(template: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut resolved = template.to_owned();
    for (key, value) in inputs {
        resolved = resolved.replace(&format!("{{{{{key}}}}}"), value);
    }
    resolved
}

#[allow(clippy::too_many_lines)] // Authentication order keeps credential classes and fail-closed routing explicit.
async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let requires_active_controller = matches!(
        *request.method(),
        Method::POST | Method::PATCH | Method::DELETE
    ) || request.uri().path() == "/constellation/v1/backup";
    if requires_active_controller && !state.controller_guard.authorize(&state.repository).await {
        return Err(ApiError::unavailable(
            "this controller is a standby or its fencing lease has expired",
        ));
    }
    if matches!(request.uri().path(), "/health" | "/ready")
        || request
            .uri()
            .path()
            .starts_with("/constellation/v1/enrollment/")
        || (request
            .uri()
            .path()
            .starts_with("/constellation/v1/workflow-webhooks/")
            && request.uri().path().ends_with("/trigger"))
        || request
            .uri()
            .path()
            .starts_with("/constellation/v1/auth/passkeys/login/")
        || request
            .uri()
            .path()
            .starts_with("/constellation/v1/auth/oidc/")
    {
        return Ok(next.run(request).await);
    }
    let token = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .find_map(|protocol| protocol.strip_prefix("constellation.bearer."))
                })
                .map(str::to_owned)
        });
    if let (Some(expected), Some(token)) = (state.api_key_hash, token.as_deref()) {
        let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if bool::from(actual.ct_eq(&expected)) {
            request
                .extensions_mut()
                .insert(AuthenticatedPrincipal::Owner);
            return Ok(next.run(request).await);
        }
    }
    if let Some(token) = token.as_deref() {
        let key_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        if let Ok(Some(principal)) = state
            .repository
            .principal_by_session_hash(&key_hash, Utc::now())
            .await
        {
            let permission = required_service_permission(request.method(), request.uri().path());
            if !principal.allows(permission) {
                return Err(ApiError::forbidden(
                    "principal does not have the required permission",
                ));
            }
            request
                .extensions_mut()
                .insert(AuthenticatedPrincipal::Human(principal));
            return Ok(next.run(request).await);
        }
        if let Ok(Some(principal)) = state
            .repository
            .service_principal_by_key_hash(&key_hash)
            .await
        {
            let permission = required_service_permission(request.method(), request.uri().path());
            if !principal.allows(permission) {
                return Err(ApiError::forbidden(
                    "service identity does not have the required scope",
                ));
            }
            request
                .extensions_mut()
                .insert(AuthenticatedPrincipal::Service(principal));
            return Ok(next.run(request).await);
        }
    }
    if let Some(encoded) = request
        .headers()
        .get("x-constellation-membership")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 4_096)
        && let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded.as_bytes())
        && let Ok(credential) = serde_json::from_slice::<MembershipCredential>(&bytes)
        && credential.verify(&state.enrollment.authority_public_key(), Utc::now(), 1)
        && state
            .repository
            .credential_active(credential.serial, credential.device_id)
            .await
            .unwrap_or(false)
        && node_transport_authenticated(&state, &request, &credential)
        && node_route_allowed(request.method(), request.uri().path())
    {
        request.extensions_mut().insert(credential.clone());
        request
            .extensions_mut()
            .insert(AuthenticatedPrincipal::Node(NodeId(credential.device_id)));
        return Ok(next.run(request).await);
    }
    if state.api_key_hash.is_none() {
        request
            .extensions_mut()
            .insert(AuthenticatedPrincipal::Owner);
        Ok(next.run(request).await)
    } else {
        Err(ApiError::unauthorized(
            "valid owner or node credentials required",
        ))
    }
}

fn required_service_permission(method: &Method, path: &str) -> Permission {
    if path.starts_with("/v1/") {
        return if *method == Method::GET {
            Permission::ClusterRead
        } else {
            Permission::WorkloadExecute
        };
    }
    if path.contains("/emergency/") || path.ends_with("/revoke") {
        Permission::EmergencyControl
    } else if path.contains("/plugins/") && path.ends_with("/execute") {
        Permission::WorkflowOperate
    } else if path.contains("/plugins") {
        if *method == Method::GET {
            Permission::ClusterRead
        } else {
            Permission::PluginAdmin
        }
    } else if path.contains("/auth-providers") || path.contains("/cloud-adapters") {
        Permission::ProviderAdmin
    } else if path.contains("/auth/passkeys/registration") {
        Permission::ClusterRead
    } else if path.contains("/teams") || path.contains("/principals") {
        Permission::TeamAdmin
    } else if path.contains("/workflows") || path.contains("/workflow-") {
        if *method == Method::GET {
            Permission::ClusterRead
        } else {
            Permission::WorkflowOperate
        }
    } else if path.contains("/workloads") {
        Permission::WorkloadExecute
    } else if *method == Method::GET {
        Permission::ClusterRead
    } else {
        Permission::ClusterAdmin
    }
}

fn principal_allows(principal: &AuthenticatedPrincipal, permission: Permission) -> bool {
    match principal {
        AuthenticatedPrincipal::Owner => true,
        AuthenticatedPrincipal::Node(_) => permission == Permission::NodeOperate,
        AuthenticatedPrincipal::Human(principal) | AuthenticatedPrincipal::Service(principal) => {
            principal.allows(permission)
        }
    }
}

fn node_transport_authenticated(
    state: &AppState,
    request: &Request,
    credential: &MembershipCredential,
) -> bool {
    !state.node_mtls_required
        || request
            .extensions()
            .get::<PeerCertificates>()
            .and_then(PeerCertificates::leaf_cn)
            .is_some_and(|common_name| common_name == credential.device_id.to_string())
}

fn node_route_allowed(method: &Method, path: &str) -> bool {
    (method == Method::POST
        && (path.ends_with("/heartbeat")
            || path == "/constellation/v1/benchmarks"
            || path.ends_with("/inventory")
            || path == "/constellation/v1/models/transfer-tickets"
            || path.ends_with("/leases/poll")
            || path.ends_with("/events") && path.contains("/workers/")
            || path.ends_with("/credentials/rotate")))
        || (method == Method::GET && path.starts_with("/constellation/v1/models/chunks/"))
        || ((method == Method::GET || method == Method::PATCH) && path.ends_with("/policy"))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    if !state.controller_guard.authorize(&state.repository).await {
        return Err(ApiError::unavailable(
            "controller does not hold the active fencing lease",
        ));
    }
    if !state.runtimes.any_ready().await {
        return Err(ApiError::unavailable("runtime is not ready"));
    }
    Ok(Json(HealthResponse {
        status: "ready",
        version: env!("CARGO_PKG_VERSION"),
    }))
}

#[derive(Debug, Serialize)]
struct ModelList {
    object: &'static str,
    data: Vec<ModelInfo>,
}

#[derive(Debug, Serialize)]
struct ModelInfo {
    id: String,
    object: &'static str,
    owned_by: &'static str,
    created: i64,
}

async fn models(State(state): State<AppState>) -> Result<Json<ModelList>, ApiError> {
    let capabilities = state
        .runtimes
        .capabilities()
        .await
        .map_err(ApiError::runtime)?;
    let mut data = capabilities
        .into_iter()
        .flat_map(|capability| capability.models)
        .map(|id| ModelInfo {
            id,
            object: "model",
            owned_by: "constellation",
            created: 0,
        })
        .collect::<Vec<_>>();
    for policy in state
        .repository
        .cloud_policies()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|policy| {
            policy.enabled
                && policy.provider_plugin == crate::cloud::OPENAI_COMPATIBLE_PROVIDER
                && policy.endpoint.is_some()
        })
    {
        data.extend(policy.models.into_iter().map(|model| ModelInfo {
            id: crate::cloud::model_alias(policy.id, &model),
            object: "model",
            owned_by: "external-provider",
            created: 0,
        }));
    }
    Ok(Json(ModelList {
        object: "list",
        data,
    }))
}

#[derive(Debug, Deserialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    stream: bool,
    max_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
    tools: Option<Value>,
    response_format: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    role: String,
    content: Value,
}

async fn chat_completions(
    State(state): State<AppState>,
    Json(request): Json<ChatRequest>,
) -> Result<Response, ApiError> {
    reject_unsupported(
        &request.model,
        request.tools.as_ref(),
        request.response_format.as_ref(),
    )?;
    let input = request
        .messages
        .iter()
        .filter(|message| message.role != "assistant")
        .filter_map(|message| value_to_text(&message.content))
        .collect::<Vec<_>>()
        .join("\n");
    let max_tokens = request
        .max_completion_tokens
        .or(request.max_tokens)
        .unwrap_or(256)
        .clamp(1, 4_096);
    let execution = prepare_execution(&state, &request.model, input, max_tokens).await?;
    if request.stream {
        Ok(chat_stream(state, request.model, execution).into_response())
    } else {
        let result = collect_execution(&state, execution).await?;
        Ok(Json(json!({
            "id": format!("chatcmpl-{}", result.workload_id.0),
            "object": "chat.completion",
            "created": Utc::now().timestamp(),
            "model": request.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": result.text},
                "finish_reason": result.finish_reason
            }],
            "usage": {
                "prompt_tokens": result.input_tokens,
                "completion_tokens": result.output_tokens,
                "total_tokens": result.input_tokens + result.output_tokens
            },
            "constellation": {"plan_id": result.plan.id, "selected_nodes": result.plan.selected_nodes}
        }))
        .into_response())
    }
}

#[derive(Debug, Deserialize)]
struct ResponsesRequest {
    model: String,
    input: Value,
    #[serde(default)]
    stream: bool,
    max_output_tokens: Option<u32>,
    tools: Option<Value>,
    text: Option<Value>,
}

async fn responses(
    State(state): State<AppState>,
    Json(request): Json<ResponsesRequest>,
) -> Result<Response, ApiError> {
    reject_unsupported(
        &request.model,
        request.tools.as_ref(),
        request.text.as_ref(),
    )?;
    let input = value_to_text(&request.input).unwrap_or_else(|| request.input.to_string());
    let execution = prepare_execution(
        &state,
        &request.model,
        input,
        request.max_output_tokens.unwrap_or(256).clamp(1, 4_096),
    )
    .await?;
    if request.stream {
        Ok(responses_stream(state, request.model, execution).into_response())
    } else {
        let result = collect_execution(&state, execution).await?;
        Ok(Json(json!({
            "id": format!("resp_{}", result.workload_id.0),
            "object": "response",
            "created_at": Utc::now().timestamp(),
            "status": "completed",
            "model": request.model,
            "output": [{
                "id": format!("msg_{}", Uuid::new_v4()),
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": result.text, "annotations": []}]
            }],
            "usage": {"input_tokens": result.input_tokens, "output_tokens": result.output_tokens, "total_tokens": result.input_tokens + result.output_tokens},
            "constellation": {"plan": result.plan}
        }))
        .into_response())
    }
}

#[derive(Debug, Deserialize)]
struct CompletionRequest {
    model: String,
    prompt: Value,
    #[serde(default)]
    stream: bool,
    max_tokens: Option<u32>,
}

async fn completions(
    State(state): State<AppState>,
    Json(request): Json<CompletionRequest>,
) -> Result<Response, ApiError> {
    let input = value_to_text(&request.prompt).unwrap_or_else(|| request.prompt.to_string());
    let execution = prepare_execution(
        &state,
        &request.model,
        input,
        request.max_tokens.unwrap_or(256).clamp(1, 4_096),
    )
    .await?;
    if request.stream {
        Ok(completion_stream(state, request.model, execution).into_response())
    } else {
        let result = collect_execution(&state, execution).await?;
        Ok(Json(json!({
            "id": format!("cmpl-{}", result.workload_id.0),
            "object": "text_completion",
            "created": Utc::now().timestamp(),
            "model": request.model,
            "choices": [{"text": result.text, "index": 0, "finish_reason": result.finish_reason}],
            "usage": {"prompt_tokens": result.input_tokens, "completion_tokens": result.output_tokens, "total_tokens": result.input_tokens + result.output_tokens},
            "constellation": {"plan_id": result.plan.id}
        }))
        .into_response())
    }
}

#[derive(Debug, Deserialize)]
struct EmbeddingRequest {
    model: String,
    input: Value,
}

async fn embeddings(Json(request): Json<EmbeddingRequest>) -> Result<Json<Value>, ApiError> {
    if request.model != MockRuntime::MODEL {
        return Err(ApiError::not_found(
            "model_not_found",
            "requested embedding model is unavailable",
        ));
    }
    let inputs = match &request.input {
        Value::Array(items) => items
            .iter()
            .filter_map(value_to_text)
            .collect::<Vec<String>>(),
        other => vec![value_to_text(other).unwrap_or_else(|| other.to_string())],
    };
    let total_tokens = inputs.iter().fold(0_u32, |total, input| {
        total.saturating_add(u32::try_from(input.split_whitespace().count()).unwrap_or(u32::MAX))
    });
    let data = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let digest = Sha256::digest(input.as_bytes());
            let embedding = digest
                .iter()
                .map(|byte| f64::from(*byte) / 255.0)
                .collect::<Vec<_>>();
            json!({"object": "embedding", "index": index, "embedding": embedding})
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "object": "list",
        "data": data,
        "model": request.model,
        "usage": {"prompt_tokens": total_tokens, "total_tokens": total_tokens}
    })))
}

fn reject_unsupported(
    model: &str,
    tools: Option<&Value>,
    structured: Option<&Value>,
) -> Result<(), ApiError> {
    let runtime = if crate::cloud::parse_model_alias(model).is_some() {
        "the built-in cloud gateway"
    } else {
        "the selected runtime"
    };
    if tools.is_some_and(|value| !value.is_null() && value != &json!([])) {
        return Err(ApiError::bad_request(
            "unsupported_feature",
            &format!("{runtime} does not support tool calling"),
        ));
    }
    if structured.is_some_and(|value| !value.is_null()) {
        return Err(ApiError::bad_request(
            "unsupported_feature",
            &format!("{runtime} does not support structured output"),
        ));
    }
    Ok(())
}

struct PreparedExecution {
    workload: WorkloadRequest,
    plan: ExecutionPlan,
    receiver: tokio::sync::mpsc::Receiver<RuntimeEvent>,
}

#[allow(clippy::too_many_lines)] // Planning, durable handoff, and local fallback remain visibly ordered.
async fn prepare_execution(
    state: &AppState,
    model: &str,
    input: String,
    max_output_tokens: u32,
) -> Result<PreparedExecution, ApiError> {
    if let Some((policy_id, provider_model)) = crate::cloud::parse_model_alias(model) {
        return prepare_cloud_execution(
            state,
            policy_id,
            provider_model,
            model,
            input,
            max_output_tokens,
        )
        .await;
    }
    let runtime = state
        .runtimes
        .adapter_for_model(model)
        .await
        .map_err(ApiError::runtime)?;
    let capabilities = runtime.capabilities().await.map_err(ApiError::runtime)?;
    let workload = WorkloadRequest {
        id: WorkloadId::new(),
        model: model.to_owned(),
        required_runtime: capabilities.runtime_id,
        estimated_memory_bytes: 1024 * 1024 * 1024,
        class: WorkloadClass::Interactive,
        policy: SchedulingPolicy::Balanced,
        allowed_nodes: Vec::new(),
        allow_remote: false,
    };
    let mut nodes = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?;
    let available_workers = state
        .repository
        .available_workers(Utc::now())
        .await
        .map_err(ApiError::internal)?;
    nodes.retain(|node| node.id == state.controller_node || available_workers.contains(&node.id));
    let benchmarks = state
        .repository
        .benchmarks()
        .await
        .map_err(ApiError::internal)?;
    let policies = state
        .repository
        .resource_policies()
        .await
        .map_err(ApiError::internal)?;
    let snapshot = ClusterSnapshot {
        nodes,
        benchmarks,
        policies,
        controller_node: Some(state.controller_node),
        observed_at: Utc::now(),
    };
    let plan = plan(&workload, &snapshot)
        .map_err(|error| ApiError::unavailable(&format!("no safe execution plan: {error}")))?;
    let event = state
        .repository
        .create_workload(&workload, &plan)
        .await
        .map_err(ApiError::internal)?;
    publish(state, event);
    let selected_node = plan
        .selected_nodes
        .first()
        .copied()
        .ok_or_else(|| ApiError::unavailable("scheduler returned no execution target"))?;
    if selected_node != state.controller_node {
        let cipher = state.content_keys.load_cipher().map_err(ApiError::secret)?;
        let lease_id = Uuid::now_v7();
        let encrypted = cipher
            .seal(
                lease_associated_data(lease_id, workload.id).as_bytes(),
                input.as_bytes(),
            )
            .map_err(ApiError::secret)?;
        let (stored_lease_id, lease_event) = state
            .repository
            .create_worker_lease(
                lease_id,
                workload.id,
                selected_node,
                encrypted.version,
                &encrypted.nonce,
                &encrypted.ciphertext,
                max_output_tokens,
            )
            .await
            .map_err(ApiError::internal)?;
        if stored_lease_id != lease_id {
            return Err(ApiError::internal(anyhow::anyhow!(
                "worker lease identity changed during persistence"
            )));
        }
        publish(state, lease_event);
        let (sender, receiver) = mpsc::channel(256);
        state
            .remote_executions
            .lock()
            .await
            .insert(lease_id, sender);
        return Ok(PreparedExecution {
            workload,
            plan,
            receiver,
        });
    }
    let receiver = runtime
        .execute_stream(RuntimeRequest {
            workload_id: workload.id,
            model: model.to_owned(),
            input,
            max_output_tokens,
            plan: plan.clone(),
        })
        .await
        .map_err(ApiError::runtime)?;
    Ok(PreparedExecution {
        workload,
        plan,
        receiver,
    })
}

#[allow(clippy::too_many_lines)] // Quota, privacy-plan, persistence, and egress ordering stay explicit.
async fn prepare_cloud_execution(
    state: &AppState,
    policy_id: Uuid,
    provider_model: &str,
    public_model: &str,
    input: String,
    max_output_tokens: u32,
) -> Result<PreparedExecution, ApiError> {
    let policy = state
        .repository
        .cloud_policy(policy_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found("model_not_found", "requested cloud model is unavailable")
        })?;
    crate::cloud::validate_execution_policy(&policy, provider_model).map_err(|_| {
        ApiError::not_found("model_not_found", "requested cloud model is unavailable")
    })?;
    let workload = WorkloadRequest {
        id: WorkloadId::new(),
        model: public_model.to_owned(),
        required_runtime: policy.provider_plugin.clone(),
        estimated_memory_bytes: 0,
        class: WorkloadClass::Interactive,
        policy: SchedulingPolicy::Balanced,
        allowed_nodes: vec![state.controller_node],
        allow_remote: true,
    };
    let reservation = crate::cloud::reservation(&policy, &input, max_output_tokens);
    let reservation_event = state
        .repository
        .reserve_cloud_usage(
            policy.id,
            workload.id,
            reservation.cost_micros,
            reservation.network_bytes,
            policy.monthly_cost_limit_micros,
            policy.monthly_network_limit_bytes,
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::rate_limited("cloud monthly spend or network ceiling would be exceeded")
        })?;
    publish(state, reservation_event);
    let endpoint_host = policy
        .endpoint
        .as_ref()
        .and_then(url::Url::host_str)
        .unwrap_or("configured provider");
    let plan = ExecutionPlan {
        id: PlanId::new(),
        workload_id: workload.id,
        strategy: ExecutionStrategy::SingleNode,
        selected_nodes: vec![state.controller_node],
        estimated_ttft_ms: 1_000.0,
        estimated_tokens_per_second: 10.0,
        estimated_memory_bytes: BTreeMap::new(),
        estimated_network_bytes: reservation.network_bytes,
        confidence: 0.5,
        reasons: vec![
            format!("The request explicitly selected an enabled cloud model at {endpoint_host}."),
            format!(
                "A worst-case reservation of {} cost-millionths and {} network bytes was committed before egress.",
                reservation.cost_micros, reservation.network_bytes
            ),
            format!("Allowed provider regions: {}.", policy.regions.join(", ")),
        ],
        alternatives: Vec::new(),
        privacy: PrivacyPath {
            prompt_nodes: vec![state.controller_node],
            model_weight_nodes: Vec::new(),
            uses_relay: false,
            leaves_local_network: true,
            uses_cloud: true,
            content_logged: false,
        },
        replan_triggers: vec![
            "the provider rejects the request or interrupts the stream".to_owned(),
            "actual spend or network use reaches its precommitted reservation".to_owned(),
        ],
        created_at: Utc::now(),
    };
    let event = match state.repository.create_workload(&workload, &plan).await {
        Ok(event) => event,
        Err(error) => {
            release_cloud_reservation(state, workload.id).await;
            return Err(ApiError::internal(error));
        }
    };
    publish(state, event);
    let receiver = match crate::cloud::execute_stream(
        &policy,
        provider_model.to_owned(),
        input,
        max_output_tokens,
        workload.id,
        reservation,
        state.repository.clone(),
        state.events.clone(),
    ) {
        Ok(receiver) => receiver,
        Err(error) => {
            release_cloud_reservation(state, workload.id).await;
            if let Ok(Some(event)) = state
                .repository
                .complete_workload(workload.id, "interrupted")
                .await
            {
                publish(state, event);
            }
            return Err(ApiError::unavailable(&format!(
                "cloud execution could not start: {error}"
            )));
        }
    };
    Ok(PreparedExecution {
        workload,
        plan,
        receiver,
    })
}

async fn release_cloud_reservation(state: &AppState, workload_id: WorkloadId) {
    if let Ok(Some(event)) = state
        .repository
        .complete_cloud_usage(workload_id, 0, 0)
        .await
    {
        publish(state, event);
    }
}

struct CollectedExecution {
    workload_id: WorkloadId,
    plan: ExecutionPlan,
    text: String,
    input_tokens: u32,
    output_tokens: u32,
    finish_reason: String,
}

async fn collect_execution(
    state: &AppState,
    mut execution: PreparedExecution,
) -> Result<CollectedExecution, ApiError> {
    let mut text = String::new();
    let mut input_tokens = 0;
    let mut output_tokens = 0;
    let mut finish_reason = "stop".to_owned();
    let mut terminal_error = None;
    let mut completed = false;
    let mut cancelled = false;
    while let Some(event) = execution.receiver.recv().await {
        match event {
            RuntimeEvent::TextDelta(delta) => text.push_str(&delta),
            RuntimeEvent::Finished {
                input_tokens: input,
                output_tokens: output,
                finish_reason: reason,
            } => {
                input_tokens = input;
                output_tokens = output;
                finish_reason = reason;
                completed = true;
            }
            RuntimeEvent::Cancelled => cancelled = true,
            RuntimeEvent::Failure { output_started, .. } => terminal_error = Some(output_started),
            RuntimeEvent::Loading { .. } | RuntimeEvent::Prefill { .. } => {}
        }
    }
    let terminal_status = if completed {
        "completed"
    } else if cancelled {
        "cancelled"
    } else {
        "interrupted"
    };
    let event = state
        .repository
        .complete_workload(execution.workload.id, terminal_status)
        .await
        .map_err(ApiError::internal)?;
    if let Some(event) = event {
        publish(state, event);
    }
    if cancelled {
        return Err(ApiError::generation_cancelled());
    }
    if terminal_error.is_some() || !completed {
        return Err(ApiError::generation_interrupted(
            terminal_error.unwrap_or(!text.is_empty()),
        ));
    }
    Ok(CollectedExecution {
        workload_id: execution.workload.id,
        plan: execution.plan,
        text,
        input_tokens,
        output_tokens,
        finish_reason,
    })
}

fn chat_stream(
    state: AppState,
    model: String,
    mut execution: PreparedExecution,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let id = format!("chatcmpl-{}", execution.workload.id.0);
        let mut terminal_status = "interrupted";
        while let Some(runtime_event) = execution.receiver.recv().await {
            match runtime_event {
                RuntimeEvent::TextDelta(delta) => {
                    let data = json!({
                        "id": id,
                        "object": "chat.completion.chunk",
                        "created": Utc::now().timestamp(),
                        "model": model,
                        "choices": [{"index": 0, "delta": {"content": delta}, "finish_reason": null}],
                        "constellation": {"plan_id": execution.plan.id, "selected_nodes": execution.plan.selected_nodes}
                    });
                    yield Ok(Event::default().data(data.to_string()));
                }
                RuntimeEvent::Finished { finish_reason, .. } => {
                    terminal_status = "completed";
                    let data = json!({
                        "id": id,
                        "object": "chat.completion.chunk",
                        "created": Utc::now().timestamp(),
                        "model": model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}]
                    });
                    yield Ok(Event::default().data(data.to_string()));
                }
                RuntimeEvent::Cancelled => {
                    terminal_status = "cancelled";
                    yield Ok(Event::default().data(json!({"error": {"type": "cancelled", "code": "cancelled", "message": "generation was cancelled"}}).to_string()));
                }
                RuntimeEvent::Failure { code, message, retryable, output_started } => {
                    terminal_status = "interrupted";
                    yield Ok(Event::default().data(json!({"error": {
                        "type": "server_error", "code": code, "message": message,
                        "retryable": retryable, "partial_output": output_started
                    }}).to_string()));
                }
                RuntimeEvent::Loading { .. } | RuntimeEvent::Prefill { .. } => {}
            }
        }
        if let Ok(Some(event)) = state.repository.complete_workload(execution.workload.id, terminal_status).await {
            publish(&state, event);
        }
        yield Ok(Event::default().data("[DONE]"));
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn responses_stream(
    state: AppState,
    model: String,
    mut execution: PreparedExecution,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let response_id = format!("resp_{}", execution.workload.id.0);
        yield Ok(Event::default().event("response.created").data(json!({
            "type": "response.created",
            "response": {"id": response_id, "object": "response", "status": "in_progress", "model": model},
            "constellation": {"plan": execution.plan}
        }).to_string()));
        let mut output = String::new();
        let mut terminal_status = "interrupted";
        while let Some(runtime_event) = execution.receiver.recv().await {
            match runtime_event {
                RuntimeEvent::TextDelta(delta) => {
                    output.push_str(&delta);
                    yield Ok(Event::default().event("response.output_text.delta").data(json!({
                        "type": "response.output_text.delta",
                        "response_id": response_id,
                        "delta": delta
                    }).to_string()));
                }
                RuntimeEvent::Failure { code, message, retryable, output_started } => {
                    terminal_status = "interrupted";
                    yield Ok(Event::default().event("response.failed").data(json!({
                        "type": "response.failed", "response_id": response_id,
                        "error": {"code": code, "message": message, "retryable": retryable,
                                  "partial_output": output_started}
                    }).to_string()));
                }
                RuntimeEvent::Cancelled => terminal_status = "cancelled",
                RuntimeEvent::Finished { .. } => terminal_status = "completed",
                RuntimeEvent::Loading { .. } | RuntimeEvent::Prefill { .. } => {}
            }
        }
        if let Ok(Some(event)) = state.repository.complete_workload(execution.workload.id, terminal_status).await {
            publish(&state, event);
        }
        if terminal_status == "completed" {
            yield Ok(Event::default().event("response.completed").data(json!({
                "type": "response.completed",
                "response": {"id": response_id, "object": "response", "status": "completed", "model": model, "output_text": output}
            }).to_string()));
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn completion_stream(
    state: AppState,
    model: String,
    mut execution: PreparedExecution,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        let id = format!("cmpl-{}", execution.workload.id.0);
        let mut terminal_status = "interrupted";
        while let Some(runtime_event) = execution.receiver.recv().await {
            match runtime_event {
                RuntimeEvent::TextDelta(delta) => yield Ok(Event::default().data(json!({
                    "id": id, "object": "text_completion", "model": model,
                    "choices": [{"text": delta, "index": 0, "finish_reason": null}]
                }).to_string())),
                RuntimeEvent::Finished { finish_reason, .. } => {
                    terminal_status = "completed";
                    yield Ok(Event::default().data(json!({
                        "id": id, "object": "text_completion", "model": model,
                        "choices": [{"text": "", "index": 0, "finish_reason": finish_reason}]
                    }).to_string()));
                }
                RuntimeEvent::Failure { code, message, retryable, output_started } => {
                    terminal_status = "interrupted";
                    yield Ok(Event::default().data(json!({"error": {
                        "type": "server_error", "code": code, "message": message,
                        "retryable": retryable, "partial_output": output_started
                    }}).to_string()));
                }
                RuntimeEvent::Cancelled => terminal_status = "cancelled",
                RuntimeEvent::Loading { .. } | RuntimeEvent::Prefill { .. } => {}
            }
        }
        if let Ok(Some(event)) = state.repository.complete_workload(execution.workload.id, terminal_status).await {
            publish(&state, event);
        }
        yield Ok(Event::default().data("[DONE]"));
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn value_to_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let parts = items
                .iter()
                .filter_map(|item| {
                    item.get("text")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| value_to_text(item))
                })
                .collect::<Vec<_>>();
            (!parts.is_empty()).then(|| parts.join("\n"))
        }
        Value::Object(map) => map
            .get("content")
            .or_else(|| map.get("input"))
            .and_then(value_to_text),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

#[derive(Debug, Deserialize)]
struct ModelImportRequest {
    path: PathBuf,
    alias: String,
    #[serde(default = "default_model_format")]
    format: String,
    quantization: Option<String>,
    source: Option<String>,
    license_id: String,
    #[serde(default)]
    license_accepted: bool,
    #[serde(default)]
    pinned: bool,
}

fn default_model_format() -> String {
    "gguf".to_owned()
}

#[derive(Debug, Deserialize)]
struct ModelAliasRequest {
    alias: String,
}

#[derive(Debug, Deserialize)]
struct ModelPinRequest {
    alias: String,
    pinned: bool,
}

async fn list_local_models(
    State(state): State<AppState>,
) -> Result<Json<Vec<ModelManifest>>, ApiError> {
    state
        .model_store
        .list()
        .await
        .map(Json)
        .map_err(ApiError::model_store)
}

async fn import_local_model(
    State(state): State<AppState>,
    Json(request): Json<ModelImportRequest>,
) -> Result<(StatusCode, Json<ModelManifest>), ApiError> {
    let source = request.source.unwrap_or_else(|| {
        request
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("local model")
            .to_owned()
    });
    let license = request.license_accepted.then(|| LicenseAcceptance {
        license_id: request.license_id,
        accepted_at: Utc::now(),
        source: source.clone(),
    });
    let manifest = state
        .model_store
        .import_file(
            request.path,
            ImportOptions {
                alias: request.alias,
                format: request.format,
                quantization: request.quantization,
                source,
                license,
                pinned: request.pinned,
            },
        )
        .await
        .map_err(ApiError::model_store)?;
    let event = state
        .repository
        .put_model(&manifest)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(manifest)))
}

async fn verify_local_model(
    State(state): State<AppState>,
    Json(request): Json<ModelAliasRequest>,
) -> Result<Json<ModelManifest>, ApiError> {
    let manifest = state
        .model_store
        .verify_alias(&request.alias)
        .await
        .map_err(ApiError::model_store)?;
    let event = state
        .repository
        .put_model(&manifest)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(manifest))
}

async fn pin_local_model(
    State(state): State<AppState>,
    Json(request): Json<ModelPinRequest>,
) -> Result<Json<ModelManifest>, ApiError> {
    let manifest = state
        .model_store
        .set_pinned(&request.alias, request.pinned)
        .await
        .map_err(ApiError::model_store)?;
    let event = state
        .repository
        .put_model(&manifest)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(manifest))
}

async fn remove_local_model(
    State(state): State<AppState>,
    Json(request): Json<ModelAliasRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .model_store
        .remove(&request.alias)
        .await
        .map_err(ApiError::model_store)?;
    let event = state
        .repository
        .remove_model(&request.alias)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(StatusCode::NO_CONTENT)
}

async fn download_backup(State(state): State<AppState>) -> Result<Response, ApiError> {
    let backup_dir = state.data_dir.join("backups");
    tokio::fs::create_dir_all(&backup_dir)
        .await
        .map_err(|error| ApiError::internal(error.into()))?;
    let path = backup_dir.join(format!("temporary-{}.db", Uuid::now_v7()));
    state
        .repository
        .backup_to(&path)
        .await
        .map_err(ApiError::internal)?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|error| ApiError::internal(error.into()));
    if let Err(error) = tokio::fs::remove_file(&path).await {
        tracing::warn!(%error, "failed to remove temporary backup");
    }
    let bytes = bytes?;
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.sqlite3"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=constellation-backup.db"),
    );
    Ok(response)
}

#[derive(Debug, Serialize)]
struct NetworkPolicyResponse {
    policy: NetworkPolicy,
    remote_kill_switch_engaged: bool,
    remote_bytes_used_this_month: u64,
}

async fn network_policy_response(state: &AppState) -> Result<NetworkPolicyResponse, ApiError> {
    let policy = state
        .repository
        .network_policy()
        .await
        .map_err(ApiError::internal)?;
    let used = state
        .bandwidth_ledger
        .lock()
        .await
        .used(state.controller_node.0, Utc::now());
    Ok(NetworkPolicyResponse {
        policy,
        remote_kill_switch_engaged: state.remote_kill_switch.load(Ordering::SeqCst),
        remote_bytes_used_this_month: used,
    })
}

async fn get_network_policy(
    State(state): State<AppState>,
) -> Result<Json<NetworkPolicyResponse>, ApiError> {
    network_policy_response(&state).await.map(Json)
}

async fn update_network_policy(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(policy): Json<NetworkPolicy>,
) -> Result<Json<NetworkPolicyResponse>, ApiError> {
    if !principal_allows(&principal, Permission::ClusterAdmin) {
        return Err(ApiError::forbidden(
            "administrator credentials are required to change network policy",
        ));
    }
    validate_network_policy(&policy)?;
    if policy.remote_enabled && state.remote_kill_switch.load(Ordering::SeqCst) {
        return Err(ApiError::bad_request(
            "remote_kill_switch_engaged",
            "restart the controller before explicitly enabling remote networking again",
        ));
    }
    let event = state
        .repository
        .put_network_policy(&policy)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    network_policy_response(&state).await.map(Json)
}

fn validate_network_policy(policy: &NetworkPolicy) -> Result<(), ApiError> {
    if policy.monthly_remote_byte_quota > i64::MAX as u64 {
        return Err(ApiError::bad_request(
            "remote_quota_too_large",
            "monthly remote byte quota exceeds the durable accounting range",
        ));
    }
    if policy.remote_enabled && policy.monthly_remote_byte_quota == 0 {
        return Err(ApiError::bad_request(
            "remote_quota_required",
            "remote networking requires an explicit nonzero monthly byte quota",
        ));
    }
    if policy.managed_relay_enabled && !policy.remote_enabled {
        return Err(ApiError::bad_request(
            "remote_opt_in_required",
            "managed relay use requires remote networking to be enabled separately",
        ));
    }
    if let Some(relay) = &policy.self_hosted_relay
        && (relay.scheme() != "https"
            || relay.host_str().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.query().is_some()
            || relay.fragment().is_some()
            || !matches!(relay.path(), "" | "/"))
    {
        return Err(ApiError::bad_request(
            "invalid_relay_origin",
            "a self-hosted relay must be an exact credential-free https origin",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TransportSimulationRequest {
    candidates: Vec<TransportCandidate>,
    #[serde(default)]
    record_observed_bytes: Option<u64>,
}

async fn simulate_transport(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<TransportSimulationRequest>,
) -> Result<Json<TransportDecision>, ApiError> {
    if !principal_allows(&principal, Permission::ClusterRead) {
        return Err(ApiError::forbidden(
            "administrator credentials are required to inspect transport plans",
        ));
    }
    if request.candidates.is_empty() || request.candidates.len() > 16 {
        return Err(ApiError::bad_request(
            "invalid_transport_candidates",
            "between one and sixteen transport candidates are required",
        ));
    }
    if request
        .candidates
        .iter()
        .any(|candidate| candidate.estimated_bytes > i64::MAX as u64)
    {
        return Err(ApiError::bad_request(
            "transport_budget_too_large",
            "a transport byte estimate exceeds the durable accounting range",
        ));
    }
    let policy = state
        .repository
        .network_policy()
        .await
        .map_err(ApiError::internal)?;
    let now = Utc::now();
    let mut ledger = state.bandwidth_ledger.lock().await;
    let decision = select_transport(
        state.controller_node.0,
        &request.candidates,
        &policy,
        &ledger,
        now,
        state.remote_kill_switch.load(Ordering::SeqCst),
    )
    .map_err(ApiError::network)?;
    if let Some(observed_bytes) = request.record_observed_bytes {
        if !decision.candidate.remote {
            return Err(ApiError::bad_request(
                "local_bandwidth_accounting",
                "observed remote bytes can only be recorded for a remote transport",
            ));
        }
        if observed_bytes > decision.candidate.estimated_bytes {
            return Err(ApiError::bad_request(
                "observed_bytes_exceed_plan",
                "observed bytes exceed the authorized transport budget",
            ));
        }
        let event = state
            .repository
            .record_network_usage(state.controller_node.0, &decision, observed_bytes, now)
            .await
            .map_err(ApiError::internal)?;
        ledger.record(state.controller_node.0, now, observed_bytes);
        publish(&state, event);
    }
    Ok(Json(decision))
}

async fn disable_remote_networking(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Result<Json<NetworkPolicyResponse>, ApiError> {
    if !principal_allows(&principal, Permission::EmergencyControl) {
        return Err(ApiError::forbidden(
            "administrator credentials are required for emergency controls",
        ));
    }
    state.remote_kill_switch.store(true, Ordering::SeqCst);
    let mut policy = state
        .repository
        .network_policy()
        .await
        .map_err(ApiError::internal)?;
    policy.remote_enabled = false;
    policy.managed_relay_enabled = false;
    let event = state
        .repository
        .put_network_policy(&policy)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    network_policy_response(&state).await.map(Json)
}

#[derive(Debug, Deserialize)]
struct TransferTicketRequest {
    alias: String,
    chunk_sha256: String,
    destination_node: Uuid,
}

async fn create_transfer_ticket(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<TransferTicketRequest>,
) -> Result<(StatusCode, Json<PeerTransferTicket>), ApiError> {
    ensure_node_scope(&principal, request.destination_node)?;
    let manifest = state
        .model_store
        .get(&request.alias)
        .await
        .map_err(ApiError::model_store)?;
    if !manifest
        .chunks
        .iter()
        .any(|chunk| chunk.sha256 == request.chunk_sha256)
    {
        return Err(ApiError::bad_request(
            "chunk_not_in_model",
            "requested chunk is not part of the verified model manifest",
        ));
    }
    let destination = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|node| node.id.0 == request.destination_node)
        .ok_or_else(|| {
            ApiError::not_found("device_not_found", "destination device does not exist")
        })?;
    if !matches!(destination.status, NodeStatus::Ready | NodeStatus::Suspect) {
        return Err(ApiError::bad_request(
            "destination_unavailable",
            "destination device is not eligible for model transfer",
        ));
    }
    let ticket = state.enrollment.issue_transfer_ticket(
        state.controller_node.0,
        request.destination_node,
        manifest.sha256,
        request.chunk_sha256,
        Utc::now(),
    );
    let event = state
        .repository
        .put_transfer_ticket(&ticket)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(ticket)))
}

async fn download_model_chunk(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(chunk_sha256): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let encoded = headers
        .get("x-constellation-transfer-ticket")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 4_096)
        .ok_or_else(|| ApiError::unauthorized("model transfer ticket is required"))?;
    let ticket: PeerTransferTicket = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ApiError::unauthorized("model transfer ticket is invalid"))?;
    ensure_node_scope(&principal, ticket.destination_node)?;
    if !ticket.verify(
        &state.enrollment.authority_public_key(),
        Utc::now(),
        state.controller_node.0,
        ticket.destination_node,
        &chunk_sha256,
    ) {
        return Err(ApiError::unauthorized(
            "model transfer ticket is invalid or expired",
        ));
    }
    let manifest_matches = state
        .model_store
        .list()
        .await
        .map_err(ApiError::model_store)?
        .into_iter()
        .any(|manifest| {
            manifest.sha256 == ticket.model_sha256
                && manifest
                    .chunks
                    .iter()
                    .any(|chunk| chunk.sha256 == chunk_sha256)
        });
    if !manifest_matches {
        return Err(ApiError::not_found(
            "model_chunk_not_found",
            "authorized model chunk is no longer present",
        ));
    }
    let bytes = state
        .model_store
        .read_verified_chunk(&chunk_sha256)
        .await
        .map_err(ApiError::model_store)?;
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::ETAG,
        HeaderValue::from_str(&format!("\"sha256:{chunk_sha256}\""))
            .map_err(|error| ApiError::internal(error.into()))?,
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct CreateConversationRequest {
    title: Option<String>,
    #[serde(default)]
    temporary: bool,
}

#[derive(Debug, Deserialize)]
struct ConversationMessageRequest {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ConversationMessageResponse {
    id: Uuid,
    conversation_id: Uuid,
    role: String,
    content: String,
    created_at: chrono::DateTime<Utc>,
}

async fn create_conversation(
    State(state): State<AppState>,
    Json(request): Json<CreateConversationRequest>,
) -> Result<(StatusCode, Json<ConversationRecord>), ApiError> {
    if request.temporary {
        return Err(ApiError::bad_request(
            "temporary_chat_not_persisted",
            "temporary chat uses the inference API directly and is never added to conversation storage",
        ));
    }
    if request
        .title
        .as_ref()
        .is_some_and(|title| title.len() > 200)
    {
        return Err(ApiError::bad_request(
            "invalid_conversation_title",
            "conversation titles are limited to 200 bytes",
        ));
    }
    let id = Uuid::now_v7();
    let cipher = state.content_keys.load_cipher().map_err(ApiError::secret)?;
    let title_envelope = request
        .title
        .filter(|title| !title.is_empty())
        .map(|title| {
            let associated_data = format!("conversation:{id}:title");
            cipher
                .seal(associated_data.as_bytes(), title.as_bytes())
                .and_then(|encrypted| {
                    serde_json::to_vec(&encrypted).map_err(|_| SecretError::Encrypt)
                })
        })
        .transpose()
        .map_err(ApiError::secret)?;
    let (conversation, event) = state
        .repository
        .create_conversation(id, title_envelope)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(conversation)))
}

async fn list_conversations(
    State(state): State<AppState>,
) -> Result<Json<Vec<ConversationRecord>>, ApiError> {
    state
        .repository
        .conversations()
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn append_conversation_message(
    State(state): State<AppState>,
    Path(conversation_id): Path<Uuid>,
    Json(request): Json<ConversationMessageRequest>,
) -> Result<(StatusCode, Json<ConversationMessageResponse>), ApiError> {
    if !matches!(
        request.role.as_str(),
        "system" | "user" | "assistant" | "tool"
    ) {
        return Err(ApiError::bad_request(
            "invalid_message_role",
            "message role must be system, user, assistant, or tool",
        ));
    }
    if request.content.is_empty() || request.content.len() > 1_048_576 {
        return Err(ApiError::bad_request(
            "invalid_message_content",
            "message content must contain between 1 and 1048576 bytes",
        ));
    }
    if !state
        .repository
        .conversations()
        .await
        .map_err(ApiError::internal)?
        .iter()
        .any(|conversation| conversation.id == conversation_id)
    {
        return Err(ApiError::not_found(
            "conversation_not_found",
            "conversation does not exist",
        ));
    }
    let message_id = Uuid::now_v7();
    let associated_data = message_associated_data(conversation_id, message_id, &request.role);
    let encrypted = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .seal(associated_data.as_bytes(), request.content.as_bytes())
        .map_err(ApiError::secret)?;
    let event = state
        .repository
        .append_encrypted_message(
            conversation_id,
            message_id,
            &request.role,
            encrypted.version,
            &encrypted.nonce,
            &encrypted.ciphertext,
        )
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(ConversationMessageResponse {
            id: message_id,
            conversation_id,
            role: request.role,
            content: request.content,
            created_at: Utc::now(),
        }),
    ))
}

async fn list_conversation_messages(
    State(state): State<AppState>,
    Path(conversation_id): Path<Uuid>,
) -> Result<Json<Vec<ConversationMessageResponse>>, ApiError> {
    let cipher = state.content_keys.load_cipher().map_err(ApiError::secret)?;
    let records = state
        .repository
        .encrypted_messages(conversation_id)
        .await
        .map_err(ApiError::internal)?;
    let mut messages = Vec::with_capacity(records.len());
    for record in records {
        let associated_data = message_associated_data(conversation_id, record.id, &record.role);
        let plaintext = cipher
            .open(
                associated_data.as_bytes(),
                &EncryptedContent {
                    version: record.envelope_version,
                    nonce: record.nonce,
                    ciphertext: record.ciphertext,
                },
            )
            .map_err(ApiError::secret)?;
        let content =
            String::from_utf8(plaintext).map_err(|_| ApiError::secret(SecretError::Decrypt))?;
        messages.push(ConversationMessageResponse {
            id: record.id,
            conversation_id,
            role: record.role,
            content,
            created_at: record.created_at,
        });
    }
    Ok(Json(messages))
}

async fn delete_conversation(
    State(state): State<AppState>,
    Path(conversation_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let event = state
        .repository
        .delete_conversation(conversation_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found("conversation_not_found", "conversation does not exist")
        })?;
    publish(&state, event);
    Ok(StatusCode::NO_CONTENT)
}

fn message_associated_data(conversation_id: Uuid, message_id: Uuid, role: &str) -> String {
    format!("conversation:{conversation_id}:message:{message_id}:role:{role}")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnrollmentMethod {
    ShortCode,
    LinkSecret,
}

impl From<EnrollmentMethod> for InvitationMethod {
    fn from(value: EnrollmentMethod) -> Self {
        match value {
            EnrollmentMethod::ShortCode => Self::ShortCode,
            EnrollmentMethod::LinkSecret => Self::LinkSecret,
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnrollmentBeginRequest {
    invitation_id: Uuid,
    method: EnrollmentMethod,
    client_message: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentBeginResponse {
    invitation_id: Uuid,
    controller_message: String,
    controller_proof: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentConfirmRequest {
    invitation_id: Uuid,
    client_proof: String,
    device_id: Uuid,
    device_public_key: String,
    device: DeviceRegistration,
}

#[derive(Debug, Serialize)]
struct EnrollmentCredentialResponse {
    status: &'static str,
    credential: Option<MembershipCredential>,
    device_certificate: Option<DeviceCertificate>,
    authority_public_key: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentCredentialRequest {
    invitation_id: Uuid,
    status_proof: String,
}

async fn create_invitation(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<InvitationPresentation>), ApiError> {
    let now = Utc::now();
    let invitation = state
        .enrollment
        .create_invitation(&state.enrollment.cluster_id(), now)
        .await
        .map_err(ApiError::identity)?;
    let status = state
        .enrollment
        .status(invitation.id)
        .await
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("new invitation missing")))?;
    let event = state
        .repository
        .put_invitation_status(&status, None, "enrollment.invitation_created")
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(invitation)))
}

async fn list_invitations(
    State(state): State<AppState>,
) -> Result<Json<Vec<InvitationStatus>>, ApiError> {
    state
        .repository
        .invitation_statuses()
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn begin_enrollment(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentBeginRequest>,
) -> Result<Json<EnrollmentBeginResponse>, ApiError> {
    let client_message = decode_bounded(&request.client_message, 256, "client_message")?;
    let result = state
        .enrollment
        .begin(
            request.invitation_id,
            request.method.into(),
            &client_message,
            Utc::now(),
        )
        .await;
    match result {
        Ok((controller_message, controller_proof)) => Ok(Json(EnrollmentBeginResponse {
            invitation_id: request.invitation_id,
            controller_message: URL_SAFE_NO_PAD.encode(controller_message),
            controller_proof: URL_SAFE_NO_PAD.encode(controller_proof),
        })),
        Err(error) => {
            persist_failed_enrollment(&state, request.invitation_id).await;
            Err(ApiError::identity(error))
        }
    }
}

async fn confirm_enrollment(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentConfirmRequest>,
) -> Result<(StatusCode, Json<InvitationStatus>), ApiError> {
    validate_device_registration(&request.device)?;
    let client_proof = decode_array::<32>(&request.client_proof, "client_proof")?;
    let public_key = decode_array::<32>(&request.device_public_key, "device_public_key")?;
    let node = Node {
        id: NodeId(request.device_id),
        name: request.device.name,
        os: request.device.os,
        architecture: request.device.architecture,
        status: NodeStatus::Joining,
        capabilities: request.device.capabilities,
        last_seen_at: Utc::now(),
    };
    let result = state
        .enrollment
        .confirm(
            request.invitation_id,
            &client_proof,
            node,
            public_key,
            Utc::now(),
        )
        .await;
    match result {
        Ok(status) => {
            let event = state
                .repository
                .put_invitation_status(
                    &status,
                    Some(NodeId(request.device_id)),
                    "enrollment.proved",
                )
                .await
                .map_err(ApiError::internal)?;
            publish(&state, event);
            Ok((StatusCode::ACCEPTED, Json(status)))
        }
        Err(error) => {
            persist_failed_enrollment(&state, request.invitation_id).await;
            Err(ApiError::identity(error))
        }
    }
}

async fn approve_invitation(
    State(state): State<AppState>,
    Path(invitation_id): Path<Uuid>,
) -> Result<Json<EnrollmentCredentialResponse>, ApiError> {
    let (mut node, credential, certificate, status) = state
        .enrollment
        .approve(invitation_id, Utc::now())
        .await
        .map_err(ApiError::identity)?;
    node.status = NodeStatus::Ready;
    let event = state
        .repository
        .approve_enrollment(&node, &credential, &certificate, &status)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(EnrollmentCredentialResponse {
        status: "approved",
        credential: Some(credential),
        device_certificate: Some(certificate),
        authority_public_key: URL_SAFE_NO_PAD.encode(state.enrollment.authority_public_key()),
    }))
}

async fn get_enrollment_credential(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentCredentialRequest>,
) -> Result<Json<EnrollmentCredentialResponse>, ApiError> {
    let proof = decode_array::<32>(&request.status_proof, "status_proof")?;
    let issuance = state
        .enrollment
        .credential(request.invitation_id, &proof)
        .await
        .map_err(ApiError::identity)?;
    Ok(Json(EnrollmentCredentialResponse {
        status: if issuance.is_some() {
            "approved"
        } else {
            "pending_approval"
        },
        credential: issuance.as_ref().map(|value| value.0.clone()),
        device_certificate: issuance.map(|value| value.1),
        authority_public_key: URL_SAFE_NO_PAD.encode(state.enrollment.authority_public_key()),
    }))
}

async fn persist_failed_enrollment(state: &AppState, invitation_id: Uuid) {
    let Some(status) = state.enrollment.status(invitation_id).await else {
        return;
    };
    match state
        .repository
        .put_invitation_status(&status, None, "enrollment.attempt_failed")
        .await
    {
        Ok(event) => publish(state, event),
        Err(error) => tracing::error!(%error, "failed to persist redacted enrollment status"),
    }
}

fn decode_bounded(value: &str, max_len: usize, field: &str) -> Result<Vec<u8>, ApiError> {
    let decoded = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|_| {
        ApiError::bad_request(
            "invalid_enrollment_encoding",
            &format!("{field} is not valid base64url"),
        )
    })?;
    if decoded.is_empty() || decoded.len() > max_len {
        return Err(ApiError::bad_request(
            "invalid_enrollment_message",
            &format!("{field} has an invalid length"),
        ));
    }
    Ok(decoded)
}

fn decode_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N], ApiError> {
    decode_bounded(value, N, field)?.try_into().map_err(|_| {
        ApiError::bad_request(
            "invalid_enrollment_message",
            &format!("{field} must contain exactly {N} bytes"),
        )
    })
}

#[derive(Debug, Deserialize)]
struct DeviceRegistration {
    name: String,
    os: OperatingSystem,
    architecture: String,
    capabilities: NodeCapabilities,
}

fn validate_device_registration(input: &DeviceRegistration) -> Result<(), ApiError> {
    if input.name.trim().is_empty() || input.name.len() > 128 {
        return Err(ApiError::bad_request(
            "invalid_device_name",
            "device name must contain 1 to 128 characters",
        ));
    }
    if input.architecture.trim().is_empty() || input.architecture.len() > 64 {
        return Err(ApiError::bad_request(
            "invalid_device_architecture",
            "device architecture must contain 1 to 64 characters",
        ));
    }
    Ok(())
}

async fn register_device(
    State(state): State<AppState>,
    Json(input): Json<DeviceRegistration>,
) -> Result<(StatusCode, Json<Node>), ApiError> {
    validate_device_registration(&input)?;
    let node = Node {
        id: NodeId::new(),
        name: input.name,
        os: input.os,
        architecture: input.architecture,
        status: NodeStatus::Ready,
        capabilities: input.capabilities,
        last_seen_at: Utc::now(),
    };
    let event = state
        .repository
        .register_node(&node)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(node)))
}

async fn update_device_inventory(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
    Json(input): Json<DeviceRegistration>,
) -> Result<Json<Node>, ApiError> {
    ensure_node_scope(&principal, node_id)?;
    validate_device_registration(&input)?;
    let node = Node {
        id: NodeId(node_id),
        name: input.name,
        os: input.os,
        architecture: input.architecture,
        status: NodeStatus::Ready,
        capabilities: input.capabilities,
        last_seen_at: Utc::now(),
    };
    let event = state
        .repository
        .update_node_inventory(&node)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(node))
}

async fn list_devices(State(state): State<AppState>) -> Result<Json<Vec<Node>>, ApiError> {
    state
        .repository
        .list_nodes()
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

#[derive(Debug, Deserialize)]
struct StatusUpdate {
    status: NodeStatus,
}

async fn update_device_status(
    State(state): State<AppState>,
    Path(node_id): Path<Uuid>,
    Json(update): Json<StatusUpdate>,
) -> Result<Json<Value>, ApiError> {
    let event = state
        .repository
        .update_node_status(NodeId(node_id), update.status)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))?;
    publish(&state, event);
    Ok(Json(json!({"node_id": node_id, "status": update.status})))
}

async fn device_heartbeat(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    if matches!(principal, AuthenticatedPrincipal::Node(credential_node) if credential_node.0 != node_id)
    {
        return Err(ApiError::forbidden(
            "node credentials cannot heartbeat for another device",
        ));
    }
    let event = state
        .repository
        .heartbeat(NodeId(node_id))
        .await
        .map_err(ApiError::internal)?;
    if let Some(event) = event {
        publish(&state, event);
    }
    let nodes = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?;
    let status = nodes
        .iter()
        .find(|node| node.id.0 == node_id)
        .map(|node| node.status)
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))?;
    if status == NodeStatus::Revoked {
        return Err(ApiError::forbidden("device membership is revoked"));
    }
    Ok(Json(
        json!({"node_id": node_id, "status": status, "observed_at": Utc::now()}),
    ))
}

async fn revoke_device(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&principal, Permission::EmergencyControl) {
        return Err(ApiError::forbidden(
            "administrator credentials are required for revocation",
        ));
    }
    let event = state
        .repository
        .revoke_node(NodeId(node_id))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))?;
    publish(&state, event);
    Ok(Json(json!({"node_id": node_id, "status": "revoked"})))
}

async fn rotate_device_credentials(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(current): Extension<MembershipCredential>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<EnrollmentCredentialResponse>, ApiError> {
    if !matches!(principal, AuthenticatedPrincipal::Node(node) if node.0 == node_id)
        || current.device_id != node_id
    {
        return Err(ApiError::forbidden(
            "a node can rotate only its own authenticated credentials",
        ));
    }
    let (credential, certificate) = state
        .enrollment
        .rotate_device_credentials(node_id, current.device_public_key, Utc::now())
        .map_err(ApiError::identity)?;
    let event = state
        .repository
        .put_rotated_credential(&credential, &certificate)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(EnrollmentCredentialResponse {
        status: "approved",
        credential: Some(credential),
        device_certificate: Some(certificate),
        authority_public_key: URL_SAFE_NO_PAD.encode(state.enrollment.authority_public_key()),
    }))
}

#[derive(Serialize)]
struct WorkerPollResponse {
    lease: Option<WorkerLease>,
}

async fn poll_worker_lease(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<WorkerPollResponse>, ApiError> {
    if !matches!(principal, AuthenticatedPrincipal::Node(node) if node.0 == node_id) {
        return Err(ApiError::forbidden(
            "a worker can poll leases only for its authenticated device",
        ));
    }
    let record = state
        .repository
        .claim_worker_lease(NodeId(node_id), Utc::now())
        .await
        .map_err(ApiError::internal)?;
    let Some(record) = record else {
        return Ok(Json(WorkerPollResponse { lease: None }));
    };
    let cipher = state.content_keys.load_cipher().map_err(ApiError::secret)?;
    let plaintext = cipher
        .open(
            lease_associated_data(record.id, record.workload_id).as_bytes(),
            &EncryptedContent {
                version: record.envelope_version,
                nonce: record.nonce,
                ciphertext: record.ciphertext,
            },
        )
        .map_err(ApiError::secret)?;
    let input = String::from_utf8(plaintext).map_err(|_| ApiError::secret(SecretError::Decrypt))?;
    Ok(Json(WorkerPollResponse {
        lease: Some(WorkerLease {
            id: record.id,
            workload_id: record.workload_id,
            node_id: record.node_id,
            attempt: record.attempt,
            model: record.model,
            input,
            maximum_output_tokens: record.maximum_output_tokens,
            plan: record.plan,
            expires_at: record.expires_at,
        }),
    }))
}

#[derive(Deserialize)]
struct WorkerEventSubmission {
    sequence: u64,
    event: WorkerRuntimeEvent,
}

async fn submit_worker_event(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path((node_id, lease_id)): Path<(Uuid, Uuid)>,
    Json(submission): Json<WorkerEventSubmission>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(principal, AuthenticatedPrincipal::Node(node) if node.0 == node_id) {
        return Err(ApiError::forbidden(
            "a worker can submit events only for its authenticated device",
        ));
    }
    validate_worker_event(submission.sequence, &submission.event)?;
    let event = state
        .repository
        .accept_worker_event(
            NodeId(node_id),
            lease_id,
            submission.sequence,
            &submission.event,
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::bad_request(
                "stale_worker_event",
                "worker event is duplicated, out of order, expired, or outside this lease",
            )
        })?;
    publish(&state, event);
    let runtime_event = worker_runtime_event(submission.event.clone());
    let terminal = submission.event.is_terminal();
    let sender = {
        let mut executions = state.remote_executions.lock().await;
        let sender = executions.get(&lease_id).cloned();
        if terminal {
            executions.remove(&lease_id);
        }
        sender
    };
    if let Some(sender) = sender {
        let _ignored = sender.send(runtime_event).await;
    }
    Ok(Json(json!({
        "lease_id": lease_id,
        "accepted_sequence": submission.sequence,
        "terminal": terminal,
    })))
}

fn validate_worker_event(sequence: u64, event: &WorkerRuntimeEvent) -> Result<(), ApiError> {
    if sequence == 0 {
        return Err(ApiError::bad_request(
            "invalid_worker_sequence",
            "worker event sequence starts at one",
        ));
    }
    match event {
        WorkerRuntimeEvent::Loading { progress }
            if !progress.is_finite() || !(0.0..=1.0).contains(progress) =>
        {
            Err(ApiError::bad_request(
                "invalid_worker_progress",
                "worker load progress must be between zero and one",
            ))
        }
        WorkerRuntimeEvent::TextDelta { text } if text.len() > 65_536 => Err(
            ApiError::bad_request("worker_delta_too_large", "worker text delta exceeds 64 KiB"),
        ),
        WorkerRuntimeEvent::Finished { finish_reason, .. }
            if finish_reason.is_empty() || finish_reason.len() > 64 =>
        {
            Err(ApiError::bad_request(
                "invalid_finish_reason",
                "worker finish reason must contain 1 to 64 characters",
            ))
        }
        WorkerRuntimeEvent::Failure { code, message, .. }
            if code.is_empty() || code.len() > 64 || message.len() > 1_024 =>
        {
            Err(ApiError::bad_request(
                "invalid_worker_failure",
                "worker failure code or redacted message exceeds its bound",
            ))
        }
        _ => Ok(()),
    }
}

fn worker_runtime_event(event: WorkerRuntimeEvent) -> RuntimeEvent {
    match event {
        WorkerRuntimeEvent::Loading { progress } => RuntimeEvent::Loading { progress },
        WorkerRuntimeEvent::Prefill { elapsed_ms } => RuntimeEvent::Prefill { elapsed_ms },
        WorkerRuntimeEvent::TextDelta { text } => RuntimeEvent::TextDelta(text),
        WorkerRuntimeEvent::Finished {
            input_tokens,
            output_tokens,
            finish_reason,
        } => RuntimeEvent::Finished {
            input_tokens,
            output_tokens,
            finish_reason,
        },
        WorkerRuntimeEvent::Failure {
            code,
            message,
            retryable,
            output_started,
        } => RuntimeEvent::Failure {
            code,
            message,
            retryable,
            output_started,
        },
        WorkerRuntimeEvent::Cancelled => RuntimeEvent::Cancelled,
    }
}

fn lease_associated_data(lease_id: Uuid, workload_id: WorkloadId) -> String {
    format!("worker-lease:{lease_id}:workload:{}", workload_id.0)
}

async fn get_device_policy(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<NodeResourcePolicy>, ApiError> {
    ensure_node_scope(&principal, node_id)?;
    state
        .repository
        .resource_policy(NodeId(node_id))
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))
}

async fn update_device_policy(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(node_id): Path<Uuid>,
    Json(policy): Json<NodeResourcePolicy>,
) -> Result<Json<NodeResourcePolicy>, ApiError> {
    ensure_node_scope(&principal, node_id)?;
    if !policy.is_valid() {
        return Err(ApiError::bad_request(
            "invalid_resource_policy",
            "resource percentages or thermal ceiling are outside supported bounds",
        ));
    }
    let existing = state
        .repository
        .resource_policy(NodeId(node_id))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))?;
    let actor = match &principal {
        AuthenticatedPrincipal::Owner if NodeId(node_id) == state.controller_node => {
            "local-owner".to_owned()
        }
        AuthenticatedPrincipal::Owner => {
            if !policy.is_at_least_as_strict_as(&existing) {
                return Err(ApiError::forbidden(
                    "a remote administrator cannot loosen a node owner's resource policy",
                ));
            }
            "remote-owner".to_owned()
        }
        AuthenticatedPrincipal::Node(_) => "node-owner".to_owned(),
        AuthenticatedPrincipal::Human(human) => {
            if !human.allows(Permission::ClusterAdmin)
                || !policy.is_at_least_as_strict_as(&existing)
            {
                return Err(ApiError::forbidden(
                    "a remote administrator cannot loosen a node owner's resource policy",
                ));
            }
            human.id.to_string()
        }
        AuthenticatedPrincipal::Service(service) => {
            if !service.allows(Permission::ClusterAdmin)
                || !policy.is_at_least_as_strict_as(&existing)
            {
                return Err(ApiError::forbidden(
                    "a service administrator cannot loosen a node owner's resource policy",
                ));
            }
            service.id.to_string()
        }
    };
    let event = state
        .repository
        .put_resource_policy(NodeId(node_id), &policy, &actor)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("device_not_found", "device does not exist"))?;
    publish(&state, event);
    Ok(Json(policy))
}

fn ensure_node_scope(
    principal: &AuthenticatedPrincipal,
    requested_node: Uuid,
) -> Result<(), ApiError> {
    if matches!(principal, AuthenticatedPrincipal::Node(node) if node.0 != requested_node) {
        Err(ApiError::forbidden(
            "node credentials cannot manage another device",
        ))
    } else {
        Ok(())
    }
}

async fn submit_benchmark(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(report): Json<BenchmarkReport>,
) -> Result<(StatusCode, Json<BenchmarkReport>), ApiError> {
    if matches!(principal, AuthenticatedPrincipal::Node(credential_node) if credential_node != report.node_id)
    {
        return Err(ApiError::forbidden(
            "node credentials cannot submit another device's benchmark",
        ));
    }
    let numeric = [
        report.tokens_per_second,
        report.time_to_first_token_ms,
        report.network_latency_ms,
        report.network_bandwidth_mbps,
        report.jitter_ms,
        report.packet_loss,
    ];
    if numeric
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
        || report.packet_loss > 1.0
        || report.sample_count == 0
    {
        return Err(ApiError::bad_request(
            "invalid_benchmark",
            "benchmark values must be finite, non-negative, sampled, and packet loss must be at most one",
        ));
    }
    let nodes = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?;
    if !nodes.iter().any(|node| node.id == report.node_id) {
        return Err(ApiError::not_found(
            "device_not_found",
            "benchmark device does not exist",
        ));
    }
    let event = state
        .repository
        .put_benchmark(&report)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(report)))
}

async fn list_benchmarks(
    State(state): State<AppState>,
) -> Result<Json<Vec<BenchmarkReport>>, ApiError> {
    let mut reports = state
        .repository
        .benchmarks()
        .await
        .map_err(ApiError::internal)?
        .into_values()
        .collect::<Vec<_>>();
    reports.sort_by_key(|report| report.node_id.0);
    Ok(Json(reports))
}

#[derive(Debug, Serialize)]
struct BenchmarkPolicySnapshot {
    node_id: NodeId,
    policy: NodeResourcePolicy,
}

#[derive(Debug, Serialize)]
struct ReproducibleBenchmarkReport {
    schema_version: u16,
    product_version: &'static str,
    generated_at: chrono::DateTime<Utc>,
    content_included: bool,
    nodes: Vec<Node>,
    policies: Vec<BenchmarkPolicySnapshot>,
    benchmarks: Vec<BenchmarkReport>,
}

async fn export_benchmark_report(
    State(state): State<AppState>,
) -> Result<Json<ReproducibleBenchmarkReport>, ApiError> {
    let mut nodes = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?;
    nodes.sort_by_key(|node| node.id.0);
    let mut policies = Vec::with_capacity(nodes.len());
    for node in &nodes {
        if let Some(policy) = state
            .repository
            .resource_policy(node.id)
            .await
            .map_err(ApiError::internal)?
        {
            policies.push(BenchmarkPolicySnapshot {
                node_id: node.id,
                policy,
            });
        }
    }
    let mut benchmarks = state
        .repository
        .benchmarks()
        .await
        .map_err(ApiError::internal)?
        .into_values()
        .collect::<Vec<_>>();
    benchmarks.sort_by_key(|report| report.node_id.0);
    Ok(Json(ReproducibleBenchmarkReport {
        schema_version: 1,
        product_version: env!("CARGO_PKG_VERSION"),
        generated_at: Utc::now(),
        content_included: false,
        nodes,
        policies,
        benchmarks,
    }))
}

#[derive(Debug, Deserialize)]
struct PlanSimulationRequest {
    #[serde(default = "default_model")]
    model: String,
    #[serde(default = "default_runtime")]
    required_runtime: String,
    #[serde(default = "default_memory")]
    estimated_memory_bytes: u64,
    #[serde(default = "default_class")]
    class: WorkloadClass,
    #[serde(default = "default_policy")]
    policy: SchedulingPolicy,
    #[serde(default)]
    allowed_nodes: Vec<NodeId>,
}

fn default_model() -> String {
    MockRuntime::MODEL.to_owned()
}

fn default_runtime() -> String {
    MockRuntime::ID.to_owned()
}

const fn default_memory() -> u64 {
    1024 * 1024 * 1024
}

const fn default_class() -> WorkloadClass {
    WorkloadClass::Interactive
}

const fn default_policy() -> SchedulingPolicy {
    SchedulingPolicy::Balanced
}

async fn simulate_plan(
    State(state): State<AppState>,
    Json(input): Json<PlanSimulationRequest>,
) -> Result<Json<ExecutionPlan>, ApiError> {
    let workload = WorkloadRequest {
        id: WorkloadId::new(),
        model: input.model,
        required_runtime: input.required_runtime,
        estimated_memory_bytes: input.estimated_memory_bytes,
        class: input.class,
        policy: input.policy,
        allowed_nodes: input.allowed_nodes,
        allow_remote: false,
    };
    let snapshot = scheduling_snapshot(&state).await?;
    plan(&workload, &snapshot)
        .map(Json)
        .map_err(|error| ApiError::unavailable(&format!("no safe execution plan: {error}")))
}

#[derive(Debug, Deserialize)]
struct DistributedPlanSimulationRequest {
    #[serde(flatten)]
    workload: PlanSimulationRequest,
    strategy: ExecutionStrategy,
    node_count: u8,
    bytes_per_token: u64,
    maximum_network_bytes: u64,
    capabilities: Vec<NodeStrategyCapabilities>,
}

async fn simulate_distributed_plan(
    State(state): State<AppState>,
    Json(input): Json<DistributedPlanSimulationRequest>,
) -> Result<Json<ExecutionPlan>, ApiError> {
    let workload = WorkloadRequest {
        id: WorkloadId::new(),
        model: input.workload.model,
        required_runtime: input.workload.required_runtime,
        estimated_memory_bytes: input.workload.estimated_memory_bytes,
        class: input.workload.class,
        policy: input.workload.policy,
        allowed_nodes: input.workload.allowed_nodes,
        allow_remote: false,
    };
    let requirements = DistributedRequirements {
        strategy: input.strategy,
        node_count: input.node_count,
        bytes_per_token: input.bytes_per_token,
        maximum_network_bytes: input.maximum_network_bytes,
        capabilities: input.capabilities,
    };
    plan_distributed(
        &workload,
        &scheduling_snapshot(&state).await?,
        &requirements,
    )
    .map(Json)
    .map_err(|error| {
        ApiError::bad_request(
            "distributed_plan_unavailable",
            &format!("capability-gated distributed plan is unavailable: {error}"),
        )
    })
}

#[derive(Debug, Deserialize)]
struct DigitalTwinRequest {
    scenarios: Vec<SimulationScenario>,
}

async fn run_digital_twin(
    State(state): State<AppState>,
    Path(workload_id): Path<Uuid>,
    Json(input): Json<DigitalTwinRequest>,
) -> Result<Json<Value>, ApiError> {
    if input.scenarios.is_empty() || input.scenarios.len() > 64 {
        return Err(ApiError::bad_request(
            "invalid_simulation_scenarios",
            "digital twin requires between one and 64 scenarios",
        ));
    }
    let plan = state
        .repository
        .plan_for_workload(WorkloadId(workload_id))
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plan_not_found", "execution plan does not exist"))?;
    let outcomes = simulate_digital_twin(&plan, &input.scenarios).map_err(|error| {
        ApiError::bad_request("invalid_simulation_scenarios", &error.to_string())
    })?;
    Ok(Json(json!({"plan_id": plan.id, "outcomes": outcomes})))
}

#[derive(Debug, Deserialize)]
struct PlanObservationRequest {
    ttft_ms: f64,
    tokens_per_second: f64,
    network_bytes: u64,
}

async fn record_plan_observation(
    State(state): State<AppState>,
    Path(workload_id): Path<Uuid>,
    Json(input): Json<PlanObservationRequest>,
) -> Result<Json<Value>, ApiError> {
    let workload_id = WorkloadId(workload_id);
    let plan = state
        .repository
        .plan_for_workload(workload_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plan_not_found", "execution plan does not exist"))?;
    let observation = observe_plan(
        &plan,
        input.ttft_ms,
        input.tokens_per_second,
        input.network_bytes,
    )
    .map_err(|error| ApiError::bad_request("invalid_plan_observation", &error.to_string()))?;
    let event = state
        .repository
        .put_plan_observation(workload_id, &observation)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!(observation)))
}

#[derive(Debug, Deserialize)]
struct TraceSpanRequest {
    id: Option<Uuid>,
    node_id: NodeId,
    parent_span_id: Option<Uuid>,
    operation: String,
    started_at: chrono::DateTime<Utc>,
    duration_us: u64,
    status: String,
    #[serde(default = "empty_json_object")]
    attributes: Value,
}

fn empty_json_object() -> Value {
    json!({})
}

async fn record_trace_span(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(workload_id): Path<Uuid>,
    Json(input): Json<TraceSpanRequest>,
) -> Result<(StatusCode, Json<ExecutionTraceSpan>), ApiError> {
    if matches!(principal, AuthenticatedPrincipal::Node(node) if node != input.node_id) {
        return Err(ApiError::forbidden(
            "a node can record trace spans only for itself",
        ));
    }
    if input.operation.is_empty()
        || input.operation.len() > 64
        || !matches!(input.status.as_str(), "ok" | "error" | "cancelled")
        || !safe_trace_attributes(&input.attributes)
    {
        return Err(ApiError::bad_request(
            "invalid_trace_span",
            "trace span operation, status, or privacy-safe attributes are invalid",
        ));
    }
    let span = ExecutionTraceSpan {
        id: input.id.unwrap_or_else(Uuid::now_v7),
        workload_id: WorkloadId(workload_id),
        node_id: input.node_id,
        parent_span_id: input.parent_span_id,
        operation: input.operation,
        started_at: input.started_at,
        duration_us: input.duration_us,
        status: input.status,
        attributes: input.attributes,
    };
    let event = state
        .repository
        .put_trace_span(&span)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(span)))
}

async fn list_trace_spans(
    State(state): State<AppState>,
    Path(workload_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let spans = state
        .repository
        .trace_spans(WorkloadId(workload_id))
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"workload_id": workload_id, "spans": spans})))
}

fn safe_trace_attributes(attributes: &Value) -> bool {
    const ALLOWED: &[&str] = &[
        "runtime_id",
        "strategy",
        "stage",
        "sequence",
        "bytes",
        "tokens",
        "error_code",
        "checkpoint",
    ];
    let Some(object) = attributes.as_object() else {
        return false;
    };
    if object.len() > 16 {
        return false;
    }
    object.iter().all(|(key, value)| {
        ALLOWED.contains(&key.as_str())
            && match value {
                Value::String(text) => text.len() <= 128,
                Value::Number(_) | Value::Bool(_) | Value::Null => true,
                Value::Array(_) | Value::Object(_) => false,
            }
    })
}

async fn scheduling_snapshot(state: &AppState) -> Result<ClusterSnapshot, ApiError> {
    Ok(ClusterSnapshot {
        nodes: state
            .repository
            .list_nodes()
            .await
            .map_err(ApiError::internal)?,
        benchmarks: state
            .repository
            .benchmarks()
            .await
            .map_err(ApiError::internal)?,
        policies: state
            .repository
            .resource_policies()
            .await
            .map_err(ApiError::internal)?,
        controller_node: Some(state.controller_node),
        observed_at: Utc::now(),
    })
}

async fn workflow_schema() -> Json<Value> {
    Json(json_schema())
}

#[derive(Debug, Deserialize)]
struct CreateWorkflowRequest {
    definition: WorkflowDefinition,
}

async fn create_workflow(
    State(state): State<AppState>,
    Json(input): Json<CreateWorkflowRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let response = persist_workflow_definition(&state, input.definition).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn persist_workflow_definition(
    state: &AppState,
    definition: WorkflowDefinition,
) -> Result<Value, ApiError> {
    validate(&definition)
        .map_err(|error| ApiError::bad_request("invalid_workflow", &error.to_string()))?;
    let workflow_id = WorkflowId::new();
    let revision = 1_u32;
    let sha256 = definition_sha256(&definition)
        .map_err(|error| ApiError::bad_request("invalid_workflow", &error.to_string()))?;
    let plaintext =
        serde_json::to_vec(&definition).map_err(|error| ApiError::internal(error.into()))?;
    let encrypted = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .seal(
            workflow_definition_ad(workflow_id, revision).as_bytes(),
            &plaintext,
        )
        .map_err(ApiError::secret)?;
    let event = state
        .repository
        .create_workflow(workflow_id, &definition.name, &sha256, &encrypted)
        .await
        .map_err(ApiError::internal)?;
    publish(state, event);
    Ok(json!({
        "id": workflow_id,
        "revision": revision,
        "sha256": sha256,
        "definition": definition,
    }))
}

#[derive(Debug, Deserialize)]
struct CreateWorkflowTemplateRequest {
    name: String,
    workflow_id: WorkflowId,
    #[serde(default = "empty_json_object")]
    metadata: Value,
}

async fn create_workflow_template(
    State(state): State<AppState>,
    Json(input): Json<CreateWorkflowTemplateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let metadata_bytes = serde_json::to_vec(&input.metadata)
        .map_err(|error| ApiError::bad_request("invalid_template", &error.to_string()))?;
    if input.name.trim().is_empty()
        || input.name.len() > 128
        || !input.metadata.is_object()
        || metadata_bytes.len() > 16_384
    {
        return Err(ApiError::bad_request(
            "invalid_template",
            "template name or declarative metadata is outside its bound",
        ));
    }
    let _definition = load_workflow_definition(&state, input.workflow_id).await?;
    let template_id = Uuid::now_v7();
    let event = state
        .repository
        .put_workflow_template(template_id, &input.name, input.workflow_id, &input.metadata)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": template_id,
            "name": input.name,
            "workflow_id": input.workflow_id,
            "metadata": input.metadata,
        })),
    ))
}

async fn list_workflow_templates(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let templates = state
        .repository
        .workflow_templates()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"data": templates})))
}

#[derive(Debug, Deserialize)]
struct InstantiateWorkflowTemplateRequest {
    name: Option<String>,
}

async fn instantiate_workflow_template(
    State(state): State<AppState>,
    Path(template_id): Path<Uuid>,
    Json(input): Json<InstantiateWorkflowTemplateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let template = state
        .repository
        .workflow_template(template_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("template_not_found", "template does not exist"))?;
    let (_, _, mut definition) = load_workflow_definition(&state, template.workflow_id).await?;
    definition.name = input
        .name
        .unwrap_or_else(|| format!("{} copy", template.name));
    let response = persist_workflow_definition(&state, definition).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

async fn list_workflows(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let workflows = state
        .repository
        .workflows()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"data": workflows})))
}

async fn get_workflow(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let workflow_id = WorkflowId(workflow_id);
    let (revision, sha256, definition) = load_workflow_definition(&state, workflow_id).await?;
    Ok(Json(json!({
        "id": workflow_id,
        "revision": revision,
        "sha256": sha256,
        "definition": definition,
    })))
}

#[derive(Debug, Deserialize)]
struct StartWorkflowRequest {
    #[serde(default)]
    inputs: BTreeMap<String, String>,
}

async fn start_workflow(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(input): Json<StartWorkflowRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let run = start_workflow_run(&state, WorkflowId(workflow_id), input.inputs).await?;
    Ok((StatusCode::CREATED, Json(workflow_run_response(&run, None))))
}

async fn start_workflow_run(
    state: &AppState,
    workflow_id: WorkflowId,
    inputs: BTreeMap<String, String>,
) -> Result<WorkflowRun, ApiError> {
    start_workflow_run_with_id(state, workflow_id, inputs, None).await
}

async fn start_workflow_run_with_id(
    state: &AppState,
    workflow_id: WorkflowId,
    inputs: BTreeMap<String, String>,
    run_id: Option<WorkflowRunId>,
) -> Result<WorkflowRun, ApiError> {
    if let Some(run_id) = run_id
        && state
            .repository
            .workflow_run(run_id)
            .await
            .map_err(ApiError::internal)?
            .is_some()
    {
        return load_workflow_run(state, run_id)
            .await
            .map(|(run, _, _)| run);
    }
    let (revision, _sha256, definition) = load_workflow_definition(state, workflow_id).await?;
    let now = Utc::now();
    let mut run = create_run(workflow_id, &definition, inputs, now)
        .map_err(|error| ApiError::bad_request("invalid_workflow_run", &error.to_string()))?;
    if let Some(run_id) = run_id {
        run.id = run_id;
    }
    apply_event(&mut run, &definition, &WorkflowEvent::Start, now)
        .map_err(|error| ApiError::bad_request("invalid_workflow_run", &error.to_string()))?;
    let encrypted = encrypt_workflow_run(state, &run)?;
    let event = state
        .repository
        .create_workflow_run(
            run.id,
            workflow_id,
            revision,
            run_status_str(run.status),
            &encrypted,
        )
        .await
        .map_err(ApiError::internal)?;
    publish(state, event);
    Ok(run)
}

async fn get_workflow_run(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let (run, definition, _) = load_workflow_run(&state, WorkflowRunId(run_id)).await?;
    Ok(Json(workflow_run_response(&run, Some(&definition))))
}

#[derive(Debug, Deserialize)]
struct WorkflowTransitionRequest {
    event: WorkflowEvent,
}

async fn transition_workflow_run(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(run_id): Path<Uuid>,
    Json(input): Json<WorkflowTransitionRequest>,
) -> Result<Json<Value>, ApiError> {
    let required = if matches!(
        &input.event,
        WorkflowEvent::ApprovalGranted { .. } | WorkflowEvent::ApprovalDenied { .. }
    ) {
        Permission::WorkflowApprove
    } else {
        Permission::WorkflowOperate
    };
    if !principal_allows(&principal, required) {
        return Err(ApiError::forbidden(
            "identity cannot administer this workflow transition",
        ));
    }
    let principal_id = authenticated_principal_id(&principal);
    let run_id = WorkflowRunId(run_id);
    let (mut run, definition, expected_nonce) = load_workflow_run(&state, run_id).await?;
    let expected_status = run_status_str(run.status).to_owned();
    let event = bind_workflow_principal(input.event, &principal_id);
    apply_event(&mut run, &definition, &event, Utc::now()).map_err(|error| {
        ApiError::bad_request("invalid_workflow_transition", &error.to_string())
    })?;
    let encrypted = encrypt_workflow_run(&state, &run)?;
    let (event_type, step_id, event_principal) = workflow_event_metadata(&event);
    let cluster_event = state
        .repository
        .update_workflow_run(
            run_id,
            &expected_status,
            &expected_nonce,
            run_status_str(run.status),
            &encrypted,
            event_type,
            step_id,
            event_principal,
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::bad_request(
                "workflow_transition_conflict",
                "workflow run changed concurrently; reload before retrying",
            )
        })?;
    publish(&state, cluster_event);
    Ok(Json(workflow_run_response(&run, Some(&definition))))
}

#[derive(Debug, Deserialize)]
struct WorkflowArtifactRequest {
    step_id: String,
    name: String,
    media_type: String,
    content_base64: String,
}

async fn create_workflow_artifact(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
    Json(input): Json<WorkflowArtifactRequest>,
) -> Result<(StatusCode, Json<ArtifactMetadata>), ApiError> {
    if input.step_id.is_empty()
        || input.step_id.len() > 64
        || input.name.is_empty()
        || input.name.len() > 128
        || input.media_type.is_empty()
        || input.media_type.len() > 128
        || input.content_base64.len() > 24 * 1024 * 1024
    {
        return Err(ApiError::bad_request(
            "invalid_workflow_artifact",
            "artifact metadata or encoded content exceeds its bound",
        ));
    }
    let run_id = WorkflowRunId(run_id);
    let (run, _, _) = load_workflow_run(&state, run_id).await?;
    if !run.steps.contains_key(&input.step_id) {
        return Err(ApiError::bad_request(
            "invalid_workflow_artifact",
            "artifact step does not exist in this run",
        ));
    }
    let content = URL_SAFE_NO_PAD
        .decode(input.content_base64.as_bytes())
        .map_err(|_| {
            ApiError::bad_request(
                "invalid_workflow_artifact",
                "artifact content is not valid base64url",
            )
        })?;
    if content.len() > 16 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "workflow_artifact_too_large",
            "artifact exceeds the 16 MiB limit",
        ));
    }
    let artifact_id = Uuid::now_v7();
    let encrypted = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .seal(
            workflow_artifact_ad(artifact_id, run_id).as_bytes(),
            &content,
        )
        .map_err(ApiError::secret)?;
    let metadata = ArtifactMetadata {
        id: artifact_id,
        run_id,
        step_id: input.step_id,
        name: input.name,
        media_type: input.media_type,
        sha256: format!("{:x}", Sha256::digest(&content)),
        size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
        storage_key: artifact_id.to_string(),
        created_at: Utc::now(),
    };
    let event = state
        .repository
        .put_workflow_artifact(&metadata, &encrypted)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(metadata)))
}

async fn download_workflow_artifact(
    State(state): State<AppState>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let record = state
        .repository
        .workflow_artifact(artifact_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found("workflow_artifact_not_found", "artifact does not exist")
        })?;
    let content = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .open(
            workflow_artifact_ad(artifact_id, record.metadata.run_id).as_bytes(),
            &record.content,
        )
        .map_err(ApiError::secret)?;
    if format!("{:x}", Sha256::digest(&content)) != record.metadata.sha256 {
        return Err(ApiError::unavailable(
            "workflow artifact integrity verification failed",
        ));
    }
    let content_type = HeaderValue::from_str(&record.metadata.media_type)
        .map_err(|_| ApiError::unavailable("workflow artifact has an invalid stored media type"))?;
    let mut response = Response::new(Body::from(content));
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct CreateWorkflowScheduleRequest {
    cron_utc: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_schedule_concurrency")]
    concurrency_limit: u16,
}

const fn default_true() -> bool {
    true
}

const fn default_schedule_concurrency() -> u16 {
    1
}

async fn create_workflow_schedule(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(input): Json<CreateWorkflowScheduleRequest>,
) -> Result<(StatusCode, Json<WorkflowSchedule>), ApiError> {
    let schedule = WorkflowSchedule {
        id: Uuid::now_v7(),
        workflow_id: WorkflowId(workflow_id),
        cron_utc: input.cron_utc,
        enabled: input.enabled,
        concurrency_limit: input.concurrency_limit,
    };
    validate_schedule(&schedule)
        .map_err(|error| ApiError::bad_request("invalid_workflow_schedule", &error.to_string()))?;
    let next_run_at = next_schedule_after(&schedule.cron_utc, Utc::now())
        .map_err(|error| ApiError::bad_request("invalid_workflow_schedule", &error.to_string()))?;
    let event = state
        .repository
        .put_workflow_schedule(&schedule, next_run_at)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((StatusCode::CREATED, Json(schedule)))
}

async fn create_workflow_webhook(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let workflow_id = WorkflowId(workflow_id);
    let _definition = state
        .repository
        .workflow_definition(workflow_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("workflow_not_found", "workflow does not exist"))?;
    let mut secret_bytes = [0_u8; 32];
    secret_bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    secret_bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_sha256 = format!("{:x}", Sha256::digest(secret.as_bytes()));
    let webhook_id = Uuid::now_v7();
    let event = state
        .repository
        .put_workflow_webhook(webhook_id, workflow_id, &secret_sha256, true)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": webhook_id,
            "workflow_id": workflow_id,
            "secret": secret,
            "secret_shown_once": true,
        })),
    ))
}

async fn trigger_workflow_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<StartWorkflowRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let (workflow_id, expected_hash, enabled) = state
        .repository
        .workflow_webhook(webhook_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found("workflow_webhook_not_found", "webhook does not exist")
        })?;
    if !enabled {
        return Err(ApiError::forbidden("workflow webhook is disabled"));
    }
    let secret = headers
        .get("x-constellation-webhook-secret")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .ok_or_else(|| ApiError::unauthorized("workflow webhook secret is required"))?;
    let actual: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    let expected = decode_sha256(&expected_hash)
        .ok_or_else(|| ApiError::unavailable("workflow webhook credential record is corrupted"))?;
    if !bool::from(actual.ct_eq(&expected)) {
        return Err(ApiError::unauthorized("workflow webhook secret is invalid"));
    }
    let run = start_workflow_run(&state, workflow_id, input.inputs).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(workflow_run_response(&run, None)),
    ))
}

async fn load_workflow_definition(
    state: &AppState,
    workflow_id: WorkflowId,
) -> Result<(u32, String, WorkflowDefinition), ApiError> {
    let record = state
        .repository
        .workflow_definition(workflow_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("workflow_not_found", "workflow does not exist"))?;
    let plaintext = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .open(
            workflow_definition_ad(workflow_id, record.revision).as_bytes(),
            &record.content,
        )
        .map_err(ApiError::secret)?;
    let definition: WorkflowDefinition =
        serde_json::from_slice(&plaintext).map_err(|error| ApiError::internal(error.into()))?;
    let actual =
        definition_sha256(&definition).map_err(|error| ApiError::internal(error.into()))?;
    if actual != record.sha256 {
        return Err(ApiError::unavailable(
            "workflow definition integrity verification failed",
        ));
    }
    Ok((record.revision, record.sha256, definition))
}

async fn load_workflow_run(
    state: &AppState,
    run_id: WorkflowRunId,
) -> Result<(WorkflowRun, WorkflowDefinition, Vec<u8>), ApiError> {
    let record = state
        .repository
        .workflow_run(run_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found("workflow_run_not_found", "workflow run does not exist")
        })?;
    let expected_nonce = record.content.nonce.clone();
    let plaintext = state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .open(workflow_run_ad(run_id).as_bytes(), &record.content)
        .map_err(ApiError::secret)?;
    let run: WorkflowRun =
        serde_json::from_slice(&plaintext).map_err(|error| ApiError::internal(error.into()))?;
    if run.workflow_id != record.workflow_id || run_status_str(run.status) != record.status {
        return Err(ApiError::unavailable(
            "workflow run metadata integrity verification failed",
        ));
    }
    let (revision, _, definition) = load_workflow_definition(state, run.workflow_id).await?;
    if revision != record.workflow_revision {
        return Err(ApiError::unavailable(
            "workflow run references an unavailable historical revision",
        ));
    }
    Ok((run, definition, expected_nonce))
}

fn encrypt_workflow_run(state: &AppState, run: &WorkflowRun) -> Result<EncryptedContent, ApiError> {
    let plaintext = serde_json::to_vec(run).map_err(|error| ApiError::internal(error.into()))?;
    state
        .content_keys
        .load_cipher()
        .map_err(ApiError::secret)?
        .seal(workflow_run_ad(run.id).as_bytes(), &plaintext)
        .map_err(ApiError::secret)
}

fn workflow_run_response(run: &WorkflowRun, definition: Option<&WorkflowDefinition>) -> Value {
    json!({
        "run": run,
        "ready_steps": definition.map_or_else(Vec::new, |value| ready_steps(run, value)),
    })
}

fn bind_workflow_principal(event: WorkflowEvent, principal: &str) -> WorkflowEvent {
    match event {
        WorkflowEvent::ApprovalGranted { step_id, .. } => WorkflowEvent::ApprovalGranted {
            step_id,
            principal_id: principal.to_owned(),
        },
        WorkflowEvent::ApprovalDenied { step_id, .. } => WorkflowEvent::ApprovalDenied {
            step_id,
            principal_id: principal.to_owned(),
        },
        WorkflowEvent::Cancel { .. } => WorkflowEvent::Cancel {
            principal_id: principal.to_owned(),
        },
        other => other,
    }
}

fn workflow_event_metadata(event: &WorkflowEvent) -> (&'static str, Option<&str>, Option<&str>) {
    match event {
        WorkflowEvent::Start => ("run.started", None, None),
        WorkflowEvent::StepStarted { step_id } => ("step.started", Some(step_id), None),
        WorkflowEvent::StepLeaseExpired { step_id } => ("step.lease_expired", Some(step_id), None),
        WorkflowEvent::StepSucceeded { step_id, .. } => ("step.succeeded", Some(step_id), None),
        WorkflowEvent::StepFailed { step_id, .. } => ("step.failed", Some(step_id), None),
        WorkflowEvent::ApprovalRequested { step_id } => ("approval.requested", Some(step_id), None),
        WorkflowEvent::ApprovalGranted {
            step_id,
            principal_id,
        } => ("approval.granted", Some(step_id), Some(principal_id)),
        WorkflowEvent::ApprovalDenied {
            step_id,
            principal_id,
        } => ("approval.denied", Some(step_id), Some(principal_id)),
        WorkflowEvent::Cancel { principal_id } => ("run.cancelled", None, Some(principal_id)),
    }
}

const fn run_status_str(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Pending => "pending",
        RunStatus::Running => "running",
        RunStatus::WaitingApproval => "waiting_approval",
        RunStatus::Completed => "completed",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

fn workflow_definition_ad(workflow_id: WorkflowId, revision: u32) -> String {
    format!("workflow:{}:revision:{revision}", workflow_id.0)
}

fn workflow_run_ad(run_id: WorkflowRunId) -> String {
    format!("workflow-run:{}", run_id.0)
}

fn workflow_artifact_ad(artifact_id: Uuid, run_id: WorkflowRunId) -> String {
    format!("workflow-artifact:{artifact_id}:run:{}", run_id.0)
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

async fn list_plugins(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let plugins = state
        .repository
        .plugins()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .map(|plugin| json!({"manifest": plugin.manifest, "enabled": plugin.enabled}))
        .collect::<Vec<_>>();
    Ok(Json(json!({"data": plugins})))
}

#[derive(Debug, Deserialize)]
struct InstallPluginRequest {
    manifest: PluginManifest,
    component_base64: String,
}

async fn install_plugin(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(input): Json<InstallPluginRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !principal_allows(&principal, Permission::PluginAdmin) {
        return Err(ApiError::forbidden(
            "plugin installation requires plugin administration permission",
        ));
    }
    if input.component_base64.len() > 90 * 1024 * 1024 {
        return Err(ApiError::bad_request(
            "plugin_component_too_large",
            "encoded plugin component exceeds its bound",
        ));
    }
    let component = URL_SAFE_NO_PAD
        .decode(input.component_base64.as_bytes())
        .map_err(|_| {
            ApiError::bad_request(
                "invalid_plugin_component",
                "plugin component is not valid base64url",
            )
        })?;
    let host = Arc::clone(&state.plugin_host);
    let manifest = input.manifest.clone();
    let compile_bytes = component.clone();
    tokio::task::spawn_blocking(move || host.compile(&manifest, &compile_bytes).map(|_| ()))
        .await
        .map_err(|error| ApiError::internal(error.into()))?
        .map_err(|error| ApiError::bad_request("invalid_plugin", &error.to_string()))?;

    let plugin_dir = state.data_dir.join("plugins");
    tokio::fs::create_dir_all(&plugin_dir)
        .await
        .map_err(|error| ApiError::internal(error.into()))?;
    let component_path = plugin_dir.join(format!("{}.wasm", input.manifest.sha256));
    if component_path.exists() {
        let existing = tokio::fs::read(&component_path)
            .await
            .map_err(|error| ApiError::internal(error.into()))?;
        if existing != component {
            return Err(ApiError::unavailable(
                "content-addressed plugin path contains different bytes",
            ));
        }
    } else {
        let temporary = plugin_dir.join(format!(".plugin-{}.tmp", Uuid::now_v7()));
        tokio::fs::write(&temporary, &component)
            .await
            .map_err(|error| ApiError::internal(error.into()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|error| ApiError::internal(error.into()))?;
        }
        tokio::fs::rename(&temporary, &component_path)
            .await
            .map_err(|error| ApiError::internal(error.into()))?;
    }
    let event = state
        .repository
        .put_plugin(&input.manifest, &component_path)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "manifest": input.manifest,
            "enabled": false,
            "grant_required": true,
        })),
    ))
}

#[derive(Debug, Deserialize)]
struct GrantPluginRequest {
    permissions: Vec<constellation_plugins::PluginPermission>,
}

async fn grant_plugin(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(plugin_id): Path<String>,
    Json(input): Json<GrantPluginRequest>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&principal, Permission::PluginAdmin) {
        return Err(ApiError::forbidden(
            "plugin grants require plugin administration permission",
        ));
    }
    let installed = state
        .repository
        .plugin(&plugin_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("plugin_not_found", "plugin is not installed"))?;
    let approved_by = authenticated_principal_id(&principal);
    let grant = PluginGrant {
        plugin_id: plugin_id.clone(),
        component_sha256: installed.manifest.sha256.clone(),
        permissions: input.permissions,
        approved_by,
    };
    validate_grant(&installed.manifest, &grant)
        .map_err(|error| ApiError::bad_request("invalid_plugin_grant", &error.to_string()))?;
    let event = state
        .repository
        .put_plugin_grant(&grant)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!({"grant": grant, "enabled": true})))
}

#[derive(Debug, Deserialize)]
struct ExecutePluginRequest {
    input: String,
}

async fn execute_plugin(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(plugin_id): Path<String>,
    Json(input): Json<ExecutePluginRequest>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&principal, Permission::WorkflowOperate) {
        return Err(ApiError::forbidden(
            "plugin execution requires workflow operation permission",
        ));
    }
    let installed = state
        .repository
        .plugin(&plugin_id)
        .await
        .map_err(ApiError::internal)?
        .filter(|plugin| plugin.enabled && plugin.manifest.kind == PluginKind::Tool)
        .ok_or_else(|| {
            ApiError::forbidden("plugin is not installed with an active exact permission grant")
        })?;
    let grant = state
        .repository
        .plugin_grant(&plugin_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::forbidden("plugin permission grant is missing"))?;
    let component = tokio::fs::read(&installed.component_path)
        .await
        .map_err(|error| ApiError::internal(error.into()))?;
    let host = Arc::clone(&state.plugin_host);
    let manifest = installed.manifest;
    let plugin_input = input.input;
    let output = tokio::task::spawn_blocking(move || {
        host.execute(&manifest, &grant, &component, &plugin_input)
    })
    .await
    .map_err(|error| ApiError::internal(error.into()))?
    .map_err(|error| ApiError::bad_request("plugin_execution_failed", &error.to_string()))?;
    Ok(Json(json!({"plugin_id": plugin_id, "output": output})))
}

#[derive(Debug, Deserialize)]
struct CreatePrincipalRequest {
    name: String,
    role: Role,
    #[serde(default)]
    scopes: Vec<Permission>,
}

async fn create_principal(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(input): Json<CreatePrincipalRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !principal_allows(&actor, Permission::TeamAdmin) {
        return Err(ApiError::forbidden(
            "principal creation requires team administration permission",
        ));
    }
    if input.name.trim().is_empty()
        || input.name.len() > 128
        || matches!(input.role, Role::Owner | Role::Node)
        || (input.role != Role::Service && !input.scopes.is_empty())
        || input.scopes.len() > 32
    {
        return Err(ApiError::bad_request(
            "invalid_principal",
            "principal name, role, or service scopes are invalid",
        ));
    }
    if state
        .repository
        .principals()
        .await
        .map_err(ApiError::internal)?
        .iter()
        .any(|principal| principal.name == input.name)
    {
        return Err(ApiError::bad_request(
            "principal_name_exists",
            "principal name is already in use",
        ));
    }
    let principal = Principal {
        id: Uuid::now_v7(),
        name: input.name,
        role: input.role,
        scopes: input.scopes,
        active: true,
        created_at: Utc::now(),
    };
    let api_key = (principal.role == Role::Service).then(|| {
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        format!("cst_svc_{}", URL_SAFE_NO_PAD.encode(bytes))
    });
    let api_key_hash = api_key
        .as_ref()
        .map(|key| format!("{:x}", Sha256::digest(key.as_bytes())));
    let event = state
        .repository
        .put_principal(&principal, api_key_hash.as_deref())
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "principal": principal,
            "api_key": api_key,
            "api_key_shown_once": api_key.is_some(),
        })),
    ))
}

async fn list_principals(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let principals = state
        .repository
        .principals()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"data": principals})))
}

#[derive(Debug, Deserialize)]
struct CreateTeamRequest {
    name: String,
}

async fn create_team(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(input): Json<CreateTeamRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !principal_allows(&actor, Permission::TeamAdmin) {
        return Err(ApiError::forbidden(
            "team creation requires team administration permission",
        ));
    }
    if input.name.trim().is_empty() || input.name.len() > 128 {
        return Err(ApiError::bad_request(
            "invalid_team",
            "team name must contain 1 to 128 characters",
        ));
    }
    let team_id = Uuid::now_v7();
    let event = state
        .repository
        .create_team(team_id, &input.name)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": team_id, "name": input.name})),
    ))
}

async fn list_teams(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let teams = state.repository.teams().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"data": teams})))
}

#[derive(Debug, Deserialize)]
struct PutTeamMemberRequest {
    principal_id: Uuid,
    role: Role,
}

async fn put_team_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Path(team_id): Path<Uuid>,
    Json(input): Json<PutTeamMemberRequest>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::TeamAdmin)
        || matches!(input.role, Role::Owner | Role::Node)
    {
        return Err(ApiError::forbidden(
            "team membership requires team administration and a team-safe role",
        ));
    }
    let membership = TeamMembership {
        team_id,
        principal_id: input.principal_id,
        role: input.role,
    };
    let event = state
        .repository
        .put_team_membership(&membership)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!(membership)))
}

async fn list_team_members(
    State(state): State<AppState>,
    Path(team_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let memberships = state
        .repository
        .team_memberships(team_id)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"team_id": team_id, "data": memberships})))
}

const PASSKEY_CEREMONY_TTL: std::time::Duration = std::time::Duration::from_mins(5);
const PASSKEY_SESSION_HOURS: i64 = 24;

#[derive(Debug, Deserialize)]
struct BeginPasskeyRegistrationRequest {
    principal_id: Uuid,
    name: String,
}

#[derive(Debug, Deserialize)]
struct FinishPasskeyRegistrationRequest {
    ceremony_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct BeginPasskeyLoginRequest {
    principal_name: String,
}

#[derive(Debug, Deserialize)]
struct FinishPasskeyLoginRequest {
    ceremony_id: Uuid,
    credential: PublicKeyCredential,
}

async fn begin_passkey_registration(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(input): Json<BeginPasskeyRegistrationRequest>,
) -> Result<Json<Value>, ApiError> {
    if !state.auth_rate_limiter.admit().await {
        return Err(ApiError::rate_limited("too many authentication ceremonies"));
    }
    if !passkey_registration_allowed(&actor, input.principal_id) {
        return Err(ApiError::forbidden(
            "a principal may register its own passkey; team administrators may register others",
        ));
    }
    if input.name.trim().is_empty() || input.name.len() > 128 {
        return Err(ApiError::bad_request(
            "invalid_passkey_name",
            "passkey name must contain 1 to 128 characters",
        ));
    }
    let principal = state
        .repository
        .principal(input.principal_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("principal_not_found", "principal does not exist"))?;
    let existing = state
        .repository
        .passkeys_for_principal(principal.id)
        .await
        .map_err(ApiError::internal)?;
    let excluded = (!existing.is_empty()).then(|| {
        existing
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect()
    });
    let (challenge, registration) = state
        .passkeys
        .webauthn
        .start_passkey_registration(principal.id, &principal.name, &principal.name, excluded)
        .map_err(|_| {
            ApiError::bad_request(
                "passkey_registration_failed",
                "unable to begin passkey registration",
            )
        })?;
    let ceremony_id = Uuid::now_v7();
    let mut pending = state.passkeys.registrations.lock().await;
    pending.retain(|_, ceremony| ceremony.created_at.elapsed() < PASSKEY_CEREMONY_TTL);
    if pending.len() >= 1_024
        || pending
            .values()
            .filter(|ceremony| ceremony.principal_id == principal.id)
            .count()
            >= 5
    {
        return Err(ApiError::rate_limited("too many active passkey ceremonies"));
    }
    pending.insert(
        ceremony_id,
        PendingPasskeyRegistration {
            principal_id: principal.id,
            name: input.name,
            created_at: Instant::now(),
            state: registration,
        },
    );
    Ok(Json(json!({
        "ceremony_id": ceremony_id,
        "public_key": challenge,
        "expires_in_seconds": PASSKEY_CEREMONY_TTL.as_secs(),
    })))
}

async fn finish_passkey_registration(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(input): Json<FinishPasskeyRegistrationRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let pending = state
        .passkeys
        .registrations
        .lock()
        .await
        .remove(&input.ceremony_id)
        .ok_or_else(|| {
            ApiError::bad_request(
                "passkey_ceremony_invalid",
                "passkey ceremony is missing, expired, or already used",
            )
        })?;
    if pending.created_at.elapsed() >= PASSKEY_CEREMONY_TTL
        || !passkey_registration_allowed(&actor, pending.principal_id)
    {
        return Err(ApiError::bad_request(
            "passkey_ceremony_invalid",
            "passkey ceremony is missing, expired, or already used",
        ));
    }
    let passkey = state
        .passkeys
        .webauthn
        .finish_passkey_registration(&input.credential, &pending.state)
        .map_err(|_| {
            ApiError::bad_request("passkey_verification_failed", "passkey verification failed")
        })?;
    let event = state
        .repository
        .put_passkey(pending.principal_id, &pending.name, &passkey)
        .await
        .map_err(|error| {
            if error.to_string().contains("UNIQUE constraint failed") {
                ApiError::bad_request(
                    "passkey_already_registered",
                    "this credential is already registered",
                )
            } else {
                ApiError::internal(error)
            }
        })?;
    publish(&state, event);
    Ok((
        StatusCode::CREATED,
        Json(json!({"principal_id": pending.principal_id, "name": pending.name})),
    ))
}

async fn begin_passkey_login(
    State(state): State<AppState>,
    Json(input): Json<BeginPasskeyLoginRequest>,
) -> Result<Json<Value>, ApiError> {
    if !state.auth_rate_limiter.admit().await {
        return Err(ApiError::rate_limited("too many authentication ceremonies"));
    }
    let principal = state
        .repository
        .principal_by_name(&input.principal_name)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("passkey authentication failed"))?;
    let passkeys = state
        .repository
        .passkeys_for_principal(principal.id)
        .await
        .map_err(ApiError::internal)?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("passkey authentication failed"));
    }
    let (challenge, authentication) = state
        .passkeys
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|_| ApiError::unauthorized("passkey authentication failed"))?;
    let ceremony_id = Uuid::now_v7();
    let mut pending = state.passkeys.authentications.lock().await;
    pending.retain(|_, ceremony| ceremony.created_at.elapsed() < PASSKEY_CEREMONY_TTL);
    if pending.len() >= 1_024
        || pending
            .values()
            .filter(|ceremony| ceremony.principal_id == principal.id)
            .count()
            >= 5
    {
        return Err(ApiError::rate_limited("too many active passkey ceremonies"));
    }
    pending.insert(
        ceremony_id,
        PendingPasskeyAuthentication {
            principal_id: principal.id,
            created_at: Instant::now(),
            state: authentication,
        },
    );
    Ok(Json(json!({
        "ceremony_id": ceremony_id,
        "public_key": challenge,
        "expires_in_seconds": PASSKEY_CEREMONY_TTL.as_secs(),
    })))
}

async fn finish_passkey_login(
    State(state): State<AppState>,
    Json(input): Json<FinishPasskeyLoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let pending = state
        .passkeys
        .authentications
        .lock()
        .await
        .remove(&input.ceremony_id)
        .ok_or_else(|| ApiError::unauthorized("passkey authentication failed"))?;
    if pending.created_at.elapsed() >= PASSKEY_CEREMONY_TTL {
        return Err(ApiError::unauthorized("passkey authentication failed"));
    }
    let result = state
        .passkeys
        .webauthn
        .finish_passkey_authentication(&input.credential, &pending.state)
        .map_err(|_| ApiError::unauthorized("passkey authentication failed"))?;
    let mut passkeys = state
        .repository
        .passkeys_for_principal(pending.principal_id)
        .await
        .map_err(ApiError::internal)?;
    let passkey = passkeys
        .iter_mut()
        .find(|passkey| passkey.cred_id() == result.cred_id())
        .ok_or_else(|| ApiError::unauthorized("passkey authentication failed"))?;
    let _updated = passkey.update_credential(&result);
    state
        .repository
        .update_passkey_after_authentication(passkey)
        .await
        .map_err(ApiError::internal)?;
    let principal = state
        .repository
        .principal(pending.principal_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("passkey authentication failed"))?;
    Ok(Json(issue_browser_session(&state, principal).await?))
}

fn passkey_registration_allowed(actor: &AuthenticatedPrincipal, principal_id: Uuid) -> bool {
    match actor {
        AuthenticatedPrincipal::Owner => true,
        AuthenticatedPrincipal::Human(principal) => {
            principal.id == principal_id || principal.allows(Permission::TeamAdmin)
        }
        AuthenticatedPrincipal::Service(principal) => principal.allows(Permission::TeamAdmin),
        AuthenticatedPrincipal::Node(_) => false,
    }
}

async fn put_auth_provider(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(provider): Json<AuthProvider>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ProviderAdmin) {
        return Err(ApiError::forbidden(
            "identity providers require provider administration permission",
        ));
    }
    validate_auth_provider(&provider)
        .map_err(|error| ApiError::bad_request("invalid_auth_provider", &error.to_string()))?;
    if provider.enabled {
        if provider.kind == AuthProviderKind::Saml {
            return Err(ApiError::bad_request(
                "unsupported_feature",
                "SAML authentication is not available in this build; keep the provider disabled",
            ));
        }
        crate::oidc::OidcState::probe(&provider)
            .await
            .map_err(|_| {
                ApiError::bad_request(
                    "oidc_discovery_failed",
                    "the OIDC provider, redirect, or credential reference could not be verified",
                )
            })?;
    }
    let event = state
        .repository
        .put_auth_provider(&provider)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!(provider)))
}

async fn list_auth_providers(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ProviderAdmin) {
        return Err(ApiError::forbidden(
            "identity providers require provider administration permission",
        ));
    }
    let providers = state
        .repository
        .auth_providers()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!(providers)))
}

async fn list_oidc_login_providers(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let providers = state
        .repository
        .auth_providers()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|provider| provider.enabled && provider.kind == AuthProviderKind::Oidc)
        .map(|provider| {
            json!({
                "id": provider.id,
                "issuer": provider.issuer,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!(providers)))
}

#[derive(Debug, Deserialize)]
struct BeginOidcLoginRequest {
    provider_id: Uuid,
}

async fn begin_oidc_login(
    State(state): State<AppState>,
    Json(request): Json<BeginOidcLoginRequest>,
) -> Result<Json<Value>, ApiError> {
    if !state.auth_rate_limiter.admit().await {
        return Err(ApiError::rate_limited("too many authentication ceremonies"));
    }
    let provider = state
        .repository
        .auth_provider(request.provider_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::bad_request("invalid_identity_provider", "OIDC login could not begin")
        })?;
    let start = state.oidc.begin(&provider).await.map_err(|_| {
        ApiError::bad_request("oidc_login_unavailable", "OIDC login could not begin")
    })?;
    Ok(Json(json!({
        "authorization_url": start.authorization_url,
        "expires_in_seconds": start.expires_in_seconds,
    })))
}

#[derive(Debug, Deserialize)]
struct FinishOidcLoginRequest {
    provider_id: Uuid,
    state: String,
    code: String,
}

async fn finish_oidc_login(
    State(state): State<AppState>,
    Json(request): Json<FinishOidcLoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let provider = state
        .repository
        .auth_provider(request.provider_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("external authentication failed"))?;
    let identity = state
        .oidc
        .finish(&provider, &request.state, &request.code)
        .await
        .map_err(|_| ApiError::unauthorized("external authentication failed"))?;
    let principal = state
        .repository
        .principal_by_external_identity(identity.provider_id, &identity.subject_sha256)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::unauthorized("external authentication failed"))?;
    Ok(Json(issue_browser_session(&state, principal).await?))
}

#[derive(Debug, Deserialize)]
struct LinkExternalIdentityRequest {
    principal_id: Uuid,
    subject: String,
}

async fn link_external_identity(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Path(provider_id): Path<Uuid>,
    Json(request): Json<LinkExternalIdentityRequest>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ProviderAdmin) {
        return Err(ApiError::forbidden(
            "identity links require provider administration permission",
        ));
    }
    if request.subject.is_empty() || request.subject.len() > 2_048 {
        return Err(ApiError::bad_request(
            "invalid_external_subject",
            "external subject violates its bounds",
        ));
    }
    if state
        .repository
        .auth_provider(provider_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
        || state
            .repository
            .principal(request.principal_id)
            .await
            .map_err(ApiError::internal)?
            .is_none()
    {
        return Err(ApiError::bad_request(
            "identity_link_target_missing",
            "provider and principal must already exist",
        ));
    }
    let digest = crate::oidc::external_subject_digest(provider_id, &request.subject);
    let event = state
        .repository
        .put_external_identity(provider_id, &digest, request.principal_id)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!({
        "provider_id": provider_id,
        "principal_id": request.principal_id,
        "linked": true,
    })))
}

async fn issue_browser_session(state: &AppState, principal: Principal) -> Result<Value, ApiError> {
    let mut token_bytes = [0_u8; 32];
    token_bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    token_bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let token = format!("cst_session_{}", URL_SAFE_NO_PAD.encode(token_bytes));
    let token_sha256 = format!("{:x}", Sha256::digest(token.as_bytes()));
    let expires_at = Utc::now() + chrono::Duration::hours(PASSKEY_SESSION_HOURS);
    state
        .repository
        .put_browser_session(&token_sha256, principal.id, expires_at)
        .await
        .map_err(ApiError::internal)?;
    Ok(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "principal": principal,
    }))
}

async fn put_cloud_adapter(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(policy): Json<CloudAdapterPolicy>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ProviderAdmin) {
        return Err(ApiError::forbidden(
            "cloud adapters require provider administration permission",
        ));
    }
    validate_cloud_policy(&policy)
        .map_err(|error| ApiError::bad_request("invalid_cloud_policy", &error.to_string()))?;
    if policy.enabled {
        if policy.provider_plugin != crate::cloud::OPENAI_COMPATIBLE_PROVIDER {
            return Err(ApiError::bad_request(
                "unsupported_feature",
                "this build executes only the built-in OpenAI-compatible cloud provider",
            ));
        }
        OsKeyring::new("com.constellation.provider", &policy.credential_reference)
            .load_secret_string()
            .map_err(|_| {
                ApiError::bad_request(
                    "cloud_credential_unavailable",
                    "the cloud credential reference could not be loaded from the native vault",
                )
            })?;
    }
    let event = state
        .repository
        .put_cloud_policy(&policy)
        .await
        .map_err(ApiError::internal)?;
    publish(&state, event);
    Ok(Json(json!(policy)))
}

async fn list_cloud_adapters(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ProviderAdmin) {
        return Err(ApiError::forbidden(
            "cloud adapters require provider administration permission",
        ));
    }
    let policies = state
        .repository
        .cloud_policies()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!(policies)))
}

async fn get_controller_lease(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let lease = state
        .repository
        .controller_lease()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"lease": lease})))
}

#[derive(Debug, Deserialize)]
struct AcquireControllerLeaseRequest {
    #[serde(default = "default_controller_lease_seconds")]
    duration_seconds: u8,
}

const fn default_controller_lease_seconds() -> u8 {
    15
}

async fn acquire_controller_lease(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedPrincipal>,
    Json(input): Json<AcquireControllerLeaseRequest>,
) -> Result<Json<Value>, ApiError> {
    if !principal_allows(&actor, Permission::ClusterAdmin) {
        return Err(ApiError::forbidden(
            "controller election requires cluster administration permission",
        ));
    }
    let now = Utc::now();
    if !(10..=60).contains(&input.duration_seconds) {
        return Err(ApiError::bad_request(
            "invalid_controller_lease",
            "controller lease duration must be 10 through 60 seconds",
        ));
    }
    let lease = state
        .repository
        .claim_controller_lease(
            state.controller_guard.controller_id(),
            now,
            input.duration_seconds,
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::bad_request(
                "controller_lease_held",
                "another controller holds an unexpired fenced lease",
            )
        })?;
    state.controller_guard.update(Some(&lease));
    Ok(Json(json!(lease)))
}

fn authenticated_principal_id(principal: &AuthenticatedPrincipal) -> String {
    match principal {
        AuthenticatedPrincipal::Owner => "local-owner".to_owned(),
        AuthenticatedPrincipal::Node(node) => format!("node:{}", node.0),
        AuthenticatedPrincipal::Human(principal) | AuthenticatedPrincipal::Service(principal) => {
            principal.id.to_string()
        }
    }
}

async fn get_workload_plan(
    State(state): State<AppState>,
    Path(workload_id): Path<Uuid>,
) -> Result<Json<ExecutionPlan>, ApiError> {
    state
        .repository
        .plan_for_workload(WorkloadId(workload_id))
        .await
        .map_err(ApiError::internal)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("plan_not_found", "execution plan does not exist"))
}

async fn cancel_workload(
    State(state): State<AppState>,
    Path(workload_id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let workload_id = WorkloadId(workload_id);
    let cancellation = state
        .repository
        .cancel_workload(workload_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::bad_request(
                "workload_not_cancellable",
                "workload does not exist or is already terminal",
            )
        })?;
    if let Some(lease_id) = cancellation.lease_id {
        if let Some(sender) = state.remote_executions.lock().await.remove(&lease_id) {
            let _ignored = sender.send(RuntimeEvent::Cancelled).await;
        }
    } else {
        state
            .runtimes
            .adapter_by_id(&cancellation.runtime)
            .await
            .map_err(ApiError::runtime)?
            .cancel(workload_id)
            .await
            .map_err(ApiError::runtime)?;
    }
    publish(&state, cancellation.event);
    Ok(Json(json!({
        "workload_id": workload_id,
        "status": "cancelled",
    })))
}

#[derive(Debug, Serialize)]
struct ClusterSummary {
    ready_nodes: usize,
    total_nodes: usize,
    usable_memory_bytes: u64,
    active_runtime: String,
    local_only: bool,
    message: String,
}

async fn cluster_summary(State(state): State<AppState>) -> Result<Json<ClusterSummary>, ApiError> {
    let nodes = state
        .repository
        .list_nodes()
        .await
        .map_err(ApiError::internal)?;
    let ready_nodes = nodes
        .iter()
        .filter(|node| node.status == NodeStatus::Ready)
        .count();
    let policies = state
        .repository
        .resource_policies()
        .await
        .map_err(ApiError::internal)?;
    let usable_memory_bytes: u64 = nodes
        .iter()
        .filter(|node| node.status == NodeStatus::Ready)
        .map(|node| {
            let policy = policies.get(&node.id).cloned().unwrap_or_default();
            let system = usable_system_memory_with_policy(
                node.capabilities.memory_total_bytes,
                node.capabilities.memory_available_bytes,
                &policy,
            );
            let accelerator = node.capabilities.accelerator.as_ref().map_or(0, |value| {
                constellation_scheduler::usable_accelerator_memory_with_policy(
                    value.memory_bytes,
                    &policy,
                )
            });
            system.max(accelerator)
        })
        .sum();
    let memory_tenths_gib = usable_memory_bytes.saturating_mul(10) / (1024 * 1024 * 1024);
    let active_runtime = state
        .runtimes
        .capabilities()
        .await
        .map_err(ApiError::runtime)?
        .into_iter()
        .map(|capability| capability.runtime_id)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(Json(ClusterSummary {
        ready_nodes,
        total_nodes: nodes.len(),
        usable_memory_bytes,
        active_runtime,
        local_only: true,
        message: format!(
            "{ready_nodes} computer{} ready with {}.{} GiB of usable AI memory.",
            if ready_nodes == 1 { " is" } else { "s are" },
            memory_tenths_gib / 10,
            memory_tenths_gib % 10,
        ),
    }))
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_event_limit")]
    limit: i64,
}

const fn default_event_limit() -> i64 {
    100
}

async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<ClusterEvent>>, ApiError> {
    state
        .repository
        .events_after(query.after, query.limit)
        .await
        .map(Json)
        .map_err(ApiError::internal)
}

async fn live_events(
    websocket: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    websocket
        .protocols(["constellation.events.v1"])
        .on_upgrade(move |socket| handle_event_socket(socket, state))
}

async fn handle_event_socket(mut socket: WebSocket, state: AppState) {
    if let Ok(history) = state.repository.events_after(0, 100).await {
        for event in history {
            let Ok(encoded) = serde_json::to_string(&event) else {
                continue;
            };
            if socket.send(Message::Text(encoded.into())).await.is_err() {
                return;
            }
        }
    }
    let mut receiver = state.events.subscribe();
    loop {
        match receiver.recv().await {
            Ok(event) => {
                let Ok(encoded) = serde_json::to_string(&event) else {
                    continue;
                };
                if socket.send(Message::Text(encoded.into())).await.is_err() {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

fn publish(state: &AppState, event: ClusterEvent) {
    let _ignored = state.events.send(event);
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    message: String,
    r#type: String,
    code: String,
    param: Option<String>,
    trace_id: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    kind: String,
    message: String,
}

impl ApiError {
    fn bad_request(code: &str, message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.to_owned(),
            kind: "invalid_request_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized".to_owned(),
            kind: "authentication_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn forbidden(message: &str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden".to_owned(),
            kind: "permission_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn rate_limited(message: &str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limit_exceeded".to_owned(),
            kind: "rate_limit_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn not_found(code: &str, message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: code.to_owned(),
            kind: "not_found_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn unavailable(message: &str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "unavailable".to_owned(),
            kind: "server_error".to_owned(),
            message: message.to_owned(),
        }
    }

    fn generation_interrupted(partial_output: bool) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "generation_interrupted".to_owned(),
            kind: "server_error".to_owned(),
            message: if partial_output {
                "generation was interrupted after output began; the partial output was not resumed"
                    .to_owned()
            } else {
                "generation was interrupted before a terminal runtime event".to_owned()
            },
        }
    }

    fn generation_cancelled() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "cancelled".to_owned(),
            kind: "invalid_request_error".to_owned(),
            message: "generation was cancelled".to_owned(),
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err at identity boundaries.
    fn identity(error: IdentityError) -> Self {
        match error {
            IdentityError::InvitationExpired => Self {
                status: StatusCode::GONE,
                code: "invitation_expired".to_owned(),
                kind: "invalid_request_error".to_owned(),
                message: "enrollment invitation expired".to_owned(),
            },
            IdentityError::InvitationInvalidated => Self {
                status: StatusCode::GONE,
                code: "invitation_invalidated".to_owned(),
                kind: "authentication_error".to_owned(),
                message: "enrollment invitation is no longer valid".to_owned(),
            },
            IdentityError::InvalidProof | IdentityError::InvalidHandshake => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_enrollment_proof".to_owned(),
                kind: "authentication_error".to_owned(),
                message: "enrollment proof is invalid".to_owned(),
            },
            IdentityError::ApprovalRequired => Self {
                status: StatusCode::CONFLICT,
                code: "approval_required".to_owned(),
                kind: "invalid_request_error".to_owned(),
                message: "administrator approval is required".to_owned(),
            },
            IdentityError::InvitationUnavailable | IdentityError::SessionConsumed => {
                Self::not_found(
                    "invitation_unavailable",
                    "enrollment invitation is unavailable",
                )
            }
            IdentityError::Certificate(error) => {
                tracing::error!(%error, "cluster certificate operation failed");
                Self::unavailable("cluster certificate authority is unavailable")
            }
        }
    }

    fn runtime(error: constellation_runtime::RuntimeError) -> Self {
        match error {
            constellation_runtime::RuntimeError::ModelUnavailable(_) => {
                Self::not_found("model_not_found", "requested model is unavailable")
            }
            constellation_runtime::RuntimeError::UnsupportedFeature(feature) => {
                Self::bad_request("unsupported_feature", &feature)
            }
            constellation_runtime::RuntimeError::Unavailable
            | constellation_runtime::RuntimeError::Execution(_) => {
                Self::unavailable("runtime could not execute the request")
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err at model-store boundaries.
    fn model_store(error: ModelStoreError) -> Self {
        match error {
            ModelStoreError::InvalidAlias => {
                Self::bad_request("invalid_model_alias", "model alias is invalid")
            }
            ModelStoreError::LicenseNotAccepted => Self::bad_request(
                "license_not_accepted",
                "model license must be accepted before import",
            ),
            ModelStoreError::NotFound(_) => {
                Self::not_found("model_not_found", "model is not present in the local cache")
            }
            ModelStoreError::Verification(_) => Self::bad_request(
                "model_verification_failed",
                "model content did not match its verified manifest",
            ),
            ModelStoreError::Io(_) | ModelStoreError::Json(_) => {
                tracing::error!(error = %error, "model store failure");
                Self::unavailable("model storage is unavailable")
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err at transport boundaries.
    fn network(error: NetworkError) -> Self {
        let code = match error {
            NetworkError::NoTrustedTransport => "no_trusted_transport",
            NetworkError::RemoteDisabled => "remote_networking_disabled",
            NetworkError::ManagedRelayDisabled => "managed_relay_disabled",
            NetworkError::BandwidthQuotaExceeded => "bandwidth_quota_exceeded",
            NetworkError::KillSwitchEngaged => "remote_kill_switch_engaged",
        };
        Self::bad_request(code, &error.to_string())
    }

    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err at credential boundaries.
    fn secret(error: SecretError) -> Self {
        tracing::error!(error = %error, "encrypted content operation failed");
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "encrypted_content_unavailable".to_owned(),
            kind: "server_error".to_owned(),
            message: "encrypted chat storage is unavailable on this device".to_owned(),
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Matches Result::map_err without repetitive closures.
    fn internal(error: anyhow::Error) -> Self {
        tracing::error!(error = %error, "internal API failure");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error".to_owned(),
            kind: "server_error".to_owned(),
            message: "an internal error occurred".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        let trace_id = Uuid::new_v4().to_string();
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    message: self.message,
                    r#type: self.kind,
                    code: self.code,
                    param: None,
                    trace_id,
                },
            }),
        )
            .into_response()
    }
}

/// Constructs a normalized local device record from explicit detector values.
#[must_use]
pub fn local_node(
    name: String,
    os: OperatingSystem,
    architecture: String,
    cpu_model: String,
    logical_cores: u16,
    memory_total_bytes: u64,
    memory_available_bytes: u64,
) -> Node {
    Node {
        id: NodeId::new(),
        name,
        os,
        architecture,
        status: NodeStatus::Ready,
        capabilities: NodeCapabilities {
            cpu_model,
            logical_cores,
            memory_total_bytes,
            memory_available_bytes,
            accelerator: None::<Accelerator>,
            runtimes: vec![MockRuntime::ID.to_owned()],
            on_battery: false,
            user_active: true,
            temperature_celsius: None,
            thermal_throttling: None,
        },
        last_seen_at: Utc::now(),
    }
}
