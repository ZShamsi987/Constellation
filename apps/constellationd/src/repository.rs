//! Dual-dialect controller persistence for local `SQLite` and server `PostgreSQL` deployments.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex as StdMutex, OnceLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Utc};
use constellation_core::{
    BenchmarkReport, ClusterEvent, ExecutionPlan, Node, NodeCapabilities, NodeId,
    NodeResourcePolicy, NodeStatus, OperatingSystem, WorkerRuntimeEvent, WorkloadId,
    WorkloadRequest,
};
use constellation_identity::{
    DeviceCertificate, InvitationStatus, MembershipCredential, PeerTransferTicket,
};
use constellation_model_store::ModelManifest;
use constellation_network::{NetworkPolicy, TransportDecision};
use constellation_plugins::{PluginGrant, PluginManifest};
use constellation_scheduler::PlanObservation;
use constellation_secrets::EncryptedContent;
use constellation_teams::{
    AuthProvider, CloudAdapterPolicy, ControllerLease, Principal, Role, TeamMembership,
};
use constellation_workflows::{ArtifactMetadata, WorkflowId, WorkflowRunId, WorkflowSchedule};
use sha2::Digest as _;
use sqlx::any::{AnyArguments, AnyPoolOptions};
use sqlx::query::{Query, QueryScalar};
use sqlx::{Any, AnyPool, FromRow, Row, Transaction};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

/// Durable repository for controller state.
#[derive(Debug, Clone)]
pub struct Repository {
    pool: AnyPool,
    dialect: DatabaseDialect,
    database_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatabaseDialect {
    Sqlite,
    Postgres,
}

/// Converts portable question-mark parameters to `$n`, which both supported engines accept.
/// The bounded cache contains only static query literals declared in this module.
fn portable_sql(input: &'static str) -> &'static str {
    static CACHE: OnceLock<StdMutex<HashMap<&'static str, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut values = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(value) = values.get(input) {
        return value;
    }
    let mut output = String::with_capacity(input.len() + 16);
    let mut parameters = 0_u16;
    let mut quoted = false;
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\'' {
            output.push(character);
            if quoted && characters.peek() == Some(&'\'') {
                output.push(characters.next().unwrap_or('\''));
            } else {
                quoted = !quoted;
            }
        } else if character == '?' && !quoted {
            parameters = parameters.saturating_add(1);
            output.push('$');
            output.push_str(&parameters.to_string());
        } else {
            output.push(character);
        }
    }
    let converted = Box::leak(output.into_boxed_str());
    values.insert(input, converted);
    converted
}

fn db_query<'query>(sql: &'static str) -> Query<'query, Any, AnyArguments<'query>> {
    sqlx::query::<Any>(portable_sql(sql))
}

fn db_query_scalar<'query, O>(
    sql: &'static str,
) -> QueryScalar<'query, Any, O, AnyArguments<'query>>
where
    (O,): for<'row> FromRow<'row, sqlx::any::AnyRow>,
{
    sqlx::query_scalar::<Any, O>(portable_sql(sql))
}

/// Content-free conversation metadata returned to authenticated clients.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversationRecord {
    /// Conversation identifier.
    pub id: Uuid,
    /// Temporary conversations never enter this table and therefore remain false here.
    pub temporary: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Most recent encrypted message time.
    pub updated_at: DateTime<Utc>,
}

/// Encrypted message row. Decryption occurs only at the API trust boundary.
#[derive(Debug)]
pub struct EncryptedMessageRecord {
    /// Message identifier.
    pub id: Uuid,
    /// Message role required as authenticated associated data.
    pub role: String,
    /// Envelope version.
    pub envelope_version: u8,
    /// `XChaCha20` nonce.
    pub nonce: Vec<u8>,
    /// Authenticated ciphertext.
    pub ciphertext: Vec<u8>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Encrypted durable worker lease loaded at the API trust boundary.
pub struct LeasedWorkRecord {
    /// Lease identity.
    pub id: Uuid,
    /// Workload identity.
    pub workload_id: WorkloadId,
    /// Authorized worker.
    pub node_id: NodeId,
    /// One-based attempt count.
    pub attempt: u8,
    /// Model alias.
    pub model: String,
    /// Authenticated encryption envelope version.
    pub envelope_version: u8,
    /// `XChaCha` nonce.
    pub nonce: Vec<u8>,
    /// Encrypted canonical input.
    pub ciphertext: Vec<u8>,
    /// Maximum output tokens.
    pub maximum_output_tokens: u32,
    /// Immutable execution plan.
    pub plan: ExecutionPlan,
    /// Current lease deadline.
    pub expires_at: DateTime<Utc>,
}

/// Controller action after a worker lease misses its 30-second deadline.
pub struct ExpiredLeaseAction {
    /// Lease identity used by the live response channel.
    pub lease_id: Uuid,
    /// True when the lease was returned to pending for its one transparent retry.
    pub retried: bool,
    /// True when partial output must be preserved and labeled interrupted.
    pub output_started: bool,
    /// Redacted durable event.
    pub event: ClusterEvent,
}

/// Durable result of cancelling one running workload.
pub struct WorkloadCancellation {
    /// Runtime adapter identifier used by a controller-local execution.
    pub runtime: String,
    /// Active remote lease, when execution was delegated to a worker.
    pub lease_id: Option<Uuid>,
    /// Redacted durable cancellation event.
    pub event: ClusterEvent,
}

/// Content-free distributed execution span.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionTraceSpan {
    /// Unique span identity.
    pub id: Uuid,
    /// Workload being traced.
    pub workload_id: WorkloadId,
    /// Node that observed the operation.
    pub node_id: NodeId,
    /// Optional causal parent.
    pub parent_span_id: Option<Uuid>,
    /// Stable operation name.
    pub operation: String,
    /// Explicit wall-clock start supplied by the authenticated node.
    pub started_at: DateTime<Utc>,
    /// Monotonic duration measured locally.
    pub duration_us: u64,
    /// `ok`, `error`, or `cancelled`.
    pub status: String,
    /// Bounded privacy-safe numeric/string attributes.
    pub attributes: serde_json::Value,
}

/// Public workflow metadata that contains no definition or run content.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowSummary {
    /// Workflow identity.
    pub id: WorkflowId,
    /// Human-facing name.
    pub name: String,
    /// Current immutable revision.
    pub revision: u32,
    /// Canonical definition digest.
    pub sha256: String,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Encrypted workflow definition loaded at the API content boundary.
pub struct EncryptedWorkflowDefinition {
    /// Current revision.
    pub revision: u32,
    /// Canonical plaintext digest.
    pub sha256: String,
    /// Authenticated encrypted definition.
    pub content: EncryptedContent,
}

/// Encrypted workflow run loaded at the API content boundary.
pub struct EncryptedWorkflowRun {
    /// Owning workflow.
    pub workflow_id: WorkflowId,
    /// Immutable definition revision.
    pub workflow_revision: u32,
    /// Public lifecycle status.
    pub status: String,
    /// Authenticated encrypted state.
    pub content: EncryptedContent,
}

/// Encrypted workflow artifact loaded at the API content boundary.
pub struct EncryptedWorkflowArtifact {
    /// Content-free artifact metadata.
    pub metadata: ArtifactMetadata,
    /// Authenticated encrypted bytes.
    pub content: EncryptedContent,
}

/// Durable scheduled occurrence waiting to be attached to its deterministic run identity.
#[derive(Debug, Clone)]
pub struct WorkflowScheduleFiring {
    /// Schedule configuration captured through the foreign-key relationship.
    pub schedule: WorkflowSchedule,
    /// Exact UTC minute represented by this occurrence.
    pub due_at: DateTime<Utc>,
    /// Stable run identity allocated when the occurrence was claimed.
    pub run_id: WorkflowRunId,
}

/// Content-free catalog entry for a reusable workflow template.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowTemplateSummary {
    /// Template identity.
    pub id: Uuid,
    /// Unique human-facing catalog name.
    pub name: String,
    /// Immutable source workflow selected by the template.
    pub workflow_id: WorkflowId,
    /// Declarative catalog metadata; workflow content remains encrypted separately.
    pub metadata: serde_json::Value,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Installed plugin metadata and component location.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstalledPluginRecord {
    /// Validated plugin manifest.
    pub manifest: PluginManifest,
    /// Content-addressed local component path.
    pub component_path: std::path::PathBuf,
    /// Plugins execute only after an exact grant is approved.
    pub enabled: bool,
}

/// Public team metadata.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TeamRecord {
    /// Team identity.
    pub id: Uuid,
    /// Unique display name.
    pub name: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

impl Repository {
    /// Opens the database and applies embedded migrations.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let dialect = if database_url.starts_with("sqlite:") {
            DatabaseDialect::Sqlite
        } else if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
            DatabaseDialect::Postgres
        } else {
            anyhow::bail!("database URL must use sqlite, postgres, or postgresql scheme");
        };
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await
            .context("connect to controller database")?;
        match dialect {
            DatabaseDialect::Sqlite => {
                db_query("PRAGMA foreign_keys = ON")
                    .execute(&pool)
                    .await
                    .context("enable SQLite foreign keys")?;
                db_query("PRAGMA journal_mode = WAL")
                    .execute(&pool)
                    .await
                    .context("enable SQLite WAL")?;
                sqlx::migrate!("../../migrations/sqlite")
                    .run(&pool)
                    .await
                    .context("apply SQLite migrations")?;
            }
            DatabaseDialect::Postgres => {
                sqlx::migrate!("../../migrations/postgres")
                    .run(&pool)
                    .await
                    .context("apply PostgreSQL migrations")?;
            }
        }
        Ok(Self {
            pool,
            dialect,
            database_url: database_url.to_owned(),
        })
    }

    /// Closes every pooled connection before offline maintenance or test cleanup.
    #[cfg(test)]
    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Produces a transactionally consistent database backup.
    pub async fn backup_to(&self, destination: &Path) -> Result<()> {
        if destination.exists() {
            anyhow::bail!("backup destination already exists");
        }
        match self.dialect {
            DatabaseDialect::Sqlite => {
                db_query("VACUUM INTO ?")
                    .bind(destination.to_string_lossy().as_ref())
                    .execute(&self.pool)
                    .await
                    .context("create consistent SQLite backup")?;
            }
            DatabaseDialect::Postgres => {
                let status = tokio::process::Command::new("pg_dump")
                    .arg("--format=custom")
                    .arg("--file")
                    .arg(destination)
                    .env("PGDATABASE", &self.database_url)
                    .status()
                    .await
                    .context("launch pg_dump for PostgreSQL backup")?;
                if !status.success() {
                    let _ignored = tokio::fs::remove_file(destination).await;
                    anyhow::bail!("pg_dump did not complete successfully");
                }
            }
        }
        Ok(())
    }

    /// Inserts or refreshes the local controller/worker node and returns its stable record.
    pub async fn ensure_local_node(&self, mut detected: Node) -> Result<Node> {
        if let Some(existing) = self.local_node().await? {
            detected.id = existing.id;
        }
        self.upsert_node(&detected, true, "device.local_ready")
            .await?;
        Ok(detected)
    }

    /// Loads the stable node record without mutating cluster state.
    pub async fn local_node(&self) -> Result<Option<Node>> {
        let row = db_query(
            "SELECT id, name, os, architecture, status, capabilities_json, last_seen_at FROM devices WHERE is_local = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("load local node")?;
        row.map(|value| decode_node(&value)).transpose()
    }

    /// Registers or refreshes a node and emits a durable event in the same transaction.
    pub async fn register_node(&self, node: &Node) -> Result<ClusterEvent> {
        self.upsert_node(node, false, "device.registered").await
    }

    /// Replaces authenticated worker inventory while preserving its stable device identity.
    pub async fn update_node_inventory(&self, node: &Node) -> Result<ClusterEvent> {
        self.upsert_node(node, false, "device.inventory_updated")
            .await
    }

    async fn upsert_node(
        &self,
        node: &Node,
        is_local: bool,
        event_type: &str,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin node transaction")?;
        let capabilities =
            serde_json::to_string(&node.capabilities).context("serialize node capabilities")?;
        db_query(
            "INSERT INTO devices (id, name, os, architecture, status, capabilities_json, last_seen_at, is_local) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, os=excluded.os, architecture=excluded.architecture, \
             status=excluded.status, capabilities_json=excluded.capabilities_json, last_seen_at=excluded.last_seen_at",
        )
        .bind(node.id.0.to_string())
        .bind(&node.name)
        .bind(os_to_str(node.os))
        .bind(&node.architecture)
        .bind(status_to_str(node.status))
        .bind(capabilities)
        .bind(node.last_seen_at.to_rfc3339())
        .bind(i64::from(is_local))
        .execute(&mut *transaction)
        .await
        .context("upsert node")?;
        let event = insert_event(
            &mut transaction,
            event_type,
            serde_json::json!({
                "node_id": node.id,
                "name": node.name,
                "status": node.status,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit node transaction")?;
        Ok(event)
    }

    /// Lists all registered nodes in stable name/ID order.
    pub async fn list_nodes(&self) -> Result<Vec<Node>> {
        let rows = db_query(
            "SELECT id, name, os, architecture, status, capabilities_json, last_seen_at FROM devices ORDER BY name, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("list nodes")?;
        rows.iter().map(decode_node).collect()
    }

    /// Updates node liveness state and emits a durable event.
    pub async fn update_node_status(
        &self,
        node_id: NodeId,
        status: NodeStatus,
    ) -> Result<Option<ClusterEvent>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin status transaction")?;
        let result = db_query("UPDATE devices SET status = ?, last_seen_at = ? WHERE id = ?")
            .bind(status_to_str(status))
            .bind(Utc::now().to_rfc3339())
            .bind(node_id.0.to_string())
            .execute(&mut *transaction)
            .await
            .context("update node status")?;
        if result.rows_affected() == 0 {
            transaction
                .rollback()
                .await
                .context("rollback missing node")?;
            return Ok(None);
        }
        let event = insert_event(
            &mut transaction,
            "device.status_changed",
            serde_json::json!({"node_id": node_id, "status": status}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit status transaction")?;
        Ok(Some(event))
    }

    /// Records an authenticated heartbeat without allowing a revoked node to rejoin.
    pub async fn heartbeat(&self, node_id: NodeId) -> Result<Option<ClusterEvent>> {
        let mut transaction = self.pool.begin().await.context("begin heartbeat")?;
        let row = db_query("SELECT status FROM devices WHERE id = ?")
            .bind(node_id.0.to_string())
            .fetch_optional(&mut *transaction)
            .await
            .context("load heartbeat node")?;
        let Some(row) = row else {
            transaction
                .rollback()
                .await
                .context("rollback unknown heartbeat")?;
            return Ok(None);
        };
        let status: String = row.try_get("status").context("read heartbeat status")?;
        if status == "revoked" {
            transaction
                .rollback()
                .await
                .context("rollback revoked heartbeat")?;
            return Ok(None);
        }
        let now = Utc::now();
        db_query("UPDATE devices SET status = 'ready', last_seen_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(node_id.0.to_string())
            .execute(&mut *transaction)
            .await
            .context("record heartbeat")?;
        let event = if status == "ready" {
            None
        } else {
            Some(
                insert_event(
                    &mut transaction,
                    "device.recovered",
                    serde_json::json!({"node_id": node_id, "status": "ready"}),
                )
                .await?,
            )
        };
        transaction.commit().await.context("commit heartbeat")?;
        Ok(event)
    }

    /// Applies the 15-second suspect and 30-second offline thresholds to non-local nodes.
    pub async fn reconcile_liveness(&self, now: DateTime<Utc>) -> Result<Vec<ClusterEvent>> {
        let rows = db_query(
            "SELECT id, status, last_seen_at FROM devices WHERE is_local = 0 AND status NOT IN ('revoked', 'joining', 'draining')",
        )
        .fetch_all(&self.pool)
        .await
        .context("load liveness candidates")?;
        let mut events = Vec::new();
        let mut transaction = self.pool.begin().await.context("begin liveness update")?;
        for row in rows {
            let id: String = row.try_get("id").context("read liveness node ID")?;
            let current: String = row.try_get("status").context("read liveness status")?;
            let last_seen: String = row
                .try_get("last_seen_at")
                .context("read liveness timestamp")?;
            let observed = DateTime::parse_from_rfc3339(&last_seen)
                .context("parse liveness timestamp")?
                .with_timezone(&Utc);
            let age = now.signed_duration_since(observed).num_seconds();
            let desired = if age >= 30 {
                "offline"
            } else if age >= 15 {
                "suspect"
            } else {
                "ready"
            };
            if desired == current {
                continue;
            }
            let node_id = NodeId(Uuid::parse_str(&id).context("parse liveness node ID")?);
            db_query("UPDATE devices SET status=? WHERE id=?")
                .bind(desired)
                .bind(node_id.0.to_string())
                .execute(&mut *transaction)
                .await
                .context("update liveness status")?;
            events.push(
                insert_event(
                    &mut transaction,
                    "device.status_changed",
                    serde_json::json!({"node_id": node_id, "status": str_to_status(desired)}),
                )
                .await?,
            );
        }
        transaction
            .commit()
            .await
            .context("commit liveness update")?;
        Ok(events)
    }

    /// Revokes all membership credentials and prevents the device from receiving new work.
    pub async fn revoke_node(&self, node_id: NodeId) -> Result<Option<ClusterEvent>> {
        let mut transaction = self.pool.begin().await.context("begin node revocation")?;
        let now = Utc::now();
        let result = db_query(
            "UPDATE devices SET status='revoked', last_seen_at=? WHERE id=? AND is_local=0",
        )
        .bind(now.to_rfc3339())
        .bind(node_id.0.to_string())
        .execute(&mut *transaction)
        .await
        .context("revoke node")?;
        if result.rows_affected() == 0 {
            transaction
                .rollback()
                .await
                .context("rollback missing revocation")?;
            return Ok(None);
        }
        db_query("UPDATE membership_credentials SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL")
            .bind(now.to_rfc3339())
            .bind(node_id.0.to_string())
            .execute(&mut *transaction)
            .await
            .context("revoke membership credentials")?;
        db_query(
            "UPDATE device_certificates SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL",
        )
        .bind(now.to_rfc3339())
        .bind(node_id.0.to_string())
        .execute(&mut *transaction)
        .await
        .context("revoke device certificates")?;
        let event = insert_event(
            &mut transaction,
            "device.revoked",
            serde_json::json!({"node_id": node_id}),
        )
        .await?;
        db_query(
            "INSERT INTO audits (principal_id, action, target_type, target_id, metadata_json, created_at) VALUES ('local-owner', 'device.revoke', 'device', ?, '{}', ?)",
        )
        .bind(node_id.0.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("audit node revocation")?;
        transaction
            .commit()
            .await
            .context("commit node revocation")?;
        Ok(Some(event))
    }

    /// Checks that a signed credential is known and has not been revoked.
    pub async fn credential_active(&self, serial: Uuid, device_id: Uuid) -> Result<bool> {
        let count: i64 = db_query_scalar(
            "SELECT COUNT(*) FROM membership_credentials WHERE serial=? AND device_id=? AND revoked_at IS NULL",
        )
        .bind(serial.to_string())
        .bind(device_id.to_string())
        .fetch_one(&self.pool)
        .await
        .context("check membership credential")?;
        Ok(count == 1)
    }

    /// Returns locally owned resource policies by node.
    pub async fn resource_policies(&self) -> Result<HashMap<NodeId, NodeResourcePolicy>> {
        let rows = db_query("SELECT node_id, policy_json FROM node_resource_policies")
            .fetch_all(&self.pool)
            .await
            .context("list resource policies")?;
        let mut policies = HashMap::with_capacity(rows.len());
        for row in rows {
            let node_id: String = row.try_get("node_id").context("read policy node ID")?;
            let policy: String = row.try_get("policy_json").context("read policy JSON")?;
            policies.insert(
                NodeId(Uuid::parse_str(&node_id).context("parse policy node ID")?),
                serde_json::from_str(&policy).context("decode resource policy")?,
            );
        }
        Ok(policies)
    }

    /// Returns a node policy or secure defaults when the owner has not customized it.
    pub async fn resource_policy(&self, node_id: NodeId) -> Result<Option<NodeResourcePolicy>> {
        let exists: i64 = db_query_scalar("SELECT COUNT(*) FROM devices WHERE id=?")
            .bind(node_id.0.to_string())
            .fetch_one(&self.pool)
            .await
            .context("check policy node")?;
        if exists == 0 {
            return Ok(None);
        }
        Ok(Some(
            self.resource_policies()
                .await?
                .remove(&node_id)
                .unwrap_or_default(),
        ))
    }

    /// Stores a validated resource policy and audits its actor without content.
    pub async fn put_resource_policy(
        &self,
        node_id: NodeId,
        policy: &NodeResourcePolicy,
        actor: &str,
    ) -> Result<Option<ClusterEvent>> {
        let mut transaction = self.pool.begin().await.context("begin policy update")?;
        let exists: i64 = db_query_scalar("SELECT COUNT(*) FROM devices WHERE id=?")
            .bind(node_id.0.to_string())
            .fetch_one(&mut *transaction)
            .await
            .context("check resource policy node")?;
        if exists == 0 {
            transaction
                .rollback()
                .await
                .context("rollback missing policy node")?;
            return Ok(None);
        }
        let now = Utc::now();
        let encoded = serde_json::to_string(policy).context("encode resource policy")?;
        db_query(
            "INSERT INTO node_resource_policies (node_id, policy_json, updated_by, updated_at) VALUES (?, ?, ?, ?) \
             ON CONFLICT(node_id) DO UPDATE SET policy_json=excluded.policy_json, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
        )
        .bind(node_id.0.to_string())
        .bind(encoded)
        .bind(actor)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store resource policy")?;
        let event = insert_event(
            &mut transaction,
            "device.policy_updated",
            serde_json::json!({"node_id": node_id, "updated_by": actor}),
        )
        .await?;
        db_query(
            "INSERT INTO audits (principal_id, action, target_type, target_id, metadata_json, created_at) VALUES (?, 'device.policy_update', 'device', ?, '{}', ?)",
        )
        .bind(actor)
        .bind(node_id.0.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("audit resource policy")?;
        transaction.commit().await.context("commit policy update")?;
        Ok(Some(event))
    }

    /// Persists a redacted, signed peer-transfer authorization for audit and expiry cleanup.
    pub async fn put_transfer_ticket(&self, ticket: &PeerTransferTicket) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin transfer ticket")?;
        db_query(
            "INSERT INTO model_transfer_tickets (id, source_node_id, destination_node_id, model_sha256, chunk_sha256, ticket_json, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(ticket.id.to_string())
        .bind(ticket.source_node.to_string())
        .bind(ticket.destination_node.to_string())
        .bind(&ticket.model_sha256)
        .bind(&ticket.chunk_sha256)
        .bind(serde_json::to_string(ticket).context("encode transfer ticket")?)
        .bind(ticket.expires_at.to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store transfer ticket")?;
        let event = insert_event(
            &mut transaction,
            "model.transfer_authorized",
            serde_json::json!({
                "ticket_id": ticket.id,
                "source_node": ticket.source_node,
                "destination_node": ticket.destination_node,
                "model_sha256": ticket.model_sha256,
                "chunk_sha256": ticket.chunk_sha256,
                "expires_at": ticket.expires_at,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit transfer ticket")?;
        Ok(event)
    }

    /// Loads the cluster network policy, defaulting to local-only with zero remote quota.
    pub async fn network_policy(&self) -> Result<NetworkPolicy> {
        let encoded: Option<String> =
            db_query_scalar("SELECT value_json FROM settings WHERE key='network.policy.v1'")
                .fetch_optional(&self.pool)
                .await
                .context("load network policy")?;
        encoded.map_or_else(
            || Ok(NetworkPolicy::default()),
            |value| serde_json::from_str(&value).context("decode network policy"),
        )
    }

    /// Persists network opt-ins and audits the change without storing traffic content.
    pub async fn put_network_policy(&self, policy: &NetworkPolicy) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin network policy")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO settings (key, value_json, updated_at) VALUES ('network.policy.v1', ?, ?) \
             ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
        )
        .bind(serde_json::to_string(policy).context("encode network policy")?)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store network policy")?;
        let event = insert_event(
            &mut transaction,
            "network.policy_updated",
            serde_json::json!({
                "remote_enabled": policy.remote_enabled,
                "managed_relay_enabled": policy.managed_relay_enabled,
                "self_hosted_relay_configured": policy.self_hosted_relay.is_some(),
                "monthly_remote_byte_quota": policy.monthly_remote_byte_quota,
            }),
        )
        .await?;
        db_query(
            "INSERT INTO audits (principal_id, action, target_type, target_id, metadata_json, created_at) VALUES ('local-owner', 'network.policy_update', 'cluster', NULL, '{}', ?)",
        )
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("audit network policy")?;
        transaction
            .commit()
            .await
            .context("commit network policy")?;
        Ok(event)
    }

    /// Loads observed remote bytes for the current UTC month.
    pub async fn network_usage(&self, cluster_id: Uuid, now: DateTime<Utc>) -> Result<u64> {
        let value: Option<i64> = db_query_scalar(
            "SELECT observed_bytes FROM network_usage WHERE cluster_id=? AND utc_year=? AND utc_month=?",
        )
        .bind(cluster_id.to_string())
        .bind(now.year())
        .bind(i64::from(now.month()))
        .fetch_optional(&self.pool)
        .await
        .context("load monthly network usage")?;
        value.map_or(Ok(0), |bytes| {
            u64::try_from(bytes).context("network usage is outside the supported range")
        })
    }

    /// Returns workers that polled recently enough to accept a new lease.
    pub async fn available_workers(&self, now: DateTime<Utc>) -> Result<Vec<NodeId>> {
        let cutoff = (now - chrono::Duration::seconds(15)).to_rfc3339();
        let ids: Vec<String> = db_query_scalar(
            "SELECT s.node_id FROM worker_sessions s JOIN devices d ON d.id=s.node_id WHERE s.last_poll_at>=? AND d.status='ready' ORDER BY s.node_id",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .context("list available workers")?;
        ids.into_iter()
            .map(|id| {
                Uuid::parse_str(&id)
                    .map(NodeId)
                    .context("parse available worker ID")
            })
            .collect()
    }

    /// Adds one encrypted request to the bounded durable worker queue.
    #[allow(clippy::too_many_arguments)] // Mirrors the normalized encrypted lease record.
    pub async fn create_worker_lease(
        &self,
        id: Uuid,
        workload_id: WorkloadId,
        node_id: NodeId,
        envelope_version: u8,
        nonce: &[u8],
        ciphertext: &[u8],
        maximum_output_tokens: u32,
    ) -> Result<(Uuid, ClusterEvent)> {
        let mut transaction = self.pool.begin().await.context("begin worker lease")?;
        let pending: i64 = db_query_scalar(
            "SELECT COUNT(*) FROM workload_leases WHERE status IN ('pending', 'leased')",
        )
        .fetch_one(&mut *transaction)
        .await
        .context("count pending worker leases")?;
        if pending >= 1_000 {
            transaction
                .rollback()
                .await
                .context("rollback full worker queue")?;
            anyhow::bail!("worker queue is at its 1000-workload safety limit");
        }
        let now = Utc::now();
        db_query(
            "INSERT INTO workload_leases (id, workload_id, node_id, attempt, status, envelope_version, input_nonce, input_ciphertext, maximum_output_tokens, created_at, updated_at) VALUES (?, ?, ?, 1, 'pending', ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(workload_id.0.to_string())
        .bind(node_id.0.to_string())
        .bind(i64::from(envelope_version))
        .bind(nonce)
        .bind(ciphertext)
        .bind(i64::from(maximum_output_tokens))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store encrypted worker lease")?;
        let event = insert_event(
            &mut transaction,
            "workload.queued",
            serde_json::json!({"workload_id": workload_id, "lease_id": id, "node_id": node_id}),
        )
        .await?;
        transaction.commit().await.context("commit worker lease")?;
        Ok((id, event))
    }

    /// Marks a worker available and claims its oldest pending or expired pre-output lease.
    pub async fn claim_worker_lease(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
    ) -> Result<Option<LeasedWorkRecord>> {
        let mut transaction = self.pool.begin().await.context("begin worker poll")?;
        db_query(
            "INSERT INTO worker_sessions (node_id, last_poll_at) VALUES (?, ?) ON CONFLICT(node_id) DO UPDATE SET last_poll_at=excluded.last_poll_at",
        )
        .bind(node_id.0.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("record worker poll")?;
        db_query(
            "UPDATE devices SET last_seen_at=?, status=CASE WHEN status IN ('suspect', 'offline') THEN 'ready' ELSE status END WHERE id=? AND status!='revoked'",
        )
        .bind(now.to_rfc3339())
        .bind(node_id.0.to_string())
        .execute(&mut *transaction)
        .await
        .context("heartbeat polling worker")?;
        let row = db_query(
            "SELECT l.id, l.workload_id, l.node_id, l.attempt, l.envelope_version, l.input_nonce, l.input_ciphertext, l.maximum_output_tokens, w.model, p.plan_json \
             FROM workload_leases l JOIN workloads w ON w.id=l.workload_id JOIN execution_plans p ON p.workload_id=l.workload_id \
             WHERE l.node_id=? AND l.status='pending' ORDER BY l.created_at, l.id LIMIT 1",
        )
        .bind(node_id.0.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .context("find pending worker lease")?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .context("commit empty worker poll")?;
            return Ok(None);
        };
        let id_text: String = row.try_get("id").context("read lease ID")?;
        let lease_id = Uuid::parse_str(&id_text).context("parse lease ID")?;
        let expires_at = now + chrono::Duration::seconds(30);
        let claimed = db_query(
            "UPDATE workload_leases SET status='leased', lease_expires_at=?, updated_at=? WHERE id=? AND status='pending'",
        )
        .bind(expires_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(&id_text)
        .execute(&mut *transaction)
        .await
        .context("claim worker lease")?;
        if claimed.rows_affected() != 1 {
            transaction
                .commit()
                .await
                .context("commit lost lease race")?;
            return Ok(None);
        }
        let workload_id: String = row.try_get("workload_id").context("read workload ID")?;
        let attempt: i64 = row.try_get("attempt").context("read lease attempt")?;
        let envelope_version: i64 = row
            .try_get("envelope_version")
            .context("read lease envelope version")?;
        let maximum_output_tokens: i64 = row
            .try_get("maximum_output_tokens")
            .context("read maximum output tokens")?;
        let plan_json: String = row.try_get("plan_json").context("read lease plan")?;
        let record = LeasedWorkRecord {
            id: lease_id,
            workload_id: WorkloadId(Uuid::parse_str(&workload_id).context("parse workload ID")?),
            node_id,
            attempt: u8::try_from(attempt).context("parse lease attempt")?,
            model: row.try_get("model").context("read lease model")?,
            envelope_version: u8::try_from(envelope_version)
                .context("parse lease envelope version")?,
            nonce: row.try_get("input_nonce").context("read lease nonce")?,
            ciphertext: row
                .try_get("input_ciphertext")
                .context("read encrypted lease input")?,
            maximum_output_tokens: u32::try_from(maximum_output_tokens)
                .context("parse maximum output tokens")?,
            plan: serde_json::from_str(&plan_json).context("decode lease plan")?,
            expires_at,
        };
        transaction.commit().await.context("commit worker claim")?;
        Ok(Some(record))
    }

    /// Accepts one strictly ordered worker event and persists only content-free state.
    pub async fn accept_worker_event(
        &self,
        node_id: NodeId,
        lease_id: Uuid,
        sequence: u64,
        event: &WorkerRuntimeEvent,
    ) -> Result<Option<ClusterEvent>> {
        let sequence = i64::try_from(sequence).context("worker sequence is too large")?;
        let (status, event_type) = match event {
            WorkerRuntimeEvent::Finished { .. } => (Some("completed"), "workload.completed"),
            WorkerRuntimeEvent::Failure { .. } => (Some("interrupted"), "workload.interrupted"),
            WorkerRuntimeEvent::Cancelled => (Some("cancelled"), "workload.cancelled"),
            WorkerRuntimeEvent::TextDelta { .. } => (None, "workload.output_started"),
            WorkerRuntimeEvent::Loading { .. } | WorkerRuntimeEvent::Prefill { .. } => {
                (None, "workload.progress")
            }
        };
        let mut transaction = self.pool.begin().await.context("begin worker event")?;
        let result = db_query(
            "UPDATE workload_leases SET last_sequence=?, output_started=CASE WHEN ? THEN 1 ELSE output_started END, status=COALESCE(?, status), lease_expires_at=?, updated_at=? WHERE id=? AND node_id=? AND status='leased' AND last_sequence<?",
        )
        .bind(sequence)
        .bind(event.starts_output())
        .bind(status)
        .bind((Utc::now() + chrono::Duration::seconds(30)).to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .bind(lease_id.to_string())
        .bind(node_id.0.to_string())
        .bind(sequence)
        .execute(&mut *transaction)
        .await
        .context("advance worker lease event")?;
        if result.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback stale worker event")?;
            return Ok(None);
        }
        let workload_id: String =
            db_query_scalar("SELECT workload_id FROM workload_leases WHERE id=?")
                .bind(lease_id.to_string())
                .fetch_one(&mut *transaction)
                .await
                .context("load event workload")?;
        if let Some(status) = status {
            db_query("UPDATE workloads SET status=?, completed_at=? WHERE id=?")
                .bind(status)
                .bind(Utc::now().to_rfc3339())
                .bind(&workload_id)
                .execute(&mut *transaction)
                .await
                .context("finish remote workload")?;
        }
        let cluster_event = insert_event(
            &mut transaction,
            event_type,
            serde_json::json!({
                "workload_id": workload_id,
                "lease_id": lease_id,
                "node_id": node_id,
                "sequence": sequence,
            }),
        )
        .await?;
        transaction.commit().await.context("commit worker event")?;
        Ok(Some(cluster_event))
    }

    /// Requeues one pre-output failure once, then interrupts expired leases deterministically.
    pub async fn reconcile_worker_leases(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<ExpiredLeaseAction>> {
        let rows = db_query(
            "SELECT id, workload_id, attempt, output_started FROM workload_leases \
             WHERE lease_expires_at<=? AND (status='leased' OR (status='pending' AND attempt=2)) \
             ORDER BY created_at, id",
        )
        .bind(now.to_rfc3339())
        .fetch_all(&self.pool)
        .await
        .context("list expired worker leases")?;
        let mut actions = Vec::with_capacity(rows.len());
        for row in rows {
            let lease_id_text: String = row.try_get("id").context("read expired lease ID")?;
            let workload_id_text: String = row
                .try_get("workload_id")
                .context("read expired workload ID")?;
            let lease_id = Uuid::parse_str(&lease_id_text).context("parse expired lease ID")?;
            let workload_id = WorkloadId(
                Uuid::parse_str(&workload_id_text).context("parse expired workload ID")?,
            );
            let attempt: i64 = row.try_get("attempt").context("read expired attempt")?;
            let output_started = row
                .try_get::<i64, _>("output_started")
                .context("read expired output state")?
                != 0;
            let retried = !output_started && attempt < 2;
            let mut transaction = self.pool.begin().await.context("begin lease recovery")?;
            let result = if retried {
                db_query(
                    "UPDATE workload_leases SET status='pending', attempt=attempt+1, last_sequence=0, lease_expires_at=?, updated_at=? WHERE id=? AND status='leased' AND lease_expires_at<=?",
                )
                .bind((now + chrono::Duration::seconds(30)).to_rfc3339())
                .bind(now.to_rfc3339())
                .bind(&lease_id_text)
                .bind(now.to_rfc3339())
                .execute(&mut *transaction)
                .await
                .context("requeue expired worker lease")?
            } else {
                db_query(
                    "UPDATE workload_leases SET status='interrupted', updated_at=? WHERE id=? AND status IN ('leased', 'pending') AND lease_expires_at<=?",
                )
                .bind(now.to_rfc3339())
                .bind(&lease_id_text)
                .bind(now.to_rfc3339())
                .execute(&mut *transaction)
                .await
                .context("interrupt expired worker lease")?
            };
            if result.rows_affected() != 1 {
                transaction
                    .rollback()
                    .await
                    .context("rollback recovered race")?;
                continue;
            }
            if !retried {
                db_query("UPDATE workloads SET status='interrupted', completed_at=? WHERE id=?")
                    .bind(now.to_rfc3339())
                    .bind(&workload_id_text)
                    .execute(&mut *transaction)
                    .await
                    .context("interrupt expired workload")?;
            }
            let event = insert_event(
                &mut transaction,
                if retried {
                    "workload.retry_queued"
                } else {
                    "workload.interrupted"
                },
                serde_json::json!({
                    "workload_id": workload_id,
                    "lease_id": lease_id,
                    "attempt": attempt,
                    "output_started": output_started,
                }),
            )
            .await?;
            transaction
                .commit()
                .await
                .context("commit lease recovery")?;
            actions.push(ExpiredLeaseAction {
                lease_id,
                retried,
                output_started,
                event,
            });
        }
        Ok(actions)
    }

    /// Atomically records privacy-safe observed transport accounting and returns its event.
    pub async fn record_network_usage(
        &self,
        cluster_id: Uuid,
        decision: &TransportDecision,
        observed_bytes: u64,
        now: DateTime<Utc>,
    ) -> Result<ClusterEvent> {
        let observed = i64::try_from(observed_bytes).context("observed byte count is too large")?;
        let estimated = i64::try_from(decision.candidate.estimated_bytes)
            .context("estimated byte count is too large")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin network accounting")?;
        db_query(
            "INSERT INTO network_usage (cluster_id, utc_year, utc_month, observed_bytes, updated_at) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(cluster_id, utc_year, utc_month) DO UPDATE SET observed_bytes=network_usage.observed_bytes + excluded.observed_bytes, updated_at=excluded.updated_at",
        )
        .bind(cluster_id.to_string())
        .bind(now.year())
        .bind(i64::from(now.month()))
        .bind(observed)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("record monthly network usage")?;
        let transport = serde_json::to_value(decision.candidate.kind)
            .context("encode transport kind")?
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        db_query(
            "INSERT INTO network_transport_records (id, cluster_id, transport_kind, remote, uses_relay, estimated_bytes, observed_bytes, created_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(cluster_id.to_string())
        .bind(&transport)
        .bind(decision.privacy.uses_relay)
        .bind(estimated)
        .bind(observed)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("record transport privacy summary")?;
        let event = insert_event(
            &mut transaction,
            "network.bytes_observed",
            serde_json::json!({
                "transport": transport,
                "uses_relay": decision.privacy.uses_relay,
                "estimated_bytes": decision.candidate.estimated_bytes,
                "observed_bytes": observed_bytes,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit network accounting")?;
        Ok(event)
    }

    /// Persists a redacted enrollment invitation and emits a content-free event.
    pub async fn put_invitation_status(
        &self,
        status: &InvitationStatus,
        requested_node_id: Option<NodeId>,
        event_type: &str,
    ) -> Result<ClusterEvent> {
        let now = Utc::now();
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin invitation transaction")?;
        db_query(
            "INSERT INTO enrollment_invitations (id, expires_at, failed_attempts, consumed, approved, approved_at, requested_node_id, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET failed_attempts=excluded.failed_attempts, consumed=excluded.consumed, \
             approved=excluded.approved, approved_at=excluded.approved_at, requested_node_id=COALESCE(excluded.requested_node_id, enrollment_invitations.requested_node_id), updated_at=excluded.updated_at",
        )
        .bind(status.id.to_string())
        .bind(status.expires_at.to_rfc3339())
        .bind(i64::from(status.failed_attempts))
        .bind(i64::from(status.consumed))
        .bind(i64::from(status.approved))
        .bind(status.approved_at.map(|value| value.to_rfc3339()))
        .bind(requested_node_id.map(|value| value.0.to_string()))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store invitation status")?;
        let event = insert_event(
            &mut transaction,
            event_type,
            serde_json::json!({
                "invitation_id": status.id,
                "expires_at": status.expires_at,
                "failed_attempts": status.failed_attempts,
                "consumed": status.consumed,
                "approved": status.approved,
                "node_id": requested_node_id,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit invitation status")?;
        Ok(event)
    }

    /// Lists redacted enrollment records without secret material.
    pub async fn invitation_statuses(&self) -> Result<Vec<InvitationStatus>> {
        let rows = db_query(
            "SELECT id, expires_at, failed_attempts, consumed, approved, approved_at FROM enrollment_invitations ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("list invitation statuses")?;
        rows.iter().map(decode_invitation_status).collect()
    }

    /// Atomically registers an approved node, stores its credential, and audits approval.
    pub async fn approve_enrollment(
        &self,
        node: &Node,
        credential: &MembershipCredential,
        certificate: &DeviceCertificate,
        status: &InvitationStatus,
    ) -> Result<ClusterEvent> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin enrollment approval")?;
        let capabilities =
            serde_json::to_string(&node.capabilities).context("serialize enrolled capabilities")?;
        db_query(
            "INSERT INTO devices (id, name, os, architecture, status, capabilities_json, last_seen_at, is_local) \
             VALUES (?, ?, ?, ?, 'ready', ?, ?, 0) \
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, os=excluded.os, architecture=excluded.architecture, \
             status='ready', capabilities_json=excluded.capabilities_json, last_seen_at=excluded.last_seen_at",
        )
        .bind(node.id.0.to_string())
        .bind(&node.name)
        .bind(os_to_str(node.os))
        .bind(&node.architecture)
        .bind(capabilities)
        .bind(node.last_seen_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("register approved node")?;
        db_query(
            "INSERT INTO membership_credentials (serial, device_id, device_public_key, roles_json, issued_at, expires_at, protocol_min, protocol_max, signature) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(serial) DO NOTHING",
        )
        .bind(credential.serial.to_string())
        .bind(credential.device_id.to_string())
        .bind(credential.device_public_key.as_slice())
        .bind(serde_json::to_string(&credential.roles).context("serialize membership roles")?)
        .bind(credential.issued_at.to_rfc3339())
        .bind(credential.expires_at.to_rfc3339())
        .bind(i64::from(credential.protocol_min))
        .bind(i64::from(credential.protocol_max))
        .bind(&credential.signature)
        .execute(&mut *transaction)
        .await
        .context("store membership credential")?;
        db_query(
            "INSERT INTO device_certificates (credential_serial, device_id, certificate_pem, issued_at, expires_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(credential_serial) DO NOTHING",
        )
        .bind(credential.serial.to_string())
        .bind(credential.device_id.to_string())
        .bind(&certificate.certificate_pem)
        .bind(certificate.issued_at.to_rfc3339())
        .bind(certificate.expires_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store device certificate")?;
        db_query(
            "UPDATE enrollment_invitations SET approved=1, approved_at=?, updated_at=? WHERE id=?",
        )
        .bind(status.approved_at.map(|value| value.to_rfc3339()))
        .bind(Utc::now().to_rfc3339())
        .bind(status.id.to_string())
        .execute(&mut *transaction)
        .await
        .context("mark invitation approved")?;
        let event = insert_event(
            &mut transaction,
            "enrollment.approved",
            serde_json::json!({
                "invitation_id": status.id,
                "node_id": node.id,
                "credential_expires_at": credential.expires_at,
            }),
        )
        .await?;
        db_query(
            "INSERT INTO audits (principal_id, action, target_type, target_id, metadata_json, created_at) VALUES ('local-owner', 'enrollment.approve', 'device', ?, ?, ?)",
        )
        .bind(node.id.0.to_string())
        .bind(serde_json::json!({"invitation_id": status.id, "credential_serial": credential.serial}).to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("audit enrollment approval")?;
        transaction
            .commit()
            .await
            .context("commit enrollment approval")?;
        Ok(event)
    }

    /// Persists one 24-hour membership and client-certificate rotation for an existing node.
    pub async fn put_rotated_credential(
        &self,
        credential: &MembershipCredential,
        certificate: &DeviceCertificate,
    ) -> Result<ClusterEvent> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin credential rotation")?;
        db_query(
            "INSERT INTO membership_credentials (serial, device_id, device_public_key, roles_json, issued_at, expires_at, protocol_min, protocol_max, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(credential.serial.to_string())
        .bind(credential.device_id.to_string())
        .bind(credential.device_public_key.as_slice())
        .bind(serde_json::to_string(&credential.roles).context("serialize membership roles")?)
        .bind(credential.issued_at.to_rfc3339())
        .bind(credential.expires_at.to_rfc3339())
        .bind(i64::from(credential.protocol_min))
        .bind(i64::from(credential.protocol_max))
        .bind(&credential.signature)
        .execute(&mut *transaction)
        .await
        .context("store rotated membership")?;
        db_query(
            "INSERT INTO device_certificates (credential_serial, device_id, certificate_pem, issued_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(credential.serial.to_string())
        .bind(credential.device_id.to_string())
        .bind(&certificate.certificate_pem)
        .bind(certificate.issued_at.to_rfc3339())
        .bind(certificate.expires_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store rotated device certificate")?;
        let event = insert_event(
            &mut transaction,
            "device.credentials_rotated",
            serde_json::json!({
                "node_id": credential.device_id,
                "credential_serial": credential.serial,
                "expires_at": credential.expires_at,
            }),
        )
        .await?;
        db_query(
            "INSERT INTO audits (principal_id, action, target_type, target_id, metadata_json, created_at) VALUES (?, 'device.credentials_rotate', 'device', ?, ?, ?)",
        )
        .bind(credential.device_id.to_string())
        .bind(credential.device_id.to_string())
        .bind(serde_json::json!({"credential_serial": credential.serial}).to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("audit credential rotation")?;
        transaction
            .commit()
            .await
            .context("commit credential rotation")?;
        Ok(event)
    }

    /// Stores the latest benchmark for a node.
    pub async fn put_benchmark(&self, report: &BenchmarkReport) -> Result<ClusterEvent> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin benchmark transaction")?;
        let encoded = serde_json::to_string(report).context("serialize benchmark")?;
        db_query(
            "INSERT INTO benchmarks (node_id, report_json, measured_at) VALUES (?, ?, ?) \
             ON CONFLICT(node_id) DO UPDATE SET report_json=excluded.report_json, measured_at=excluded.measured_at",
        )
        .bind(report.node_id.0.to_string())
        .bind(encoded)
        .bind(report.measured_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store benchmark")?;
        let event = insert_event(
            &mut transaction,
            "benchmark.completed",
            serde_json::json!({
                "node_id": report.node_id,
                "tokens_per_second": report.tokens_per_second,
                "time_to_first_token_ms": report.time_to_first_token_ms,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit benchmark transaction")?;
        Ok(event)
    }

    /// Returns the latest benchmark by node.
    pub async fn benchmarks(&self) -> Result<HashMap<NodeId, BenchmarkReport>> {
        let rows = db_query("SELECT report_json FROM benchmarks ORDER BY measured_at DESC")
            .fetch_all(&self.pool)
            .await
            .context("list benchmarks")?;
        let mut reports = HashMap::with_capacity(rows.len());
        for row in rows {
            let encoded: String = row.try_get("report_json").context("read benchmark JSON")?;
            let report: BenchmarkReport =
                serde_json::from_str(&encoded).context("decode benchmark JSON")?;
            reports.insert(report.node_id, report);
        }
        Ok(reports)
    }

    /// Stores a workload and immutable execution plan transactionally.
    pub async fn create_workload(
        &self,
        workload: &WorkloadRequest,
        plan: &ExecutionPlan,
    ) -> Result<ClusterEvent> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin workload transaction")?;
        db_query(
            "INSERT INTO workloads (id, model, runtime, class, policy, status, created_at) VALUES (?, ?, ?, ?, ?, 'running', ?)",
        )
        .bind(workload.id.0.to_string())
        .bind(&workload.model)
        .bind(&workload.required_runtime)
        .bind(serde_json::to_string(&workload.class).context("encode workload class")?)
        .bind(serde_json::to_string(&workload.policy).context("encode workload policy")?)
        .bind(plan.created_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("insert workload")?;
        db_query(
            "INSERT INTO execution_plans (id, workload_id, plan_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(plan.id.0.to_string())
        .bind(workload.id.0.to_string())
        .bind(serde_json::to_string(plan).context("encode execution plan")?)
        .bind(plan.created_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("insert execution plan")?;
        let event = insert_event(
            &mut transaction,
            "workload.started",
            serde_json::json!({
                "workload_id": workload.id,
                "plan_id": plan.id,
                "strategy": plan.strategy,
                "selected_nodes": plan.selected_nodes,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workload transaction")?;
        Ok(event)
    }

    /// Marks a workload terminal without storing generated content.
    pub async fn complete_workload(
        &self,
        workload_id: constellation_core::WorkloadId,
        status: &str,
    ) -> Result<Option<ClusterEvent>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin completion transaction")?;
        let updated = db_query(
            "UPDATE workloads SET status = ?, completed_at = ? WHERE id = ? AND status='running'",
        )
        .bind(status)
        .bind(Utc::now().to_rfc3339())
        .bind(workload_id.0.to_string())
        .execute(&mut *transaction)
        .await
        .context("complete workload")?;
        if updated.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback terminal workload completion")?;
            return Ok(None);
        }
        let event = insert_event(
            &mut transaction,
            "workload.completed",
            serde_json::json!({"workload_id": workload_id, "status": status}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit completion transaction")?;
        Ok(Some(event))
    }

    /// Cancels a running workload and any outstanding remote lease atomically.
    pub async fn cancel_workload(
        &self,
        workload_id: WorkloadId,
    ) -> Result<Option<WorkloadCancellation>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin workload cancellation")?;
        let runtime: Option<String> =
            db_query_scalar("SELECT runtime FROM workloads WHERE id=? AND status='running'")
                .bind(workload_id.0.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .context("load cancellable workload")?;
        let Some(runtime) = runtime else {
            transaction
                .rollback()
                .await
                .context("rollback inactive workload cancellation")?;
            return Ok(None);
        };
        let lease_id_text: Option<String> = db_query_scalar(
            "SELECT id FROM workload_leases WHERE workload_id=? AND status IN ('pending', 'leased') ORDER BY created_at DESC LIMIT 1",
        )
        .bind(workload_id.0.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .context("load cancellable worker lease")?;
        db_query("UPDATE workloads SET status='cancelled', completed_at=? WHERE id=?")
            .bind(Utc::now().to_rfc3339())
            .bind(workload_id.0.to_string())
            .execute(&mut *transaction)
            .await
            .context("cancel workload")?;
        if let Some(lease_id) = lease_id_text.as_deref() {
            db_query(
                "UPDATE workload_leases SET status='cancelled', updated_at=? WHERE id=? AND status IN ('pending', 'leased')",
            )
            .bind(Utc::now().to_rfc3339())
            .bind(lease_id)
            .execute(&mut *transaction)
            .await
            .context("cancel worker lease")?;
        }
        let event = insert_event(
            &mut transaction,
            "workload.cancelled",
            serde_json::json!({
                "workload_id": workload_id,
                "remote_lease": lease_id_text.is_some(),
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workload cancellation")?;
        Ok(Some(WorkloadCancellation {
            runtime,
            lease_id: lease_id_text
                .map(|id| Uuid::parse_str(&id).context("parse cancelled lease ID"))
                .transpose()?,
            event,
        }))
    }

    /// Returns a plan by workload ID.
    pub async fn plan_for_workload(
        &self,
        workload_id: constellation_core::WorkloadId,
    ) -> Result<Option<ExecutionPlan>> {
        let row = db_query(
            "SELECT plan_json FROM execution_plans WHERE workload_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(workload_id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load execution plan")?;
        row.map(|value| {
            let encoded: String = value.try_get("plan_json").context("read plan JSON")?;
            serde_json::from_str(&encoded).context("decode plan JSON")
        })
        .transpose()
    }

    /// Persists a content-free predicted-versus-observed calibration record.
    pub async fn put_plan_observation(
        &self,
        workload_id: WorkloadId,
        observation: &PlanObservation,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin plan observation")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO execution_observations (id, plan_id, workload_id, observation_json, observed_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(observation.plan_id.0.to_string())
        .bind(workload_id.0.to_string())
        .bind(serde_json::to_string(observation).context("encode plan observation")?)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store plan observation")?;
        let event = insert_event(
            &mut transaction,
            "plan.observed",
            serde_json::json!({
                "workload_id": workload_id,
                "plan_id": observation.plan_id,
                "materially_missed": observation.materially_missed,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit plan observation")?;
        Ok(event)
    }

    /// Stores one bounded content-free distributed trace span.
    pub async fn put_trace_span(&self, span: &ExecutionTraceSpan) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin trace span")?;
        db_query(
            "INSERT INTO execution_trace_spans (id, workload_id, node_id, parent_span_id, operation, started_at, duration_us, status, attributes_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(span.id.to_string())
        .bind(span.workload_id.0.to_string())
        .bind(span.node_id.0.to_string())
        .bind(span.parent_span_id.map(|id| id.to_string()))
        .bind(&span.operation)
        .bind(span.started_at.to_rfc3339())
        .bind(i64::try_from(span.duration_us).context("trace duration is too large")?)
        .bind(&span.status)
        .bind(serde_json::to_string(&span.attributes).context("encode trace attributes")?)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store trace span")?;
        let event = insert_event(
            &mut transaction,
            "trace.span_recorded",
            serde_json::json!({
                "span_id": span.id,
                "workload_id": span.workload_id,
                "node_id": span.node_id,
                "operation": span.operation,
                "status": span.status,
            }),
        )
        .await?;
        transaction.commit().await.context("commit trace span")?;
        Ok(event)
    }

    /// Returns trace spans in stable causal-time order.
    pub async fn trace_spans(&self, workload_id: WorkloadId) -> Result<Vec<ExecutionTraceSpan>> {
        let rows = db_query(
            "SELECT id, node_id, parent_span_id, operation, started_at, duration_us, status, attributes_json FROM execution_trace_spans WHERE workload_id=? ORDER BY started_at, id LIMIT 10000",
        )
        .bind(workload_id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .context("load trace spans")?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").context("read trace ID")?;
                let node_id: String = row.try_get("node_id").context("read trace node")?;
                let parent: Option<String> =
                    row.try_get("parent_span_id").context("read trace parent")?;
                let started_at: String = row.try_get("started_at").context("read trace start")?;
                let duration_us: i64 = row.try_get("duration_us").context("read trace duration")?;
                let attributes: String = row
                    .try_get("attributes_json")
                    .context("read trace attributes")?;
                Ok(ExecutionTraceSpan {
                    id: Uuid::parse_str(&id).context("parse trace ID")?,
                    workload_id,
                    node_id: NodeId(Uuid::parse_str(&node_id).context("parse trace node")?),
                    parent_span_id: parent
                        .map(|value| Uuid::parse_str(&value).context("parse trace parent"))
                        .transpose()?,
                    operation: row.try_get("operation").context("read trace operation")?,
                    started_at: DateTime::parse_from_rfc3339(&started_at)
                        .context("parse trace start")?
                        .with_timezone(&Utc),
                    duration_us: u64::try_from(duration_us).context("parse trace duration")?,
                    status: row.try_get("status").context("read trace status")?,
                    attributes: serde_json::from_str(&attributes)
                        .context("decode trace attributes")?,
                })
            })
            .collect()
    }

    /// Creates an encrypted workflow and its immutable first revision.
    pub async fn create_workflow(
        &self,
        workflow_id: WorkflowId,
        name: &str,
        sha256: &str,
        content: &EncryptedContent,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow create")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO workflows (id, name, current_revision, current_sha256, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?)",
        )
        .bind(workflow_id.0.to_string())
        .bind(name)
        .bind(sha256)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store workflow metadata")?;
        db_query(
            "INSERT INTO workflow_revisions (workflow_id, revision, definition_sha256, envelope_version, nonce, ciphertext, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)",
        )
        .bind(workflow_id.0.to_string())
        .bind(sha256)
        .bind(i64::from(content.version))
        .bind(&content.nonce)
        .bind(&content.ciphertext)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store encrypted workflow revision")?;
        let event = insert_event(
            &mut transaction,
            "workflow.created",
            serde_json::json!({"workflow_id": workflow_id, "revision": 1, "sha256": sha256}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow create")?;
        Ok(event)
    }

    /// Lists public workflow metadata without decrypting definitions.
    pub async fn workflows(&self) -> Result<Vec<WorkflowSummary>> {
        let rows = db_query(
            "SELECT id, name, current_revision, current_sha256, updated_at FROM workflows ORDER BY name, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("list workflows")?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").context("read workflow ID")?;
                let revision: i64 = row
                    .try_get("current_revision")
                    .context("read workflow revision")?;
                let updated_at: String = row
                    .try_get("updated_at")
                    .context("read workflow update time")?;
                Ok(WorkflowSummary {
                    id: WorkflowId(Uuid::parse_str(&id).context("parse workflow ID")?),
                    name: row.try_get("name").context("read workflow name")?,
                    revision: u32::try_from(revision).context("parse workflow revision")?,
                    sha256: row
                        .try_get("current_sha256")
                        .context("read workflow digest")?,
                    updated_at: DateTime::parse_from_rfc3339(&updated_at)
                        .context("parse workflow update time")?
                        .with_timezone(&Utc),
                })
            })
            .collect()
    }

    /// Loads the encrypted current workflow revision.
    pub async fn workflow_definition(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<EncryptedWorkflowDefinition>> {
        let row = db_query(
            "SELECT r.revision, r.definition_sha256, r.envelope_version, r.nonce, r.ciphertext FROM workflow_revisions r JOIN workflows w ON w.id=r.workflow_id AND w.current_revision=r.revision WHERE r.workflow_id=?",
        )
        .bind(workflow_id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load encrypted workflow definition")?;
        row.map(|row| {
            let revision: i64 = row.try_get("revision").context("read workflow revision")?;
            let version: i64 = row
                .try_get("envelope_version")
                .context("read workflow envelope version")?;
            Ok(EncryptedWorkflowDefinition {
                revision: u32::try_from(revision).context("parse workflow revision")?,
                sha256: row
                    .try_get("definition_sha256")
                    .context("read definition digest")?,
                content: EncryptedContent {
                    version: u8::try_from(version).context("parse workflow envelope version")?,
                    nonce: row.try_get("nonce").context("read workflow nonce")?,
                    ciphertext: row
                        .try_get("ciphertext")
                        .context("read workflow ciphertext")?,
                },
            })
        })
        .transpose()
    }

    /// Persists one encrypted initial run state and a content-free event.
    pub async fn create_workflow_run(
        &self,
        run_id: WorkflowRunId,
        workflow_id: WorkflowId,
        workflow_revision: u32,
        status: &str,
        content: &EncryptedContent,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow run")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO workflow_runs (id, workflow_id, workflow_revision, status, envelope_version, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(run_id.0.to_string())
        .bind(workflow_id.0.to_string())
        .bind(i64::from(workflow_revision))
        .bind(status)
        .bind(i64::from(content.version))
        .bind(&content.nonce)
        .bind(&content.ciphertext)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store encrypted workflow run")?;
        db_query(
            "INSERT INTO workflow_events (run_id, event_type, created_at) VALUES (?, 'run.created', ?)",
        )
        .bind(run_id.0.to_string())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store workflow run event")?;
        let event = insert_event(
            &mut transaction,
            "workflow.run_created",
            serde_json::json!({"workflow_id": workflow_id, "run_id": run_id}),
        )
        .await?;
        transaction.commit().await.context("commit workflow run")?;
        Ok(event)
    }

    /// Loads one encrypted workflow run.
    pub async fn workflow_run(
        &self,
        run_id: WorkflowRunId,
    ) -> Result<Option<EncryptedWorkflowRun>> {
        let row = db_query(
            "SELECT workflow_id, workflow_revision, status, envelope_version, nonce, ciphertext FROM workflow_runs WHERE id=?",
        )
        .bind(run_id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load encrypted workflow run")?;
        row.map(|row| {
            let workflow_id: String = row.try_get("workflow_id").context("read run workflow ID")?;
            let workflow_revision: i64 = row
                .try_get("workflow_revision")
                .context("read run workflow revision")?;
            let envelope_version: i64 = row
                .try_get("envelope_version")
                .context("read run envelope version")?;
            Ok(EncryptedWorkflowRun {
                workflow_id: WorkflowId(
                    Uuid::parse_str(&workflow_id).context("parse run workflow ID")?,
                ),
                workflow_revision: u32::try_from(workflow_revision)
                    .context("parse run workflow revision")?,
                status: row.try_get("status").context("read run status")?,
                content: EncryptedContent {
                    version: u8::try_from(envelope_version)
                        .context("parse run envelope version")?,
                    nonce: row.try_get("nonce").context("read run nonce")?,
                    ciphertext: row.try_get("ciphertext").context("read run ciphertext")?,
                },
            })
        })
        .transpose()
    }

    /// Lists active run identifiers for bounded engine recovery after restart.
    pub async fn active_workflow_runs(&self, limit: u32) -> Result<Vec<WorkflowRunId>> {
        let ids: Vec<String> = db_query_scalar(
            "SELECT id FROM workflow_runs WHERE status IN ('running', 'waiting_approval') ORDER BY created_at, id LIMIT ?",
        )
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .context("list active workflow runs")?;
        ids.into_iter()
            .map(|id| {
                Uuid::parse_str(&id)
                    .map(WorkflowRunId)
                    .context("parse active workflow run ID")
            })
            .collect()
    }

    /// Atomically updates encrypted run state and appends its redacted event.
    #[allow(clippy::too_many_arguments)] // Mirrors the durable event record.
    pub async fn update_workflow_run(
        &self,
        run_id: WorkflowRunId,
        expected_status: &str,
        expected_nonce: &[u8],
        status: &str,
        content: &EncryptedContent,
        event_type: &str,
        step_id: Option<&str>,
        principal_id: Option<&str>,
    ) -> Result<Option<ClusterEvent>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin workflow transition")?;
        let now = Utc::now();
        let changed = db_query(
            "UPDATE workflow_runs SET status=?, envelope_version=?, nonce=?, ciphertext=?, updated_at=? WHERE id=? AND status=? AND nonce=?",
        )
        .bind(status)
        .bind(i64::from(content.version))
        .bind(&content.nonce)
        .bind(&content.ciphertext)
        .bind(now.to_rfc3339())
        .bind(run_id.0.to_string())
        .bind(expected_status)
        .bind(expected_nonce)
        .execute(&mut *transaction)
        .await
        .context("update encrypted workflow run")?;
        if changed.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback workflow race")?;
            return Ok(None);
        }
        db_query(
            "INSERT INTO workflow_events (run_id, event_type, step_id, principal_id, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(run_id.0.to_string())
        .bind(event_type)
        .bind(step_id)
        .bind(principal_id)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("append workflow transition")?;
        let event = insert_event(
            &mut transaction,
            "workflow.run_updated",
            serde_json::json!({
                "run_id": run_id,
                "status": status,
                "event_type": event_type,
                "step_id": step_id,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow transition")?;
        Ok(Some(event))
    }

    /// Stores encrypted artifact bytes and their content-free metadata.
    pub async fn put_workflow_artifact(
        &self,
        metadata: &ArtifactMetadata,
        content: &EncryptedContent,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow artifact")?;
        db_query(
            "INSERT INTO workflow_artifacts (id, run_id, step_id, name, media_type, sha256, size_bytes, envelope_version, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(metadata.id.to_string())
        .bind(metadata.run_id.0.to_string())
        .bind(&metadata.step_id)
        .bind(&metadata.name)
        .bind(&metadata.media_type)
        .bind(&metadata.sha256)
        .bind(i64::try_from(metadata.size_bytes).context("artifact is too large")?)
        .bind(i64::from(content.version))
        .bind(&content.nonce)
        .bind(&content.ciphertext)
        .bind(metadata.created_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store encrypted workflow artifact")?;
        let event = insert_event(
            &mut transaction,
            "workflow.artifact_created",
            serde_json::json!({
                "artifact_id": metadata.id,
                "run_id": metadata.run_id,
                "step_id": metadata.step_id,
                "sha256": metadata.sha256,
                "size_bytes": metadata.size_bytes,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow artifact")?;
        Ok(event)
    }

    /// Loads encrypted artifact bytes by opaque identifier.
    pub async fn workflow_artifact(
        &self,
        artifact_id: Uuid,
    ) -> Result<Option<EncryptedWorkflowArtifact>> {
        let row = db_query(
            "SELECT run_id, step_id, name, media_type, sha256, size_bytes, envelope_version, nonce, ciphertext, created_at FROM workflow_artifacts WHERE id=?",
        )
        .bind(artifact_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load encrypted workflow artifact")?;
        row.map(|row| {
            let run_id: String = row.try_get("run_id").context("read artifact run")?;
            let size_bytes: i64 = row.try_get("size_bytes").context("read artifact size")?;
            let version: i64 = row
                .try_get("envelope_version")
                .context("read artifact envelope version")?;
            let created_at: String = row
                .try_get("created_at")
                .context("read artifact creation time")?;
            Ok(EncryptedWorkflowArtifact {
                metadata: ArtifactMetadata {
                    id: artifact_id,
                    run_id: WorkflowRunId(Uuid::parse_str(&run_id).context("parse artifact run")?),
                    step_id: row.try_get("step_id").context("read artifact step")?,
                    name: row.try_get("name").context("read artifact name")?,
                    media_type: row
                        .try_get("media_type")
                        .context("read artifact media type")?,
                    sha256: row.try_get("sha256").context("read artifact digest")?,
                    size_bytes: u64::try_from(size_bytes).context("parse artifact size")?,
                    storage_key: artifact_id.to_string(),
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .context("parse artifact creation time")?
                        .with_timezone(&Utc),
                },
                content: EncryptedContent {
                    version: u8::try_from(version).context("parse artifact envelope version")?,
                    nonce: row.try_get("nonce").context("read artifact nonce")?,
                    ciphertext: row
                        .try_get("ciphertext")
                        .context("read artifact ciphertext")?,
                },
            })
        })
        .transpose()
    }

    /// Creates or updates a validated workflow schedule.
    pub async fn put_workflow_schedule(
        &self,
        schedule: &WorkflowSchedule,
        next_run_at: DateTime<Utc>,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow schedule")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO workflow_schedules (id, workflow_id, cron_utc, enabled, concurrency_limit, next_run_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET cron_utc=excluded.cron_utc, enabled=excluded.enabled, concurrency_limit=excluded.concurrency_limit, next_run_at=excluded.next_run_at, updated_at=excluded.updated_at",
        )
        .bind(schedule.id.to_string())
        .bind(schedule.workflow_id.0.to_string())
        .bind(&schedule.cron_utc)
        .bind(i64::from(schedule.enabled))
        .bind(i64::from(schedule.concurrency_limit))
        .bind(next_run_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store workflow schedule")?;
        let event = insert_event(
            &mut transaction,
            "workflow.schedule_updated",
            serde_json::json!({
                "schedule_id": schedule.id,
                "workflow_id": schedule.workflow_id,
                "enabled": schedule.enabled,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow schedule")?;
        Ok(event)
    }

    /// Lists enabled schedules whose next occurrence is due.
    pub async fn due_workflow_schedules(
        &self,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<(WorkflowSchedule, DateTime<Utc>)>> {
        let rows = db_query(
            "SELECT id, workflow_id, cron_utc, enabled, concurrency_limit, next_run_at FROM workflow_schedules WHERE enabled=1 AND next_run_at IS NOT NULL AND next_run_at<=? ORDER BY next_run_at, id LIMIT ?",
        )
        .bind(now.to_rfc3339())
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .context("list due workflow schedules")?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").context("read schedule ID")?;
                let workflow_id: String = row
                    .try_get("workflow_id")
                    .context("read scheduled workflow ID")?;
                let concurrency_limit: i64 = row
                    .try_get("concurrency_limit")
                    .context("read schedule concurrency")?;
                let next_run_at: String = row
                    .try_get("next_run_at")
                    .context("read next schedule time")?;
                Ok((
                    WorkflowSchedule {
                        id: Uuid::parse_str(&id).context("parse schedule ID")?,
                        workflow_id: WorkflowId(
                            Uuid::parse_str(&workflow_id).context("parse scheduled workflow ID")?,
                        ),
                        cron_utc: row.try_get("cron_utc").context("read schedule cron")?,
                        enabled: row
                            .try_get::<i64, _>("enabled")
                            .context("read schedule state")?
                            != 0,
                        concurrency_limit: u16::try_from(concurrency_limit)
                            .context("parse schedule concurrency")?,
                    },
                    DateTime::parse_from_rfc3339(&next_run_at)
                        .context("parse next schedule time")?
                        .with_timezone(&Utc),
                ))
            })
            .collect()
    }

    /// Atomically advances a due schedule and persists a recoverable firing.
    pub async fn claim_workflow_schedule(
        &self,
        schedule_id: Uuid,
        due_at: DateTime<Utc>,
        next_run_at: DateTime<Utc>,
        run_id: WorkflowRunId,
    ) -> Result<bool> {
        let mut transaction = self.pool.begin().await.context("begin schedule claim")?;
        let now = Utc::now();
        let changed = db_query(
            "UPDATE workflow_schedules SET next_run_at=?, updated_at=? WHERE id=? AND enabled=1 AND next_run_at=?",
        )
        .bind(next_run_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(schedule_id.to_string())
        .bind(due_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("advance claimed schedule")?;
        if changed.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback schedule race")?;
            return Ok(false);
        }
        db_query(
            "INSERT INTO workflow_schedule_firings (schedule_id, due_at, run_id, status, created_at, updated_at) VALUES (?, ?, ?, 'claimed', ?, ?)",
        )
        .bind(schedule_id.to_string())
        .bind(due_at.to_rfc3339())
        .bind(run_id.0.to_string())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("persist schedule firing")?;
        transaction
            .commit()
            .await
            .context("commit schedule claim")?;
        Ok(true)
    }

    /// Lists unstarted schedule firings so daemon restarts cannot lose an occurrence.
    pub async fn pending_workflow_schedule_firings(
        &self,
        limit: u32,
    ) -> Result<Vec<WorkflowScheduleFiring>> {
        let rows = db_query(
            "SELECT f.schedule_id, f.due_at, f.run_id, s.workflow_id, s.cron_utc, s.enabled, s.concurrency_limit FROM workflow_schedule_firings f JOIN workflow_schedules s ON s.id=f.schedule_id WHERE f.status='claimed' ORDER BY f.due_at, f.schedule_id LIMIT ?",
        )
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await
        .context("list pending schedule firings")?;
        rows.into_iter()
            .map(|row| {
                let schedule_id: String =
                    row.try_get("schedule_id").context("read firing schedule")?;
                let workflow_id: String =
                    row.try_get("workflow_id").context("read firing workflow")?;
                let run_id: String = row.try_get("run_id").context("read firing run")?;
                let due_at: String = row.try_get("due_at").context("read firing time")?;
                let concurrency_limit: i64 = row
                    .try_get("concurrency_limit")
                    .context("read firing concurrency")?;
                Ok(WorkflowScheduleFiring {
                    schedule: WorkflowSchedule {
                        id: Uuid::parse_str(&schedule_id).context("parse firing schedule")?,
                        workflow_id: WorkflowId(
                            Uuid::parse_str(&workflow_id).context("parse firing workflow")?,
                        ),
                        cron_utc: row.try_get("cron_utc").context("read firing cron")?,
                        enabled: row
                            .try_get::<i64, _>("enabled")
                            .context("read firing state")?
                            != 0,
                        concurrency_limit: u16::try_from(concurrency_limit)
                            .context("parse firing concurrency")?,
                    },
                    due_at: DateTime::parse_from_rfc3339(&due_at)
                        .context("parse firing time")?
                        .with_timezone(&Utc),
                    run_id: WorkflowRunId(Uuid::parse_str(&run_id).context("parse firing run")?),
                })
            })
            .collect()
    }

    /// Counts nonterminal runs started by one schedule.
    pub async fn active_schedule_run_count(&self, schedule_id: Uuid) -> Result<u32> {
        let count: i64 = db_query_scalar(
            "SELECT COUNT(*) FROM workflow_schedule_firings f JOIN workflow_runs r ON r.id=f.run_id WHERE f.schedule_id=? AND f.status='started' AND r.status IN ('pending', 'running', 'waiting_approval')",
        )
        .bind(schedule_id.to_string())
        .fetch_one(&self.pool)
        .await
        .context("count active scheduled runs")?;
        u32::try_from(count).context("parse active scheduled run count")
    }

    /// Marks a recoverable firing attached after its run is durably created.
    pub async fn mark_workflow_schedule_started(
        &self,
        schedule_id: Uuid,
        due_at: DateTime<Utc>,
    ) -> Result<()> {
        db_query(
            "UPDATE workflow_schedule_firings SET status='started', updated_at=? WHERE schedule_id=? AND due_at=? AND status='claimed'",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(schedule_id.to_string())
        .bind(due_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .context("mark schedule firing started")?;
        Ok(())
    }

    /// Adds a workflow to the reusable template catalog.
    pub async fn put_workflow_template(
        &self,
        template_id: Uuid,
        name: &str,
        workflow_id: WorkflowId,
        metadata: &serde_json::Value,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow template")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO workflow_templates (id, name, workflow_id, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(template_id.to_string())
        .bind(name)
        .bind(workflow_id.0.to_string())
        .bind(serde_json::to_string(metadata).context("encode template metadata")?)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store workflow template")?;
        let event = insert_event(
            &mut transaction,
            "workflow.template_created",
            serde_json::json!({
                "template_id": template_id,
                "workflow_id": workflow_id,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow template")?;
        Ok(event)
    }

    /// Lists reusable workflow template catalog entries.
    pub async fn workflow_templates(&self) -> Result<Vec<WorkflowTemplateSummary>> {
        let rows = db_query(
            "SELECT id, name, workflow_id, metadata_json, created_at FROM workflow_templates ORDER BY name, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("list workflow templates")?;
        rows.iter().map(decode_workflow_template).collect()
    }

    /// Loads one reusable workflow template catalog entry.
    pub async fn workflow_template(
        &self,
        template_id: Uuid,
    ) -> Result<Option<WorkflowTemplateSummary>> {
        db_query(
            "SELECT id, name, workflow_id, metadata_json, created_at FROM workflow_templates WHERE id=?",
        )
        .bind(template_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load workflow template")?
        .map(|row| decode_workflow_template(&row))
        .transpose()
    }

    /// Stores a webhook trigger secret hash and returns a redacted event.
    pub async fn put_workflow_webhook(
        &self,
        webhook_id: Uuid,
        workflow_id: WorkflowId,
        secret_sha256: &str,
        enabled: bool,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin workflow webhook")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO workflow_webhooks (id, workflow_id, secret_sha256, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET secret_sha256=excluded.secret_sha256, enabled=excluded.enabled, updated_at=excluded.updated_at",
        )
        .bind(webhook_id.to_string())
        .bind(workflow_id.0.to_string())
        .bind(secret_sha256)
        .bind(i64::from(enabled))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store workflow webhook")?;
        let event = insert_event(
            &mut transaction,
            "workflow.webhook_updated",
            serde_json::json!({
                "webhook_id": webhook_id,
                "workflow_id": workflow_id,
                "enabled": enabled,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit workflow webhook")?;
        Ok(event)
    }

    /// Loads webhook authentication data for constant-time verification.
    pub async fn workflow_webhook(
        &self,
        webhook_id: Uuid,
    ) -> Result<Option<(WorkflowId, String, bool)>> {
        let row = db_query(
            "SELECT workflow_id, secret_sha256, enabled FROM workflow_webhooks WHERE id=?",
        )
        .bind(webhook_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load workflow webhook")?;
        row.map(|row| {
            let workflow_id: String = row
                .try_get("workflow_id")
                .context("read webhook workflow")?;
            Ok((
                WorkflowId(Uuid::parse_str(&workflow_id).context("parse webhook workflow ID")?),
                row.try_get("secret_sha256")
                    .context("read webhook secret hash")?,
                row.try_get::<i64, _>("enabled")
                    .context("read webhook enabled")?
                    != 0,
            ))
        })
        .transpose()
    }

    /// Installs or upgrades a validated plugin with execution disabled until grant approval.
    pub async fn put_plugin(
        &self,
        manifest: &PluginManifest,
        component_path: &Path,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin plugin install")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO plugins (id, version, kind, sha256, manifest_json, component_path, enabled, installed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT(id) DO UPDATE SET version=excluded.version, kind=excluded.kind, sha256=excluded.sha256, manifest_json=excluded.manifest_json, component_path=excluded.component_path, enabled=0, updated_at=excluded.updated_at",
        )
        .bind(&manifest.id)
        .bind(manifest.version.to_string())
        .bind(serde_json::to_value(manifest.kind).context("encode plugin kind")?.as_str().unwrap_or("unknown"))
        .bind(&manifest.sha256)
        .bind(serde_json::to_string(manifest).context("encode plugin manifest")?)
        .bind(component_path.to_string_lossy().as_ref())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store plugin")?;
        db_query("DELETE FROM plugin_grants WHERE plugin_id=?")
            .bind(&manifest.id)
            .execute(&mut *transaction)
            .await
            .context("invalidate plugin grants after install")?;
        let event = insert_event(
            &mut transaction,
            "plugin.installed",
            serde_json::json!({
                "plugin_id": manifest.id,
                "version": manifest.version,
                "sha256": manifest.sha256,
                "enabled": false,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit plugin install")?;
        Ok(event)
    }

    /// Lists installed plugin records without component bytes.
    pub async fn plugins(&self) -> Result<Vec<InstalledPluginRecord>> {
        let rows =
            db_query("SELECT manifest_json, component_path, enabled FROM plugins ORDER BY id")
                .fetch_all(&self.pool)
                .await
                .context("list plugins")?;
        rows.iter().map(decode_plugin_record).collect()
    }

    /// Loads one installed plugin record.
    pub async fn plugin(&self, plugin_id: &str) -> Result<Option<InstalledPluginRecord>> {
        let row = db_query("SELECT manifest_json, component_path, enabled FROM plugins WHERE id=?")
            .bind(plugin_id)
            .fetch_optional(&self.pool)
            .await
            .context("load plugin")?;
        row.as_ref().map(decode_plugin_record).transpose()
    }

    /// Approves the exact declared permission subset and enables the plugin.
    pub async fn put_plugin_grant(&self, grant: &PluginGrant) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin plugin grant")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO plugin_grants (plugin_id, component_sha256, grant_json, approved_by, approved_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(plugin_id) DO UPDATE SET component_sha256=excluded.component_sha256, grant_json=excluded.grant_json, approved_by=excluded.approved_by, approved_at=excluded.approved_at",
        )
        .bind(&grant.plugin_id)
        .bind(&grant.component_sha256)
        .bind(serde_json::to_string(grant).context("encode plugin grant")?)
        .bind(&grant.approved_by)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store plugin grant")?;
        let enabled =
            db_query("UPDATE plugins SET enabled=1, updated_at=? WHERE id=? AND sha256=?")
                .bind(now.to_rfc3339())
                .bind(&grant.plugin_id)
                .bind(&grant.component_sha256)
                .execute(&mut *transaction)
                .await
                .context("enable granted plugin")?;
        if enabled.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback stale plugin grant")?;
            anyhow::bail!("plugin grant digest does not match the installed component");
        }
        let event = insert_event(
            &mut transaction,
            "plugin.granted",
            serde_json::json!({
                "plugin_id": grant.plugin_id,
                "component_sha256": grant.component_sha256,
                "permission_count": grant.permissions.len(),
                "approved_by": grant.approved_by,
            }),
        )
        .await?;
        transaction.commit().await.context("commit plugin grant")?;
        Ok(event)
    }

    /// Loads the current exact plugin grant.
    pub async fn plugin_grant(&self, plugin_id: &str) -> Result<Option<PluginGrant>> {
        let value: Option<String> =
            db_query_scalar("SELECT grant_json FROM plugin_grants WHERE plugin_id=?")
                .bind(plugin_id)
                .fetch_optional(&self.pool)
                .await
                .context("load plugin grant")?;
        value
            .map(|encoded| serde_json::from_str(&encoded).context("decode plugin grant"))
            .transpose()
    }

    /// Creates or updates a principal and optional hashed service API key.
    pub async fn put_principal(
        &self,
        principal: &Principal,
        api_key_sha256: Option<&str>,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin principal update")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO principals (id, name, role, scopes_json, api_key_sha256, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, role=excluded.role, scopes_json=excluded.scopes_json, api_key_sha256=COALESCE(excluded.api_key_sha256, principals.api_key_sha256), active=excluded.active, updated_at=excluded.updated_at",
        )
        .bind(principal.id.to_string())
        .bind(&principal.name)
        .bind(role_to_str(principal.role))
        .bind(serde_json::to_string(&principal.scopes).context("encode principal scopes")?)
        .bind(api_key_sha256)
        .bind(i64::from(principal.active))
        .bind(principal.created_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store principal")?;
        let event = insert_event(
            &mut transaction,
            "principal.updated",
            serde_json::json!({
                "principal_id": principal.id,
                "role": principal.role,
                "active": principal.active,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit principal update")?;
        Ok(event)
    }

    /// Lists public principal metadata without API key hashes.
    pub async fn principals(&self) -> Result<Vec<Principal>> {
        let rows = db_query(
            "SELECT id, name, role, scopes_json, active, created_at FROM principals ORDER BY name, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("list principals")?;
        rows.iter().map(decode_principal).collect()
    }

    /// Loads one active human principal by stable identifier.
    pub async fn principal(&self, principal_id: Uuid) -> Result<Option<Principal>> {
        let row = db_query(
            "SELECT id, name, role, scopes_json, active, created_at FROM principals WHERE id=? AND active=1 AND role NOT IN ('node', 'service')",
        )
        .bind(principal_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("load human principal")?;
        row.as_ref().map(decode_principal).transpose()
    }

    /// Resolves an exact, unique human sign-in name.
    pub async fn principal_by_name(&self, name: &str) -> Result<Option<Principal>> {
        let row = db_query(
            "SELECT id, name, role, scopes_json, active, created_at FROM principals WHERE name=? AND active=1 AND role NOT IN ('node', 'service')",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("load human principal by name")?;
        row.as_ref().map(decode_principal).transpose()
    }

    /// Loads every passkey registered to an active human principal.
    pub async fn passkeys_for_principal(&self, principal_id: Uuid) -> Result<Vec<Passkey>> {
        let rows = db_query(
            "SELECT k.passkey_json FROM passkeys k JOIN principals p ON p.id=k.principal_id WHERE k.principal_id=? AND p.active=1 AND p.role NOT IN ('node', 'service') ORDER BY k.created_at",
        )
        .bind(principal_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("load principal passkeys")?;
        rows.into_iter()
            .map(|row| {
                let encoded: String = row.try_get("passkey_json").context("read passkey")?;
                serde_json::from_str(&encoded).context("decode passkey")
            })
            .collect()
    }

    /// Stores a newly verified passkey and rejects reuse by another principal.
    pub async fn put_passkey(
        &self,
        principal_id: Uuid,
        name: &str,
        passkey: &Passkey,
    ) -> Result<ClusterEvent> {
        let encoded = serde_json::to_string(passkey).context("encode passkey")?;
        let credential = serde_json::to_vec(passkey.cred_id()).context("encode credential ID")?;
        let credential_sha256 = format!("{:x}", sha2::Sha256::digest(credential));
        let now = Utc::now();
        let mut transaction = self.pool.begin().await.context("begin passkey create")?;
        db_query(
            "INSERT INTO passkeys (credential_sha256, principal_id, name, passkey_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&credential_sha256)
        .bind(principal_id.to_string())
        .bind(name)
        .bind(encoded)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store passkey")?;
        let event = insert_event(
            &mut transaction,
            "principal.passkey_registered",
            serde_json::json!({"principal_id": principal_id, "name": name}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit passkey create")?;
        Ok(event)
    }

    /// Persists authenticator counter and backup-state changes after successful use.
    pub async fn update_passkey_after_authentication(&self, passkey: &Passkey) -> Result<()> {
        let encoded = serde_json::to_string(passkey).context("encode updated passkey")?;
        let credential = serde_json::to_vec(passkey.cred_id()).context("encode credential ID")?;
        let credential_sha256 = format!("{:x}", sha2::Sha256::digest(credential));
        let now = Utc::now().to_rfc3339();
        let changed = db_query(
            "UPDATE passkeys SET passkey_json=?, last_used_at=?, updated_at=? WHERE credential_sha256=?",
        )
        .bind(encoded)
        .bind(&now)
        .bind(&now)
        .bind(credential_sha256)
        .execute(&self.pool)
        .await
        .context("update authenticated passkey")?;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "authenticated passkey disappeared"
        );
        Ok(())
    }

    /// Creates a hashed, expiring browser session. The bearer token never enters durable state.
    pub async fn put_browser_session(
        &self,
        token_sha256: &str,
        principal_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        db_query(
            "INSERT INTO browser_sessions (token_sha256, principal_id, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(token_sha256)
        .bind(principal_id.to_string())
        .bind(&now)
        .bind(expires_at.to_rfc3339())
        .bind(&now)
        .execute(&self.pool)
        .await
        .context("store browser session")?;
        Ok(())
    }

    /// Authenticates a browser session and returns only an active human principal.
    pub async fn principal_by_session_hash(
        &self,
        token_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Principal>> {
        let row = db_query(
            "SELECT p.id, p.name, p.role, p.scopes_json, p.active, p.created_at FROM browser_sessions s JOIN principals p ON p.id=s.principal_id WHERE s.token_sha256=? AND s.expires_at>? AND p.active=1 AND p.role NOT IN ('node', 'service')",
        )
        .bind(token_sha256)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await
        .context("authenticate browser session")?;
        if row.is_some() {
            db_query("UPDATE browser_sessions SET last_used_at=? WHERE token_sha256=?")
                .bind(now.to_rfc3339())
                .bind(token_sha256)
                .execute(&self.pool)
                .await
                .context("touch browser session")?;
        }
        row.as_ref().map(decode_principal).transpose()
    }

    /// Authenticates an active service identity by its SHA-256 API key hash.
    pub async fn service_principal_by_key_hash(
        &self,
        api_key_sha256: &str,
    ) -> Result<Option<Principal>> {
        let row = db_query(
            "SELECT id, name, role, scopes_json, active, created_at FROM principals WHERE api_key_sha256=? AND role='service' AND active=1",
        )
        .bind(api_key_sha256)
        .fetch_optional(&self.pool)
        .await
        .context("authenticate service principal")?;
        row.as_ref().map(decode_principal).transpose()
    }

    /// Creates a team.
    pub async fn create_team(&self, id: Uuid, name: &str) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin team create")?;
        let now = Utc::now();
        db_query("INSERT INTO teams (id, name, created_at) VALUES (?, ?, ?)")
            .bind(id.to_string())
            .bind(name)
            .bind(now.to_rfc3339())
            .execute(&mut *transaction)
            .await
            .context("store team")?;
        let event = insert_event(
            &mut transaction,
            "team.created",
            serde_json::json!({"team_id": id}),
        )
        .await?;
        transaction.commit().await.context("commit team create")?;
        Ok(event)
    }

    /// Lists teams.
    pub async fn teams(&self) -> Result<Vec<TeamRecord>> {
        let rows = db_query("SELECT id, name, created_at FROM teams ORDER BY name, id")
            .fetch_all(&self.pool)
            .await
            .context("list teams")?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").context("read team ID")?;
                let created_at: String = row.try_get("created_at").context("read team creation")?;
                Ok(TeamRecord {
                    id: Uuid::parse_str(&id).context("parse team ID")?,
                    name: row.try_get("name").context("read team name")?,
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .context("parse team creation")?
                        .with_timezone(&Utc),
                })
            })
            .collect()
    }

    /// Creates or replaces one team membership.
    pub async fn put_team_membership(&self, membership: &TeamMembership) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin team membership")?;
        db_query(
            "INSERT INTO team_memberships (team_id, principal_id, role, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(team_id, principal_id) DO UPDATE SET role=excluded.role",
        )
        .bind(membership.team_id.to_string())
        .bind(membership.principal_id.to_string())
        .bind(role_to_str(membership.role))
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store team membership")?;
        let event = insert_event(
            &mut transaction,
            "team.membership_updated",
            serde_json::json!({
                "team_id": membership.team_id,
                "principal_id": membership.principal_id,
                "role": membership.role,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit team membership")?;
        Ok(event)
    }

    /// Lists memberships for one team.
    pub async fn team_memberships(&self, team_id: Uuid) -> Result<Vec<TeamMembership>> {
        let rows = db_query(
            "SELECT principal_id, role FROM team_memberships WHERE team_id=? ORDER BY principal_id",
        )
        .bind(team_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("list team memberships")?;
        rows.into_iter()
            .map(|row| {
                let principal_id: String = row
                    .try_get("principal_id")
                    .context("read member principal")?;
                let role: String = row.try_get("role").context("read member role")?;
                Ok(TeamMembership {
                    team_id,
                    principal_id: Uuid::parse_str(&principal_id)
                        .context("parse member principal")?,
                    role: str_to_role(&role),
                })
            })
            .collect()
    }

    /// Stores a validated external authentication provider.
    pub async fn put_auth_provider(&self, provider: &AuthProvider) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin auth provider")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO auth_providers (id, provider_json, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET provider_json=excluded.provider_json, enabled=excluded.enabled, updated_at=excluded.updated_at",
        )
        .bind(provider.id.to_string())
        .bind(serde_json::to_string(provider).context("encode auth provider")?)
        .bind(i64::from(provider.enabled))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store auth provider")?;
        let event = insert_event(
            &mut transaction,
            "auth_provider.updated",
            serde_json::json!({
                "provider_id": provider.id,
                "kind": provider.kind,
                "enabled": provider.enabled,
            }),
        )
        .await?;
        transaction.commit().await.context("commit auth provider")?;
        Ok(event)
    }

    /// Loads an authentication provider by its stable identifier.
    pub async fn auth_provider(&self, id: Uuid) -> Result<Option<AuthProvider>> {
        let row = db_query("SELECT provider_json FROM auth_providers WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("load authentication provider")?;
        row.map(|row| {
            let encoded: String = row.try_get("provider_json").context("read provider JSON")?;
            serde_json::from_str(&encoded).context("decode authentication provider")
        })
        .transpose()
    }

    /// Lists configured authentication providers without resolving their secret references.
    pub async fn auth_providers(&self) -> Result<Vec<AuthProvider>> {
        let rows = db_query("SELECT provider_json FROM auth_providers ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .context("list authentication providers")?;
        rows.into_iter()
            .map(|row| {
                let encoded: String = row.try_get("provider_json").context("read provider JSON")?;
                serde_json::from_str(&encoded).context("decode authentication provider")
            })
            .collect()
    }

    /// Binds a provider subject digest to a pre-provisioned human principal.
    pub async fn put_external_identity(
        &self,
        provider_id: Uuid,
        subject_sha256: &str,
        principal_id: Uuid,
    ) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin identity link")?;
        db_query(
            "INSERT INTO external_identities (provider_id, subject_sha256, principal_id, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(provider_id, subject_sha256) DO UPDATE SET principal_id=excluded.principal_id",
        )
        .bind(provider_id.to_string())
        .bind(subject_sha256)
        .bind(principal_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store external identity link")?;
        let event = insert_event(
            &mut transaction,
            "external_identity.linked",
            serde_json::json!({
                "provider_id": provider_id,
                "principal_id": principal_id,
            }),
        )
        .await?;
        transaction.commit().await.context("commit identity link")?;
        Ok(event)
    }

    /// Resolves a verified external subject digest to an active local principal.
    pub async fn principal_by_external_identity(
        &self,
        provider_id: Uuid,
        subject_sha256: &str,
    ) -> Result<Option<Principal>> {
        let row = db_query(
            "SELECT p.id, p.name, p.role, p.scopes_json, p.active, p.created_at FROM principals p INNER JOIN external_identities e ON e.principal_id=p.id WHERE e.provider_id=? AND e.subject_sha256=? AND p.active=1",
        )
        .bind(provider_id.to_string())
        .bind(subject_sha256)
        .fetch_optional(&self.pool)
        .await
        .context("resolve external identity")?;
        row.map(|row| decode_principal(&row)).transpose()
    }

    /// Stores a validated cloud adapter policy, which remains disabled unless explicitly enabled.
    pub async fn put_cloud_policy(&self, policy: &CloudAdapterPolicy) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin cloud policy")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO cloud_adapter_policies (id, policy_json, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET policy_json=excluded.policy_json, enabled=excluded.enabled, updated_at=excluded.updated_at",
        )
        .bind(policy.id.to_string())
        .bind(serde_json::to_string(policy).context("encode cloud policy")?)
        .bind(i64::from(policy.enabled))
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store cloud policy")?;
        let event = insert_event(
            &mut transaction,
            "cloud_policy.updated",
            serde_json::json!({
                "policy_id": policy.id,
                "provider_plugin": policy.provider_plugin,
                "enabled": policy.enabled,
            }),
        )
        .await?;
        transaction.commit().await.context("commit cloud policy")?;
        Ok(event)
    }

    /// Loads one cloud adapter policy without resolving its credential reference.
    pub async fn cloud_policy(&self, id: Uuid) -> Result<Option<CloudAdapterPolicy>> {
        let row = db_query("SELECT policy_json FROM cloud_adapter_policies WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("load cloud policy")?;
        row.map(|row| {
            let encoded: String = row
                .try_get("policy_json")
                .context("read cloud policy JSON")?;
            serde_json::from_str(&encoded).context("decode cloud policy")
        })
        .transpose()
    }

    /// Lists cloud adapter policies without loading secret values.
    pub async fn cloud_policies(&self) -> Result<Vec<CloudAdapterPolicy>> {
        let rows = db_query("SELECT policy_json FROM cloud_adapter_policies ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .context("list cloud policies")?;
        rows.into_iter()
            .map(|row| {
                let encoded: String = row
                    .try_get("policy_json")
                    .context("read cloud policy JSON")?;
                serde_json::from_str(&encoded).context("decode cloud policy")
            })
            .collect()
    }

    /// Atomically reserves monthly cloud spend and egress before any external request begins.
    /// `None` means the hard policy ceiling would be exceeded.
    #[allow(clippy::too_many_arguments)] // Every bound remains explicit at the transaction edge.
    pub async fn reserve_cloud_usage(
        &self,
        policy_id: Uuid,
        workload_id: WorkloadId,
        reserved_cost_micros: u64,
        reserved_network_bytes: u64,
        monthly_cost_limit_micros: u64,
        monthly_network_limit_bytes: u64,
    ) -> Result<Option<ClusterEvent>> {
        let reserved_cost = i64::try_from(reserved_cost_micros)
            .context("cloud cost reservation exceeds database range")?;
        let reserved_network = i64::try_from(reserved_network_bytes)
            .context("cloud network reservation exceeds database range")?;
        let mut transaction = self.pool.begin().await.context("begin cloud reservation")?;
        db_query(
            "INSERT INTO cloud_usage_locks (policy_id, marker) VALUES (?, 1) ON CONFLICT(policy_id) DO NOTHING",
        )
        .bind(policy_id.to_string())
        .execute(&mut *transaction)
        .await
        .context("initialize cloud quota lock")?;
        if self.dialect == DatabaseDialect::Postgres {
            db_query("SELECT marker FROM cloud_usage_locks WHERE policy_id=? FOR UPDATE")
                .bind(policy_id.to_string())
                .fetch_one(&mut *transaction)
                .await
                .context("lock PostgreSQL cloud quota")?;
        } else {
            db_query("UPDATE cloud_usage_locks SET marker=marker WHERE policy_id=?")
                .bind(policy_id.to_string())
                .execute(&mut *transaction)
                .await
                .context("lock SQLite cloud quota")?;
        }
        let month_start = Utc::now().format("%Y-%m-01T00:00:00+00:00").to_string();
        let usage = db_query(
            "SELECT COALESCE(SUM(COALESCE(actual_cost_micros, reserved_cost_micros)), 0) AS cost, COALESCE(SUM(COALESCE(actual_network_bytes, reserved_network_bytes)), 0) AS network FROM cloud_usage_reservations WHERE policy_id=? AND created_at>=?",
        )
        .bind(policy_id.to_string())
        .bind(month_start)
        .fetch_one(&mut *transaction)
        .await
        .context("sum monthly cloud usage")?;
        let used_cost: i64 = usage.try_get("cost").context("read monthly cloud cost")?;
        let used_network: i64 = usage
            .try_get("network")
            .context("read monthly cloud network")?;
        let projected_cost = u64::try_from(used_cost)
            .unwrap_or(u64::MAX)
            .saturating_add(reserved_cost_micros);
        let projected_network = u64::try_from(used_network)
            .unwrap_or(u64::MAX)
            .saturating_add(reserved_network_bytes);
        if projected_cost > monthly_cost_limit_micros
            || projected_network > monthly_network_limit_bytes
        {
            transaction
                .rollback()
                .await
                .context("rollback rejected cloud reservation")?;
            return Ok(None);
        }
        db_query(
            "INSERT INTO cloud_usage_reservations (workload_id, policy_id, reserved_cost_micros, reserved_network_bytes, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(workload_id.0.to_string())
        .bind(policy_id.to_string())
        .bind(reserved_cost)
        .bind(reserved_network)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("reserve cloud usage")?;
        let event = insert_event(
            &mut transaction,
            "cloud_usage.reserved",
            serde_json::json!({
                "policy_id": policy_id,
                "workload_id": workload_id,
                "reserved_cost_micros": reserved_cost_micros,
                "reserved_network_bytes": reserved_network_bytes,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit cloud reservation")?;
        Ok(Some(event))
    }

    /// Reconciles a cloud reservation to bounded actual usage after the stream terminates.
    pub async fn complete_cloud_usage(
        &self,
        workload_id: WorkloadId,
        actual_cost_micros: u64,
        actual_network_bytes: u64,
    ) -> Result<Option<ClusterEvent>> {
        let mut transaction = self.pool.begin().await.context("begin cloud usage")?;
        let result = db_query(
            "UPDATE cloud_usage_reservations SET actual_cost_micros=?, actual_network_bytes=?, completed_at=? WHERE workload_id=? AND completed_at IS NULL AND actual_cost_micros IS NULL AND actual_network_bytes IS NULL AND ?<=reserved_cost_micros AND ?<=reserved_network_bytes",
        )
        .bind(i64::try_from(actual_cost_micros).context("actual cloud cost exceeds range")?)
        .bind(i64::try_from(actual_network_bytes).context("actual cloud network exceeds range")?)
        .bind(Utc::now().to_rfc3339())
        .bind(workload_id.0.to_string())
        .bind(i64::try_from(actual_cost_micros).unwrap_or(i64::MAX))
        .bind(i64::try_from(actual_network_bytes).unwrap_or(i64::MAX))
        .execute(&mut *transaction)
        .await
        .context("reconcile cloud usage")?;
        if result.rows_affected() == 0 {
            transaction
                .rollback()
                .await
                .context("rollback cloud usage")?;
            return Ok(None);
        }
        let event = insert_event(
            &mut transaction,
            "cloud_usage.completed",
            serde_json::json!({
                "workload_id": workload_id,
                "cost_micros": actual_cost_micros,
                "network_bytes": actual_network_bytes,
            }),
        )
        .await?;
        transaction.commit().await.context("commit cloud usage")?;
        Ok(Some(event))
    }

    /// Loads the current controller lease.
    pub async fn controller_lease(&self) -> Result<Option<ControllerLease>> {
        let row = db_query(
            "SELECT controller_id, term, fencing_token, expires_at FROM controller_leases WHERE singleton=1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("load controller lease")?;
        row.as_ref().map(decode_controller_lease).transpose()
    }

    /// Acquires, renews, or takes over the singleton controller lease atomically.
    /// Active leases owned by another controller return `None` without mutation.
    pub async fn claim_controller_lease(
        &self,
        controller_id: Uuid,
        now: DateTime<Utc>,
        duration_seconds: u8,
    ) -> Result<Option<ControllerLease>> {
        anyhow::ensure!(
            (10..=60).contains(&duration_seconds),
            "controller lease duration must be 10 through 60 seconds"
        );
        let mut transaction = self.pool.begin().await.context("begin controller claim")?;
        let current_row = db_query(
            "SELECT controller_id, term, fencing_token, expires_at FROM controller_leases WHERE singleton=1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .context("load controller claim")?;
        let current = current_row
            .as_ref()
            .map(decode_controller_lease)
            .transpose()?;
        if current
            .as_ref()
            .is_some_and(|lease| lease.controller_id != controller_id && lease.expires_at > now)
        {
            transaction
                .rollback()
                .await
                .context("rollback held controller claim")?;
            return Ok(None);
        }
        let lease = if let Some(current) = current.as_ref()
            && current.controller_id == controller_id
            && current.expires_at > now
        {
            ControllerLease {
                expires_at: now + chrono::Duration::seconds(i64::from(duration_seconds)),
                ..current.clone()
            }
        } else {
            ControllerLease::next(current.as_ref(), controller_id, now, duration_seconds)
                .context("advance controller lease")?
        };
        let changed = if let Some(current) = current.as_ref() {
            db_query(
                "UPDATE controller_leases SET controller_id=?, term=?, fencing_token=?, expires_at=?, updated_at=? WHERE singleton=1 AND term=? AND fencing_token=?",
            )
            .bind(lease.controller_id.to_string())
            .bind(i64::try_from(lease.term).context("controller term is too large")?)
            .bind(i64::try_from(lease.fencing_token).context("fencing token is too large")?)
            .bind(lease.expires_at.to_rfc3339())
            .bind(now.to_rfc3339())
            .bind(i64::try_from(current.term).context("current term is too large")?)
            .bind(
                i64::try_from(current.fencing_token)
                    .context("current fencing token is too large")?,
            )
            .execute(&mut *transaction)
            .await
            .context("renew controller lease")?
        } else {
            db_query(
                "INSERT INTO controller_leases (singleton, controller_id, term, fencing_token, expires_at, updated_at) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(singleton) DO NOTHING",
            )
            .bind(lease.controller_id.to_string())
            .bind(i64::try_from(lease.term).context("controller term is too large")?)
            .bind(i64::try_from(lease.fencing_token).context("fencing token is too large")?)
            .bind(lease.expires_at.to_rfc3339())
            .bind(now.to_rfc3339())
            .execute(&mut *transaction)
            .await
            .context("insert controller lease")?
        };
        if changed.rows_affected() != 1 {
            transaction
                .rollback()
                .await
                .context("rollback controller claim race")?;
            return Ok(None);
        }
        if current.as_ref().is_none_or(|value| {
            value.term != lease.term || value.controller_id != lease.controller_id
        }) {
            let _event = insert_event(
                &mut transaction,
                "controller.lease_acquired",
                serde_json::json!({
                    "controller_id": lease.controller_id,
                    "term": lease.term,
                    "fencing_token": lease.fencing_token,
                    "expires_at": lease.expires_at,
                }),
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .context("commit controller claim")?;
        Ok(Some(lease))
    }

    /// Returns ordered events after a sequence, bounded by the supplied limit.
    pub async fn events_after(&self, after: i64, limit: i64) -> Result<Vec<ClusterEvent>> {
        let rows = db_query(
            "SELECT sequence, event_type, payload_json, created_at FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?",
        )
        .bind(after.max(0))
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await
        .context("load cluster events")?;
        rows.iter().map(decode_event).collect()
    }

    /// Stores a verified model manifest and emits a content-free event atomically.
    pub async fn put_model(&self, manifest: &ModelManifest) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin model transaction")?;
        let now = Utc::now();
        db_query(
            "INSERT INTO models (id, alias, sha256, format, quantization, size_bytes, manifest_json, status, pinned, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?) \
             ON CONFLICT(alias) DO UPDATE SET sha256=excluded.sha256, format=excluded.format, \
             quantization=excluded.quantization, size_bytes=excluded.size_bytes, manifest_json=excluded.manifest_json, \
             status='verified', pinned=excluded.pinned, updated_at=excluded.updated_at",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(&manifest.alias)
        .bind(&manifest.sha256)
        .bind(&manifest.format)
        .bind(&manifest.quantization)
        .bind(i64::try_from(manifest.size_bytes).unwrap_or(i64::MAX))
        .bind(serde_json::to_string(manifest).context("encode model manifest")?)
        .bind(i64::from(manifest.pinned))
        .bind(manifest.created_at.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store model manifest")?;
        let event = insert_event(
            &mut transaction,
            "model.verified",
            serde_json::json!({
                "alias": manifest.alias,
                "sha256": manifest.sha256,
                "size_bytes": manifest.size_bytes,
                "format": manifest.format,
                "pinned": manifest.pinned,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit model transaction")?;
        Ok(event)
    }

    /// Removes model metadata and emits an audit event. Content cleanup is owned by the model store.
    pub async fn remove_model(&self, alias: &str) -> Result<ClusterEvent> {
        let mut transaction = self.pool.begin().await.context("begin model removal")?;
        db_query("DELETE FROM models WHERE alias = ?")
            .bind(alias)
            .execute(&mut *transaction)
            .await
            .context("remove model metadata")?;
        let event = insert_event(
            &mut transaction,
            "model.removed",
            serde_json::json!({"alias": alias}),
        )
        .await?;
        transaction.commit().await.context("commit model removal")?;
        Ok(event)
    }

    /// Creates an encrypted persistent chat conversation.
    pub async fn create_conversation(
        &self,
        id: Uuid,
        title_envelope: Option<Vec<u8>>,
    ) -> Result<(ConversationRecord, ClusterEvent)> {
        let now = Utc::now();
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin conversation transaction")?;
        db_query(
            "INSERT INTO chat_conversations (id, title_ciphertext, temporary, created_at, updated_at) VALUES (?, ?, 0, ?, ?)",
        )
        .bind(id.to_string())
        .bind(title_envelope)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("create encrypted conversation")?;
        let event = insert_event(
            &mut transaction,
            "chat.conversation_created",
            serde_json::json!({"conversation_id": id}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit conversation creation")?;
        Ok((
            ConversationRecord {
                id,
                temporary: false,
                created_at: now,
                updated_at: now,
            },
            event,
        ))
    }

    /// Lists content-free persistent conversation metadata.
    pub async fn conversations(&self) -> Result<Vec<ConversationRecord>> {
        let rows = db_query(
            "SELECT id, temporary, created_at, updated_at FROM chat_conversations ORDER BY updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("list encrypted conversations")?;
        rows.iter().map(decode_conversation).collect()
    }

    /// Appends an encrypted message and records a content-free event atomically.
    pub async fn append_encrypted_message(
        &self,
        conversation_id: Uuid,
        message_id: Uuid,
        role: &str,
        envelope_version: u8,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<ClusterEvent> {
        let now = Utc::now();
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin encrypted message transaction")?;
        db_query(
            "INSERT INTO chat_messages (id, conversation_id, role, envelope_version, content_ciphertext, nonce, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(message_id.to_string())
        .bind(conversation_id.to_string())
        .bind(role)
        .bind(i64::from(envelope_version))
        .bind(ciphertext)
        .bind(nonce)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("store encrypted chat message")?;
        db_query("UPDATE chat_conversations SET updated_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(conversation_id.to_string())
            .execute(&mut *transaction)
            .await
            .context("update conversation timestamp")?;
        let event = insert_event(
            &mut transaction,
            "chat.message_stored",
            serde_json::json!({
                "conversation_id": conversation_id,
                "message_id": message_id,
                "role": role,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit encrypted message")?;
        Ok(event)
    }

    /// Loads encrypted messages in stable conversation order.
    pub async fn encrypted_messages(
        &self,
        conversation_id: Uuid,
    ) -> Result<Vec<EncryptedMessageRecord>> {
        let rows = db_query(
            "SELECT id, role, envelope_version, nonce, content_ciphertext, created_at FROM chat_messages WHERE conversation_id = ? ORDER BY created_at, id",
        )
        .bind(conversation_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("load encrypted messages")?;
        rows.iter().map(decode_encrypted_message).collect()
    }

    /// Deletes a conversation and all of its encrypted messages.
    pub async fn delete_conversation(&self, id: Uuid) -> Result<Option<ClusterEvent>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin conversation deletion")?;
        let result = db_query("DELETE FROM chat_conversations WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await
            .context("delete encrypted conversation")?;
        if result.rows_affected() == 0 {
            transaction
                .rollback()
                .await
                .context("rollback missing chat")?;
            return Ok(None);
        }
        let event = insert_event(
            &mut transaction,
            "chat.conversation_deleted",
            serde_json::json!({"conversation_id": id}),
        )
        .await?;
        transaction
            .commit()
            .await
            .context("commit conversation deletion")?;
        Ok(Some(event))
    }
}

async fn insert_event(
    transaction: &mut Transaction<'_, Any>,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<ClusterEvent> {
    let created_at = Utc::now();
    let payload_json = serde_json::to_string(&payload).context("encode event payload")?;
    let sequence: i64 = db_query_scalar(
        "INSERT INTO events (event_type, payload_json, created_at) VALUES (?, ?, ?) RETURNING sequence",
    )
    .bind(event_type)
    .bind(payload_json)
    .bind(created_at.to_rfc3339())
    .fetch_one(&mut **transaction)
    .await
    .context("insert event")?;
    db_query("INSERT INTO outbox (sequence) VALUES (?)")
        .bind(sequence)
        .execute(&mut **transaction)
        .await
        .context("insert outbox record")?;
    Ok(ClusterEvent {
        sequence,
        event_type: event_type.to_owned(),
        payload,
        created_at,
    })
}

fn decode_node(row: &sqlx::any::AnyRow) -> Result<Node> {
    let id: String = row.try_get("id").context("read node ID")?;
    let os: String = row.try_get("os").context("read node OS")?;
    let status: String = row.try_get("status").context("read node status")?;
    let capabilities: String = row
        .try_get("capabilities_json")
        .context("read capabilities JSON")?;
    let last_seen: String = row.try_get("last_seen_at").context("read last seen")?;
    Ok(Node {
        id: NodeId(Uuid::parse_str(&id).context("parse node ID")?),
        name: row.try_get("name").context("read node name")?,
        os: str_to_os(&os),
        architecture: row
            .try_get("architecture")
            .context("read node architecture")?,
        status: str_to_status(&status),
        capabilities: serde_json::from_str::<NodeCapabilities>(&capabilities)
            .context("decode capabilities JSON")?,
        last_seen_at: DateTime::parse_from_rfc3339(&last_seen)
            .context("parse last seen")?
            .with_timezone(&Utc),
    })
}

fn decode_controller_lease(row: &sqlx::any::AnyRow) -> Result<ControllerLease> {
    let controller_id: String = row
        .try_get("controller_id")
        .context("read controller lease identity")?;
    let term: i64 = row.try_get("term").context("read controller term")?;
    let fencing_token: i64 = row
        .try_get("fencing_token")
        .context("read controller fencing token")?;
    let expires_at: String = row
        .try_get("expires_at")
        .context("read controller lease expiry")?;
    Ok(ControllerLease {
        controller_id: Uuid::parse_str(&controller_id)
            .context("parse controller lease identity")?,
        term: u64::try_from(term).context("parse controller term")?,
        fencing_token: u64::try_from(fencing_token).context("parse controller fencing token")?,
        expires_at: DateTime::parse_from_rfc3339(&expires_at)
            .context("parse controller lease expiry")?
            .with_timezone(&Utc),
    })
}

fn decode_event(row: &sqlx::any::AnyRow) -> Result<ClusterEvent> {
    let payload: String = row.try_get("payload_json").context("read event payload")?;
    let created_at: String = row.try_get("created_at").context("read event time")?;
    Ok(ClusterEvent {
        sequence: row.try_get("sequence").context("read event sequence")?,
        event_type: row.try_get("event_type").context("read event type")?,
        payload: serde_json::from_str(&payload).context("decode event payload")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .context("parse event time")?
            .with_timezone(&Utc),
    })
}

fn decode_plugin_record(row: &sqlx::any::AnyRow) -> Result<InstalledPluginRecord> {
    let manifest: String = row
        .try_get("manifest_json")
        .context("read plugin manifest")?;
    let component_path: String = row
        .try_get("component_path")
        .context("read plugin component path")?;
    Ok(InstalledPluginRecord {
        manifest: serde_json::from_str(&manifest).context("decode plugin manifest")?,
        component_path: component_path.into(),
        enabled: row
            .try_get::<i64, _>("enabled")
            .context("read plugin enabled state")?
            != 0,
    })
}

fn decode_workflow_template(row: &sqlx::any::AnyRow) -> Result<WorkflowTemplateSummary> {
    let id: String = row.try_get("id").context("read template ID")?;
    let workflow_id: String = row
        .try_get("workflow_id")
        .context("read template workflow ID")?;
    let metadata_json: String = row
        .try_get("metadata_json")
        .context("read template metadata")?;
    let created_at: String = row
        .try_get("created_at")
        .context("read template creation time")?;
    Ok(WorkflowTemplateSummary {
        id: Uuid::parse_str(&id).context("parse template ID")?,
        name: row.try_get("name").context("read template name")?,
        workflow_id: WorkflowId(
            Uuid::parse_str(&workflow_id).context("parse template workflow ID")?,
        ),
        metadata: serde_json::from_str(&metadata_json).context("decode template metadata")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .context("parse template creation time")?
            .with_timezone(&Utc),
    })
}

fn decode_principal(row: &sqlx::any::AnyRow) -> Result<Principal> {
    let id: String = row.try_get("id").context("read principal ID")?;
    let role: String = row.try_get("role").context("read principal role")?;
    let scopes: String = row
        .try_get("scopes_json")
        .context("read principal scopes")?;
    let created_at: String = row
        .try_get("created_at")
        .context("read principal creation")?;
    Ok(Principal {
        id: Uuid::parse_str(&id).context("parse principal ID")?,
        name: row.try_get("name").context("read principal name")?,
        role: str_to_role(&role),
        scopes: serde_json::from_str(&scopes).context("decode principal scopes")?,
        active: row
            .try_get::<i64, _>("active")
            .context("read principal state")?
            != 0,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .context("parse principal creation")?
            .with_timezone(&Utc),
    })
}

const fn role_to_str(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
        Role::Node => "node",
        Role::Service => "service",
    }
}

fn str_to_role(role: &str) -> Role {
    match role {
        "owner" => Role::Owner,
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        "viewer" => Role::Viewer,
        "node" => Role::Node,
        _ => Role::Service,
    }
}

fn decode_conversation(row: &sqlx::any::AnyRow) -> Result<ConversationRecord> {
    let id: String = row.try_get("id").context("read conversation ID")?;
    let created_at: String = row
        .try_get("created_at")
        .context("read conversation creation time")?;
    let updated_at: String = row
        .try_get("updated_at")
        .context("read conversation update time")?;
    Ok(ConversationRecord {
        id: Uuid::parse_str(&id).context("parse conversation ID")?,
        temporary: row
            .try_get::<i64, _>("temporary")
            .context("read conversation retention")?
            != 0,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .context("parse conversation creation time")?
            .with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&updated_at)
            .context("parse conversation update time")?
            .with_timezone(&Utc),
    })
}

fn decode_encrypted_message(row: &sqlx::any::AnyRow) -> Result<EncryptedMessageRecord> {
    let id: String = row.try_get("id").context("read message ID")?;
    let created_at: String = row
        .try_get("created_at")
        .context("read message creation time")?;
    let envelope_version: i64 = row
        .try_get("envelope_version")
        .context("read message envelope version")?;
    Ok(EncryptedMessageRecord {
        id: Uuid::parse_str(&id).context("parse message ID")?,
        role: row.try_get("role").context("read message role")?,
        envelope_version: u8::try_from(envelope_version).context("parse envelope version")?,
        nonce: row.try_get("nonce").context("read message nonce")?,
        ciphertext: row
            .try_get("content_ciphertext")
            .context("read message ciphertext")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .context("parse message creation time")?
            .with_timezone(&Utc),
    })
}

fn decode_invitation_status(row: &sqlx::any::AnyRow) -> Result<InvitationStatus> {
    let id: String = row.try_get("id").context("read invitation ID")?;
    let expires_at: String = row
        .try_get("expires_at")
        .context("read invitation expiry")?;
    let approved_at: Option<String> = row
        .try_get("approved_at")
        .context("read invitation approval time")?;
    let failed_attempts: i64 = row
        .try_get("failed_attempts")
        .context("read invitation failures")?;
    Ok(InvitationStatus {
        id: Uuid::parse_str(&id).context("parse invitation ID")?,
        expires_at: DateTime::parse_from_rfc3339(&expires_at)
            .context("parse invitation expiry")?
            .with_timezone(&Utc),
        failed_attempts: u8::try_from(failed_attempts).context("parse invitation failures")?,
        consumed: row
            .try_get::<i64, _>("consumed")
            .context("read invitation consumed status")?
            != 0,
        approved: row
            .try_get::<i64, _>("approved")
            .context("read invitation approval status")?
            != 0,
        approved_at: approved_at
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .context("parse invitation approval time")
                    .map(|time| time.with_timezone(&Utc))
            })
            .transpose()?,
    })
}

fn os_to_str(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Windows => "windows",
        OperatingSystem::MacOs => "macos",
        OperatingSystem::Linux => "linux",
        OperatingSystem::Unknown => "unknown",
    }
}

fn str_to_os(os: &str) -> OperatingSystem {
    match os {
        "windows" => OperatingSystem::Windows,
        "macos" => OperatingSystem::MacOs,
        "linux" => OperatingSystem::Linux,
        _ => OperatingSystem::Unknown,
    }
}

fn status_to_str(status: NodeStatus) -> &'static str {
    match status {
        NodeStatus::Joining => "joining",
        NodeStatus::Ready => "ready",
        NodeStatus::Suspect => "suspect",
        NodeStatus::Offline => "offline",
        NodeStatus::Revoked => "revoked",
        NodeStatus::Draining => "draining",
    }
}

fn str_to_status(status: &str) -> NodeStatus {
    match status {
        "joining" => NodeStatus::Joining,
        "ready" => NodeStatus::Ready,
        "suspect" => NodeStatus::Suspect,
        "revoked" => NodeStatus::Revoked,
        "draining" => NodeStatus::Draining,
        _ => NodeStatus::Offline,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;
    use constellation_core::{
        ExecutionStrategy, PlanId, PrivacyPath, SchedulingPolicy, WorkerRuntimeEvent,
        WorkloadClass, WorkloadId,
    };
    use constellation_network::{
        TransportCandidate, TransportDecision, TransportKind, TransportPrivacyReport,
    };

    use super::*;

    async fn test_repository() -> (Repository, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("constellation-repository-{}.db", Uuid::now_v7()));
        let repository = Repository::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap_or_else(|error| panic!("test repository: {error}"));
        (repository, path)
    }

    fn node(status: NodeStatus, last_seen_at: DateTime<Utc>) -> Node {
        Node {
            id: NodeId::new(),
            name: "test node".to_owned(),
            os: OperatingSystem::Linux,
            architecture: "x86_64".to_owned(),
            status,
            capabilities: NodeCapabilities {
                cpu_model: "test".to_owned(),
                logical_cores: 8,
                memory_total_bytes: 16 * 1024 * 1024 * 1024,
                memory_available_bytes: 12 * 1024 * 1024 * 1024,
                accelerator: None,
                runtimes: vec!["mock".to_owned()],
                on_battery: false,
                user_active: false,
                temperature_celsius: None,
                thermal_throttling: None,
            },
            last_seen_at,
        }
    }

    fn workload_and_plan(worker: NodeId, now: DateTime<Utc>) -> (WorkloadRequest, ExecutionPlan) {
        let workload = WorkloadRequest {
            id: WorkloadId::new(),
            model: "constellation/mock".to_owned(),
            required_runtime: "mock".to_owned(),
            estimated_memory_bytes: 64 * 1024 * 1024,
            class: WorkloadClass::Interactive,
            policy: SchedulingPolicy::Balanced,
            allowed_nodes: vec![worker],
            allow_remote: false,
        };
        let plan = ExecutionPlan {
            id: PlanId::new(),
            workload_id: workload.id,
            strategy: ExecutionStrategy::SingleNode,
            selected_nodes: vec![worker],
            estimated_ttft_ms: 1.0,
            estimated_tokens_per_second: 100.0,
            estimated_memory_bytes: BTreeMap::from([(worker.0.to_string(), 64 * 1024 * 1024)]),
            estimated_network_bytes: 1024,
            confidence: 1.0,
            reasons: vec!["test".to_owned()],
            alternatives: Vec::new(),
            privacy: PrivacyPath {
                prompt_nodes: vec![worker],
                model_weight_nodes: vec![worker],
                uses_relay: false,
                leaves_local_network: false,
                uses_cloud: false,
                content_logged: false,
            },
            replan_triggers: Vec::new(),
            created_at: now,
        };
        (workload, plan)
    }

    async fn remove_test_database(path: &std::path::Path) {
        for candidate in [
            path.to_path_buf(),
            std::path::PathBuf::from(format!("{}-wal", path.display())),
            std::path::PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ignored = tokio::fs::remove_file(candidate).await;
        }
    }

    #[tokio::test]
    async fn liveness_thresholds_recover_and_revocation_is_terminal() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let stale = node(NodeStatus::Ready, now - Duration::seconds(16));
        let offline = node(NodeStatus::Ready, now - Duration::seconds(31));
        assert!(repository.register_node(&stale).await.is_ok());
        assert!(repository.register_node(&offline).await.is_ok());
        let events = repository.reconcile_liveness(now).await.unwrap_or_default();
        assert_eq!(events.len(), 2);
        let nodes = repository.list_nodes().await.unwrap_or_default();
        assert!(
            nodes
                .iter()
                .any(|value| { value.id == stale.id && value.status == NodeStatus::Suspect })
        );
        assert!(
            nodes
                .iter()
                .any(|value| { value.id == offline.id && value.status == NodeStatus::Offline })
        );
        assert!(repository.heartbeat(stale.id).await.is_ok());
        assert!(repository.revoke_node(stale.id).await.is_ok());
        assert!(
            repository
                .heartbeat(stale.id)
                .await
                .is_ok_and(|event| event.is_none())
        );
        let nodes = repository.list_nodes().await.unwrap_or_default();
        assert!(
            nodes
                .iter()
                .any(|value| { value.id == stale.id && value.status == NodeStatus::Revoked })
        );
        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn remote_usage_is_durable_and_month_scoped() {
        let (repository, path) = test_repository().await;
        let cluster = Uuid::now_v7();
        let now = Utc::now();
        let candidate = TransportCandidate {
            kind: TransportKind::DirectQuic,
            authenticated: true,
            encrypted: true,
            remote: true,
            relay: None,
            estimated_bytes: 2_048,
        };
        let decision = TransportDecision {
            privacy: TransportPrivacyReport {
                transport: TransportKind::DirectQuic,
                leaves_local_network: true,
                uses_relay: false,
                relay: None,
                relay_sees_plaintext: false,
                estimated_bytes: 2_048,
            },
            candidate,
        };
        assert!(
            repository
                .record_network_usage(cluster, &decision, 1_500, now)
                .await
                .is_ok()
        );
        assert_eq!(
            repository
                .network_usage(cluster, now)
                .await
                .unwrap_or_default(),
            1_500
        );
        assert_eq!(
            repository
                .network_usage(cluster, now + Duration::days(35))
                .await
                .unwrap_or_default(),
            0
        );
        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Exercises the complete durable lease state machine.
    async fn encrypted_worker_lease_is_claimed_once_and_orders_events() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let worker = node(NodeStatus::Ready, now);
        assert!(repository.register_node(&worker).await.is_ok());
        let (workload, plan) = workload_and_plan(worker.id, now);
        assert!(repository.create_workload(&workload, &plan).await.is_ok());
        let lease_id = Uuid::now_v7();
        assert!(
            repository
                .create_worker_lease(
                    lease_id,
                    workload.id,
                    worker.id,
                    1,
                    &[1_u8; 24],
                    b"ciphertext-not-content",
                    256,
                )
                .await
                .is_ok()
        );
        assert!(
            repository
                .available_workers(now)
                .await
                .unwrap_or_default()
                .is_empty()
        );
        let claimed = repository.claim_worker_lease(worker.id, now).await;
        assert!(claimed.is_ok_and(|value| value.is_some_and(|lease| lease.id == lease_id)));
        assert!(
            repository
                .available_workers(now)
                .await
                .is_ok_and(|workers| workers == vec![worker.id])
        );
        assert!(
            repository
                .claim_worker_lease(worker.id, now)
                .await
                .is_ok_and(|value| value.is_none())
        );
        let delta = WorkerRuntimeEvent::TextDelta {
            text: "private output".to_owned(),
        };
        assert!(
            repository
                .accept_worker_event(worker.id, lease_id, 1, &delta)
                .await
                .is_ok_and(|event| event.is_some())
        );
        assert!(
            repository
                .accept_worker_event(worker.id, lease_id, 1, &delta)
                .await
                .is_ok_and(|event| event.is_none())
        );
        assert!(
            repository
                .accept_worker_event(
                    worker.id,
                    lease_id,
                    2,
                    &WorkerRuntimeEvent::Finished {
                        input_tokens: 2,
                        output_tokens: 2,
                        finish_reason: "stop".to_owned(),
                    },
                )
                .await
                .is_ok_and(|event| event.is_some())
        );
        let plaintext_rows: i64 = db_query_scalar(
            "SELECT COUNT(*) FROM workload_leases WHERE CAST(input_ciphertext AS TEXT) LIKE '%private output%'",
        )
        .fetch_one(&repository.pool)
        .await
        .unwrap_or(1);
        assert_eq!(plaintext_rows, 0);
        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn expired_worker_lease_retries_once_then_interrupts() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let worker = node(NodeStatus::Ready, now);
        assert!(repository.register_node(&worker).await.is_ok());
        let (workload, plan) = workload_and_plan(worker.id, now);
        assert!(repository.create_workload(&workload, &plan).await.is_ok());
        let lease_id = Uuid::now_v7();
        assert!(
            repository
                .create_worker_lease(
                    lease_id,
                    workload.id,
                    worker.id,
                    1,
                    &[2_u8; 24],
                    b"encrypted request",
                    32,
                )
                .await
                .is_ok()
        );
        assert!(repository.claim_worker_lease(worker.id, now).await.is_ok());

        let first = repository
            .reconcile_worker_leases(now + Duration::seconds(31))
            .await
            .unwrap_or_default();
        assert_eq!(first.len(), 1);
        assert!(first[0].retried);
        assert!(!first[0].output_started);

        let second = repository
            .reconcile_worker_leases(now + Duration::seconds(62))
            .await
            .unwrap_or_default();
        assert_eq!(second.len(), 1);
        assert!(!second[0].retried);
        assert!(!second[0].output_started);
        let status: String = db_query_scalar("SELECT status FROM workloads WHERE id=?")
            .bind(workload.id.0.to_string())
            .fetch_one(&repository.pool)
            .await
            .unwrap_or_default();
        assert_eq!(status, "interrupted");

        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn expired_worker_lease_never_retries_after_output() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let worker = node(NodeStatus::Ready, now);
        assert!(repository.register_node(&worker).await.is_ok());
        let (workload, plan) = workload_and_plan(worker.id, now);
        assert!(repository.create_workload(&workload, &plan).await.is_ok());
        let lease_id = Uuid::now_v7();
        assert!(
            repository
                .create_worker_lease(
                    lease_id,
                    workload.id,
                    worker.id,
                    1,
                    &[3_u8; 24],
                    b"encrypted request",
                    32,
                )
                .await
                .is_ok()
        );
        assert!(repository.claim_worker_lease(worker.id, now).await.is_ok());
        assert!(
            repository
                .accept_worker_event(
                    worker.id,
                    lease_id,
                    1,
                    &WorkerRuntimeEvent::TextDelta {
                        text: "partial".to_owned(),
                    },
                )
                .await
                .is_ok()
        );

        let actions = repository
            .reconcile_worker_leases(now + Duration::seconds(31))
            .await
            .unwrap_or_default();
        assert_eq!(actions.len(), 1);
        assert!(!actions[0].retried);
        assert!(actions[0].output_started);

        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn browser_sessions_are_hashed_expiring_and_human_only() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let human = Principal {
            id: Uuid::now_v7(),
            name: "Passkey operator".to_owned(),
            role: Role::Operator,
            scopes: Vec::new(),
            active: true,
            created_at: now,
        };
        assert!(repository.put_principal(&human, None).await.is_ok());
        let token_hash = format!("{:x}", sha2::Sha256::digest(b"opaque browser token"));
        assert!(
            repository
                .put_browser_session(&token_hash, human.id, now + Duration::hours(24))
                .await
                .is_ok()
        );
        assert!(
            repository
                .principal_by_session_hash(&token_hash, now)
                .await
                .is_ok_and(|principal| principal.is_some_and(|value| value.id == human.id))
        );
        assert!(
            repository
                .principal_by_session_hash(&token_hash, now + Duration::hours(25))
                .await
                .is_ok_and(|principal| principal.is_none())
        );
        let stored_tokens: i64 = db_query_scalar(
            "SELECT COUNT(*) FROM browser_sessions WHERE token_sha256='opaque browser token'",
        )
        .fetch_one(&repository.pool)
        .await
        .unwrap_or(1);
        assert_eq!(stored_tokens, 0);

        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn postgres_repository_contract_smoke() {
        let Ok(database_url) = std::env::var("CONSTELLATION_TEST_POSTGRES_URL") else {
            return;
        };
        let repository = Repository::connect(&database_url)
            .await
            .unwrap_or_else(|error| panic!("connect PostgreSQL test repository: {error}"));
        let now = Utc::now();
        let worker = node(NodeStatus::Ready, now);
        assert!(repository.register_node(&worker).await.is_ok());
        let principal = Principal {
            id: Uuid::now_v7(),
            name: format!("PostgreSQL operator {}", Uuid::now_v7()),
            role: Role::Operator,
            scopes: Vec::new(),
            active: true,
            created_at: now,
        };
        assert!(repository.put_principal(&principal, None).await.is_ok());
        let team_name = format!("PostgreSQL team {}", Uuid::now_v7());
        assert!(
            repository
                .create_team(Uuid::now_v7(), &team_name)
                .await
                .is_ok()
        );
        assert!(
            repository
                .events_after(0, 100)
                .await
                .is_ok_and(|events| !events.is_empty())
        );
        repository.close().await;
    }

    #[tokio::test]
    async fn controller_claim_renews_and_fences_takeover() {
        let (repository, path) = test_repository().await;
        let now = Utc::now();
        let first_id = Uuid::now_v7();
        let second_id = Uuid::now_v7();
        let first = repository
            .claim_controller_lease(first_id, now, 15)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("first controller should acquire"));
        assert!(
            repository
                .claim_controller_lease(second_id, now + Duration::seconds(5), 15)
                .await
                .is_ok_and(|lease| lease.is_none())
        );
        let renewed = repository
            .claim_controller_lease(first_id, now + Duration::seconds(5), 15)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("first controller should renew"));
        assert_eq!(renewed.term, first.term);
        assert_eq!(renewed.fencing_token, first.fencing_token);
        let takeover = repository
            .claim_controller_lease(second_id, now + Duration::seconds(21), 15)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("expired lease should be taken over"));
        assert!(takeover.term > renewed.term);
        assert!(takeover.fencing_token > renewed.fencing_token);
        assert!(
            takeover
                .authorize_write(
                    second_id,
                    takeover.term,
                    takeover.fencing_token,
                    now + Duration::seconds(22),
                )
                .is_ok()
        );
        assert!(
            takeover
                .authorize_write(
                    first_id,
                    renewed.term,
                    renewed.fencing_token,
                    now + Duration::seconds(22),
                )
                .is_err()
        );
        repository.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn encrypted_workflow_run_recovers_after_repository_restart() {
        let (repository, path) = test_repository().await;
        let workflow_id = WorkflowId::new();
        let definition = constellation_workflows::WorkflowDefinition {
            version: 1,
            name: "Restart recovery".to_owned(),
            description: String::new(),
            steps: vec![constellation_workflows::StepDefinition {
                id: "artifact".to_owned(),
                action: constellation_workflows::StepAction::Artifact {
                    name: "result.txt".to_owned(),
                    media_type: "text/plain".to_owned(),
                    value: "recovered".to_owned(),
                },
                depends_on: Vec::new(),
                when: None,
                timeout_seconds: 30,
                retry_limit: 1,
            }],
        };
        let cipher = constellation_secrets::ContentCipher::from_key([41_u8; 32]);
        let definition_bytes = serde_json::to_vec(&definition).unwrap_or_default();
        let definition_encrypted = cipher
            .seal(
                format!("workflow:{}:revision:1", workflow_id.0).as_bytes(),
                &definition_bytes,
            )
            .unwrap_or_else(|error| panic!("encrypt definition: {error}"));
        let digest = constellation_workflows::definition_sha256(&definition).unwrap_or_default();
        assert!(
            repository
                .create_workflow(
                    workflow_id,
                    &definition.name,
                    &digest,
                    &definition_encrypted,
                )
                .await
                .is_ok()
        );
        let mut run = constellation_workflows::create_run(
            workflow_id,
            &definition,
            BTreeMap::new(),
            Utc::now(),
        )
        .unwrap_or_else(|error| panic!("create run: {error}"));
        assert!(
            constellation_workflows::apply_event(
                &mut run,
                &definition,
                &constellation_workflows::WorkflowEvent::Start,
                Utc::now(),
            )
            .is_ok()
        );
        let run_bytes = serde_json::to_vec(&run).unwrap_or_default();
        let run_encrypted = cipher
            .seal(format!("workflow-run:{}", run.id.0).as_bytes(), &run_bytes)
            .unwrap_or_else(|error| panic!("encrypt run: {error}"));
        assert!(
            repository
                .create_workflow_run(run.id, workflow_id, 1, "running", &run_encrypted,)
                .await
                .is_ok()
        );
        repository.close().await;

        let reopened = Repository::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap_or_else(|error| panic!("reopen repository: {error}"));
        assert!(
            reopened
                .active_workflow_runs(10)
                .await
                .is_ok_and(|runs| runs == vec![run.id])
        );
        let recovered = reopened
            .workflow_run(run.id)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recover encrypted run"));
        let plaintext = cipher
            .open(
                format!("workflow-run:{}", run.id.0).as_bytes(),
                &recovered.content,
            )
            .unwrap_or_else(|error| panic!("decrypt recovered run: {error}"));
        let decoded: constellation_workflows::WorkflowRun = serde_json::from_slice(&plaintext)
            .unwrap_or_else(|error| panic!("decode run: {error}"));
        assert_eq!(decoded, run);
        reopened.close().await;
        remove_test_database(&path).await;
    }

    #[tokio::test]
    async fn cloud_quota_is_reserved_atomically_and_reconciled_downward() {
        let (repository, path) = test_repository().await;
        let policy = CloudAdapterPolicy {
            id: Uuid::now_v7(),
            provider_plugin: "com.constellation.cloud.openai-compatible".to_owned(),
            credential_reference: "test-cloud".to_owned(),
            ..CloudAdapterPolicy::default()
        };
        assert!(repository.put_cloud_policy(&policy).await.is_ok());
        let first = WorkloadId::new();
        assert!(
            repository
                .reserve_cloud_usage(policy.id, first, 60, 60, 100, 100)
                .await
                .is_ok_and(|event| event.is_some())
        );
        assert!(
            repository
                .reserve_cloud_usage(policy.id, WorkloadId::new(), 50, 50, 100, 100)
                .await
                .is_ok_and(|event| event.is_none())
        );
        assert!(
            repository
                .complete_cloud_usage(first, 10, 10)
                .await
                .is_ok_and(|event| event.is_some())
        );
        assert!(
            repository
                .reserve_cloud_usage(policy.id, WorkloadId::new(), 50, 50, 100, 100)
                .await
                .is_ok_and(|event| event.is_some())
        );
        repository.close().await;
        remove_test_database(&path).await;
    }
}
