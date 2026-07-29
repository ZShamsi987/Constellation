# Database Schema

## Principles

SQLite WAL is the local source of truth; PostgreSQL is supported through dialect-specific migrations behind repository traits. Identifiers are UUIDv7 where ordering helps. Timestamps are UTC. Security and event records are append-only except for documented retention. Migrations are forward-only in place and require backup plus application rollback compatibility for destructive changes.

## Core records

- `schema_migrations`: version, checksum, applied time and binary version.
- `clusters`: identity, name, authority fingerprint, policy and locked state.
- `principals`, `role_bindings`, `api_keys`: users/services, scoped roles, one-time key prefixes and hashes.
- `devices`, `device_certificates`, `invitations`: identities, membership, status, revocation, certificate metadata and attempt-limited enrollment.
- `hardware_snapshots`, `runtime_capabilities`, `heartbeats`: normalized reports with source quality and collection time.
- `links`, `benchmark_runs`, `benchmark_samples`: pairwise and compute measurements with environment and confidence.
- `models`, `model_artifacts`, `model_chunks`, `node_cache_entries`: manifests, license, source, verified content and placement.
- `workloads`, `workload_attempts`, `leases`, `execution_plans`: canonical requirements, retries, assignment and immutable plan evidence.
- `events`, `outbox`: monotonic durable state transitions and undelivered notifications.
- `policies`: versioned cluster, principal, node and workload constraints.
- `audit_events`: actor, action, target, result, request/trace ID and redacted context.
- `notifications`: channel-neutral delivery state.
- `encrypted_content`: separately encrypted conversations and artifacts with retention metadata.

## Invariants

Invitation secrets and API keys are never stored in plaintext. Device revocation prevents active certificates and leases. Workloads and attempts are separate so retries never rewrite history. Plans are immutable. Outbox insertion shares the state transaction. Content tables are never joined into telemetry export by default.

The executable migrations currently persist:

- controller/worker state: devices, certificates, invitations, credentials, resource policies, worker sessions, workload leases, benchmarks, workloads, plans, observations, trace spans, events and outbox records;
- local content boundaries: verified model manifests, runtime instances, encrypted chat conversations/messages, encrypted workflow definitions/runs/artifacts, schedules, schedule firings, webhooks and templates;
- security and administration: settings, audits, notifications, principals, passkeys, hashed browser sessions, teams, memberships, OIDC/SAML configuration records, hashed external identities, plugin manifests/grants, cloud policies and quota reservations;
- network/model operations: transfer tickets, monthly byte accounting and privacy-safe transport records; and
- high availability: the single-row controller lease with monotonically increasing term and fencing expiry.

SQLite and PostgreSQL have separate forward migrations under `migrations/sqlite` and `migrations/postgres`; the repository uses `sqlx::AnyPool` and dialect-specific locking where correctness differs. Filesystem model content is independently SHA-256 addressed in fixed 4 MiB chunks; the database stores its verified manifest and lifecycle state.

Content ciphertext is intentionally not included in telemetry or support-bundle queries. PostgreSQL backup/restore uses `pg_dump`/`pg_restore`; SQLite uses a consistent database backup and preserves the previous state in a recoverable directory during restore.
