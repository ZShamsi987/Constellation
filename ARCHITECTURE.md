# Architecture

## Shape

Constellation is a local-first modular monolith. `constellationd` can run controller, worker, or both roles. The first device normally runs both; additional devices run workers. Modules have service-style interfaces so deployments can separate them later without changing public contracts.

```text
Desktop/Web/CLI/OpenAI clients
              |
        HTTP + SSE/WS
              |
       API gateway module
              |
  workload service -> scheduler core
       |                  |
 durable store       immutable snapshot
       |
 authenticated outbound control ===TLS 1.3/mTLS===> worker/resource manager
                                  |
                           runtime adapter
                                  |
                     mock or loopback sidecar
```

## Components

- **Gateway:** authenticates, validates, limits, normalizes APIs, and streams results.
- **Controller:** owns durable state, event sequence, work queue, leases, audit, and node membership.
- **Scheduler core:** pure deterministic planning over an immutable snapshot; it performs no I/O.
- **Worker:** reports normalized resources, enforces local policy, benchmarks, supervises runtimes, and executes leases.
- **Runtime layer:** versioned, capability-driven adapters; runtime-specific logic never enters scheduler or UI.
- **Model manager:** verified content-addressed cache, manifests, source credentials, resumable transfer, and eviction.
- **UI:** shared React application; the Tauri shell is not a security boundary.
- **Telemetry:** structured metadata, metrics, and traces with content redaction.

## Deployment

Local mode uses SQLite WAL and a loopback HTTP endpoint. Server mode uses PostgreSQL, authenticated TLS, and a database-fenced active-controller lease. Runtime sidecars bind to loopback with a per-process secret. Nodes initiate controller connections. The active worker transport is bounded HTTPS/JSON with rotating membership credentials; generated Tonic services define the future streaming boundary. Direct peer QUIC and relay implementations are not enabled until their security gates pass.

## Data flow

HTTP requests become canonical workloads. The controller builds a snapshot from durable inventory, recent heartbeats, capabilities, benchmarks, caches, queues, and policy. The scheduler returns an immutable execution plan. A worker lease identifies the workload, attempt, plan, deadline, and resource budget. Streaming chunks flow back through the controller and gateway. Metadata and estimates persist transactionally; content persists only in a separately encrypted, user-enabled content store.

## Consistency and recovery

One database-fenced controller is the active writer at a time. A standby may serve safe reads but mutating middleware revalidates the 15-second lease; the term advances on takeover. State changes and outbox events share a transaction. Workers treat repeated commands as idempotent by command ID. Leases expire and may be reassigned only under defined retry semantics. A restarted controller recovers queues, workflows, and event sequence from the database.

## Extraction boundaries

Gateway, scheduler, model registry, telemetry, and relay communicate through traits and canonical types even while linked in one binary. Extraction requires an ADR, protocol mapping, failure budget, and operational justification.
