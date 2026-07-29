# Roadmap

## Phase 0A — Contracts — implemented

Product, UX, architecture, security, privacy, protocol, scheduler, runtime, plugin, persistence, API, testing, contribution, development, and release contracts. Exit when contradictions are resolved and CI can validate schemas and documentation.

## Phase 0B — Executable vertical slice — implemented

SQLite-backed daemon, deterministic scheduler and mock runtime, simulated heterogeneous nodes, inventory and benchmark ingestion, workload planning, OpenAI-style streaming, live dashboard state, event replay, and failure replanning.

## Phase 1 — Useful local product — implemented, release evidence open

Installed daemon and Tauri shell, real hardware collectors, model library, supervised llama.cpp, local chat, diagnostics, encrypted content storage, and updates.

## Phase 2 — Trusted LAN cluster / 0.1 — implemented, physical gate open

Authenticated discovery and enrollment, certificates, pairwise benchmarks, replicas and request routing, peer model cache, resource controls, benchmark exports, privacy inspection, new-request failover, and tier-1 installers.

## Phase 3 — Remote trusted nodes — policy layer implemented, transport gate open

Remote policy, direct/self-hosted/managed transport selection, quota accounting, WAN-aware plan inputs, audit, privacy reporting, and a kill switch are implemented and off by default. Production NAT traversal and relay transports remain disabled until interoperability and security gates pass; transport labels are not presented as live paths without a registered implementation.

## Phase 4 — Advanced distributed inference — planner implemented, execution gate open

Capability-gated pipeline/tensor/prefill-decode/speculative/hybrid planning, digital-twin scenarios, distributed traces, observations, replanning triggers, and a pinned EXO sidecar boundary are implemented. Real sharded execution is unavailable until an adapter advertises and validates it and reproducible hardware benchmarks prove benefit.

## Phase 5 — Agent compute — implemented, soak gate open

Durable workflow engine, visual/YAML authoring, parallel and conditional steps, approvals, sandboxed tools, artifacts, schedules, webhooks, and templates.

## Phase 6 — Ecosystem and teams — implemented with explicit provider gates

WASI Component Model plugins, exact-digest grants, declarative UI panels, RBAC/service identities/teams, passkeys, OIDC, PostgreSQL/SQLite repositories, database-fenced controller leadership, quota-bound cloud execution, and marketplace metadata are implemented. SAML is rejected as unsupported; automatic deployment orchestration and release-qualified HA remain gated.

Stretch features require separate design and cannot bypass earlier gates. The authoritative implementation/evidence matrix is [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).
