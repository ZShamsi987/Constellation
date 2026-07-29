# Test Strategy

## Layers

- Unit and property tests cover scheduler constraints/scoring, fit arithmetic, policy, normalization, adapter capability matching, configuration, failure semantics and redaction.
- Protocol golden tests cover protobuf/JSON serialization, unknown fields, limits, version negotiation and TypeScript/Python interoperability.
- Repository tests run every migration on new and upgraded SQLite/PostgreSQL databases and verify transaction/outbox invariants.
- Integration tests start real daemon processes with deterministic mock runtimes and simulated nodes for enrollment, inventory, benchmarks, work, streaming, cancellation, leases, replanning, metrics and restart recovery.
- E2E tests drive the shared web UI and native shell for onboarding, chat, policy, plan/privacy inspection, failure, report, update, rollback and removal.

## Security

Negative tests cover invitation guessing/replay/expiry, revoked/wrong-cluster identity, authorization, malicious metadata, traversal, injection, secret leakage, redaction, rate limiting, queue exhaustion, unsafe plugin manifests and unsigned/downgrade updates. Fuzz protocol, manifests, archives, paths, adapter output and support-bundle scrubbing.

## Chaos and performance

An in-process network harness introduces latency, loss, jitter, bandwidth collapse, partitions, clock drift and duplicate messages. Fault injection covers runtime crash, corrupt model, disk full, OOM, thermal throttling, controller restart and version skew. Benchmarks track scheduler overhead, streaming latency, API throughput, model load/distribution, memory, dashboard rendering and 50 simulated nodes.

## Platform matrix

Tier 1 is Windows 11 x64 CPU/CUDA, macOS 14+ Apple Silicon CPU/Metal, and Ubuntu 24.04 x64 CPU/CUDA. AMD Vulkan is beta until it passes the same gates. CI covers logic on hosted runners; release claims require physical hardware evidence.

## Merge and release gates

Every change passes formatting, lint, type checking, unit/integration tests, schema compatibility, docs commands, licenses, dependency audit and secret scan. Release additionally requires E2E, security, chaos, update/rollback, signed packages, SBOM, provenance and acceptance evidence.
