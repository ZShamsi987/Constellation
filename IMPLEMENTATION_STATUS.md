# Implementation Status

This document separates executable implementation from release qualification. Constellation is `0.1.0-alpha.1`; no section below overrides the physical-platform and signing requirements in `MVP_ACCEPTANCE_CRITERIA.md`.

## Implemented and exercised locally

| Capability | Implementation | Executable evidence |
| --- | --- | --- |
| Contracts and storage | OpenAPI 3.1, protobuf/Buf, generated Prost/Tonic crate, SQLite/PostgreSQL migrations and repositories, durable outbox/event sequence | `buf lint`, `buf generate`, protocol golden test, repository tests, PostgreSQL CI service |
| Local AI service | Controller/worker/all roles, hardware detection, deterministic scheduler, mock runtime, supervised loopback llama.cpp, pinned EXO sidecar boundary, model import/chunks, encrypted chat | Rust unit/integration tests and `scripts/vertical-slice.sh` |
| Compatible API | Responses, chat completions, completions, embeddings, models, SSE, cancellation, normalized errors, trace IDs and unsupported-feature checks | TypeScript/Python SDK tests and `scripts/official-client-compatibility.sh` |
| Trusted workers | PAKE/link enrollment, approval, Ed25519 device identity, 24-hour rotating certificates, outbound worker leases/events, liveness, revocation, resource policy and transfer tickets | Enrollment negative tests and vertical-slice worker process |
| Administration UI | Shared React UI, Tauri shell, Simple/Engineering modes, planning/privacy views, WebSocket replay, encrypted history, workflows, teams, passkeys and provider configuration | Vitest, desktop checks and browser-assisted end-to-end smoke |
| Advanced planning | Capability-gated distributed strategies, digital twin, plan observations, content-free traces and explicit replanning triggers | Scheduler property/unit tests and native API tests |
| Agent compute | Encrypted durable DAGs, parallel/conditional steps, retries, approvals, artifacts, schedules, webhooks, templates, accounting and restart recovery | Workflow state-machine, repository and daemon tests |
| Plugins and teams | Wasmtime Component Model host, fuel/I/O limits, non-inheriting WASI, digest-bound grants, declarative UI, RBAC/service identities, passkeys, OIDC, teams and cloud quotas | Plugin/RBAC/identity negative tests and daemon API tests |
| Control-plane HA | SQLite/PostgreSQL controller lease term, expiry and middleware fencing; standby takeover | `scripts/controller-failover.sh` |
| Documentation | Product/security/architecture contracts, ADRs and searchable Astro Starlight site | `pnpm --filter @constellation/docs check && pnpm --filter @constellation/docs build` |

## Deliberately gated

| Gate | Current behavior | Evidence required to open |
| --- | --- | --- |
| Public `0.1.0` | Alpha label; no production-ready claim | Signed/notarized tier-1 installers, SBOM/provenance, update/rollback/uninstall and complete physical MVP matrix |
| Remote direct/relay transport | Policy, quota, privacy report and kill switch work; no production transport is registered | NAT/relay implementation, security review, interoperability, partitions/abuse tests and privacy verification |
| Advanced sharded execution | Plans are rejected without adapter-attested capabilities; daemon does not execute synthetic sharded plans | Real adapter implementation plus reproducible multi-node correctness and performance results |
| EXO promotion | Exact reviewed revision and loopback endpoint are required | Pinned-sidecar compatibility suite and supported-platform hardware evidence; Windows remains unclaimed |
| SAML | Enabled configuration returns `unsupported_feature` | Metadata/signature/replay design, implementation and independent security review |
| Release-qualified HA | Database fencing and failover script exist | PostgreSQL deployment automation, process orchestration, fault/partition soak and restore drills |
| Managed cloud/relay defaults | Disabled; cloud requires an exact HTTPS endpoint, model, region, secret reference and hard quotas | Operator opt-in and provider-specific conformance/security evidence |

## Complete verification

Run `just check` for formatting, Clippy, all Rust tests, TypeScript checks/tests, Starlight validation and Python SDK tests. CI additionally runs PostgreSQL, controller failover, the vertical slice, official OpenAI clients, desktop checks on Windows/macOS/Linux, Buf compatibility, OpenAPI lint, dependency/license audits and secret scanning.
