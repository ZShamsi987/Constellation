---
title: Feature status
description: Implemented capabilities and release evidence still required.
---

Constellation separates implemented code from release claims. Capability-gated code can exist while a public release gate remains closed.

| Area                  | Executable today                                                                                                                                                                                      | Gate still open                                                                                                          |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Local product         | Rust daemon, SQLite/PostgreSQL repositories, Tauri shell, shared React UI, hardware detection, mock and supervised llama.cpp adapters, encrypted chat, model cache, diagnostics, backup/restore       | Signed installers, updater/rollback evidence, and the complete tier-1 physical matrix                                    |
| Trusted nodes         | PAKE/link enrollment, approval, Ed25519 identity, rotating certificates, outbound workers, durable leases, routing, revocation, resource policy, peer-transfer tickets                                | Physical two-to-eight-device benchmark and usability acceptance evidence                                                 |
| Remote networking     | Deny-by-default policy, quota accounting, emergency stop, deterministic direct/relay selection, privacy reports                                                                                       | Production NAT traversal and relay transports remain disabled pending interoperability and security review               |
| Distributed inference | Capability-gated pipeline/tensor/prefill-decode/speculative/hybrid planning, digital-twin scenarios, observations, traces, pinned EXO shim                                                            | Real multi-node execution is not enabled until adapter and real-hardware benchmarks prove correctness and benefit        |
| Agent compute         | Durable encrypted workflow DAGs, parallel/conditional steps, approvals, artifacts, schedules, webhooks, templates, sandboxed tools, accounting, restart recovery                                      | Long-duration soak and broad native UI automation                                                                        |
| Ecosystem and teams   | WASI Component Model sandbox, exact-digest permission grants, declarative UI extensions, RBAC, service identities, teams, passkeys, OIDC, PostgreSQL leader fencing, opt-in quota-bound cloud adapter | SAML and automatic multi-controller failover orchestration are explicitly unavailable; HA needs deployment soak evidence |

The `/v1/models` response and runtime capability checks are authoritative for model-facing features. An unavailable strategy or identity provider must return `unsupported_feature` or a more specific normalized error.
