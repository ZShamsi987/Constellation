# Threat Model

## Scope and trust boundaries

Protected assets are device and cluster keys, enrollment secrets, API keys, model-source credentials, prompts and outputs, files, model weights and licenses, policies, audit history, workload integrity, node availability, and update metadata.

Boundaries exist between client and gateway, controller and worker, worker and runtime sidecar, peers transferring model data, plugins and host, local content store and telemetry, relay and endpoints, and update infrastructure and installer.

Trusted nodes are administered by known people but may still be compromised. A relay, local network, model source, plugin, runtime process, and submitted model/file are never implicitly trusted.

## Principal threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Invitation guessing or replay | PAKE, eight-character codes, 10-minute TTL, five attempts, single use, approval, audit | Compromised controller can approve an attacker |
| Device impersonation | Hardware-independent Ed25519 identity, mTLS, short-lived certs, pinning, revocation | Stolen unlocked credential store |
| Rogue or compromised node | Trust and allowed-node policy, least-privilege leases, quotas, validation, revocation, privacy inspector | Trusted hardware can observe data it executes |
| LAN interception | TLS 1.3/QUIC authenticated encryption and replay protection | Endpoint compromise |
| Runtime escape | Loopback binding, per-process secret, constrained subprocess, resource limits, sanitized arguments | Runtime and driver vulnerabilities |
| Prompt/secret leakage | Content-free logs, field redaction, explicit content storage, scoped secrets, support-bundle scrubber | A selected executor receives required plaintext |
| Malicious metadata | Strict schemas, size/range limits, unknown-field handling, no shell interpolation | Parser defects |
| Model/archive attack | Content hashes, bounded paths, no archive traversal, staged verification, explicit license | Malicious model behavior and native runtime bugs |
| Scheduler abuse | Hard policy constraints, bounded queue, quotas, deadline and budget checks, deterministic audit | Resource estimation error |
| Supply-chain compromise | Locked dependencies, audits, SBOM, provenance, code signing, signed update metadata, rollback | Compromised maintainer or signing identity |
| Split brain | One authoritative controller in 0.1, durable controller identity, DB writer lock | Controller outage halts new scheduling |

## Abuse cases required in tests

Expired, replayed, malformed, and brute-forced invitations; revoked and wrong-cluster certificates; privilege escalation; metadata bombs; traversal and command injection; malicious runtime output; API key scope bypass; rate-limit evasion; content in logs/support bundles; queue exhaustion; disk full; corrupt model chunks; duplicate identities; clock drift; downgrade and unsigned updates.

## Explicit non-claim

Distributed or split inference does not make prompts private from participating executors. The privacy inspector must state which node receives prompts, tokens, activations, weights, caches, and logs.
