# Security Requirements

## Identity and authentication

- Devices generate non-exported Ed25519 identities where OS facilities permit and otherwise store encrypted key material with restrictive permissions.
- Controller, worker, peer, UI, API key, and service identities authenticate independently.
- Certificates last at most 24 hours and require a non-revoked device identity for rotation.
- Invitation secrets are single-purpose, short-lived, attempt-limited, and redacted everywhere.
- Non-loopback HTTP binding requires authentication and TLS; runtime sidecars never bind publicly.

## Authorization

Roles are Owner, Admin, Operator, Viewer, Node, and scoped Service. Authorization is checked server-side for every administrative and workload operation. API keys are hashed at rest and reveal their value only once. Node-owner policy is locally enforced and can be tightened but not remotely loosened.

## Data protection

Secrets use native credential storage. Persisted chat content uses application-level authenticated encryption with a separately wrapped key. Logs, metrics, traces, audit context, crash data, and support bundles exclude raw content by default. Temporary chat persists no content.

## Input and process safety

Apply request, message, field, archive, path, model, queue, concurrency, and duration bounds. Runtime arguments are structured, never shell-concatenated. Subprocesses receive minimal environment and filesystem access, loopback-only listeners, random secrets, quotas, graceful termination, then forced termination after a deadline.

## Network safety

Use TLS 1.3 mutual authentication for node control and authenticated encrypted QUIC for peer data. LAN discovery carries no hardware, models, user names, or invitation secrets. Peer operations require narrow controller-issued tickets with target, operation, byte budget, and expiry.

## Operations

Audit security changes and denied administrative attempts without content. Provide revoke, lock cluster, disconnect remote nodes, stop downloads, revoke invitations, disable relay, and wipe local credentials. Signed update metadata, rollback protection, SBOM, and reproducible release provenance are release gates.
