# API Specification

The implemented machine-readable contract lives in `openapi/constellation.openapi.yaml`. JSON uses UTF-8, RFC 3339 UTC timestamps, UUID identifiers, and normalized error envelopes containing `message`, `type`, `code`, optional `param`, and `trace_id`.

## Compatibility endpoints

- `GET /v1/models`
- `POST /v1/responses`
- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`

Responses and chat support synchronous and SSE forms. SSE ends with the endpoint-compatible terminal event. Runtime-dependent tools, structured output, images, audio, and parallel behavior are accepted only when the selected adapter advertises them; otherwise the request fails with `unsupported_feature`.

## Native endpoints

- `/constellation/v1/cluster`: capacity and readiness summary.
- `/constellation/v1/devices`: inventory, registration, status, approval and revocation.
- `/constellation/v1/benchmarks`: submission, history and report export.
- `/constellation/v1/models`: verified model-cache listing, license-gated local import, digest verification, pinning and removal.
- `/constellation/v1/workloads`: submit, inspect, cancel and list attempts.
- `/constellation/v1/plans`: simulation, explanation, privacy path and actual comparison.
- `/constellation/v1/events`: ordered replay and WebSocket live feed.
- `/constellation/v1/invitations` and `/enrollment`: expiring PAKE/link enrollment, proof, approval and credential pickup.
- `/constellation/v1/network` and `/emergency`: local-only defaults, transport simulation, quotas and remote stop.
- `/constellation/v1/workflows`, `/workflow-runs`, `/workflow-templates` and `/workflow-webhooks`: durable agent compute.
- `/constellation/v1/plugins`: component installation, exact-digest permission grants and bounded execution.
- `/constellation/v1/principals`, `/teams`, `/auth/passkeys` and `/auth/oidc`: RBAC and browser identity.
- `/constellation/v1/cloud-adapters`: explicit provider policy with opaque credential references and atomic quotas.
- `/constellation/v1/traces`, plan observations and digital-twin endpoints: content-free execution evidence.
- `/constellation/v1/control-plane/lease`: controller leadership/fencing visibility and acquisition.

## Authentication and limits

Loopback development may use a local OS-authenticated session. Any non-loopback binding requires TLS and an API key or user session. API keys use Bearer authentication and server-side scopes. Requests carry trace IDs; write operations accept idempotency keys. Bodies, streams, queues, concurrency, tokens, files and deadlines are bounded.

Browser access supports passkeys and pre-provisioned OIDC identities. OIDC uses authorization code, PKCE, CSRF state, nonce, exact redirect URLs and verified ID tokens. A browser session is returned only after the external subject hash is already linked to a local principal. Enabled SAML configuration is rejected with `unsupported_feature`.

## Stability

OpenAI compatibility follows its documented shapes only for the published feature matrix. Native APIs use additive minor evolution within `v1`; breaking changes require a new major prefix and migration guide.
