# Privacy Model

## Defaults

Local-only networking, no relay, no cloud, no paid compute, telemetry off, raw prompt logging off, temporary support bundles, and local chat history are the defaults. Chat history is a user content feature, not a log, and is encrypted separately. Temporary chat disables it.

## Data classes

- **Secrets:** device/cluster keys, API keys, source tokens, recovery codes. Never logged or synchronized implicitly.
- **User content:** prompts, outputs, attachments, tool input/output, conversation history. Sent only to nodes required by the displayed plan.
- **Model data:** weights, manifests, licenses, private source locations. Weights may be shared only among authorized nodes.
- **Operational metadata:** identifiers, sizes, timings, plan, token counts, errors, utilization, and hashes. Stored according to retention policy.
- **Audit data:** actor, action, target, time, result, and policy identifiers. No raw content.

## Request data path

The gateway necessarily receives the request. The controller may inspect declared metadata and content needed for adapter routing. Executor nodes receive the inputs their runtime requires. Pipeline/tensor executors may receive tokens or activations when those strategies exist. Relay infrastructure transports ciphertext and must not receive endpoint plaintext. No data goes to cloud resources unless a future cloud plan is explicitly enabled and approved.

## Privacy inspector

Before execution, show intended controller, prompt, token, activation, weight, cache, log, relay, and cloud paths with estimate confidence. After execution, show observed nodes, transport path, stored metadata/content, retention, and deviations. A plan is blocked if observed prerequisites would exceed policy.

## Retention and deletion

Operational metadata has configurable retention; raw content is excluded. Deleting a conversation removes encrypted content and schedules attachment cleanup. Revoking a device does not silently erase its owner-controlled model cache. Credential wipe is explicit, destructive, and confirmed.
