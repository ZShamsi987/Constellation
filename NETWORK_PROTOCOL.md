# Network Protocol

## Versioning

Canonical protobuf uses package `constellation.v1`. Generated Prost/Tonic client/server code and a descriptor golden test are built from `protocol/constellation/v1`; Buf lint, generation, and compatibility checks run in CI. Every versioned session contract exchanges product version, protocol minimum/maximum, role, identity, cluster, and capabilities. Unsupported windows fail explicitly and additive unknown fields remain tolerated.

## Channels

- Client API: HTTP/1.1 or HTTP/2 with JSON; SSE for generation; WebSocket for live cluster events.
- Node control today: outbound bounded HTTPS/JSON polling and event submission with a rotating membership credential and TLS 1.3 client certificate on non-loopback deployments. The generated gRPC services are the versioned migration boundary, not yet the active daemon transport.
- Model data today: controller-authorized, single-use chunk transfer over the authenticated control endpoint. Direct QUIC and relay candidates exist only in the policy/capability layer until a transport implementation passes its gate.
- Discovery: LAN multicast announcement of opaque cluster ID, certificate fingerprint, and enrollment endpoint only.

## Enrollment

The joining node creates an identity and starts a PAKE exchange using an eight-character invitation code, or proves a 128-bit QR/link secret. Invitations expire after ten minutes, after one use, or five failed attempts. The controller displays both identity fingerprints; approval issues cluster membership and a short-lived certificate.

## Control stream

Messages include unique command/event IDs and sequence numbers. Workers send hello, inventory, capabilities, heartbeat, benchmark updates, lease status, chunks, and resource events. Controllers send policy, leases, cancellation, drain, certificate rotation, peer tickets, and revocation state. Repeated commands are idempotent.

The active worker uses one outbound request stream: inventory and runtime benchmarks are published, credentials rotate before their 24-hour expiry, heartbeats run every five seconds, leases are polled, and monotonically sequenced runtime events are returned. A worker never binds an unauthenticated runtime or control port.

## Limits and liveness

Message and metadata sizes are bounded per type. Heartbeats are sent every five seconds, suspect at 15, offline at 30. Clock offsets outside tolerance are reported; deadlines use controller time plus negotiated monotonic durations where possible.

## Privacy

Discovery and relays expose no plaintext user content. Protocol tracing records type, size, IDs, and timing but not sensitive fields. Each protobuf field is classified in the protocol documentation before release.

Remote direct/relay selection is deterministic and requires authentication, encryption, an explicit remote opt-in, a nonzero monthly byte quota, and a separate managed-relay opt-in. The emergency stop overrides every remote candidate. A selected simulated path produces a pre-execution privacy report but does not imply that a production NAT/relay implementation is installed.
