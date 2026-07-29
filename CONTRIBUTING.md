# Contributing

Read [AGENTS.md](AGENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [THREAT_MODEL.md](THREAT_MODEL.md) before changing contracts or security boundaries.

1. Open an issue or design note for public API, protocol, schema, security, or dependency changes.
2. Keep commits small and scoped to one workstream.
3. Add tests and documentation with behavior changes.
4. Run `just check` before requesting review.
5. Never add production demo data, public unauthenticated listeners, raw content logging, unbounded queues, or silent capability fallbacks.

Contract owners review protobuf, OpenAPI, migration, runtime, scheduler, and security changes. A change is complete only when error behavior, metrics, documentation, and rollback implications are covered.
