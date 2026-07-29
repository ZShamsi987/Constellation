---
title: Contributing
description: Repository checks and non-negotiable invariants.
---

Read `AGENTS.md`, `CONTRIBUTING.md`, and the relevant ADR before changing a trust boundary or public contract.

Run the complete local gate before proposing a change:

```bash
just check
buf lint
buf generate
```

Security-sensitive changes require a negative test. Scheduler work should remain deterministic and side-effect free. Runtime-specific behavior belongs in an adapter. Unsupported behavior must remain explicit, and logging changes must prove that content and credentials cannot cross the operational logging boundary.
