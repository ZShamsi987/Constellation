# MVP Acceptance Criteria

Release 0.1 is accepted only when all statements below are demonstrated on Windows 11 x64, macOS 14+ Apple Silicon, and Ubuntu 24.04 x64 where applicable.

- A clean install starts a local authenticated service without Docker or a cloud account.
- A user creates a cluster and adds a second trusted computer within five minutes without editing configuration.
- Enrollment expires, limits attempts, requires approval, establishes mutual identity, and supports revocation.
- Inventory normalizes OS, CPU, memory, accelerator, disk, power, thermal availability, network, runtime, and model cache; unavailable metrics do not crash the node.
- Fast compute and pairwise network benchmarks finish within 90 seconds and record method, timestamp, samples, and confidence.
- Mock and llama.cpp runtimes are detected through the same capability contract.
- A model can be imported, verified, loaded, unloaded, and represented in the cluster cache.
- Chat streams through `/v1/responses` and `/v1/chat/completions`; models and embeddings are exposed where supported.
- Separate requests route across eligible nodes, and every plan shows estimates, constraints, reasons, alternatives, confidence, and privacy path.
- Keep This Computer Responsive materially changes placement or produces a clear infeasibility reason.
- Revoked or offline nodes cannot receive new leases. New work replans within the documented heartbeat window.
- Interrupted output is preserved and labeled restarted versus resumed correctly.
- Simple and Engineering modes are keyboard accessible, handle empty/offline/partial failure states, and never show nonfunctional release controls.
- Benchmark reports are exportable and contain reproducibility inputs without prompt content.
- API, integration, E2E, security, chaos, upgrade, rollback, and uninstaller suites pass; signed artifacts and SBOMs are produced.

Until these criteria pass on physical supported hardware, documentation must call the product pre-release rather than production-ready.
