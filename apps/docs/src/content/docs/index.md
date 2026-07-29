---
title: Constellation
description: Local-first control plane for trusted private AI compute.
template: splash
hero:
  tagline: Turn the computers you control into one private AI compute pool.
  actions:
    - text: Run locally
      link: /getting-started/
      icon: right-arrow
      variant: primary
    - text: See feature gates
      link: /feature-status/
      icon: open-book
---

Constellation is an Apache-2.0 control plane, scheduler, runtime host, and shared desktop/web interface for private AI workloads. A single `constellationd` process can be the controller, a worker, or both. SQLite and the deterministic mock runtime make the basic product usable without an account, internet connection, container runtime, or accelerator.

The current build is an alpha. It includes executable local and trusted-node flows plus gated later-phase subsystems. It is not represented as production-ready until the physical platform, installer, signing, update, rollback, chaos, and real-hardware acceptance matrices pass.

## Design rules

- Raw prompts, generated output, files, and secrets never enter operational logs.
- Node-owner resource limits, privacy, trust, and adapter capabilities are hard constraints.
- Remote networking, relays, cloud execution, and plugin permissions default to disabled.
- Unsupported capabilities fail with a stable error instead of silently degrading.
- Plans record placement, estimates, alternatives, confidence, privacy paths, and replanning triggers.
