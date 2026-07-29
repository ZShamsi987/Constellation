---
title: Security and privacy
description: Trust boundaries, default policies, and safe operations.
---

## Secure defaults

- Services bind to loopback by default. A non-loopback controller requires an explicit interface, a strong API key, TLS 1.3, and enrolled-node authentication.
- Worker and runtime connections are outbound or loopback-only. Runtime sidecars receive a per-process secret.
- Device identities and content keys use the operating system credential store. Test-only ephemeral identity is restricted to loopback.
- Remote networking, managed relay use, cloud execution, prompt logging, and telemetry are disabled by default.
- API keys and sessions are stored as hashes. Recovery and enrollment secrets are bounded, expiring, rate-limited, and single-use where applicable.

## Content boundary

Operational records may contain identifiers, timing, byte counts, runtime state, estimates, redacted error codes, and plan metadata. They must not contain prompts, completions, file contents, model-repository tokens, provider secrets, or workflow artifacts. Chat and workflow content use a separately wrapped encryption key.

## Reporting a vulnerability

Do not open a public issue. Follow the private reporting instructions in the repository `SECURITY.md`. Include the affected version, deployment mode, reproduction, and impact without sending live credentials or private content.
