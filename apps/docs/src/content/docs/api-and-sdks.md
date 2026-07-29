---
title: APIs and SDKs
description: OpenAI-compatible and native interfaces.
---

## OpenAI-compatible gateway

The preferred interface is `POST /v1/responses`. Compatibility endpoints also include chat completions, completions, embeddings, and models. Streaming uses server-sent events, cancellation preserves accurate partial-output semantics, and every error uses a normalized envelope with a trace ID.

The repository runs compatibility tests against pinned official OpenAI TypeScript and Python clients. Runtime-dependent tools, structured output, embeddings, multimodality, and parallel behavior are accepted only when the selected adapter advertises them.

## Native API

Native endpoints live below `/constellation/v1`. The OpenAPI 3.1 source is `openapi/constellation.openapi.yaml`; generated protobuf code comes from `protocol/constellation/v1` and passes Buf lint and compatibility gates.

## SDKs

- `packages/typescript-sdk` provides typed JSON and SSE clients.
- `packages/python-sdk` provides a dependency-free Python 3.13 client.
- `apps/constellation-cli` covers cluster state, enrollment, worker operation, model management, planning, chat, workflows, plugins, teams, provider secrets, diagnostics, and backup.

The service does not silently accept unsupported fields. Feature availability is defined by the published matrix and adapter capabilities, not by shape compatibility alone.
