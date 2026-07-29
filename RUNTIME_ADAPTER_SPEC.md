# Runtime Adapter Specification

## Boundary

Runtime-specific code is isolated behind an in-process trait or an authenticated loopback sidecar using the same versioned messages. The scheduler and UI consume canonical capabilities and metrics only.

## Required operations

`detect`, `capabilities`, `validate_model`, `estimate`, `load`, `execute_stream`, `cancel`, `unload`, `health`, `metrics`, and `recover`.

Adapters declare supported OS/architecture, accelerators, formats, quantizations, context limits, batching, streaming, embeddings, tools, structured output, multimodality, parallel strategies, cache controls, cancellation, metrics, health, migration, and recovery. Absence is explicit and never inferred from runtime name.

## Execution

Execution receives a canonical workload, immutable plan fragment, resource budget, deadline, cancellation token, and content handles. It emits typed loading, prefill, token/content, tool, metrics, finish, cancel, and error events. Output order is stable within an attempt.

## Sidecar security

Bind to a random loopback port or local socket; require a random per-launch secret; pass arguments without a shell; minimize environment and file access; enforce RAM/VRAM/CPU/disk/network limits; capture content-free logs; health check startup; drain before termination; kill after deadline.

## Initial adapters

The mock adapter is deterministic and supports tests without hardware. The llama.cpp adapter supervises `llama-server` and maps its declared capabilities. EXO, Ollama, MLX, and vLLM follow as separately versioned adapters; EXO remains a sidecar/API integration with upstream attribution and no Windows claim unless upstream support changes.

The implemented llama.cpp adapter binds a fresh loopback port, writes a mode-0600 per-process API key file, passes arguments without a shell, suppresses sidecar output that may contain content, polls health through model load, translates OpenAI-style SSE into typed runtime events, supports cancellation and recovery, and labels post-output failures `generation_interrupted`. It advertises tools, structured output, embeddings, and parallel strategies conservatively until model-specific validation exists.

## Compatibility

Adapter protocol major versions must match. Minor capability additions are optional. Runtime binary version, build features, driver versions, model metadata, and adapter version are included in health and plan evidence.
