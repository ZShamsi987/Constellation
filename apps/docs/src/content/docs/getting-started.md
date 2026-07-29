---
title: Getting started
description: Start a local controller, dashboard, CLI, and deterministic runtime.
---

## Requirements

- Rust 1.97.1
- Node.js 24 LTS
- pnpm 11
- Python 3.13 only for the Python SDK and adapter tooling

## Start a private local node

```bash
corepack enable
pnpm install
cargo run -p constellationd -- \
  --database-url 'sqlite://constellation.db?mode=rwc'
```

The API binds to `127.0.0.1:4317`. In a second terminal, start the shared web interface:

```bash
pnpm --filter @constellation/web dev
```

Open `http://127.0.0.1:5173`. The default mock model is `constellation/mock`; it exercises scheduling, persistence, streaming, cancellation, usage accounting, and live events without downloading model weights.

## Use the CLI

```bash
cargo run -p constellation-cli -- status
cargo run -p constellation-cli -- diagnostics
cargo run -p constellation-cli -- chat 'hello from my private cluster'
```

Run the end-to-end simulated node scenario with:

```bash
bash scripts/vertical-slice.sh
```

The script creates isolated temporary state, exercises enrollment, approval, inventory, benchmarks, authenticated worker execution, streaming, model chunks, policy, and failure handling, and removes its temporary state on exit.
