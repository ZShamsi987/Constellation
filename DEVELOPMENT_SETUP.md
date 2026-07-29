# Development Setup

## Required tools

- Rust 1.97.1 with rustfmt and Clippy
- Node.js 24.18.x and pnpm 11.9.x
- Python 3.13 only for Python adapters/tooling
- Git and `just`
- PostgreSQL and Docker are optional for local development; normal desktop operation must not require Docker

The installed versions in this repository are declared by `rust-toolchain.toml`, `.node-version`, `.python-version`, and `package.json`.

## Bootstrap

```bash
corepack enable
pnpm install
cargo test --workspace
pnpm check
```

## Run the vertical slice

```bash
cargo run -p constellationd -- --database-url 'sqlite://constellation.db?mode=rwc'
```

In another terminal:

```bash
cargo run -p constellation-node-simulator -- --controller http://127.0.0.1:4317
pnpm --filter @constellation/web dev
```

Open `http://127.0.0.1:5173`. Vite proxies API and WebSocket traffic to the daemon.

To bind beyond loopback, set a strong `CONSTELLATION_API_KEY` and terminate TLS in an explicitly configured development proxy. Direct public exposure is unsupported.

The operator CLI uses the same API:

```bash
cargo run -p constellation-cli -- status
cargo run -p constellation-cli -- diagnostics
cargo run -p constellation-cli -- chat 'hello from the private cluster'
```

Importing a local model requires explicit license acknowledgement:

```bash
cargo run -p constellation-cli -- model import ./model.gguf \
  --alias local/example --license '<upstream license>' --accept-license --pin
```

To enable the supervised llama.cpp adapter after import, restart the daemon with both `--llama-server /path/to/llama-server` and `--llama-model local/example`. The sidecar remains loopback-only.

The native shell reuses the web build:

```bash
pnpm --filter @constellation/desktop dev
pnpm --filter @constellation/desktop check
```

The searchable documentation site is built with Astro Starlight:

```bash
pnpm --filter @constellation/docs dev
pnpm --filter @constellation/docs build
```

Python SDK tests are dependency-free:

```bash
PYTHONPATH=packages/python-sdk/src \
  python3 -m unittest discover -s packages/python-sdk/tests -v
```

## Checks

```bash
just check
```

Tests must not require a GPU, external model, cloud account, or paid service. Use temporary databases and deterministic mock nodes. Never commit credentials, local databases, model files, generated support bundles, or raw user content.

`scripts/controller-failover.sh` exercises database-fenced leader takeover with two daemon processes. `scripts/official-client-compatibility.sh` launches an isolated daemon and runs pinned official OpenAI TypeScript and Python clients against it.
