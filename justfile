set dotenv-load := true

default:
    @just --list

bootstrap:
    corepack enable
    pnpm install --frozen-lockfile=false

format:
    cargo fmt --all --check
    pnpm format

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    pnpm check
    pnpm test
    PYTHONPATH=packages/python-sdk/src python3 -m unittest discover -s packages/python-sdk/tests -v

dev-daemon:
    cargo run -p constellationd -- --database-url sqlite://constellation.db?mode=rwc

dev-web:
    pnpm --filter @constellation/web dev

simulate:
    cargo run -p constellation-node-simulator -- --controller http://127.0.0.1:4317
