# Plugin Specification

Plugins are not enabled in release 0.1. This contract prevents early extension points from becoming unsandboxed host code.

## Types

Runtime adapter, model source, authentication, storage, scheduler strategy, workload, agent tool, UI extension, metrics exporter, notification, cloud provider, and hardware detector.

## Manifest

Each plugin declares ID, publisher, version, compatible host/protocol range, platforms, entry component, configuration schema, health check, permissions, network domains, filesystem paths, secret names, resource limits, and data classifications.

## Execution model

General plugins use WASI components hosted by Wasmtime with no network, filesystem, environment, clock precision, or secret access unless explicitly granted. Runtime adapters remain supervised sidecars because accelerator ecosystems may require native processes. UI extensions are declarative or sandboxed origins with strict CSP; arbitrary scripts cannot join the privileged desktop context.

## Lifecycle and trust

Install verifies hashes/signatures, displays permissions, and records attribution. Enable, update, revoke, quarantine, and remove are audited. Compatibility is checked before loading. Repeated crashes, limit violations, invalid output, or revoked signing identities quarantine the plugin.

## Scheduler plugins

External strategies may propose candidates but cannot bypass host hard constraints. The core validator rechecks every returned plan.
