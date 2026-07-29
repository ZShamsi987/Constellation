# AGENTS.md

These instructions apply to the entire repository.

## Product invariants

- Preserve local-first operation and secure defaults.
- Do not log prompts, outputs, secrets, file contents, or private model locations.
- Bind runtime subprocesses to loopback and authenticate them.
- Treat privacy, trust, resource, and capability rules as hard scheduler constraints.
- Describe interrupted generation accurately; never call a restart a resume.
- Reject unsupported features explicitly.

## Ownership boundaries

- `crates/constellation-core`: shared domain types only; no runtime- or UI-specific behavior.
- `crates/constellation-scheduler`: deterministic planning; no I/O.
- `crates/constellation-runtime`: adapter contracts and runtime implementations.
- `apps/constellationd`: orchestration, persistence, and public APIs.
- `apps/web`: product UI; it may not enforce security rules by itself.
- `protocol` and `openapi`: contract-owner review required.

Agents working in parallel must claim disjoint paths, coordinate shared contract edits before coding, and avoid modifying generated files unless they own the source schema. Do not overwrite unrelated or user-authored changes.

## Verification

Run targeted tests while iterating and `just check` before handoff. Security-sensitive changes also require negative tests. Formatting commands may not rewrite unrelated files.
