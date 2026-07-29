# ADR 0001: Rust modular monolith

Status: Accepted

Use one Rust service with controller/worker roles and trait-separated modules. This avoids bundling a Node runtime in desktop installers, minimizes privileged languages, and preserves later service extraction. TypeScript remains the UI and SDK language.
