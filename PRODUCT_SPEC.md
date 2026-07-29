# Product Specification

## Promise

Constellation turns computers controlled by one trusted owner or group into one private AI compute pool. Users submit work to a single endpoint; Constellation chooses a safe execution plan, explains it, and declines distribution when it would be slower or violate policy.

## Release 0.1 outcome

A user can install Constellation on tier-1 Windows, macOS, and Linux systems, create a cluster, enroll a second trusted computer, inspect normalized hardware, run fast benchmarks, detect or configure a runtime, add a model, stream chat through one OpenAI-compatible endpoint, route independent requests across nodes, preserve local responsiveness, revoke a node, reroute new work after failure, and export a benchmark report.

## Product principles

1. Local-only is a complete product state, not a degraded cloud client.
2. Privacy, trust, capability, cost, and owner resource limits are hard constraints.
3. Distribution must show measurable benefit or solve a fit constraint.
4. Simple Mode describes outcomes; Engineering Mode exposes evidence.
5. Estimates are labeled and compared with actual results.
6. Partial failure is visible, recoverable, and described precisely.

## Initial workloads

Chat completions, text completions, Responses-style text/tool interactions, embeddings, deterministic test jobs, and batch request routing. Each workload carries priority, privacy, deadline, resource and cost limits, allowed nodes, runtime requirements, retention, retry, cancellation, and interactive/batch classification.

## Modes

Simple Mode focuses on Add Computer, Choose Model, Start Chatting, View Cluster, Activity, and high-level policies. Engineering Mode adds topology, normalized capabilities, measurements, runtime/model placement, queues, plans, traces, failures, manual constraints, and exports.

## Non-goals for 0.1

Remote strangers, public marketplaces, paid cloud bursting, training frontier models, custom inference engines, guaranteed privacy on untrusted hardware, advanced distributed inference without adapter support, and automatic multi-controller HA.

## Success measures

The leading measure is completion of a useful two-node workload within five minutes without editing configuration. Supporting measures include enrollment completion, scheduler estimate error, request success, failover of new requests, crash-free sessions, update success, and the percentage of workloads for which clustering provides measured benefit.
