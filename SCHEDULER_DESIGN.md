# Scheduler Design

## Contract

The scheduler is a pure deterministic function from a versioned cluster snapshot and workload requirements to either an `ExecutionPlan` or structured infeasibility. It performs no network, database, runtime, clock, or random I/O.

## Planning pipeline

1. Normalize the snapshot and reject stale, revoked, offline, or malformed entries.
2. Enforce hard privacy, trust, allowed-node, runtime, model, memory, owner-resource, cost, deadline, retention, and strategy constraints.
3. Enumerate single-node, independent-routing, and replica candidates for 0.1.
4. Estimate model fit, queue time, load time, TTFT, tokens/second, network traffic, reliability, power, and thermal risk.
5. Score interactive work primarily by TTFT and inter-token latency; score batch work primarily by completion throughput and deadline risk.
6. Select the lowest-risk feasible score, retain considered alternatives, and produce explanations and replanning triggers.

## Memory policy

Usable system memory subtracts the larger of 15% or 2 GiB. Usable accelerator memory subtracts the larger of 10% or 512 MiB. Node-owner configuration can reserve more. Estimated model, KV cache, runtime overhead, batch, and input buffers must fit separately; shared memory is not double counted.

## Confidence

Confidence decreases with missing or stale benchmarks, model/runtime version mismatch, estimated rather than measured capabilities, unstable links, thermal throttling, and sparse historical samples. Low confidence is visible and may trigger a conservative single-node plan.

## Explanations

Plans include strategy, nodes, runtime, estimates, budgets, reasons, rejected alternatives, confidence, privacy path, and triggers. Simple explanations avoid distributed terminology; engineering output retains numeric factors and constraint codes.

## Learning

Store prediction and actual metadata separately from the planner. Calibration produces versioned coefficients only after minimum sample and regression checks; planner inputs always identify the coefficient version, preserving reproducibility.

## Failure semantics

Replan before execution when prerequisites change. Retry once transparently only before first output and only for an idempotent request. After output, return `generation_interrupted` with partial output. A later attempt is restarted. Batch resume requires an adapter-declared verified checkpoint.
