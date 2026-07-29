# ADR 0008: Deterministic scheduler

Status: Accepted

The planner is a pure function. Hard constraints precede scoring; plans retain alternatives, confidence and evidence. Calibration coefficients are versioned inputs rather than hidden mutable state.
