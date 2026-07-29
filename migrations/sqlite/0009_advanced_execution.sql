CREATE TABLE IF NOT EXISTS execution_observations (
    id TEXT PRIMARY KEY NOT NULL,
    plan_id TEXT NOT NULL REFERENCES execution_plans(id) ON DELETE CASCADE,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    observation_json TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS execution_observations_plan
ON execution_observations(plan_id, observed_at);

CREATE TABLE IF NOT EXISTS execution_trace_spans (
    id TEXT PRIMARY KEY NOT NULL,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    parent_span_id TEXT,
    operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
    started_at TEXT NOT NULL,
    duration_us INTEGER NOT NULL CHECK (duration_us >= 0),
    status TEXT NOT NULL CHECK (status IN ('ok', 'error', 'cancelled')),
    attributes_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS execution_trace_spans_workload
ON execution_trace_spans(workload_id, started_at, id);
