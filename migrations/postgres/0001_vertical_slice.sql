
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    os TEXT NOT NULL,
    architecture TEXT NOT NULL,
    status TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_local BIGINT NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS devices_one_local
ON devices(is_local) WHERE is_local = 1;

CREATE TABLE IF NOT EXISTS benchmarks (
    node_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    report_json TEXT NOT NULL,
    measured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workloads (
    id TEXT PRIMARY KEY NOT NULL,
    model TEXT NOT NULL,
    runtime TEXT NOT NULL,
    class TEXT NOT NULL,
    policy TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS execution_plans (
    id TEXT PRIMARY KEY NOT NULL,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS execution_plans_by_workload
ON execution_plans(workload_id, created_at DESC);

CREATE TABLE IF NOT EXISTS events (
    sequence BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    sequence BIGINT PRIMARY KEY REFERENCES events(sequence) ON DELETE CASCADE,
    delivered_at TEXT
);
