CREATE TABLE IF NOT EXISTS cloud_usage_reservations (
    workload_id TEXT PRIMARY KEY NOT NULL,
    policy_id TEXT NOT NULL REFERENCES cloud_adapter_policies(id) ON DELETE RESTRICT,
    reserved_cost_micros INTEGER NOT NULL CHECK (reserved_cost_micros >= 0),
    reserved_network_bytes INTEGER NOT NULL CHECK (reserved_network_bytes >= 0),
    actual_cost_micros INTEGER CHECK (actual_cost_micros IS NULL OR actual_cost_micros >= 0),
    actual_network_bytes INTEGER CHECK (actual_network_bytes IS NULL OR actual_network_bytes >= 0),
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_usage_policy_month
    ON cloud_usage_reservations(policy_id, created_at);

CREATE TABLE IF NOT EXISTS cloud_usage_locks (
    policy_id TEXT PRIMARY KEY NOT NULL REFERENCES cloud_adapter_policies(id) ON DELETE CASCADE,
    marker INTEGER NOT NULL DEFAULT 1 CHECK (marker = 1)
);
