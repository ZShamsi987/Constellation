CREATE TABLE IF NOT EXISTS worker_sessions (
    node_id TEXT PRIMARY KEY NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    last_poll_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workload_leases (
    id TEXT PRIMARY KEY NOT NULL,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    attempt BIGINT NOT NULL DEFAULT 1 CHECK (attempt BETWEEN 1 AND 2),
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'completed', 'cancelled', 'interrupted')),
    envelope_version BIGINT NOT NULL,
    input_nonce BYTEA NOT NULL CHECK (length(input_nonce) = 24),
    input_ciphertext BYTEA NOT NULL,
    maximum_output_tokens BIGINT NOT NULL CHECK (maximum_output_tokens BETWEEN 1 AND 4096),
    last_sequence BIGINT NOT NULL DEFAULT 0,
    output_started BIGINT NOT NULL DEFAULT 0 CHECK (output_started IN (0, 1)),
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS workload_leases_claim
ON workload_leases(node_id, status, created_at);
