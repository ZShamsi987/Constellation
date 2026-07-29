CREATE TABLE IF NOT EXISTS network_usage (
    cluster_id TEXT NOT NULL,
    utc_year BIGINT NOT NULL,
    utc_month BIGINT NOT NULL CHECK (utc_month BETWEEN 1 AND 12),
    observed_bytes BIGINT NOT NULL CHECK (observed_bytes >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (cluster_id, utc_year, utc_month)
);

CREATE TABLE IF NOT EXISTS network_transport_records (
    id TEXT PRIMARY KEY NOT NULL,
    cluster_id TEXT NOT NULL,
    transport_kind TEXT NOT NULL,
    remote BIGINT NOT NULL CHECK (remote IN (0, 1)),
    uses_relay BIGINT NOT NULL CHECK (uses_relay IN (0, 1)),
    estimated_bytes BIGINT NOT NULL CHECK (estimated_bytes >= 0),
    observed_bytes BIGINT NOT NULL CHECK (observed_bytes >= 0),
    created_at TEXT NOT NULL
);
