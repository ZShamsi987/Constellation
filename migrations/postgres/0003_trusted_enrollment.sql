CREATE TABLE IF NOT EXISTS enrollment_invitations (
    id TEXT PRIMARY KEY NOT NULL,
    expires_at TEXT NOT NULL,
    failed_attempts BIGINT NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
    consumed BIGINT NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
    approved BIGINT NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
    approved_at TEXT,
    requested_node_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS enrollment_invitations_by_expiry
ON enrollment_invitations(expires_at DESC);

CREATE TABLE IF NOT EXISTS membership_credentials (
    serial TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    device_public_key BYTEA NOT NULL CHECK (length(device_public_key) = 32),
    roles_json TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    protocol_min BIGINT NOT NULL,
    protocol_max BIGINT NOT NULL,
    signature BYTEA NOT NULL CHECK (length(signature) = 64),
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS membership_credentials_by_device
ON membership_credentials(device_id, expires_at DESC);
