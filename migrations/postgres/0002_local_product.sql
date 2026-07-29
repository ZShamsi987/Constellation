CREATE TABLE IF NOT EXISTS models (
    id TEXT PRIMARY KEY NOT NULL,
    alias TEXT UNIQUE NOT NULL,
    sha256 TEXT NOT NULL,
    format TEXT NOT NULL,
    quantization TEXT,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    manifest_json TEXT NOT NULL,
    status TEXT NOT NULL,
    pinned BIGINT NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS models_by_digest ON models(sha256);

CREATE TABLE IF NOT EXISTS runtime_instances (
    id TEXT PRIMARY KEY NOT NULL,
    adapter_id TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    runtime_version TEXT,
    model_alias TEXT REFERENCES models(alias) ON DELETE SET NULL,
    status TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    process_id BIGINT,
    endpoint TEXT,
    started_at TEXT,
    observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_conversations (
    id TEXT PRIMARY KEY NOT NULL,
    title_ciphertext BYTEA,
    temporary BIGINT NOT NULL DEFAULT 0 CHECK (temporary IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    envelope_version BIGINT NOT NULL,
    content_ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
    sequence BIGSERIAL PRIMARY KEY,
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY NOT NULL,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    acknowledged_at TEXT,
    created_at TEXT NOT NULL
);
