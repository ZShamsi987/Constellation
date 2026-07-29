CREATE TABLE IF NOT EXISTS passkeys (
    credential_sha256 TEXT PRIMARY KEY NOT NULL CHECK (length(credential_sha256) = 64),
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passkeys_principal
    ON passkeys(principal_id, created_at);

CREATE TABLE IF NOT EXISTS browser_sessions (
    token_sha256 TEXT PRIMARY KEY NOT NULL CHECK (length(token_sha256) = 64),
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_browser_sessions_expiry
    ON browser_sessions(expires_at);
