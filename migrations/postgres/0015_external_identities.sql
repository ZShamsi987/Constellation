CREATE TABLE IF NOT EXISTS external_identities (
    provider_id TEXT NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    subject_sha256 TEXT NOT NULL CHECK (length(subject_sha256) = 64),
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (provider_id, subject_sha256)
);

CREATE INDEX IF NOT EXISTS idx_external_identities_principal
    ON external_identities(principal_id, provider_id);
