CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY NOT NULL,
    version TEXT NOT NULL,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    manifest_json TEXT NOT NULL,
    component_path TEXT NOT NULL,
    enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    installed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugin_grants (
    plugin_id TEXT PRIMARY KEY NOT NULL REFERENCES plugins(id) ON DELETE CASCADE,
    component_sha256 TEXT NOT NULL CHECK (length(component_sha256) = 64),
    grant_json TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer', 'node', 'service')),
    scopes_json TEXT NOT NULL,
    api_key_sha256 TEXT UNIQUE,
    active BIGINT NOT NULL CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS team_memberships (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer', 'service')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (team_id, principal_id)
);

CREATE TABLE IF NOT EXISTS auth_providers (
    id TEXT PRIMARY KEY NOT NULL,
    provider_json TEXT NOT NULL,
    enabled BIGINT NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_adapter_policies (
    id TEXT PRIMARY KEY NOT NULL,
    policy_json TEXT NOT NULL,
    enabled BIGINT NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS controller_leases (
    singleton BIGINT PRIMARY KEY NOT NULL CHECK (singleton = 1),
    controller_id TEXT NOT NULL,
    term BIGINT NOT NULL CHECK (term >= 1),
    fencing_token BIGINT NOT NULL CHECK (fencing_token >= 1),
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
