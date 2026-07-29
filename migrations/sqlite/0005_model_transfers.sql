CREATE TABLE IF NOT EXISTS model_transfer_tickets (
    id TEXT PRIMARY KEY NOT NULL,
    source_node_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    destination_node_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    model_sha256 TEXT NOT NULL,
    chunk_sha256 TEXT NOT NULL,
    ticket_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS model_transfer_tickets_by_destination
ON model_transfer_tickets(destination_node_id, expires_at DESC);
