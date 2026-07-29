CREATE TABLE IF NOT EXISTS device_certificates (
    credential_serial TEXT PRIMARY KEY NOT NULL REFERENCES membership_credentials(serial) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    certificate_pem TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS device_certificates_by_device
ON device_certificates(device_id, expires_at DESC);
