# ADR 0009: Content-addressed model storage

Status: Accepted

Model artifacts use verified SHA-256 identities and 4 MiB resumable chunks. Manifests track source, license, format and compatibility. Unverified data never enters the active cache.
