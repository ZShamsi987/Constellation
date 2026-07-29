# ADR 0003: SQLite local, PostgreSQL server

Status: Accepted

Use SQLite WAL for zero-admin local operation and PostgreSQL for server deployments. Repository traits isolate dialect-specific queries and migrations. Do not introduce Redis as a required queue dependency.
