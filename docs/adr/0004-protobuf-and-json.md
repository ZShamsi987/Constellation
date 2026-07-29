# ADR 0004: Protobuf internally, JSON publicly

Status: Accepted

Use versioned protobuf for node and adapter protocols; use OpenAPI-described JSON for public HTTP APIs, SSE for inference, and WebSocket for live UI events. Enforce compatibility in CI.
