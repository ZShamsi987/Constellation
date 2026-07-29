# ADR 0005: Authenticated local-first network

Status: Accepted

Nodes initiate mTLS control connections. Peer data uses authenticated QUIC and narrow tickets. Discovery reveals only opaque enrollment metadata. Remote relay is deferred and disabled by default.
