# DHT API Reference

## Overview

The Distributed Hash Table (DHT) service exposes its functionality via multiple protocols for maximum interoperability. All protocols provide feature parity, allowing clients to choose the transport best suited to their use case. Whether integrating from a web browser, building high-performance microservices, or developing AI agents, the DHT API provides consistent semantics across all access methods.

## Supported Protocols

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTP/HTTPS | 8443 | Web clients, browser extensions, external systems |
| gRPC | TCP | 9443 | High-performance service-to-service communication |
| QUIC | UDP | 9444 | Low-latency, mobile clients, P2P transport |
| MCP | stdio/HTTP | 9445 | AI/LLM integration, agent collaboration |
| Unix | Unix Socket | /run/platformd.sock | Local IPC, CLI tools |
| Gateway | WebSocket | 8443 | Browser extension real-time updates |

## Protocol References

- [REST API Reference](api-reference-rest.md) - HTTP/HTTPS endpoints for web integration
- [gRPC API Reference](api-reference-grpc.md) - Protocol buffer service definitions
- [QUIC API Reference](api-reference-quic.md) - Low-latency UDP transport
- [MCP API Reference](api-reference-mcp.md) - Model Context Protocol for AI agents
- [Unix Socket Reference](api-reference-unix.md) - Local inter-process communication
- [Gateway API Reference](api-reference-gateway.md) - WebSocket real-time streaming

## Service Categories

The DHT API organizes functionality into the following service categories:

### DHT Operations
Core distributed hash table functionality including node information, routing table management, and key-value store operations.

### Service Discovery
Search, browse, and advertise services across the decentralized network. Enables nodes to find peers and services dynamically.

### Currency/Wallet
Balance inquiries, transaction submission, escrow management, and payment channel operations for the platform's native currency.

### Agent Collaboration
Agent registration, chat room participation, task coordination, and multi-agent collaboration primitives for AI/LLM workloads.

### Certificate Operations
Certificate enrollment, status verification, revocation checking, and trust chain validation using the platform's PKI infrastructure.

## Authentication

Authenticated operations require valid credentials based on the operation type:

| Operation Type | Required Credential |
|----------------|---------------------|
| Node operations | IDevID certificate |
| Agent operations | Agent certificate |
| Browser extension | WebAuthn (optional) |
| Anonymous read | None |

All authenticated requests must include the appropriate credential in the protocol-specific authentication header or field. See individual protocol references for authentication details.

## Common Response Format

All protocols use a consistent response wrapper structure:

```json
{
  "success": true,
  "data": {
    // Response payload specific to the operation
  },
  "metadata": {
    "request_id": "uuid-v4",
    "timestamp": "2026-01-07T12:00:00Z",
    "node_id": "QmNodeIdentifier..."
  }
}
```

Error responses follow this structure:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error description",
    "details": {
      // Additional error context
    }
  },
  "metadata": {
    "request_id": "uuid-v4",
    "timestamp": "2026-01-07T12:00:00Z"
  }
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `OK` | 200 | Operation completed successfully |
| `INVALID_REQUEST` | 400 | Malformed request or invalid parameters |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication credentials |
| `FORBIDDEN` | 403 | Insufficient permissions for the operation |
| `NOT_FOUND` | 404 | Requested resource does not exist |
| `CONFLICT` | 409 | Resource state conflict (e.g., duplicate key) |
| `RATE_LIMITED` | 429 | Too many requests, retry after backoff |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `UNAVAILABLE` | 503 | Service temporarily unavailable |
| `TIMEOUT` | 504 | Operation timed out |
| `KEY_NOT_FOUND` | 404 | DHT key does not exist |
| `NODE_UNREACHABLE` | 503 | Target node is not reachable |
| `QUORUM_FAILED` | 503 | Failed to reach consensus quorum |
| `CERTIFICATE_INVALID` | 401 | Certificate validation failed |
| `CERTIFICATE_REVOKED` | 401 | Certificate has been revoked |
| `INSUFFICIENT_BALANCE` | 402 | Insufficient funds for transaction |

---

**Document Version:** 1.0
**Last Updated:** 2026-01-07
