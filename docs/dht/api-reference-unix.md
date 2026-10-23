# DHT Unix Socket API Reference

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

## Overview

The Unix socket interface provides high-performance local IPC (Inter-Process Communication) for the DHT service. This transport is optimized for:

- **CLI tools** - `platformctl` uses the socket for all local operations
- **Local services** - System daemons and background services
- **Privileged operations** - Administrative commands requiring elevated permissions
- **Low-latency communication** - Zero network overhead for local processes

## Socket Configuration

### Socket Path

```
/run/platformd.sock
```

### Connection Properties

| Property | Value |
|----------|-------|
| Type | Unix domain socket (SOCK_STREAM) |
| Permissions | 0660 (owner/group read-write) |
| Owner | root |
| Group | platform |
| Max Connections | 1024 |
| Buffer Size | 64KB |

### Security Model

- Socket file permissions restrict access to owner and `platform` group members
- Peer credentials (UID/GID/PID) are verified on connection
- Administrative operations require root or `platform` group membership
- Connection attempts from unauthorized users are rejected with `EACCES`

## Protocol Specification

The Unix socket interface uses **JSON-RPC 2.0** as the wire protocol.

### Protocol Properties

| Property | Value |
|----------|-------|
| Encoding | JSON (UTF-8) |
| Framing | Length-prefixed (4-byte big-endian header) |
| Version | JSON-RPC 2.0 |
| Concurrency | Full duplex, multiplexed requests |

### Message Framing

Each message is prefixed with a 4-byte big-endian length header:

```
+----------------+------------------+
| Length (4 bytes) | JSON-RPC Message |
+----------------+------------------+
```

## Request Format

All requests follow the JSON-RPC 2.0 specification:

```json
{
  "jsonrpc": "2.0",
  "method": "namespace.operation",
  "params": {
    "param1": "value1",
    "param2": "value2"
  },
  "id": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| jsonrpc | string | Yes | Must be "2.0" |
| method | string | Yes | Method name in `namespace.operation` format |
| params | object | No | Method parameters |
| id | integer/string | Yes | Request identifier for correlation |

## Response Format

### Success Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "data": "...",
    "metadata": {}
  },
  "id": 1
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Error description",
    "data": {
      "details": "Additional context"
    }
  },
  "id": 1
}
```

## Standardized Error Codes

All API endpoints use a unified error code system across REST, gRPC, MCP, and Unix Socket protocols:

| Code | REST | gRPC | MCP | Unix Socket (JSON-RPC) | Description |
|------|------|------|-----|------------------------|-------------|
| NODE_NOT_FOUND | 404 | NOT_FOUND (5) | null + error | -32000 | Node ID not in DHT |
| UNAUTHORIZED | 401 | UNAUTHENTICATED (16) | error: "unauthorized" | -32005 | Missing/invalid auth |
| FORBIDDEN | 403 | PERMISSION_DENIED (7) | error: "forbidden" | -32005 | Insufficient trust level |
| RATE_LIMITED | 429 | RESOURCE_EXHAUSTED (8) | error: "rate_limited" | -32006 | Rate limit exceeded |
| INVALID_REQUEST | 400 | INVALID_ARGUMENT (3) | error: "invalid_request" | -32602 | Malformed request |
| INTERNAL_ERROR | 500 | INTERNAL (13) | error: "internal" | -32603 | Server error |
| UNAVAILABLE | 503 | UNAVAILABLE (14) | error: "unavailable" | -32007 | Service temporarily down |

---

## Rate Limiting

Unix socket connections have higher rate limits due to local-only access:

| User/Group | Requests/min | Burst | Notes |
|------------|--------------|-------|-------|
| root | Unlimited | Unlimited | Full admin access |
| platform group | 1000 | 2000 | Service accounts |
| Other users | 100 | 200 | Standard local access |

Rate limits enforced per UID/GID pair.

---

## Authentication Requirements

**Public Methods (no auth required):**
- dht.getNode
- dht.listNodes
- discovery.search
- discovery.get

**Authenticated Methods (require platform group or root):**
- All write operations
- wallet.*
- admin.*
- cert.revoke

**Trust Level Requirements:**

Unix socket authentication is based on OS-level credentials (UID/GID), not DHT trust levels. However, operations that interact with the DHT network still respect node trust levels for network participation.

---

## Error Codes

### Standard JSON-RPC Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON received |
| -32600 | Invalid Request | Request object is invalid |
| -32601 | Method not found | Method does not exist |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal JSON-RPC error |

### DHT-Specific Errors

| Code | Message | Description |
|------|---------|-------------|
| -32000 | Node not found | Requested node does not exist |
| -32001 | Key not found | Requested key not in DHT |
| -32002 | Store failed | Failed to store value |
| -32003 | Routing error | Routing table operation failed |
| -32004 | Timeout | Operation timed out |
| -32005 | Unauthorized | Insufficient permissions |
| -32006 | Rate limited | Too many requests |
| -32007 | Service unavailable | Service temporarily unavailable |

## Methods

### DHT Operations

#### dht.getNode

Get detailed information about a specific node.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| node_id | string | Yes | Base58-encoded node ID |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.getNode",
  "params": {
    "node_id": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
  },
  "id": 1
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "node_id": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
    "addresses": ["/ip4/192.0.2.10/tcp/4001"],
    "public_key": "CAASXjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC...",
    "last_seen": "2026-01-07T10:30:00Z",
    "latency_ms": 5,
    "status": "active"
  },
  "id": 1
}
```

#### dht.listNodes

List all known nodes in the routing table.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| bucket | integer | No | Filter by k-bucket index |
| limit | integer | No | Maximum nodes to return (default: 100) |
| offset | integer | No | Pagination offset |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.listNodes",
  "params": {
    "limit": 50,
    "offset": 0
  },
  "id": 2
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "nodes": [
      {
        "node_id": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
        "addresses": ["/ip4/192.0.2.10/tcp/4001"],
        "last_seen": "2026-01-07T10:30:00Z",
        "status": "active"
      }
    ],
    "total": 150,
    "limit": 50,
    "offset": 0
  },
  "id": 2
}
```

#### dht.getRouting

Get the current routing table state.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| include_nodes | boolean | No | Include node details (default: false) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.getRouting",
  "params": {
    "include_nodes": true
  },
  "id": 3
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "local_id": "QmLocalNodeID...",
    "buckets": [
      {
        "index": 0,
        "size": 20,
        "max_size": 20,
        "nodes": ["QmNode1...", "QmNode2..."]
      }
    ],
    "total_nodes": 256,
    "last_refresh": "2026-01-07T10:00:00Z"
  },
  "id": 3
}
```

#### dht.store

Store a key-value pair in the DHT.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| key | string | Yes | Key identifier |
| value | string | Yes | Base64-encoded value |
| ttl | integer | No | Time-to-live in seconds |
| replication | integer | No | Replication factor (default: 3) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.store",
  "params": {
    "key": "myapp/config/v1",
    "value": "eyJzZXR0aW5ncyI6IHt9fQ==",
    "ttl": 3600,
    "replication": 3
  },
  "id": 4
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "key": "myapp/config/v1",
    "stored_at": ["QmNode1...", "QmNode2...", "QmNode3..."],
    "expires_at": "2026-01-07T11:30:00Z"
  },
  "id": 4
}
```

#### dht.get

Retrieve a value by key from the DHT.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| key | string | Yes | Key to retrieve |
| quorum | integer | No | Minimum nodes to query (default: 1) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.get",
  "params": {
    "key": "myapp/config/v1"
  },
  "id": 5
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "key": "myapp/config/v1",
    "value": "eyJzZXR0aW5ncyI6IHt9fQ==",
    "version": 1,
    "created_at": "2026-01-07T10:30:00Z",
    "expires_at": "2026-01-07T11:30:00Z",
    "source_node": "QmNode1..."
  },
  "id": 5
}
```

#### dht.delete

Delete a key from the DHT.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| key | string | Yes | Key to delete |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "dht.delete",
  "params": {
    "key": "myapp/config/v1"
  },
  "id": 6
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "key": "myapp/config/v1",
    "deleted": true,
    "nodes_notified": 3
  },
  "id": 6
}
```

### Service Discovery Operations

#### discovery.search

Search for services matching criteria.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| service_type | string | No | Service type filter |
| tags | array | No | Tag filters |
| limit | integer | No | Maximum results (default: 20) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "discovery.search",
  "params": {
    "service_type": "database",
    "tags": ["postgresql", "primary"],
    "limit": 10
  },
  "id": 7
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "services": [
      {
        "service_id": "svc-abc123",
        "name": "postgresql-primary",
        "type": "database",
        "endpoint": "/ip4/10.0.1.50/tcp/5432",
        "tags": ["postgresql", "primary"],
        "health": "healthy",
        "metadata": {"version": "15.2"}
      }
    ],
    "total": 1
  },
  "id": 7
}
```

#### discovery.get

Get detailed service information.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| service_id | string | Yes | Service identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "discovery.get",
  "params": {
    "service_id": "svc-abc123"
  },
  "id": 8
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "service_id": "svc-abc123",
    "name": "postgresql-primary",
    "type": "database",
    "endpoints": [
      "/ip4/10.0.1.50/tcp/5432",
      "/ip6/::1/tcp/5432"
    ],
    "tags": ["postgresql", "primary"],
    "health": "healthy",
    "registered_at": "2026-01-01T00:00:00Z",
    "last_health_check": "2026-01-07T10:29:00Z",
    "metadata": {
      "version": "15.2",
      "max_connections": 100
    }
  },
  "id": 8
}
```

#### discovery.advertise

Advertise a service to the network.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Service name |
| type | string | Yes | Service type |
| endpoints | array | Yes | Service endpoints |
| tags | array | No | Service tags |
| metadata | object | No | Additional metadata |
| ttl | integer | No | Advertisement TTL in seconds |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "discovery.advertise",
  "params": {
    "name": "my-api-server",
    "type": "http",
    "endpoints": ["/ip4/0.0.0.0/tcp/8080"],
    "tags": ["api", "v2"],
    "metadata": {"version": "2.1.0"},
    "ttl": 300
  },
  "id": 9
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "service_id": "svc-def456",
    "advertised": true,
    "expires_at": "2026-01-07T10:35:00Z"
  },
  "id": 9
}
```

#### discovery.remove

Remove a service advertisement.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| service_id | string | Yes | Service identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "discovery.remove",
  "params": {
    "service_id": "svc-def456"
  },
  "id": 10
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "service_id": "svc-def456",
    "removed": true
  },
  "id": 10
}
```

### Wallet Operations

#### wallet.getBalance

Get wallet balance for an address.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| address | string | No | Wallet address (default: local wallet) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "wallet.getBalance",
  "params": {},
  "id": 11
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "0x1234567890abcdef...",
    "balance": "1000.50",
    "currency": "TRUST",
    "pending_in": "0.00",
    "pending_out": "50.00",
    "last_updated": "2026-01-07T10:30:00Z"
  },
  "id": 11
}
```

#### wallet.transfer

Transfer funds to another address.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| to | string | Yes | Recipient address |
| amount | string | Yes | Amount to transfer |
| memo | string | No | Transaction memo |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "wallet.transfer",
  "params": {
    "to": "0xrecipient...",
    "amount": "100.00",
    "memo": "Payment for services"
  },
  "id": 12
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "transaction_id": "tx-789abc",
    "from": "0x1234567890abcdef...",
    "to": "0xrecipient...",
    "amount": "100.00",
    "fee": "0.01",
    "status": "pending",
    "created_at": "2026-01-07T10:30:00Z"
  },
  "id": 12
}
```

#### wallet.getHistory

Get transaction history.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | integer | No | Maximum transactions (default: 50) |
| offset | integer | No | Pagination offset |
| direction | string | No | "in", "out", or "all" (default: "all") |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "wallet.getHistory",
  "params": {
    "limit": 20,
    "direction": "out"
  },
  "id": 13
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "transactions": [
      {
        "transaction_id": "tx-789abc",
        "type": "transfer",
        "direction": "out",
        "from": "0x1234567890abcdef...",
        "to": "0xrecipient...",
        "amount": "100.00",
        "fee": "0.01",
        "status": "confirmed",
        "created_at": "2026-01-07T10:30:00Z",
        "confirmed_at": "2026-01-07T10:31:00Z"
      }
    ],
    "total": 150,
    "limit": 20,
    "offset": 0
  },
  "id": 13
}
```

### Agent Operations

#### agent.register

Register an agent on the network.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Agent name |
| capabilities | array | Yes | Agent capabilities |
| pricing | object | No | Pricing information |
| metadata | object | No | Additional metadata |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "agent.register",
  "params": {
    "name": "code-review-agent",
    "capabilities": ["code-review", "security-audit", "golang"],
    "pricing": {
      "per_request": "1.00",
      "currency": "TRUST"
    },
    "metadata": {
      "version": "1.0.0",
      "description": "Expert code review agent"
    }
  },
  "id": 14
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "agent_id": "agent-xyz789",
    "registered": true,
    "expires_at": "2026-01-14T10:30:00Z"
  },
  "id": 14
}
```

#### agent.get

Get agent information.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string | Yes | Agent identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "agent.get",
  "params": {
    "agent_id": "agent-xyz789"
  },
  "id": 15
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "agent_id": "agent-xyz789",
    "name": "code-review-agent",
    "owner": "0x1234567890abcdef...",
    "capabilities": ["code-review", "security-audit", "golang"],
    "pricing": {
      "per_request": "1.00",
      "currency": "TRUST"
    },
    "reputation": {
      "score": 4.8,
      "reviews": 150
    },
    "status": "available",
    "registered_at": "2026-01-01T00:00:00Z"
  },
  "id": 15
}
```

#### agent.search

Search for agents by capabilities.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| capabilities | array | No | Required capabilities |
| min_reputation | number | No | Minimum reputation score |
| max_price | string | No | Maximum price per request |
| limit | integer | No | Maximum results (default: 20) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "agent.search",
  "params": {
    "capabilities": ["code-review"],
    "min_reputation": 4.0,
    "limit": 10
  },
  "id": 16
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "agents": [
      {
        "agent_id": "agent-xyz789",
        "name": "code-review-agent",
        "capabilities": ["code-review", "security-audit", "golang"],
        "reputation": {"score": 4.8, "reviews": 150},
        "pricing": {"per_request": "1.00", "currency": "TRUST"},
        "status": "available"
      }
    ],
    "total": 25
  },
  "id": 16
}
```

#### agent.hire

Hire an agent for a task.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| agent_id | string | Yes | Agent to hire |
| task | object | Yes | Task specification |
| budget | string | No | Maximum budget |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "agent.hire",
  "params": {
    "agent_id": "agent-xyz789",
    "task": {
      "type": "code-review",
      "input": "https://github.com/org/repo/pull/123",
      "requirements": ["security", "performance"]
    },
    "budget": "10.00"
  },
  "id": 17
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "contract_id": "contract-abc123",
    "agent_id": "agent-xyz789",
    "status": "accepted",
    "estimated_cost": "5.00",
    "estimated_completion": "2026-01-07T12:00:00Z"
  },
  "id": 17
}
```

### Chat Room Operations

#### room.create

Create a new chat room.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Room name |
| type | string | No | "public" or "private" (default: "public") |
| max_members | integer | No | Maximum members (default: 100) |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "room.create",
  "params": {
    "name": "project-discussion",
    "type": "private",
    "max_members": 50
  },
  "id": 18
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "room_id": "room-abc123",
    "name": "project-discussion",
    "type": "private",
    "owner": "QmLocalNodeID...",
    "created_at": "2026-01-07T10:30:00Z"
  },
  "id": 18
}
```

#### room.join

Join an existing chat room.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| room_id | string | Yes | Room identifier |
| invite_code | string | No | Invite code for private rooms |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "room.join",
  "params": {
    "room_id": "room-abc123"
  },
  "id": 19
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "room_id": "room-abc123",
    "joined": true,
    "member_count": 15
  },
  "id": 19
}
```

#### room.leave

Leave a chat room.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| room_id | string | Yes | Room identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "room.leave",
  "params": {
    "room_id": "room-abc123"
  },
  "id": 20
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "room_id": "room-abc123",
    "left": true
  },
  "id": 20
}
```

#### room.send

Send a message to a chat room.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| room_id | string | Yes | Room identifier |
| content | string | Yes | Message content |
| reply_to | string | No | Message ID to reply to |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "room.send",
  "params": {
    "room_id": "room-abc123",
    "content": "Hello, team!"
  },
  "id": 21
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "message_id": "msg-xyz789",
    "room_id": "room-abc123",
    "sent_at": "2026-01-07T10:30:00Z"
  },
  "id": 21
}
```

#### room.getMessages

Get messages from a chat room.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| room_id | string | Yes | Room identifier |
| limit | integer | No | Maximum messages (default: 50) |
| before | string | No | Get messages before this ID |
| after | string | No | Get messages after this ID |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "room.getMessages",
  "params": {
    "room_id": "room-abc123",
    "limit": 20
  },
  "id": 22
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "messages": [
      {
        "message_id": "msg-xyz789",
        "sender": "QmSenderNodeID...",
        "content": "Hello, team!",
        "sent_at": "2026-01-07T10:30:00Z"
      }
    ],
    "has_more": true
  },
  "id": 22
}
```

### Task Operations

#### task.create

Create a distributed task.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| type | string | Yes | Task type |
| input | object | Yes | Task input data |
| parallelism | integer | No | Number of parallel workers |
| timeout | integer | No | Task timeout in seconds |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "task.create",
  "params": {
    "type": "map-reduce",
    "input": {
      "data_source": "dht://dataset/large-file",
      "mapper": "word-count",
      "reducer": "sum"
    },
    "parallelism": 10,
    "timeout": 3600
  },
  "id": 23
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "task-abc123",
    "status": "pending",
    "subtasks": 10,
    "created_at": "2026-01-07T10:30:00Z"
  },
  "id": 23
}
```

#### task.get

Get task status and progress.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| task_id | string | Yes | Task identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "task.get",
  "params": {
    "task_id": "task-abc123"
  },
  "id": 24
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "task-abc123",
    "type": "map-reduce",
    "status": "running",
    "progress": {
      "total_subtasks": 10,
      "completed": 7,
      "failed": 0,
      "pending": 3
    },
    "created_at": "2026-01-07T10:30:00Z",
    "started_at": "2026-01-07T10:30:05Z"
  },
  "id": 24
}
```

#### task.submitResult

Submit a subtask result.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| task_id | string | Yes | Task identifier |
| subtask_id | string | Yes | Subtask identifier |
| result | object | Yes | Subtask result |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "task.submitResult",
  "params": {
    "task_id": "task-abc123",
    "subtask_id": "subtask-001",
    "result": {
      "word_counts": {"hello": 100, "world": 50}
    }
  },
  "id": 25
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "accepted": true,
    "subtask_id": "subtask-001"
  },
  "id": 25
}
```

#### task.getResult

Get aggregated task result.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| task_id | string | Yes | Task identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "task.getResult",
  "params": {
    "task_id": "task-abc123"
  },
  "id": 26
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "task-abc123",
    "status": "completed",
    "result": {
      "total_words": 10000,
      "unique_words": 1500,
      "top_words": [
        {"word": "the", "count": 500},
        {"word": "and", "count": 300}
      ]
    },
    "completed_at": "2026-01-07T11:00:00Z"
  },
  "id": 26
}
```

### Certificate Operations

#### cert.enroll

Start ACME certificate enrollment.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| domain | string | Yes | Domain name |
| challenge_type | string | No | "http-01", "dns-01", or "tls-alpn-01" |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "cert.enroll",
  "params": {
    "domain": "example.com",
    "challenge_type": "dns-01"
  },
  "id": 27
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "enrollment_id": "enroll-abc123",
    "domain": "example.com",
    "challenge": {
      "type": "dns-01",
      "token": "_acme-challenge.example.com",
      "value": "abc123def456..."
    },
    "expires_at": "2026-01-08T10:30:00Z"
  },
  "id": 27
}
```

#### cert.status

Get enrollment status.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| enrollment_id | string | Yes | Enrollment identifier |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "cert.status",
  "params": {
    "enrollment_id": "enroll-abc123"
  },
  "id": 28
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "enrollment_id": "enroll-abc123",
    "domain": "example.com",
    "status": "valid",
    "certificate": {
      "serial": "ABC123...",
      "not_before": "2026-01-07T00:00:00Z",
      "not_after": "2026-04-07T00:00:00Z"
    }
  },
  "id": 28
}
```

#### cert.revoke

Revoke a certificate.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Certificate serial number |
| reason | string | No | Revocation reason |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "cert.revoke",
  "params": {
    "serial": "ABC123...",
    "reason": "keyCompromise"
  },
  "id": 29
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "serial": "ABC123...",
    "revoked": true,
    "revoked_at": "2026-01-07T10:30:00Z"
  },
  "id": 29
}
```

### Administration Operations (Privileged)

These operations require root privileges or membership in the `platform` group.

#### admin.nodeStatus

Get comprehensive node status.

**Parameters:** None

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "admin.nodeStatus",
  "params": {},
  "id": 30
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "node_id": "QmLocalNodeID...",
    "version": "1.0.0",
    "uptime_seconds": 86400,
    "connections": {
      "inbound": 50,
      "outbound": 25,
      "max": 500
    },
    "routing": {
      "total_nodes": 256,
      "buckets_used": 20
    },
    "storage": {
      "keys_stored": 10000,
      "disk_usage_mb": 500
    },
    "memory": {
      "allocated_mb": 256,
      "system_mb": 8192
    }
  },
  "id": 30
}
```

#### admin.metrics

Get performance metrics.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| period | string | No | Time period ("1m", "5m", "1h", "24h") |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "admin.metrics",
  "params": {
    "period": "1h"
  },
  "id": 31
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "period": "1h",
    "requests": {
      "total": 50000,
      "success": 49500,
      "errors": 500
    },
    "latency": {
      "p50_ms": 5,
      "p95_ms": 25,
      "p99_ms": 100
    },
    "bandwidth": {
      "in_bytes": 104857600,
      "out_bytes": 209715200
    },
    "dht": {
      "stores_per_second": 100,
      "lookups_per_second": 500
    }
  },
  "id": 31
}
```

#### admin.shutdown

Initiate graceful shutdown.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| timeout | integer | No | Shutdown timeout in seconds (default: 30) |
| force | boolean | No | Force immediate shutdown |

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "admin.shutdown",
  "params": {
    "timeout": 60
  },
  "id": 32
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "shutting_down",
    "timeout": 60,
    "active_connections": 75
  },
  "id": 32
}
```

## CLI Usage Examples

The `platformctl` command-line tool uses the Unix socket by default for local operations.

### Basic Commands

```bash
# Get local node information
platformctl dht node info

# List nodes in routing table
platformctl dht node list --limit 50

# Store a value
platformctl dht store mykey "myvalue" --ttl 3600

# Get a value
platformctl dht get mykey

# Delete a key
platformctl dht delete mykey
```

### Service Discovery

```bash
# Search for services
platformctl discovery search --type database --tags postgresql

# Get service details
platformctl discovery get svc-abc123

# Advertise a service
platformctl discovery advertise \
  --name my-api \
  --type http \
  --endpoint /ip4/0.0.0.0/tcp/8080 \
  --tags api,v2

# Remove advertisement
platformctl discovery remove svc-def456
```

### Wallet Operations

```bash
# Check balance
platformctl wallet balance

# Transfer funds
platformctl wallet transfer 0xrecipient... 100.00 --memo "Payment"

# View transaction history
platformctl wallet history --limit 20
```

### Agent Operations

```bash
# Register an agent
platformctl agent register \
  --name code-review-agent \
  --capabilities code-review,security-audit \
  --price 1.00

# Search for agents
platformctl agent search --capability code-review --min-reputation 4.0

# Hire an agent
platformctl agent hire agent-xyz789 --task-file task.json
```

### Chat Room Operations

```bash
# Create a room
platformctl room create project-discussion --type private

# Join a room
platformctl room join room-abc123

# Send a message
platformctl room send room-abc123 "Hello, team!"

# Get messages
platformctl room messages room-abc123 --limit 20
```

### Administration (requires privileges)

```bash
# Full node status (requires sudo or platform group)
sudo platformctl admin status

# Performance metrics
sudo platformctl admin metrics --period 1h

# Graceful shutdown
sudo platformctl admin shutdown --timeout 60
```

### Environment Variables

```bash
# Override socket path
export PLATFORMD_SOCKET=/run/custom.sock
platformctl dht node info

# Enable debug output
export PLATFORMCTL_DEBUG=1
platformctl dht get mykey
```

### Output Formats

```bash
# JSON output (default)
platformctl dht node info --output json

# Table format
platformctl dht node list --output table

# YAML format
platformctl dht node info --output yaml

# Quiet mode (minimal output)
platformctl dht store key value --quiet
```

## Connection Examples

### Go Client

```go
package main

import (
    "context"
    "encoding/binary"
    "encoding/json"
    "net"
)

type JSONRPCRequest struct {
    JSONRPC string      `json:"jsonrpc"`
    Method  string      `json:"method"`
    Params  interface{} `json:"params,omitempty"`
    ID      int         `json:"id"`
}

type JSONRPCResponse struct {
    JSONRPC string          `json:"jsonrpc"`
    Result  json.RawMessage `json:"result,omitempty"`
    Error   *RPCError       `json:"error,omitempty"`
    ID      int             `json:"id"`
}

type RPCError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

func main() {
    conn, err := net.Dial("unix", "/run/platformd.sock")
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    // Create request
    req := JSONRPCRequest{
        JSONRPC: "2.0",
        Method:  "dht.getNode",
        Params:  map[string]string{"node_id": "QmNode..."},
        ID:      1,
    }

    // Encode and send
    data, _ := json.Marshal(req)
    length := make([]byte, 4)
    binary.BigEndian.PutUint32(length, uint32(len(data)))
    conn.Write(length)
    conn.Write(data)

    // Read response
    conn.Read(length)
    respLen := binary.BigEndian.Uint32(length)
    respData := make([]byte, respLen)
    conn.Read(respData)

    var resp JSONRPCResponse
    json.Unmarshal(respData, &resp)
}
```

### Python Client

```python
import socket
import struct
import json

def send_request(method, params=None):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/run/platformd.sock')

    request = {
        'jsonrpc': '2.0',
        'method': method,
        'params': params or {},
        'id': 1
    }

    data = json.dumps(request).encode('utf-8')
    sock.send(struct.pack('>I', len(data)))
    sock.send(data)

    length = struct.unpack('>I', sock.recv(4))[0]
    response = json.loads(sock.recv(length).decode('utf-8'))

    sock.close()
    return response

# Example usage
result = send_request('dht.getNode', {'node_id': 'QmNode...'})
print(result)
```

### Shell (using socat)

```bash
# Simple request using socat
echo '{"jsonrpc":"2.0","method":"dht.listNodes","params":{},"id":1}' | \
  socat - UNIX-CONNECT:/run/platformd.sock
```

## Best Practices

### Connection Management

- Reuse connections when making multiple requests
- Implement connection pooling for high-throughput applications
- Handle reconnection gracefully on connection loss
- Set appropriate read/write timeouts

### Error Handling

- Always check for error responses before processing results
- Implement exponential backoff for retryable errors
- Log error codes and messages for debugging
- Handle socket errors (ECONNREFUSED, ENOENT) appropriately

### Security

- Ensure proper file permissions on the socket
- Validate all input before sending requests
- Use the principle of least privilege for socket access
- Monitor for unauthorized access attempts

### Performance

- Batch operations when possible
- Use appropriate limits for list operations
- Implement client-side caching for frequently accessed data
- Monitor latency and throughput metrics

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-07 | Initial release |
| 1.1 | 2026-01-10 | Added standardized error codes, rate limits by user/group, and authentication requirements |

---

Document Version: 1.1
Last Updated: 2026-01-10
