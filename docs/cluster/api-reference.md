# Cluster API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and its siblings; describes an API surface and a `platformctl cluster` CLI that do not exist.

## Overview

The Cluster API provides management operations for go-trusted-platform cluster deployments, including cluster formation, membership management, and status monitoring.

## gRPC API

### Service Definition

```protobuf
service ClusterService {
  // Bootstrap initializes a new cluster with this node as the leader
  rpc Bootstrap(BootstrapRequest) returns (BootstrapResponse);

  // Join adds this node to an existing cluster
  rpc Join(JoinRequest) returns (JoinResponse);

  // Leave gracefully removes this node from the cluster
  rpc Leave(LeaveRequest) returns (LeaveResponse);

  // Status returns the current cluster and node status
  rpc Status(StatusRequest) returns (StatusResponse);

  // ListNodes returns all nodes in the cluster
  rpc ListNodes(ListNodesRequest) returns (ListNodesResponse);

  // GetNode returns details for a specific node
  rpc GetNode(GetNodeRequest) returns (GetNodeResponse);

  // RemoveNode forcefully removes a node from the cluster
  rpc RemoveNode(RemoveNodeRequest) returns (RemoveNodeResponse);

  // TransferLeadership transfers leadership to another node
  rpc TransferLeadership(TransferLeadershipRequest) returns (TransferLeadershipResponse);
}
```

### Bootstrap

Initializes a new cluster with the current node as the initial leader.

**Request:**

```protobuf
message BootstrapRequest {
  uint64 node_id = 1;           // Unique node identifier
  string listen_addr = 2;       // Raft listen address (host:port)
  string advertise_addr = 3;    // Raft advertise address (host:port)
  map<string, string> metadata = 4;  // Optional node metadata
}
```

**Response:**

```protobuf
message BootstrapResponse {
  bool success = 1;
  string cluster_id = 2;        // Generated cluster identifier
  string message = 3;
}
```

**Example:**

```bash
# gRPC request
grpcurl -plaintext -d '{
  "node_id": 1,
  "listen_addr": "192.168.1.10:63000",
  "advertise_addr": "192.168.1.10:63000"
}' localhost:63001 platform.ClusterService/Bootstrap
```

### Join

Joins an existing cluster via a known member.

**Request:**

```protobuf
message JoinRequest {
  uint64 node_id = 1;           // Unique node identifier
  string listen_addr = 2;       // Raft listen address
  string advertise_addr = 3;    // Raft advertise address
  repeated string join_addrs = 4;  // Existing member addresses to contact
  map<string, string> metadata = 5;
}
```

**Response:**

```protobuf
message JoinResponse {
  bool success = 1;
  string cluster_id = 2;
  string leader_addr = 3;       // Current leader address
  string message = 4;
}
```

**Example:**

```bash
grpcurl -plaintext -d '{
  "node_id": 2,
  "listen_addr": "192.168.1.11:63000",
  "advertise_addr": "192.168.1.11:63000",
  "join_addrs": ["192.168.1.10:63000"]
}' localhost:63001 platform.ClusterService/Join
```

### Leave

Gracefully removes the current node from the cluster.

**Request:**

```protobuf
message LeaveRequest {
  bool force = 1;               // Force removal even if not graceful
}
```

**Response:**

```protobuf
message LeaveResponse {
  bool success = 1;
  string message = 2;
}
```

### Status

Returns comprehensive cluster and node status.

**Request:**

```protobuf
message StatusRequest {
  bool include_details = 1;     // Include detailed node information
}
```

**Response:**

```protobuf
message StatusResponse {
  ClusterStatus cluster = 1;
  NodeStatus local_node = 2;
}

message ClusterStatus {
  string cluster_id = 1;
  string state = 2;             // "healthy", "degraded", "unavailable"
  int32 total_nodes = 3;
  int32 healthy_nodes = 4;
  uint64 leader_id = 5;
  string leader_addr = 6;
  uint64 current_term = 7;
  uint64 commit_index = 8;
}

message NodeStatus {
  uint64 node_id = 1;
  string address = 2;
  string raft_state = 3;        // "leader", "follower", "candidate"
  string health = 4;            // "healthy", "unhealthy"
  google.protobuf.Duration uptime = 5;
  uint64 applied_index = 6;
  map<string, string> metadata = 7;
}
```

**Example:**

```bash
grpcurl -plaintext localhost:63001 platform.ClusterService/Status
```

### ListNodes

Returns all nodes in the cluster.

**Request:**

```protobuf
message ListNodesRequest {
  bool healthy_only = 1;        // Filter to healthy nodes only
}
```

**Response:**

```protobuf
message ListNodesResponse {
  repeated NodeInfo nodes = 1;
}

message NodeInfo {
  uint64 node_id = 1;
  string address = 2;
  string raft_state = 3;
  string health = 4;
  google.protobuf.Duration uptime = 5;
  google.protobuf.Timestamp last_seen = 6;
  map<string, string> metadata = 7;
}
```

### GetNode

Returns details for a specific node.

**Request:**

```protobuf
message GetNodeRequest {
  uint64 node_id = 1;
}
```

**Response:**

```protobuf
message GetNodeResponse {
  NodeInfo node = 1;
}
```

### RemoveNode

Forcefully removes a node from the cluster (leader only).

**Request:**

```protobuf
message RemoveNodeRequest {
  uint64 node_id = 1;
  bool force = 2;               // Force removal without graceful shutdown
}
```

**Response:**

```protobuf
message RemoveNodeResponse {
  bool success = 1;
  string message = 2;
}
```

### TransferLeadership

Transfers leadership to another node.

**Request:**

```protobuf
message TransferLeadershipRequest {
  uint64 target_node_id = 1;    // Node to transfer leadership to
}
```

**Response:**

```protobuf
message TransferLeadershipResponse {
  bool success = 1;
  uint64 new_leader_id = 2;
  string message = 3;
}
```

## REST API

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/cluster/bootstrap` | Bootstrap new cluster |
| POST | `/api/v1/cluster/join` | Join existing cluster |
| POST | `/api/v1/cluster/leave` | Leave cluster |
| GET | `/api/v1/cluster/status` | Get cluster status |
| GET | `/api/v1/cluster/nodes` | List all nodes |
| GET | `/api/v1/cluster/nodes/{id}` | Get node details |
| DELETE | `/api/v1/cluster/nodes/{id}` | Remove node |
| POST | `/api/v1/cluster/transfer-leadership` | Transfer leadership |

### Bootstrap

```http
POST /api/v1/cluster/bootstrap
Content-Type: application/json

{
  "node_id": 1,
  "listen_addr": "192.168.1.10:63000",
  "advertise_addr": "192.168.1.10:63000",
  "metadata": {
    "datacenter": "dc1",
    "rack": "rack1"
  }
}
```

**Response:**

```json
{
  "success": true,
  "cluster_id": "cluster-abc123",
  "message": "Cluster bootstrapped successfully"
}
```

### Join

```http
POST /api/v1/cluster/join
Content-Type: application/json

{
  "node_id": 2,
  "listen_addr": "192.168.1.11:63000",
  "advertise_addr": "192.168.1.11:63000",
  "join_addrs": ["192.168.1.10:63000"]
}
```

**Response:**

```json
{
  "success": true,
  "cluster_id": "cluster-abc123",
  "leader_addr": "192.168.1.10:63000",
  "message": "Successfully joined cluster"
}
```

### Status

```http
GET /api/v1/cluster/status
```

**Response:**

```json
{
  "cluster": {
    "cluster_id": "cluster-abc123",
    "state": "healthy",
    "total_nodes": 3,
    "healthy_nodes": 3,
    "leader_id": 1,
    "leader_addr": "192.168.1.10:63000",
    "current_term": 5,
    "commit_index": 12345
  },
  "local_node": {
    "node_id": 1,
    "address": "192.168.1.10:63000",
    "raft_state": "leader",
    "health": "healthy",
    "uptime": "2h15m30s",
    "applied_index": 12345
  }
}
```

### List Nodes

```http
GET /api/v1/cluster/nodes
GET /api/v1/cluster/nodes?healthy_only=true
```

**Response:**

```json
{
  "nodes": [
    {
      "node_id": 1,
      "address": "192.168.1.10:63000",
      "raft_state": "leader",
      "health": "healthy",
      "uptime": "2h15m30s",
      "last_seen": "2024-01-15T10:30:00Z"
    },
    {
      "node_id": 2,
      "address": "192.168.1.11:63000",
      "raft_state": "follower",
      "health": "healthy",
      "uptime": "2h10m15s",
      "last_seen": "2024-01-15T10:30:00Z"
    },
    {
      "node_id": 3,
      "address": "192.168.1.12:63000",
      "raft_state": "follower",
      "health": "healthy",
      "uptime": "2h05m45s",
      "last_seen": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Remove Node

```http
DELETE /api/v1/cluster/nodes/2
DELETE /api/v1/cluster/nodes/2?force=true
```

**Response:**

```json
{
  "success": true,
  "message": "Node 2 removed from cluster"
}
```

### Transfer Leadership

```http
POST /api/v1/cluster/transfer-leadership
Content-Type: application/json

{
  "target_node_id": 2
}
```

**Response:**

```json
{
  "success": true,
  "new_leader_id": 2,
  "message": "Leadership transferred to node 2"
}
```

## Error Codes

| Code | gRPC Status | Description |
|------|-------------|-------------|
| CLUSTER_NOT_INITIALIZED | FAILED_PRECONDITION | Cluster not bootstrapped |
| ALREADY_MEMBER | ALREADY_EXISTS | Node already in cluster |
| NOT_MEMBER | NOT_FOUND | Node not in cluster |
| NOT_LEADER | FAILED_PRECONDITION | Operation requires leader |
| NO_QUORUM | UNAVAILABLE | Quorum not available |
| NODE_NOT_FOUND | NOT_FOUND | Specified node not found |
| INVALID_NODE_ID | INVALID_ARGUMENT | Invalid node ID |
| TRANSFER_FAILED | INTERNAL | Leadership transfer failed |

## Authentication

All cluster API calls require authentication:

```bash
# Using mTLS
curl --cert client.crt --key client.key --cacert ca.crt \
  https://localhost:63002/api/v1/cluster/status

# Using JWT
curl -H "Authorization: Bearer <token>" \
  https://localhost:63002/api/v1/cluster/status
```

## Rate Limiting

Cluster management operations are rate limited:

| Operation | Rate Limit |
|-----------|------------|
| Status | 100/minute |
| ListNodes | 100/minute |
| Bootstrap | 1/minute |
| Join | 10/minute |
| Leave | 10/minute |
| RemoveNode | 10/minute |

## Related Documentation

- [CLI Usage](cli-usage.md) - Command-line interface
- [Configuration](configuration.md) - Cluster configuration
- [Architecture](architecture.md) - Cluster architecture
- [Roadmap](../ROADMAP.md) - Development roadmap
