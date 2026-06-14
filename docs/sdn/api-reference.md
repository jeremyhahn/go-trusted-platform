# SDN API Reference

## Overview

The SDN subsystem provides network management through multiple protocols for maximum interoperability. All operations are available via REST, gRPC, QUIC, MCP, and Unix Socket.

## Protocol-Specific Documentation

| Protocol | Documentation | Port | Use Case |
|----------|---------------|------|----------|
| REST | [api-reference-rest.md](api-reference-rest.md) | 8443 | Web clients, external systems |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | 9443 | High-performance service-to-service |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | 9444 | Low-latency, mobile clients |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | 9445 | AI/LLM integration |
| Unix Socket | [api-reference-unix.md](api-reference-unix.md) | /run/platformd.sock | Local IPC, CLI |

## Service Operations

### Bridge Operations

| Operation | Description |
|-----------|-------------|
| CreateBridge | Create a new OVS bridge |
| GetBridge | Get bridge details |
| DeleteBridge | Delete an OVS bridge |
| ListBridges | List all bridges |

### Port Operations

| Operation | Description |
|-----------|-------------|
| AddPort | Add port to a bridge |
| DeletePort | Remove port from bridge |
| GetPortState | Get port admin state |
| SetPortState | Set port admin state |
| GetPortStats | Get port statistics |

### Flow Operations

| Operation | Description |
|-----------|-------------|
| AddFlow | Add OpenFlow rule |
| DeleteFlow | Delete OpenFlow rule |
| ListFlows | List flows on bridge |

### VLAN Operations

| Operation | Description |
|-----------|-------------|
| CreateVLAN | Create VLAN |
| DeleteVLAN | Delete VLAN |
| ListVLANs | List VLANs |

### Policy Operations

| Operation | Description |
|-----------|-------------|
| ApplyPolicy | Apply security policy to port |
| GetPolicy | Get port policy |
| ListPolicies | List all policies |

## Data Types

### Bridge

```go
type Bridge struct {
    UUID string `json:"uuid"`
    Name string `json:"name"`
}
```

### Port

```go
type Port struct {
    UUID       string   `json:"uuid"`
    Name       string   `json:"name"`
    Tag        int64    `json:"tag,omitempty"`
    Trunks     []int64  `json:"trunks,omitempty"`
    Interfaces []string `json:"interfaces"`
}
```

### Flow

```go
type Flow struct {
    Priority int         `json:"priority"`
    Match    FlowMatch   `json:"match"`
    Actions  []FlowAction `json:"actions"`
    Cookie   uint64      `json:"cookie"`
    Idle     int         `json:"idle_timeout"`
    Hard     int         `json:"hard_timeout"`
}
```

### Policy

```go
type PortPolicy struct {
    TenantID  string            `json:"tenant_id"`
    VLAN      uint16            `json:"vlan"`
    ACLs      []ACLRule         `json:"acls"`
    ExpiresAt time.Time         `json:"expires_at"`
    Metadata  map[string]string `json:"metadata"`
}
```

## Error Codes

| Code | Description |
|------|-------------|
| BRIDGE_NOT_FOUND | Bridge does not exist |
| BRIDGE_EXISTS | Bridge already exists |
| PORT_NOT_FOUND | Port does not exist |
| INVALID_VLAN | Invalid VLAN ID (must be 1-4094) |
| POLICY_NOT_FOUND | Policy does not exist |
| TRANSACTION_FAILED | OVSDB transaction failed |
| FLOW_INSTALL_FAILED | Flow installation failed |

## Authentication

All protocols require mTLS authentication. Clients must present valid certificates signed by the platform CA.

## Network Zone Management

All zone endpoints are available across REST, gRPC, QUIC, MCP, Unix socket, and CLI:

| Operation | REST | gRPC | CLI |
|-----------|------|------|-----|
| Create | `POST /api/v1/sdn/zones` | `CreateNetworkZone` | `platformctl sdn zone create` |
| List | `GET /api/v1/sdn/zones` | `ListNetworkZones` | `platformctl sdn zone list` |
| Update | `PUT /api/v1/sdn/zones/{name}` | `UpdateNetworkZone` | `platformctl sdn zone update` |
| Delete | `DELETE /api/v1/sdn/zones/{name}` | `DeleteNetworkZone` | `platformctl sdn zone delete` |
| Assign | `PUT /api/v1/sdn/networks/{network}/zone` | `AssignNetworkZone` | `platformctl sdn zone assign` |

MCP tools: `gateway_zone_list`, `gateway_zone_create`, `gateway_zone_update`,
`gateway_zone_delete`, `gateway_zone_assign`.

See the protocol-specific reference docs for full request/response schemas.
