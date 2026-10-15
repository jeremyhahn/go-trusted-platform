# SDN API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> Index of the SDN service's transports.

## Overview

The SDN subsystem provides network management through multiple protocols.
The operations below are the gRPC `SDNService`'s (Unix socket included).
Not every operation is on every transport: the QUIC opcodes and the MCP
tools are listed on their pages, `GetPortState` has no gRPC method, and
`StreamFlowLogs` is gRPC only.

## Protocol-Specific Documentation

| Protocol | Documentation | Port | Use Case |
|----------|---------------|------|----------|
| REST | [api-reference-rest.md](api-reference-rest.md) | 8443 | Web clients, external systems |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | 10443 | High-performance service-to-service |
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
| GetPort | Get port details |
| ListPorts | List ports on a bridge |
| GetPortState | Get port admin state (REST, QUIC, MCP) |
| SetPortState | Set port admin state and ingress policing |
| GetPortStats | Get port statistics |

### Flow Operations

| Operation | Description |
|-----------|-------------|
| AddFlow | Add OpenFlow rule |
| DeleteFlow | Delete OpenFlow rule |
| ListFlows | List flows on bridge |
| FlushFlows | Delete all flows on a bridge |
| GetFlowStats | Get flow statistics |
| StreamFlowLogs | gRPC only: every second, one entry per flow on the bridge (cookie, actions, bytes) |

### VLAN Operations

| Operation | Description |
|-----------|-------------|
| CreateVLAN | Create VLAN |
| DeleteVLAN | Delete VLAN |
| ListVLANs | List VLANs |

### Port Authentication

| Operation | Description |
|-----------|-------------|
| AuthenticatePort | Refused (`FailedPrecondition`): authenticate a port with a device certificate (802.1X-style) |
| RevokePortAuth | Refused (`FailedPrecondition`): revoke port authentication |

Both operations are refused on every transport with
`policy.ErrPortAuthNotEnforced` until the switch enforces port authentication;
[api.md](api.md) §4 names what is missing and what each transport answers.

### Policy Operations

| Operation | Description |
|-----------|-------------|
| ApplyPolicy | Apply a network policy to a bridge |
| GetPolicy | Get a policy by ID |
| ListPolicies | List all policies |
| DeletePolicy | Delete a policy |

## Data Types

Resources are config + status pairs defined in
`pkg/api/grpc/proto/sdn.proto` (package `platform.v1`), e.g.:

```protobuf
message Bridge {
  string id = 1;
  BridgeConfig config = 2;      // name, type (OVS/LINUX/VXLAN), MTU, ...
  BridgeStatus status = 3;      // UP, DOWN, ERROR
  google.protobuf.Timestamp created_at = 4;
  google.protobuf.Timestamp updated_at = 5;
  repeated Port ports = 6;
  BridgeStats stats = 7;
}
```

`Port`, `Flow`, `VLAN`, and `Policy` follow the same shape. See the
[gRPC reference](api-reference-grpc.md) and the proto file for the
full message set.

## Error Codes

The MCP tools fail with these codes (`pkg/api/mcp/sdn_tools.go`); gRPC
answers status codes and REST HTTP statuses (see the protocol pages).

| Code | Description |
|------|-------------|
| SDN_SERVICE_UNAVAILABLE | SDN service is not available |
| SDN_BRIDGE_NOT_FOUND | Bridge does not exist |
| SDN_PORT_NOT_FOUND | Port does not exist |
| SDN_FLOW_NOT_FOUND | Flow does not exist |
| SDN_POLICY_NOT_FOUND | Policy does not exist |
| SDN_BRIDGE_NAME_REQUIRED | Bridge name/ID missing from request |
| SDN_PORT_NAME_REQUIRED | Port name missing from request |
| SDN_FLOW_ID_REQUIRED | Flow ID missing from request |
| SDN_POLICY_NAME_REQUIRED, SDN_POLICY_ID_REQUIRED, SDN_POLICY_RULES_REQUIRED | Policy name, ID or rules missing |
| SDN_FLOW_MATCH_REQUIRED | Flow match criteria missing |
| SDN_FLOW_ACTIONS_REQUIRED | Flow actions missing |

## Authentication

The TCP transports require mTLS: clients present a certificate signed by
the platform CA. The Unix socket authenticates the caller by its peer
credentials (SO_PEERCRED). The webservice REST stack takes a platform
session with the `admin` role.


## Network Zone Management

Zones are the underlay zones of the
[reference network](../architecture/reference-network.md): nine built-ins at
fixed offsets (policy tunable) and owner-defined zones at offsets 9–99. All
zone operations are available across REST, gRPC, QUIC, MCP, Unix socket,
embedded and CLI:

| Operation | REST | gRPC | CLI |
|-----------|------|------|-----|
| Create (owner-defined) | `POST /api/v1/sdn/zones` | `CreateNetworkZone` | `platformctl sdn zone create` |
| List (with numbering) | `GET /api/v1/sdn/zones` | `ListNetworkZones` | `platformctl sdn zone list` |
| Tune / replace | `PUT /api/v1/sdn/zones/{name}` | `UpdateNetworkZone` | `platformctl sdn zone update` |
| Delete / omit | `DELETE /api/v1/sdn/zones/{name}` | `DeleteNetworkZone` | `platformctl sdn zone delete` |

MCP tools: `gateway_zone_list`, `gateway_zone_create`, `gateway_zone_update`,
`gateway_zone_delete`.

There is no assign operation: networks are zones (one per zone, derived by
netplan). The rules every mutation must satisfy are in [api.md](api.md) §5.

See the protocol-specific reference docs for full request/response schemas.
