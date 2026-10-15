# SDN gRPC API Reference

Endpoint: `localhost:10443`

Requires mTLS authentication. The service and all message definitions
live in `pkg/api/grpc/proto/sdn.proto` (package `platform.v1`); the
generated Go client is in `sdk/go/gen`.

## Service Definition

```protobuf
service SDNService {
  // Bridge operations
  rpc CreateBridge(CreateBridgeRequest) returns (CreateBridgeResponse);
  rpc DeleteBridge(DeleteBridgeRequest) returns (DeleteBridgeResponse);
  rpc GetBridge(GetBridgeRequest) returns (GetBridgeResponse);
  rpc ListBridges(ListBridgesRequest) returns (ListBridgesResponse);

  // Port operations
  rpc AddPort(AddPortRequest) returns (AddPortResponse);
  rpc DeletePort(DeletePortRequest) returns (DeletePortResponse);
  rpc GetPort(GetPortRequest) returns (GetPortResponse);
  rpc ListPorts(ListPortsRequest) returns (ListPortsResponse);
  rpc SetPortState(SetPortStateRequest) returns (SetPortStateResponse);

  // Flow operations
  rpc AddFlow(AddFlowRequest) returns (AddFlowResponse);
  rpc DeleteFlow(DeleteFlowRequest) returns (DeleteFlowResponse);
  rpc ListFlows(ListFlowsRequest) returns (ListFlowsResponse);
  rpc FlushFlows(FlushFlowsRequest) returns (FlushFlowsResponse);

  // VLAN operations
  rpc CreateVLAN(CreateVLANRequest) returns (CreateVLANResponse);
  rpc DeleteVLAN(DeleteVLANRequest) returns (DeleteVLANResponse);
  rpc ListVLANs(ListVLANsRequest) returns (ListVLANsResponse);

  // Port authentication (802.1X-style); both refused, FAILED_PRECONDITION
  rpc AuthenticatePort(AuthenticatePortRequest) returns (AuthenticatePortResponse);
  rpc RevokePortAuth(RevokePortAuthRequest) returns (RevokePortAuthResponse);

  // Statistics
  rpc GetPortStats(GetPortStatsRequest) returns (GetPortStatsResponse);
  rpc GetFlowStats(GetFlowStatsRequest) returns (GetFlowStatsResponse);

  // Policy operations
  rpc ApplyPolicy(ApplyPolicyRequest) returns (ApplyPolicyResponse);
  rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
  rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);

  // Underlay zones of the reference network
  rpc CreateNetworkZone(CreateNetworkZoneRequest) returns (CreateNetworkZoneResponse);
  rpc UpdateNetworkZone(UpdateNetworkZoneRequest) returns (UpdateNetworkZoneResponse);
  rpc DeleteNetworkZone(DeleteNetworkZoneRequest) returns (DeleteNetworkZoneResponse);
  rpc ListNetworkZones(ListNetworkZonesRequest) returns (ListNetworkZonesResponse);

  // Flow log streaming
  rpc StreamFlowLogs(StreamFlowLogsRequest) returns (stream FlowLogEntry);
}
```

## Key Message Types

Resources are config + status pairs. For example bridges:

```protobuf
message BridgeConfig {
  string name = 1;
  BridgeType type = 2;              // OVS, LINUX, VXLAN
  string datapath_id = 3;
  bool stp_enabled = 4;
  uint32 mtu = 5;
  repeated string controllers = 6;  // OpenFlow controllers
  map<string, string> options = 7;
  map<string, string> labels = 8;
}

message Bridge {
  string id = 1;
  BridgeConfig config = 2;
  BridgeStatus status = 3;          // UP, DOWN, ERROR
  google.protobuf.Timestamp created_at = 4;
  google.protobuf.Timestamp updated_at = 5;
  repeated Port ports = 6;
  BridgeStats stats = 7;
}
```

Ports, flows, VLANs, and policies follow the same pattern. See
`pkg/api/grpc/proto/sdn.proto` for the complete message set (enums:
`BridgeType`, `PortType`, `BridgeStatus`, ...).

## Usage Example (Go)

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Connect with mTLS
creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
if err != nil {
    return err
}
conn, err := grpc.NewClient("localhost:10443", grpc.WithTransportCredentials(creds))
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewSDNServiceClient(conn)

// Create bridge
resp, err := client.CreateBridge(ctx, &platformv1.CreateBridgeRequest{
    Config: &platformv1.BridgeConfig{
        Name: "br0",
        Type: platformv1.BridgeType_BRIDGE_TYPE_OVS,
    },
})
```

## Error Codes

gRPC status codes:

- `NOT_FOUND`: Resource does not exist
- `ALREADY_EXISTS`: Resource already exists
- `INVALID_ARGUMENT`: Invalid request parameters
- `INTERNAL`: Server error
- `UNAUTHENTICATED`: Missing or invalid credentials
- `FAILED_PRECONDITION`: `AuthenticatePort` and `RevokePortAuth`, always
  (`policy.ErrPortAuthNotEnforced`): nothing enforces port authentication on
  the switch, so the service refuses both and records nothing. Both need
  `sdn:write`. [api.md](api.md) §4 names what is missing.

## Network Zone RPC

Service: `platform.v1.SDNService`

| RPC | Request | Response |
|-----|---------|----------|
| `CreateNetworkZone` | `CreateNetworkZoneRequest{config}` | `CreateNetworkZoneResponse{zone, status}` |
| `UpdateNetworkZone` | `UpdateNetworkZoneRequest{name, config}` | `UpdateNetworkZoneResponse{zone, status}` |
| `DeleteNetworkZone` | `DeleteNetworkZoneRequest{name}` | `DeleteNetworkZoneResponse{status, restart_required}` |
| `ListNetworkZones`  | `ListNetworkZonesRequest{lifecycle_role}` | `ListNetworkZonesResponse{zones}` |

`NetworkZoneConfig` mirrors `pkg/sdn/zone.ZoneConfig`: `name`, `offset`,
`port_classes`, `internet_ingress`, `isolate_from`, `allow_to`
(`NetworkZonePath{zone, services}`), `services`, `isolate`, `oob`,
`lifecycle_role`, `privileged_access`
(`NetworkZonePrivilegedAccess{reason, approved_by}`) and `omit`. Field 7
(`isolate_per_tenant`) is reserved: tenants are not zones.

`NetworkZone` wraps the config with `created_at`, `updated_at`,
`restart_required` (true after every accepted mutation: the network plan
is derived at daemon startup) and, when the node has an `sdn.environment`,
`numbering` (`NetworkZoneNumbering{vlan, subnet4, subnet6, gateway}`).

Status codes: `INVALID_ARGUMENT` for a missing name or config and for a
mutation that fails zone or numbering validation (built-in renumbered,
owner offset outside 9–99, reserved name, unaudited privileged path,
required built-in deleted); `ALREADY_EXISTS` for a zone that exists (the
built-ins always do); `NOT_FOUND` for an unknown zone;
`FAILED_PRECONDITION` when the daemon has no zone service.

`AssignNetworkZone` was removed with #708: networks are zones.
