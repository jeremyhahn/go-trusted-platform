# VXLAN Overlay gRPC API Reference

gRPC service definition for the VXLAN overlay service.

| Property | Value |
|----------|-------|
| Service | `overlay.OverlayService` |
| Port | 10443 |
| Transport | TCP with TLS |

## Service Definition

```protobuf
syntax = "proto3";
package overlay;

import "google/protobuf/empty.proto";
import "google/protobuf/timestamp.proto";

service OverlayService {
  // VTEP operations
  rpc RegisterVTEP(RegisterVTEPRequest) returns (VTEP);
  rpc GetVTEP(GetVTEPRequest) returns (VTEP);
  rpc ListVTEPs(ListVTEPsRequest) returns (ListVTEPsResponse);
  rpc DeregisterVTEP(DeregisterVTEPRequest) returns (google.protobuf.Empty);
  rpc HealthCheckVTEP(HealthCheckVTEPRequest) returns (VTEPHealthResponse);

  // VNI operations
  rpc CreateVNI(CreateVNIRequest) returns (VNI);
  rpc GetVNI(GetVNIRequest) returns (VNI);
  rpc ListVNIs(ListVNIsRequest) returns (ListVNIsResponse);
  rpc DeleteVNI(DeleteVNIRequest) returns (google.protobuf.Empty);
  rpc JoinVNI(JoinVNIRequest) returns (google.protobuf.Empty);
  rpc LeaveVNI(LeaveVNIRequest) returns (google.protobuf.Empty);
  rpc ListVNIMembers(ListVNIMembersRequest) returns (ListVNIMembersResponse);

  // Tunnel operations
  rpc CreateTunnel(CreateTunnelRequest) returns (Tunnel);
  rpc GetTunnel(GetTunnelRequest) returns (Tunnel);
  rpc ListTunnels(ListTunnelsRequest) returns (ListTunnelsResponse);
  rpc DeleteTunnel(DeleteTunnelRequest) returns (google.protobuf.Empty);
  rpc GetTunnelStats(GetTunnelStatsRequest) returns (TunnelStats);

  // MAC operations
  rpc GetMAC(GetMACRequest) returns (MACEntry);
  rpc ListMACs(ListMACsRequest) returns (ListMACsResponse);
  rpc LearnMAC(LearnMACRequest) returns (MACEntry);
  rpc DeleteMAC(DeleteMACRequest) returns (google.protobuf.Empty);
  rpc FlushMACs(FlushMACsRequest) returns (FlushMACsResponse);

  // Streaming operations
  rpc WatchVTEPs(WatchVTEPsRequest) returns (stream VTEPEvent);
  rpc WatchTunnels(WatchTunnelsRequest) returns (stream TunnelEvent);
  rpc WatchMACs(WatchMACsRequest) returns (stream MACEvent);
}
```

## VTEP Operations

### RegisterVTEP

```protobuf
message RegisterVTEPRequest {
  string ip = 1;
  string underlay_iface = 2;
  uint32 underlay_mtu = 3;
  uint32 vxlan_port = 4;
}

message VTEP {
  string ip = 1;
  string node_id = 2;
  string underlay_iface = 3;
  uint32 underlay_mtu = 4;
  uint32 vxlan_port = 5;
  repeated uint32 active_vnis = 6;
  bool healthy = 7;
  google.protobuf.Timestamp last_heartbeat = 8;
}
```

**Go Example:**
```go
resp, err := client.RegisterVTEP(ctx, &overlay.RegisterVTEPRequest{
    Ip:            "10.0.0.1",
    UnderlayIface: "eth0",
    UnderlayMtu:   9000,
    VxlanPort:     4789,
})
```

### GetVTEP

```protobuf
message GetVTEPRequest {
  string ip = 1;
}
```

**Go Example:**
```go
vtep, err := client.GetVTEP(ctx, &overlay.GetVTEPRequest{
    Ip: "10.0.0.1",
})
```

### ListVTEPs

```protobuf
message ListVTEPsRequest {
  bool healthy_only = 1;
  uint32 limit = 2;
  uint32 offset = 3;
}

message ListVTEPsResponse {
  repeated VTEP vteps = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### DeregisterVTEP

```protobuf
message DeregisterVTEPRequest {
  string ip = 1;
}
```

### HealthCheckVTEP

```protobuf
message HealthCheckVTEPRequest {
  string ip = 1;
}

message VTEPHealthResponse {
  string ip = 1;
  bool healthy = 2;
  uint32 latency_ms = 3;
  google.protobuf.Timestamp last_check = 4;
  uint64 uptime_seconds = 5;
  uint32 tunnel_count = 6;
  string error = 7;
}
```

## VNI Operations

### CreateVNI

```protobuf
message CreateVNIRequest {
  uint32 id = 1;
  uint32 vlan_id = 2;
  string multicast_group = 3;
}

message VNI {
  uint32 id = 1;
  uint32 vlan_id = 2;
  repeated string member_vteps = 3;
  string multicast_group = 4;
  repeated string local_ports = 5;
  uint32 mac_count = 6;
}
```

**Go Example:**
```go
vni, err := client.CreateVNI(ctx, &overlay.CreateVNIRequest{
    Id:             1000100,
    VlanId:         100,
    MulticastGroup: "239.1.1.100",
})
```

### GetVNI

```protobuf
message GetVNIRequest {
  uint32 id = 1;
}
```

### ListVNIs

```protobuf
message ListVNIsRequest {
  uint32 vlan_id = 1;  // optional filter
  uint32 limit = 2;
  uint32 offset = 3;
}

message ListVNIsResponse {
  repeated VNI vnis = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### DeleteVNI

```protobuf
message DeleteVNIRequest {
  uint32 id = 1;
}
```

### JoinVNI

```protobuf
message JoinVNIRequest {
  uint32 vni_id = 1;
}
```

**Go Example:**
```go
_, err := client.JoinVNI(ctx, &overlay.JoinVNIRequest{
    VniId: 1000100,
})
```

### LeaveVNI

```protobuf
message LeaveVNIRequest {
  uint32 vni_id = 1;
}
```

### ListVNIMembers

```protobuf
message ListVNIMembersRequest {
  uint32 vni_id = 1;
}

message ListVNIMembersResponse {
  uint32 vni_id = 1;
  repeated VNIMember members = 2;
}

message VNIMember {
  string vtep_ip = 1;
  string node_id = 2;
  google.protobuf.Timestamp joined_at = 3;
}
```

## Tunnel Operations

### CreateTunnel

```protobuf
message CreateTunnelRequest {
  string remote_vtep = 1;
  repeated uint32 vnis = 2;
}

message Tunnel {
  string id = 1;
  string local_vtep = 2;
  string remote_vtep = 3;
  repeated uint32 vnis = 4;
  string ovs_port = 5;
  uint32 of_port = 6;
  TunnelState state = 7;
  google.protobuf.Timestamp last_check = 8;
  string rtt = 9;
  TunnelStats stats = 10;
}

enum TunnelState {
  TUNNEL_STATE_UNKNOWN = 0;
  TUNNEL_STATE_ACTIVE = 1;
  TUNNEL_STATE_UNHEALTHY = 2;
  TUNNEL_STATE_FAILED = 3;
}
```

**Go Example:**
```go
tunnel, err := client.CreateTunnel(ctx, &overlay.CreateTunnelRequest{
    RemoteVtep: "10.0.0.2",
    Vnis:       []uint32{1000100, 1000200},
})
```

### GetTunnel

```protobuf
message GetTunnelRequest {
  string remote_vtep = 1;
}
```

### ListTunnels

```protobuf
message ListTunnelsRequest {
  TunnelState state = 1;  // optional filter
  uint32 limit = 2;
  uint32 offset = 3;
}

message ListTunnelsResponse {
  repeated Tunnel tunnels = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### DeleteTunnel

```protobuf
message DeleteTunnelRequest {
  string remote_vtep = 1;
}
```

### GetTunnelStats

```protobuf
message GetTunnelStatsRequest {
  string remote_vtep = 1;
}

message TunnelStats {
  uint64 tx_packets = 1;
  uint64 rx_packets = 2;
  uint64 tx_bytes = 3;
  uint64 rx_bytes = 4;
  uint64 tx_errors = 5;
  uint64 rx_errors = 6;
  uint64 tx_drops = 7;
  uint64 rx_drops = 8;
  google.protobuf.Timestamp collected_at = 9;
}
```

## MAC Operations

### GetMAC

```protobuf
message GetMACRequest {
  uint32 vni = 1;
  string mac = 2;
}

message MACEntry {
  string mac = 1;
  uint32 vni = 2;
  string vtep_ip = 3;
  string port_id = 4;
  MACType type = 5;
  google.protobuf.Timestamp learned_at = 6;
  google.protobuf.Timestamp expires_at = 7;
}

enum MACType {
  MAC_TYPE_UNKNOWN = 0;
  MAC_TYPE_LOCAL = 1;
  MAC_TYPE_REMOTE = 2;
  MAC_TYPE_STATIC = 3;
}
```

### ListMACs

```protobuf
message ListMACsRequest {
  uint32 vni = 1;
  MACType type = 2;  // optional filter
  uint32 limit = 3;
  uint32 offset = 4;
}

message ListMACsResponse {
  uint32 vni = 1;
  repeated MACEntry macs = 2;
  uint32 total = 3;
  uint32 limit = 4;
  uint32 offset = 5;
}
```

**Go Example:**
```go
resp, err := client.ListMACs(ctx, &overlay.ListMACsRequest{
    Vni:   1000100,
    Type:  overlay.MAC_TYPE_REMOTE,
    Limit: 100,
})
for _, mac := range resp.Macs {
    fmt.Printf("MAC: %s -> VTEP: %s\n", mac.Mac, mac.VtepIp)
}
```

### LearnMAC

```protobuf
message LearnMACRequest {
  uint32 vni = 1;
  string mac = 2;
  string vtep_ip = 3;
  MACType type = 4;
}
```

### DeleteMAC

```protobuf
message DeleteMACRequest {
  uint32 vni = 1;
  string mac = 2;
}
```

### FlushMACs

```protobuf
message FlushMACsRequest {
  uint32 vni = 1;
  MACType type = 2;  // optional: flush specific type only
}

message FlushMACsResponse {
  uint32 vni = 1;
  uint32 count = 2;
}
```

## Streaming Operations

### WatchVTEPs

Monitor VTEP registration and health changes in real-time.

```protobuf
message WatchVTEPsRequest {
  bool include_initial = 1;  // Send current state first
}

message VTEPEvent {
  VTEPEventType type = 1;
  VTEP vtep = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum VTEPEventType {
  VTEP_EVENT_UNKNOWN = 0;
  VTEP_EVENT_ADDED = 1;
  VTEP_EVENT_UPDATED = 2;
  VTEP_EVENT_REMOVED = 3;
  VTEP_EVENT_HEALTHY = 4;
  VTEP_EVENT_UNHEALTHY = 5;
}
```

**Go Example:**
```go
stream, err := client.WatchVTEPs(ctx, &overlay.WatchVTEPsRequest{
    IncludeInitial: true,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case overlay.VTEP_EVENT_ADDED:
        log.Printf("VTEP added: %s", event.Vtep.Ip)
    case overlay.VTEP_EVENT_UNHEALTHY:
        log.Printf("VTEP unhealthy: %s", event.Vtep.Ip)
    case overlay.VTEP_EVENT_REMOVED:
        log.Printf("VTEP removed: %s", event.Vtep.Ip)
    }
}
```

### WatchTunnels

Monitor tunnel state changes.

```protobuf
message WatchTunnelsRequest {
  bool include_initial = 1;
  string remote_vtep = 2;  // optional filter
}

message TunnelEvent {
  TunnelEventType type = 1;
  Tunnel tunnel = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum TunnelEventType {
  TUNNEL_EVENT_UNKNOWN = 0;
  TUNNEL_EVENT_ESTABLISHED = 1;
  TUNNEL_EVENT_UNHEALTHY = 2;
  TUNNEL_EVENT_RECOVERED = 3;
  TUNNEL_EVENT_FAILED = 4;
  TUNNEL_EVENT_DELETED = 5;
}
```

**Go Example:**
```go
stream, err := client.WatchTunnels(ctx, &overlay.WatchTunnelsRequest{
    IncludeInitial: true,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case overlay.TUNNEL_EVENT_ESTABLISHED:
        log.Printf("Tunnel established: %s -> %s",
            event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
    case overlay.TUNNEL_EVENT_FAILED:
        log.Printf("Tunnel failed: %s -> %s",
            event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
    }
}
```

### WatchMACs

Monitor MAC address learning and expiration.

```protobuf
message WatchMACsRequest {
  uint32 vni = 1;  // optional filter by VNI
  bool include_initial = 2;
}

message MACEvent {
  MACEventType type = 1;
  MACEntry entry = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum MACEventType {
  MAC_EVENT_UNKNOWN = 0;
  MAC_EVENT_LEARNED = 1;
  MAC_EVENT_MOVED = 2;
  MAC_EVENT_AGED = 3;
  MAC_EVENT_REMOVED = 4;
}
```

**Go Example:**
```go
stream, err := client.WatchMACs(ctx, &overlay.WatchMACsRequest{
    Vni:            1000100,
    IncludeInitial: false,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case overlay.MAC_EVENT_LEARNED:
        log.Printf("MAC learned: %s on VNI %d from VTEP %s",
            event.Entry.Mac, event.Entry.Vni, event.Entry.VtepIp)
    case overlay.MAC_EVENT_MOVED:
        log.Printf("MAC moved: %s to VTEP %s",
            event.Entry.Mac, event.Entry.VtepIp)
    case overlay.MAC_EVENT_AGED:
        log.Printf("MAC aged out: %s", event.Entry.Mac)
    }
}
```

## Error Handling

gRPC status codes map to overlay errors:

| gRPC Code | Overlay Error |
|-----------|---------------|
| `NOT_FOUND` | vtep_not_found, vni_not_found, tunnel_not_found, mac_not_found |
| `ALREADY_EXISTS` | vtep_already_exists, vni_already_exists, tunnel_exists |
| `INVALID_ARGUMENT` | invalid_vni_range, invalid_vtep_ip, invalid_mac |
| `FAILED_PRECONDITION` | mtu_too_small, underlay_unreachable |
| `RESOURCE_EXHAUSTED` | mac_table_full |
| `UNAUTHENTICATED` | unauthorized |
| `PERMISSION_DENIED` | forbidden |

**Go Example:**
```go
vtep, err := client.GetVTEP(ctx, req)
if err != nil {
    if status.Code(err) == codes.NotFound {
        // Handle VTEP not found
    }
    if status.Code(err) == codes.FailedPrecondition {
        // Handle underlay issue
    }
}
```

## Client Setup

```go
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    overlay "github.com/jeremyhahn/go-trusted-platform/api/sdn/overlay/v1"
)

func NewOverlayClient(addr string, tlsConfig *tls.Config) (overlay.OverlayServiceClient, error) {
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    return overlay.NewOverlayServiceClient(conn), nil
}

// Usage
client, err := NewOverlayClient("localhost:10443", tlsConfig)
if err != nil {
    return err
}

// Register VTEP
vtep, err := client.RegisterVTEP(ctx, &overlay.RegisterVTEPRequest{
    Ip:            "10.0.0.1",
    UnderlayIface: "eth0",
    UnderlayMtu:   9000,
    VxlanPort:     4789,
})

// Create VNI and join
vni, err := client.CreateVNI(ctx, &overlay.CreateVNIRequest{
    Id:     1000100,
    VlanId: 100,
})
_, err = client.JoinVNI(ctx, &overlay.JoinVNIRequest{VniId: 1000100})

// Create tunnel to remote VTEP
tunnel, err := client.CreateTunnel(ctx, &overlay.CreateTunnelRequest{
    RemoteVtep: "10.0.0.2",
    Vnis:       []uint32{1000100},
})
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [Architecture](architecture.md)
- [Configuration](configuration.md)
