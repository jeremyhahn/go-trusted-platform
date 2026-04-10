# VXLAN Overlay API Reference

## Overview

The VXLAN overlay subsystem provides management operations through multiple protocols for maximum interoperability. All operations are available via REST, gRPC, QUIC, MCP, and Unix Socket.

## Protocol-Specific Documentation

| Protocol | Documentation | Port | Use Case |
|----------|---------------|------|----------|
| REST | [api-reference-rest.md](api-reference-rest.md) | 8443 | Web clients, external systems |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | 10443 | High-performance service-to-service |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | 9444 | Low-latency, mobile clients |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | 9445 | AI/LLM integration |
| Unix Socket | [api-reference-unix.md](api-reference-unix.md) | /run/platformd.sock | Local IPC, CLI |

## Service Operations

### VTEP Operations

| Operation | Description |
|-----------|-------------|
| RegisterVTEP | Register local VTEP with cluster |
| GetVTEP | Get VTEP details by IP |
| ListVTEPs | List all registered VTEPs |
| DeregisterVTEP | Remove VTEP from cluster |
| HealthCheckVTEP | Check VTEP health status |

### VNI Operations

| Operation | Description |
|-----------|-------------|
| CreateVNI | Create new VNI with VLAN mapping |
| GetVNI | Get VNI details |
| ListVNIs | List all VNIs |
| DeleteVNI | Delete VNI |
| JoinVNI | Add local host to VNI membership |
| LeaveVNI | Remove local host from VNI |
| ListVNIMembers | List hosts participating in VNI |

### Tunnel Operations

| Operation | Description |
|-----------|-------------|
| CreateTunnel | Establish tunnel to remote VTEP |
| GetTunnel | Get tunnel details |
| ListTunnels | List all tunnels |
| DeleteTunnel | Tear down tunnel |
| GetTunnelStats | Get tunnel statistics |

### MAC Table Operations

| Operation | Description |
|-----------|-------------|
| GetMAC | Get MAC address details |
| ListMACs | List MAC addresses for VNI |
| FlushMACs | Clear MAC table for VNI |
| LearnMAC | Manually add MAC entry |

## Data Types

### VTEP

```go
type VTEP struct {
    IP              string   `json:"ip"`
    NodeID          string   `json:"node_id"`
    UnderlayIface   string   `json:"underlay_iface"`
    UnderlayMTU     int      `json:"underlay_mtu"`
    VXLANPort       int      `json:"vxlan_port"`
    ActiveVNIs      []uint32 `json:"active_vnis"`
    Healthy         bool     `json:"healthy"`
    LastHeartbeat   string   `json:"last_heartbeat"`
}
```

### VNI

```go
type VNI struct {
    ID              uint32   `json:"id"`
    VLANID          uint16   `json:"vlan_id"`
    MemberVTEPs     []string `json:"member_vteps"`
    MulticastGroup  string   `json:"multicast_group,omitempty"`
    LocalPorts      []string `json:"local_ports"`
    MACCount        int      `json:"mac_count"`
}
```

### Tunnel

```go
type Tunnel struct {
    ID              string   `json:"id"`
    LocalVTEP       string   `json:"local_vtep"`
    RemoteVTEP      string   `json:"remote_vtep"`
    VNIs            []uint32 `json:"vnis"`
    OVSPort         string   `json:"ovs_port"`
    OFPort          uint32   `json:"of_port"`
    State           string   `json:"state"`
    LastCheck       string   `json:"last_check"`
    RTT             string   `json:"rtt"`
    Stats           *TunnelStats `json:"stats,omitempty"`
}

type TunnelStats struct {
    TxPackets       uint64   `json:"tx_packets"`
    RxPackets       uint64   `json:"rx_packets"`
    TxBytes         uint64   `json:"tx_bytes"`
    RxBytes         uint64   `json:"rx_bytes"`
    TxErrors        uint64   `json:"tx_errors"`
    RxErrors        uint64   `json:"rx_errors"`
}
```

### MACEntry

```go
type MACEntry struct {
    MAC             string   `json:"mac"`
    VNI             uint32   `json:"vni"`
    VTEPIP          string   `json:"vtep_ip"`
    PortID          string   `json:"port_id,omitempty"`
    Type            string   `json:"type"`  // "local", "remote", "static"
    LearnedAt       string   `json:"learned_at"`
    ExpiresAt       string   `json:"expires_at"`
}
```

## REST API Quick Reference

Base URL: `https://localhost:8443/api/v1/sdn/overlay`

### VTEP Endpoints

```http
GET    /vteps              # List all VTEPs
GET    /vteps/{ip}         # Get VTEP by IP
POST   /vteps              # Register local VTEP
DELETE /vteps/{ip}         # Deregister VTEP
GET    /vteps/{ip}/health  # Health check VTEP
```

### VNI Endpoints

```http
GET    /vnis               # List all VNIs
GET    /vnis/{id}          # Get VNI by ID
POST   /vnis               # Create VNI
DELETE /vnis/{id}          # Delete VNI
GET    /vnis/{id}/members  # List VNI members
POST   /vnis/{id}/join     # Join VNI
POST   /vnis/{id}/leave    # Leave VNI
```

### Tunnel Endpoints

```http
GET    /tunnels                 # List all tunnels
GET    /tunnels/{remote_vtep}   # Get tunnel by remote VTEP
POST   /tunnels                 # Create tunnel
DELETE /tunnels/{remote_vtep}   # Delete tunnel
GET    /tunnels/{remote_vtep}/stats  # Get tunnel stats
```

### MAC Table Endpoints

```http
GET    /macs                    # List all MACs
GET    /macs/{vni}              # List MACs for VNI
GET    /macs/{vni}/{mac}        # Get MAC details
POST   /macs/{vni}              # Add static MAC
DELETE /macs/{vni}              # Flush VNI MAC table
DELETE /macs/{vni}/{mac}        # Delete MAC entry
```

## gRPC API Quick Reference

### Service Definition

```protobuf
service OverlayService {
    // VTEP operations
    rpc RegisterVTEP(RegisterVTEPRequest) returns (VTEP);
    rpc GetVTEP(GetVTEPRequest) returns (VTEP);
    rpc ListVTEPs(ListVTEPsRequest) returns (ListVTEPsResponse);
    rpc DeregisterVTEP(DeregisterVTEPRequest) returns (google.protobuf.Empty);
    rpc HealthCheckVTEP(HealthCheckVTEPRequest) returns (HealthCheckResponse);

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
    rpc FlushMACs(FlushMACsRequest) returns (google.protobuf.Empty);
}
```

## CLI Reference

### VTEP Commands

```bash
# List VTEPs
platformctl sdn overlay vtep list

# Get VTEP details
platformctl sdn overlay vtep get 10.0.0.1

# Show local VTEP status
platformctl sdn overlay vtep status

# Health check remote VTEP
platformctl sdn overlay vtep health 10.0.0.2
```

### VNI Commands

```bash
# List VNIs
platformctl sdn overlay vni list

# Get VNI details
platformctl sdn overlay vni get 1000100

# Create VNI (manual)
platformctl sdn overlay vni create --vni 1000100 --vlan 100

# List VNI members
platformctl sdn overlay vni members 1000100

# Join VNI
platformctl sdn overlay vni join 1000100

# Leave VNI
platformctl sdn overlay vni leave 1000100
```

### Tunnel Commands

```bash
# List tunnels
platformctl sdn overlay tunnel list

# Get tunnel details
platformctl sdn overlay tunnel get 10.0.0.2

# Create tunnel (manual)
platformctl sdn overlay tunnel create --remote 10.0.0.2 --vnis 1000100,1000200

# Get tunnel stats
platformctl sdn overlay tunnel stats 10.0.0.2

# Delete tunnel
platformctl sdn overlay tunnel delete 10.0.0.2
```

### MAC Commands

```bash
# List MACs for VNI
platformctl sdn overlay mac list --vni 1000100

# Get MAC details
platformctl sdn overlay mac get --vni 1000100 --mac aa:bb:cc:dd:ee:ff

# Add static MAC
platformctl sdn overlay mac add --vni 1000100 --mac aa:bb:cc:dd:ee:ff --vtep 10.0.0.2

# Flush VNI MACs
platformctl sdn overlay mac flush --vni 1000100
```

### Diagnostic Commands

```bash
# Ping remote VTEP
platformctl sdn overlay ping 10.0.0.2

# Trace overlay path
platformctl sdn overlay trace --vni 1000100 --dst aa:bb:cc:dd:ee:ff

# Show overlay flows
platformctl sdn overlay flows --table 10

# Show overlay status summary
platformctl sdn overlay status
```

## Error Codes

| Code | Description |
|------|-------------|
| VTEP_NOT_FOUND | VTEP with specified IP not found |
| VTEP_ALREADY_EXISTS | VTEP already registered |
| VTEP_UNREACHABLE | Cannot reach remote VTEP |
| VNI_NOT_FOUND | VNI does not exist |
| VNI_OUT_OF_RANGE | VNI value outside valid range |
| VNI_ALREADY_EXISTS | VNI already configured |
| TUNNEL_FAILED | Tunnel establishment failed |
| TUNNEL_UNHEALTHY | Tunnel health check failed |
| MAC_NOT_FOUND | MAC address not in table |
| MAC_TABLE_FULL | MAC table capacity exceeded |
| MTU_TOO_SMALL | Underlay MTU insufficient for VXLAN |
| INVALID_VXLAN_PORT | Invalid VXLAN UDP port |
| UNDERLAY_UNREACHABLE | Underlay network unreachable |

## Authentication

All protocols require mTLS authentication. Clients must present valid certificates signed by the platform CA.

### Required Permissions

| Operation | Permission |
|-----------|------------|
| Read operations | `sdn:overlay:read` |
| VTEP management | `sdn:overlay:vtep:manage` |
| VNI management | `sdn:overlay:vni:manage` |
| Tunnel management | `sdn:overlay:tunnel:manage` |
| MAC management | `sdn:overlay:mac:manage` |

## Rate Limiting

| Operation Type | Rate Limit |
|---------------|------------|
| Read operations | 1000 req/min |
| Write operations | 100 req/min |
| Bulk operations | 10 req/min |

## Streaming APIs

### Watch VTEPs (gRPC)

```protobuf
rpc WatchVTEPs(WatchVTEPsRequest) returns (stream VTEPEvent);

message VTEPEvent {
    string type = 1;  // "added", "updated", "removed"
    VTEP vtep = 2;
}
```

### Watch Tunnels (gRPC)

```protobuf
rpc WatchTunnels(WatchTunnelsRequest) returns (stream TunnelEvent);

message TunnelEvent {
    string type = 1;  // "established", "unhealthy", "recovered", "failed"
    Tunnel tunnel = 2;
}
```

### Watch MACs (gRPC)

```protobuf
rpc WatchMACs(WatchMACsRequest) returns (stream MACEvent);

message WatchMACsRequest {
    uint32 vni = 1;  // Optional filter by VNI
}

message MACEvent {
    string type = 1;  // "learned", "aged", "removed"
    MACEntry entry = 2;
}
```

## Examples

### Create VNI and Establish Tunnel (REST)

```bash
# Create VNI
curl -X POST https://localhost:8443/api/v1/sdn/overlay/vnis \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1000100,
    "vlan_id": 100
  }'

# Join VNI
curl -X POST https://localhost:8443/api/v1/sdn/overlay/vnis/1000100/join \
  --cert client.crt --key client.key --cacert ca.crt

# Create tunnel to remote VTEP
curl -X POST https://localhost:8443/api/v1/sdn/overlay/tunnels \
  --cert client.crt --key client.key --cacert ca.crt \
  -H "Content-Type: application/json" \
  -d '{
    "remote_vtep": "10.0.0.2",
    "vnis": [1000100]
  }'
```

### Monitor Tunnels (gRPC Go)

```go
import (
    "context"
    pb "github.com/jeremyhahn/go-trusted-platform/api/sdn/overlay/v1"
)

func watchTunnels(ctx context.Context, client pb.OverlayServiceClient) error {
    stream, err := client.WatchTunnels(ctx, &pb.WatchTunnelsRequest{})
    if err != nil {
        return err
    }

    for {
        event, err := stream.Recv()
        if err != nil {
            return err
        }

        switch event.Type {
        case "established":
            log.Printf("Tunnel established: %s -> %s",
                event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
        case "unhealthy":
            log.Printf("Tunnel unhealthy: %s -> %s",
                event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
        case "failed":
            log.Printf("Tunnel failed: %s -> %s",
                event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
        }
    }
}
```

## See Also

- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [SDN API Reference](../api-reference.md)
- [CLI Reference](../cli-usage.md)
