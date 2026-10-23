# VXLAN Overlay API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> Index of the overlay's transports.

## Overview

The VXLAN overlay subsystem provides management operations through
multiple protocols. All operations are available via REST, gRPC, QUIC,
MCP, and Unix Socket (gRPC over UDS).

## Protocol-Specific Documentation

| Protocol | Documentation | Port | Use Case |
|----------|---------------|------|----------|
| REST | [api-reference-rest.md](api-reference-rest.md) | 8443 | Web clients, external systems |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | 10443 | High-performance service-to-service |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | 9444 | Low-latency, mobile clients |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | 9445 | AI/LLM integration |
| Unix Socket | [api-reference-unix.md](api-reference-unix.md) | /run/platformd.sock | Local IPC, CLI |

## Service Operations

The overlay service exposes a read-mostly management surface over
platformd's overlay controller. The controller registers the local VTEP
itself; nothing feeds it remote VTEPs, tunnels or learned MACs, so the
VTEP list holds this node alone, the tunnel and MAC lists are empty, and
`GetTunnelStats` and `ForgetMAC` answer not found (see
[Overlay Controller](architecture.md#overlay-controller)). The remote
VTEPs and MACs EVPN delivers are the gateway's, read with
`platformctl sdn gateway overlay vteps` and `platformctl sdn gateway snapshot`.


| Operation | Description |
|-----------|-------------|
| GetOverlayStatus | Node ID, VTEP IP, VTEP/VNI/tunnel/MAC counts, health |
| ListVTEPs | List all known VTEPs |
| GetVTEP | Get VTEP details by node ID |
| ListVNIs | List all configured VNIs |
| CreateVNI | Create a VNI with VLAN mapping |
| DeleteVNI | Delete a VNI |
| ListTunnels | List VXLAN tunnels (optional VNI filter) |
| GetTunnelStats | Get tunnel counters for a remote VTEP + VNI |
| ListRemoteMACs | List MACs learned from remote VTEPs (optional VNI filter) |
| ForgetMAC | Remove a learned MAC from the FDB |

## Data Types

From `pkg/api/grpc/proto/overlay.proto`:

```protobuf
message VTEPInfo {
  string node_id = 1;
  string ip = 2;
  bool healthy = 3;
  google.protobuf.Timestamp last_seen = 4;
  repeated uint32 vnis = 5;
  uint32 mac_count = 6;
  uint64 bytes_sent = 7;
  uint64 bytes_recv = 8;
}

message VNIConfig {
  uint32 vni = 1;
  uint32 vlan = 2;
  string name = 3;
  map<string, string> labels = 4;
}

message TunnelInfo {
  string local_vtep = 1;
  string remote_vtep = 2;
  uint32 vni = 3;
  string state = 4;
  uint64 bytes_tx = 5;
  uint64 bytes_rx = 6;
}

message RemoteMACEntry {
  string mac = 1;
  uint32 vni = 2;
  string remote_vtep = 3;
  google.protobuf.Timestamp learned_at = 4;
}

message OverlayStatus {
  string node_id = 1;
  string vtep_ip = 2;
  uint32 vtep_count = 3;
  uint32 vni_count = 4;
  uint32 tunnel_count = 5;
  uint32 remote_mac_count = 6;
  bool healthy = 7;
  uint32 vxlan_port = 8;
  uint32 underlay_mtu = 9;
}
```

`CreateVNI` stores only `vni` and `vlan`; `name` and `labels` are accepted
and dropped.

`OverlayStatus` carries no ND suppression counters. ND suppression runs in
the gateway overlay mode, and its counters are on that handler's status
(`OverlayModeStatus.NDSuppression` and `NDCounters`, see
[ND suppression](../../gateway/engineering.md#nd-suppression)). gatewayd's
`overlay` service reports `NDCounters` in the overlay section of the gateway
telemetry snapshot (`nd_counters`), served on every transport
([gateway API](../../gateway/api.md)) and by `platformctl sdn gateway snapshot`.

## REST API Quick Reference

Base URL: `https://localhost:8443/api/v1/overlay` (the webservice; the
daemon-only REST stack uses `/api/v1/sdn/overlay`, see
[api-reference-rest.md](api-reference-rest.md))

```http
GET    /status                          # Overlay status
GET    /vteps                           # List all VTEPs
GET    /vteps/{nodeId}                  # Get VTEP by node ID
GET    /vnis                            # List all VNIs
POST   /vnis                            # Create VNI
DELETE /vnis/{vni}                      # Delete VNI
GET    /tunnels[?vni=N]                 # List tunnels (optional VNI filter)
GET    /tunnels/stats?remote_vtep=IP&vni=N  # Tunnel counters
GET    /macs[?vni=N]                    # List remote MACs (optional VNI filter)
DELETE /macs?mac=MAC&vni=N              # Forget a learned MAC
```

## gRPC API Quick Reference

```protobuf
service OverlayService {
  rpc ListVTEPs(ListVTEPsRequest) returns (ListVTEPsResponse);
  rpc GetVTEP(GetVTEPRequest) returns (GetVTEPResponse);
  rpc CreateVNI(CreateVNIRequest) returns (CreateVNIResponse);
  rpc DeleteVNI(DeleteVNIRequest) returns (DeleteVNIResponse);
  rpc ListVNIs(ListVNIsRequest) returns (ListVNIsResponse);
  rpc ListTunnels(ListTunnelsRequest) returns (ListTunnelsResponse);
  rpc GetTunnelStats(GetTunnelStatsRequest) returns (GetTunnelStatsResponse);
  rpc ListRemoteMACs(ListRemoteMACsRequest) returns (ListRemoteMACsResponse);
  rpc ForgetMAC(ForgetMACRequest) returns (ForgetMACResponse);
  rpc GetOverlayStatus(GetOverlayStatusRequest) returns (GetOverlayStatusResponse);
}
```

## CLI Reference

```bash
# Status
platformctl sdn overlay status

# VTEPs
platformctl sdn overlay vtep list
platformctl sdn overlay vtep get node-001

# VNIs
platformctl sdn overlay vni list
platformctl sdn overlay vni create --vni 1000100 --vlan 100 --name production
platformctl sdn overlay vni delete 1000100

# Tunnels
platformctl sdn overlay tunnel list [--vni 1000100]

# MACs
platformctl sdn overlay mac list [--vni 1000100]
platformctl sdn overlay mac forget aa:bb:cc:dd:ee:ff --vni 1000100
```

## See Also

- [README](README.md) — Overlay overview
- [Architecture](architecture.md) — Component design
- [Configuration](configuration.md) — Configuration reference
- [Operations](operations.md) — Operational procedures
