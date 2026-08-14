# VXLAN Overlay gRPC API Reference

## Overview

| Property | Value |
|----------|-------|
| Service | `platform.v1.OverlayService` |
| Port | 10443 (TLS) |
| Proto | `pkg/api/grpc/proto/overlay.proto` |

## Service Definition

```protobuf
service OverlayService {
  // VTEP management
  rpc ListVTEPs(ListVTEPsRequest) returns (ListVTEPsResponse);
  rpc GetVTEP(GetVTEPRequest) returns (GetVTEPResponse);

  // VNI management
  rpc CreateVNI(CreateVNIRequest) returns (CreateVNIResponse);
  rpc DeleteVNI(DeleteVNIRequest) returns (DeleteVNIResponse);
  rpc ListVNIs(ListVNIsRequest) returns (ListVNIsResponse);

  // Tunnel monitoring
  rpc ListTunnels(ListTunnelsRequest) returns (ListTunnelsResponse);
  rpc GetTunnelStats(GetTunnelStatsRequest) returns (GetTunnelStatsResponse);

  // MAC table
  rpc ListRemoteMACs(ListRemoteMACsRequest) returns (ListRemoteMACsResponse);
  rpc ForgetMAC(ForgetMACRequest) returns (ForgetMACResponse);

  // Status
  rpc GetOverlayStatus(GetOverlayStatusRequest) returns (GetOverlayStatusResponse);
}
```

## Messages

```protobuf
message GetVTEPRequest      { string node_id = 1; }
message CreateVNIRequest    { VNIConfig config = 1; }
message DeleteVNIRequest    { uint32 vni = 1; }
message ListTunnelsRequest  { uint32 vni = 1; }          // 0 for all VNIs
message GetTunnelStatsRequest {
  string remote_vtep = 1;
  uint32 vni = 2;
}
message ListRemoteMACsRequest { uint32 vni = 1; }        // 0 for all VNIs
message ForgetMACRequest {
  string mac = 1;
  uint32 vni = 2;
}
```

See [api-reference.md](api-reference.md) for the shared data types
(`VTEPInfo`, `VNIConfig`, `VNI`, `TunnelInfo`, `RemoteMACEntry`,
`OverlayStatus`).

## Example (grpcurl)

```bash
# Overlay status
grpcurl -cacert ca.pem -cert client.pem -key client.key \
  localhost:10443 platform.v1.OverlayService/GetOverlayStatus

# Create a VNI
grpcurl -cacert ca.pem -cert client.pem -key client.key \
  -d '{"config": {"vni": 1000100, "vlan": 100, "name": "production"}}' \
  localhost:10443 platform.v1.OverlayService/CreateVNI

# Forget a MAC
grpcurl -cacert ca.pem -cert client.pem -key client.key \
  -d '{"mac": "aa:bb:cc:dd:ee:ff", "vni": 1000100}' \
  localhost:10443 platform.v1.OverlayService/ForgetMAC
```

## See Also

- [API Reference](api-reference.md) — Overview and data types
- [Unix API Reference](api-reference-unix.md) — Same service over UDS
