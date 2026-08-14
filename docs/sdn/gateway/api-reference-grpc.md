# Gateway gRPC API Reference

Endpoint: `localhost:10443`, mTLS required.

Service and messages: `pkg/api/grpc/proto/gateway.proto`
(package `platform.v1`); generated Go client in `sdk/go/gen`.

## Service Definition

```protobuf
service GatewayService {
  // Gateway status and mode
  rpc GetGatewayStatus(GetGatewayStatusRequest) returns (GetGatewayStatusResponse);
  rpc SetGatewayMode(SetGatewayModeRequest) returns (SetGatewayModeResponse);

  // BGP operations
  rpc GetBGPStatus(GetBGPStatusRequest) returns (GetBGPStatusResponse);
  rpc ListBGPPeers(ListBGPPeersRequest) returns (ListBGPPeersResponse);
  rpc AnnouncePrefix(AnnouncePrefixRequest) returns (AnnouncePrefixResponse);
  rpc WithdrawPrefix(WithdrawPrefixRequest) returns (WithdrawPrefixResponse);
  rpc ListAnnouncedPrefixes(ListAnnouncedPrefixesRequest) returns (ListAnnouncedPrefixesResponse);

  // IPAM pool management
  rpc CreateIPAMPool(CreateIPAMPoolRequest) returns (CreateIPAMPoolResponse);
  rpc GetIPAMPool(GetIPAMPoolRequest) returns (GetIPAMPoolResponse);
  rpc UpdateIPAMPool(UpdateIPAMPoolRequest) returns (UpdateIPAMPoolResponse);
  rpc DeleteIPAMPool(DeleteIPAMPoolRequest) returns (DeleteIPAMPoolResponse);
  rpc ListIPAMPools(ListIPAMPoolsRequest) returns (ListIPAMPoolsResponse);

  // IPAM allocations
  rpc AllocateIP(AllocateIPRequest) returns (AllocateIPResponse);
  rpc ReleaseIP(ReleaseIPRequest) returns (ReleaseIPResponse);
  rpc ListAllocations(ListAllocationsRequest) returns (ListAllocationsResponse);

  // Load balancer (OVS-native L4 VIPs)
  rpc AddVIP(AddVIPRequest) returns (AddVIPResponse);
  rpc RemoveVIP(RemoveVIPRequest) returns (RemoveVIPResponse);
  rpc GetVIP(GetVIPRequest) returns (GetVIPResponse);
  rpc ListVIPs(ListVIPsRequest) returns (ListVIPsResponse);
  rpc SetVIPBackends(SetVIPBackendsRequest) returns (SetVIPBackendsResponse);
  rpc GetLBStatus(GetLBStatusRequest) returns (GetLBStatusResponse);

  // Performance verification (real datapath measurements)
  rpc GetPerfFlows(GetPerfFlowsRequest) returns (GetPerfFlowsResponse);
  rpc GetPerfDatapath(GetPerfDatapathRequest) returns (GetPerfDatapathResponse);
  rpc GetPerfConntrack(GetPerfConntrackRequest) returns (GetPerfConntrackResponse);
}
```

Note: there is no gateway register/deregister, health-check, cluster,
or device-onboarding RPC — gateway lifecycle is config-driven and node
health is reported through `GetGatewayStatus` and the daemon health
service.

## Key Semantics

- **SetGatewayMode** replaces the active mode set (`overlay`, `edge`,
  `transit`).
- **VIPs** are identified by the `(protocol, address, port)` triple;
  backends are `VIPBackend{address, port, weight}` and are replaced
  atomically with `SetVIPBackends`.
- **GetPerfFlows** MUTATES the bridge flow tables (installs and removes
  ephemeral flows in perf table 250) and requires write permission; the
  datapath/conntrack RPCs are read-only.

## Usage Example (Go)

```go
import platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

client := platformv1.NewGatewayServiceClient(conn)

status, err := client.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})

resp, err := client.AddVIP(ctx, &platformv1.AddVIPRequest{
    Config: &platformv1.VIPConfig{
        Protocol: "tcp",
        Address:  "10.100.0.10",
        Port:     443,
        Backends: []*platformv1.VIPBackend{
            {Address: "10.0.1.5", Port: 8443, Weight: 2},
            {Address: "10.0.1.6", Port: 8443},
        },
    },
})
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [Operations Guide](operations.md)
- [Load Balancer](loadbalancer.md)
