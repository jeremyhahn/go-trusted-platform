# IPAM gRPC API Reference

> **Status: REFERENCE**
> IPAM over gRPC, as part of `platform.v1.GatewayService`.

There is no standalone `IPAMService` — IPAM operations are part of
`platform.v1.GatewayService` in `pkg/api/grpc/proto/gateway.proto`,
served on TCP port 10443 (mTLS).

## IPAM RPCs

```protobuf
service GatewayService {
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
}
```

Pools carry an ID, display name, CIDR (immutable after creation),
gateway address, zone, description, default lease duration, and the
allocation window: `reserved` (never-allocatable prefixes; the gateway is
always reserved), `range_start` and `range_end` (the dynamic window
`AllocateIP` draws from). `UpdateIPAMPoolRequest` replaces the window only
when `update_window` is true, with exactly the values given (empty clears).
A reserved address or a window that does not fit the CIDR is
`InvalidArgument`. Allocations associate an IP with a device ID and optional
hostname.

## Usage Example (Go)

```go
import platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

client := platformv1.NewGatewayServiceClient(conn)

pools, err := client.ListIPAMPools(ctx, &platformv1.ListIPAMPoolsRequest{})

pool, err := client.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
    Name:       "lab",
    Cidr:       "10.4.9.0/24",
    Gateway:    "10.4.9.1",
    Reserved:   []string{"10.4.9.1/32"},
    RangeStart: "10.4.9.50",
    RangeEnd:   "10.4.9.254",
})

alloc, err := client.AllocateIP(ctx, &platformv1.AllocateIPRequest{
    PoolId:   "pool1",
    DeviceId: "vm-123",
    Hostname: "webserver",
})
```

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway gRPC API Reference](../../gateway/api.md)
