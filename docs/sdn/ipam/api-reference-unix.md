# IPAM Unix Socket API Reference

Unix socket interface for local IPC with the IPAM service.

| Property | Value |
|----------|-------|
| Socket Path | `/run/platformd.sock` |
| Protocol | gRPC over Unix socket |
| Authentication | Peer credentials (SO_PEERCRED) |

## Overview

The Unix socket API provides:

- **Zero network overhead** - Direct kernel-level IPC
- **Automatic authentication** - Uses Unix peer credentials
- **CLI integration** - Primary transport for platformctl
- **Local-only access** - Secure for IP management operations

## Connection Setup

### Go Client

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    ipam "github.com/jeremyhahn/go-trusted-platform/api/sdn/ipam/v1"
)

func NewIPAMUnixClient() (ipam.IPAMServiceClient, error) {
    socketPath := "/run/platformd.sock"

    dialer := func(ctx context.Context, addr string) (net.Conn, error) {
        return net.Dial("unix", socketPath)
    }

    conn, err := grpc.DialContext(
        context.Background(),
        "unix://"+socketPath,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithContextDialer(dialer),
    )
    if err != nil {
        return nil, err
    }

    return ipam.NewIPAMServiceClient(conn), nil
}
```

## Service Methods

### Pool Operations

#### CreatePool

```go
client, err := NewIPAMUnixClient()
if err != nil {
    return err
}

pool, err := client.CreatePool(ctx, &ipam.CreatePoolRequest{
    Id:                   "prod-v4",
    Name:                 "Production IPv4",
    Cidr:                 "10.0.0.0/24",
    Gateway:              "10.0.0.1",
    Description:          "Internal production workloads",
    Tags:                 []string{"production", "internal"},
    DefaultLeaseDuration: durationpb.New(24 * time.Hour),
    InactivityTimeout:    durationpb.New(30 * 24 * time.Hour),
})
if err != nil {
    return err
}
fmt.Printf("Pool created: %s\n", pool.Name)
fmt.Printf("  CIDR: %s\n", pool.Cidr)
fmt.Printf("  Gateway: %s\n", pool.Gateway)
fmt.Printf("  Total IPs: %d\n", pool.TotalIps)
```

#### GetPool

```go
pool, err := client.GetPool(ctx, &ipam.GetPoolRequest{
    PoolId: "prod-v4",
})
if err != nil {
    return err
}
fmt.Printf("Pool: %s (%s)\n", pool.Name, pool.Id)
fmt.Printf("  CIDR: %s\n", pool.Cidr)
fmt.Printf("  Gateway: %s\n", pool.Gateway)
fmt.Printf("  Total: %d\n", pool.TotalIps)
fmt.Printf("  Allocated: %d\n", pool.AllocatedIps)
fmt.Printf("  Available: %d\n", pool.AvailableIps)
fmt.Printf("  Default Lease: %s\n", pool.DefaultLeaseDuration.AsDuration())
```

#### GetPoolByName

```go
pool, err := client.GetPoolByName(ctx, &ipam.GetPoolByNameRequest{
    Name: "Production IPv4",
})
```

#### GetPoolByCIDR

```go
pool, err := client.GetPoolByCIDR(ctx, &ipam.GetPoolByCIDRRequest{
    Cidr: "10.0.0.0/24",
})
```

#### ListPools

```go
resp, err := client.ListPools(ctx, &ipam.ListPoolsRequest{
    Tag:      "production",
    PageSize: 100,
})
if err != nil {
    return err
}
for _, pool := range resp.Pools {
    utilization := float64(pool.AllocatedIps) / float64(pool.TotalIps) * 100
    fmt.Printf("%s (%s): %.1f%% used (%d/%d)\n",
        pool.Name, pool.Cidr, utilization, pool.AllocatedIps, pool.TotalIps)
}
```

#### UpdatePool

```go
pool, err := client.UpdatePool(ctx, &ipam.UpdatePoolRequest{
    Id:                   "prod-v4",
    Name:                 "Production IPv4 (Updated)",
    Description:          "Updated description",
    Tags:                 []string{"production", "updated"},
    DefaultLeaseDuration: durationpb.New(48 * time.Hour),
})
```

#### DeletePool

```go
resp, err := client.DeletePool(ctx, &ipam.DeletePoolRequest{
    PoolId: "dev-v4",
})
if err != nil {
    return err
}
fmt.Printf("Pool deleted: %s\n", resp.PoolId)
```

#### GetPoolStats

```go
stats, err := client.GetPoolStats(ctx, &ipam.GetPoolStatsRequest{
    PoolId: "prod-v4",
})
if err != nil {
    return err
}
fmt.Printf("Pool %s statistics:\n", stats.PoolId)
fmt.Printf("  Total IPs: %d\n", stats.TotalIps)
fmt.Printf("  Allocated: %d\n", stats.AllocatedIps)
fmt.Printf("  Available: %d\n", stats.AvailableIps)
fmt.Printf("  Expired: %d\n", stats.ExpiredIps)
fmt.Printf("  Reserved: %d\n", stats.ReservedIps)
fmt.Printf("  Utilization: %.2f%%\n", stats.UtilizationPct)
```

### Allocation Operations

#### Allocate

```go
alloc, err := client.Allocate(ctx, &ipam.AllocationRequest{
    PoolId:        "prod-v4",
    DeviceId:      "vm-001",
    Hostname:      "webserver",
    Description:   "Primary web server",
    Tags:          []string{"web", "frontend"},
    Metadata:      map[string]string{"environment": "production", "owner": "platform-team"},
    LeaseDuration: durationpb.New(48 * time.Hour),
})
if err != nil {
    return err
}
fmt.Printf("Allocated IP: %s\n", alloc.Ip)
fmt.Printf("  Pool: %s\n", alloc.PoolId)
fmt.Printf("  Device: %s\n", alloc.DeviceId)
fmt.Printf("  Hostname: %s\n", alloc.Hostname)
fmt.Printf("  Status: %s\n", alloc.Status)
fmt.Printf("  Allocated: %s\n", alloc.AllocatedAt.AsTime())
fmt.Printf("  Expires: %s\n", alloc.ExpiresAt.AsTime())
```

#### AllocateSpecific

```go
alloc, err := client.AllocateSpecific(ctx, &ipam.AllocationRequest{
    PoolId:      "prod-v4",
    DeviceId:    "db-001",
    Hostname:    "database",
    RequestedIp: "10.0.0.100",
    Description: "Primary database server",
})
if err != nil {
    return err
}
fmt.Printf("Allocated specific IP: %s\n", alloc.Ip)
```

#### Release

```go
resp, err := client.Release(ctx, &ipam.ReleaseRequest{
    Ip: "10.0.0.50",
})
if err != nil {
    return err
}
fmt.Printf("Released IP: %s\n", resp.Ip)
fmt.Printf("  From pool: %s\n", resp.PoolId)
fmt.Printf("  Device: %s\n", resp.DeviceId)
```

#### ReleaseByDeviceID

```go
resp, err := client.ReleaseByDeviceID(ctx, &ipam.ReleaseByDeviceIDRequest{
    DeviceId: "vm-001",
})
if err != nil {
    return err
}
fmt.Printf("Released %d IPs for device %s:\n",
    resp.ReleasedCount, resp.DeviceId)
for _, ip := range resp.ReleasedIps {
    fmt.Printf("  %s\n", ip)
}
```

#### GetAllocation

```go
alloc, err := client.GetAllocation(ctx, &ipam.GetAllocationRequest{
    Ip: "10.0.0.50",
})
if err != nil {
    return err
}
fmt.Printf("Allocation for %s:\n", alloc.Ip)
fmt.Printf("  Pool: %s\n", alloc.PoolId)
fmt.Printf("  Device: %s\n", alloc.DeviceId)
fmt.Printf("  Hostname: %s\n", alloc.Hostname)
fmt.Printf("  Description: %s\n", alloc.Description)
fmt.Printf("  Status: %s\n", alloc.Status)
fmt.Printf("  Allocated: %s\n", alloc.AllocatedAt.AsTime())
fmt.Printf("  Last seen: %s\n", alloc.LastSeen.AsTime())
fmt.Printf("  Expires: %s\n", alloc.ExpiresAt.AsTime())
```

#### GetAllocationsByPool

```go
resp, err := client.GetAllocationsByPool(ctx, &ipam.GetAllocationsByPoolRequest{
    PoolId:   "prod-v4",
    Status:   ipam.ALLOCATION_STATUS_ACTIVE,
    PageSize: 100,
})
if err != nil {
    return err
}
fmt.Printf("Found %d allocations:\n", resp.Total)
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s -> %s (%s) - %s\n",
        alloc.Ip, alloc.DeviceId, alloc.Hostname, alloc.Status)
}
```

#### GetAllocationsByDevice

```go
resp, err := client.GetAllocationsByDevice(ctx, &ipam.GetAllocationsByDeviceRequest{
    DeviceId: "vm-001",
    PageSize: 100,
})
if err != nil {
    return err
}
fmt.Printf("Allocations for device %s:\n", "vm-001")
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s in pool %s\n", alloc.Ip, alloc.PoolId)
}
```

### Lease Operations

#### Renew

```go
resp, err := client.Renew(ctx, &ipam.RenewRequest{
    Ip: "10.0.0.50",
})
if err != nil {
    return err
}
fmt.Printf("Renewed lease for %s\n", resp.Ip)
fmt.Printf("  Last seen: %s\n", resp.LastSeen.AsTime())
fmt.Printf("  New expiry: %s\n", resp.ExpiresAt.AsTime())
```

#### ExpireInactive

```go
resp, err := client.ExpireInactive(ctx, &ipam.ExpireInactiveRequest{
    PoolId: "prod-v4",
})
if err != nil {
    return err
}
fmt.Printf("Expired %d allocations in pool %s:\n",
    resp.ExpiredCount, resp.PoolId)
for _, alloc := range resp.ExpiredAllocations {
    fmt.Printf("  %s (device: %s, last seen: %s)\n",
        alloc.Ip, alloc.DeviceId, alloc.LastSeen.AsTime())
}
```

### Reservation Operations

#### Reserve

```go
alloc, err := client.Reserve(ctx, &ipam.ReserveRequest{
    PoolId:      "prod-v4",
    Ip:          "10.0.0.200",
    Description: "Reserved for future load balancer",
})
if err != nil {
    return err
}
fmt.Printf("Reserved IP: %s\n", alloc.Ip)
fmt.Printf("  Status: %s\n", alloc.Status)
```

#### Unreserve

```go
resp, err := client.Unreserve(ctx, &ipam.UnreserveRequest{
    Ip: "10.0.0.200",
})
if err != nil {
    return err
}
fmt.Printf("Unreserved IP: %s from pool %s\n", resp.Ip, resp.PoolId)
```

#### ListReservations

```go
resp, err := client.ListReservations(ctx, &ipam.ListReservationsRequest{
    PoolId:   "prod-v4",
    PageSize: 100,
})
if err != nil {
    return err
}
fmt.Printf("Reservations in pool %s:\n", "prod-v4")
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s: %s\n", alloc.Ip, alloc.Description)
}
```

### Batch Operations

#### AllocateBatch

```go
resp, err := client.AllocateBatch(ctx, &ipam.AllocateBatchRequest{
    Requests: []*ipam.AllocationRequest{
        {PoolId: "prod-v4", DeviceId: "vm-001", Hostname: "web-001"},
        {PoolId: "prod-v4", DeviceId: "vm-002", Hostname: "web-002"},
        {PoolId: "prod-v4", DeviceId: "vm-003", Hostname: "web-003"},
    },
})
if err != nil {
    return err
}
fmt.Printf("Batch allocation: %d/%d successful\n",
    resp.TotalAllocated, resp.TotalRequested)
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s -> %s\n", alloc.Ip, alloc.DeviceId)
}
if len(resp.FailedDeviceIds) > 0 {
    fmt.Printf("Failed devices: %v\n", resp.FailedDeviceIds)
}
```

#### ReleaseBatch

```go
resp, err := client.ReleaseBatch(ctx, &ipam.ReleaseBatchRequest{
    Ips: []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
})
if err != nil {
    return err
}
fmt.Printf("Batch release: %d/%d successful\n",
    resp.TotalReleased, resp.TotalRequested)
fmt.Printf("Released: %v\n", resp.ReleasedIps)
if len(resp.FailedIps) > 0 {
    fmt.Printf("Failed: %v\n", resp.FailedIps)
}
```

### Health

#### Ping

```go
resp, err := client.Ping(ctx, &ipam.PingRequest{})
if err != nil {
    return err
}
fmt.Printf("IPAM service healthy: %v\n", resp.Healthy)
fmt.Printf("Backend: %s\n", resp.Backend)
fmt.Printf("Timestamp: %s\n", resp.Timestamp.AsTime())
```

## CLI Integration

```bash
# List pools
platformctl ipam pool list
platformctl ipam pool list --tag production

# Get pool details
platformctl ipam pool get prod-v4

# Create pool
platformctl ipam pool create \
  --id prod-v4 \
  --name "Production IPv4" \
  --cidr 10.0.0.0/24 \
  --gateway 10.0.0.1 \
  --tags production,internal

# Update pool
platformctl ipam pool update prod-v4 \
  --name "Production IPv4 (Updated)"

# Delete pool
platformctl ipam pool delete dev-v4

# Get pool stats
platformctl ipam pool stats prod-v4

# Allocate IP
platformctl ipam allocate \
  --pool prod-v4 \
  --device vm-001 \
  --hostname webserver

# Allocate specific IP
platformctl ipam allocate \
  --pool prod-v4 \
  --device db-001 \
  --hostname database \
  --ip 10.0.0.100

# Get allocation
platformctl ipam allocation get 10.0.0.50

# List allocations
platformctl ipam allocation list --pool prod-v4
platformctl ipam allocation list --device vm-001
platformctl ipam allocation list --pool prod-v4 --status active

# Release IP
platformctl ipam release --ip 10.0.0.50

# Release all IPs for device
platformctl ipam release --device vm-001

# Renew lease
platformctl ipam renew --ip 10.0.0.50

# Expire inactive
platformctl ipam expire --pool prod-v4

# Reserve IP
platformctl ipam reserve \
  --pool prod-v4 \
  --ip 10.0.0.200 \
  --description "Load balancer"

# Unreserve IP
platformctl ipam unreserve --ip 10.0.0.200

# List reservations
platformctl ipam reservation list --pool prod-v4

# Batch allocate
platformctl ipam allocate-batch \
  --pool prod-v4 \
  --devices vm-001,vm-002,vm-003

# Batch release
platformctl ipam release-batch --ips 10.0.0.2,10.0.0.3,10.0.0.4

# Health check
platformctl ipam ping
```

## Error Handling

```go
alloc, err := client.Allocate(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.NotFound:
            fmt.Println("Pool not found")
        case codes.AlreadyExists:
            fmt.Println("IP already allocated")
        case codes.ResourceExhausted:
            fmt.Println("Pool exhausted - no available IPs")
        case codes.FailedPrecondition:
            fmt.Println("Cannot delete pool with active allocations")
        case codes.InvalidArgument:
            fmt.Println("Invalid request parameters")
        case codes.PermissionDenied:
            fmt.Println("Permission denied")
        default:
            fmt.Printf("Error: %s\n", st.Message())
        }
    }
    return err
}
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [MCP API Reference](api-reference-mcp.md)
- [Architecture](architecture.md)


## Gateway Pool CRUD via Unix Socket (Z5b)

The Unix adapter uses gRPC over the Unix socket to the same `GatewayService`
RPCs described in api-reference-grpc.md. The zone filter is passed in
`ListIPAMPoolsRequest.zone`; empty returns all pools.
