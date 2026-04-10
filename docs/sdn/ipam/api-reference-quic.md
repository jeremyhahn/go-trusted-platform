# IPAM QUIC API Reference

QUIC transport for the IPAM service, providing low-latency, multiplexed connections.

| Property | Value |
|----------|-------|
| Service | `ipam.IPAMService` |
| Port | 9444 |
| Transport | QUIC (UDP) with TLS 1.3 |

## Overview

QUIC transport provides several advantages for IPAM operations:

- **0-RTT connection establishment** - Fast allocation requests
- **Stream multiplexing** - Independent streams for pools and allocations
- **Built-in encryption** - TLS 1.3 integrated into transport
- **Connection migration** - Handle network changes gracefully
- **Low latency** - Ideal for high-frequency allocation workloads

## Connection Setup

### TLS Configuration

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    ipam "github.com/jeremyhahn/go-trusted-platform/api/sdn/ipam/v1"
)

func NewIPAMQUICClient(addr string, tlsConfig *tls.Config) (ipam.IPAMServiceClient, error) {
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"ipam-quic-v1"}

    quicConfig := &quic.Config{
        MaxIdleTimeout:        30 * time.Second,
        KeepAlivePeriod:       10 * time.Second,
        MaxIncomingStreams:    1000,
        MaxIncomingUniStreams: 1000,
        Enable0RTT:            true,
    }

    conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return ipam.NewIPAMServiceClientQUIC(conn), nil
}
```

### Connection with 0-RTT

```go
func NewIPAMQUICClient0RTT(addr string, tlsConfig *tls.Config, sessionCache tls.ClientSessionCache) (ipam.IPAMServiceClient, error) {
    tlsConfig.ClientSessionCache = sessionCache
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"ipam-quic-v1"}

    quicConfig := &quic.Config{
        Enable0RTT: true,
    }

    conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return ipam.NewIPAMServiceClientQUIC(conn), nil
}
```

## Service Methods

### Pool Operations

#### CreatePool

```go
client, err := NewIPAMQUICClient("platform.example.com:9444", tlsConfig)
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
fmt.Printf("Pool created: %s (%d IPs available)\n", pool.Name, pool.AvailableIps)
```

#### GetPool

```go
pool, err := client.GetPool(ctx, &ipam.GetPoolRequest{
    PoolId: "prod-v4",
})
if err != nil {
    return err
}
fmt.Printf("Pool: %s\n", pool.Name)
fmt.Printf("  CIDR: %s\n", pool.Cidr)
fmt.Printf("  Gateway: %s\n", pool.Gateway)
fmt.Printf("  Total: %d, Allocated: %d, Available: %d\n",
    pool.TotalIps, pool.AllocatedIps, pool.AvailableIps)
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
    fmt.Printf("%s (%s): %d/%d used\n",
        pool.Name, pool.Cidr, pool.AllocatedIps, pool.TotalIps)
}
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
fmt.Printf("  Total: %d\n", stats.TotalIps)
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
    Metadata:      map[string]string{"environment": "production"},
    LeaseDuration: durationpb.New(48 * time.Hour),
})
if err != nil {
    return err
}
fmt.Printf("Allocated: %s\n", alloc.Ip)
fmt.Printf("  Pool: %s\n", alloc.PoolId)
fmt.Printf("  Device: %s\n", alloc.DeviceId)
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
fmt.Printf("Released: %s from pool %s\n", resp.Ip, resp.PoolId)
```

#### ReleaseByDeviceID

```go
resp, err := client.ReleaseByDeviceID(ctx, &ipam.ReleaseByDeviceIDRequest{
    DeviceId: "vm-001",
})
if err != nil {
    return err
}
fmt.Printf("Released %d IPs for device %s\n",
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
fmt.Printf("Allocation: %s\n", alloc.Ip)
fmt.Printf("  Pool: %s\n", alloc.PoolId)
fmt.Printf("  Device: %s\n", alloc.DeviceId)
fmt.Printf("  Hostname: %s\n", alloc.Hostname)
fmt.Printf("  Status: %s\n", alloc.Status)
fmt.Printf("  Last seen: %s\n", alloc.LastSeen.AsTime())
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
for _, alloc := range resp.Allocations {
    fmt.Printf("%s -> %s (%s)\n", alloc.Ip, alloc.DeviceId, alloc.Status)
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
for _, alloc := range resp.Allocations {
    fmt.Printf("%s in pool %s\n", alloc.Ip, alloc.PoolId)
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
fmt.Printf("Renewed: %s\n", resp.Ip)
fmt.Printf("  Last seen: %s\n", resp.LastSeen.AsTime())
fmt.Printf("  Expires: %s\n", resp.ExpiresAt.AsTime())
```

#### ExpireInactive

```go
resp, err := client.ExpireInactive(ctx, &ipam.ExpireInactiveRequest{
    PoolId: "prod-v4",
})
if err != nil {
    return err
}
fmt.Printf("Expired %d allocations in pool %s\n",
    resp.ExpiredCount, resp.PoolId)
for _, alloc := range resp.ExpiredAllocations {
    fmt.Printf("  %s (last seen: %s)\n",
        alloc.Ip, alloc.LastSeen.AsTime())
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
fmt.Printf("Reserved: %s\n", alloc.Ip)
```

#### Unreserve

```go
resp, err := client.Unreserve(ctx, &ipam.UnreserveRequest{
    Ip: "10.0.0.200",
})
if err != nil {
    return err
}
fmt.Printf("Unreserved: %s\n", resp.Ip)
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
for _, alloc := range resp.Allocations {
    fmt.Printf("%s: %s\n", alloc.Ip, alloc.Description)
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
fmt.Printf("Allocated %d/%d IPs\n",
    resp.TotalAllocated, resp.TotalRequested)
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s -> %s\n", alloc.Ip, alloc.DeviceId)
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
fmt.Printf("Released %d/%d IPs\n",
    resp.TotalReleased, resp.TotalRequested)
```

### Health

#### Ping

```go
resp, err := client.Ping(ctx, &ipam.PingRequest{})
if err != nil {
    return err
}
fmt.Printf("IPAM healthy: %v (backend: %s)\n",
    resp.Healthy, resp.Backend)
```

## Error Handling

```go
import (
    "github.com/quic-go/quic-go"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

alloc, err := client.Allocate(ctx, req)
if err != nil {
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        log.Printf("QUIC error: code=%d", qErr.ErrorCode)
    }

    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.NotFound:
            log.Printf("Pool not found")
        case codes.AlreadyExists:
            log.Printf("IP already allocated")
        case codes.ResourceExhausted:
            log.Printf("Pool exhausted - no available IPs")
        }
    }

    return err
}
```

## CLI Usage

```bash
# Use QUIC transport
platformctl --transport quic ipam pool list

# Create pool
platformctl --transport quic ipam pool create \
  --id prod-v4 \
  --name "Production IPv4" \
  --cidr 10.0.0.0/24 \
  --gateway 10.0.0.1

# Get pool stats
platformctl --transport quic ipam pool stats prod-v4

# Allocate IP
platformctl --transport quic ipam allocate \
  --pool prod-v4 \
  --device vm-001 \
  --hostname webserver

# Allocate specific IP
platformctl --transport quic ipam allocate \
  --pool prod-v4 \
  --device db-001 \
  --ip 10.0.0.100

# Release IP
platformctl --transport quic ipam release --ip 10.0.0.50

# Renew lease
platformctl --transport quic ipam renew --ip 10.0.0.50

# List allocations
platformctl --transport quic ipam allocations --pool prod-v4
platformctl --transport quic ipam allocations --device vm-001

# Reserve IP
platformctl --transport quic ipam reserve \
  --pool prod-v4 \
  --ip 10.0.0.200 \
  --description "Load balancer"
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [MCP API Reference](api-reference-mcp.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)
