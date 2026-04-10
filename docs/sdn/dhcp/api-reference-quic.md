# DHCP QUIC API Reference

QUIC transport for the DHCP service, providing low-latency, multiplexed connections.

| Property | Value |
|----------|-------|
| Service | `dhcp.DHCPService` |
| Port | 9444 |
| Transport | QUIC (UDP) with TLS 1.3 |

## Overview

QUIC transport provides several advantages for DHCP management operations:

- **0-RTT connection establishment** - Fast reconnection for monitoring
- **Stream multiplexing** - Independent streams for leases and events
- **Built-in encryption** - TLS 1.3 integrated into transport
- **Connection migration** - Handle network changes gracefully
- **Low latency** - Ideal for real-time lease monitoring

## Connection Setup

### TLS Configuration

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    dhcp "github.com/jeremyhahn/go-trusted-platform/api/sdn/dhcp/v1"
)

func NewDHCPQUICClient(addr string, tlsConfig *tls.Config) (dhcp.DHCPServiceClient, error) {
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"dhcp-quic-v1"}

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

    return dhcp.NewDHCPServiceClientQUIC(conn), nil
}
```

### Connection with 0-RTT

```go
func NewDHCPQUICClient0RTT(addr string, tlsConfig *tls.Config, sessionCache tls.ClientSessionCache) (dhcp.DHCPServiceClient, error) {
    tlsConfig.ClientSessionCache = sessionCache
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"dhcp-quic-v1"}

    quicConfig := &quic.Config{
        Enable0RTT: true,
    }

    conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return dhcp.NewDHCPServiceClientQUIC(conn), nil
}
```

## Service Methods

### Status Operations

#### GetStatus

```go
client, err := NewDHCPQUICClient("platform.example.com:9444", tlsConfig)
if err != nil {
    return err
}

status, err := client.GetStatus(ctx, &dhcp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("DHCP Server Running: %v\n", status.Running)
fmt.Printf("IPAM Backend: %s\n", status.IpamBackend)
fmt.Printf("Uptime: %d seconds\n", status.UptimeSeconds)
for _, iface := range status.Interfaces {
    fmt.Printf("  Interface %s: %s (pool: %s)\n",
        iface.Name, iface.Address, iface.PoolId)
}
```

#### GetStats

```go
stats, err := client.GetStats(ctx, &dhcp.GetStatsRequest{})
if err != nil {
    return err
}
fmt.Printf("DHCP Statistics:\n")
fmt.Printf("  Started: %s\n", stats.StartedAt.AsTime())
fmt.Printf("  Packets: %d received, %d sent\n",
    stats.PacketsReceived, stats.PacketsSent)
fmt.Printf("  DISCOVER: %d\n", stats.DiscoverCount)
fmt.Printf("  OFFER: %d\n", stats.OfferCount)
fmt.Printf("  REQUEST: %d\n", stats.RequestCount)
fmt.Printf("  ACK: %d\n", stats.AckCount)
fmt.Printf("  NAK: %d\n", stats.NakCount)
fmt.Printf("  RELEASE: %d\n", stats.ReleaseCount)
fmt.Printf("  Active Leases: %d\n", stats.ActiveLeases)
```

### Lease Operations

#### GetLease

```go
lease, err := client.GetLease(ctx, &dhcp.GetLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})
if err != nil {
    return err
}
fmt.Printf("Lease for %s:\n", lease.Mac)
fmt.Printf("  IP: %s\n", lease.Ip)
fmt.Printf("  Hostname: %s\n", lease.Hostname)
fmt.Printf("  Pool: %s\n", lease.PoolId)
fmt.Printf("  Interface: %s\n", lease.Interface)
fmt.Printf("  State: %s\n", lease.State)
fmt.Printf("  Leased: %s\n", lease.LeasedAt.AsTime())
fmt.Printf("  Expires: %s\n", lease.ExpiresAt.AsTime())
fmt.Printf("  Time remaining: %d seconds\n", lease.TimeRemainingSeconds)
```

#### GetLeaseByIP

```go
lease, err := client.GetLeaseByIP(ctx, &dhcp.GetLeaseByIPRequest{
    Ip: "192.168.1.100",
})
if err != nil {
    return err
}
fmt.Printf("Lease for IP %s:\n", lease.Ip)
fmt.Printf("  MAC: %s\n", lease.Mac)
fmt.Printf("  Hostname: %s\n", lease.Hostname)
```

#### ListLeases

```go
resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
    PoolId:    "internal-pool",
    State:     dhcp.LEASE_STATE_ACTIVE,
    Limit:     100,
})
if err != nil {
    return err
}
fmt.Printf("Found %d leases:\n", resp.Total)
for _, lease := range resp.Leases {
    fmt.Printf("  %s -> %s (%s) - %s\n",
        lease.Mac, lease.Ip, lease.Hostname, lease.State)
}
```

#### ReleaseLease

```go
_, err := client.ReleaseLease(ctx, &dhcp.ReleaseLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})
if err != nil {
    return err
}
fmt.Println("Lease released")
```

#### ExpireLeases

```go
resp, err := client.ExpireLeases(ctx, &dhcp.ExpireLeasesRequest{})
if err != nil {
    return err
}
fmt.Printf("Expired %d leases, %d active remaining\n",
    resp.ExpiredCount, resp.ActiveLeases)
```

### Interface Operations

#### ListInterfaces

```go
resp, err := client.ListInterfaces(ctx, &dhcp.ListInterfacesRequest{})
if err != nil {
    return err
}
for _, iface := range resp.Interfaces {
    fmt.Printf("Interface %s:\n", iface.Name)
    fmt.Printf("  Network: %s\n", iface.Network)
    fmt.Printf("  Address: %s\n", iface.Address)
    fmt.Printf("  Pool: %s\n", iface.PoolId)
    fmt.Printf("  Active Leases: %d\n", iface.ActiveLeases)
    fmt.Printf("  Options:\n")
    fmt.Printf("    Router: %s\n", iface.Options.Router)
    fmt.Printf("    DNS: %v\n", iface.Options.Dns)
    fmt.Printf("    Lease Time: %d\n", iface.Options.LeaseTimeSeconds)
}
```

#### GetInterface

```go
iface, err := client.GetInterface(ctx, &dhcp.GetInterfaceRequest{
    Name: "eth0",
})
if err != nil {
    return err
}
fmt.Printf("Interface %s:\n", iface.Name)
fmt.Printf("  Network: %s\n", iface.Network)
fmt.Printf("  Address: %s\n", iface.Address)
fmt.Printf("  Pool: %s\n", iface.PoolId)
```

#### UpdateInterfaceOptions

```go
iface, err := client.UpdateInterfaceOptions(ctx, &dhcp.UpdateInterfaceOptionsRequest{
    Name: "eth0",
    Options: &dhcp.DHCPOptionsUpdate{
        Dns:               []string{"1.1.1.1", "8.8.8.8"},
        DomainName:        "newdomain.local",
        LeaseTimeSeconds:  43200,
    },
})
if err != nil {
    return err
}
fmt.Printf("Updated interface %s options\n", iface.Name)
```

### Pool Operations

#### GetPoolStats

```go
stats, err := client.GetPoolStats(ctx, &dhcp.GetPoolStatsRequest{
    PoolId: "internal-pool",
})
if err != nil {
    return err
}
fmt.Printf("Pool %s:\n", stats.PoolId)
fmt.Printf("  Total: %d\n", stats.TotalAddresses)
fmt.Printf("  Allocated: %d\n", stats.Allocated)
fmt.Printf("  Available: %d\n", stats.Available)
fmt.Printf("  Utilization: %.1f%%\n", stats.UtilizationPercent)
fmt.Printf("  Leases by state:\n")
for state, count := range stats.LeasesByState {
    fmt.Printf("    %s: %d\n", state, count)
}
```

## Streaming Operations

### WatchLeases

Monitor lease events in real-time.

```go
stream, err := client.WatchLeases(ctx, &dhcp.WatchLeasesRequest{
    PoolId:         "internal-pool",
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
    case dhcp.LEASE_EVENT_CREATED:
        log.Printf("[+] New lease: %s -> %s (%s)",
            event.Lease.Mac, event.Lease.Ip, event.Lease.Hostname)
    case dhcp.LEASE_EVENT_RENEWED:
        log.Printf("[~] Lease renewed: %s -> %s",
            event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_RELEASED:
        log.Printf("[-] Lease released: %s",
            event.Lease.Mac)
    case dhcp.LEASE_EVENT_EXPIRED:
        log.Printf("[!] Lease expired: %s -> %s",
            event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_DECLINED:
        log.Printf("[X] Lease declined: %s -> %s",
            event.Lease.Mac, event.Lease.Ip)
    }
}
```

### Multiple Concurrent Streams

```go
var wg sync.WaitGroup

// Stream 1: Watch internal pool
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchLeases(ctx, &dhcp.WatchLeasesRequest{
        PoolId: "internal-pool",
    })
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleInternalPoolEvent(event)
    }
}()

// Stream 2: Watch public pool
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchLeases(ctx, &dhcp.WatchLeasesRequest{
        PoolId: "public-pool",
    })
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handlePublicPoolEvent(event)
    }
}()

wg.Wait()
```

## Error Handling

```go
import (
    "github.com/quic-go/quic-go"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

lease, err := client.GetLease(ctx, req)
if err != nil {
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        log.Printf("QUIC error: code=%d", qErr.ErrorCode)
    }

    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.NotFound:
            log.Printf("Lease not found")
        case codes.InvalidArgument:
            log.Printf("Invalid MAC address format")
        case codes.Unavailable:
            log.Printf("DHCP server not running")
        }
    }

    return err
}
```

## CLI Usage

```bash
# Use QUIC transport
platformctl --transport quic dhcp status

# Get server statistics
platformctl --transport quic dhcp stats

# List leases
platformctl --transport quic dhcp lease list
platformctl --transport quic dhcp lease list --pool internal-pool
platformctl --transport quic dhcp lease list --state active

# Get lease by MAC
platformctl --transport quic dhcp lease get --mac aa:bb:cc:dd:ee:ff

# Get lease by IP
platformctl --transport quic dhcp lease get --ip 192.168.1.100

# Release lease
platformctl --transport quic dhcp lease release --mac aa:bb:cc:dd:ee:ff

# Expire old leases
platformctl --transport quic dhcp lease expire

# List interfaces
platformctl --transport quic dhcp interface list

# Get interface
platformctl --transport quic dhcp interface get eth0

# Update interface options
platformctl --transport quic dhcp interface update eth0 \
  --dns 1.1.1.1,8.8.8.8 \
  --lease-time 43200

# Get pool stats
platformctl --transport quic dhcp pool stats internal-pool

# Watch lease events
platformctl --transport quic dhcp lease watch
platformctl --transport quic dhcp lease watch --pool internal-pool
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [MCP API Reference](api-reference-mcp.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)
