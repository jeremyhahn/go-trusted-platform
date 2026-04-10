# DHCP Unix Socket API Reference

Unix socket interface for local IPC with the DHCP service.

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
- **Local-only access** - Secure for DHCP management

## Connection Setup

### Go Client

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    dhcp "github.com/jeremyhahn/go-trusted-platform/api/sdn/dhcp/v1"
)

func NewDHCPUnixClient() (dhcp.DHCPServiceClient, error) {
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

    return dhcp.NewDHCPServiceClient(conn), nil
}
```

## Service Methods

### Status Operations

#### GetStatus

```go
client, err := NewDHCPUnixClient()
if err != nil {
    return err
}

status, err := client.GetStatus(ctx, &dhcp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("DHCP Server Status:\n")
fmt.Printf("  Running: %v\n", status.Running)
fmt.Printf("  IPAM Backend: %s\n", status.IpamBackend)
fmt.Printf("  Uptime: %d seconds\n", status.UptimeSeconds)
fmt.Printf("  Interfaces:\n")
for _, iface := range status.Interfaces {
    fmt.Printf("    %s: %s (pool: %s, network: %s)\n",
        iface.Name, iface.Address, iface.PoolId, iface.Network)
}
```

#### GetStats

```go
stats, err := client.GetStats(ctx, &dhcp.GetStatsRequest{})
if err != nil {
    return err
}
fmt.Printf("DHCP Server Statistics:\n")
fmt.Printf("  Started: %s\n", stats.StartedAt.AsTime())
fmt.Printf("  Packets received: %d\n", stats.PacketsReceived)
fmt.Printf("  Packets sent: %d\n", stats.PacketsSent)
fmt.Printf("  Message counts:\n")
fmt.Printf("    DISCOVER: %d\n", stats.DiscoverCount)
fmt.Printf("    OFFER: %d\n", stats.OfferCount)
fmt.Printf("    REQUEST: %d\n", stats.RequestCount)
fmt.Printf("    ACK: %d\n", stats.AckCount)
fmt.Printf("    NAK: %d\n", stats.NakCount)
fmt.Printf("    RELEASE: %d\n", stats.ReleaseCount)
fmt.Printf("    DECLINE: %d\n", stats.DeclineCount)
fmt.Printf("    INFORM: %d\n", stats.InformCount)
fmt.Printf("  Errors: %d\n", stats.ErrorCount)
fmt.Printf("  Active leases: %d\n", stats.ActiveLeases)
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
fmt.Printf("Lease for MAC %s:\n", lease.Mac)
fmt.Printf("  IP: %s\n", lease.Ip)
fmt.Printf("  Hostname: %s\n", lease.Hostname)
fmt.Printf("  Pool: %s\n", lease.PoolId)
fmt.Printf("  Interface: %s\n", lease.Interface)
fmt.Printf("  Client ID: %x\n", lease.ClientId)
fmt.Printf("  Vendor Class: %s\n", lease.VendorClass)
fmt.Printf("  State: %s\n", lease.State)
fmt.Printf("  Leased at: %s\n", lease.LeasedAt.AsTime())
fmt.Printf("  Renewed at: %s\n", lease.RenewedAt.AsTime())
fmt.Printf("  Expires at: %s\n", lease.ExpiresAt.AsTime())
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
fmt.Printf("  State: %s\n", lease.State)
```

#### ListLeases

```go
resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
    PoolId:    "internal-pool",
    Interface: "eth0",
    State:     dhcp.LEASE_STATE_ACTIVE,
    Limit:     100,
})
if err != nil {
    return err
}
fmt.Printf("Found %d leases (showing %d):\n", resp.Total, len(resp.Leases))
for _, lease := range resp.Leases {
    remaining := time.Duration(lease.TimeRemainingSeconds) * time.Second
    fmt.Printf("  %s -> %s (%s) - %s, expires in %s\n",
        lease.Mac, lease.Ip, lease.Hostname, lease.State, remaining)
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
fmt.Println("Lease released successfully")
```

#### ExpireLeases

```go
resp, err := client.ExpireLeases(ctx, &dhcp.ExpireLeasesRequest{})
if err != nil {
    return err
}
fmt.Printf("Expired %d leases\n", resp.ExpiredCount)
fmt.Printf("Active leases remaining: %d\n", resp.ActiveLeases)
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
    fmt.Printf("  Active leases: %d\n", iface.ActiveLeases)
    fmt.Printf("  Options:\n")
    fmt.Printf("    Subnet mask: %s\n", iface.Options.SubnetMask)
    fmt.Printf("    Router: %s\n", iface.Options.Router)
    fmt.Printf("    DNS: %v\n", iface.Options.Dns)
    fmt.Printf("    Domain: %s\n", iface.Options.DomainName)
    fmt.Printf("    Lease time: %d seconds\n", iface.Options.LeaseTimeSeconds)
    fmt.Printf("    Renewal time: %d seconds\n", iface.Options.RenewalTimeSeconds)
    fmt.Printf("    Rebind time: %d seconds\n", iface.Options.RebindTimeSeconds)
    if len(iface.Options.NtpServers) > 0 {
        fmt.Printf("    NTP: %v\n", iface.Options.NtpServers)
    }
    if iface.Options.Mtu > 0 {
        fmt.Printf("    MTU: %d\n", iface.Options.Mtu)
    }
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
fmt.Printf("  Active leases: %d\n", iface.ActiveLeases)
```

#### UpdateInterfaceOptions

```go
iface, err := client.UpdateInterfaceOptions(ctx, &dhcp.UpdateInterfaceOptionsRequest{
    Name: "eth0",
    Options: &dhcp.DHCPOptionsUpdate{
        Dns:               []string{"1.1.1.1", "8.8.8.8"},
        DomainName:        "newdomain.local",
        LeaseTimeSeconds:  43200,
        RenewalTimeSeconds: 21600,
        RebindTimeSeconds:  37800,
        NtpServers:        []string{"pool.ntp.org"},
        Mtu:               1500,
    },
})
if err != nil {
    return err
}
fmt.Printf("Updated DHCP options for interface %s\n", iface.Name)
fmt.Printf("  New DNS: %v\n", iface.Options.Dns)
fmt.Printf("  New domain: %s\n", iface.Options.DomainName)
fmt.Printf("  New lease time: %d seconds\n", iface.Options.LeaseTimeSeconds)
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
fmt.Printf("Pool %s statistics:\n", stats.PoolId)
fmt.Printf("  Total addresses: %d\n", stats.TotalAddresses)
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

```go
stream, err := client.WatchLeases(ctx, &dhcp.WatchLeasesRequest{
    PoolId:         "internal-pool",
    Interface:      "eth0",
    IncludeInitial: true,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }

    timestamp := event.Timestamp.AsTime().Format("15:04:05")

    switch event.Type {
    case dhcp.LEASE_EVENT_CREATED:
        fmt.Printf("[%s] NEW: %s -> %s (%s)\n",
            timestamp, event.Lease.Mac, event.Lease.Ip, event.Lease.Hostname)
    case dhcp.LEASE_EVENT_RENEWED:
        fmt.Printf("[%s] RENEW: %s -> %s\n",
            timestamp, event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_RELEASED:
        fmt.Printf("[%s] RELEASE: %s -> %s\n",
            timestamp, event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_EXPIRED:
        fmt.Printf("[%s] EXPIRE: %s -> %s\n",
            timestamp, event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_DECLINED:
        fmt.Printf("[%s] DECLINE: %s -> %s\n",
            timestamp, event.Lease.Mac, event.Lease.Ip)
    }
}
```

## CLI Integration

```bash
# Get server status
platformctl dhcp status

# Get server statistics
platformctl dhcp stats

# List all leases
platformctl dhcp lease list

# List leases with filters
platformctl dhcp lease list --pool internal-pool
platformctl dhcp lease list --interface eth0
platformctl dhcp lease list --state active
platformctl dhcp lease list --pool internal-pool --state active --limit 50

# Get lease by MAC
platformctl dhcp lease get --mac aa:bb:cc:dd:ee:ff

# Get lease by IP
platformctl dhcp lease get --ip 192.168.1.100

# Release a lease
platformctl dhcp lease release --mac aa:bb:cc:dd:ee:ff

# Expire old leases
platformctl dhcp lease expire

# List interfaces
platformctl dhcp interface list

# Get interface details
platformctl dhcp interface get eth0

# Update interface options
platformctl dhcp interface update eth0 \
  --dns 1.1.1.1,8.8.8.8 \
  --domain newdomain.local \
  --lease-time 43200

# Get pool statistics
platformctl dhcp pool stats internal-pool

# Watch lease events
platformctl dhcp lease watch
platformctl dhcp lease watch --pool internal-pool
platformctl dhcp lease watch --interface eth0

# Watch in verbose mode
platformctl dhcp lease watch -v
```

## Error Handling

```go
lease, err := client.GetLease(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.NotFound:
            fmt.Println("Lease not found for specified MAC")
        case codes.InvalidArgument:
            fmt.Println("Invalid MAC address format")
        case codes.Unavailable:
            fmt.Println("DHCP server is not running")
        case codes.FailedPrecondition:
            fmt.Println("Lease has expired")
        case codes.PermissionDenied:
            fmt.Println("Permission denied")
        default:
            fmt.Printf("Error: %s\n", st.Message())
        }
    }
    return err
}
```

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/status"
    "google.golang.org/grpc/codes"

    dhcp "github.com/jeremyhahn/go-trusted-platform/api/sdn/dhcp/v1"
)

func main() {
    // Connect via Unix socket
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
        log.Fatal(err)
    }
    defer conn.Close()

    client := dhcp.NewDHCPServiceClient(conn)
    ctx := context.Background()

    // Get server status
    status, err := client.GetStatus(ctx, &dhcp.GetStatusRequest{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("DHCP Server Running: %v\n", status.Running)
    fmt.Printf("Uptime: %d seconds\n\n", status.UptimeSeconds)

    // Get statistics
    stats, err := client.GetStats(ctx, &dhcp.GetStatsRequest{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Statistics:\n")
    fmt.Printf("  Active leases: %d\n", stats.ActiveLeases)
    fmt.Printf("  ACK/NAK: %d/%d\n\n", stats.AckCount, stats.NakCount)

    // List active leases
    resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
        State: dhcp.LEASE_STATE_ACTIVE,
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Active leases (%d total):\n", resp.Total)
    for _, lease := range resp.Leases {
        remaining := time.Duration(lease.TimeRemainingSeconds) * time.Second
        fmt.Printf("  %s -> %s (%s) expires in %s\n",
            lease.Mac, lease.Ip, lease.Hostname, remaining)
    }

    // Get specific lease
    lease, err := client.GetLease(ctx, &dhcp.GetLeaseRequest{
        Mac: "aa:bb:cc:dd:ee:ff",
    })
    if err != nil {
        if status.Code(err) == codes.NotFound {
            fmt.Println("\nLease not found for aa:bb:cc:dd:ee:ff")
        } else {
            log.Fatal(err)
        }
    } else {
        fmt.Printf("\nLease details:\n")
        fmt.Printf("  %s -> %s\n", lease.Mac, lease.Ip)
    }

    // Get pool statistics
    poolStats, err := client.GetPoolStats(ctx, &dhcp.GetPoolStatsRequest{
        PoolId: "internal-pool",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("\nPool utilization: %.1f%%\n", poolStats.UtilizationPercent)
}
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [MCP API Reference](api-reference-mcp.md)
- [Architecture](architecture.md)
