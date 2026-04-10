# VXLAN Overlay QUIC API Reference

QUIC transport for the VXLAN overlay service, providing low-latency, multiplexed connections.

| Property | Value |
|----------|-------|
| Service | `overlay.OverlayService` |
| Port | 9444 |
| Transport | QUIC (UDP) with TLS 1.3 |

## Overview

QUIC transport provides several advantages for overlay operations:

- **0-RTT connection establishment** - Reduced latency for repeated connections
- **Stream multiplexing** - Multiple independent streams over single connection
- **Built-in encryption** - TLS 1.3 integrated into transport
- **Connection migration** - Seamless handling of network changes
- **Head-of-line blocking elimination** - Independent stream delivery

## Connection Setup

### TLS Configuration

QUIC requires TLS 1.3 with mutual authentication.

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    overlay "github.com/jeremyhahn/go-trusted-platform/api/sdn/overlay/v1"
)

func NewOverlayQUICClient(addr string, tlsConfig *tls.Config) (overlay.OverlayServiceClient, error) {
    // Ensure TLS 1.3 minimum
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"overlay-quic-v1"}

    // QUIC configuration
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

    return overlay.NewOverlayServiceClientQUIC(conn), nil
}
```

### Connection with 0-RTT

Enable 0-RTT for reduced latency on subsequent connections.

```go
func NewOverlayQUICClient0RTT(addr string, tlsConfig *tls.Config, sessionCache tls.ClientSessionCache) (overlay.OverlayServiceClient, error) {
    tlsConfig.ClientSessionCache = sessionCache
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"overlay-quic-v1"}

    quicConfig := &quic.Config{
        Enable0RTT: true,
    }

    // Use early data for 0-RTT
    conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return overlay.NewOverlayServiceClientQUIC(conn), nil
}
```

## Service Methods

All gRPC service methods are available over QUIC transport with identical semantics.

### VTEP Operations

#### RegisterVTEP

```go
client, err := NewOverlayQUICClient("platform.example.com:9444", tlsConfig)
if err != nil {
    return err
}

vtep, err := client.RegisterVTEP(ctx, &overlay.RegisterVTEPRequest{
    Ip:            "10.0.0.1",
    UnderlayIface: "eth0",
    UnderlayMtu:   9000,
    VxlanPort:     4789,
})
if err != nil {
    return err
}
fmt.Printf("VTEP registered: %s\n", vtep.Ip)
```

#### ListVTEPs

```go
resp, err := client.ListVTEPs(ctx, &overlay.ListVTEPsRequest{
    HealthyOnly: true,
    Limit:       100,
})
if err != nil {
    return err
}
for _, vtep := range resp.Vteps {
    fmt.Printf("VTEP: %s (node: %s)\n", vtep.Ip, vtep.NodeId)
}
```

#### HealthCheckVTEP

```go
health, err := client.HealthCheckVTEP(ctx, &overlay.HealthCheckVTEPRequest{
    Ip: "10.0.0.1",
})
if err != nil {
    return err
}
fmt.Printf("VTEP %s healthy: %v (latency: %dms)\n",
    health.Ip, health.Healthy, health.LatencyMs)
```

### VNI Operations

#### CreateVNI

```go
vni, err := client.CreateVNI(ctx, &overlay.CreateVNIRequest{
    Id:             1000100,
    VlanId:         100,
    MulticastGroup: "239.1.1.100",
})
if err != nil {
    return err
}
fmt.Printf("VNI created: %d\n", vni.Id)
```

#### JoinVNI

```go
_, err := client.JoinVNI(ctx, &overlay.JoinVNIRequest{
    VniId: 1000100,
})
if err != nil {
    return err
}
```

#### ListVNIMembers

```go
resp, err := client.ListVNIMembers(ctx, &overlay.ListVNIMembersRequest{
    VniId: 1000100,
})
if err != nil {
    return err
}
for _, member := range resp.Members {
    fmt.Printf("Member: %s (node: %s)\n", member.VtepIp, member.NodeId)
}
```

### Tunnel Operations

#### CreateTunnel

```go
tunnel, err := client.CreateTunnel(ctx, &overlay.CreateTunnelRequest{
    RemoteVtep: "10.0.0.2",
    Vnis:       []uint32{1000100, 1000200},
})
if err != nil {
    return err
}
fmt.Printf("Tunnel created: %s (state: %s)\n", tunnel.Id, tunnel.State)
```

#### GetTunnelStats

```go
stats, err := client.GetTunnelStats(ctx, &overlay.GetTunnelStatsRequest{
    RemoteVtep: "10.0.0.2",
})
if err != nil {
    return err
}
fmt.Printf("TX: %d packets, RX: %d packets\n",
    stats.TxPackets, stats.RxPackets)
```

### MAC Operations

#### ListMACs

```go
resp, err := client.ListMACs(ctx, &overlay.ListMACsRequest{
    Vni:   1000100,
    Type:  overlay.MAC_TYPE_REMOTE,
    Limit: 100,
})
if err != nil {
    return err
}
for _, mac := range resp.Macs {
    fmt.Printf("MAC %s -> VTEP %s\n", mac.Mac, mac.VtepIp)
}
```

#### LearnMAC

```go
entry, err := client.LearnMAC(ctx, &overlay.LearnMACRequest{
    Vni:    1000100,
    Mac:    "aa:bb:cc:dd:ee:ff",
    VtepIp: "10.0.0.2",
    Type:   overlay.MAC_TYPE_STATIC,
})
if err != nil {
    return err
}
fmt.Printf("MAC learned: %s\n", entry.Mac)
```

## Streaming Operations

QUIC's multiplexing makes streaming particularly efficient.

### WatchVTEPs

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
        log.Printf("Tunnel up: %s -> %s",
            event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
    case overlay.TUNNEL_EVENT_FAILED:
        log.Printf("Tunnel down: %s -> %s",
            event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
    }
}
```

### WatchMACs

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
        log.Printf("MAC learned: %s on VNI %d",
            event.Entry.Mac, event.Entry.Vni)
    case overlay.MAC_EVENT_MOVED:
        log.Printf("MAC moved: %s to VTEP %s",
            event.Entry.Mac, event.Entry.VtepIp)
    }
}
```

## Concurrent Streams

QUIC allows multiple independent streams over a single connection.

```go
// Create multiple streams concurrently
var wg sync.WaitGroup

// Stream 1: Watch VTEPs
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchVTEPs(ctx, &overlay.WatchVTEPsRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleVTEPEvent(event)
    }
}()

// Stream 2: Watch tunnels
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchTunnels(ctx, &overlay.WatchTunnelsRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleTunnelEvent(event)
    }
}()

// Stream 3: Watch MACs for VNI 1000100
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchMACs(ctx, &overlay.WatchMACsRequest{Vni: 1000100})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleMACEvent(event)
    }
}()

wg.Wait()
```

## Error Handling

QUIC connections may experience unique error conditions.

```go
import (
    "github.com/quic-go/quic-go"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

vtep, err := client.GetVTEP(ctx, req)
if err != nil {
    // Check for QUIC-specific errors
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        log.Printf("QUIC application error: code=%d", qErr.ErrorCode)
    }

    var transportErr *quic.TransportError
    if errors.As(err, &transportErr) {
        log.Printf("QUIC transport error: %s", transportErr.ErrorCode)
    }

    // Check for gRPC status
    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.NotFound:
            log.Printf("VTEP not found")
        case codes.Unavailable:
            log.Printf("Service unavailable, will retry")
        }
    }

    return err
}
```

## Connection Management

### Connection Pooling

```go
type QUICConnectionPool struct {
    mu      sync.RWMutex
    conns   map[string]quic.Connection
    config  *quic.Config
    tlsConf *tls.Config
}

func (p *QUICConnectionPool) GetConnection(addr string) (quic.Connection, error) {
    p.mu.RLock()
    if conn, ok := p.conns[addr]; ok {
        p.mu.RUnlock()
        return conn, nil
    }
    p.mu.RUnlock()

    p.mu.Lock()
    defer p.mu.Unlock()

    conn, err := quic.DialAddr(context.Background(), addr, p.tlsConf, p.config)
    if err != nil {
        return nil, err
    }

    p.conns[addr] = conn
    return conn, nil
}
```

### Connection Migration

QUIC supports connection migration when the client's network changes.

```go
quicConfig := &quic.Config{
    AllowConnectionMigration: true,
    MaxIdleTimeout:           30 * time.Second,
}
```

## Performance Considerations

### Latency Optimization

- Enable 0-RTT for repeated connections
- Use connection pooling
- Leverage stream multiplexing for concurrent operations

### Throughput Optimization

```go
quicConfig := &quic.Config{
    MaxIncomingStreams:      10000,
    MaxIncomingUniStreams:   10000,
    InitialStreamReceiveWindow:    512 * 1024,
    MaxStreamReceiveWindow:        6 * 1024 * 1024,
    InitialConnectionReceiveWindow: 512 * 1024,
    MaxConnectionReceiveWindow:    15 * 1024 * 1024,
}
```

## CLI Usage

The `platformctl` CLI supports QUIC transport.

```bash
# Use QUIC transport
platformctl --transport quic overlay vtep list

# Register VTEP via QUIC
platformctl --transport quic overlay vtep register \
  --ip 10.0.0.1 \
  --underlay-iface eth0 \
  --underlay-mtu 9000

# Create VNI
platformctl --transport quic overlay vni create \
  --id 1000100 \
  --vlan-id 100

# Watch tunnel events
platformctl --transport quic overlay tunnel watch
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [MCP API Reference](api-reference-mcp.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)
