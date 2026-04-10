# BGP QUIC API Reference

QUIC transport for the BGP service, providing low-latency, multiplexed connections.

| Property | Value |
|----------|-------|
| Service | `bgp.BGPService` |
| Port | 9444 |
| Transport | QUIC (UDP) with TLS 1.3 |

## Overview

QUIC transport provides several advantages for BGP operations:

- **0-RTT connection establishment** - Reduced latency for route queries
- **Stream multiplexing** - Independent streams for peers, routes, and EVPN
- **Built-in encryption** - TLS 1.3 integrated into transport
- **Connection migration** - Handle network path changes gracefully
- **Head-of-line blocking elimination** - Stream independence

## Connection Setup

### TLS Configuration

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    bgp "github.com/jeremyhahn/go-trusted-platform/api/sdn/bgp/v1"
)

func NewBGPQUICClient(addr string, tlsConfig *tls.Config) (bgp.BGPServiceClient, error) {
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"bgp-quic-v1"}

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

    return bgp.NewBGPServiceClientQUIC(conn), nil
}
```

### Connection with 0-RTT

```go
func NewBGPQUICClient0RTT(addr string, tlsConfig *tls.Config, sessionCache tls.ClientSessionCache) (bgp.BGPServiceClient, error) {
    tlsConfig.ClientSessionCache = sessionCache
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"bgp-quic-v1"}

    quicConfig := &quic.Config{
        Enable0RTT: true,
    }

    conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return bgp.NewBGPServiceClientQUIC(conn), nil
}
```

## Service Methods

### Status Operations

#### GetStatus

```go
client, err := NewBGPQUICClient("platform.example.com:9444", tlsConfig)
if err != nil {
    return err
}

status, err := client.GetStatus(ctx, &bgp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("ASN: %d, Peers: %d/%d established\n",
    status.Asn, status.EstablishedPeers, status.PeerCount)
fmt.Printf("Routes: IPv4=%d, IPv6=%d, EVPN=%d\n",
    status.RouteCount.Ipv4Unicast,
    status.RouteCount.Ipv6Unicast,
    status.RouteCount.L2VpnEvpn)
```

#### GetSpeakerInfo

```go
info, err := client.GetSpeakerInfo(ctx, &bgp.GetSpeakerInfoRequest{})
if err != nil {
    return err
}
fmt.Printf("Speaker: %s, Role: %s, Router ID: %s\n",
    info.Id, info.Role, info.RouterId)
```

### Peer Operations

#### AddPeer

```go
peer, err := client.AddPeer(ctx, &bgp.AddPeerRequest{
    Address:     "198.51.100.1",
    RemoteAsn:   64500,
    Type:        bgp.PEER_TYPE_EBGP,
    Description: "ISP-Primary",
    Config: &bgp.PeerConfig{
        HoldTime:          90,
        KeepaliveInterval: 30,
        Md5Secret:         "bgp_secret",
        BfdEnabled:        true,
        GracefulRestart:   true,
    },
    Families: []*bgp.AddressFamily{
        {Afi: "ipv4", Safi: "unicast"},
        {Afi: "ipv6", Safi: "unicast"},
    },
})
if err != nil {
    return err
}
fmt.Printf("Added peer: %s (AS%d)\n", peer.Address, peer.RemoteAsn)
```

#### GetPeer

```go
peer, err := client.GetPeer(ctx, &bgp.GetPeerRequest{
    Address: "198.51.100.1",
})
if err != nil {
    return err
}
fmt.Printf("Peer %s: state=%s, uptime=%ds\n",
    peer.Address, peer.State, peer.UptimeSeconds)
```

#### ListPeers

```go
resp, err := client.ListPeers(ctx, &bgp.ListPeersRequest{
    State: bgp.PEER_STATE_ESTABLISHED,
    Limit: 100,
})
if err != nil {
    return err
}
for _, peer := range resp.Peers {
    fmt.Printf("Peer %s (AS%d): %s, prefixes: %d/%d\n",
        peer.Address, peer.RemoteAsn, peer.State,
        peer.Statistics.PrefixesReceived,
        peer.Statistics.PrefixesSent)
}
```

#### ResetPeer

```go
_, err := client.ResetPeer(ctx, &bgp.ResetPeerRequest{
    Address: "198.51.100.1",
    Soft:    true, // Route refresh only
})
```

### Route Operations

#### ListRoutes

```go
resp, err := client.ListRoutes(ctx, &bgp.ListRoutesRequest{
    Family:   &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    BestOnly: true,
    Limit:    100,
})
if err != nil {
    return err
}
for _, route := range resp.Routes {
    fmt.Printf("%s via %s, AS-Path: %v\n",
        route.Prefix, route.NextHop, route.AsPath)
}
```

#### GetRoute

```go
route, err := client.GetRoute(ctx, &bgp.GetRouteRequest{
    Family: &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    Prefix: "2602:F5BB::/36",
})
if err != nil {
    return err
}
for _, path := range route.Paths {
    fmt.Printf("Path: via %s, best=%v\n", path.NextHop, path.Best)
}
```

### EVPN Operations

#### ListEVPNRoutes

```go
resp, err := client.ListEVPNRoutes(ctx, &bgp.ListEVPNRoutesRequest{
    Type:  bgp.EVPN_TYPE_2_MAC_IP,
    Vni:   1000100,
    Limit: 100,
})
if err != nil {
    return err
}
for _, route := range resp.Routes {
    fmt.Printf("Type-%d: MAC=%s IP=%s VNI=%d\n",
        route.Type, route.Mac, route.Ip, route.Vni)
}
```

#### AdvertiseMacIP

```go
route, err := client.AdvertiseMacIP(ctx, &bgp.AdvertiseMacIPRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
    Ip:  "192.168.100.10",
    Vni: 1000100,
})
if err != nil {
    return err
}
fmt.Printf("Advertised Type-2: %s/%s on VNI %d\n",
    route.Mac, route.Ip, route.Vni)
```

#### AdvertiseIPPrefix

```go
route, err := client.AdvertiseIPPrefix(ctx, &bgp.AdvertiseIPPrefixRequest{
    Prefix:    "192.168.1.0/24",
    L3Vni:     10000,
    GatewayIp: "10.0.0.1",
})
if err != nil {
    return err
}
fmt.Printf("Advertised Type-5: %s on L3 VNI %d\n",
    route.Prefix, route.Vni)
```

### Transit Operations

#### ListTransitPrefixes

```go
resp, err := client.ListTransitPrefixes(ctx, &bgp.ListTransitPrefixesRequest{
    AnnouncedOnly: true,
})
if err != nil {
    return err
}
for _, prefix := range resp.Prefixes {
    fmt.Printf("%s: announced=%v, RPKI=%s\n",
        prefix.Prefix, prefix.Announced, prefix.RpkiStatus)
}
```

#### AnnouncePrefix

```go
transit, err := client.AnnouncePrefix(ctx, &bgp.AnnouncePrefixRequest{
    Prefix:         "2602:F5BB:0001::/48",
    NextHop:        "2602:F5BB:0001::1",
    Communities:    []string{"65001:300"},
    RequireSigning: true,
})
if err != nil {
    return err
}
fmt.Printf("Announced: %s (signed=%v)\n", transit.Prefix, transit.Signed)
```

#### BlackholePrefix

```go
transit, err := client.BlackholePrefix(ctx, &bgp.BlackholePrefixRequest{
    Prefix: "2602:F5BB:0001:1000::/64",
    Reason: "DDoS mitigation",
})
if err != nil {
    return err
}
fmt.Printf("Blackholed: %s\n", transit.Prefix)
```

### RPKI Operations

#### GetRPKIStatus

```go
status, err := client.GetRPKIStatus(ctx, &bgp.GetRPKIStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("RPKI enabled: %v\n", status.Enabled)
for _, server := range status.Servers {
    fmt.Printf("Server %s: %s, records=%d\n",
        server.Address, server.State, server.Records)
}
```

#### ValidatePrefix

```go
validation, err := client.ValidatePrefix(ctx, &bgp.ValidatePrefixRequest{
    Prefix: "2602:F5BB::/36",
    Asn:    65001,
})
if err != nil {
    return err
}
fmt.Printf("RPKI validation: %s\n", validation.Status)
```

## Streaming Operations

### WatchPeers

```go
stream, err := client.WatchPeers(ctx, &bgp.WatchPeersRequest{
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
    case bgp.PEER_EVENT_ESTABLISHED:
        log.Printf("Peer up: %s (AS%d)",
            event.Peer.Address, event.Peer.RemoteAsn)
    case bgp.PEER_EVENT_DOWN:
        log.Printf("Peer down: %s, error: %s",
            event.Peer.Address, event.Peer.LastError)
    }
}
```

### WatchRoutes

```go
stream, err := client.WatchRoutes(ctx, &bgp.WatchRoutesRequest{
    Family:         &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
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
    case bgp.ROUTE_EVENT_ANNOUNCED:
        log.Printf("Route announced: %s via %s",
            event.Route.Prefix, event.Route.NextHop)
    case bgp.ROUTE_EVENT_WITHDRAWN:
        log.Printf("Route withdrawn: %s", event.Route.Prefix)
    case bgp.ROUTE_EVENT_BEST_CHANGED:
        log.Printf("Best path changed: %s", event.Route.Prefix)
    }
}
```

### WatchEVPNRoutes

```go
stream, err := client.WatchEVPNRoutes(ctx, &bgp.WatchEVPNRoutesRequest{
    Type:           bgp.EVPN_TYPE_2_MAC_IP,
    Vni:            1000100,
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
    case bgp.EVPN_EVENT_ANNOUNCED:
        log.Printf("EVPN Type-2: MAC %s IP %s on VNI %d",
            event.Route.Mac, event.Route.Ip, event.Route.Vni)
    case bgp.EVPN_EVENT_MAC_MOVE:
        log.Printf("MAC moved: %s now at %s",
            event.Route.Mac, event.Route.NextHop)
    }
}
```

## Concurrent Streams

```go
var wg sync.WaitGroup

// Stream 1: Watch peer events
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchPeers(ctx, &bgp.WatchPeersRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handlePeerEvent(event)
    }
}()

// Stream 2: Watch IPv6 routes
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchRoutes(ctx, &bgp.WatchRoutesRequest{
        Family: &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    })
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleRouteEvent(event)
    }
}()

// Stream 3: Watch EVPN routes
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchEVPNRoutes(ctx, &bgp.WatchEVPNRoutesRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleEVPNEvent(event)
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

peer, err := client.GetPeer(ctx, req)
if err != nil {
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        log.Printf("QUIC error: code=%d", qErr.ErrorCode)
    }

    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.NotFound:
            log.Printf("Peer not found")
        case codes.FailedPrecondition:
            log.Printf("Peer not established")
        }
    }

    return err
}
```

## CLI Usage

```bash
# Use QUIC transport
platformctl --transport quic bgp status

# List peers via QUIC
platformctl --transport quic bgp peer list

# Add peer
platformctl --transport quic bgp peer add \
  --address 198.51.100.1 \
  --remote-asn 64500 \
  --type ebgp

# List routes
platformctl --transport quic bgp route list --family ipv6

# Watch peer events
platformctl --transport quic bgp peer watch

# Announce transit prefix
platformctl --transport quic bgp transit announce \
  --prefix "2602:F5BB:0001::/48" \
  --require-signing

# Validate RPKI
platformctl --transport quic bgp rpki validate \
  --prefix "2602:F5BB::/36" \
  --asn 65001
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [MCP API Reference](api-reference-mcp.md)
- [Unix Socket API Reference](api-reference-unix.md)
- [Architecture](architecture.md)
