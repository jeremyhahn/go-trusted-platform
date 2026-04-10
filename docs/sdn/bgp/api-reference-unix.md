# BGP Unix Socket API Reference

Unix socket interface for local IPC with the BGP service.

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
- **Local-only access** - Secure for sensitive BGP operations

## Connection Setup

### Go Client

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    bgp "github.com/jeremyhahn/go-trusted-platform/api/sdn/bgp/v1"
)

func NewBGPUnixClient() (bgp.BGPServiceClient, error) {
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

    return bgp.NewBGPServiceClient(conn), nil
}
```

## Service Methods

### Status Operations

#### GetStatus

```go
client, err := NewBGPUnixClient()
if err != nil {
    return err
}

status, err := client.GetStatus(ctx, &bgp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("ASN: %d, State: %s\n", status.Asn, status.State)
fmt.Printf("Peers: %d/%d established\n",
    status.EstablishedPeers, status.PeerCount)
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
fmt.Printf("Speaker ID: %s\n", info.Id)
fmt.Printf("Router ID: %s\n", info.RouterId)
fmt.Printf("Role: %s\n", info.Role)
fmt.Printf("Listen Port: %d\n", info.ListenPort)
for _, family := range info.Families {
    fmt.Printf("Family: %s/%s\n", family.Afi, family.Safi)
}
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
        Md5Secret:         "bgp_secret_key",
        BfdEnabled:        true,
        GracefulRestart:   true,
    },
    Families: []*bgp.AddressFamily{
        {Afi: "ipv4", Safi: "unicast"},
        {Afi: "ipv6", Safi: "unicast"},
    },
    Policies: &bgp.PeerPolicies{
        ImportPolicy: "import-from-isp",
        ExportPolicy: "export-to-isp",
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
fmt.Printf("Peer: %s (AS%d)\n", peer.Address, peer.RemoteAsn)
fmt.Printf("State: %s\n", peer.State)
fmt.Printf("Uptime: %d seconds\n", peer.UptimeSeconds)
fmt.Printf("Prefixes: %d received, %d sent\n",
    peer.Statistics.PrefixesReceived,
    peer.Statistics.PrefixesSent)
```

#### ListPeers

```go
resp, err := client.ListPeers(ctx, &bgp.ListPeersRequest{
    State: bgp.PEER_STATE_ESTABLISHED,
    Type:  bgp.PEER_TYPE_EBGP,
    Limit: 100,
})
if err != nil {
    return err
}
for _, peer := range resp.Peers {
    fmt.Printf("%s (AS%d): %s, prefixes=%d\n",
        peer.Address, peer.RemoteAsn, peer.State,
        peer.Statistics.PrefixesReceived)
}
```

#### UpdatePeer

```go
peer, err := client.UpdatePeer(ctx, &bgp.UpdatePeerRequest{
    Address:     "198.51.100.1",
    Description: "ISP-Primary-Updated",
    Config: &bgp.PeerConfig{
        HoldTime: 120,
    },
})
```

#### DeletePeer

```go
_, err := client.DeletePeer(ctx, &bgp.DeletePeerRequest{
    Address: "198.51.100.1",
})
```

#### ResetPeer

```go
// Hard reset
_, err := client.ResetPeer(ctx, &bgp.ResetPeerRequest{
    Address: "198.51.100.1",
    Soft:    false,
})

// Soft reset (route refresh)
_, err = client.ResetPeer(ctx, &bgp.ResetPeerRequest{
    Address: "198.51.100.1",
    Soft:    true,
})
```

### Route Operations

#### GetRoute

```go
route, err := client.GetRoute(ctx, &bgp.GetRouteRequest{
    Family: &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    Prefix: "2602:F5BB::/36",
})
if err != nil {
    return err
}
fmt.Printf("Prefix: %s\n", route.Prefix)
for i, path := range route.Paths {
    fmt.Printf("  Path %d: via %s, AS-Path=%v, best=%v\n",
        i+1, path.NextHop, path.AsPath, path.Best)
}
```

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
    fmt.Printf("%s via %s, AS-Path=%v, RPKI=%s\n",
        route.Prefix, route.NextHop, route.AsPath, route.RpkiStatus)
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
    fmt.Printf("Type-%d: MAC=%s IP=%s VNI=%d NextHop=%s\n",
        route.Type, route.Mac, route.Ip, route.Vni, route.NextHop)
}
```

#### AdvertiseMacIP

```go
route, err := client.AdvertiseMacIP(ctx, &bgp.AdvertiseMacIPRequest{
    Mac:         "aa:bb:cc:dd:ee:ff",
    Ip:          "192.168.100.10",
    Vni:         1000100,
    EthernetTag: 0,
})
if err != nil {
    return err
}
fmt.Printf("Advertised: MAC=%s IP=%s\n", route.Mac, route.Ip)
```

#### WithdrawMacIP

```go
_, err := client.WithdrawMacIP(ctx, &bgp.WithdrawMacIPRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
    Vni: 1000100,
})
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
fmt.Printf("Advertised Type-5: %s on VNI %d\n", route.Prefix, route.Vni)
```

#### WithdrawIPPrefix

```go
_, err := client.WithdrawIPPrefix(ctx, &bgp.WithdrawIPPrefixRequest{
    Prefix: "192.168.1.0/24",
    L3Vni:  10000,
})
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
    fmt.Printf("%s: announced=%v, signed=%v, RPKI=%s\n",
        prefix.Prefix, prefix.Announced, prefix.Signed, prefix.RpkiStatus)
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
fmt.Printf("Announced: %s (signed=%v, sigs=%d)\n",
    transit.Prefix, transit.Signed, transit.SignatureCount)
```

#### WithdrawPrefix

```go
_, err := client.WithdrawPrefix(ctx, &bgp.WithdrawPrefixRequest{
    Prefix: "2602:F5BB:0001::/48",
})
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
fmt.Printf("RPKI Enabled: %v\n", status.Enabled)
for _, server := range status.Servers {
    fmt.Printf("  Server %s: %s, records=%d\n",
        server.Address, server.State, server.Records)
}
fmt.Printf("Stats: valid=%d, invalid=%d, not_found=%d\n",
    status.Statistics.ValidRoutes,
    status.Statistics.InvalidRoutes,
    status.Statistics.NotFoundRoutes)
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
fmt.Printf("Prefix: %s, ASN: %d, Status: %s\n",
    validation.Prefix, validation.Asn, validation.Status)
for _, roa := range validation.Roas {
    fmt.Printf("  ROA: %s/%d from AS%d\n",
        roa.Prefix, roa.MaxLength, roa.Asn)
}
```

### Dampening Operations

#### GetDampeningStatus

```go
status, err := client.GetDampeningStatus(ctx, &bgp.GetDampeningStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("Dampening Enabled: %v\n", status.Enabled)
fmt.Printf("Suppressed Routes: %d\n", status.SuppressedRoutes)
fmt.Printf("Config: half-life=%ds, suppress=%d, reuse=%d\n",
    status.Config.HalfLifeSeconds,
    status.Config.SuppressThreshold,
    status.Config.ReuseThreshold)
```

#### ListSuppressedRoutes

```go
resp, err := client.ListSuppressedRoutes(ctx, &bgp.ListSuppressedRoutesRequest{})
if err != nil {
    return err
}
for _, route := range resp.Routes {
    fmt.Printf("%s: penalty=%d, flaps=%d, reuse=%s\n",
        route.Prefix, route.Penalty, route.FlapCount,
        route.ReuseTime.AsTime())
}
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
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }

    switch event.Type {
    case bgp.PEER_EVENT_ADDED:
        fmt.Printf("[+] Peer added: %s (AS%d)\n",
            event.Peer.Address, event.Peer.RemoteAsn)
    case bgp.PEER_EVENT_ESTABLISHED:
        fmt.Printf("[*] Peer established: %s\n", event.Peer.Address)
    case bgp.PEER_EVENT_DOWN:
        fmt.Printf("[!] Peer down: %s, error: %s\n",
            event.Peer.Address, event.Peer.LastError)
    case bgp.PEER_EVENT_REMOVED:
        fmt.Printf("[-] Peer removed: %s\n", event.Peer.Address)
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
        fmt.Printf("[+] Route: %s via %s\n",
            event.Route.Prefix, event.Route.NextHop)
    case bgp.ROUTE_EVENT_WITHDRAWN:
        fmt.Printf("[-] Route: %s\n", event.Route.Prefix)
    case bgp.ROUTE_EVENT_BEST_CHANGED:
        fmt.Printf("[~] Best changed: %s\n", event.Route.Prefix)
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
        fmt.Printf("[+] EVPN: MAC=%s IP=%s\n",
            event.Route.Mac, event.Route.Ip)
    case bgp.EVPN_EVENT_WITHDRAWN:
        fmt.Printf("[-] EVPN: MAC=%s\n", event.Route.Mac)
    case bgp.EVPN_EVENT_MAC_MOVE:
        fmt.Printf("[~] MAC moved: %s -> %s\n",
            event.Route.Mac, event.Route.NextHop)
    }
}
```

## CLI Integration

```bash
# Get BGP status
platformctl bgp status

# Get speaker info
platformctl bgp speaker info

# List peers
platformctl bgp peer list
platformctl bgp peer list --state established
platformctl bgp peer list --type ebgp

# Get peer details
platformctl bgp peer get 198.51.100.1

# Add peer
platformctl bgp peer add \
  --address 198.51.100.1 \
  --remote-asn 64500 \
  --type ebgp \
  --description "ISP-Primary" \
  --bfd

# Reset peer
platformctl bgp peer reset 198.51.100.1
platformctl bgp peer reset 198.51.100.1 --soft

# Delete peer
platformctl bgp peer delete 198.51.100.1

# List routes
platformctl bgp route list --family ipv6
platformctl bgp route list --family ipv6 --best-only
platformctl bgp route get --family ipv6 --prefix "2602:F5BB::/36"

# EVPN operations
platformctl bgp evpn list --type 2 --vni 1000100
platformctl bgp evpn advertise-mac --mac aa:bb:cc:dd:ee:ff --ip 192.168.100.10 --vni 1000100
platformctl bgp evpn withdraw-mac --mac aa:bb:cc:dd:ee:ff --vni 1000100

# Transit operations
platformctl bgp transit list
platformctl bgp transit announce --prefix "2602:F5BB:0001::/48" --require-signing
platformctl bgp transit withdraw --prefix "2602:F5BB:0001::/48"
platformctl bgp transit blackhole --prefix "2602:F5BB:0001:1000::/64" --reason "DDoS"

# RPKI operations
platformctl bgp rpki status
platformctl bgp rpki validate --prefix "2602:F5BB::/36" --asn 65001

# Dampening
platformctl bgp dampening status
platformctl bgp dampening suppressed

# Watch events
platformctl bgp peer watch
platformctl bgp route watch --family ipv6
platformctl bgp evpn watch --vni 1000100
```

## Error Handling

```go
peer, err := client.GetPeer(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.NotFound:
            fmt.Println("Peer not found")
        case codes.FailedPrecondition:
            fmt.Println("Peer not established")
        case codes.PermissionDenied:
            fmt.Println("Permission denied")
        case codes.Unavailable:
            fmt.Println("BGP speaker not running")
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
