# VXLAN Overlay Unix Socket API Reference

Unix socket interface for local IPC with the VXLAN overlay service.

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
- **Local-only access** - Enhanced security for sensitive operations

## Connection Setup

### Go Client

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    overlay "github.com/jeremyhahn/go-trusted-platform/api/sdn/overlay/v1"
)

func NewOverlayUnixClient() (overlay.OverlayServiceClient, error) {
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

    return overlay.NewOverlayServiceClient(conn), nil
}
```

### With Connection Options

```go
func NewOverlayUnixClientWithOptions() (overlay.OverlayServiceClient, error) {
    socketPath := "/run/platformd.sock"

    conn, err := grpc.DialContext(
        context.Background(),
        "unix://"+socketPath,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithBlock(),
        grpc.WithDefaultCallOptions(
            grpc.MaxCallRecvMsgSize(16*1024*1024),
            grpc.MaxCallSendMsgSize(16*1024*1024),
        ),
        grpc.WithKeepaliveParams(keepalive.ClientParameters{
            Time:                10 * time.Second,
            Timeout:             3 * time.Second,
            PermitWithoutStream: true,
        }),
    )
    if err != nil {
        return nil, err
    }

    return overlay.NewOverlayServiceClient(conn), nil
}
```

## Service Methods

All gRPC service methods are available over Unix socket.

### VTEP Operations

#### RegisterVTEP

```go
client, err := NewOverlayUnixClient()
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
fmt.Printf("Registered VTEP: %s (node: %s)\n", vtep.Ip, vtep.NodeId)
```

#### GetVTEP

```go
vtep, err := client.GetVTEP(ctx, &overlay.GetVTEPRequest{
    Ip: "10.0.0.1",
})
if err != nil {
    return err
}
fmt.Printf("VTEP: %s, Healthy: %v, VNIs: %v\n",
    vtep.Ip, vtep.Healthy, vtep.ActiveVnis)
```

#### ListVTEPs

```go
resp, err := client.ListVTEPs(ctx, &overlay.ListVTEPsRequest{
    HealthyOnly: false,
    Limit:       100,
})
if err != nil {
    return err
}
for _, vtep := range resp.Vteps {
    fmt.Printf("VTEP %s: healthy=%v\n", vtep.Ip, vtep.Healthy)
}
```

#### DeregisterVTEP

```go
_, err := client.DeregisterVTEP(ctx, &overlay.DeregisterVTEPRequest{
    Ip: "10.0.0.1",
})
if err != nil {
    return err
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
fmt.Printf("Health: %v, Latency: %dms, Tunnels: %d\n",
    health.Healthy, health.LatencyMs, health.TunnelCount)
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
fmt.Printf("Created VNI: %d\n", vni.Id)
```

#### GetVNI

```go
vni, err := client.GetVNI(ctx, &overlay.GetVNIRequest{
    Id: 1000100,
})
if err != nil {
    return err
}
fmt.Printf("VNI %d: VLAN=%d, Members=%v\n",
    vni.Id, vni.VlanId, vni.MemberVteps)
```

#### ListVNIs

```go
resp, err := client.ListVNIs(ctx, &overlay.ListVNIsRequest{
    Limit: 100,
})
if err != nil {
    return err
}
for _, vni := range resp.Vnis {
    fmt.Printf("VNI %d: %d members, %d MACs\n",
        vni.Id, len(vni.MemberVteps), vni.MacCount)
}
```

#### DeleteVNI

```go
_, err := client.DeleteVNI(ctx, &overlay.DeleteVNIRequest{
    Id: 1000100,
})
```

#### JoinVNI

```go
_, err := client.JoinVNI(ctx, &overlay.JoinVNIRequest{
    VniId: 1000100,
})
```

#### LeaveVNI

```go
_, err := client.LeaveVNI(ctx, &overlay.LeaveVNIRequest{
    VniId: 1000100,
})
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
    fmt.Printf("Member: %s (node: %s, joined: %s)\n",
        member.VtepIp, member.NodeId, member.JoinedAt.AsTime())
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
fmt.Printf("Tunnel: %s, State: %s\n", tunnel.Id, tunnel.State)
```

#### GetTunnel

```go
tunnel, err := client.GetTunnel(ctx, &overlay.GetTunnelRequest{
    RemoteVtep: "10.0.0.2",
})
if err != nil {
    return err
}
fmt.Printf("Tunnel to %s: state=%s, RTT=%s\n",
    tunnel.RemoteVtep, tunnel.State, tunnel.Rtt)
```

#### ListTunnels

```go
resp, err := client.ListTunnels(ctx, &overlay.ListTunnelsRequest{
    State: overlay.TUNNEL_STATE_ACTIVE,
    Limit: 100,
})
if err != nil {
    return err
}
for _, tunnel := range resp.Tunnels {
    fmt.Printf("Tunnel %s -> %s: %s\n",
        tunnel.LocalVtep, tunnel.RemoteVtep, tunnel.State)
}
```

#### DeleteTunnel

```go
_, err := client.DeleteTunnel(ctx, &overlay.DeleteTunnelRequest{
    RemoteVtep: "10.0.0.2",
})
```

#### GetTunnelStats

```go
stats, err := client.GetTunnelStats(ctx, &overlay.GetTunnelStatsRequest{
    RemoteVtep: "10.0.0.2",
})
if err != nil {
    return err
}
fmt.Printf("TX: %d pkts / %d bytes\n", stats.TxPackets, stats.TxBytes)
fmt.Printf("RX: %d pkts / %d bytes\n", stats.RxPackets, stats.RxBytes)
```

### MAC Operations

#### GetMAC

```go
entry, err := client.GetMAC(ctx, &overlay.GetMACRequest{
    Vni: 1000100,
    Mac: "aa:bb:cc:dd:ee:ff",
})
if err != nil {
    return err
}
fmt.Printf("MAC %s -> VTEP %s (%s)\n", entry.Mac, entry.VtepIp, entry.Type)
```

#### ListMACs

```go
resp, err := client.ListMACs(ctx, &overlay.ListMACsRequest{
    Vni:   1000100,
    Type:  overlay.MAC_TYPE_REMOTE,
    Limit: 1000,
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
fmt.Printf("Learned MAC: %s\n", entry.Mac)
```

#### DeleteMAC

```go
_, err := client.DeleteMAC(ctx, &overlay.DeleteMACRequest{
    Vni: 1000100,
    Mac: "aa:bb:cc:dd:ee:ff",
})
```

#### FlushMACs

```go
resp, err := client.FlushMACs(ctx, &overlay.FlushMACsRequest{
    Vni:  1000100,
    Type: overlay.MAC_TYPE_REMOTE,
})
if err != nil {
    return err
}
fmt.Printf("Flushed %d MACs\n", resp.Count)
```

## Streaming Operations

Unix sockets support streaming with low latency.

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
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }

    switch event.Type {
    case overlay.VTEP_EVENT_ADDED:
        fmt.Printf("[+] VTEP added: %s\n", event.Vtep.Ip)
    case overlay.VTEP_EVENT_REMOVED:
        fmt.Printf("[-] VTEP removed: %s\n", event.Vtep.Ip)
    case overlay.VTEP_EVENT_HEALTHY:
        fmt.Printf("[*] VTEP healthy: %s\n", event.Vtep.Ip)
    case overlay.VTEP_EVENT_UNHEALTHY:
        fmt.Printf("[!] VTEP unhealthy: %s\n", event.Vtep.Ip)
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
        fmt.Printf("[+] Tunnel up: %s -> %s\n",
            event.Tunnel.LocalVtep, event.Tunnel.RemoteVtep)
    case overlay.TUNNEL_EVENT_FAILED:
        fmt.Printf("[!] Tunnel failed: %s -> %s\n",
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
        fmt.Printf("[+] MAC learned: %s -> %s\n",
            event.Entry.Mac, event.Entry.VtepIp)
    case overlay.MAC_EVENT_MOVED:
        fmt.Printf("[~] MAC moved: %s -> %s\n",
            event.Entry.Mac, event.Entry.VtepIp)
    case overlay.MAC_EVENT_AGED:
        fmt.Printf("[-] MAC aged: %s\n", event.Entry.Mac)
    }
}
```

## CLI Integration

The `platformctl` CLI uses Unix socket by default.

```bash
# List VTEPs
platformctl overlay vtep list

# Register VTEP
platformctl overlay vtep register \
  --ip 10.0.0.1 \
  --underlay-iface eth0 \
  --underlay-mtu 9000

# Get VTEP health
platformctl overlay vtep health 10.0.0.1

# Create VNI
platformctl overlay vni create \
  --id 1000100 \
  --vlan-id 100

# Join VNI
platformctl overlay vni join 1000100

# List tunnels
platformctl overlay tunnel list

# Create tunnel
platformctl overlay tunnel create \
  --remote-vtep 10.0.0.2 \
  --vnis 1000100,1000200

# Get tunnel stats
platformctl overlay tunnel stats 10.0.0.2

# Watch events
platformctl overlay vtep watch
platformctl overlay tunnel watch
platformctl overlay mac watch --vni 1000100

# List MACs for VNI
platformctl overlay mac list --vni 1000100

# Add static MAC
platformctl overlay mac add \
  --vni 1000100 \
  --mac aa:bb:cc:dd:ee:ff \
  --vtep 10.0.0.2

# Flush MACs
platformctl overlay mac flush --vni 1000100 --type remote
```

## Authentication

Unix socket authentication uses peer credentials.

### Server-Side Verification

```go
func (s *server) authenticate(ctx context.Context) error {
    peer, ok := peer.FromContext(ctx)
    if !ok {
        return status.Error(codes.Unauthenticated, "no peer info")
    }

    authInfo, ok := peer.AuthInfo.(credentials.UnixCredentials)
    if !ok {
        return status.Error(codes.Unauthenticated, "not unix socket")
    }

    creds := authInfo.Credentials

    // Check UID - require root or platform service user
    if creds.Uid != 0 && creds.Uid != platformUID {
        return status.Error(codes.PermissionDenied, "unauthorized user")
    }

    return nil
}
```

### Socket Permissions

```bash
# Socket is created with restricted permissions
# /run/platformd.sock: srw-rw---- root platform

# Users in 'platform' group can access
sudo usermod -aG platform myuser
```

## Error Handling

```go
vtep, err := client.GetVTEP(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.NotFound:
            fmt.Println("VTEP not found")
        case codes.PermissionDenied:
            fmt.Println("Permission denied - check socket permissions")
        case codes.Unavailable:
            fmt.Println("Service unavailable - is platformd running?")
        default:
            fmt.Printf("Error: %s\n", st.Message())
        }
    }
    return err
}
```

## Socket Path Configuration

The socket path can be configured.

```yaml
# /etc/platform/config.yaml
api:
  unix:
    enabled: true
    socket_path: /run/platformd.sock
    permissions: 0660
    group: platform
```

## Performance

Unix sockets provide optimal performance for local operations.

| Metric | Unix Socket | gRPC/TCP | REST |
|--------|-------------|----------|------|
| Latency | ~50us | ~200us | ~500us |
| Throughput | 100K+ req/s | 50K req/s | 20K req/s |
| Setup time | ~10us | ~100us | ~300us |

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [QUIC API Reference](api-reference-quic.md)
- [MCP API Reference](api-reference-mcp.md)
- [Architecture](architecture.md)
