# Gateway QUIC API Reference

QUIC transport for the gateway service, providing low-latency, multiplexed connections.

| Property | Value |
|----------|-------|
| Service | `gateway.GatewayService` |
| Port | 9444 |
| Transport | QUIC (UDP) with TLS 1.3 |

## Overview

QUIC transport provides several advantages for gateway operations:

- **0-RTT connection establishment** - Fast reconnection for mobile clients
- **Stream multiplexing** - Independent streams for devices, IPv6, and load balancers
- **Built-in encryption** - TLS 1.3 integrated into transport
- **Connection migration** - Handle client network changes seamlessly
- **Low latency** - Ideal for real-time device onboarding

## Connection Setup

### TLS Configuration

```go
import (
    "crypto/tls"
    "github.com/quic-go/quic-go"
    gateway "github.com/jeremyhahn/go-trusted-platform/api/sdn/gateway/v1"
)

func NewGatewayQUICClient(addr string, tlsConfig *tls.Config) (gateway.GatewayServiceClient, error) {
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"gateway-quic-v1"}

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

    return gateway.NewGatewayServiceClientQUIC(conn), nil
}
```

### Connection with 0-RTT

```go
func NewGatewayQUICClient0RTT(addr string, tlsConfig *tls.Config, sessionCache tls.ClientSessionCache) (gateway.GatewayServiceClient, error) {
    tlsConfig.ClientSessionCache = sessionCache
    tlsConfig.MinVersion = tls.VersionTLS13
    tlsConfig.NextProtos = []string{"gateway-quic-v1"}

    quicConfig := &quic.Config{
        Enable0RTT: true,
    }

    conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, quicConfig)
    if err != nil {
        return nil, err
    }

    return gateway.NewGatewayServiceClientQUIC(conn), nil
}
```

## Service Methods

### Gateway Registration Operations

#### RegisterGateway

```go
client, err := NewGatewayQUICClient("platform.example.com:9444", tlsConfig)
if err != nil {
    return err
}

gw, err := client.RegisterGateway(ctx, &gateway.RegisterGatewayRequest{
    Region:       "us-east-1",
    Ipv6Prefix:   "2602:F5BB:0001::/48",
    Ipv4Address:  "23.143.36.1",
    VtepIp:       "10.0.0.1",
    Capabilities: []string{"ipv6", "ipv4", "nat64", "load_balancer"},
    Config: &gateway.GatewayConfig{
        MaxConnections:           10000,
        ConnectionTimeoutSeconds: 300,
        Nat64Enabled:            true,
    },
})
if err != nil {
    return err
}
fmt.Printf("Gateway registered: %s (mode: %s)\n", gw.Id, gw.Mode)
```

#### GetGateway

```go
gw, err := client.GetGateway(ctx, &gateway.GetGatewayRequest{
    Id: "gw-001",
})
if err != nil {
    return err
}
fmt.Printf("Gateway: %s, Mode: %s, Healthy: %v\n",
    gw.Id, gw.Mode, gw.Healthy)
fmt.Printf("Connections: %d active, %d total\n",
    gw.Connections.Active, gw.Connections.Total)
```

#### ListGateways

```go
resp, err := client.ListGateways(ctx, &gateway.ListGatewaysRequest{
    Mode:        gateway.GATEWAY_MODE_ACTIVE,
    Region:      "us-east-1",
    HealthyOnly: true,
    Limit:       100,
})
if err != nil {
    return err
}
for _, gw := range resp.Gateways {
    fmt.Printf("Gateway %s: %s, connections=%d\n",
        gw.Id, gw.Mode, gw.Connections.Active)
}
```

### Gateway Mode Operations

#### PromoteGateway

```go
resp, err := client.PromoteGateway(ctx, &gateway.PromoteGatewayRequest{
    Id: "gw-002",
})
if err != nil {
    return err
}
fmt.Printf("Gateway %s promoted to %s\n", resp.Id, resp.Mode)
if resp.DemotedGateway != "" {
    fmt.Printf("Demoted gateway: %s\n", resp.DemotedGateway)
}
```

#### DemoteGateway

```go
resp, err := client.DemoteGateway(ctx, &gateway.DemoteGatewayRequest{
    Id: "gw-001",
})
if err != nil {
    return err
}
fmt.Printf("Gateway %s demoted to %s\n", resp.Id, resp.Mode)
```

### Health Operations

#### GetGatewayHealth

```go
health, err := client.GetGatewayHealth(ctx, &gateway.GetGatewayHealthRequest{
    Id: "gw-001",
})
if err != nil {
    return err
}
fmt.Printf("Gateway %s: healthy=%v\n", health.Id, health.Healthy)
for _, check := range health.Checks {
    fmt.Printf("  %s: %s (%s)\n", check.Name, check.Status, check.Message)
}
```

#### Heartbeat

```go
resp, err := client.Heartbeat(ctx, &gateway.HeartbeatRequest{
    Id: "gw-001",
})
if err != nil {
    return err
}
fmt.Printf("Heartbeat acknowledged: %v\n", resp.Acknowledged)
```

### IPv6 Allocation Operations

#### AllocateIPv6

```go
alloc, err := client.AllocateIPv6(ctx, &gateway.AllocateIPv6Request{
    DeviceId:     "device-001",
    PrefixLength: 128,
    Vni:          1000100,
    Metadata: map[string]string{
        "owner":   "tenant-a",
        "purpose": "vm-network",
    },
})
if err != nil {
    return err
}
fmt.Printf("Allocated: %s/%d\n", alloc.Address, alloc.PrefixLength)
```

#### ReleaseIPv6

```go
_, err := client.ReleaseIPv6(ctx, &gateway.ReleaseIPv6Request{
    Address: "2602:F5BB:0001:0100::1",
})
if err != nil {
    return err
}
```

#### ListIPv6Allocations

```go
resp, err := client.ListIPv6Allocations(ctx, &gateway.ListIPv6AllocationsRequest{
    Vni:   1000100,
    Limit: 100,
})
if err != nil {
    return err
}
for _, alloc := range resp.Allocations {
    fmt.Printf("%s -> device %s\n", alloc.Address, alloc.DeviceId)
}
```

#### GetIPv6Pools

```go
resp, err := client.GetIPv6Pools(ctx, &gateway.GetIPv6PoolsRequest{})
if err != nil {
    return err
}
for _, pool := range resp.Pools {
    fmt.Printf("Pool %s: %d/%d used (%.1f%%)\n",
        pool.Prefix, pool.Allocated, pool.TotalAddresses,
        pool.UtilizationPercent)
}
```

### Device Onboarding Operations

#### OnboardDevice

```go
device, err := client.OnboardDevice(ctx, &gateway.OnboardDeviceRequest{
    DeviceId:      "device-001",
    MacAddress:    "aa:bb:cc:dd:ee:ff",
    VlanId:        100,
    Profile:       "standard-workstation",
    CertificateCn: "device-001.example.internal",
})
if err != nil {
    return err
}
fmt.Printf("Device onboarded:\n")
fmt.Printf("  IPv6: %s\n", device.Ipv6Address)
fmt.Printf("  VNI: %d\n", device.Vni)
fmt.Printf("  Gateway: %s\n", device.GatewayId)
fmt.Printf("  State: %s\n", device.State)
```

#### OffboardDevice

```go
resp, err := client.OffboardDevice(ctx, &gateway.OffboardDeviceRequest{
    DeviceId: "device-001",
})
if err != nil {
    return err
}
fmt.Printf("Device offboarded: %v\n", resp.Offboarded)
fmt.Printf("Released IPv6: %s\n", resp.ResourcesReleased.Ipv6Address)
```

#### GetDeviceStatus

```go
status, err := client.GetDeviceStatus(ctx, &gateway.GetDeviceStatusRequest{
    DeviceId: "device-001",
})
if err != nil {
    return err
}
fmt.Printf("Device %s: state=%s\n", status.DeviceId, status.State)
fmt.Printf("  IPv6: %s\n", status.Ipv6Address)
fmt.Printf("  VTEP: %s\n", status.ConnectedVtep)
fmt.Printf("  Traffic: %d in, %d out\n",
    status.Traffic.BytesIn, status.Traffic.BytesOut)
```

### Load Balancer Operations

#### CreateLoadBalancer

```go
lb, err := client.CreateLoadBalancer(ctx, &gateway.CreateLoadBalancerRequest{
    Name:      "web-frontend",
    Vip:       "2602:F5BB:0001:0100::80",
    Port:      443,
    Protocol:  gateway.PROTOCOL_TCP,
    Algorithm: gateway.ALGORITHM_ROUND_ROBIN,
    Backends: []*gateway.BackendConfig{
        {Address: "2602:F5BB:0001:0100::10", Port: 8443, Weight: 100},
        {Address: "2602:F5BB:0001:0100::11", Port: 8443, Weight: 100},
    },
    HealthCheck: &gateway.HealthCheckConfig{
        Protocol:           gateway.PROTOCOL_HTTPS,
        Path:               "/health",
        IntervalSeconds:    10,
        TimeoutSeconds:     5,
        HealthyThreshold:   2,
        UnhealthyThreshold: 3,
    },
})
if err != nil {
    return err
}
fmt.Printf("Load balancer created: %s\n", lb.Id)
```

#### GetLoadBalancer

```go
lb, err := client.GetLoadBalancer(ctx, &gateway.GetLoadBalancerRequest{
    Id: "lb-001",
})
if err != nil {
    return err
}
fmt.Printf("Load Balancer: %s (%s)\n", lb.Name, lb.State)
fmt.Printf("VIP: %s:%d\n", lb.Vip, lb.Port)
for _, backend := range lb.Backends {
    fmt.Printf("  Backend %s:%d - %s\n",
        backend.Address, backend.Port, backend.State)
}
```

#### ListLoadBalancers

```go
resp, err := client.ListLoadBalancers(ctx, &gateway.ListLoadBalancersRequest{
    State: gateway.LB_STATE_ACTIVE,
    Limit: 100,
})
if err != nil {
    return err
}
for _, lb := range resp.Loadbalancers {
    fmt.Printf("LB %s: %s, backends=%d\n",
        lb.Name, lb.State, len(lb.Backends))
}
```

#### AddBackend

```go
backend, err := client.AddBackend(ctx, &gateway.AddBackendRequest{
    LoadbalancerId: "lb-001",
    Backend: &gateway.BackendConfig{
        Address: "2602:F5BB:0001:0100::12",
        Port:    8443,
        Weight:  100,
    },
})
if err != nil {
    return err
}
fmt.Printf("Backend added: %s\n", backend.Address)
```

#### DrainBackend

```go
backend, err := client.DrainBackend(ctx, &gateway.DrainBackendRequest{
    LoadbalancerId: "lb-001",
    Address:        "2602:F5BB:0001:0100::10",
})
if err != nil {
    return err
}
fmt.Printf("Backend draining: %d active connections\n",
    backend.Statistics.ActiveConnections)
```

## Streaming Operations

### WatchGateways

```go
stream, err := client.WatchGateways(ctx, &gateway.WatchGatewaysRequest{
    IncludeInitial: true,
    Region:         "us-east-1",
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
    case gateway.GATEWAY_EVENT_REGISTERED:
        log.Printf("Gateway registered: %s", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_PROMOTED:
        log.Printf("Gateway promoted: %s", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_UNHEALTHY:
        log.Printf("Gateway unhealthy: %s", event.Gateway.Id)
    }
}
```

### WatchDevices

```go
stream, err := client.WatchDevices(ctx, &gateway.WatchDevicesRequest{
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
    case gateway.DEVICE_EVENT_ONBOARDED:
        log.Printf("Device onboarded: %s with IPv6 %s",
            event.Device.DeviceId, event.Device.Ipv6Address)
    case gateway.DEVICE_EVENT_OFFBOARDED:
        log.Printf("Device offboarded: %s", event.Device.DeviceId)
    case gateway.DEVICE_EVENT_ACTIVE:
        log.Printf("Device active: %s", event.Device.DeviceId)
    }
}
```

### WatchLoadBalancers

```go
stream, err := client.WatchLoadBalancers(ctx, &gateway.WatchLoadBalancersRequest{
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
    case gateway.LB_EVENT_BACKEND_UNHEALTHY:
        log.Printf("Backend unhealthy: %s on LB %s",
            event.Backend.Address, event.Loadbalancer.Id)
    case gateway.LB_EVENT_BACKEND_HEALTHY:
        log.Printf("Backend recovered: %s", event.Backend.Address)
    }
}
```

## Concurrent Streams

```go
var wg sync.WaitGroup

// Stream 1: Watch gateway events
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchGateways(ctx, &gateway.WatchGatewaysRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleGatewayEvent(event)
    }
}()

// Stream 2: Watch device events
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchDevices(ctx, &gateway.WatchDevicesRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleDeviceEvent(event)
    }
}()

// Stream 3: Watch load balancer events
wg.Add(1)
go func() {
    defer wg.Done()
    stream, _ := client.WatchLoadBalancers(ctx, &gateway.WatchLoadBalancersRequest{})
    for {
        event, err := stream.Recv()
        if err != nil {
            return
        }
        handleLBEvent(event)
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

gw, err := client.GetGateway(ctx, req)
if err != nil {
    var qErr *quic.ApplicationError
    if errors.As(err, &qErr) {
        log.Printf("QUIC error: code=%d", qErr.ErrorCode)
    }

    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.NotFound:
            log.Printf("Gateway not found")
        case codes.FailedPrecondition:
            log.Printf("Gateway unhealthy")
        case codes.ResourceExhausted:
            log.Printf("Pool exhausted")
        }
    }

    return err
}
```

## CLI Usage

```bash
# Use QUIC transport
platformctl --transport quic gateway list

# Register gateway
platformctl --transport quic gateway register \
  --region us-east-1 \
  --ipv6-prefix "2602:F5BB:0001::/48" \
  --vtep-ip 10.0.0.1

# Promote gateway
platformctl --transport quic gateway promote gw-002

# Onboard device
platformctl --transport quic gateway device onboard \
  --device-id device-001 \
  --mac aa:bb:cc:dd:ee:ff \
  --vlan-id 100

# Allocate IPv6
platformctl --transport quic gateway ipv6 allocate \
  --device-id device-001 \
  --vni 1000100

# Create load balancer
platformctl --transport quic gateway lb create \
  --name web-frontend \
  --vip "2602:F5BB:0001:0100::80" \
  --port 443

# Watch events
platformctl --transport quic gateway watch
platformctl --transport quic gateway device watch
platformctl --transport quic gateway lb watch
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [gRPC API Reference](api-reference-grpc.md)
- [MCP API Reference](api-reference-mcp.md)
- [Unix Socket API Reference](api-reference-unix.md)
