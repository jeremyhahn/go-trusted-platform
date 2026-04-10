# Gateway Unix Socket API Reference

Unix socket interface for local IPC with the gateway service.

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
- **Local-only access** - Secure for gateway management

## Connection Setup

### Go Client

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    gateway "github.com/jeremyhahn/go-trusted-platform/api/sdn/gateway/v1"
)

func NewGatewayUnixClient() (gateway.GatewayServiceClient, error) {
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

    return gateway.NewGatewayServiceClient(conn), nil
}
```

## Service Methods

### Gateway Registration Operations

#### RegisterGateway

```go
client, err := NewGatewayUnixClient()
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
fmt.Printf("Gateway registered: %s\n", gw.Id)
fmt.Printf("  Mode: %s\n", gw.Mode)
fmt.Printf("  Region: %s\n", gw.Region)
fmt.Printf("  IPv6 Prefix: %s\n", gw.Ipv6Prefix)
```

#### GetGateway

```go
gw, err := client.GetGateway(ctx, &gateway.GetGatewayRequest{
    Id: "gw-001",
})
if err != nil {
    return err
}
fmt.Printf("Gateway: %s\n", gw.Id)
fmt.Printf("  Mode: %s\n", gw.Mode)
fmt.Printf("  Healthy: %v\n", gw.Healthy)
fmt.Printf("  Uptime: %d seconds\n", gw.UptimeSeconds)
fmt.Printf("  Connections: %d active\n", gw.Connections.Active)
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
    fmt.Printf("%s: mode=%s, healthy=%v, connections=%d\n",
        gw.Id, gw.Mode, gw.Healthy, gw.Connections.Active)
}
```

#### UpdateGateway

```go
gw, err := client.UpdateGateway(ctx, &gateway.UpdateGatewayRequest{
    Id: "gw-001",
    Config: &gateway.GatewayConfig{
        MaxConnections: 20000,
    },
})
```

#### DeregisterGateway

```go
_, err := client.DeregisterGateway(ctx, &gateway.DeregisterGatewayRequest{
    Id: "gw-001",
})
```

### Gateway Mode Operations

#### SetGatewayMode

```go
resp, err := client.SetGatewayMode(ctx, &gateway.SetGatewayModeRequest{
    Id:   "gw-001",
    Mode: gateway.GATEWAY_MODE_MAINTENANCE,
})
if err != nil {
    return err
}
fmt.Printf("Mode changed: %s -> %s\n", resp.PreviousMode, resp.Mode)
```

#### PromoteGateway

```go
resp, err := client.PromoteGateway(ctx, &gateway.PromoteGatewayRequest{
    Id: "gw-002",
})
if err != nil {
    return err
}
fmt.Printf("Gateway %s promoted to active\n", resp.Id)
if resp.DemotedGateway != "" {
    fmt.Printf("Gateway %s was demoted\n", resp.DemotedGateway)
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
fmt.Printf("Gateway %s health:\n", health.Id)
fmt.Printf("  Overall: %v\n", health.Healthy)
fmt.Printf("  Uptime: %d seconds\n", health.UptimeSeconds)
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
fmt.Printf("Heartbeat acknowledged at %s\n", resp.Timestamp.AsTime())
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
fmt.Printf("Allocated IPv6: %s/%d\n", alloc.Address, alloc.PrefixLength)
fmt.Printf("  Device: %s\n", alloc.DeviceId)
fmt.Printf("  Gateway: %s\n", alloc.GatewayId)
fmt.Printf("  VNI: %d\n", alloc.Vni)
```

#### ReleaseIPv6

```go
_, err := client.ReleaseIPv6(ctx, &gateway.ReleaseIPv6Request{
    Address: "2602:F5BB:0001:0100::1",
})
if err != nil {
    return err
}
fmt.Println("IPv6 address released")
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
fmt.Printf("Found %d allocations:\n", resp.Total)
for _, alloc := range resp.Allocations {
    fmt.Printf("  %s -> %s (VNI %d)\n",
        alloc.Address, alloc.DeviceId, alloc.Vni)
}
```

#### GetIPv6Pools

```go
resp, err := client.GetIPv6Pools(ctx, &gateway.GetIPv6PoolsRequest{})
if err != nil {
    return err
}
for _, pool := range resp.Pools {
    fmt.Printf("Pool %s:\n", pool.Prefix)
    fmt.Printf("  Gateway: %s\n", pool.GatewayId)
    fmt.Printf("  Total: %d\n", pool.TotalAddresses)
    fmt.Printf("  Allocated: %d\n", pool.Allocated)
    fmt.Printf("  Available: %d\n", pool.Available)
    fmt.Printf("  Utilization: %.1f%%\n", pool.UtilizationPercent)
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
fmt.Printf("  Device ID: %s\n", device.DeviceId)
fmt.Printf("  MAC: %s\n", device.MacAddress)
fmt.Printf("  VLAN: %d -> VNI: %d\n", device.VlanId, device.Vni)
fmt.Printf("  IPv6: %s\n", device.Ipv6Address)
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
fmt.Printf("Released resources:\n")
fmt.Printf("  IPv6: %s\n", resp.ResourcesReleased.Ipv6Address)
fmt.Printf("  VNI: %d\n", resp.ResourcesReleased.Vni)
```

#### GetDeviceStatus

```go
status, err := client.GetDeviceStatus(ctx, &gateway.GetDeviceStatusRequest{
    DeviceId: "device-001",
})
if err != nil {
    return err
}
fmt.Printf("Device %s:\n", status.DeviceId)
fmt.Printf("  State: %s\n", status.State)
fmt.Printf("  MAC: %s\n", status.MacAddress)
fmt.Printf("  IPv6: %s\n", status.Ipv6Address)
fmt.Printf("  VTEP: %s\n", status.ConnectedVtep)
fmt.Printf("  Last activity: %s\n", status.LastActivity.AsTime())
fmt.Printf("  Traffic: %d in / %d out bytes\n",
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
fmt.Printf("  VIP: %s:%d\n", lb.Vip, lb.Port)
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
fmt.Printf("  VIP: %s:%d\n", lb.Vip, lb.Port)
fmt.Printf("  Protocol: %s\n", lb.Protocol)
fmt.Printf("  Algorithm: %s\n", lb.Algorithm)
fmt.Printf("  Active connections: %d\n", lb.Statistics.ActiveConnections)
for _, backend := range lb.Backends {
    fmt.Printf("  Backend %s:%d - %s (weight: %d)\n",
        backend.Address, backend.Port, backend.State, backend.Weight)
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
    fmt.Printf("%s (%s): %s:%d, backends=%d\n",
        lb.Name, lb.Id, lb.Vip, lb.Port, len(lb.Backends))
}
```

#### UpdateLoadBalancer

```go
lb, err := client.UpdateLoadBalancer(ctx, &gateway.UpdateLoadBalancerRequest{
    Id:        "lb-001",
    Algorithm: gateway.ALGORITHM_LEAST_CONNECTIONS,
})
```

#### DeleteLoadBalancer

```go
_, err := client.DeleteLoadBalancer(ctx, &gateway.DeleteLoadBalancerRequest{
    Id: "lb-001",
})
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
fmt.Printf("Backend added: %s:%d\n", backend.Address, backend.Port)
```

#### RemoveBackend

```go
_, err := client.RemoveBackend(ctx, &gateway.RemoveBackendRequest{
    LoadbalancerId: "lb-001",
    Address:        "2602:F5BB:0001:0100::12",
})
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
fmt.Printf("Backend draining: %s\n", backend.State)
fmt.Printf("Active connections: %d\n", backend.Statistics.ActiveConnections)
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
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }

    switch event.Type {
    case gateway.GATEWAY_EVENT_REGISTERED:
        fmt.Printf("[+] Gateway registered: %s\n", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_DEREGISTERED:
        fmt.Printf("[-] Gateway deregistered: %s\n", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_PROMOTED:
        fmt.Printf("[*] Gateway promoted: %s\n", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_DEMOTED:
        fmt.Printf("[*] Gateway demoted: %s\n", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_UNHEALTHY:
        fmt.Printf("[!] Gateway unhealthy: %s\n", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_HEALTHY:
        fmt.Printf("[*] Gateway healthy: %s\n", event.Gateway.Id)
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
        fmt.Printf("[+] Device onboarded: %s (IPv6: %s)\n",
            event.Device.DeviceId, event.Device.Ipv6Address)
    case gateway.DEVICE_EVENT_OFFBOARDED:
        fmt.Printf("[-] Device offboarded: %s\n", event.Device.DeviceId)
    case gateway.DEVICE_EVENT_ACTIVE:
        fmt.Printf("[*] Device active: %s\n", event.Device.DeviceId)
    case gateway.DEVICE_EVENT_INACTIVE:
        fmt.Printf("[!] Device inactive: %s\n", event.Device.DeviceId)
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
    case gateway.LB_EVENT_CREATED:
        fmt.Printf("[+] LB created: %s\n", event.Loadbalancer.Name)
    case gateway.LB_EVENT_DELETED:
        fmt.Printf("[-] LB deleted: %s\n", event.Loadbalancer.Name)
    case gateway.LB_EVENT_BACKEND_HEALTHY:
        fmt.Printf("[*] Backend healthy: %s on %s\n",
            event.Backend.Address, event.Loadbalancer.Name)
    case gateway.LB_EVENT_BACKEND_UNHEALTHY:
        fmt.Printf("[!] Backend unhealthy: %s on %s\n",
            event.Backend.Address, event.Loadbalancer.Name)
    case gateway.LB_EVENT_BACKEND_DRAINING:
        fmt.Printf("[~] Backend draining: %s\n", event.Backend.Address)
    }
}
```

## CLI Integration

```bash
# List gateways
platformctl gateway list
platformctl gateway list --mode active --healthy-only

# Get gateway details
platformctl gateway get gw-001

# Register gateway
platformctl gateway register \
  --region us-east-1 \
  --ipv6-prefix "2602:F5BB:0001::/48" \
  --vtep-ip 10.0.0.1

# Promote/demote gateway
platformctl gateway promote gw-002
platformctl gateway demote gw-001

# Check health
platformctl gateway health gw-001

# IPv6 operations
platformctl gateway ipv6 allocate --device-id device-001 --vni 1000100
platformctl gateway ipv6 release --address "2602:F5BB:0001:0100::1"
platformctl gateway ipv6 list --vni 1000100
platformctl gateway ipv6 pools

# Device operations
platformctl gateway device onboard \
  --device-id device-001 \
  --mac aa:bb:cc:dd:ee:ff \
  --vlan-id 100
platformctl gateway device offboard --device-id device-001
platformctl gateway device status device-001

# Load balancer operations
platformctl gateway lb list
platformctl gateway lb get lb-001
platformctl gateway lb create \
  --name web-frontend \
  --vip "2602:F5BB:0001:0100::80" \
  --port 443 \
  --protocol tcp
platformctl gateway lb delete lb-001
platformctl gateway lb backend add --lb lb-001 --address "2602:F5BB:0001:0100::12" --port 8443
platformctl gateway lb backend remove --lb lb-001 --address "2602:F5BB:0001:0100::12"
platformctl gateway lb backend drain --lb lb-001 --address "2602:F5BB:0001:0100::10"

# Watch events
platformctl gateway watch
platformctl gateway device watch
platformctl gateway lb watch
```

## Error Handling

```go
gw, err := client.GetGateway(ctx, req)
if err != nil {
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.NotFound:
            fmt.Println("Gateway not found")
        case codes.FailedPrecondition:
            fmt.Println("Gateway unhealthy")
        case codes.ResourceExhausted:
            fmt.Println("Pool exhausted - no available IPs")
        case codes.PermissionDenied:
            fmt.Println("Permission denied")
        case codes.Unavailable:
            fmt.Println("Service unavailable")
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
