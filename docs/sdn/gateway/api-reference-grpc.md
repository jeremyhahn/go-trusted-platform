# Gateway gRPC API Reference

gRPC service definition for the gateway service.

| Property | Value |
|----------|-------|
| Service | `gateway.GatewayService` |
| Port | 10443 |
| Transport | TCP with TLS |

## Service Definition

```protobuf
syntax = "proto3";
package gateway;

import "google/protobuf/empty.proto";
import "google/protobuf/timestamp.proto";

service GatewayService {
  // Gateway registration operations
  rpc RegisterGateway(RegisterGatewayRequest) returns (Gateway);
  rpc GetGateway(GetGatewayRequest) returns (Gateway);
  rpc UpdateGateway(UpdateGatewayRequest) returns (Gateway);
  rpc DeregisterGateway(DeregisterGatewayRequest) returns (google.protobuf.Empty);
  rpc ListGateways(ListGatewaysRequest) returns (ListGatewaysResponse);

  // Gateway mode operations
  rpc SetGatewayMode(SetGatewayModeRequest) returns (GatewayModeResponse);
  rpc PromoteGateway(PromoteGatewayRequest) returns (GatewayModeResponse);
  rpc DemoteGateway(DemoteGatewayRequest) returns (GatewayModeResponse);

  // Health operations
  rpc GetGatewayHealth(GetGatewayHealthRequest) returns (GatewayHealth);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // IPv6 allocation operations
  rpc AllocateIPv6(AllocateIPv6Request) returns (IPv6Allocation);
  rpc ReleaseIPv6(ReleaseIPv6Request) returns (google.protobuf.Empty);
  rpc ListIPv6Allocations(ListIPv6AllocationsRequest) returns (ListIPv6AllocationsResponse);
  rpc GetIPv6Pools(GetIPv6PoolsRequest) returns (GetIPv6PoolsResponse);

  // Device onboarding operations
  rpc OnboardDevice(OnboardDeviceRequest) returns (OnboardedDevice);
  rpc OffboardDevice(OffboardDeviceRequest) returns (OffboardDeviceResponse);
  rpc GetDeviceStatus(GetDeviceStatusRequest) returns (DeviceStatus);

  // Load balancer operations
  rpc CreateLoadBalancer(CreateLoadBalancerRequest) returns (LoadBalancer);
  rpc GetLoadBalancer(GetLoadBalancerRequest) returns (LoadBalancer);
  rpc UpdateLoadBalancer(UpdateLoadBalancerRequest) returns (LoadBalancer);
  rpc DeleteLoadBalancer(DeleteLoadBalancerRequest) returns (google.protobuf.Empty);
  rpc ListLoadBalancers(ListLoadBalancersRequest) returns (ListLoadBalancersResponse);
  rpc AddBackend(AddBackendRequest) returns (Backend);
  rpc RemoveBackend(RemoveBackendRequest) returns (google.protobuf.Empty);
  rpc DrainBackend(DrainBackendRequest) returns (Backend);

  // Streaming operations
  rpc WatchGateways(WatchGatewaysRequest) returns (stream GatewayEvent);
  rpc WatchDevices(WatchDevicesRequest) returns (stream DeviceEvent);
  rpc WatchLoadBalancers(WatchLoadBalancersRequest) returns (stream LoadBalancerEvent);
}
```

## Gateway Registration Operations

### RegisterGateway

```protobuf
message RegisterGatewayRequest {
  string region = 1;
  string ipv6_prefix = 2;
  string ipv4_address = 3;
  string vtep_ip = 4;
  repeated string capabilities = 5;
  GatewayConfig config = 6;
}

message Gateway {
  string id = 1;
  string node_id = 2;
  string region = 3;
  GatewayMode mode = 4;
  string ipv6_prefix = 5;
  string ipv4_address = 6;
  string vtep_ip = 7;
  bool healthy = 8;
  google.protobuf.Timestamp last_heartbeat = 9;
  uint64 uptime_seconds = 10;
  GatewayConnections connections = 11;
  repeated string capabilities = 12;
  GatewayConfig config = 13;
  GatewayStatistics statistics = 14;
}

enum GatewayMode {
  GATEWAY_MODE_UNKNOWN = 0;
  GATEWAY_MODE_ACTIVE = 1;
  GATEWAY_MODE_STANDBY = 2;
  GATEWAY_MODE_MAINTENANCE = 3;
}

message GatewayConfig {
  uint32 max_connections = 1;
  uint32 connection_timeout_seconds = 2;
  bool nat64_enabled = 3;
  string nat64_prefix = 4;
}

message GatewayConnections {
  uint32 active = 1;
  uint64 total = 2;
}

message GatewayStatistics {
  uint64 bytes_in = 1;
  uint64 bytes_out = 2;
  uint64 packets_in = 3;
  uint64 packets_out = 4;
  uint64 errors = 5;
}
```

**Go Example:**
```go
gw, err := client.RegisterGateway(ctx, &gateway.RegisterGatewayRequest{
    Region:      "us-east-1",
    Ipv6Prefix:  "2602:F5BB:0001::/48",
    Ipv4Address: "23.143.36.1",
    VtepIp:      "10.0.0.1",
    Capabilities: []string{"ipv6", "ipv4", "nat64", "load_balancer"},
    Config: &gateway.GatewayConfig{
        MaxConnections:           10000,
        ConnectionTimeoutSeconds: 300,
        Nat64Enabled:            true,
    },
})
```

### GetGateway

```protobuf
message GetGatewayRequest {
  string id = 1;
}
```

**Go Example:**
```go
gw, err := client.GetGateway(ctx, &gateway.GetGatewayRequest{
    Id: "gw-001",
})
```

### ListGateways

```protobuf
message ListGatewaysRequest {
  GatewayMode mode = 1;
  string region = 2;
  bool healthy_only = 3;
  uint32 limit = 4;
  uint32 offset = 5;
}

message ListGatewaysResponse {
  repeated Gateway gateways = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### UpdateGateway

```protobuf
message UpdateGatewayRequest {
  string id = 1;
  GatewayConfig config = 2;
}
```

### DeregisterGateway

```protobuf
message DeregisterGatewayRequest {
  string id = 1;
}
```

## Gateway Mode Operations

### SetGatewayMode

```protobuf
message SetGatewayModeRequest {
  string id = 1;
  GatewayMode mode = 2;
}

message GatewayModeResponse {
  string id = 1;
  GatewayMode previous_mode = 2;
  GatewayMode mode = 3;
  google.protobuf.Timestamp transition_time = 4;
  string demoted_gateway = 5;
}
```

**Go Example:**
```go
resp, err := client.SetGatewayMode(ctx, &gateway.SetGatewayModeRequest{
    Id:   "gw-001",
    Mode: gateway.GATEWAY_MODE_ACTIVE,
})
```

### PromoteGateway

```protobuf
message PromoteGatewayRequest {
  string id = 1;
}
```

**Go Example:**
```go
resp, err := client.PromoteGateway(ctx, &gateway.PromoteGatewayRequest{
    Id: "gw-001",
})
fmt.Printf("Gateway promoted, demoted: %s\n", resp.DemotedGateway)
```

### DemoteGateway

```protobuf
message DemoteGatewayRequest {
  string id = 1;
}
```

## Health Operations

### GetGatewayHealth

```protobuf
message GetGatewayHealthRequest {
  string id = 1;
}

message GatewayHealth {
  string id = 1;
  bool healthy = 2;
  repeated HealthCheck checks = 3;
  uint64 uptime_seconds = 4;
  google.protobuf.Timestamp last_failure = 5;
}

message HealthCheck {
  string name = 1;
  HealthStatus status = 2;
  string message = 3;
  google.protobuf.Timestamp last_check = 4;
}

enum HealthStatus {
  HEALTH_STATUS_UNKNOWN = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_UNHEALTHY = 2;
  HEALTH_STATUS_DEGRADED = 3;
}
```

**Go Example:**
```go
health, err := client.GetGatewayHealth(ctx, &gateway.GetGatewayHealthRequest{
    Id: "gw-001",
})
for _, check := range health.Checks {
    fmt.Printf("Check %s: %s (%s)\n", check.Name, check.Status, check.Message)
}
```

### Heartbeat

```protobuf
message HeartbeatRequest {
  string id = 1;
}

message HeartbeatResponse {
  string id = 1;
  bool acknowledged = 2;
  google.protobuf.Timestamp timestamp = 3;
}
```

## IPv6 Allocation Operations

### AllocateIPv6

```protobuf
message AllocateIPv6Request {
  string device_id = 1;
  uint32 prefix_length = 2;
  uint32 vni = 3;
  map<string, string> metadata = 4;
}

message IPv6Allocation {
  string address = 1;
  uint32 prefix_length = 2;
  string device_id = 3;
  string gateway_id = 4;
  uint32 vni = 5;
  google.protobuf.Timestamp allocated_at = 6;
  google.protobuf.Timestamp expires_at = 7;
  map<string, string> metadata = 8;
}
```

**Go Example:**
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
fmt.Printf("Allocated: %s/%d\n", alloc.Address, alloc.PrefixLength)
```

### ReleaseIPv6

```protobuf
message ReleaseIPv6Request {
  string address = 1;
}
```

### ListIPv6Allocations

```protobuf
message ListIPv6AllocationsRequest {
  string device_id = 1;
  uint32 vni = 2;
  string gateway_id = 3;
  uint32 limit = 4;
  uint32 offset = 5;
}

message ListIPv6AllocationsResponse {
  repeated IPv6Allocation allocations = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### GetIPv6Pools

```protobuf
message GetIPv6PoolsRequest {}

message GetIPv6PoolsResponse {
  repeated IPv6Pool pools = 1;
}

message IPv6Pool {
  string prefix = 1;
  string gateway_id = 2;
  uint64 total_addresses = 3;
  uint64 allocated = 4;
  uint64 available = 5;
  float utilization_percent = 6;
}
```

## Device Onboarding Operations

### OnboardDevice

```protobuf
message OnboardDeviceRequest {
  string device_id = 1;
  string mac_address = 2;
  uint32 vlan_id = 3;
  string profile = 4;
  string certificate_cn = 5;
}

message OnboardedDevice {
  string device_id = 1;
  string mac_address = 2;
  uint32 vlan_id = 3;
  uint32 vni = 4;
  string ipv6_address = 5;
  string gateway_id = 6;
  google.protobuf.Timestamp onboarded_at = 7;
  DeviceState state = 8;
}

enum DeviceState {
  DEVICE_STATE_UNKNOWN = 0;
  DEVICE_STATE_PROVISIONING = 1;
  DEVICE_STATE_PROVISIONED = 2;
  DEVICE_STATE_ACTIVE = 3;
  DEVICE_STATE_INACTIVE = 4;
  DEVICE_STATE_OFFBOARDED = 5;
}
```

**Go Example:**
```go
device, err := client.OnboardDevice(ctx, &gateway.OnboardDeviceRequest{
    DeviceId:      "device-001",
    MacAddress:    "aa:bb:cc:dd:ee:ff",
    VlanId:        100,
    Profile:       "standard-workstation",
    CertificateCn: "device-001.example.internal",
})
fmt.Printf("Device onboarded: IPv6=%s, VNI=%d\n",
    device.Ipv6Address, device.Vni)
```

### OffboardDevice

```protobuf
message OffboardDeviceRequest {
  string device_id = 1;
}

message OffboardDeviceResponse {
  string device_id = 1;
  bool offboarded = 2;
  ReleasedResources resources_released = 3;
}

message ReleasedResources {
  string ipv6_address = 1;
  uint32 vni = 2;
}
```

### GetDeviceStatus

```protobuf
message GetDeviceStatusRequest {
  string device_id = 1;
}

message DeviceStatus {
  string device_id = 1;
  DeviceState state = 2;
  string mac_address = 3;
  uint32 vlan_id = 4;
  uint32 vni = 5;
  string ipv6_address = 6;
  string gateway_id = 7;
  string connected_vtep = 8;
  google.protobuf.Timestamp last_activity = 9;
  DeviceTraffic traffic = 10;
}

message DeviceTraffic {
  uint64 bytes_in = 1;
  uint64 bytes_out = 2;
  uint64 packets_in = 3;
  uint64 packets_out = 4;
}
```

## Load Balancer Operations

### CreateLoadBalancer

```protobuf
message CreateLoadBalancerRequest {
  string name = 1;
  string vip = 2;
  uint32 port = 3;
  Protocol protocol = 4;
  Algorithm algorithm = 5;
  repeated BackendConfig backends = 6;
  HealthCheckConfig health_check = 7;
}

message LoadBalancer {
  string id = 1;
  string name = 2;
  string gateway_id = 3;
  string vip = 4;
  uint32 port = 5;
  Protocol protocol = 6;
  Algorithm algorithm = 7;
  LoadBalancerState state = 8;
  repeated Backend backends = 9;
  HealthCheckConfig health_check = 10;
  LoadBalancerStatistics statistics = 11;
}

enum Protocol {
  PROTOCOL_UNKNOWN = 0;
  PROTOCOL_TCP = 1;
  PROTOCOL_UDP = 2;
  PROTOCOL_HTTP = 3;
  PROTOCOL_HTTPS = 4;
}

enum Algorithm {
  ALGORITHM_UNKNOWN = 0;
  ALGORITHM_ROUND_ROBIN = 1;
  ALGORITHM_LEAST_CONNECTIONS = 2;
  ALGORITHM_IP_HASH = 3;
  ALGORITHM_WEIGHTED = 4;
}

enum LoadBalancerState {
  LB_STATE_UNKNOWN = 0;
  LB_STATE_ACTIVE = 1;
  LB_STATE_DRAINING = 2;
  LB_STATE_DISABLED = 3;
}

message BackendConfig {
  string address = 1;
  uint32 port = 2;
  uint32 weight = 3;
}

message Backend {
  string address = 1;
  uint32 port = 2;
  uint32 weight = 3;
  BackendState state = 4;
  BackendStatistics statistics = 5;
}

enum BackendState {
  BACKEND_STATE_UNKNOWN = 0;
  BACKEND_STATE_HEALTHY = 1;
  BACKEND_STATE_UNHEALTHY = 2;
  BACKEND_STATE_DRAINING = 3;
  BACKEND_STATE_DISABLED = 4;
}

message BackendStatistics {
  uint32 active_connections = 1;
  uint64 total_connections = 2;
}

message HealthCheckConfig {
  Protocol protocol = 1;
  string path = 2;
  uint32 interval_seconds = 3;
  uint32 timeout_seconds = 4;
  uint32 healthy_threshold = 5;
  uint32 unhealthy_threshold = 6;
}

message LoadBalancerStatistics {
  uint32 active_connections = 1;
  uint64 total_connections = 2;
  uint64 bytes_in = 3;
  uint64 bytes_out = 4;
}
```

**Go Example:**
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
```

### GetLoadBalancer

```protobuf
message GetLoadBalancerRequest {
  string id = 1;
}
```

### ListLoadBalancers

```protobuf
message ListLoadBalancersRequest {
  string gateway_id = 1;
  LoadBalancerState state = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}

message ListLoadBalancersResponse {
  repeated LoadBalancer loadbalancers = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### UpdateLoadBalancer

```protobuf
message UpdateLoadBalancerRequest {
  string id = 1;
  Algorithm algorithm = 2;
  repeated BackendConfig backends = 3;
  HealthCheckConfig health_check = 4;
}
```

### DeleteLoadBalancer

```protobuf
message DeleteLoadBalancerRequest {
  string id = 1;
}
```

### AddBackend

```protobuf
message AddBackendRequest {
  string loadbalancer_id = 1;
  BackendConfig backend = 2;
}
```

### RemoveBackend

```protobuf
message RemoveBackendRequest {
  string loadbalancer_id = 1;
  string address = 2;
}
```

### DrainBackend

```protobuf
message DrainBackendRequest {
  string loadbalancer_id = 1;
  string address = 2;
}
```

## Streaming Operations

### WatchGateways

Monitor gateway registration and state changes.

```protobuf
message WatchGatewaysRequest {
  bool include_initial = 1;
  string region = 2;
}

message GatewayEvent {
  GatewayEventType type = 1;
  Gateway gateway = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum GatewayEventType {
  GATEWAY_EVENT_UNKNOWN = 0;
  GATEWAY_EVENT_REGISTERED = 1;
  GATEWAY_EVENT_DEREGISTERED = 2;
  GATEWAY_EVENT_PROMOTED = 3;
  GATEWAY_EVENT_DEMOTED = 4;
  GATEWAY_EVENT_HEALTHY = 5;
  GATEWAY_EVENT_UNHEALTHY = 6;
}
```

**Go Example:**
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
    case gateway.GATEWAY_EVENT_PROMOTED:
        log.Printf("Gateway promoted to active: %s", event.Gateway.Id)
    case gateway.GATEWAY_EVENT_UNHEALTHY:
        log.Printf("Gateway unhealthy: %s", event.Gateway.Id)
    }
}
```

### WatchDevices

Monitor device onboarding and state changes.

```protobuf
message WatchDevicesRequest {
  bool include_initial = 1;
  string gateway_id = 2;
}

message DeviceEvent {
  DeviceEventType type = 1;
  OnboardedDevice device = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum DeviceEventType {
  DEVICE_EVENT_UNKNOWN = 0;
  DEVICE_EVENT_ONBOARDED = 1;
  DEVICE_EVENT_OFFBOARDED = 2;
  DEVICE_EVENT_ACTIVE = 3;
  DEVICE_EVENT_INACTIVE = 4;
}
```

**Go Example:**
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
    }
}
```

### WatchLoadBalancers

Monitor load balancer and backend state changes.

```protobuf
message WatchLoadBalancersRequest {
  bool include_initial = 1;
  string gateway_id = 2;
}

message LoadBalancerEvent {
  LoadBalancerEventType type = 1;
  LoadBalancer loadbalancer = 2;
  Backend backend = 3;
  google.protobuf.Timestamp timestamp = 4;
}

enum LoadBalancerEventType {
  LB_EVENT_UNKNOWN = 0;
  LB_EVENT_CREATED = 1;
  LB_EVENT_DELETED = 2;
  LB_EVENT_BACKEND_ADDED = 3;
  LB_EVENT_BACKEND_REMOVED = 4;
  LB_EVENT_BACKEND_HEALTHY = 5;
  LB_EVENT_BACKEND_UNHEALTHY = 6;
  LB_EVENT_BACKEND_DRAINING = 7;
}
```

**Go Example:**
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
        log.Printf("Backend recovered: %s on LB %s",
            event.Backend.Address, event.Loadbalancer.Id)
    }
}
```

## Error Handling

gRPC status codes map to gateway errors:

| gRPC Code | Gateway Error |
|-----------|---------------|
| `NOT_FOUND` | gateway_not_found, device_not_found, loadbalancer_not_found |
| `ALREADY_EXISTS` | gateway_exists, ip_allocated, device_onboarded |
| `INVALID_ARGUMENT` | invalid_ipv6, invalid_vni, invalid_config |
| `FAILED_PRECONDITION` | gateway_unhealthy, no_available_ips |
| `RESOURCE_EXHAUSTED` | pool_exhausted, max_connections |
| `UNAUTHENTICATED` | unauthorized |
| `PERMISSION_DENIED` | forbidden |

**Go Example:**
```go
gw, err := client.GetGateway(ctx, req)
if err != nil {
    if status.Code(err) == codes.NotFound {
        // Handle gateway not found
    }
    if status.Code(err) == codes.FailedPrecondition {
        // Handle gateway unhealthy
    }
}
```

## Client Setup

```go
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    gateway "github.com/jeremyhahn/go-trusted-platform/api/sdn/gateway/v1"
)

func NewGatewayClient(addr string, tlsConfig *tls.Config) (gateway.GatewayServiceClient, error) {
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    return gateway.NewGatewayServiceClient(conn), nil
}

// Usage
client, err := NewGatewayClient("localhost:10443", tlsConfig)
if err != nil {
    return err
}

// Register gateway
gw, err := client.RegisterGateway(ctx, &gateway.RegisterGatewayRequest{
    Region:       "us-east-1",
    Ipv6Prefix:   "2602:F5BB:0001::/48",
    VtepIp:       "10.0.0.1",
    Capabilities: []string{"ipv6", "ipv4", "nat64", "load_balancer"},
})

// Promote to active
resp, err := client.PromoteGateway(ctx, &gateway.PromoteGatewayRequest{
    Id: gw.Id,
})

// Onboard device
device, err := client.OnboardDevice(ctx, &gateway.OnboardDeviceRequest{
    DeviceId:   "device-001",
    MacAddress: "aa:bb:cc:dd:ee:ff",
    VlanId:     100,
    Profile:    "standard-workstation",
})

// Create load balancer
lb, err := client.CreateLoadBalancer(ctx, &gateway.CreateLoadBalancerRequest{
    Name:      "web-frontend",
    Vip:       "2602:F5BB:0001:0100::80",
    Port:      443,
    Protocol:  gateway.PROTOCOL_TCP,
    Algorithm: gateway.ALGORITHM_ROUND_ROBIN,
    Backends: []*gateway.BackendConfig{
        {Address: "2602:F5BB:0001:0100::10", Port: 8443, Weight: 100},
    },
})
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [SDN Architecture](../architecture.md)
- [BGP Transit](../bgp/transit.md)
- [Overlay Configuration](../overlay/configuration.md)
