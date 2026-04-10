# DHCP gRPC API Reference

gRPC service definition for the DHCP service.

| Property | Value |
|----------|-------|
| Service | `dhcp.DHCPService` |
| Port | 10443 |
| Transport | TCP with TLS |

## Service Definition

```protobuf
syntax = "proto3";
package dhcp;

import "google/protobuf/empty.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

service DHCPService {
  // Status operations
  rpc GetStatus(GetStatusRequest) returns (DHCPStatus);
  rpc GetStats(GetStatsRequest) returns (ServerStats);

  // Lease operations
  rpc GetLease(GetLeaseRequest) returns (Lease);
  rpc GetLeaseByIP(GetLeaseByIPRequest) returns (Lease);
  rpc ListLeases(ListLeasesRequest) returns (ListLeasesResponse);
  rpc ReleaseLease(ReleaseLeaseRequest) returns (google.protobuf.Empty);
  rpc ExpireLeases(ExpireLeasesRequest) returns (ExpireLeasesResponse);

  // Interface operations
  rpc ListInterfaces(ListInterfacesRequest) returns (ListInterfacesResponse);
  rpc GetInterface(GetInterfaceRequest) returns (InterfaceInfo);
  rpc UpdateInterfaceOptions(UpdateInterfaceOptionsRequest) returns (InterfaceInfo);

  // Pool operations
  rpc GetPoolStats(GetPoolStatsRequest) returns (PoolStats);

  // Streaming operations
  rpc WatchLeases(WatchLeasesRequest) returns (stream LeaseEvent);
}
```

## Status Operations

### GetStatus

Returns the current DHCP server status.

```protobuf
message GetStatusRequest {}

message DHCPStatus {
  bool running = 1;
  repeated InterfaceStatus interfaces = 2;
  string ipam_backend = 3;
  uint64 uptime_seconds = 4;
}

message InterfaceStatus {
  string name = 1;
  string address = 2;
  string pool_id = 3;
  string network = 4;
}
```

**Go Example:**
```go
status, err := client.GetStatus(ctx, &dhcp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("DHCP Server Running: %v, Interfaces: %d\n",
    status.Running, len(status.Interfaces))
```

### GetStats

Returns server statistics.

```protobuf
message GetStatsRequest {}

message ServerStats {
  google.protobuf.Timestamp started_at = 1;
  uint64 packets_received = 2;
  uint64 packets_sent = 3;
  uint64 discover_count = 4;
  uint64 offer_count = 5;
  uint64 request_count = 6;
  uint64 ack_count = 7;
  uint64 nak_count = 8;
  uint64 release_count = 9;
  uint64 decline_count = 10;
  uint64 inform_count = 11;
  uint64 error_count = 12;
  int32 active_leases = 13;
}
```

**Go Example:**
```go
stats, err := client.GetStats(ctx, &dhcp.GetStatsRequest{})
if err != nil {
    return err
}
fmt.Printf("Active Leases: %d, Packets: %d/%d (rx/tx)\n",
    stats.ActiveLeases, stats.PacketsReceived, stats.PacketsSent)
```

## Lease Operations

### GetLease

Retrieves a lease by MAC address.

```protobuf
message GetLeaseRequest {
  string mac = 1;  // MAC address in colon-separated format
}

message Lease {
  string ip = 1;
  string mac = 2;
  string hostname = 3;
  string pool_id = 4;
  string interface = 5;
  bytes client_id = 6;
  string vendor_class = 7;
  string user_class = 8;
  google.protobuf.Timestamp leased_at = 9;
  google.protobuf.Timestamp expires_at = 10;
  google.protobuf.Timestamp renewed_at = 11;
  LeaseState state = 12;
  int64 time_remaining_seconds = 13;
}

enum LeaseState {
  LEASE_STATE_UNKNOWN = 0;
  LEASE_STATE_ACTIVE = 1;
  LEASE_STATE_EXPIRED = 2;
  LEASE_STATE_RELEASED = 3;
  LEASE_STATE_DECLINED = 4;
}
```

**Go Example:**
```go
lease, err := client.GetLease(ctx, &dhcp.GetLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})
if err != nil {
    if status.Code(err) == codes.NotFound {
        fmt.Println("Lease not found")
        return nil
    }
    return err
}
fmt.Printf("Lease: %s -> %s (expires: %v)\n",
    lease.Mac, lease.Ip, lease.ExpiresAt.AsTime())
```

### GetLeaseByIP

Retrieves a lease by IP address.

```protobuf
message GetLeaseByIPRequest {
  string ip = 1;  // IP address
}
```

**Go Example:**
```go
lease, err := client.GetLeaseByIP(ctx, &dhcp.GetLeaseByIPRequest{
    Ip: "192.168.1.100",
})
```

### ListLeases

Lists all active leases with optional filtering.

```protobuf
message ListLeasesRequest {
  string pool_id = 1;     // Filter by pool ID
  string interface = 2;   // Filter by interface
  LeaseState state = 3;   // Filter by state
  uint32 limit = 4;       // Max results (default 100)
  uint32 offset = 5;      // Pagination offset
}

message ListLeasesResponse {
  repeated Lease leases = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

**Go Example:**
```go
resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
    PoolId: "internal-pool",
    State:  dhcp.LEASE_STATE_ACTIVE,
    Limit:  50,
})
if err != nil {
    return err
}
for _, lease := range resp.Leases {
    fmt.Printf("%s -> %s (%s)\n", lease.Mac, lease.Ip, lease.Hostname)
}
```

### ReleaseLease

Releases a lease by MAC address.

```protobuf
message ReleaseLeaseRequest {
  string mac = 1;
}
```

**Go Example:**
```go
_, err := client.ReleaseLease(ctx, &dhcp.ReleaseLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})
if err != nil {
    return err
}
fmt.Println("Lease released")
```

### ExpireLeases

Manually triggers expiration of old leases.

```protobuf
message ExpireLeasesRequest {}

message ExpireLeasesResponse {
  int32 expired_count = 1;
  int32 active_leases = 2;
}
```

**Go Example:**
```go
resp, err := client.ExpireLeases(ctx, &dhcp.ExpireLeasesRequest{})
if err != nil {
    return err
}
fmt.Printf("Expired %d leases, %d active\n",
    resp.ExpiredCount, resp.ActiveLeases)
```

## Interface Operations

### ListInterfaces

Lists all configured DHCP interfaces.

```protobuf
message ListInterfacesRequest {}

message ListInterfacesResponse {
  repeated InterfaceInfo interfaces = 1;
}

message InterfaceInfo {
  string name = 1;
  string network = 2;
  string address = 3;
  string pool_id = 4;
  DHCPOptions options = 5;
  int32 active_leases = 6;
}

message DHCPOptions {
  string subnet_mask = 1;
  string router = 2;
  repeated string dns = 3;
  string domain_name = 4;
  int64 lease_time_seconds = 5;
  int64 renewal_time_seconds = 6;
  int64 rebind_time_seconds = 7;
  repeated string ntp_servers = 8;
  uint32 mtu = 9;
  string hostname = 10;
}
```

**Go Example:**
```go
resp, err := client.ListInterfaces(ctx, &dhcp.ListInterfacesRequest{})
if err != nil {
    return err
}
for _, iface := range resp.Interfaces {
    fmt.Printf("Interface: %s, Pool: %s, Active: %d\n",
        iface.Name, iface.PoolId, iface.ActiveLeases)
}
```

### GetInterface

Gets details for a specific interface.

```protobuf
message GetInterfaceRequest {
  string name = 1;
}
```

**Go Example:**
```go
iface, err := client.GetInterface(ctx, &dhcp.GetInterfaceRequest{
    Name: "eth0",
})
if err != nil {
    return err
}
fmt.Printf("Interface %s: %s (pool: %s)\n",
    iface.Name, iface.Address, iface.PoolId)
```

### UpdateInterfaceOptions

Updates DHCP options for an interface.

```protobuf
message UpdateInterfaceOptionsRequest {
  string name = 1;
  DHCPOptionsUpdate options = 2;
}

message DHCPOptionsUpdate {
  repeated string dns = 1;
  string domain_name = 2;
  int64 lease_time_seconds = 3;
  int64 renewal_time_seconds = 4;
  int64 rebind_time_seconds = 5;
  repeated string ntp_servers = 6;
  uint32 mtu = 7;
}
```

**Go Example:**
```go
iface, err := client.UpdateInterfaceOptions(ctx, &dhcp.UpdateInterfaceOptionsRequest{
    Name: "eth0",
    Options: &dhcp.DHCPOptionsUpdate{
        Dns:             []string{"1.1.1.1", "8.8.8.8"},
        DomainName:      "newdomain.local",
        LeaseTimeSeconds: 43200,
    },
})
if err != nil {
    return err
}
fmt.Printf("Updated interface %s options\n", iface.Name)
```

## Pool Operations

### GetPoolStats

Gets statistics for an IPAM pool.

```protobuf
message GetPoolStatsRequest {
  string pool_id = 1;
}

message PoolStats {
  string pool_id = 1;
  int32 total_addresses = 2;
  int32 allocated = 3;
  int32 available = 4;
  float utilization_percent = 5;
  map<string, int32> leases_by_state = 6;
}
```

**Go Example:**
```go
stats, err := client.GetPoolStats(ctx, &dhcp.GetPoolStatsRequest{
    PoolId: "internal-pool",
})
if err != nil {
    return err
}
fmt.Printf("Pool %s: %d/%d used (%.1f%%)\n",
    stats.PoolId, stats.Allocated, stats.TotalAddresses, stats.UtilizationPercent)
```

## Streaming Operations

### WatchLeases

Streams lease events in real-time.

```protobuf
message WatchLeasesRequest {
  string pool_id = 1;        // Optional: filter by pool
  string interface = 2;      // Optional: filter by interface
  bool include_initial = 3;  // Include current leases as initial events
}

message LeaseEvent {
  LeaseEventType type = 1;
  Lease lease = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum LeaseEventType {
  LEASE_EVENT_UNKNOWN = 0;
  LEASE_EVENT_CREATED = 1;
  LEASE_EVENT_RENEWED = 2;
  LEASE_EVENT_RELEASED = 3;
  LEASE_EVENT_EXPIRED = 4;
  LEASE_EVENT_DECLINED = 5;
}
```

**Go Example:**
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
        log.Printf("New lease: %s -> %s", event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_RENEWED:
        log.Printf("Renewed: %s -> %s", event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_RELEASED:
        log.Printf("Released: %s", event.Lease.Mac)
    case dhcp.LEASE_EVENT_EXPIRED:
        log.Printf("Expired: %s -> %s", event.Lease.Mac, event.Lease.Ip)
    case dhcp.LEASE_EVENT_DECLINED:
        log.Printf("Declined: %s -> %s", event.Lease.Mac, event.Lease.Ip)
    }
}
```

## Error Handling

gRPC status codes map to DHCP errors:

| gRPC Code | DHCP Error |
|-----------|-----------|
| `NOT_FOUND` | lease_not_found, interface_not_found, pool_not_found |
| `INVALID_ARGUMENT` | invalid_mac, invalid_ip, validation_error |
| `FAILED_PRECONDITION` | lease_expired |
| `UNAVAILABLE` | server_not_running |
| `RESOURCE_EXHAUSTED` | pool_exhausted |
| `UNAUTHENTICATED` | unauthorized |
| `PERMISSION_DENIED` | forbidden |

**Go Example:**
```go
lease, err := client.GetLease(ctx, req)
if err != nil {
    if status.Code(err) == codes.NotFound {
        // Handle lease not found
        return nil
    }
    if status.Code(err) == codes.InvalidArgument {
        // Handle invalid MAC format
        return fmt.Errorf("invalid MAC: %w", err)
    }
    return err
}
```

## Client Setup

```go
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    dhcp "github.com/jeremyhahn/go-trusted-platform/api/sdn/dhcp/v1"
)

func NewDHCPClient(addr string, tlsConfig *tls.Config) (dhcp.DHCPServiceClient, error) {
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    return dhcp.NewDHCPServiceClient(conn), nil
}

// Usage
client, err := NewDHCPClient("localhost:10443", tlsConfig)
if err != nil {
    return err
}

// Get status
status, err := client.GetStatus(ctx, &dhcp.GetStatusRequest{})
if err != nil {
    return err
}

// List leases
resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
    Limit: 100,
})
if err != nil {
    return err
}

// Get specific lease
lease, err := client.GetLease(ctx, &dhcp.GetLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})

// Release lease
_, err = client.ReleaseLease(ctx, &dhcp.ReleaseLeaseRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
})

// Watch lease events
stream, err := client.WatchLeases(ctx, &dhcp.WatchLeasesRequest{
    IncludeInitial: true,
})
for {
    event, err := stream.Recv()
    if err != nil {
        break
    }
    fmt.Printf("Event: %s for %s\n", event.Type, event.Lease.Mac)
}
```

## Complete Example

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/status"
    "google.golang.org/grpc/codes"

    dhcp "github.com/jeremyhahn/go-trusted-platform/api/sdn/dhcp/v1"
)

func main() {
    // Load TLS credentials
    cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
    if err != nil {
        log.Fatal(err)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    // Connect to server
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial("localhost:10443", grpc.WithTransportCredentials(creds))
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
    fmt.Printf("Server running: %v\n", status.Running)

    // List all leases
    resp, err := client.ListLeases(ctx, &dhcp.ListLeasesRequest{
        Limit: 10,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d leases:\n", resp.Total)
    for _, lease := range resp.Leases {
        fmt.Printf("  %s -> %s (%s)\n", lease.Mac, lease.Ip, lease.State)
    }

    // Get specific lease
    lease, err := client.GetLease(ctx, &dhcp.GetLeaseRequest{
        Mac: "aa:bb:cc:dd:ee:ff",
    })
    if err != nil {
        if status.Code(err) == codes.NotFound {
            fmt.Println("Lease not found")
        } else {
            log.Fatal(err)
        }
    } else {
        fmt.Printf("Found lease: %s -> %s\n", lease.Mac, lease.Ip)
    }

    // Get pool statistics
    poolStats, err := client.GetPoolStats(ctx, &dhcp.GetPoolStatsRequest{
        PoolId: "internal-pool",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Pool utilization: %.1f%%\n", poolStats.UtilizationPercent)
}
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [API Overview](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
