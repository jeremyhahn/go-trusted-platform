# IPAM gRPC API Reference

gRPC service methods for the IPAM service.

| Property | Value |
|----------|-------|
| Package | `platform.sdn.ipam.v1` |
| Port | 10443 |
| Protocol | HTTP/2 + Protobuf |

## Service Definition

```protobuf
syntax = "proto3";

package platform.sdn.ipam.v1;

option go_package = "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/ipam/v1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

// IPAMService provides IP address management operations.
service IPAMService {
  // Pool Management
  rpc CreatePool(CreatePoolRequest) returns (Pool);
  rpc GetPool(GetPoolRequest) returns (Pool);
  rpc GetPoolByName(GetPoolByNameRequest) returns (Pool);
  rpc GetPoolByCIDR(GetPoolByCIDRRequest) returns (Pool);
  rpc ListPools(ListPoolsRequest) returns (ListPoolsResponse);
  rpc UpdatePool(UpdatePoolRequest) returns (Pool);
  rpc DeletePool(DeletePoolRequest) returns (DeletePoolResponse);
  rpc GetPoolStats(GetPoolStatsRequest) returns (PoolStats);

  // Allocation Operations
  rpc Allocate(AllocationRequest) returns (Allocation);
  rpc AllocateSpecific(AllocationRequest) returns (Allocation);
  rpc Release(ReleaseRequest) returns (ReleaseResponse);
  rpc ReleaseByDeviceID(ReleaseByDeviceIDRequest) returns (ReleaseByDeviceIDResponse);

  // Lease Management
  rpc Renew(RenewRequest) returns (RenewResponse);
  rpc GetAllocation(GetAllocationRequest) returns (Allocation);
  rpc GetAllocationsByDevice(GetAllocationsByDeviceRequest) returns (GetAllocationsResponse);
  rpc GetAllocationsByPool(GetAllocationsByPoolRequest) returns (GetAllocationsResponse);
  rpc ExpireInactive(ExpireInactiveRequest) returns (ExpireInactiveResponse);

  // Reservation Operations
  rpc Reserve(ReserveRequest) returns (Allocation);
  rpc Unreserve(UnreserveRequest) returns (UnreserveResponse);
  rpc ListReservations(ListReservationsRequest) returns (GetAllocationsResponse);

  // Batch Operations
  rpc AllocateBatch(AllocateBatchRequest) returns (AllocateBatchResponse);
  rpc ReleaseBatch(ReleaseBatchRequest) returns (ReleaseBatchResponse);

  // Health
  rpc Ping(PingRequest) returns (PingResponse);
}
```

## Messages

### Pool

```protobuf
message Pool {
  string id = 1;
  string name = 2;
  string cidr = 3;
  string gateway = 4;
  string description = 5;
  repeated string tags = 6;

  uint64 total_ips = 10;
  uint64 allocated_ips = 11;
  uint64 available_ips = 12;

  google.protobuf.Duration default_lease_duration = 20;
  google.protobuf.Duration inactivity_timeout = 21;

  google.protobuf.Timestamp created_at = 30;
  google.protobuf.Timestamp updated_at = 31;
}
```

### Allocation

```protobuf
enum AllocationStatus {
  ALLOCATION_STATUS_UNSPECIFIED = 0;
  ALLOCATION_STATUS_ACTIVE = 1;
  ALLOCATION_STATUS_EXPIRED = 2;
  ALLOCATION_STATUS_RELEASED = 3;
  ALLOCATION_STATUS_RESERVED = 4;
}

message Allocation {
  string id = 1;
  string pool_id = 2;
  string ip = 3;
  string device_id = 4;
  string hostname = 5;
  string description = 6;
  repeated string tags = 7;
  map<string, string> metadata = 8;

  AllocationStatus status = 10;

  google.protobuf.Timestamp allocated_at = 20;
  google.protobuf.Timestamp last_seen = 21;
  google.protobuf.Timestamp expires_at = 22;
  google.protobuf.Timestamp released_at = 23;
}
```

### AllocationRequest

```protobuf
message AllocationRequest {
  string pool_id = 1;
  string device_id = 2;
  string hostname = 3;
  string description = 4;
  repeated string tags = 5;
  map<string, string> metadata = 6;

  // For AllocateSpecific only
  string requested_ip = 10;

  // Override pool default
  google.protobuf.Duration lease_duration = 20;
}
```

### PoolStats

```protobuf
message PoolStats {
  string pool_id = 1;
  uint64 total_ips = 2;
  uint64 allocated_ips = 3;
  uint64 available_ips = 4;
  uint64 expired_ips = 5;
  uint64 reserved_ips = 6;
  double utilization_pct = 7;
}
```

## Pool Operations

### CreatePool

Creates a new IP address pool.

```protobuf
message CreatePoolRequest {
  string id = 1;
  string name = 2;
  string cidr = 3;
  string gateway = 4;
  string description = 5;
  repeated string tags = 6;
  google.protobuf.Duration default_lease_duration = 7;
  google.protobuf.Duration inactivity_timeout = 8;
}
```

**Example:**
```go
req := &ipamv1.CreatePoolRequest{
    Id:                   "prod-v4",
    Name:                 "Production IPv4",
    Cidr:                 "10.0.0.0/24",
    Gateway:              "10.0.0.1",
    Description:          "Internal production workloads",
    Tags:                 []string{"production", "internal"},
    DefaultLeaseDuration: durationpb.New(24 * time.Hour),
    InactivityTimeout:    durationpb.New(30 * 24 * time.Hour),
}

pool, err := client.CreatePool(ctx, req)
```

### GetPool

Retrieves a pool by ID.

```protobuf
message GetPoolRequest {
  string pool_id = 1;
}
```

### GetPoolByName

Retrieves a pool by name.

```protobuf
message GetPoolByNameRequest {
  string name = 1;
}
```

### GetPoolByCIDR

Retrieves a pool by CIDR.

```protobuf
message GetPoolByCIDRRequest {
  string cidr = 1;
}
```

### ListPools

Lists all pools with optional filtering.

```protobuf
message ListPoolsRequest {
  string tag = 1;              // Filter by tag
  int32 page_size = 10;        // Max results
  string page_token = 11;      // Pagination token
}

message ListPoolsResponse {
  repeated Pool pools = 1;
  int32 total = 2;
  string next_page_token = 3;
}
```

### UpdatePool

Updates an existing pool.

```protobuf
message UpdatePoolRequest {
  string id = 1;
  string name = 2;
  string description = 3;
  repeated string tags = 4;
  google.protobuf.Duration default_lease_duration = 5;
  google.protobuf.Duration inactivity_timeout = 6;
}
```

**Note:** CIDR cannot be changed after pool creation.

### DeletePool

Deletes a pool.

```protobuf
message DeletePoolRequest {
  string pool_id = 1;
}

message DeletePoolResponse {
  bool deleted = 1;
  string pool_id = 2;
}
```

### GetPoolStats

Gets pool statistics.

```protobuf
message GetPoolStatsRequest {
  string pool_id = 1;
}
```

## Allocation Operations

### Allocate

Allocates the next available IP from a pool.

```go
req := &ipamv1.AllocationRequest{
    PoolId:        "prod-v4",
    DeviceId:      "vm-001",
    Hostname:      "webserver",
    Description:   "Primary web server",
    Tags:          []string{"web", "frontend"},
    Metadata:      map[string]string{"environment": "production"},
    LeaseDuration: durationpb.New(48 * time.Hour),
}

alloc, err := client.Allocate(ctx, req)
fmt.Printf("Allocated IP: %s\n", alloc.Ip)
```

### AllocateSpecific

Allocates a specific IP address.

```go
req := &ipamv1.AllocationRequest{
    PoolId:      "prod-v4",
    DeviceId:    "db-001",
    Hostname:    "database",
    RequestedIp: "10.0.0.100",
}

alloc, err := client.AllocateSpecific(ctx, req)
```

### Release

Releases an IP allocation.

```protobuf
message ReleaseRequest {
  string ip = 1;
}

message ReleaseResponse {
  bool released = 1;
  string ip = 2;
  string pool_id = 3;
  string device_id = 4;
}
```

### ReleaseByDeviceID

Releases all allocations for a device.

```protobuf
message ReleaseByDeviceIDRequest {
  string device_id = 1;
}

message ReleaseByDeviceIDResponse {
  string device_id = 1;
  int32 released_count = 2;
  repeated string released_ips = 3;
}
```

## Lease Operations

### Renew

Renews an allocation lease.

```protobuf
message RenewRequest {
  string ip = 1;
}

message RenewResponse {
  string ip = 1;
  bool renewed = 2;
  google.protobuf.Timestamp last_seen = 3;
  google.protobuf.Timestamp expires_at = 4;
}
```

### GetAllocation

Gets an allocation by IP address.

```protobuf
message GetAllocationRequest {
  string ip = 1;
}
```

### GetAllocationsByDevice

Gets all allocations for a device.

```protobuf
message GetAllocationsByDeviceRequest {
  string device_id = 1;
  int32 page_size = 10;
  string page_token = 11;
}

message GetAllocationsResponse {
  repeated Allocation allocations = 1;
  int32 total = 2;
  string next_page_token = 3;
}
```

### GetAllocationsByPool

Gets all allocations in a pool.

```protobuf
message GetAllocationsByPoolRequest {
  string pool_id = 1;
  AllocationStatus status = 2;  // Optional filter
  int32 page_size = 10;
  string page_token = 11;
}
```

### ExpireInactive

Expires inactive allocations in a pool.

```protobuf
message ExpireInactiveRequest {
  string pool_id = 1;
}

message ExpireInactiveResponse {
  string pool_id = 1;
  int32 expired_count = 2;
  repeated Allocation expired_allocations = 3;
}
```

## Reservation Operations

### Reserve

Reserves an IP address.

```protobuf
message ReserveRequest {
  string pool_id = 1;
  string ip = 2;
  string description = 3;
}
```

### Unreserve

Removes a reservation.

```protobuf
message UnreserveRequest {
  string ip = 1;
}

message UnreserveResponse {
  string ip = 1;
  bool unreserved = 2;
  string pool_id = 3;
}
```

### ListReservations

Lists reservations in a pool.

```protobuf
message ListReservationsRequest {
  string pool_id = 1;
  int32 page_size = 10;
  string page_token = 11;
}
```

## Batch Operations

### AllocateBatch

Allocates multiple IPs in a single operation.

```protobuf
message AllocateBatchRequest {
  repeated AllocationRequest requests = 1;
}

message AllocateBatchResponse {
  repeated Allocation allocations = 1;
  int32 total_requested = 2;
  int32 total_allocated = 3;
  repeated string failed_device_ids = 4;
}
```

### ReleaseBatch

Releases multiple IPs in a single operation.

```protobuf
message ReleaseBatchRequest {
  repeated string ips = 1;
}

message ReleaseBatchResponse {
  int32 total_requested = 1;
  int32 total_released = 2;
  repeated string released_ips = 3;
  repeated string failed_ips = 4;
}
```

## Health

### Ping

Checks backend health.

```protobuf
message PingRequest {}

message PingResponse {
  bool healthy = 1;
  string backend = 2;
  google.protobuf.Timestamp timestamp = 3;
}
```

## Error Handling

gRPC errors use standard status codes with IPAM-specific details.

### Status Codes

| Code | Condition |
|------|-----------|
| `OK` | Success |
| `INVALID_ARGUMENT` | Invalid request parameters |
| `NOT_FOUND` | Pool or allocation not found |
| `ALREADY_EXISTS` | Pool or allocation already exists |
| `RESOURCE_EXHAUSTED` | Pool exhausted, no available IPs |
| `FAILED_PRECONDITION` | Operation not allowed (e.g., delete pool with allocations) |
| `UNAVAILABLE` | Backend unavailable |
| `INTERNAL` | Internal error |

### Error Details

```go
// Check for specific error
st, ok := status.FromError(err)
if ok {
    switch st.Code() {
    case codes.NotFound:
        // Handle not found
    case codes.AlreadyExists:
        // Handle conflict
    case codes.ResourceExhausted:
        // Handle pool exhausted
    }

    // Get error details
    for _, detail := range st.Details() {
        switch t := detail.(type) {
        case *errdetails.BadRequest:
            // Field-level validation errors
        case *errdetails.ResourceInfo:
            // Resource details (pool_id, ip, etc.)
        }
    }
}
```

## Client Example

```go
package main

import (
    "context"
    "log"
    "time"

    ipamv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/ipam/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/protobuf/types/known/durationpb"
)

func main() {
    // Load TLS credentials
    creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
    if err != nil {
        log.Fatal(err)
    }

    // Connect
    conn, err := grpc.Dial("platform.example.com:10443",
        grpc.WithTransportCredentials(creds),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := ipamv1.NewIPAMServiceClient(conn)
    ctx := context.Background()

    // Create pool
    pool, err := client.CreatePool(ctx, &ipamv1.CreatePoolRequest{
        Id:                   "example-pool",
        Name:                 "Example Pool",
        Cidr:                 "10.100.0.0/24",
        Gateway:              "10.100.0.1",
        DefaultLeaseDuration: durationpb.New(24 * time.Hour),
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Created pool: %s (%d IPs)", pool.Name, pool.TotalIps)

    // Allocate IP
    alloc, err := client.Allocate(ctx, &ipamv1.AllocationRequest{
        PoolId:   "example-pool",
        DeviceId: "my-device",
        Hostname: "myserver",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Allocated: %s", alloc.Ip)

    // Get pool stats
    stats, err := client.GetPoolStats(ctx, &ipamv1.GetPoolStatsRequest{
        PoolId: "example-pool",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Pool utilization: %.2f%%", stats.UtilizationPct)

    // Renew lease
    _, err = client.Renew(ctx, &ipamv1.RenewRequest{
        Ip: alloc.Ip,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Lease renewed for %s", alloc.Ip)

    // Release
    _, err = client.Release(ctx, &ipamv1.ReleaseRequest{
        Ip: alloc.Ip,
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Released: %s", alloc.Ip)
}
```

## Streaming (Future)

Future versions may support streaming for:

```protobuf
// Watch allocation changes
rpc WatchAllocations(WatchAllocationsRequest) returns (stream AllocationEvent);

// Stream pool stats
rpc StreamPoolStats(StreamPoolStatsRequest) returns (stream PoolStats);
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [API Overview](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
