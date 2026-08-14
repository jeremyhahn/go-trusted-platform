# IPAM (IP Address Management)

IP Address Management service providing pool-based IP allocation with support for multiple storage backends, lease management, and distributed environments.

## Overview

The IPAM package implements a complete IP address management solution for go-trusted-platform, enabling:

- Pool-based IP allocation for IPv4 and IPv6 networks
- Automatic and specific IP address allocation
- Lease management with expiration and renewal
- Multiple storage backends (Memory, QuicBaaS, DHT)
- Lock-free concurrent allocation using bitmap tracking
- Integration with SDN overlay and gateway components

## Status

| Component | Status | Description |
|-----------|--------|-------------|
| Core Allocator | Complete | Pool and allocation management interface |
| Pool Management | Complete | CRUD operations for IP pools |
| Bitmap Allocation | Complete | Lock-free O(1) allocation tracking |
| Lease Management | Complete | Expiration, renewal, inactivity timeout |
| Memory Backend | Complete | In-memory storage for development/testing |
| QuicBaaS Backend | Complete | Raft-based distributed storage |
| DHT Backend | Complete | P2P distributed allocation (platform_p2p build) |
| Batch Operations | Complete | Bulk allocation and release |
| Reservations | Complete | IP reservation support |

## Package Structure

```
pkg/sdn/ipam/
+-- types.go              # Pool, Allocation, AllocationRequest, PoolStats
+-- allocator.go          # Allocator interface, factory, iterators
+-- pool.go               # Pool calculations, IP offset conversion
+-- bitmap.go             # Lock-free bitmap for allocation tracking
+-- errors.go             # Typed errors for IPAM operations
+-- backends/
    +-- memory.go         # In-memory backend (testing/development)
    +-- quicbaas.go       # QuicBaaS backend (production)
    +-- dht.go            # DHT backend (P2P environments)
    +-- errors.go         # Backend-specific errors
```

## Key Concepts

### Pools

An IP pool defines an allocatable address space:

| Field | Description |
|-------|-------------|
| `ID` | Unique identifier for the pool |
| `Name` | Human-readable pool name |
| `CIDR` | Network prefix (e.g., `10.0.0.0/24`) |
| `Gateway` | Optional gateway address |
| `DefaultLeaseDuration` | Default allocation lease time |
| `InactivityTimeout` | Time before inactive allocations expire |

### Allocations

An allocation represents an IP address assigned to a device:

| Field | Description |
|-------|-------------|
| `ID` | Unique allocation identifier |
| `PoolID` | Parent pool ID |
| `IP` | Allocated IP address |
| `DeviceID` | Device holding the allocation |
| `Status` | active, expired, released, reserved |
| `ExpiresAt` | Lease expiration time |
| `LastSeen` | Last activity timestamp |

### Allocation Status

| Status | Description |
|--------|-------------|
| `active` | Currently in use |
| `expired` | Lease expired or inactive |
| `released` | Explicitly released by device |
| `reserved` | Reserved, cannot be auto-allocated |

## Quick Start

### Basic Usage

```go
import (
    "context"
    "net/netip"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// Create memory backend for development
backend := backends.NewMemoryBackend()

// Create a pool
pool := &ipam.Pool{
    ID:      "prod-v4",
    Name:    "Production IPv4",
    CIDR:    netip.MustParsePrefix("10.0.0.0/24"),
    Gateway: netip.MustParseAddr("10.0.0.1"),
}

ctx := context.Background()
if err := backend.CreatePool(ctx, pool); err != nil {
    return err
}

// Allocate an IP
req := &ipam.AllocationRequest{
    PoolID:   "prod-v4",
    DeviceID: "vm-001",
    Hostname: "webserver",
}

alloc, err := backend.Allocate(ctx, req)
if err != nil {
    return err
}

fmt.Printf("Allocated: %s\n", alloc.IP)  // e.g., 10.0.0.2
```

### Specific IP Allocation

```go
// Request a specific IP address
req := &ipam.AllocationRequest{
    PoolID:      "prod-v4",
    DeviceID:    "db-001",
    RequestedIP: netip.MustParseAddr("10.0.0.100"),
    Hostname:    "database",
}

alloc, err := backend.AllocateSpecific(ctx, req)
if err != nil {
    if errors.Is(err, ipam.ErrIPAlreadyAllocated) {
        // IP is already in use
    }
    return err
}
```

### Lease Management

```go
// Create pool with lease duration
pool := &ipam.Pool{
    ID:                   "dhcp-pool",
    Name:                 "DHCP Pool",
    CIDR:                 netip.MustParsePrefix("192.168.1.0/24"),
    DefaultLeaseDuration: 24 * time.Hour,
    InactivityTimeout:    7 * 24 * time.Hour,
}

// Renew a lease
if err := backend.Renew(ctx, allocatedIP); err != nil {
    return err
}

// Expire inactive allocations
expired, err := backend.ExpireInactive(ctx, "dhcp-pool")
if err != nil {
    return err
}
fmt.Printf("Expired %d allocations\n", len(expired))
```

### IP Reservation

```go
// Cast to ReservationAllocator for reservation support
reservator, ok := backend.(ipam.ReservationAllocator)
if !ok {
    return errors.New("backend does not support reservations")
}

// Reserve an IP (prevents automatic allocation)
err := reservator.Reserve(ctx, "prod-v4",
    netip.MustParseAddr("10.0.0.200"),
    "Reserved for future load balancer")
if err != nil {
    return err
}

// List reservations
reserved, err := reservator.ListReservations(ctx, "prod-v4")
for _, r := range reserved {
    fmt.Printf("Reserved: %s - %s\n", r.IP, r.Description)
}
```

## Storage Backends

### Memory Backend

In-memory storage for development and testing:

```go
backend := backends.NewMemoryBackend()
```

**Characteristics:**
- No persistence (data lost on restart)
- Fast allocation (O(1) with bitmap)
- Thread-safe with mutex protection
- Supports all IPAM features

### QuicBaaS Backend

Production backend using QuicBaaS for distributed, consistent storage:

```go
client := quicbaas.NewClient(config)
backend, err := backends.NewQuicBaaSBackend(client, &backends.QuicBaaSBackendConfig{
    MaxRetries: 10,
    Logger:     logger,
})
```

**Characteristics:**
- Persistent storage via Raft consensus
- Strongly consistent across nodes
- Automatic retry on conflicts
- Secondary indexes for name/CIDR lookup

### DHT Backend (P2P)

Distributed backend for P2P environments (requires `platform_p2p` build tag):

```go
node := p2p.NewNode(config)
backend, err := backends.NewDHTBackend(node)
```

**Characteristics:**
- Decentralized allocation via Kademlia DHT
- Claim-based eventual consistency
- Random IP selection to reduce conflicts
- Local caching for pool metadata

## IPv4 vs IPv6 Handling

The IPAM package handles both address families:

| Aspect | IPv4 | IPv6 |
|--------|------|------|
| Pool Size | `2^(32-prefix) - 2` (network/broadcast) | `2^(128-prefix)` |
| Network Address | Excluded from allocation | Included |
| Broadcast | Excluded from allocation | N/A (no broadcast) |
| Point-to-Point | /31 and /32 include all addresses | /127 and /128 include all |

```go
// IPv4 pool
ipv4Pool := &ipam.Pool{
    ID:   "v4-pool",
    Name: "IPv4 Network",
    CIDR: netip.MustParsePrefix("10.0.0.0/24"),  // 254 usable IPs
}

// IPv6 pool
ipv6Pool := &ipam.Pool{
    ID:   "v6-pool",
    Name: "IPv6 Network",
    CIDR: netip.MustParsePrefix("2602:F5BB:1234::/64"),  // 2^64 IPs
}
```

## Integration Points

### SDN Gateway Integration

IPAM provides IP allocation for edge gateway mode:

```go
// Gateway allocates IP for onboarding device
alloc, err := ipam.Allocate(ctx, &ipam.AllocationRequest{
    PoolID:   "edge-ipv6",
    DeviceID: device.PeerID,
    Hostname: device.Hostname,
    Metadata: map[string]string{
        "onboarded_at": time.Now().Format(time.RFC3339),
        "vtep_ip":      vtepIP.String(),
    },
})
```

### DHT Network Integration

IPAM coordinates with DHT for distributed allocation:

- Pool metadata published to DHT
- Allocation claims verified through DHT consensus
- Device-to-IP mappings stored in DHT namespace

### Overlay Network Integration

IPAM provides addressing for VXLAN overlay networks:

- Allocates IP addresses for VTEP endpoints
- Coordinates with EVPN for MAC/IP advertisement
- Supports tenant-specific pools via tags

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Technical architecture and component design |
| [Configuration](configuration.md) | Configuration reference and examples |
| [API Reference](api-reference.md) | API overview and protocol links |
| [REST API](api-reference-rest.md) | REST endpoint documentation |
| [gRPC API](api-reference-grpc.md) | gRPC service methods |

## CLI Usage

See [SDN CLI Usage](../cli-usage.md) for complete IPAM CLI commands:

```bash
# List pools
platformctl sdn ipam pool list

# Create pool
platformctl sdn ipam pool create --name prod-v4 --cidr 10.0.0.0/24 --gateway 10.0.0.1

# Allocate IP
platformctl sdn ipam allocate --pool-id prod-v4 --device-id vm-001 --hostname webserver

# Release IP
platformctl sdn ipam release --ip 10.0.0.50

# List allocations
platformctl sdn ipam allocations --pool-id prod-v4
```

## Related Documentation

- [SDN Architecture](../architecture.md) - SDN subsystem overview
- [Gateway Edge Mode](../gateway/edge-mode.md) - Edge gateway IPAM integration
- [Overlay Networking](../overlay/README.md) - VXLAN overlay addressing
- [BGP Transit](../bgp/transit.md) - IP prefix announcement

## References

- [RFC 4632 - CIDR: The Internet Address Assignment and Aggregation Plan](https://datatracker.ietf.org/doc/html/rfc4632)
- [RFC 3021 - Using 31-Bit Prefixes on Point-to-Point Links](https://datatracker.ietf.org/doc/html/rfc3021)
- [RFC 4291 - IP Version 6 Addressing Architecture](https://datatracker.ietf.org/doc/html/rfc4291)
