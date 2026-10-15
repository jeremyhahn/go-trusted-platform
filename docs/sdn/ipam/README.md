# IPAM (IP Address Management)

> **Status: REFERENCE** · Last verified: 2026-10-15
> Overview of the IPAM package.

IP Address Management service providing pool-based IP allocation with support for multiple storage backends, lease management, and distributed environments.

## Overview

The IPAM package implements a complete IP address management solution for go-trusted-platform, enabling:

- Pool-based IP allocation for IPv4 and IPv6 networks
- Automatic and specific IP address allocation
- Lease management with expiration and renewal
- Multiple storage backends (Memory, QuicBaaS, DHT)
- Bitmap allocation tracking with atomic words (memory backend)
- Allocation for the gateway's VPN clients and the VTEP records the gateway admits

## Status

| Component | Status | Description |
|-----------|--------|-------------|
| Core Allocator | Complete | Pool and allocation management interface |
| Pool Management | Complete | CRUD operations for IP pools |
| Bitmap Allocation | Complete | Atomic-word bitmap; the next free bit is found by scanning words |
| Lease Management | Complete | Expiration, renewal, inactivity timeout |
| Memory Backend | Complete | In-memory storage for development/testing |
| QuicBaaS Backend | Defect | Persistent in the QuicBaaS KV, but allocation has no compare-and-swap or retry (see below); not built with `platform_p2p` |
| DHT Backend | Complete, not wired | P2P allocation (`platform_p2p` build only); nothing calls `app.RegisterDHTIPAMBackend`, so `backend: dht` fails at start |
| Batch Operations | Memory backend only | `ipam.BatchAllocator` (`AllocateBatch`, `ReleaseBatch`) |
| Reservations | Memory backend only | `ipam.ReservationAllocator` (`Reserve`, `Unreserve`, `ListReservations`) |

## Package Structure

```
pkg/sdn/ipam/
+-- types.go              # Pool, Allocation, AllocationRequest, PoolStats
+-- allocator.go          # Allocator interface, factory, iterators
+-- pool.go               # Pool calculations, IP offset conversion
+-- bitmap.go             # Atomic-word bitmap for allocation tracking
+-- window.go             # Reserved prefixes and the dynamic window (RangeStart-RangeEnd)
+-- utils.go              # Usable-address helpers
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
| `Gateway` | Optional gateway address; always reserved |
| `Zone` | Underlay zone of a zone pool (e.g. `control-plane`); empty otherwise |
| `Reserved` | Prefixes that are never allocatable |
| `RangeStart`, `RangeEnd` | Dynamic allocation window (`Allocate`); unset = whole CIDR |
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
    "fmt"
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
    CIDR:                 netip.MustParsePrefix("192.0.2.0/24"),
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
// Reservations are an optional interface; only the memory backend has them.
var allocator ipam.Allocator = backend
reservator, ok := allocator.(ipam.ReservationAllocator)
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
- One bit per usable address; the next free address is found by scanning
  64-bit words from the window start
- Thread-safe: one `sync.RWMutex` guards the backend's maps and bitmaps
- The only backend with batch and reservation support
- Cannot hold a large IPv6 pool: the bitmap is sized from `CalculatePoolSize`
  (`pkg/sdn/ipam/backends/memory.go:120`), so a `/64` asks for 2^64 − 1 bits

The memory backend is platformd's default (`sdn.ipam.backend` empty or
`memory`, `pkg/app/sdn.go:480`).

### QuicBaaS Backend

Persistent backend over the QuicBaaS KV. It takes any `backends.QuicBaaSClient`
(`IsStarted`, `Put`, `Get`, `Delete`, `List`, `Query`); platformd adapts its
QuicBaaS SDK client to it (`pkg/app/sdn_ipam_backends.go:36`):

```go
backend, err := backends.NewQuicBaaSBackend(client, &backends.QuicBaaSBackendConfig{
    MaxRetries: 10, // 0 means 10
    Logger:     logger,
})
```

**Characteristics:**
- Persistent; replicated by the QuicBaaS store's Raft
- Name and CIDR lookups go through index entries stored beside the pools
- Built only without `platform_p2p` (`//go:build !platform_p2p`)
- **No conflict handling.** `Allocate` lists the pool's allocations, picks a
  free address and writes it with a plain `Put`; `MaxRetries` is stored but
  nothing reads it. Two nodes allocating at once can hand out the same address.

### DHT Backend (P2P)

Distributed backend for P2P environments (requires `platform_p2p` build tag):

```go
node, err := p2p.NewNode(nodeConfig) // pkg/sdn/gateway/p2p
backend, err := backends.NewDHTBackend(node, ipam.WithLogger(logger))
```

`NewDHTBackend` refuses a nil node, a node without a DHT, or one without a peer
ID (`ErrDHTBackendInit`).

**Characteristics:**
- Decentralized allocation via Kademlia DHT (keys under `/ipam/pool/`,
  `/ipam/alloc/`, `/ipam/device/`)
- Claim-based eventual consistency (`ErrClaimConflict`, `ErrVerificationFailed`)
- Random IP selection to reduce conflicts
- Local caching for pool metadata

platformd selects it with `sdn.ipam.backend: dht` only after
`app.RegisterDHTIPAMBackend(node)`; nothing calls that today, so the
placeholder factory refuses at start (`pkg/app/sdn_ipam_backends_p2p.go:38`).

## IPv4 vs IPv6 Handling

The IPAM package handles both address families:

| Aspect | IPv4 | IPv6 |
|--------|------|------|
| Pool Size (`CalculatePoolSize`) | `2^(32-prefix) - 2` (network/broadcast) | `2^(128-prefix)`, saturating at 2^64 − 1 for `/64` and wider |
| Network Address | Excluded from allocation | Included |
| Broadcast | Excluded from allocation | N/A (no broadcast) |
| Point-to-Point | /31 and /32 include all addresses | /127 and /128 include all |

`Pool.TotalIPs` is that size less the gateway and the `Reserved` prefixes.

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
    CIDR: netip.MustParsePrefix("2001:DB8:1234::/64"),  // size 2^64 − 1; not on the memory backend
}
```

## Integration Points

### SDN Gateway Integration

The gateway's VPN service leases each client's tunnel address from IPAM
(`pkg/sdn/gateway/services/vpn/admission.go:462`):

```go
alloc, err := allocator.Allocate(ctx, &ipam.AllocationRequest{
    PoolID:        pool.ID,
    DeviceID:      deviceID,
    Description:   "vpn lease",
    Tags:          []string{"vpn", "tenant:" + tenantID},
    LeaseDuration: leaseTTL,
})
```

On restart it re-claims recorded leases with `AllocateSpecific`
(`services/vpn/restore.go`). VTEP admission (`pkg/sdn/gateway/vtep_admission.go`)
only reads: it looks up platformd's fabric-zone allocations
(`GetAllocation`, `GetAllocationsByDevice`) to admit a VTEP.

### DHT Network Integration

IPAM coordinates with DHT for distributed allocation:

- Pool metadata published to DHT
- Allocation claims verified through DHT consensus
- Device-to-IP mappings stored in DHT namespace

### Overlay Network Integration

`overlay.WithIPAM` (`pkg/sdn/overlay/options.go:80`) stores an allocator on the
overlay controller, but the controller never reads it and no caller passes
one: the overlay allocates nothing from IPAM today.

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

# Create pool (--id is generated when omitted; optional --zone, --description,
# --reserved, --range-start, --range-end)
platformctl sdn ipam pool create --id prod-v4 --name prod-v4 --cidr 10.0.0.0/24 --gateway 10.0.0.1

# Allocate IP
platformctl sdn ipam allocate --pool-id prod-v4 --device-id vm-001 --hostname webserver

# Release IP
platformctl sdn ipam release --ip 10.0.0.50

# List allocations
platformctl sdn ipam allocations --pool-id prod-v4
```

## Related Documentation

- [SDN Architecture](../architecture.md) - SDN subsystem overview
- [Gateway](../../gateway/architecture.md) - the edge gateway and its IPAM surface
- [Overlay Networking](../overlay/README.md) - VXLAN overlay addressing
- [BGP](../../bgp/architecture.md) - the BGP speaker; prefix announcement is Planned (#553)

## References

- [RFC 4632 - CIDR: The Internet Address Assignment and Aggregation Plan](https://datatracker.ietf.org/doc/html/rfc4632)
- [RFC 3021 - Using 31-Bit Prefixes on Point-to-Point Links](https://datatracker.ietf.org/doc/html/rfc3021)
- [RFC 4291 - IP Version 6 Addressing Architecture](https://datatracker.ietf.org/doc/html/rfc4291)
