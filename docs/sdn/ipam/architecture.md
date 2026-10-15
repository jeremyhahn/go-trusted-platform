# IPAM Architecture

> **Status: REFERENCE** · Last verified: 2026-10-15
> The IPAM package's pools, allocators and storage.

## Overview

The IPAM package implements a pool-based IP address management system with pluggable storage backends, lock-free allocation tracking, and support for distributed environments. The architecture prioritizes consistency, performance, and operational flexibility.

## Component Architecture

```
+------------------------------------------------------------------+
|                          IPAM Service                              |
+------------------------------------------------------------------+
|                                                                    |
|  +--------------------+    +--------------------+                 |
|  |   Allocator API    |    |   Pool Manager     |                 |
|  |   (Interface)      |    |   (Calculations)   |                 |
|  +--------+-----------+    +--------+-----------+                 |
|           |                         |                              |
|           +------------+------------+                              |
|                        |                                           |
|           +------------v------------+                              |
|           |    Backend Abstraction  |                              |
|           +------------+------------+                              |
|                        |                                           |
|     +------------------+------------------+                        |
|     |                  |                  |                        |
| +---v----+       +-----v----+       +-----v----+                  |
| | Memory |       | QuicBaaS |       |   DHT    |                  |
| | Backend|       | Backend  |       | Backend  |                  |
| +--------+       +----------+       +----------+                  |
|                        |                  |                        |
|                  +-----v-----+      +-----v-----+                  |
|                  | QuicBaaS  |      | libp2p    |                  |
|                  | Cluster   |      | Kademlia  |                  |
|                  +-----------+      +-----------+                  |
+------------------------------------------------------------------+
```

## Allocator Interface

The `Allocator` interface defines the contract for all IPAM operations:

```go
type Allocator interface {
    // Pool Management
    CreatePool(ctx context.Context, pool *Pool) error
    GetPool(ctx context.Context, poolID string) (*Pool, error)
    GetPoolByName(ctx context.Context, name string) (*Pool, error)
    GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*Pool, error)
    ListPools(ctx context.Context) ([]*Pool, error)
    UpdatePool(ctx context.Context, pool *Pool) error
    DeletePool(ctx context.Context, poolID string) error
    GetPoolStats(ctx context.Context, poolID string) (*PoolStats, error)

    // Allocation Operations
    Allocate(ctx context.Context, req *AllocationRequest) (*Allocation, error)
    AllocateSpecific(ctx context.Context, req *AllocationRequest) (*Allocation, error)
    Release(ctx context.Context, ip netip.Addr) error
    ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error)

    // Lease Management
    Renew(ctx context.Context, ip netip.Addr) error
    GetAllocation(ctx context.Context, ip netip.Addr) (*Allocation, error)
    GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*Allocation, error)
    GetAllocationsByPool(ctx context.Context, poolID string) ([]*Allocation, error)
    ExpireInactive(ctx context.Context, poolID string) ([]*Allocation, error)

    // Zone Queries
    ListPoolsByZone(ctx context.Context, zone string) ([]*Pool, error)

    // Health and Lifecycle
    Ping(ctx context.Context) error
    Close() error
}
```

### Zone Integration

Pools carry a `Zone string` field that links them to the platform's SDN zone topology. Allocations inherit the zone from their pool at allocation time so callers can determine the security segment without a second lookup.

```
Pool.Zone ───────────────────────────────────────────────► Allocation.Zone
(the zone of a plan-derived zone pool, or an explicit pool's)   (stamped on Allocate)
```

Zone pools are derived from the network plan (`pkg/sdn/netplan`), one per
underlay zone, so their zone is always declared. An explicit pool in
`sdn.ipam.pools` with a zone not in the resolved set fails
`sdn.Config.Validate()` with `ErrPoolZoneUndeclared`.

### Allocation Window

Every pool has an allocation window, shared by all backends through
`pkg/sdn/ipam/window.go`:

- `Reserved` prefixes and the pool `Gateway` are never allocatable.
  `Allocate` skips them a whole reserved prefix at a time;
  `AllocateSpecific` refuses them with the typed `*ErrIPReserved`.
- `RangeStart`/`RangeEnd` bound `Allocate` (`Pool.DynamicOffsets`). Unset
  means the whole usable CIDR. `AllocateSpecific` may take a static address
  outside the range (`Pool.CheckSpecific`).
- `PoolManager.ValidatePool` refuses reserved prefixes outside the CIDR and
  a range outside it, half set, or reversed (`*ErrInvalidWindow`).
- `TotalIPs` is `Pool.AllocatableIPs`: usable addresses less reserved ones.

`ListPoolsByZone(ctx, zone)` filters pools by zone on all three backends. An empty zone string returns all pools.

### Extended Interfaces

```go
// BatchAllocator provides bulk operations
type BatchAllocator interface {
    Allocator
    AllocateBatch(ctx context.Context, reqs []*AllocationRequest) ([]*Allocation, error)
    ReleaseBatch(ctx context.Context, ips []netip.Addr) (int, error)
}

// ReservationAllocator provides IP reservation
type ReservationAllocator interface {
    Allocator
    Reserve(ctx context.Context, poolID string, ip netip.Addr, description string) error
    Unreserve(ctx context.Context, ip netip.Addr) error
    ListReservations(ctx context.Context, poolID string) ([]*Allocation, error)
}
```

## Pool-Based Allocation Design

### Pool Structure

```
+------------------------------------------------------------------+
|                         IP POOL                                    |
+------------------------------------------------------------------+
|                                                                    |
|  Pool ID: provisioning                                             |
|  Name: provisioning                                                |
|  CIDR: 192.0.2.0/24                                                 |
|  Zone: provisioning                                                |
|  Reserved: 192.0.2.1/32 (gateway)   Range: 192.0.2.50-192.0.2.254     |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |                    Address Space                              |  |
|  +--------------------------------------------------------------+  |
|  | .0   | .1   | .2-.49          | .50  | .51  | ... | .254 | .255|  |
|  | NET  | GW   | STATIC (by role)| ALLOC| AVAIL| ... |AVAIL |BCAST|  |
|  |      |(rsvd)| AllocateSpecific| <-- dynamic window ---> |     |  |
|  +--------------------------------------------------------------+  |
|                                                                    |
|  Statistics:                                                       |
|    Total IPs:     253   (254 usable less the reserved gateway)     |
|    Allocated:     1                                                |
|    Available:     252                                              |
|    Utilization:   0.4%                                             |
|                                                                    |
+------------------------------------------------------------------+
```

### Pool Size Calculation

```go
func CalculatePoolSize(cidr netip.Prefix) uint64 {
    bits := cidr.Bits()
    var totalBits int
    if cidr.Addr().Is4() {
        totalBits = 32
    } else {
        totalBits = 128
    }

    hostBits := totalBits - bits

    // Handle edge cases
    if hostBits == 0 { return 1 }    // /32 or /128
    if hostBits == 1 { return 2 }    // /31 or /127
    if hostBits >= 64 { return ^uint64(0) }  // Very large prefixes

    total := uint64(1) << hostBits

    // IPv4: subtract network and broadcast
    if cidr.Addr().Is4() && hostBits >= 2 {
        return total - 2
    }

    return total
}
```

### IP Offset Conversion

IP addresses are converted to/from pool offsets for efficient bitmap tracking:

```
CIDR: 10.0.0.0/24

IP Address    Offset    Bitmap Index (usable)
-----------   ------    --------------------
10.0.0.0      0         N/A (network)
10.0.0.1      1         0 (first usable)
10.0.0.2      2         1
10.0.0.3      3         2
...           ...       ...
10.0.0.254    254       253 (last usable)
10.0.0.255    255       N/A (broadcast)
```

```go
// Convert IP to offset
func IPToOffset(cidr netip.Prefix, ip netip.Addr) (uint64, error) {
    if !ContainsIP(cidr, ip) {
        return 0, ErrIPNotInPool
    }

    network := cidr.Masked().Addr()

    if ip.Is4() {
        ipBytes := ip.As4()
        netBytes := network.As4()
        ipVal := binary.BigEndian.Uint32(ipBytes[:])
        netVal := binary.BigEndian.Uint32(netBytes[:])
        return uint64(ipVal - netVal), nil
    }

    // IPv6: use big.Int for 128-bit arithmetic
    // ...
}

// Convert offset to IP
func OffsetToIP(cidr netip.Prefix, offset uint64) (netip.Addr, error) {
    network := cidr.Masked().Addr()

    if network.Is4() {
        netBytes := network.As4()
        netVal := binary.BigEndian.Uint32(netBytes[:])
        ipVal := netVal + uint32(offset)

        var ipBytes [4]byte
        binary.BigEndian.PutUint32(ipBytes[:], ipVal)
        return netip.AddrFrom4(ipBytes), nil
    }

    // IPv6: use big.Int
    // ...
}
```

## Bitmap Allocation Algorithm

### Lock-Free Bitmap Design

The bitmap uses atomic operations for thread-safe, lock-free allocation:

```
+------------------------------------------------------------------+
|                      BITMAP STRUCTURE                              |
+------------------------------------------------------------------+
|                                                                    |
|  words: []atomic.Uint64                                           |
|                                                                    |
|  Word 0      Word 1      Word 2      Word 3                       |
|  [64 bits]   [64 bits]   [64 bits]   [64 bits]                   |
|  |.......|   |.......|   |.......|   |.......|                   |
|                                                                    |
|  Bit = 0: Available                                                |
|  Bit = 1: Allocated                                                |
|                                                                    |
|  For /24 pool (254 usable IPs):                                   |
|    - 4 words needed (254/64 = 3.97)                               |
|    - Last 2 bits of word 3 are unused                             |
|                                                                    |
+------------------------------------------------------------------+
```

### Atomic Set Operation

```go
func (b *Bitmap) Set(offset uint64) bool {
    if offset >= b.size {
        return false
    }

    wordIdx := offset / 64
    bitIdx := offset % 64
    mask := uint64(1) << bitIdx

    for {
        oldVal := b.words[wordIdx].Load()
        if oldVal&mask != 0 {
            return false  // Already set
        }
        newVal := oldVal | mask
        if b.words[wordIdx].CompareAndSwap(oldVal, newVal) {
            return true  // Successfully set
        }
        // CAS failed, retry
    }
}
```

### Next Clear Bit Search

```go
func (b *Bitmap) NextClear(start uint64) (uint64, bool) {
    if start >= b.size {
        return 0, false
    }

    wordIdx := start / 64
    bitIdx := start % 64

    // Check first partial word
    word := b.words[wordIdx].Load()
    maskedWord := word | ((1 << bitIdx) - 1)  // Mask off bits before start

    if maskedWord != ^uint64(0) {
        clearBit := findFirstClearBit(maskedWord)
        offset := wordIdx*64 + clearBit
        if offset < b.size {
            return offset, true
        }
    }

    // Scan remaining words
    for i := wordIdx + 1; i < uint64(len(b.words)); i++ {
        word := b.words[i].Load()
        if word != ^uint64(0) {
            clearBit := findFirstClearBit(word)
            offset := i*64 + clearBit
            if offset < b.size {
                return offset, true
            }
            return 0, false  // the first clear bit is past the end
        }
    }

    return 0, false
}
```

### de Bruijn Bit Manipulation

The bitmap uses a de Bruijn sequence for O(1) first set bit detection:

```go
func findFirstSetBit(word uint64) uint64 {
    if word == 0 {
        return 64
    }

    const debruijn64 = 0x03f79d71b4cb0a89
    var debruijnIndex = [64]uint64{
        0, 1, 48, 2, 57, 49, 28, 3, 61, 58, 50, 42, 38, 29, 17, 4,
        62, 55, 59, 36, 53, 51, 43, 22, 45, 39, 33, 30, 24, 18, 12, 5,
        63, 47, 56, 27, 60, 41, 37, 16, 54, 35, 52, 21, 44, 32, 23, 11,
        46, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
    }

    isolated := word & (^word + 1)  // Isolate lowest set bit
    return debruijnIndex[(isolated*debruijn64)>>58]
}
```

## Backend Architecture

### Backend Dispatch

The backend is selected at startup via `sdn.ipam.backend` in the config and resolved through a map-based factory registry:

```go
var ipamBackendFactory = map[string]func(ctx context.Context, app *App) (ipam.Allocator, error){}
```

| Config value | Factory registered in | Availability |
|-------------|----------------------|--------------|
| `memory` | `sdn_ipam_backends.go` | Always |
| `quicbaas` | `sdn_ipam_backends.go` | Requires a QuicBaaS SDK client; not registered in `platform_p2p` builds |
| `dht` | `sdn_ipam_backends_p2p.go` | Requires the `platform_p2p` build tag, and a p2p node passed to `RegisterDHTIPAMBackend` — nothing calls it yet, so the placeholder entry (`sdn_ipam_backends_p2p.go:37`) refuses |

`memory` is registered in both builds. An unknown backend returns `ErrIPAMBackendUnknown`. Requesting `dht` without the build tag returns `ErrIPAMBackendP2PRequired`. Requesting `quicbaas` without a configured SDK client returns `ErrIPAMBackendUnconfigured`.

### Memory Backend

```
+------------------------------------------------------------------+
|                     MEMORY BACKEND                                 |
+------------------------------------------------------------------+
|                                                                    |
|  +------------------+  +------------------+  +------------------+  |
|  |   pools          |  |   allocations    |  |   bitmaps        |  |
|  |   map[string]    |  |   map[netip.Addr]|  |   map[string]    |  |
|  |   *Pool          |  |   *Allocation    |  |   *Bitmap        |  |
|  +------------------+  +------------------+  +------------------+  |
|                                                                    |
|  +------------------+  +------------------+                       |
|  |   poolsByName    |  |   poolsByCIDR    |                       |
|  |   map[string]    |  |   map[Prefix]    |                       |
|  |   string         |  |   string         |                       |
|  +------------------+  +------------------+                       |
|                                                                    |
|  Synchronization: sync.RWMutex                                     |
|                                                                    |
+------------------------------------------------------------------+
```

### QuicBaaS Backend

```
+------------------------------------------------------------------+
|                   QUICBAAS BACKEND                                 |
+------------------------------------------------------------------+
|                                                                    |
|  Entity Types:                                                     |
|  +--------------------+  +--------------------+                    |
|  | ipam_pool          |  | ipam_allocation    |                    |
|  | ID: FNV-1a hash    |  | ID: FNV-1a(IP)     |                    |
|  | Data: JSON pool    |  | Data: JSON alloc   |                    |
|  +--------------------+  +--------------------+                    |
|                                                                    |
|  Index Types:                                                      |
|  +--------------------+                                            |
|  | ipam_index         |                                            |
|  | Key: "name:NAME"   |  -> Pool ID                                |
|  | Key: "cidr:CIDR"   |  -> Pool ID                                |
|  +--------------------+                                            |
|                                                                    |
|  QuicBaaSClient operations (by entity type + uint64 ID):           |
|  - Put / Get / Delete                                              |
|  - List: paginated scan                                            |
|  - Query: secondary-index lookup                                   |
|  No compare-and-swap: Allocate is read-then-Put                    |
|                                                                    |
+------------------------------------------------------------------+
```

### DHT Backend (P2P)

```
+------------------------------------------------------------------+
|                      DHT BACKEND                                   |
+------------------------------------------------------------------+
|                                                                    |
|  Key Namespaces:                                                   |
|  +--------------------+                                            |
|  | /ipam/pool/{id}    |  -> JSON pool metadata                     |
|  | /ipam/alloc/{ip}   |  -> JSON allocation                        |
|  | /ipam/device/{id}  |  -> Device allocation index                |
|  +--------------------+                                            |
|                                                                    |
|  Allocation Flow (Claim-Based):                                    |
|                                                                    |
|  1. Generate random IP in pool                                     |
|  2. Check DHT for existing allocation                              |
|  3. Write claim to DHT                                             |
|  4. Wait for propagation delay                                     |
|  5. Verify claim ownership                                         |
|  6. If conflict, retry with new IP                                 |
|                                                                    |
|  Local Caches:                                                     |
|  +------------------+  +------------------+  +------------------+  |
|  |   poolCache      |  |   poolNameIndex  |  |   poolCIDRIndex  |  |
|  |   sync.Map       |  |   sync.Map       |  |   sync.Map       |  |
|  +------------------+  +------------------+  +------------------+  |
|                                                                    |
+------------------------------------------------------------------+
```

## Allocation Flow

### Sequential Allocation (Memory/QuicBaaS)

```
+------------------------------------------------------------------+
|                   SEQUENTIAL ALLOCATION                            |
+------------------------------------------------------------------+
|                                                                    |
|  1. Validate Request                                               |
|     - Check pool exists                                            |
|     - Validate device ID                                           |
|                                                                    |
|  2. Find Available IP (Pool.NextDynamic)                           |
|     - window = DynamicOffsets() (RangeStart..RangeEnd)             |
|     - memory: bitmap.NextClear(first); quicbaas: scan the set of   |
|       stored allocations; past last -> exhausted                   |
|     - reserved address -> skip past its reserved prefix            |
|     - OffsetToIP(cidr, offset) -> IP                               |
|                                                                    |
|  3. Claim                                                          |
|     - memory: bitmap.Set(offset), all under the backend's write    |
|       lock (memory.go:392)                                         |
|     - quicbaas: no claim step; the Put in step 5 is unconditional  |
|                                                                    |
|  4. Create Allocation Record                                       |
|     - Generate UUID                                                |
|     - Set timestamps, status                                       |
|     - Calculate expiration                                         |
|                                                                    |
|  5. Persist                                                        |
|     - Store allocation                                             |
|     - Update pool stats                                            |
|                                                                    |
|  6. Return Allocation                                              |
|                                                                    |
+------------------------------------------------------------------+
```

### DHT Claim-Based Allocation

```
+------------------------------------------------------------------+
|                   DHT ALLOCATION FLOW                              |
+------------------------------------------------------------------+
|                                                                    |
|     Node A                       DHT                  Node B       |
|        |                          |                      |         |
|        |  1. Random IP in window  |                      |         |
|        |----------------------->  |                      |         |
|        |                          |                      |         |
|        |  2. Check if allocated   |                      |         |
|        |  GET /ipam/alloc/IP      |                      |         |
|        |<----------------------   |                      |         |
|        |     (not found)          |                      |         |
|        |                          |                      |         |
|        |  3. Write claim          |                      |         |
|        |  PUT /ipam/alloc/IP      |                      |         |
|        |----------------------->  |                      |         |
|        |                          |                      |         |
|        |  4. Wait propagation     |  (propagating)       |         |
|        |     (100ms)              |--------------------> |         |
|        |                          |                      |         |
|        |  5. Verify claim         |                      |         |
|        |  GET /ipam/alloc/IP      |                      |         |
|        |<----------------------   |                      |         |
|        |                          |                      |         |
|        |  6a. Our claim wins      |                      |         |
|        |      -> Success          |                      |         |
|        |                          |                      |         |
|        |  6b. Other claim wins    |                      |         |
|        |      -> Retry new IP     |                      |         |
|        |                          |                      |         |
+------------------------------------------------------------------+
```

## Concurrency Model

### Memory Backend Locking

```go
type MemoryBackend struct {
    mu          sync.RWMutex  // Protects all maps
    pools       map[string]*ipam.Pool
    allocations map[netip.Addr]*ipam.Allocation
    bitmaps     map[string]*ipam.Bitmap  // Lock-free internals
}

// Read operations use RLock
func (m *MemoryBackend) GetPool(ctx context.Context, poolID string) (*Pool, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    // ...
}

// Write operations use Lock
func (m *MemoryBackend) Allocate(ctx context.Context, req *AllocationRequest) (*Allocation, error) {
    m.mu.Lock()
    defer m.mu.Unlock()
    // Bitmap operations are lock-free within this lock
}
```

### QuicBaaS: no concurrency control

The QuicBaaS backend has no compare-and-swap and no retry loop. `Allocate`
reads the pool's allocations, picks the first free offset in the window,
and `Put`s the allocation unconditionally
(`pkg/sdn/ipam/backends/quicbaas.go:487`). Two platformd instances
allocating from the same pool at the same moment can both pick the same
address. The configured `MaxRetries` is stored (`quicbaas.go:105`) but never read, and `ErrCASConflict` /
`ErrMaxRetriesExceeded` are declared in `errors.go` but no backend returns
them.

### DHT Eventual Consistency

```go
// DHT uses claim-verify pattern for eventual consistency
func (d *DHTBackend) tryClaim(ctx context.Context, pool *Pool, ip netip.Addr, req *AllocationRequest) (*Allocation, error) {
    // 1. Check existing: an active allocation at this address wins
    existing, err := d.dht.GetValue(opCtx, key)
    // ... unmarshal; Status == Active -> return nil, ErrIPAlreadyAllocated

    // 2. Write claim (and the device index, best effort)
    if err := d.dht.PutValue(opCtx, key, data); err != nil {
        return nil, &ErrAllocationFailed{PoolID: pool.ID, Reason: "DHT put failed", Cause: err}
    }

    // 3. Propagation delay
    select {
    case <-time.After(claimPropagationDelay):
    case <-ctx.Done():
        return nil, ctx.Err()
    }

    // 4. Verify our claim won (read and unmarshal errors are ErrAllocationFailed)
    verified, err := d.dht.GetValue(verifyCtx, key)
    var verifiedAlloc Allocation
    json.Unmarshal(verified, &verifiedAlloc)

    if verifiedAlloc.DeviceID != req.DeviceID {
        return nil, ErrIPAlreadyAllocated
    }

    return &alloc, nil
}
```

## Lease Management

### Expiration Flow

```
+------------------------------------------------------------------+
|                    LEASE LIFECYCLE                                 |
+------------------------------------------------------------------+
|                                                                    |
|  Created                                                           |
|  (AllocatedAt)                                                     |
|      |                                                             |
|      v                                                             |
|  +--------+                                                        |
|  | Active |<------------+                                          |
|  +--------+             |                                          |
|      |                  |                                          |
|      |  Renew()         |                                          |
|      +------------------+                                          |
|      |                                                             |
|      |  ExpireInactive(): LastSeen older than InactivityTimeout   |
|      v                                                             |
|  +---------+                                                       |
|  | Expired |  (IP returned to pool)                                |
|  +---------+                                                       |
|                                                                    |
+------------------------------------------------------------------+
```

### Inactivity Timeout

```go
func (m *MemoryBackend) ExpireInactive(ctx context.Context, poolID string) ([]*Allocation, error) {
    pool := m.pools[poolID]

    if pool.InactivityTimeout == 0 {
        return nil, nil  // No timeout configured
    }

    threshold := time.Now().Add(-pool.InactivityTimeout)
    var expired []*Allocation

    for ip, alloc := range m.allocations {
        if alloc.PoolID != poolID {
            continue
        }
        if alloc.Status != AllocationStatusActive {
            continue
        }
        if alloc.LastSeen.Before(threshold) {
            alloc.Status = AllocationStatusExpired
            alloc.ReleasedAt = time.Now()
            expired = append(expired, alloc.Clone())

            // Clear bitmap (IPv4 below /31 skips the network address)
            offset, err := IPToOffset(pool.CIDR, ip)
            if err != nil {
                continue
            }
            bitmapOffset := offset
            if pool.CIDR.Addr().Is4() && pool.CIDR.Bits() < 31 {
                bitmapOffset = offset - 1
            }
            m.bitmaps[poolID].Clear(bitmapOffset)

            // Update stats
            pool.AllocatedIPs--
            pool.AvailableIPs++
        }
    }

    return expired, nil
}
```

## Error Handling

### Typed Errors

```go
// Sentinel errors for common conditions
var (
    ErrPoolNotFound       = errors.New("pool not found")
    ErrPoolAlreadyExists  = errors.New("pool already exists")
    ErrPoolExhausted      = errors.New("pool exhausted")
    ErrIPAlreadyAllocated = errors.New("IP already allocated")
    ErrAllocationNotFound = errors.New("allocation not found")
    ErrBackendUnavailable = errors.New("backend unavailable")
)

// Structured errors for context
type ErrAllocationFailed struct {
    PoolID string
    Reason string
    Cause  error
}

type ErrIPConflict struct {
    IP       netip.Addr
    DeviceID string
}

// Error classification
func IsPoolError(err error) bool
func IsAllocationError(err error) bool
func IsValidationError(err error) bool
func IsBackendError(err error) bool
```

## Monitoring and Metrics

### Pool Statistics

```go
type PoolStats struct {
    PoolID         string
    TotalIPs       uint64
    AllocatedIPs   uint64
    AvailableIPs   uint64
    ExpiredIPs     uint64
    ReservedIPs    uint64
    UtilizationPct float64
}
```

### Observable Metrics

IPAM exports no metrics today: `pkg/sdn/ipam` registers no instruments.
`GetPoolStats` (above) is the only view of pool usage.
