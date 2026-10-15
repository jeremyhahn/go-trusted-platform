# DHCP Architecture

## Overview

The DHCP service implements a plugin-based architecture built on CoreDHCP, providing high-performance IP allocation integrated with the platform IPAM system.

## Component Architecture

### High-Level Design

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              DHCP Service                                     │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        CoreDHCPServer                                    │ │
│  │                                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐│ │
│  │  │  server4[0]  │  │  server4[1]  │  │  server4[2]  │  │  server4[N]  ││ │
│  │  │   (eth0)     │  │   (eth1)     │  │   (br0)      │  │   (ifN)      ││ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘│ │
│  │         │                 │                 │                 │         │ │
│  │         └─────────────────┼─────────────────┼─────────────────┘         │ │
│  │                           │                 │                           │ │
│  │                    ┌──────▼──────┐   ┌──────▼──────┐                    │ │
│  │                    │ IPAM Plugin │   │ PXE Plugin  │                    │ │
│  │                    │ (per-iface) │   │ (optional)  │                    │ │
│  │                    └──────┬──────┘   └─────────────┘                    │ │
│  │                           │                                             │ │
│  │                    ┌──────▼──────┐                                      │ │
│  │                    │ Lease Store │                                      │ │
│  │                    │ (sync.Map)  │                                      │ │
│  │                    └──────┬──────┘                                      │ │
│  │                           │                                             │ │
│  └───────────────────────────┼─────────────────────────────────────────────┘ │
│                              │                                               │
│                       ┌──────▼──────┐                                        │
│                       │   Platform  │                                        │
│                       │    IPAM     │                                        │
│                       │  Allocator  │                                        │
│                       └─────────────┘                                        │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Core Components

#### CoreDHCPServer

The main server implementation wrapping CoreDHCP with platform integration.

```go
type CoreDHCPServer struct {
    config      *ServerConfig
    allocator   ipam.Allocator
    servers     map[string]*server4.Server // per-interface servers
    plugins     map[string]*IPAMPlugin     // per-interface IPAM plugins
    leases      *LeaseStore
    stats       *StatsCollector
    running     atomic.Bool
    logger      *slog.Logger
    mu          sync.RWMutex
    cancelFuncs map[string]context.CancelFunc
}
```

**Responsibilities:**
- Manage multiple interface-specific DHCP servers
- Coordinate plugin lifecycle
- Aggregate statistics across interfaces
- Provide unified lease management API

#### IPAMPlugin

Bridges CoreDHCP to the platform IPAM system using map-based dispatch for O(1) message routing.

```go
type IPAMPlugin struct {
    allocator    ipam.Allocator
    poolID       string
    leaseStore   *LeaseStore
    defaultLease time.Duration
    options      DHCPOptions
    handlers     map[dhcpv4.MessageType]MessageHandler  // O(1) dispatch
    logger       *slog.Logger
    mu           sync.RWMutex
    closed       atomic.Bool
}
```

**Responsibilities:**
- Handle DHCP message types (DISCOVER, REQUEST, RELEASE, DECLINE, INFORM)
- Allocate IPs from IPAM pools
- Manage lease state
- Build DHCP responses with configured options

#### LeaseStore

Thread-safe lease storage with O(1) lookup by IP or MAC address.

```go
type LeaseStore struct {
    leasesByIP  sync.Map // netip.Addr -> *Lease
    leasesByMAC sync.Map // string (MAC string) -> *Lease
    closed      atomic.Bool
}
```

**Responsibilities:**
- Store active leases
- Provide dual-index lookup (IP and MAC)
- Handle lease expiration
- Support lease state transitions

#### StatsCollector

Lock-free statistics collection using atomic operations.

```go
type statsCollector struct {
    startedAt       atomic.Value // time.Time
    packetsReceived atomic.Uint64
    packetsSent     atomic.Uint64
    discoverCount   atomic.Uint64
    offerCount      atomic.Uint64
    requestCount    atomic.Uint64
    ackCount        atomic.Uint64
    nakCount        atomic.Uint64
    releaseCount    atomic.Uint64
    declineCount    atomic.Uint64
    informCount     atomic.Uint64
    errorCount      atomic.Uint64
    activeLeases    atomic.Int64
}
```

**Responsibilities:**
- Track DHCP message counts
- Monitor packet statistics
- Report active lease counts
- Provide zero-lock reads via atomic operations

#### PXEPlugin

Adds PXE boot capabilities with architecture-aware boot file selection.

```go
type PXEPlugin struct {
    nextServer    net.IP
    bootFileName  string
    tftpRoot      string
    archFilters   map[uint16]string  // Architecture -> boot file
    logger        *slog.Logger
    mu            sync.RWMutex
    closed        atomic.Bool
}
```

**Responsibilities:**
- Detect PXE clients via vendor class
- Extract client architecture (option 93)
- Configure boot options (options 66, 67)
- Support BIOS and UEFI boot modes

## CoreDHCP Integration

### Server Initialization

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        Server Initialization Flow                             │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  1. NewCoreDHCPServer(config, allocator)                                     │
│     │                                                                         │
│     ├─► Validate configuration                                               │
│     ├─► Initialize LeaseStore                                                │
│     ├─► Initialize StatsCollector                                            │
│     └─► Apply options (logger, custom lease store)                           │
│                                                                               │
│  2. server.Start(ctx)                                                        │
│     │                                                                         │
│     ├─► For each interface in config:                                        │
│     │   │                                                                     │
│     │   ├─► Create IPAMPlugin for interface                                  │
│     │   │   └─► Configure with pool ID, DHCP options                         │
│     │   │                                                                     │
│     │   ├─► Create handler function wrapping plugin                          │
│     │   │   └─► Add statistics collection                                    │
│     │   │                                                                     │
│     │   ├─► Create server4.Server on interface                               │
│     │   │   └─► Bind to interface:67 (UDP)                                   │
│     │   │                                                                     │
│     │   └─► Start server goroutine with cancellable context                  │
│     │                                                                         │
│     ├─► Mark server as running                                               │
│     └─► Start statistics collection                                          │
│                                                                               │
│  3. server.Stop(ctx)                                                         │
│     │                                                                         │
│     ├─► Cancel all server contexts                                           │
│     ├─► Close all server4.Server instances                                   │
│     ├─► Close all IPAMPlugin instances                                       │
│     └─► Mark server as stopped                                               │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Message Handling Pipeline

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        DHCP Message Handling Pipeline                         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  UDP Packet Received on Interface                                            │
│         │                                                                     │
│         ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ server4.Server (CoreDHCP)                                                │ │
│  │ - Parse DHCPv4 packet                                                    │ │
│  │ - Extract message type                                                   │ │
│  │ - Call registered handler                                                │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                     │
│         ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ Handler Wrapper (createHandlerFunc)                                      │ │
│  │ - Increment packetsReceived                                              │ │
│  │ - Record message type stats                                              │ │
│  │ - Create response skeleton                                               │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                     │
│         ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ IPAMPlugin.Handler4()                                                    │ │
│  │ - Map-based dispatch to message handler (O(1))                           │ │
│  │ - Process message (DISCOVER, REQUEST, RELEASE, etc.)                     │ │
│  │ - Interact with IPAM allocator                                           │ │
│  │ - Update lease store                                                     │ │
│  │ - Build response                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                     │
│         ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ PXE Plugin (Optional, if client is PXE)                                  │ │
│  │ - Detect PXE client (option 60)                                          │ │
│  │ - Extract architecture (option 93)                                       │ │
│  │ - Add boot options (66, 67)                                              │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│         │                                                                     │
│         ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ Response Transmission                                                    │ │
│  │ - Increment packetsSent                                                  │ │
│  │ - Record response type stats (OFFER, ACK, NAK)                           │ │
│  │ - Update active lease count                                              │ │
│  │ - Send UDP response                                                      │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Plugin Architecture

### IPAM Plugin Message Dispatch

The IPAM plugin uses map-based dispatch for O(1) constant-time message routing:

```go
// Initialize message handlers using map-based dispatch
p.handlers = map[dhcpv4.MessageType]MessageHandler{
    dhcpv4.MessageTypeDiscover: p.handleDiscover,
    dhcpv4.MessageTypeRequest:  p.handleRequest,
    dhcpv4.MessageTypeRelease:  p.handleRelease,
    dhcpv4.MessageTypeDecline:  p.handleDecline,
    dhcpv4.MessageTypeInform:   p.handleInform,
}

// Handler dispatch
func (p *IPAMPlugin) Handler4() handler.Handler4 {
    return func(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
        // O(1) lookup
        if handler, ok := p.handlers[req.MessageType()]; ok {
            return handler(ctx, req, resp)
        }
        return resp, false  // Continue chain for unknown types
    }
}
```

### Message Handler Flow

#### DHCPDISCOVER

```
┌─────────────────────────────────────────────────────────────────┐
│                     handleDiscover Flow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Extract client MAC address                                  │
│                                                                  │
│  2. Check existing lease                                        │
│     │                                                            │
│     ├─► If active lease exists:                                 │
│     │   ├─► Renew in IPAM                                       │
│     │   └─► Return OFFER with existing IP                       │
│     │                                                            │
│     └─► If no lease or renewal failed:                          │
│         └─► Continue to step 3                                  │
│                                                                  │
│  3. Allocate from IPAM                                          │
│     │                                                            │
│     ├─► Create AllocationRequest with:                          │
│     │   - PoolID                                                │
│     │   - DeviceID (MAC)                                        │
│     │   - Hostname                                              │
│     │   - LeaseDuration                                         │
│     │                                                            │
│     ├─► Call allocator.Allocate()                               │
│     │                                                            │
│     └─► On failure: return nil (no response)                    │
│                                                                  │
│  4. Create lease record                                         │
│     │                                                            │
│     ├─► Set IP, MAC, Hostname, PoolID                           │
│     ├─► Set LeasedAt, ExpiresAt                                 │
│     ├─► Set State = LeaseStateActive                            │
│     └─► Add to LeaseStore                                       │
│                                                                  │
│  5. Build DHCPOFFER response                                    │
│     │                                                            │
│     ├─► Set MessageType = OFFER                                 │
│     ├─► Set YourIPAddr                                          │
│     ├─► Add common options (subnet, router, DNS)                │
│     └─► Add lease options (T1, T2, lease time)                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### DHCPREQUEST

```
┌─────────────────────────────────────────────────────────────────┐
│                     handleRequest Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Extract client MAC and requested IP                         │
│     │                                                            │
│     └─► If no requested IP: return NAK                          │
│                                                                  │
│  2. Check existing lease for this MAC                           │
│     │                                                            │
│     ├─► If lease exists with matching IP:                       │
│     │   ├─► Renew in IPAM                                       │
│     │   ├─► Update LeaseStore                                   │
│     │   └─► Return ACK                                          │
│     │                                                            │
│     └─► If no matching lease: continue                          │
│                                                                  │
│  3. Check IP availability                                       │
│     │                                                            │
│     └─► If IP leased to different MAC: return NAK               │
│                                                                  │
│  4. Allocate specific IP                                        │
│     │                                                            │
│     ├─► Call allocator.AllocateSpecific()                       │
│     │                                                            │
│     └─► On failure: return NAK                                  │
│                                                                  │
│  5. Create lease record and store                               │
│                                                                  │
│  6. Build DHCPACK response                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### PXE Plugin Chain

The PXE plugin operates in the handler chain after IPAM:

```
┌─────────────────────────────────────────────────────────────────┐
│                       PXE Plugin Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Check if PXE client                                         │
│     │                                                            │
│     ├─► Check option 60 (Vendor Class Identifier)               │
│     │   └─► Must start with "PXEClient"                         │
│     │                                                            │
│     └─► Check option 93 (Client System Architecture)            │
│                                                                  │
│  2. If not PXE client: return response unchanged                │
│                                                                  │
│  3. Extract client architecture                                 │
│     │                                                            │
│     ├─► Parse option 93 (2 bytes, big-endian)                   │
│     │                                                            │
│     └─► Common values:                                          │
│         ├─► 0: Intel x86 (BIOS)                                 │
│         ├─► 6: EFI IA32                                         │
│         ├─► 7: EFI x86-64 (UEFI)                                │
│         └─► 11: ARM 64-bit UEFI                                 │
│                                                                  │
│  4. Select boot file                                            │
│     │                                                            │
│     ├─► Check archFilters map                                   │
│     │   └─► If architecture found: use specific boot file       │
│     │                                                            │
│     └─► Fall back to default boot file                          │
│                                                                  │
│  5. Add PXE options to response                                 │
│     │                                                            │
│     ├─► Set ServerIPAddr (next-server)                          │
│     ├─► Set BootFileName                                        │
│     ├─► Add option 66 (TFTP Server Name)                        │
│     └─► Add option 67 (Boot File Name)                          │
│                                                                  │
│  6. Return response (continue chain)                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Lease Management

### LeaseStore Operations

```
┌─────────────────────────────────────────────────────────────────┐
│                    LeaseStore Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌─────────────────┐                          │
│                    │   LeaseStore    │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│         ┌───────────────────┼───────────────────┐               │
│         │                   │                   │               │
│  ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐       │
│  │ leasesByIP  │     │ leasesByMAC │     │   closed    │       │
│  │  (sync.Map) │     │  (sync.Map) │     │(atomic.Bool)│       │
│  └──────┬──────┘     └──────┬──────┘     └─────────────┘       │
│         │                   │                                    │
│         │    ┌──────────────┴──────────────┐                    │
│         │    │                             │                    │
│  Key: netip.Addr              Key: string (MAC.String())        │
│  Value: *Lease                Value: *Lease                     │
│                                                                  │
│  Operations:                                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Add(lease)      - Store by both IP and MAC                  ││
│  │ GetByIP(ip)     - O(1) lookup by IP                         ││
│  │ GetByMAC(mac)   - O(1) lookup by MAC                        ││
│  │ Remove(ip)      - Remove from both maps                     ││
│  │ RemoveByMAC(mac)- Remove from both maps                     ││
│  │ Renew(ip, dur)  - Extend lease expiration                   ││
│  │ SetState(ip, s) - Update lease state                        ││
│  │ ExpireOld()     - Remove expired leases                     ││
│  │ All()           - Return all leases                         ││
│  │ AllActive()     - Return non-expired leases                 ││
│  │ Count()         - Total lease count                         ││
│  │ CountActive()   - Active lease count                        ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Lease State Machine

```
┌─────────────────────────────────────────────────────────────────┐
│                     Lease State Machine                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                    ┌─────────────┐                              │
│       ┌────────────│   (none)    │                              │
│       │            └──────┬──────┘                              │
│       │                   │ DHCPDISCOVER                        │
│       │                   ▼                                      │
│       │            ┌─────────────┐                              │
│       │            │   Active    │◄──────────────┐              │
│       │            └──────┬──────┘               │              │
│       │                   │                      │              │
│       │    ┌──────────────┼──────────────┐       │              │
│       │    │              │              │       │              │
│       │    │ DHCPRELEASE  │ Expiration   │ DHCPREQUEST         │
│       │    │              │              │ (Renewal)            │
│       │    ▼              ▼              │       │              │
│       │ ┌─────────┐ ┌─────────────┐      │       │              │
│       │ │Released │ │  Expired    │──────┘       │              │
│       │ └────┬────┘ └─────────────┘               │              │
│       │      │                                    │              │
│       │      │         ┌─────────────┐           │              │
│       │      └────────►│  (removed)  │◄──────────┘              │
│       │                └─────────────┘                          │
│       │                                                          │
│       │    DHCPDECLINE                                          │
│       │         │                                                │
│       │         ▼                                                │
│       │  ┌─────────────┐                                        │
│       └─►│  Declined   │                                        │
│          └─────────────┘                                        │
│                                                                  │
│  States:                                                        │
│  - Active:   Lease in use, not expired                          │
│  - Released: Client explicitly released                         │
│  - Expired:  Lease duration exceeded                            │
│  - Declined: Client reported address conflict                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Multi-Interface Support

### Per-Interface Isolation

Each network interface operates independently with its own:

- IPAM pool assignment
- DHCP options configuration
- Server4 instance
- IPAMPlugin instance

```
┌─────────────────────────────────────────────────────────────────┐
│                    Multi-Interface Design                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     CoreDHCPServer                          ││
│  │                                                              ││
│  │  config.Interfaces: [                                        ││
│  │    {Name: "eth0", PoolID: "mgmt",   Options: {...}},        ││
│  │    {Name: "eth1", PoolID: "tenant", Options: {...}},        ││
│  │    {Name: "br0",  PoolID: "guests", Options: {...}},        ││
│  │  ]                                                           ││
│  │                                                              ││
│  │  servers: map[string]*server4.Server {                       ││
│  │    "eth0": server4@192.0.2.1:67,                            ││
│  │    "eth1": server4@10.0.0.1:67,                             ││
│  │    "br0":  server4@192.0.2.1:67,                             ││
│  │  }                                                           ││
│  │                                                              ││
│  │  plugins: map[string]*IPAMPlugin {                           ││
│  │    "eth0": IPAMPlugin{poolID: "mgmt"},                      ││
│  │    "eth1": IPAMPlugin{poolID: "tenant"},                    ││
│  │    "br0":  IPAMPlugin{poolID: "guests"},                    ││
│  │  }                                                           ││
│  │                                                              ││
│  │  leases: *LeaseStore (shared across interfaces)              ││
│  │  stats:  *StatsCollector (aggregated)                        ││
│  │                                                              ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Network Types

| Type | Constant | Use Case |
|------|----------|----------|
| Public | `NetworkPublic` | Internet-facing networks |
| Private | `NetworkPrivate` | Internal/management networks |

## Statistics Collection

### Lock-Free Design

Statistics use atomic operations for zero-lock reads:

```go
// Increment operations (writers)
func (s *statsCollector) incPacketsReceived() {
    s.packetsReceived.Add(1)
}

// Snapshot operation (readers)
func (s *statsCollector) snapshot() ServerStats {
    return ServerStats{
        StartedAt:       s.startedAt.Load().(time.Time),
        PacketsReceived: s.packetsReceived.Load(),
        PacketsSent:     s.packetsSent.Load(),
        // ... other fields
    }
}
```

### Tracked Metrics

| Metric | Description |
|--------|-------------|
| `packetsReceived` | Total DHCP packets received |
| `packetsSent` | Total DHCP packets sent |
| `discoverCount` | DHCPDISCOVER messages received |
| `offerCount` | DHCPOFFER messages sent |
| `requestCount` | DHCPREQUEST messages received |
| `ackCount` | DHCPACK messages sent |
| `nakCount` | DHCPNAK messages sent |
| `releaseCount` | DHCPRELEASE messages received |
| `declineCount` | DHCPDECLINE messages received |
| `informCount` | DHCPINFORM messages received |
| `errorCount` | Total errors encountered |
| `activeLeases` | Current active lease count |

## IPAM Integration

### Allocator Interface

The DHCP service uses the platform IPAM allocator interface:

```go
type Allocator interface {
    Allocate(ctx context.Context, req *AllocationRequest) (*Allocation, error)
    AllocateSpecific(ctx context.Context, req *AllocationRequest) (*Allocation, error)
    Release(ctx context.Context, ip netip.Addr) error
    Renew(ctx context.Context, ip netip.Addr) error
}
```

### Backend Support

| Backend | Constant | Description |
|---------|----------|-------------|
| Memory | `IPAMBackendMemory` | In-memory storage (single instance) |
| QuicBaaS | `IPAMBackendQuicBaaS` | Distributed storage (HA) |
| DHT | `IPAMBackendDHT` | P2P distributed storage |

## Error Handling

### Error Types

The package defines typed errors for precise error handling:

```go
// Sentinel errors
var (
    ErrPluginClosed          = errors.New("plugin closed")
    ErrAllocatorRequired     = errors.New("allocator required")
    ErrPoolIDRequired        = errors.New("pool ID required")
    ErrLeaseNotFound         = errors.New("lease not found")
    ErrInvalidMAC            = errors.New("invalid MAC address")
    ErrServerAlreadyRunning  = errors.New("server already running")
    // ...
)

// Structured errors
type ErrLeaseConflict struct {
    IP           netip.Addr
    ExistingMAC  net.HardwareAddr
    RequestedMAC net.HardwareAddr
}

type ErrPoolExhausted struct {
    PoolID string
}

type ErrInterfaceOperation struct {
    Interface string
    Operation string
    Cause     error
}
```

### Error Classification

```go
// Check error categories
IsLeaseError(err)      // Lease-related errors
IsValidationError(err) // Input validation errors
IsServerError(err)     // Server operation errors
IsPoolError(err)       // Pool-related errors
```

## See Also

- [README](README.md) - Package overview
- [Configuration](configuration.md) - Configuration reference
- [Plugins](plugins.md) - Plugin documentation
- [API Reference](api-reference.md) - API overview
