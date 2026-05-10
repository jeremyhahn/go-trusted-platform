# Firewall Architecture

## Design Philosophy

The firewall engine is designed for high-performance packet processing with:

- **Lock-free fast path**: Established connections processed without synchronization
- **Sharded architecture**: 256 independent connection tracking buckets reduce contention
- **Minimal allocations**: Reuse PacketInfo per packet
- **Simple evaluation**: Linear rule search (priority order) until first match
- **Stateful tracking**: Track connection state across packets

## Packet Processing Pipeline

```
┌─────────────────────────────────────────────────────────┐
│ Raw Packet (raw bytes, metadata)                        │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ Parse to PacketInfo                                     │
│ - Extract: SrcIP, DstIP, SrcPort, DstPort, Protocol     │
│ - Extract: InIface, OutIface, Length                    │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│ ConnTrack.LookupOrCreate()                              │
│ - Hash 5-tuple (srcip:srcport:dstip:dstport:protocol)   │
│ - Shard = hash & (ShardCount-1)                         │
│ - RWLock shard, lookup/create connection entry          │
│ - Set PacketInfo.ConnState                              │
└─────────────────────┬───────────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
    ┌────▼────────┐          ┌────▼─────────┐
    │ NEW/INVALID │          │ ESTABLISHED  │
    │ (slow path) │          │ (fast path)  │
    └────┬────────┘          └────┬─────────┘
         │                        │
  (needs locking)          (read-only lookup)
         │                        │
    ┌────▼────────────────────────▼─────┐
    │ Zone Resolver                      │
    │ - ifToZone map lookup              │
    │ - Set SrcZone, DstZone            │
    └────┬─────────────────────────────┘
         │
    ┌────▼───────────────────────────────┐
    │ NAT Engine (if rules match)         │
    │ - Check SNAT/DNAT rules             │
    │ - Update pkt addresses              │
    │ - Store NAT entry in conntrack      │
    └────┬───────────────────────────────┘
         │
    ┌────▼───────────────────────────────┐
    │ Rule Evaluator                      │
    │ - Sort by priority (pre-sorted)     │
    │ - Iterate: match + return on hit    │
    │ - Default to DefaultPolicy if none  │
    └────┬───────────────────────────────┘
         │
    ┌────┴──────────┬──────────┬──────────┐
    │               │          │          │
┌───▼────┐  ┌──────▼──┐  ┌───▼────┐  ┌───▼────┐
│ ALLOW  │  │  DENY   │  │ REJECT │  │STATS   │
│(pass)  │  │(drop)   │  │(err)   │  │(incr)  │
└────────┘  └─────────┘  └────────┘  └────────┘
```

## Connection Tracking (ConnTrack)

### Sharded Hash Table

The connection tracking table uses 256 shards to reduce lock contention:

```go
const (
    shardCount = 256
    shardMask  = 255  // 256 - 1 for fast modulo
)

type ConnTrack struct {
    shards [256]*shard
}

type shard struct {
    mu          sync.RWMutex
    connections map[uint64]*connEntry
}
```

### 5-Tuple Hashing

Each connection is identified by a 5-tuple hash:

```go
hash = XXHash64(srcIP || srcPort || dstIP || dstPort || protocol)
shard_id = hash & shardMask  // Fast modulo
```

### Connection State Machine

```
    ┌──────────────┐
    │     NEW      │ (first packet from initiator)
    └──────┬───────┘
           │
    ┌──────▼────────────────────────┐
    │ Packet from initiator sent?    │
    └──────┬────────────────────────┘
           │ yes
    ┌──────▼────────────────────────┐
    │ Packet from responder sent?    │
    └──────┬────────────────────────┘
           │ yes
    ┌──────▼──────────────┐
    │  ESTABLISHED        │ (bidirectional traffic)
    └──────┬──────────────┘
           │
    ┌──────▼────────────────────────────────────┐
    │ Close timeout reached?                     │
    │ (TCP FIN/RST or idle timeout)              │
    └──────┬────────────────────────────────────┘
           │ yes
    ┌──────▼──────────┐
    │   EXPIRED       │ (entry garbage collected)
    └─────────────────┘
```

### Per-Connection Entry

```go
type connEntry struct {
    // 5-tuple (forward direction)
    srcIP      netip.Addr
    srcPort    uint16
    dstIP      netip.Addr
    dstPort    uint16
    protocol   uint8
    
    // State tracking
    state      ConnState
    initiator  bool  // true if packet is from initiator
    responder  bool  // true if packet is from responder
    
    // Timestamps
    createdAt  time.Time
    lastSeen   time.Time
    expireAt   time.Time
    
    // Reverse flow tracking (for reply packets)
    revHash    uint64
    
    // NAT (if applicable)
    natEntry   *NATEntry
}
```

### Idle Timeout Garbage Collection

Expired connections are garbage-collected when:

1. A new packet lookup touches a shard
2. Every N seconds via cleanup goroutine
3. Shard size exceeds max entries

This is lock-free for the lookup path (reads don't check expiry).

## Zone Resolution

### Interface-to-Zone Mapping

```go
type ZoneResolver struct {
    zones    map[string]*Zone      // name -> Zone definition
    ifToZone map[string]string     // interface name -> zone name
}
```

Built at initialization time, accessed during packet processing:

```go
zone, ok := zoneResolver.ZoneForInterface(pkt.InIface)
pkt.SrcZone = zone
```

### Zone Policy Semantics

- **Zone policy**: Default action (allow/deny) for traffic originating from the zone
- **Rule evaluation**: Explicit rules override zone policy
- **Zone transitions**: Rules match on source and destination zones

## NAT Processing

### SNAT (Source NAT / Masquerade)

Rewrites source address for traffic originating from a zone:

```
Original:   trusted (10.0.1.x) -> internet
Translated: gateway (203.0.113.1) -> internet
```

**Processing**:
1. Match SNAT rules (src zone, dst zone, protocol)
2. Update packet source address
3. Store translation in connection entry
4. Return packets automatically de-NATted via reverse flow

### DNAT (Destination NAT / Port Forward)

Rewrites destination address/port for incoming traffic:

```
Original:   internet -> gateway:80
Translated: internet -> internal:8080
```

**Processing**:
1. Match DNAT rules (dst port, protocol)
2. Update packet destination address and port
3. Store translation in connection entry
4. Return packets automatically de-NATted via reverse flow

### NAT Entry

```go
type NATEntry struct {
    Type           NATType         // SNAT or DNAT
    OriginalSrc    netip.AddrPort
    OriginalDst    netip.AddrPort
    TranslatedSrc  netip.AddrPort
    TranslatedDst  netip.AddrPort
}
```

## Rule Evaluation

### Rule Storage

Rules are stored in priority order (pre-sorted at init):

```go
type ruleSet struct {
    rules []Rule  // Sorted by priority
}
```

### Rule Matching

```go
func (rs *ruleSet) eval(pkt *PacketInfo) Action {
    for _, rule := range rs.rules {
        if rule.match(pkt) {
            return rule.action
        }
    }
    return defaultAction
}
```

### Match Criteria

Each rule defines match criteria (all must match):

```go
type RuleMatch struct {
    SrcZone  string        // Zone name (empty = any)
    DstZone  string        // Zone name (empty = any)
    SrcNet   netip.Prefix  // Network (zero = any)
    DstNet   netip.Prefix  // Network (zero = any)
    SrcPort  uint16        // Port (0 = any)
    DstPort  uint16        // Port (0 = any)
    Protocol uint8         // IP protocol (0 = any)
    ConnState ConnState    // Connection state (0 = any)
}

func (rm *RuleMatch) matches(pkt *PacketInfo) bool {
    if rm.SrcZone != "" && pkt.SrcZone != rm.SrcZone {
        return false
    }
    if rm.DstZone != "" && pkt.DstZone != rm.DstZone {
        return false
    }
    if rm.Protocol != 0 && pkt.Protocol != rm.Protocol {
        return false
    }
    // ... continue for all fields
    return true
}
```

## Performance Optimizations

### Lock-Free Fast Path

Established connections use only RWLock read:

```go
// In LookupOrCreate:
shard.mu.RLock()
entry := shard.connections[hash]
shard.mu.RUnlock()

if entry != nil && entry.state == ESTABLISHED {
    // Fast path: established, no write lock needed
    return entry, nil
}

// Slow path: need write lock for NEW/INVALID
```

### XXHash-based Hashing

Fast 64-bit hash (1-2 nanoseconds):

```go
hash := xxhash.Sum64String(fmt.Sprintf("%s:%d:%s:%d:%d",
    srcIP, srcPort, dstIP, dstPort, protocol))
```

### Pre-sorted Rules

Rules are sorted once at init time:

```go
sort.Slice(rules, func(i, j int) bool {
    return rules[i].Priority < rules[j].Priority
})
```

### Minimal Allocations

PacketInfo is reused per packet:

```go
pkt := &PacketInfo{}  // Allocated once per packet
// Update fields...
engine.FilterPacket(ctx, pkt)
// Reuse for next packet
```

## Statistics

Atomic counters track firewall activity:

```go
type EngineStats struct {
    PacketsProcessed   atomic.Uint64  // Total packets
    PacketsAllowed     atomic.Uint64  // Allowed
    PacketsDenied      atomic.Uint64  // Denied
    PacketsNATted      atomic.Uint64  // NATted
    ActiveConnections  atomic.Int64   // Current tracked
}
```

Counters use atomics to avoid lock contention.

## Thread Safety

- **ZoneResolver**: Immutable after init, safe for concurrent reads
- **ConnTrack**: Per-shard locking, independent shards safe for concurrent access
- **RuleSet**: Immutable after init, safe for concurrent reads
- **Stats**: Atomic counters, safe for concurrent increments
- **PacketInfo**: Per-call allocation, no sharing between threads

## Memory Layout

Sharded design reduces CPU cache conflicts:

```
┌─────────────────────────────────────┐
│ ConnTrack                           │
├─────────────────────────────────────┤
│ Shard 0 [RWMutex, map]  ┐           │
│ Shard 1 [RWMutex, map]  ├─ L3 cache │
│ Shard 2 [RWMutex, map]  ┘           │
├─────────────────────────────────────┤
│ Shard N [RWMutex, map]              │
└─────────────────────────────────────┘
```

Multiple shards fit in L3 cache, reducing false sharing.

## See Also

- [README](./README.md) - Overview
- [Configuration](./configuration.md) - Config schema
- [Performance](./performance.md) - Tuning guide
