# Stateful Firewall Engine

The `pkg/sdn/firewall` package provides a pure-Go stateful firewall engine with connection tracking, zone-based policy, NAT, and priority-ordered rules. It is designed for high-performance data-plane packet processing with sub-microsecond latency on established connections.

## Features

- **Connection tracking**: Bidirectional flow tracking with per-packet state management
- **Zone-based policy**: Default allow/deny per zone with zone transitions
- **Stateful matching**: Rules match on NEW, ESTABLISHED, RELATED, INVALID connections
- **NAT support**: SNAT (source masquerade) and DNAT (port forward) with connection binding
- **Priority rules**: Configurable rule ordering; first match wins
- **High performance**: Lock-free packet fast path, sharded connection table
- **Pure Go**: No kernel modules or external dependencies required

## Architecture

```
┌──────────────────────────────────────────────┐
│ Incoming Packet (SrcIP, DstIP, Protocol, etc)│
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Connection Tracking (ConnTrack)              │
│ - Hash packet 5-tuple                        │
│ - Lookup/update connection state             │
│ - Track reverse flow                         │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Zone Resolver                                │
│ - Resolve InIface → SrcZone                  │
│ - Resolve OutIface → DstZone                 │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ NAT Engine (if enabled)                      │
│ - Evaluate SNAT/DNAT rules                   │
│ - Update packet addresses                    │
│ - Bind connection to translation             │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Rule Evaluator (Priority-Ordered)            │
│ - Iterate rules in priority order            │
│ - Match against zone, IP, port, protocol     │
│ - Return verdict (allow/deny/reject)         │
└──────────────────────┬───────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
    ┌───▼───┐                     ┌───▼────┐
    │ ALLOW │                     │ DENY   │
    │ REJECT│                     │FORWARD │
    └───────┘                     └────────┘
```

## Core Concepts

### Connection State

Connections are tracked through four states:

- **NEW**: First packet of a new connection (no prior state)
- **ESTABLISHED**: Bidirectional traffic seen (both directions)
- **RELATED**: Related to an existing connection (e.g., ICMP error response)
- **INVALID**: Packet doesn't match any valid state transition

### Zone Model

Zones group network interfaces with a default traffic policy:

```yaml
firewall:
  zones:
    - name: trusted
      interfaces:
        - eth0
        - eth1
      policy: allow

    - name: untrusted
      interfaces:
        - eth2
      policy: deny

    - name: dmz
      interfaces:
        - eth3
      policy: allow
```

### Rule Priority

Rules are evaluated in ascending priority order. The first matching rule determines the verdict:

```yaml
rules:
  - name: allow-dns
    priority: 10
    match:
      dst-port: 53
      protocol: 17  # UDP
    action: allow

  - name: allow-ssh
    priority: 20
    match:
      dst-port: 22
      protocol: 6   # TCP
    action: allow

  - name: deny-all
    priority: 999
    match: {}
    action: deny
```

## Performance Characteristics

The firewall achieves high performance through:

- **Lock-free fast path**: Established connections use read-only lookups (no synchronization)
- **Sharded conntrack**: 256 independent hash buckets reduce lock contention
- **Minimal allocations**: Packet metadata reused per packet
- **XXHash-based hashing**: Fast 64-bit hash for connection lookup
- **Data-plane design**: Processing loop optimized for modern CPUs

Benchmark results on modern hardware:

- **NEW connections**: ~5-10 microseconds
- **ESTABLISHED**: <1 microsecond (lock-free fast path)
- **Throughput**: >1 million packets/second per core

## Configuration

Firewall is configured via the `firewall:` section in the platform config:

```yaml
sdn:
  firewall:
    enabled: true
    default-policy: deny        # Default action for unmatched packets

    zones:
      - name: trusted
        interfaces:
          - eth0
        policy: allow

      - name: untrusted
        interfaces:
          - eth1
        policy: deny

    rules:
      - name: allow-established
        priority: 1
        match:
          src-zone: any
          dst-zone: any
        action: allow

      - name: deny-untrusted-to-trusted
        priority: 10
        match:
          src-zone: untrusted
          dst-zone: trusted
        action: deny

    nat:
      snat:
        - name: masquerade-trusted
          from-zone: trusted
          masquerade: true

      dnat:
        - name: forward-web
          dst-port: 80
          target-ip: 10.0.1.100
          target-port: 8080
          protocol: 6  # TCP

    timeouts:
      tcp-established: 5m
      tcp-close: 30s
      udp: 30s
      icmp: 30s
```

See [Configuration Reference](./configuration.md) for complete schema.

## Usage

### Initialize the Engine

```go
config := &firewall.Config{
    Enabled:       true,
    DefaultPolicy: "deny",
    Zones: []firewall.Zone{
        {
            Name:       "trusted",
            Interfaces: []string{"eth0"},
            Policy:     "allow",
        },
        {
            Name:       "untrusted",
            Interfaces: []string{"eth1"},
            Policy:     "deny",
        },
    },
    Rules: []firewall.Rule{
        {
            Name:     "allow-ssh",
            Priority: 10,
            Action:   firewall.ActionAllow,
            Match: firewall.RuleMatch{
                DstPort:  22,
                Protocol: 6,  // TCP
            },
        },
    },
}

engine, err := firewall.NewEngine(config)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()
```

### Process Packets

```go
ctx := context.Background()

pkt := &firewall.PacketInfo{
    SrcIP:    netip.MustParseAddr("10.0.1.10"),
    DstIP:    netip.MustParseAddr("10.0.2.20"),
    SrcPort:  52000,
    DstPort:  22,
    Protocol: 6,  // TCP
    InIface:  "eth0",
    OutIface: "eth1",
    Length:   60,
}

verdict, err := engine.FilterPacket(ctx, pkt)
if err != nil {
    log.Fatal(err)
}

switch verdict {
case firewall.ActionAllow:
    // Forward packet
case firewall.ActionDeny:
    // Drop packet
case firewall.ActionReject:
    // Drop packet and send ICMP error
}
```

### Get Statistics

```go
stats := engine.Stats()
fmt.Printf("Packets processed: %d\n", stats.PacketsProcessed.Load())
fmt.Printf("Packets allowed: %d\n", stats.PacketsAllowed.Load())
fmt.Printf("Packets denied: %d\n", stats.PacketsDenied.Load())
fmt.Printf("Packets NATted: %d\n", stats.PacketsNATted.Load())
fmt.Printf("Active connections: %d\n", stats.ActiveConnections.Load())
```

## Integration with Gateway

The firewall service integrates with the gateway node:

```go
if config.Firewall != nil && config.Firewall.Enabled {
    g.serviceHandlers[gateway.ServiceFirewall] = newFirewallServiceHandler(g)
}
```

When firewall service starts, it initializes the engine and installs packet hooks on all configured zones.

## See Also

- [Configuration Reference](./configuration.md) - Full config schema
- [Architecture Deep Dive](./architecture.md) - Internals and design
- [Performance Tuning](./performance.md) - Optimization guide
