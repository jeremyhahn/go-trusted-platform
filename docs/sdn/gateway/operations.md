# Gateway Operations Guide

## Overview

This guide covers day-to-day operations for gateway nodes: mode
management, BGP operations, load balancer / VIP management, IP address
management, health monitoring, and performance verification.

The gateway CLI surface is `platformctl sdn gateway` with the
subcommands `status`, `mode set`, `bgp`, `lb`, and `perf`. Every
command works over all client protocols (REST, gRPC, QUIC, MCP, Unix).

## Gateway Mode Management

### Viewing Gateway Status

```bash
platformctl sdn gateway status
platformctl sdn gateway status -o json
```

Shows the gateway ID and node ID, active modes (overlay, edge,
transit), speaker tier (backbone, datacenter, coordinator),
reputation, uptime, and health status.

### Setting Gateway Modes

```bash
# Overlay only
platformctl sdn gateway mode set --modes overlay

# Overlay + edge
platformctl sdn gateway mode set --modes overlay,edge

# All three modes
platformctl sdn gateway mode set --modes overlay,edge,transit
```

Available modes:

- `overlay`: VXLAN/EVPN overlay networking
- `edge`: IoT device onboarding and P2P gateway
- `transit`: BGP route announcement

`mode set` replaces the active mode set, so pass the complete list of
modes the gateway should run. Verify the result with
`platformctl sdn gateway status`.

### Mode Prerequisites

| Mode | Prerequisites | Verification |
|------|---------------|--------------|
| Overlay | OVS running, VTEP IP assigned | `ovs-vsctl show`, `platformctl sdn overlay status` |
| Edge | Public IP, TLS certificates | `platformctl sdn gateway status` |
| Transit | BGP ASN assigned, peering configured | `platformctl sdn gateway bgp status` |

## BGP Operations

```bash
# Speaker status: local ASN, router ID, peer counts, announced prefixes
platformctl sdn gateway bgp status

# List configured peers
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp peers -o json

# Announce a prefix
platformctl sdn gateway bgp announce --prefix 2602:F5BB::/36
platformctl sdn gateway bgp announce --prefix 23.143.36.0/24 --next-hop 10.0.0.1

# Withdraw a previously announced prefix
platformctl sdn gateway bgp withdraw --prefix 2602:F5BB::/36

# List currently announced prefixes
platformctl sdn gateway bgp routes
```

For BGP session diagnostics see
[BGP Troubleshooting](../bgp/troubleshooting.md).

## Health Monitoring

Gateway-level health is part of `platformctl sdn gateway status`;
daemon-wide health is available via `platformctl health` and the
platform API:

| Endpoint | Protocol | Purpose |
|----------|----------|---------|
| `/health` | HTTP | Overall daemon health |
| `/metrics` | HTTP | Prometheus metrics |
| gRPC health service | gRPC | gRPC health check |

## Load Balancer Management

VIPs are implemented as OVS OpenFlow select groups (hash-based
selection, per-connection sticky via conntrack) with DNAT applied in
the datapath. Backends are specified as `address:port` or
`address:port:weight` (weight defaults to 1). See
[Load Balancer](loadbalancer.md) for the full design.

### VIP Operations

```bash
# Load balancer health: active state, VIP count, healthy/total backends
platformctl sdn gateway lb status

# Add a VIP with two weighted backends
platformctl sdn gateway lb vip add --protocol tcp --address 10.100.0.10 --port 443 \
  --backend 10.0.1.5:8443:2 --backend 10.0.1.6:8443

# List all VIPs
platformctl sdn gateway lb vip list
platformctl sdn gateway lb vip list -o json

# Show one VIP including per-backend health
platformctl sdn gateway lb vip get --protocol tcp --address 10.100.0.10 --port 443

# Remove a VIP
platformctl sdn gateway lb vip remove --protocol tcp --address 10.100.0.10 --port 443
```

Notes:

- `--protocol` accepts `tcp` or `udp` (default `tcp`).
- `--algorithm` on `vip add` accepts `hash` or `round-robin`; both map
  to select-group `dp_hash` balancing. `least-conn` is not supported
  by the OVS datapath.

### Backend Management

There are no per-backend add/remove/drain commands; the backend set is
replaced atomically with `vip set-backends`:

```bash
# Replace the backend set (add, remove, or reweight backends)
platformctl sdn gateway lb vip set-backends --protocol tcp --address 10.100.0.10 --port 443 \
  --backend 10.0.1.7:8443 --backend 10.0.1.8:8443:3
```

To take a backend out of rotation, issue `vip set-backends` with the
remaining backends. Existing conntrack-pinned connections to a removed
backend are not force-closed.

## IP Address Management

IPAM is managed with `platformctl sdn ipam` (a sibling of the gateway
command, not a gateway subcommand):

```bash
# Pool operations
platformctl sdn ipam pool list
platformctl sdn ipam pool list --zone trusted

# Allocate an IP to a device
platformctl sdn ipam allocate --pool-id pool1 --device-id vm-123 --hostname webserver

# Release an allocated IP
platformctl sdn ipam release --ip 10.0.0.5

# List allocations (all pools, or one pool)
platformctl sdn ipam allocations
platformctl sdn ipam allocations --pool-id pool1
```

See [IPAM](../ipam/README.md) for the full pool lifecycle
(`pool create/update/delete/get`).

## Performance Verification

`platformctl sdn gateway perf` reports REAL datapath measurements only —
flow programming is timed against the live bridge with a monotonic
clock, and datapath / conntrack values are read straight from
ovs-vswitchd counters. The command works over every protocol (REST,
gRPC, QUIC, MCP, Unix).

```bash
# Measure OpenFlow programming throughput: installs ephemeral flows in
# the dedicated perf table (250, cookie 0xf1be00ff00000000), times the
# install, then removes them with a cookie-scoped delete. MUTATES the
# bridge flow tables (requires sdn:write).
platformctl sdn gateway perf flows --count 1000 --batch
platformctl sdn gateway perf flows --count 1000 --bridge br-int

# Live datapath counters: flow-cache hits/misses/lost, hardware-offloaded
# flow count, hw-offload config state, bridge datapath type (sdn:read).
platformctl sdn gateway perf datapath
platformctl sdn gateway perf datapath --bridge br-int -o json

# Conntrack table summary: total entries + per-zone counts (sdn:read).
platformctl sdn gateway perf conntrack
platformctl sdn gateway perf conntrack --zone 12
```

Sample output shape (illustrative FORMAT only — the values below are
placeholders, not measurements):

```json
// perf flows
{"installed": <count>, "duration_ns": <measured>, "flows_per_second": <measured>, "batched": true, "bridge": "br-int"}

// perf datapath
{"hits": <live>, "misses": <live>, "lost": <live>, "offloaded_flow_count": <live>, "hw_offload_enabled": false, "datapath_type": "system", "bridge": "br-int"}

// perf conntrack
{"total_entries": <live>, "per_zone": {"<zone>": <live>}}
```

The equivalent raw OVS commands remain available on the gateway node:

```bash
# Datapath packet/byte/flow statistics (megaflow cache hit rate)
ovs-appctl dpctl/show -s

# Hardware-offloaded datapath flows
ovs-appctl dpctl/dump-flows type=offloaded

# Per-flow packet/byte counters
ovs-ofctl dump-flows br-int

# Conntrack entries (optionally zone-scoped)
ovs-appctl dpctl/dump-conntrack

# Interface throughput and drops
ip -s link show
```

For the 400G hardware-offload validation procedure see
[performance/x10-lab-validation.md](../performance/x10-lab-validation.md).

## Performance Tuning

Standard host-level tuning applies: enable RSS/multiqueue on the
datapath NICs (`ethtool -L`), raise socket buffer limits
(`net.core.rmem_max` / `wmem_max`) for high-throughput links, and
enable NIC offloads (checksum, TSO, VXLAN) where the hardware
supports them.

## Diagnostic Commands Summary

```bash
# Gateway status (modes, tier, health)
platformctl sdn gateway status

# BGP speaker and peers
platformctl sdn gateway bgp status
platformctl sdn gateway bgp peers

# Load balancer health and VIPs
platformctl sdn gateway lb status
platformctl sdn gateway lb vip list

# IP allocations
platformctl sdn ipam allocations | head -20

# Performance verification (real measurements)
platformctl sdn gateway perf datapath
platformctl sdn gateway perf conntrack
platformctl sdn gateway perf flows --count 1000 --batch
```

## Maintenance Checklist

### Daily Checks

- [ ] Gateway status (`platformctl sdn gateway status`)
- [ ] BGP peer status (if transit mode)
- [ ] Load balancer / VIP backend health

### Weekly Checks

- [ ] Datapath and conntrack counters (`perf datapath`, `perf conntrack`)
- [ ] IPAM pool utilization
- [ ] Connection trends

### Monthly Checks

- [ ] Capacity planning review
- [ ] Certificate expiration check

## See Also

- [Architecture](architecture.md) - Gateway architecture overview
- [Configuration](configuration.md) - Configuration reference
- [Overlay Mode](overlay-mode.md) - SDN overlay operations
- [Edge Mode](edge-mode.md) - Edge gateway operations
- [Transit Mode](transit-mode.md) - BGP transit operations
- [Load Balancer](loadbalancer.md) - Load balancer configuration
- [BGP Troubleshooting](../bgp/troubleshooting.md) - BGP-specific troubleshooting
