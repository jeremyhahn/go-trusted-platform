# IPAM Configuration Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> IPAM pools and where they come from.

## Overview

IPAM holds the platform's address pools and their allocations. Since the
reference network (#708) the pools of an environment are **derived**, not
declared: the network plan (`pkg/sdn/netplan`, configured by
`sdn.environment`) produces one pool per underlay zone and one pool per range
of the environment's IPAM `/17`, and the control plane seeds them at startup.
`sdn.ipam.pools` only adds explicit pools beside them, for example a public
block or an overlay subnet carved from the tenant default range.

Every pool carries an **allocation window**:

- **Reserved prefixes** — never allocatable. The pool's gateway (the anycast
  or VRRP `.1`) is always reserved, listed or not. The tunnel range reserves
  its first `/31` for the gateway HA sync link.
- **Dynamic range** (`range_start`–`range_end`) — where `Allocate` draws
  addresses. A zone pool's range is its DHCP range, `.50` to the last usable
  address. Without a range the whole usable CIDR is the window.

`AllocateSpecific` may take a static address outside the dynamic range (a
control-plane node's `.10`, say) but never a reserved one; it refuses those
with the typed `ipam.ErrIPReserved`.

## Configuration Structure

```yaml
sdn:
  environment:
    id: 4                      # the plan derives every zone and range pool
  ipam:
    # Backend: "memory" (default), "quicbaas", or "dht" (platform_p2p builds)
    backend: quicbaas
    # Explicit pools beside the derived ones (seed-only).
    pools:
      - name: public
        cidr: 203.0.113.0/24
        gateway: 203.0.113.1
        range-start: 203.0.113.10
        range-end: 203.0.113.250
        lease-duration: 24h
```

## Derived Pools

For environment `E` on the default base `10.0.0.0/8`:

| Pool | Prefix | Reserved | Dynamic range |
|------|--------|----------|---------------|
| one per zone (`transit` … `backup`, owner zones) | the zone subnet, `10.E.n.0/24` | the gateway `.1` | `.50`–`.254` (none below a `/26`) |
| `tunnel-p2p` | `10.E.128.0/22` | `10.E.128.0/31` (gateway HA sync) | `10.E.128.2`–`10.E.131.255` |
| `loopbacks` | `10.E.132.0/22` | — | whole prefix |
| `service-vips` | `10.E.136.0/21` | — | whole prefix |
| `platform-hosts` | `10.E.144.0/20` | — | whole prefix |

The tenant default range `10.E.192.0/18` is not one pool: tenant overlay
subnets are carved from it, each a pool of its own. See
[reference network](../../architecture/reference-network.md) for the full
layout and budgets.

## Explicit Pool Parameters

`sdn.ipam.pools[]` (`sdn.PoolConfig`):

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | Yes | Unique pool name; may not take a derived pool's name |
| `cidr` | prefix | Yes | Address space; may not overlap a derived pool or a reserved range |
| `gateway` | address | No | Gateway address; always reserved |
| `zone` | string | No | A declared underlay zone; overlay pools carry none |
| `dns` | []address | No | Parsed; IPAM does not read it today |
| `range-start`, `range-end` | address | No | Dynamic allocation window; set both or neither |
| `lease-duration` | duration | No | Default lease duration (0 = never expires) |
| `dhcp` | bool | No | Parsed; IPAM does not read it today (no daemon serves DHCP, see [DHCP](../dhcp/README.md)) |

A pool's ID is its name, for derived and explicit pools alike
(`pkg/app/sdn.go:572`).

### Validation

| Rule | Error |
|------|-------|
| Name non-empty and unique | `sdn.ErrInvalidPoolName`, `sdn.ErrDuplicatePoolName` |
| Name not a derived pool's | `sdn.ErrPoolNameReserved` |
| CIDR valid | `sdn.ErrInvalidPoolCIDR` |
| No overlap with a derived pool or reserved range | `sdn.ErrPoolOverlap` |
| Zone, when set, declared | `sdn.ErrPoolZoneUndeclared` |
| Reserved prefixes inside the CIDR; range inside the CIDR, both bounds set, start ≤ end | `ipam.ErrInvalidWindow` (at pool creation) |
| Gateway inside the CIDR | `ipam.ErrInvalidGateway` |

## Seeding Semantics

The derived pools and `sdn.ipam.pools` are **seeds**, not runtime state. At
control-plane startup (`sdn.environment` is required; without it seeding fails
with `sdn.ErrEnvironmentRequired`) each pool is created if no pool of that name
exists in the backend; an existing pool and its allocations are never mutated
or deleted. An existing pool whose CIDR, gateway, range or reserved prefixes
differ from the seed stops startup with `ErrSDNIPAMPoolDrift`
(`pkg/app/sdn.go:553`). Removing a pool from configuration does not delete it from the
backend. Pre-release, the upgrade path is wipe and re-bootstrap, so a
changed environment means a fresh backend.

## Backend Selection

| Backend | Persistence | Consistency | Use |
|---------|-------------|-------------|-----|
| `memory` (default) | none | strong, single instance | development, tests |
| `quicbaas` | Raft log and snapshots (via the quicbaas SDK) | strong storage, but `Allocate` has no compare-and-swap: concurrent allocators can collide ([README](README.md#quicbaas-backend)) | production |
| `dht` | DHT, replicated | eventual, claim-based | P2P (`platform_p2p` build tag) |

`quicbaas` needs the top-level `quicbaas:` client (`sdn.ErrIPAMBackendUnconfigured`
otherwise) and is not built under `platform_p2p`; `dht` in a binary built
without `platform_p2p` fails with `sdn.ErrIPAMBackendP2PRequired`, and with it
still fails until something calls `app.RegisterDHTIPAMBackend` (nothing does
today). Any other name is `sdn.ErrIPAMBackendUnknown`. All three backends apply the same window
rules: `memory` and `quicbaas` hand out the lowest free address of the window,
`dht` draws random addresses inside it.

## Pool Size

`total` (`TotalIPs`) counts what can ever be allocated: the usable addresses of
the CIDR less the reserved ones. A `/24` zone pool therefore reports 253.
`available` is `total` less the current allocations. Both count static
addresses and the dynamic window together: a zone pool whose window
(`.50`–`.254`, 205 addresses) is full makes `Allocate` return
`ErrPoolExhausted` while `available` still counts the static addresses
`.2`–`.49` that `AllocateSpecific` can take. Very large IPv6 pools saturate at
the maximum `uint64`.

## Zone-Filtered Queries

```go
pools, err := allocator.ListPoolsByZone(ctx, "provisioning")
all, err := allocator.ListPoolsByZone(ctx, "") // every pool
```

An allocation is stamped with its pool's zone (`Allocation.Zone`).

## Allocation

```go
// Dynamic: the lowest free, unreserved address of the window (.50 first).
alloc, err := allocator.Allocate(ctx, &ipam.AllocationRequest{
    PoolID: "provisioning", DeviceID: "node-7",
})

// Static: any unreserved usable address, inside the window or not.
alloc, err = allocator.AllocateSpecific(ctx, &ipam.AllocationRequest{
    PoolID: "control-plane", DeviceID: "cp-01",
    RequestedIP: netip.MustParseAddr("10.4.6.10"),
})

// The gateway is refused.
_, err = allocator.AllocateSpecific(ctx, &ipam.AllocationRequest{
    PoolID: "control-plane", DeviceID: "x",
    RequestedIP: netip.MustParseAddr("10.4.6.1"),
})
var reserved *ipam.ErrIPReserved
errors.As(err, &reserved) // true
```

## See Also

- [Architecture](architecture.md) — IPAM architecture and design
- [API Reference](api-reference.md) — the window fields on every transport
- [SDN configuration](../configuration.md) — `sdn.environment` and zones
