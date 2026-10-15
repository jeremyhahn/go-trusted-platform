# Stateful Firewall

> **Status: REFERENCE** · Last verified: 2026-10-15
> The OVS-native stateful firewall and NAT of the SDN gateway.

OVS-native stateful firewall and NAT for the trusted-platform SDN gateway.
All enforcement happens in the OVS kernel datapath using connection
tracking (`ct()` / `ct_state`) flows — there is no userspace packet path.
The former Go userspace firewall engine (`pkg/sdn/firewall`) has been
deleted; `pkg/sdn/gateway/services/firewall` compiles policy into flows and
manages their lifecycle, nothing more.

## How It Works

The [zone matrix](../../architecture/reference-network.md) is the single
source of truth for inter-zone policy. The firewall service compiles it
into conntrack flows in two dedicated tables of the gateway's base OpenFlow
pipeline (`pkg/sdn/gateway/pipeline.go`). The firewall, NAT and load
balancer are refused beside an enabled overlay
(`ErrOverlayServiceConflict`, `pkg/sdn/gateway/types.go:1421`).

| Table | Role |
|-------|------|
| 10 | Base pipeline ingress; its default continues to table 30. The firewall installs a priority-2 diversion flow here; the base pipeline is untouched |
| 20 | Conntrack gate — per-zone `ip` flows send traffic through `ct(zone=Z)` |
| 21 | Conntrack verdict — `+est`/`+rel` fast-path, `+inv` drop, `+new` consults the zone matrix |
| 25 | NAT — `ct(commit, nat(...))` SNAT/DNAT commits (NAT service) |
| 30 | MAC learning — traffic re-enters the base pipeline here |

- **New connections** (`ct_state=+new+trk`) are checked against the
  compiled matrix: allowed zone pairs get `ct(commit)` and continue;
  denied pairs drop.
- **Established/related connections** short-circuit through a high-priority
  fast path — the matrix is consulted once per connection, not per packet.
- **Invalid conntrack state** is dropped.
- **The verdict table miss** applies `default-policy` (`allow` or `deny`).

Each zone gets its own conntrack zone ID from the `pkg/sdn/ct` allocator,
so per-zone connection state is partitioned in the kernel tracker. NAT
uses a further disjoint conntrack zone.

## Enabling

```yaml
gateway:
  firewall:
    enabled: true
    default-policy: deny   # allow | deny
  nat:
    enabled: true
    external-ip: 203.0.113.10
    port-range-start: 1024
    port-range-end: 65535
    internal-cidr: 10.0.100.0/24   # enables SNAT at start
    max-sessions: 65536
```

When `firewall.enabled` is false, nothing changes: the firewall installs
zero flows and the base pipeline is byte-identical to a build without
the feature.

## Behavior Guarantees

- **No userspace data path.** Once flows are installed, packets never
  leave the kernel (or the NIC, with hardware offload).
- **Additive activation.** The service diverts table 10 into the ct
  pipeline with a single flow it owns; stopping the service removes the
  diversion first, then sweeps its flows by cookie. The base pipeline is
  never edited.
- **Deterministic teardown.** Every firewall flow carries cookie
  `0xF1BE0001…`, every NAT flow `0xF1BE0002…`; teardown is one
  cookie-masked `OFPFC_DELETE`.
- **Hot reconcile.** Zone changes are converged by installing
  changed/missing flows first and strict-deleting stale ones after, so the
  pipeline is never empty mid-update.

## Documentation

- [Architecture](./architecture.md) — table design, flow layout, cookies,
  conntrack zone allocation
- [Configuration](./configuration.md) — config reference and NAT rule
  management
- [Performance](./performance.md) — datapath performance characteristics
  and tuning
