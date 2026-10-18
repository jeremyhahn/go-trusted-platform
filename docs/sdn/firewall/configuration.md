# Firewall Configuration

> **Status: REFERENCE** · Last verified: 2026-10-15
> The firewall and NAT gateway service configuration.

The firewall and NAT services are config-driven gateway services: each
loads when its section is present with `enabled: true`. Policy itself is
not configured here — it is derived from the
[zone declarations](../../device-templates.md) and their compiled
allow/deny matrix.

## Firewall

```yaml
gateway:
  firewall:
    enabled: true
    default-policy: deny   # verdict-table miss: allow | deny
    bridge: br-int         # optional; overrides the runtime bridge
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Load the firewall service |
| `default-policy` | string | — (required) | Verdict for connections no matrix rule matched: `allow` continues the pipeline, `deny` drops |
| `bridge` | string | runtime bridge | OVS bridge carrying the conntrack pipeline |

Everything else — which zone may open connections to which, on which
VLANs and subnets — comes from the zone matrix. Adding or changing a zone
and calling `Gateway.ReconcileFirewall` converges the datapath without a
restart.

## NAT

```yaml
gateway:
  uplinks:
    - name: eth0
      mtu: 1500
  nat:
    enabled: true
    external-ip: 203.0.113.10
    port-range-start: 1024
    port-range-end: 65535
    max-sessions: 65536
    internal-cidr: 10.0.100.0/24   # optional: SNAT at service start
    uplink-port: eth0              # optional: defaults to first uplink
    bridge: br-int                 # optional; overrides the runtime bridge
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Load the NAT service |
| `external-ip` | string | — (required unless `uplinks` is set) | Public IPv4 address SNAT translates to and DNAT accepts on |
| `port-range-start` / `port-range-end` | uint16 | — (required, start < end) | L4 port range SNAT may allocate from |
| `max-sessions` | int | — (required, > 0) | Session ceiling (validation only; the kernel conntrack table enforces capacity) |
| `internal-cidr` | string | empty | IPv4 prefix whose egress is source-NATed at start; empty defers SNAT to `EnableSNAT` |
| `uplink-port` | string | first gateway uplink | OVS port name DNAT ingress matches on (`pkg/sdn/gateway/handlers.go:346`) |
| `bridge` | string | runtime bridge | OVS bridge carrying the NAT tables |
| `uplinks` | list | empty | One SNAT pool per uplink in place of `external-ip`; see below |
| `static` | list | empty | 1:1 translations, both directions, with hairpin; requires `uplinks` |

Each `uplinks` entry (`NATUplinkConfig`, `pkg/sdn/gateway/types.go:830`):
`name` (a gateway uplink), `port` (OVS port; defaults to `name`), `addresses`
(IPv4 addresses or inclusive ranges such as `192.0.2.4-192.0.2.5`),
optional `port-range-start` / `port-range-end` overriding the NAT-wide range,
`destinations` (IPv4 prefixes that leave through this uplink) and `default`
(the uplink for every other destination; the first uplink when none is
marked). Each `static` entry (`NATStaticConfig`) has `internal`, `external`
and an optional `uplink` (the default uplink when empty).

### SNAT / DNAT at runtime

The running NAT service (obtained via `Gateway.NATService()`) manages
translation rules:

```go
nat, ok := gw.NATService()
// SNAT
err := nat.EnableSNAT(ctx, netip.MustParsePrefix("10.0.100.0/24"))
err  = nat.DisableSNAT(ctx)
// DNAT: tcp 203.0.113.10:443 → 10.0.100.5:8443
err  = nat.AddDNAT(ctx, "tcp",
        netip.MustParseAddrPort("203.0.113.10:443"),
        netip.MustParseAddrPort("10.0.100.5:8443"))
err  = nat.RemoveDNAT(ctx, "tcp", netip.MustParseAddrPort("203.0.113.10:443"))
```

DNAT protocols are `tcp` and `udp`. All addresses are IPv4 (matching the
OVS NAT action encoder).

## Runtime Dependencies

Both services need live infrastructure the config file cannot carry: the
OVS client, the flow controller, and the zone providers. The daemon
injects them via `GatewayConfig.Runtime` (`gateway.GatewayRuntime`, never
serialized). `gatewayd serve` assembles the runtime from its `sdn:`
configuration section (OVSDB socket, bridge, zones, networks — see
`docs/gateway/engineering.md` §5); enabling `firewall` or `nat` without
that section fails assembly with `ErrSDNRequiredForService`, and a
runtime-less `Gateway.Start` fails with `ErrRuntimeMissing` — typed,
immediate errors rather than a silently inert service.

## Health

```go
fw, ok  := gw.FirewallHealth() // Active, FlowCount, LastReconcile, CTZones
nh, ok  := gw.NATHealth()      // Active, SNATEnabled, DNATRules, CTZone
```

## Inspecting the Datapath

```bash
ovs-ofctl -O OpenFlow13 dump-flows br-int table=20   # gates
ovs-ofctl -O OpenFlow13 dump-flows br-int table=21   # verdicts
ovs-ofctl -O OpenFlow13 dump-flows br-int table=25   # NAT
ovs-appctl dpctl/ct-stats-show                        # conntrack entries
```

Firewall flows carry cookie `0xf1be0001…`, NAT flows `0xf1be0002…`.

## See Also

- [README](./README.md) — overview
- [Architecture](./architecture.md) — table and flow design
- [Performance](./performance.md) — tuning
