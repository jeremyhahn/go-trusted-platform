# Firewall Architecture

The stateful firewall is a compiler and lifecycle manager for OVS
conntrack flows. Policy lives in the zone matrix (`pkg/sdn/zone`), flow
generation lives in `pkg/sdn/policy/zoneflows`
(`CompileStatefulMatrixRules`), and the service in
`pkg/sdn/gateway/services/firewall` installs, reconciles, and removes the
flows. Packets are filtered exclusively by the OVS datapath.

## Pipeline

The overlay pipeline (installed by `pkg/sdn/gateway/modes`) is
`0 → 10 → 30 → 40 → 50 → 60`. Tables 20, 21, and 25 are reserved for the
firewall/NAT services and are empty when they are disabled:

```
        table 0          table 10                 table 20               table 21
  ┌────────────┐   ┌────────────────┐      ┌─────────────────┐   ┌──────────────────────┐
  │  ingress   │──▶│  VXLAN decap   │─fw──▶│  conntrack gate │──▶│  conntrack verdict   │
  └────────────┘   │ (default→30;   │gate  │ ip: ct(zone=Z,  │   │ +inv → drop          │
                   │  fw diverts→20)│      │       table=21) │   │ +est/+rel → 30       │
                   └───────┬────────┘      │ non-ip → 30     │   │ +new: matrix verdict │
                           │(fw disabled)  │ nat diverts→25  │   │   allow: ct(commit)→30│
                           ▼               └─────────────────┘   │   deny:  drop        │
                    table 30 MAC learning ◀──────────────────────│ miss: default-policy │
                    table 40 ARP                       ▲         └──────────────────────┘
                    table 50 L3            table 25 NAT│
                    table 60 egress        ct(commit,nat(...)) ──┘
```

### Table 10 — activation gate

`installOpenFlowPipeline` installs the table 10 default (priority 0,
`goto_table:30`). The firewall service never edits that flow. Instead it
installs its own priority-2 catch-all `goto_table:20` in table 10 on
`Start` and strict-deletes it on `Stop`. The NAT service does the same at
priority 1 so the two gates are distinct OVS flows with independent
lifecycles (identical match+priority would make the second `OFPFC_ADD`
replace the first). With both services stopped, table 10 contains exactly
the flows the base pipeline installed — byte-identical to the
firewall-disabled build.

VXLAN-decapsulated traffic matches the per-VNI decap flows (priority 100,
`goto_table:30`) and therefore bypasses the ct pipeline; the firewall
gates the table 10 default path (native/VLAN traffic).

### Table 20 — conntrack gate

| Priority | Match | Actions |
|----------|-------|---------|
| 200 | `in_port=<uplink>,ip,nw_proto=P,nw_dst=EXT,tp_dst=PORT` | `ct(table=25,zone=Znat)` (per DNAT rule) |
| 200 | `dl_vlan=<zone VLAN>,ipv6,nw_proto=58,icmp_type=133…137` | `goto_table:30` (ICMPv6 neighbor discovery, per zone) |
| 100 | `dl_vlan=<zone VLAN>,ip` | `ct(table=21,zone=Z)` (per zone) |
| 100 | `dl_vlan=<zone VLAN>,ipv6` | `ct(table=21,zone=Z)` (per zone) |
| 90 | `ip,nw_src=<internal CIDR>` | `ct(table=25,zone=Znat)` (SNAT divert) |
| 1 | (any) | `goto_table:30` (non-IP / unclassified bypass) |

### Table 21 — conntrack verdict

| Priority | Match | Actions |
|----------|-------|---------|
| 400 | `ct_state=+inv+trk,dl_vlan=V` | `drop` |
| 300 | `ct_state=+est+trk,dl_vlan=V` | `goto_table:30` |
| 300 | `ct_state=+rel+trk,dl_vlan=V` | `goto_table:30` |
| 200 | `ct_state=+new+trk,dl_vlan=V,ip,nw_dst=<subnet>` | `drop` (denied matrix pair) |
| 200 | `ct_state=+new+trk,dl_vlan=V,ipv6,ipv6_dst=<subnet6>` | `drop` (denied matrix pair, IPv6 twin) |
| 100 | `ct_state=+new+trk,dl_vlan=V,ip,nw_dst=<subnet>` | `ct(commit,zone=Z),goto_table:30` (allowed pair) |
| 100 | `ct_state=+new+trk,dl_vlan=V,ipv6,ipv6_dst=<subnet6>` | `ct(commit,zone=Z),goto_table:30` (allowed pair, IPv6 twin) |
| 0 | (miss) | `default-policy`: `goto_table:30` or `drop` |

Matrix verdicts are emitted for every `(from, to)` zone pair with a
VLAN-backed source and subnet-backed destination — including intra-zone
(`from == to`) pairs, because once traffic is gated through conntrack,
intra-zone connections also need a commit verdict.

**The compiler is dual-stack (#554).** Every rule that matches an IP header is
emitted once per address family: the IPv4 rule and its IPv6 twin differ only in
the EtherType (`dl_type=0x0800` / `0x86dd`) and the destination field
(`nw_dst` / `ipv6_dst`). A network declares its IPv6 prefix with `subnet6:`; a
network without one still has its IPv6 traffic gated into conntrack and
subject to the same default policy — it simply has no per-prefix verdicts
addressed to it. ICMPv6 neighbor discovery (RS/RA/NS/NA/redirect) bypasses
conntrack ahead of the gate, exactly as ARP is permitted, because a segment
cannot resolve its gateway without it. Before #554 every match was IPv4-only,
so IPv6 frames matched nothing — including the default deny — and passed.
The `zoneflows` unit tests hold a static parity invariant: an IPv4 rule with
no IPv6 twin at the same table, priority and action fails the build.

### Table 25 — NAT

| Priority | Match | Actions |
|----------|-------|---------|
| 400 | `ct_state=+inv+trk` | `drop` |
| 300 | `ct_state=+est+trk` / `+rel+trk` | `goto_table:30` (translation auto-applied) |
| 200 | `ct_state=+new+trk,in_port=<uplink>,…` | `ct(commit,zone=Znat,nat(dst=IP:port)),goto_table:30` (per DNAT rule) |
| 100 | `ct_state=+new+trk,ip,nw_src=<internal>` | `ct(commit,zone=Znat,nat(src=EXT:pmin-pmax)),goto_table:30` (SNAT) |
| 0 | (miss) | `goto_table:30` |

When both services are active, VLAN-tagged zone traffic is claimed by the
firewall gates (priority 100) and is not source-NATed; SNAT applies to
traffic no zone gate claimed (untagged/routed), and DNAT outranks the zone
gates so inbound public traffic is translated before zone policy applies.

## Conntrack Zone Allocation

`pkg/sdn/ct.ZoneAllocator` hands out disjoint 16-bit conntrack zone IDs
(1–65535; zone 0 is the kernel default and reserved) to named owners:
`firewall/<zone-name>`, `nat/default`, `lb/<vip>`. Allocation is
deterministic — a truncated xxhash of `owner/key` picks the slot, linear
probing resolves collisions — so restarts converge on the same layout.
The authoritative snapshot can additionally be persisted as JSON in the
bridge `external_ids` column (`trusted-platform-ct-zones` key) via
`OVSExternalIDsPersister`, surviving daemon restarts alongside the bridge.

## Flow Ownership and Teardown

Every flow carries an owner cookie:

| Owner | Cookie | Mask |
|-------|--------|------|
| Firewall | `0xF1BE000100000000` | `0xFFFFFFFF00000000` |
| NAT | `0xF1BE000200000000` | `0xFFFFFFFF00000000` |

- **Stop** removes the table 10 gate first (strict delete: exact
  table/priority/match/cookie), then sweeps everything else with one
  cookie-masked `OFPFC_DELETE`, then releases the conntrack zones.
- **Reconcile** recompiles from the current zone set, batch-installs
  changed/missing rules (`OFPFC_ADD` replaces identical match+priority
  entries), then strict-deletes stale rules — the pipeline is never empty
  mid-update.

Strict deletion matters: a non-strict delete matches every flow at least
as specific as the given match regardless of priority, which could remove
neighboring rules. `DeleteFlowStrict` (`pkg/sdn/ovs`) pins table,
priority, match, and full-mask cookie.

## Component Map

| Component | Responsibility |
|-----------|----------------|
| `pkg/sdn/zone` | Zone schema, matrix compilation (`CompileMatrix`) |
| `pkg/sdn/policy/zoneflows` | `CompileStatefulMatrixRules` — matrix → ct flow strings |
| `pkg/sdn/ct` | Conntrack zone allocator + external_ids persistence |
| `pkg/sdn/ovs` | Match/action string grammar (`ct_state`, `ct()`, `nat()`, `goto_table`), cookie/strict deletes |
| `pkg/sdn/openflow` | Wire encoders: `ActionCT`, `ActionNAT`, conntrack OXM fields |
| `pkg/sdn/gateway/services/firewall` | Service lifecycle: Start/Stop/Reconcile/Health, SNAT/DNAT management |
| `pkg/sdn/gateway` (node.go) | `firewall`/`nat` service handlers, runtime dependency injection |

## See Also

- [README](./README.md) — overview and enablement
- [Configuration](./configuration.md) — config reference
- [Performance](./performance.md) — datapath performance and tuning
