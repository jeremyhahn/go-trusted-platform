# Firewall Architecture

> **Status: REFERENCE**
> How zone policy compiles to OVS conntrack flows.

The stateful firewall is a compiler and lifecycle manager for OVS
conntrack flows. Policy lives in the zone matrix (`pkg/sdn/zone`), flow
generation lives in `pkg/sdn/policy/zoneflows`
(`CompileStatefulMatrixRules`), and the service in
`pkg/sdn/gateway/services/firewall` installs, reconciles, and removes the
flows. Packets are filtered exclusively by the OVS datapath.

## Pipeline

The overlay pipeline (installed by `pkg/sdn/gateway/modes`) is
`0 → 10 → 30 → 40 → 50 → 60`. Tables 20, 21, 25, 26 and 27 are reserved for
the firewall, NAT, load-balancer and NAT64 services and are empty when they
are disabled:

```
        table 0          table 10                 table 20               table 21
  ┌────────────┐   ┌────────────────┐      ┌─────────────────┐   ┌──────────────────────┐
  │  ingress   │──▶│  VXLAN decap   │─fw──▶│  conntrack gate │──▶│  conntrack verdict   │
  └────────────┘   │ (default→30;   │gate  │ ip: ct(zone=Z,  │   │ +inv → drop          │
                   │  fw diverts→20)│      │       table=21) │   │ +est/+rel → 30       │
                   └───────┬────────┘      │ miss → 30       │   │ +new: matrix verdict │
                           │(fw disabled)  │ nat diverts→25  │   │   allow: ct(commit)→30│
                           ▼               └─────────────────┘   │   deny:  drop        │
                    table 30 MAC learning ◀──────────────────────│ miss: default-policy │
                    table 40 ARP                       ▲         └──────────────────────┘
                    table 50 L3            table 25 NAT│
                    table 60 egress        ct(commit,nat(...)) ──┘
```

### Table 10 — activation gate

The gateway's base pipeline (`GatewayRuntime.EnsurePipeline`,
`pkg/sdn/gateway/pipeline.go`) installs the table 10 default (priority 0,
`goto_table:30`). The firewall service never edits that flow. Instead it
installs its own priority-2 catch-all `goto_table:20` in table 10 on
`Start` and strict-deletes it on `Stop`. The NAT service does the same at
priority 1, the load balancer at priority 3 and the NAT64 service at
priority 4, so the gates are distinct OVS flows with independent lifecycles.
Identical match+priority would make the second `OFPFC_ADD` replace the
first: OpenFlow identifies a flow by (table, priority, match), and the
cookie scopes deletion rather than distinguishing flows on install, so two
services on one priority share a single resident gate and whichever owns its
cookie removes the other's gate on `Stop`. One priority per service, and
`TestGatewayGates_Table10PriorityIsUnique` holds them to it. With every service stopped,
table 10 contains exactly the flows the base pipeline installed —
byte-identical to the firewall-disabled build.

The NAT64 gate is why the service works on a gateway running neither the
firewall nor NAT: without it nothing enters table 20, and the divert below
would be installed but unreachable.

VXLAN-decapsulated traffic matches the per-VNI decap flows (priority 100,
`goto_table:30`) and therefore bypasses the ct pipeline; the firewall
gates the table 10 default path (native/VLAN traffic).

### Table 20 — conntrack gate

| Priority | Match | Actions |
|----------|-------|---------|
| 220 | `ip,nw_src=<internal CIDR>,nw_dst=EXT` | `ct(table=25,zone=Znat)` (hairpin divert, per static 1:1) |
| 210 | `in_port=<uplink>,ip,nw_dst=EXT` / `ip,nw_src=INT` | `ct(table=25,zone=Znat)` (static 1:1 divert, ingress / egress) |
| 200 | `in_port=<uplink>,ip,nw_proto=P,nw_dst=EXT,tp_dst=PORT` | `ct(table=25,zone=Znat)` (per DNAT rule) |
| 200 | `dl_vlan=<zone VLAN>,ipv6,nw_proto=58,icmp_type=133…137` | `goto_table:30` (ICMPv6 neighbor discovery, per zone) |
| 100 | `dl_vlan=<zone VLAN>,ip` | `ct(table=21,zone=Z)` (per zone) |
| 100 | `dl_vlan=<zone VLAN>,ipv6` | `ct(table=21,zone=Z)` (per zone) |
| 95 | `ip,nw_src=<internal CIDR>,nw_dst=<uplink destination prefix>` | `load:<selector>->NXM_NX_REG0[],ct(table=25,zone=Znat)` (uplink selection, multi-uplink NAT) |
| 90 | `ip,nw_src=<internal CIDR>` | `ct(table=25,zone=Znat)` — with `load:<default selector>->NXM_NX_REG0[]` in multi-uplink mode (SNAT divert) |
| 80 | `ipv6` | `goto_table:30` (NAT44 only: IPv6 passes untranslated, ND included) |
| 0 | (miss) | `goto_table:30` — the base pipeline's flow (`CookiePipeline`), not a service's |

**The table-20 miss belongs to the pipeline (#614).**
Every datapath service gates table 10 into table 20 with an empty-match flow
and then claims only the frames it handles there, so what none of them
claims needs one disposition that no single service owns. OVS's own table
miss is a drop. When each service carried its own miss, NAT and NAT64 on
their own carried none and dropped every unclaimed frame (ARP, neighbour
discovery, all other IPv4 and IPv6), and the firewall's (priority 1) and the
load balancer's (priority 0) were two flows where one would do, the second
of them identical to any third a service added — one OpenFlow flow that
either service's cookie-scoped `Stop` deleted from under the other. The
pipeline installs it once; no service installs an empty-match table-20
flow. `TestPipelineInvariant_EveryGatedTableHasAMiss` starts each datapath
service alone and asserts every table a gate or a `goto` routes into has an
empty-match miss; `TestPipelineInvariant_TheTableTwentyMissIsThePipelines`
asserts there is exactly one in table 20 and it carries the pipeline's
cookie.

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
| 260 | `ct_state=+new+trk,ip,nw_src=<internal CIDR>,nw_dst=EXT` | `ct(commit,zone=Znat,nat(dst=INT)),ct(commit,zone=Znat,nat(src=EXT)),goto_table:30` (hairpin: one entry carries both translations, so the inside server's reply is un-NATed on the way back) |
| 250 | `ct_state=+new+trk,in_port=<uplink>,ip,nw_dst=EXT` / `…,ip,nw_src=INT` | `ct(commit,zone=Znat,nat(dst=INT))` / `nat(src=EXT)` `,goto_table:30` (static 1:1, both directions; outranks pool SNAT so a 1:1 host never falls into the pool) |
| 200 | `ct_state=+new+trk,in_port=<uplink>,…` | `ct(commit,zone=Znat,nat(dst=IP:port)),goto_table:30` (per DNAT rule) |
| 100 | `ct_state=+new+trk,ip,nw_src=<internal>` | `ct(commit,zone=Znat,nat(src=EXT:pmin-pmax)),goto_table:30` (SNAT, single-address mode) |
| 100 | `ct_state=+new+trk,ip,nw_src=<internal>,reg0=<selector>` | `ct(commit,zone=Znat,nat(src=POOL:pmin-pmax)),goto_table:30` (SNAT per uplink pool; `POOL` is one address or an inclusive range `a-b`) |
| 0 | (miss) | `goto_table:30` |

**Multi-uplink NAT (#586).** With `uplinks:` configured, the uplink an egress
connection leaves through is chosen at the table-20 divert and carried in
`reg0` (uplink index + 1; registers survive the `ct(table=25)` recirculation):
the default uplink's divert at priority 90 loads its selector, and every
destination prefix another uplink claims loads that uplink's selector at
priority 95 — the platform's equivalent of the ASRs' per-ISP routing. Table 25
then commits each selector to its own pool. Statics and DNAT bindings are bound
to the uplink whose pool or static set owns the external address (the default
uplink otherwise), so their `in_port` is that uplink's port. IPv6 is passed
untranslated at priority 80 — the service is NAT44; NAT66/NPTv6 are out of
scope by design. OVS exposes no per-pool exhaustion counter (`ct-stats` counts
entries, not free ports), so `NATHealth.Uplinks[].PoolExhaustion` is always
false and documents the gap: exhaustion is observable only as new connections
failing to commit.

When both services are active, VLAN-tagged zone traffic is claimed by the
firewall gates (priority 100) and is not source-NATed; SNAT applies to
traffic no zone gate claimed (untagged/routed), and DNAT outranks the zone
gates so inbound public traffic is translated before zone policy applies.

### Table 27 — NAT64 hand-off

Table 27 belongs to the `nat64:` service (#601, ruling R6). OVS `ct(nat)`
cannot rewrite between address families, so translation is never an OpenFlow
action: the pipeline's whole job is to deliver frames addressed to the RFC
6052 translation prefix to the translator's port, where the Jool kernel
instance's netfilter hooks see them.

The flows are installed as one unit, and only as one unit — a
`goto_table:27` with nothing routing into 27 programs nothing while
reporting success:

| Table | Priority | Match | Action |
|---|---|---|---|
| 10 | 4 | (catch-all) | `goto_table:20` |
| 20 | 210 | `dl_type=0x86dd[,dl_vlan=V],ipv6_dst=<prefix>` | `goto_table:27` |
| 27 | 110 | `dl_type=0x86dd,vlan_vid=0x1000/0x1000,ipv6_dst=<prefix>` | `strip_vlan,mod_dl_dst:<translator MAC>,output:<translator port>` |
| 27 | 100 | `dl_type=0x86dd,ipv6_dst=<prefix>` | `mod_dl_dst:<translator MAC>,output:<translator port>` |
| 27 | 0 | (miss) | `goto_table:30` |

**The hand-off re-addresses the frame.** It arrives addressed to the zone's
router MAC. Output unchanged, the translator interface receives a frame for
another host (`PACKET_OTHERHOST`) and the kernel drops it in `ipv6_rcv`,
before the `PREROUTING` hook where Jool translates; a frame still carrying
its 802.1Q tag is not an IPv6 packet to the host at all. So the hand-off
rewrites the destination to the translator port's own MAC (read from OVSDB
`mac_in_use` at Start and on every reconcile) and strips the tag. The NAT64
VM suite (`make integration-test-nat64`) proves both: with the rewrite
removed, the translated ping goes unanswered.

The divert at 210 outranks the firewall's per-zone gate (100) and NAT's
IPv6 pass (80), on the same reasoning as the DNAT divert: a frame addressed
to the translation prefix has no other disposition, because nothing routes
`64:ff9b::/96`. The alternative to translating it is dropping it for want of
a route, not adjudicating it against the zone matrix.

Zone policy is expressed at the gate instead. `client-zones:` names the
zones whose frames are diverted, matching each zone's VLAN; a zone that is
not named gets no translation. An empty list diverts every frame addressed
to the prefix.

The table-27 miss continues to table 30, so the table is never a black hole
for traffic that reaches it and matches nothing.

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
| Load balancer | `0xF1BE000300000000` | `0xFFFFFFFF00000000` |
| NAT64 | `0xF1BE000400000000` | `0xFFFFFFFF00000000` |
| Base pipeline | `0xF1BE000000000000` | `0xFFFFFFFF00000000` |

Every owner sweeps with the same mask, so the owner id in the high 32 bits
must be unique across services: two services sharing one delete each other's
flows on `Stop`, silently, while both keep reporting themselves healthy.
`TestServiceFlowCookies_OwnerIDsAreUnique` (`pkg/sdn/gateway`) holds the
registry to that.

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
