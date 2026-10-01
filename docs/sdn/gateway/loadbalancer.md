# Load Balancer

The gateway load balancer is an OVS-native L4 load balancer implemented in
`pkg/sdn/gateway/services/loadbalancer`. All balancing happens in the OVS
datapath: VIP traffic is spread across backends by an OpenFlow **select
group** (hash-based bucket selection) and translated by **conntrack DNAT**
committed in the group buckets. The Go service only compiles VIPs into
flows/groups, probes backend health, and manages lifecycle — no packet ever
traverses userspace.

## Capabilities

| Feature | Implementation |
|---------|----------------|
| VIP management | `tcp`/`udp` IPv4 VIPs, config-driven at start plus runtime CRUD |
| Algorithms | `hash` and `round-robin` (both map to select-group dp_hash selection) |
| Session persistence | Per-connection stickiness via conntrack (committed DNAT state) |
| Health probes | TCP connect probes with rise/fall hysteresis |
| Weighted backends | Select-group bucket weights (`weight`, default 1) |
| Fail-closed | Zero healthy backends → bucketless group → new connections drop |
| Reply translation | A backend's replies are reverse-translated so the client hears from the VIP (#718) |
| Hairpin | Clients on a `hairpin-prefixes` network are source-NATed to the VIP, so a backend on their segment answers through the gateway |
| Recovery | Deterministic group IDs + `GetGroupDesc` reconciliation on start |

**Not supported:** `least-conn` is rejected with the typed
`ErrAlgorithmUnsupported` error — per-connection bookkeeping cannot be
expressed in the OVS group datapath. UDP VIPs are **unprobed** (there is no
protocol-agnostic UDP liveness signal); their backends are treated as
always healthy and a warning is logged when a UDP VIP is installed.

### Algorithm semantics

Both accepted algorithm names program an `OFPGT_SELECT` group. OVS picks
the bucket from the datapath flow hash (`dp_hash`), weighted by the bucket
weights. This means:

- Selection is **per connection**, not per packet. `round-robin` is an
  accepted alias, documented as hash-based selection — successive
  connections from distinct 5-tuples spread across buckets, but there is no
  strict rotation.
- Once a connection is committed, conntrack pins it to its backend for the
  connection lifetime (stickiness survives group rebuilds).

## Datapath design

The load balancer integrates with the shared conntrack pipeline used by
the firewall (tables 20/21) and NAT (table 25) services. It owns tables 26,
28 and 29 (table 27 is the NAT64 hand-off, #601) and cookie
`0xF1BE0003_00000000` (mask `0xFFFFFFFF00000000`; firewall is
`0xF1BE0001…`, NAT `0xF1BE0002…`).

```
table 10 (gate)      priority 3: goto_table:20            [LB gate]
                     (firewall gate = prio 2, NAT gate = prio 1; all
                      three are distinct flows and tear down independently)

table 20 (ct gate)   priority 260 per backend B:P of every VIP (reply divert):
                       reg1=0/0x1,ip,nw_proto=P,nw_src=B,tp_src=P
                         -> load:1->reg1[0], ct(table=29,zone=Zhairpin,nat)
                     priority 250 per VIP (request divert):
                       ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> ct(table=26,zone=Zvip,nat)
                     priority 0 miss: goto_table:30

table 26 (dispatch)  priority 400: ct_state=+inv+trk           -> drop
                     priority 300: ct_state=+est+trk           -> goto_table:28
                     priority 300: ct_state=+rel+trk           -> goto_table:28
                     priority 200 per VIP:
                       ct_state=+new+trk,ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> group:G
                     priority 0 miss:                          -> drop

group G (select)     one bucket per healthy backend, weight = backend weight
                       ct(commit,zone=Zvip,nat(dst=B:P),table=28)

table 28 (hairpin)   priority 200 per VIP per hairpin prefix H:
                       ct_state=+new+trk,ct_zone=Zvip,ip,nw_src=H
                         -> ct(commit,zone=Zhairpin,nat(src=VIP),table=30)
                       ct_state=+est+trk,ct_zone=Zvip,ip,nw_src=H
                         -> ct(zone=Zhairpin,nat,table=30)
                     priority 0 miss:                          -> goto_table:30

table 29 (reply)     priority 200 per backend B:P (back from the hairpin zone):
                       ct_zone=Zhairpin,ip,nw_proto=P,nw_src=B,tp_src=P
                         -> ct(table=29,zone=Zvip,nat)
                     priority 100: ct_state=+est+rpl+trk       -> goto_table:30
                     priority 0 miss:                          -> resubmit(,20)
```

### Replies are reverse-translated (#718)

A VIP connection is DNATed: the client sends to `VIP:PORT` and the backend
receives from the client. The backend's reply carries the backend's address,
`B:P -> client`, so the request divert, which matches `nw_dst=VIP`, never sees
it. Until #718 nothing else did either: the reply reached the client from
`B:P`, an address it never connected to, and the client answered the SYN-ACK
with a reset. No TCP connection through a VIP could complete.

The service now installs a **reply divert per backend**. It is keyed on the
backend's source address and port, and runs `ct(nat)` in the hairpin zone
(table 20), then in the VIP's zone (table 29). Conntrack reverses whatever
translations the connection was committed with, so the client receives
`VIP:PORT -> client`. Both lookups recirculate into table 29, and `ct_zone`
tells them apart: the per-backend flow takes a packet back from the hairpin
zone; a packet back from the VIP zone falls to the verdicts.

**A backend's own traffic is left alone.** The divert matches by source
address:port, so it also catches traffic the backend sends from its service
port that has nothing to do with the VIP, such as a client that connects to
the backend directly. Table 29 lets only `+est+rpl` (a reply of a committed VIP
connection) continue. Everything else is resubmitted to table 20 with
register 1 bit 0 set. The reply divert matches only packets with that bit
clear, so the packet then meets the firewall and NAT gates exactly as if the
load balancer were not installed. The NAT service owns register 0.

**One backend endpoint, one VIP.** Because the reply divert is keyed on the
backend's address:port alone, that endpoint's replies can be steered into one
VIP zone only. A backend `address:port` that already serves another VIP of the
same protocol is refused with `ErrBackendInUse`. This applies at configuration
validation, `AddVIP` and `SetBackends`. The same endpoint behind a TCP VIP and a
UDP VIP is fine: they are different tuples.

### Hairpin source NAT

A client on the same segment as its backend is the case reply translation
alone cannot fix. The gateway forwards the DNATed request back out the port it
arrived on, and the backend sees the client's own address on-link, so it
answers the client directly and the reply never passes the gateway. The fix is
the usual one: also **source-NAT the connection to the VIP**. The backend then
answers the VIP, which is the gateway, and the reply is reversed on the way
back.

Clients whose source is inside `hairpin-prefixes` get this treatment. Everyone
else keeps their own address, so a backend still sees the real client address
for north-south traffic.

OVS permits NAT arguments only on a committing `ct`, and a committed connection
cannot take a second translation. So the source NAT lives in a **second
conntrack zone**, `Zhairpin`, which every VIP shares:
- **The first packet** of a hairpin connection is committed there with
  `nat(src=VIP)` after the bucket has committed the DNAT in `Zvip`.
- **Later packets** have the same translation applied by `ct(zone=Zhairpin,nat)`.
  That is why table 26 sends established and related packets through
  table 28 rather than straight to table 30.
- **On a reply**, the hairpin zone is consulted first (un-SNAT: the
  destination returns to the client), then the VIP zone (un-DNAT: the source
  becomes the VIP).

Entries in `Zhairpin` are keyed by the backend address:port, which belongs to
one VIP only, so sharing the zone between VIPs cannot collide.

### Bucket action: commit + DNAT + recirculate

Group buckets carry **actions**, not instructions, so a bucket cannot
`goto_table`. The standard OVS pattern is a single conntrack action that
commits, DNATs, and recirculates in one step:
`ct(commit,zone=Z,nat(dst=B:P),table=28)` — `RecircTable` and
`NXCTFCommit` are set together on `nx_action_conntrack`. The encoding
produced by `openflow.NewActionCT(NXCTFCommit, zone, 28,
NewActionNATDst(addr, port))`:

```
ffff0030000023200023000100000000002a1c0000000000
ffff00180000232000240000000200110a0001051f900000
  = ct(commit,table=28,zone=42,nat(dst=10.0.1.5:8080))
```

This byte sequence is pinned by `TestBucketActionEncoding` in
`pkg/sdn/gateway/services/loadbalancer/service_test.go`. The bare `nat`
argument on the table 20 divert (`ct(table=26,zone=Z,nat)`) is likewise
pinned by `TestParseCTActionBareNAT` in `pkg/sdn/ovs/group_test.go`.

### Conntrack zones and group IDs

- Each VIP gets its own conntrack zone from the shared `ct.ZoneAllocator`
  (owner `lb`, key `<proto>/<vip>:<port>`, e.g. `tcp/10.100.0.10:443`), so
  VIP state never collides with firewall or NAT state. The hairpin source
  NAT has one more zone, shared by every VIP (owner `lb`, key `hairpin`),
  allocated at `Start` and released at `Stop`.
- OpenFlow group IDs carry no cookie, so the load balancer owns the
  dedicated range `0x4C420000–0x4C42FFFF` ("LB"). The ID is derived
  deterministically from the VIP key (xxhash low 16 bits, linear probing on
  collision). On `Start` the service lists the bridge groups via
  `GetGroupDesc`: surviving groups in the range are reused with
  `OFPGC_MODIFY`, stale ones are deleted, and groups outside the range are
  never touched.

### Lifecycle ordering

- **Start:** the hairpin zone first (every VIP's reply divert names it),
  then groups (flows referencing `group:G` require the group to exist),
  then scaffolding + VIP flows in one batch, then the table 10 gate last —
  packets never enter an incomplete pipeline. Health probing starts after
  the datapath is programmed. **Start is transactional.** The gateway
  registers the service only after `Start` succeeds, so a failed `Start` has
  no `Stop` to clean up after it. Any failure after the hairpin zone is
  allocated rolls everything back, and the rollback continues past a failed
  step:
  - every load-balancer flow (one cookie-masked delete);
  - the installed VIPs' groups and conntrack zones;
  - the hairpin zone.

  The configuration is validated as a whole before anything is programmed:
  `ValidateVIPSet` refuses a duplicate VIP (`ErrVIPExists`) and a backend
  shared between VIPs (`ErrBackendInUse`).
- **AddVIP:** a VIP installs whole or not at all. A failed group or flow
  install takes back the group, any flows of the refused batch, and the
  VIP's zone.
- **SetBackends:** the new backend set's flows (its reply diverts among them)
  are installed before the group can select a new backend, and the removed
  backends' flows are deleted after it no longer can. A removed backend's
  established connections stop being translated, as a removed VIP's do.
- **Stop:** probing is cancelled, the gate is strict-deleted first (traffic
  falls back to the base pipeline), then all LB flows fall in one
  cookie-masked delete, groups are removed, and conntrack zones (the
  hairpin zone included) released.
- **Reconcile:** re-installs all flows (`OFPFC_ADD` replaces identical
  match+priority entries) and rebuilds every group from its current
  healthy set.

### Hardware/datapath offload caveat

The first packet of a new connection takes the slow(er) kernel path through
the group select and conntrack commit. Established connections are plain
conntrack lookups (`+est+trk -> goto_table:28 -> goto_table:30`; one more
lookup in the hairpin zone for a hairpin client) and megaflow-cache /
offload friendly. A backend's reply costs two conntrack lookups, the hairpin
zone then the VIP zone, each a recirculation. Expect the group-selection
cost only on connection setup.

## Testing

`make integration-test-lb` runs `TestGroupLoadBalancer`
(`test/integration/sdn/group_lb_test.go`) in the devcontainer against a real
Open vSwitch, kernel conntrack and network namespaces. No platformd is
involved. The harness supplies only what the rest of the gateway would:
- the table 0 hand-off;
- a table 30 that forwards a DNATed packet to its backend's port, and sends a
  packet routed back onto the hairpin segment out the port it came in on.

It supplies **no reply flow**. It used to install one, which is how a load
balancer that never reverse-translated a reply passed this test (#718).

The test asserts:
- a TCP handshake and exchange through a VIP whose backends each sit on
  their own port;
- that a backend stays reachable directly on its service port;
- a handshake through a hairpin VIP whose client and backend share one Linux
  bridge behind a single OVS port, with the backend seeing the VIP, not the
  client, as its peer;
- distribution, stickiness, prober-driven failover and fail-closed.

## Health probing

`prober.go` drives a ticker-based loop (interval = `health-check-interval`)
that dials every **TCP** backend concurrently each tick
(`net.DialTimeout`, timeout = `health-check-timeout`) and feeds a per-backend
rise/fall state machine:

- A healthy backend transitions **unhealthy** after `health-check-fall`
  consecutive failures (default 3).
- An unhealthy backend transitions **healthy** after `health-check-rise`
  consecutive successes (default 2).
- Any opposite result resets the counter (flapping never accumulates).
- Every transition rebuilds the VIP's select group from the healthy set
  and is logged.
- **All backends down = fail closed:** the group is modified to zero
  buckets, so new connections are dropped in table 26 while established
  connections continue through conntrack until they expire naturally.
- Backends start healthy at install; the prober demotes unreachable ones.
- UDP backends are never probed (always healthy).

Health can also be forced through `Service.SetBackendHealth` (used by the
prober and available for operational overrides).

## Configuration

The `load-balancer:` section of the gateway config
(`gateway.LoadBalancerConfig`):

```yaml
gateway:
  enabled: true
  load-balancer:
    enabled: true
    algorithm: hash              # default for VIPs: hash | round-robin
    health-check-interval: 10s
    health-check-timeout: 2s     # must be < interval
    health-check-rise: 2         # consecutive successes to mark healthy
    health-check-fall: 3         # consecutive failures to mark unhealthy
    max-backends: 32             # per-VIP backend cap (required here;
                                 # the service library defaults 0 to 64)
    hairpin-prefixes:            # IPv4 client networks that share a segment
      - 10.0.1.0/24              # with backends: source-NATed to the VIP
    bridge: br-ovs               # optional: overrides the runtime bridge
    vips:
      - address: 10.100.0.10
        port: 443
        protocol: tcp
        algorithm: hash          # optional per-VIP override
        backends:
          - address: 10.0.1.5
            port: 8443
            weight: 2
          - address: 10.0.1.6
            port: 8443           # weight omitted -> 1
```

The service requires the daemon-injected `GatewayRuntime` (flow controller,
OVS client, `Groups` group client, conntrack zone allocator), assembled by
`gatewayd serve` from its `sdn:` configuration section (see
`docs/gateway/engineering.md` §5). Enabling the section without `sdn:`
fails assembly with `ErrSDNRequiredForService`; a runtime-less `Start`
fails with `ErrRuntimeMissing`.

## API surface

VIP CRUD is part of the **gateway service** on every protocol. Operations:
`AddVIP`, `RemoveVIP`, `GetVIP`, `ListVIPs`, `SetVIPBackends`,
`GetLBStatus`.

| Protocol | Surface |
|----------|---------|
| gRPC | `platform.v1.GatewayService/{AddVIP,RemoveVIP,GetVIP,ListVIPs,SetVIPBackends,GetLBStatus}` — see [api-reference-grpc.md](api-reference-grpc.md) |
| REST | `/api/v1/sdn/gateway/lb/...` — see [api-reference-rest.md](api-reference-rest.md) |
| QUIC | Gateway category `0x2F`, sub-opcodes `0x30–0x35` — see [api-reference-quic.md](api-reference-quic.md) |
| MCP | `gateway_lb_*` tools — see [api-reference-mcp.md](api-reference-mcp.md) |
| Unix | gRPC over UDS (same methods) — see [api-reference-unix.md](api-reference-unix.md) |

Required scopes: `sdn:read` (get/list/status), `sdn:write`
(add/set-backends), `sdn:delete` (remove).

### CLI

```bash
# Service health
platformctl sdn gateway lb status

# VIP CRUD
platformctl sdn gateway lb vip add --protocol tcp --address 10.100.0.10 --port 443 \
  --backend 10.0.1.5:8443:2 --backend 10.0.1.6:8443
platformctl sdn gateway lb vip list
platformctl sdn gateway lb vip get --protocol tcp --address 10.100.0.10 --port 443
platformctl sdn gateway lb vip set-backends --protocol tcp --address 10.100.0.10 --port 443 \
  --backend 10.0.1.7:8443
platformctl sdn gateway lb vip remove --protocol tcp --address 10.100.0.10 --port 443
```

Backends are `address:port[:weight]`; weight defaults to 1.

### Go surface

`gateway.Gateway` exposes the VIP operations when the load balancer service
is running: `AddVIP`, `RemoveVIP`, `GetVIP`, `ListVIPs`, `SetVIPBackends`,
`LBStatus`, plus `LBHealth()` / `LBService()` accessors mirroring
`FirewallHealth` / `NATService`. When the service is not active every
operation returns the typed `ErrServiceNotActive`.

## Coexistence with firewall and NAT

| Concern | Resolution |
|---------|-----------|
| Table 10 gates | Distinct priorities (fw 2, NAT 1, LB 3) keep the three gates independent flows; teardown of one never removes another's gate |
| Table 20 priority order | LB divert 250 > NAT DNAT divert 200 > firewall zone gates 100 > SNAT divert 90 > firewall non-IP bypass 1 > LB miss 0 |
| Cookies | `0xF1BE0001` fw / `0xF1BE0002` NAT / `0xF1BE0003` LB (high 32 bits), each torn down by its own cookie-masked delete |
| Conntrack zones | Separate zones per subsystem via the shared allocator; VIP DNAT state never leaks into firewall verdicts |
