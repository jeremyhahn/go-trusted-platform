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
the firewall (tables 20/21) and NAT (table 25) services. It owns table 26
and cookie `0xF1BE0003_00000000` (mask `0xFFFFFFFF00000000`; firewall is
`0xF1BE0001…`, NAT `0xF1BE0002…`).

```
table 10 (gate)      priority 3: goto_table:20            [LB gate]
                     (firewall gate = prio 2, NAT gate = prio 1; all
                      three are distinct flows and tear down independently)

table 20 (ct gate)   priority 250 per VIP:
                       ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> ct(table=26,zone=Zvip,nat)
                     (outranks the NAT DNAT divert at 200; the bare "nat"
                      applies committed DNAT state to established/reply
                      packets)
                     priority 0 miss: goto_table:30
                     (so non-VIP traffic continues when no firewall
                      bypass flow exists; firewall's own bypass is prio 1)

table 26 (dispatch)  priority 400: ct_state=+inv+trk           -> drop
                     priority 300: ct_state=+est+trk           -> goto_table:30
                     priority 300: ct_state=+rel+trk           -> goto_table:30
                     priority 200 per VIP:
                       ct_state=+new+trk,ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> group:G
                     priority 0 miss:                          -> drop
                     (VIP traffic must never leak unbalanced)

group G (select)     one bucket per healthy backend, weight = backend weight
                     bucket actions:
                       ct(commit,zone=Zvip,nat(dst=BACKEND:PORT),table=30)
```

### Bucket action: commit + DNAT + recirculate

Group buckets carry **actions**, not instructions, so a bucket cannot
`goto_table`. The standard OVS pattern is a single conntrack action that
commits, DNATs, and recirculates in one step:
`ct(commit,zone=Z,nat(dst=B:P),table=30)` — `RecircTable` and
`NXCTFCommit` are set together on `nx_action_conntrack`. The encoding
produced by `openflow.NewActionCT(NXCTFCommit, zone, 30,
NewActionNATDst(addr, port))` was verified against Open vSwitch 3.3.4:

```
$ echo ffff0030000023200023000100000000002a1e0000000000\
ffff00180000232000240000000200110a0001051f900000 \
  | ovs-ofctl parse-actions OpenFlow13
actions=ct(commit,table=30,zone=42,nat(dst=10.0.1.5:8080))
```

This byte sequence is pinned by `TestBucketActionEncoding` in
`pkg/sdn/gateway/services/loadbalancer/service_test.go`. The bare `nat`
argument on the table 20 divert (`ct(table=26,zone=Z,nat)`) is likewise
pinned by `TestParseCTActionBareNAT` in `pkg/sdn/ovs/group_test.go`.

### Conntrack zones and group IDs

- Each VIP gets its own conntrack zone from the shared `ct.ZoneAllocator`
  (owner `lb`, key `<proto>/<vip>:<port>`, e.g. `tcp/10.100.0.10:443`), so
  VIP state never collides with firewall or NAT state.
- OpenFlow group IDs carry no cookie, so the load balancer owns the
  dedicated range `0x4C420000–0x4C42FFFF` ("LB"). The ID is derived
  deterministically from the VIP key (xxhash low 16 bits, linear probing on
  collision). On `Start` the service lists the bridge groups via
  `GetGroupDesc`: surviving groups in the range are reused with
  `OFPGC_MODIFY`, stale ones are deleted, and groups outside the range are
  never touched.

### Lifecycle ordering

- **Start:** groups first (flows referencing `group:G` require the group
  to exist), then scaffolding + VIP flows in one batch, then the table 10
  gate last — packets never enter an incomplete pipeline. Health probing
  starts after the datapath is programmed.
- **Stop:** probing is cancelled, the gate is strict-deleted first (traffic
  falls back to the base pipeline), then all LB flows fall in one
  cookie-masked delete, groups are removed, and conntrack zones released.
- **Reconcile:** re-installs all flows (`OFPFC_ADD` replaces identical
  match+priority entries) and rebuilds every group from its current
  healthy set.

### Hardware/datapath offload caveat

The first packet of a new connection takes the slow(er) kernel path through
the group select and conntrack commit. Established connections are plain
conntrack lookups (`+est+trk -> goto_table:30`) and megaflow-cache /
offload friendly. Expect the group-selection cost only on connection setup.

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
OVS client, `Groups` group client, conntrack zone allocator); enabling the
section without a runtime fails `Start` with `ErrRuntimeMissing`.

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
