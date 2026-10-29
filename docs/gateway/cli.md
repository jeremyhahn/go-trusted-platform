# Edge Gateway — CLI

> **Status: NORMATIVE** · Scope: `platformctl sdn gateway` (incl. `lb`, `nat64`, `perf`), `platformctl sdn ipam`, `platformctl proxy`, `gatewayd` · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.

---

## 1. Where the gateway CLI actually lives

**There is no `platformctl gateway` command group.** `pkg/cli/commands/root.go`
registers 50 top-level commands and `gateway` is not one of them
([`docs/daemon/cli.md`](../daemon/cli.md) §3). The gateway
verbs are subgroups of `sdn`:

| Path | Covers |
|---|---|
| `platformctl sdn gateway` | Status, telemetry snapshot, deprecated mode, BGP |
| `platformctl sdn gateway lb` | Load balancer VIPs |
| `platformctl sdn gateway nat64` | NAT64 translator status |
| `platformctl sdn gateway perf` | Datapath performance |
| `platformctl sdn ipam` | Pools and allocations |
| `platformctl proxy` | The trusted reverse proxy — **this one is top-level** |

`lb`, `nat64` and `perf` are registered only under `sdn gateway`
(`pkg/cli/commands/sdn/gateway.go`). There is no `platformctl sdn lb` and no
`platformctl sdn perf`.

`gatewayd` itself is the daemon binary (`cmd/gatewayd/main.go`), not an
administrative CLI: its `main` calls `commands.Execute()` and it is run as a
service, configured by file. `gatewayd serve` takes only the global persistent
flags (`pkg/sdn/gateway/commands/root.go`): `--config` (default
`/etc/gatewayd/config.yaml`), `--config-dir` (default `/etc/gatewayd`),
`--data-dir` (default `/var/lib/gatewayd`), `--debug`/`-d`, `--log-format`
(default `json`) and `--log-level` (default `info`). Every listener address and
the BGP speaker come from the config file.
The `--listen`, `--api-port`, `--grpc-port`, `--bgp-asn` and `--bgp-router-id`
flags it once had configured nothing and are gone (#93).

`gatewayd service run <process>` is the child half of the supervised process
model (`process:` in [`user.md`](user.md), #557). `gatewayd serve` starts it;
an operator does not. It takes `--ipc-socket`, `--socket-group`,
`--supervisor-uid`, `--uid` and `--gid` from the supervisor, plus the global
flags the supervisor resolved: `--config`, `--data-dir`, `--log-format` and
`--debug` (a flag the supervisor left unset is left unset). Without
`--data-dir` the proxy child would open the default pin store rather than the
supervisor's and trust every `tofu` peer afresh. It drops to the process's privilege class before it reads the
configuration, so it exits with an error if that file is unreadable by the
service account, or if the process hosts no enabled service.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:135-156`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` (`unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`) |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

---

## 2. `platformctl sdn gateway`

| Path | Purpose |
|---|---|
| `gateway status` | Gateway node status |
| `gateway snapshot` | Telemetry snapshot: sessions, BFD, tunnels, uplinks, filters, NAT, overlay, pipeline |
| `gateway overlay vteps` | List overlay VTEPs admitted by gatewayd |
| `gateway overlay vteps get` | Read one admitted overlay VTEP |
| `gateway mode set` | **Deprecated** — set gateway modes |
| `gateway bgp status` | BGP status |
| `gateway bgp peers` | List BGP peers |
| `gateway bgp announce` | Announce a prefix |
| `gateway bgp withdraw` | Withdraw a prefix |
| `gateway bgp routes` | List announced prefixes |

**`gateway mode set`** takes `--modes <comma-separated>` (required). It drives
the deprecated `GatewayMode` bitmask, which can express only three of the
service sections (`overlay`, `edge`, `transit`). Any other name is refused
before the request is sent. It is retained for compatibility.

**`gateway status` and `gateway mode set` answer "not configured" from
`platformd`.** They read the gateway in the daemon's own process, and the
control plane runs none (`gatewayd` does). The `gateway bgp` verbs answer
the same way, because `platformd` has no BGP speaker. Configure a gateway by
its service sections, not with this verb — see
[architecture.md](architecture.md).

**`gateway bgp`** verbs and flags:
[BGP CLI](../bgp/cli.md).

**`gateway snapshot`** prints what a gateway's services actually programmed.
`--gateway-id <id>` reads the report the control plane holds for that gateway;
without it, the node's own gateway answers. `--all` lists every gateway that
has reported. `--output json|yaml` emits the document instead of the rendered
sections. Sections a gateway does not run are not printed — an absent Tunnels
section means the service is not running, not that it runs with no tunnels. When
the overlay service is running, the snapshot prints the local VTEP, admitted
VTEPs, and ND counters for punted, answered, meter-dropped, queue-dropped and
fell-through packets.

**`gateway overlay vteps`** lists the VTEPs gatewayd currently admits for
decapsulation. Use `--gateway-id <id>` to read a control-plane report for a
specific gateway; without it, the local gateway answers.

**`gateway overlay vteps get <vtep>`** reads one admitted VTEP by IP address.
It uses the same `--gateway-id <id>` selector and returns not found when the
address is not currently admitted.

```bash
platformctl sdn gateway status --output json
platformctl sdn gateway snapshot
platformctl sdn gateway snapshot --gateway-id gw-01-gateway
platformctl sdn gateway snapshot --all --output json
platformctl sdn gateway overlay vteps --gateway-id gw-01-gateway
platformctl sdn gateway overlay vteps get 10.255.0.10 --gateway-id gw-01-gateway
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp announce --prefix 203.0.113.0/24 --next-hop 198.51.100.1
platformctl sdn gateway bgp withdraw --prefix 203.0.113.0/24
platformctl sdn gateway bgp routes
```

---

## 3. `platformctl sdn ipam`

Pools first, then allocations from them.

### `ipam pool`

| Verb | Flags |
|---|---|
| `list` | `--zone` (filter; empty returns all pools) |
| `get` | `--id` (required) |
| `create` | `--id` (optional, generated if omitted), `--name` (required), `--cidr` (required, **immutable**), `--gateway`, `--zone`, `--description`, `--lease-seconds` (default lease; `0` never expires) |
| `update` | `--id` (required), `--name`, `--gateway`, `--zone`, `--description`, `--lease-seconds`, `--reserved`, `--range-start`, `--range-end` |
| `delete` | `--id` (required) |

**`update` changes only the flags you pass.** It reads the pool first and
sends the current zone and description, and leaves the lease and inactivity
timeout alone, for every flag it was not given. Pass a flag empty
(`--zone ""`) or zero (`--lease-seconds 0`) to clear it. The window flags are
the exception: passing any of them replaces the whole window.

**`--cidr` is immutable.** `update` has no `--cidr` flag, deliberately: changing
a pool's range under live allocations would orphan them. A pool with the wrong
CIDR is replaced, not edited.

`--zone` names an underlay zone such as `control-plane` or `provisioning`
([`../architecture/reference-network.md`](../architecture/reference-network.md)). It
must be a zone that exists — the SDN configuration rejects a pool declared in an
undeclared zone (`ErrPoolZoneUndeclared`).

### `ipam` allocations

| Verb | Flags |
|---|---|
| `allocate` | `--pool-id` (required), `--device-id` (required), `--hostname` (optional) |
| `release` | `--ip` (required) |
| `allocations` | `--pool-id` (filter) |

`--device-id` is required on allocate: an address is allocated **to a device**,
not to nothing. That is what makes the allocation table joinable against the
device registry.

`pool delete` and `release` print a structured result in the selected output
format, like every other `sdn` delete: `{"pool_id": "<id>", "deleted": true}`
and `{"ip": "<ip>", "released": true}`. `--output json` therefore always yields
JSON a script can parse.

```bash
platformctl sdn ipam pool create --name tenant-a --cidr 10.20.0.0/24 \
    --gateway 10.20.0.1 --zone trusted --description "Tenant A workloads"
platformctl sdn ipam allocate --pool-id tenant-a --device-id dev-0f21 --hostname web-01
platformctl sdn ipam allocations --pool-id tenant-a
platformctl sdn ipam release --ip 10.20.0.17
```

---

## 4. `platformctl sdn gateway lb`

| Path | Purpose |
|---|---|
| `lb status` | Load balancer status |
| `lb vip add` | Add a VIP |
| `lb vip get` | Get one VIP with per-backend health |
| `lb vip list` | List VIPs |
| `lb vip remove` | Remove a VIP |
| `lb vip set-backends` | Replace a VIP's backends |

A VIP is identified by protocol, address and port. Every VIP-scoped verb
(`add`, `get`, `remove`, `set-backends`) takes the same three flags; `list` and
`status` take none:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--protocol` | string | `tcp` | `tcp` or `udp` |
| `--address` | string | | Virtual IPv4 address (required) |
| `--port` | uint16 | | Virtual L4 port (required) |

**`add`** adds `--algorithm` (`hash` or `round-robin`; defaults to the service
algorithm when omitted) and `--backend`, a repeatable `address:port[:weight]`
(required; weight defaults to 1). Both algorithms map to select-group
`dp_hash` balancing; `least-conn` is refused because the OVS datapath cannot
implement it.

**`set-backends`** takes `--backend`, repeatable, and **replaces** the whole
backend set. It is not additive; a `set-backends` with one backend leaves one
backend.

```bash
platformctl sdn gateway lb vip add --protocol tcp --address 203.0.113.10 --port 443 \
    --algorithm round-robin \
    --backend 10.20.0.11:8443:2 --backend 10.20.0.12:8443:1
platformctl sdn gateway lb vip set-backends --protocol tcp --address 203.0.113.10 --port 443 \
    --backend 10.20.0.11:8443 --backend 10.20.0.13:8443
platformctl sdn gateway lb vip get --address 203.0.113.10 --port 443
platformctl sdn gateway lb status
```

## 4a. `platformctl sdn gateway nat64`

| Path | Purpose |
|---|---|
| `nat64 status` | NAT64 translator health |

```
platformctl sdn gateway nat64 status
platformctl sdn gateway nat64 status -o json
```

Reports whether the service is started, whether the kernel instance is
present, the translation prefix and instance name, the live session count,
`pool4` usage, the module version, and the last reconcile error if there was
one. A started service reporting `instance_present: false` means the kernel
instance went away underneath it.

There are no mutating verbs: the translator is configured declaratively in
the `nat64:` section and reconciled, so anything set here would be undone on
the next reconcile.

Against a production `platformd` today this command fails with "nat64
translator not configured", even while the `nat64:` section is running. The
translator lives in `gatewayd`, and the control-plane path to it is planned
([api.md §5a](api.md#5a-nat64-translator)).

---

## 5. `platformctl sdn gateway perf`

Datapath performance verification against a live OVS bridge.

| Verb | Purpose | Flags |
|---|---|---|
| `perf flows` | Measure flow-programming throughput | `--count` (default 1000, range 1-100000), `--batch` (install all flows behind a single barrier), `--bridge` (default: the daemon's default bridge) |
| `perf datapath` | Read live datapath counters | `--bridge` |
| `perf conntrack` | Summarise the connection-tracking table | `--zone` (0-65535; omit for every zone) |

**`perf flows` mutates the bridge** and needs `sdn:write`. It installs `--count`
ephemeral drop flows into the dedicated perf table 250 under cookie
`0xF1BE00FF00000000` (`pkg/sdn/gateway/services/perf/service.go`), times the
install, then removes them with one cookie-scoped delete. Table 250 is above
every pipeline table, so the measurement flows never match production traffic.

`perf flows --batch` measures a different thing from `perf flows` without it:
batched installation behind one barrier versus one flow at a time. Compare like
with like.

`perf datapath` reports the flow-cache hit / miss / lost counters, the number
of datapath flows offloaded to hardware, the `hw-offload` setting and the
bridge datapath type. `perf conntrack` reports the total conntrack entry count
and per-zone counts. Both read `ovs-vswitchd` through `ovs-appctl`; without it
they fail rather than report zeros.

```bash
platformctl sdn gateway perf flows --count 1000 --batch --bridge br-tenant-a
platformctl sdn gateway perf datapath --bridge br-tenant-a
platformctl sdn gateway perf conntrack --zone 12
```

---

## 6. `platformctl proxy`

Reverse-proxy configuration management. This group **is** top-level.

| Path | Purpose |
|---|---|
| `proxy status` | Proxy configuration store status |
| `proxy reload` | Bump the proxy config version |
| `proxy zone-matrix` | Show the SDN zone matrix |
| `proxy route add\|get <id>\|update\|delete <id>\|list` | Route operations |
| `proxy pool add\|get <id>\|update\|delete <id>\|list` | Backend pool operations |

**`proxy reload` bumps a version; it does not re-read a file.** The proxy
configuration lives in a versioned store, and the reload verb is how consumers
are told a new version exists.

**`proxy zone-matrix`** prints which SDN zones may reach which. It is the join
between proxy routing and network zoning, and it is the first thing to check
when a route is reachable or unreachable in a way the route definition does not
explain.

```bash
platformctl proxy pool add   # backend pool first
platformctl proxy route add  # then the route that references it
platformctl proxy reload
platformctl proxy zone-matrix
```

Order matters: a route referencing a pool that does not exist fails validation
with `ErrUnknownPoolID`, at configuration time rather than at first request.

---

## 7. Configuration errors you will hit first

The proxy validates before it starts, and refuses several things people expect
to work:

- A non-public route with no auth chain (`ErrAuthChainRequired`).
- A non-public route without server TLS (`ErrTLSRequiredForAuth`).
- A route requiring mTLS or token auth when the chain cannot do it
  (`ErrMTLSAuthNotConfigured`, `ErrTokenAuthNotConfigured`) — the route is **not**
  downgraded to what the chain can do.
- A route path prefix not starting with `/` (`ErrInvalidPathPrefix`).
- A backend URL that is not http or https (`ErrInvalidBackendScheme`).
- A pool with no backends (`ErrNoBackends`).
- A zone extractor without a matrix, or vice versa (`ErrZoneConfigIncomplete`).

---

## 8. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
