# Edge Gateway — CLI

> **Status: NORMATIVE** · Scope: `platformctl sdn gateway|lb|perf|ipam`, `platformctl proxy`, `gatewayd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.

---

## 1. Where the gateway CLI actually lives

**There is no `platformctl gateway` command group.** `pkg/cli/commands/root.go`
registers 41 top-level groups and `gateway` is not one of them. The gateway
verbs are subgroups of `sdn`:

| Path | Covers |
|---|---|
| `platformctl sdn gateway` | Status, deprecated mode, BGP |
| `platformctl sdn lb` | Load balancer VIPs |
| `platformctl sdn perf` | Datapath performance |
| `platformctl sdn ipam` | Pools and allocations |
| `platformctl proxy` | The trusted reverse proxy — **this one is top-level** |

`gatewayd` itself is the daemon binary (`cmd/gatewayd/main.go`), not an
administrative CLI: its `main` calls `commands.Execute()` and it is run as a
service, configured by file.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
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
| `gateway mode set` | **Deprecated** — set gateway modes |
| `gateway bgp status` | BGP status |
| `gateway bgp peers` | List BGP peers |
| `gateway bgp announce` | Announce a prefix |
| `gateway bgp withdraw` | Withdraw a prefix |
| `gateway bgp routes` | List announced prefixes |

**`gateway mode set`** takes `--modes <comma-separated>` (required). It drives
the deprecated `GatewayMode` bitmask, which can express only three of the
service sections (`overlay`, `edge`, `transit`). It is retained for
compatibility. Configure a gateway by its service sections, not with this verb —
see [architecture.md](architecture.md).

**`gateway bgp announce`**: `--prefix` (required), `--next-hop` (optional).
**`gateway bgp withdraw`**: `--prefix` (required).

```bash
platformctl sdn gateway status --output json
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
| `create` | `--id` (optional, generated if omitted), `--name` (required), `--cidr` (required, **immutable**), `--gateway`, `--zone`, `--description` |
| `update` | `--id` (required), `--name`, `--gateway`, `--zone`, `--description` |
| `delete` | `--id` (required) |

**`--cidr` is immutable.** `update` has no `--cidr` flag, deliberately: changing
a pool's range under live allocations would orphan them. A pool with the wrong
CIDR is replaced, not edited.

`--zone` names a trust/exposure zone such as `trusted` or `provisioning`. It
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

```bash
platformctl sdn ipam pool create --name tenant-a --cidr 10.20.0.0/24 \
    --gateway 10.20.0.1 --zone trusted --description "Tenant A workloads"
platformctl sdn ipam allocate --pool-id tenant-a --device-id dev-0f21 --hostname web-01
platformctl sdn ipam allocations --pool-id tenant-a
platformctl sdn ipam release --ip 10.20.0.17
```

---

## 4. `platformctl sdn lb`

| Path | Purpose |
|---|---|
| `lb status` | Load balancer status |
| `lb vip add` | Add a VIP |
| `lb vip get` | Get a VIP |
| `lb vip list` | List VIPs |
| `lb vip remove` | Remove a VIP |
| `lb vip set-backends` | Replace a VIP's backends |

VIP-scoped verbs share two flags:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--address` | string | | Virtual IPv4 address (required) |
| `--protocol` | string | `tcp` | `tcp` or `udp` |

**`add`** adds `--algorithm` (`hash` or `round-robin`; defaults to the service
algorithm when omitted) and `--backend`, a repeatable
`address:port[:weight]` (required).

**`set-backends`** takes `--backend`, repeatable, and **replaces** the whole
backend set. It is not additive; a `set-backends` with one backend leaves one
backend.

```bash
platformctl sdn lb vip add --address 203.0.113.10 --protocol tcp \
    --algorithm round-robin \
    --backend 10.20.0.11:8443:2 --backend 10.20.0.12:8443:1
platformctl sdn lb vip set-backends --address 203.0.113.10 \
    --backend 10.20.0.11:8443 --backend 10.20.0.13:8443
platformctl sdn lb status
```

---

## 5. `platformctl sdn perf`

Datapath performance verification.

| Verb | Purpose | Flags |
|---|---|---|
| `perf flows` | Measure flow-programming throughput | `--batch` (install all flows behind a single batched barrier), `--bridge` (default: the daemon's default bridge) |
| `perf datapath` | Read live datapath counters | `--bridge` |
| `perf conntrack` | Summarise the connection-tracking table | — |

`perf flows --batch` measures a different thing from `perf flows` without it:
batched installation behind one barrier versus per-flow barriers. Compare like
with like.

```bash
platformctl sdn perf flows --bridge br-tenant-a --batch
platformctl sdn perf datapath --bridge br-tenant-a
platformctl sdn perf conntrack
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
