# Cluster — CLI

> **Status: NORMATIVE** · Scope: `pkg/cli/commands/cluster/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. There is no `platformctl cluster` command today

**`pkg/cli/commands/cluster` is a complete cobra command tree that is not
registered on any root command.** Grepped repo-wide on 2026-08-18:

- `pkg/cli/commands/root.go` imports no cluster package and calls no
  `cluster.NewCommand`.
- No file outside `pkg/cli/commands/cluster/` imports
  `github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/cluster`.
- `cmd/` contains no reference to it.

So `platformctl cluster status` is **not a command a user can run**. Running it
produces cobra's unknown-command error.

This is recorded rather than papered over. The legacy
[`cli-usage.md`](cli-usage.md) in this folder documents the command group as
though it ships; it does not, and several of the flags it documents do not
exist even in the unregistered code (§4).

The rest of this file documents the command tree **as written**, because it is
the requirement the wiring must satisfy when the feature is connected — and
because the flags below are what an implementer will find, not what the legacy
doc claims.

## 2. The command tree as written

```
cluster              Cluster management operations
  bootstrap          Bootstrap a new cluster
  join               Join an existing cluster
  leave              Leave the cluster
  status             Show cluster status
  nodes              List cluster nodes
```

`cluster.NewCommand(getFlags)` builds the group and adds all five verbs. No verb
takes a positional argument.

Every verb goes through `cli.NewBaseCommand(flags)` and then
`base.Client().Cluster()`, returning `ErrClusterClientNotInitialized` when that
client is nil. Each then wraps the gRPC client in
`clustersvc.NewClientFromGRPC` (`sdk/go/services/cluster`).

**All five are client verbs** — they need a reachable `platformd`.
`--transport embedded` runs the services in-process, but the embedded
`ServiceRegistry.Cluster` field is not populated by the one place a registry is
built (`pkg/api/daemon/embedded_host.go`), so embedded does not reach the
cluster service either ([api.md](api.md) §3).

### Global flags

`platformctl` persistent flags, precedence **flag > environment > config file >
built-in default**:

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

An unrecognised `--output` yields `cli.ErrInvalidOutputFormat`.

## 3. Verbs and flags

### `cluster bootstrap`

Bootstrap a new cluster with this node as the initial leader.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--node-id` | **string** | `""` | **yes** (`MarkFlagRequired`) | Unique identifier for this node |
| `--listen-addr` | string | `""` | **yes** (`MarkFlagRequired`) | Address to listen on, `host:port` |
| `--advertise-addr` | string | `""` | no | Address to advertise; defaults to `--listen-addr` |
| `--data-dir` | string | `""` | no | Directory for Raft data |

Client-side validation before any RPC: `--node-id` non-empty
(`ErrMissingNodeID`), `--listen-addr` non-empty (`ErrMissingListenAddr`) and
parseable as `host:port` with both parts non-empty (`ErrInvalidListenAddr`);
`--advertise-addr` validated the same way when supplied.

Both addresses are split into host and port and passed as separate fields.
`BootstrapDomain(ctx, clusterName, nodeName, bindHost, bindPort, advHost, advPort)`
receives **`--node-id` for both `clusterName` and `nodeName`** — there is no way
to name the cluster separately from this verb.

**`--data-dir` is never sent.** It is echoed back in the printed
`BootstrapResult` and nothing else; the RPC has no field for it.

```bash
platformctl cluster bootstrap \
    --node-id node-a \
    --listen-addr node-a.example.com:7000

# Behind NAT or in a container
platformctl cluster bootstrap \
    --node-id node-a \
    --listen-addr 0.0.0.0:7000 \
    --advertise-addr node-a.example.com:7000
```

**Run bootstrap exactly once per cluster.** Running it on two nodes creates two
separate clusters that cannot be merged.

### `cluster join`

Join this node to an existing cluster as a follower.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--node-id` | **string** | `""` | **yes** | Unique identifier for this node |
| `--listen-addr` | string | `""` | **yes** | Address to listen on, `host:port` |
| `--advertise-addr` | string | `""` | no | Defaults to `--listen-addr` |
| `--join` | **string** | `""` | **yes** | **Comma-separated** list of existing member addresses |

`--join` is a single string split on commas by `parseAddressList`, which trims
whitespace and drops empty entries. Every resulting address must be `host:port`
(`ErrInvalidJoinAddr`), and an empty result is `ErrMissingJoinAddrs`.

**`--join` is not repeatable.** Passing it twice sets the value twice; only the
last wins. Use one flag with commas.

```bash
platformctl cluster join \
    --node-id node-b \
    --listen-addr node-b.example.com:7000 \
    --join node-a.example.com:7000

# Multiple seeds, one flag
platformctl cluster join \
    --node-id node-c \
    --listen-addr node-c.example.com:7000 \
    --join node-a.example.com:7000,node-b.example.com:7000
```

### `cluster leave`

Remove a node from the cluster.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--force` | bool | `false` | no | Force leave without graceful shutdown |
| `--node-id` | string | `""` | no | Node to remove; empty means the local node |
| `--timeout` | uint32 | **`30`** | no | Seconds to allow for a graceful leave |

`--timeout` is a plain integer of **seconds**, not a duration string. `--timeout
30s` is a parse error.

```bash
platformctl cluster leave
platformctl cluster leave --force
platformctl cluster leave --node-id node-b --timeout 60
```

### `cluster status`

Show cluster status.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--include-nodes` | bool | `false` | no | Include the node list in the response |

```bash
platformctl cluster status
platformctl cluster status --include-nodes
platformctl cluster status -o json
```

Table output:

```
Cluster is healthy

Cluster Information:
  Cluster ID     cluster-a
  Node ID        node-a
  Node Count     3
  Voter Count    3

Raft State:
  State          LEADER
  Term           7
  Commit Index   0
  Applied Index  0

Leader Information:
  Leader ID      node-a
  Leader Address node-a.example.com:7000
  Last Contact   2026-08-18T09:14:22Z

Timestamp        2026-08-18T09:14:23Z
```

**`Commit Index` and `Applied Index` are always `0`.** `runStatus` hard-codes
both to zero; the `GetClusterStatusResponse` message carries neither. They are
printed for shape, not for information.

**`Voter Count` is `HealthyNodes`, not a voter count.** `runStatus` assigns
`VoterCount: int(resp.HealthyNodes)`. The label is wrong.

`--include-nodes` is passed to the RPC but the table renders no node list — only
`-o json`/`-o yaml` would show what the server returned, and even then the
printed struct is `ClusterStatusSummary`, which has no nodes field. **Use
`cluster nodes` to see nodes.**

### `cluster nodes`

List all cluster nodes. **No flags.**

```bash
platformctl cluster nodes
platformctl cluster nodes -o json
```

Node rows carry `NodeID`, `Address` (rendered `host:port` from the response's
separate address and port fields), `State`, `RaftState`, `IsVoter`, `IsLeader`,
`LastSeen`, `Uptime`. A node is counted as a voter when its role is **not**
`NodeRoleObserver`. `LastSeen` and `Uptime` render `N/A` when the response
omits the timestamps.

## 4. Corrections to the legacy `cli-usage.md`

[`cli-usage.md`](cli-usage.md) in this folder predates this convention and does
not match the code:

| Legacy claim | Reality |
|---|---|
| `--node-id` is `uint64` | It is a **string** on every verb |
| `--join` is `string[]`, repeatable | It is a **single comma-separated string** |
| `bootstrap --metadata "k=v,..."` | **No such flag** |
| `join --metadata` | **No such flag** |
| `join --timeout duration` (default `30s`) | **No `--timeout` on `join`.** `leave --timeout` exists and is a **uint32 of seconds** |
| `--data-dir` is sent to the server | It is echoed in local output only |
| Examples use literal private-range IP addresses and port `63000` | The default listen address in code is `0.0.0.0:7000`. Published examples use placeholder hosts such as `node-a.example.com` |

Where they disagree, the code is right and the legacy file is the defect.

## 5. Exit codes

`0` on success, non-zero on failure. Errors are wrapped per verb:
`ErrClusterBootstrapFailed`, `ErrClusterJoinFailed`, `ErrClusterLeaveFailed`,
`ErrClusterStatusFailed`, `ErrClusterNodesFailed`, each carrying the underlying
error.

Because the daemon's cluster service is an `Unimplemented` stub
([architecture.md](architecture.md) §3), every one of these verbs would fail
against a shipped daemon even if the command tree were registered.

`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface.

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so that
requirement is unmet repo-wide. For cluster the gap is larger than parity: the
verbs are not reachable at all.
