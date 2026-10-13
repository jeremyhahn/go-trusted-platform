# Cluster — Using It

> **Status: NORMATIVE** · Scope: `pkg/cluster/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## Start here: what you can and cannot do today

**The platform's cluster management API is not usable yet.** Verified against
the code on 2026-08-18:

- `platformctl cluster …` **is not a command.** The command tree exists in the
  source and is registered on no root command, so the binary does not have it.
- Every cluster REST route returns **503**.
- Every cluster gRPC call returns **unimplemented**.
- Every cluster MCP tool returns **"cluster: service provider not configured"**.
- There is no cluster operation on QUIC at all.

None of that is a bug in your deployment. The lifecycle verbs, the status
projection and the transports are all written; the piece that connects them to
a consensus engine is not wired.

**What still works:** clustering itself. Forming a cluster is not this
repository's job — it belongs to the database and consensus layers underneath.
You configure it there, under `quicbaas:`, and the platform runs on top of it.
What you do not get is the platform's own view of that cluster: no
`cluster status`, no node list, no quorum verdict from platformd.

If you are looking for the commands, [cli.md](cli.md) documents them as written
so you know what will exist when they are connected. If you are looking for a
working cluster, read on.

---

## Who does what

Time spent understanding this saves a lot of confusion later.

| Layer | Does |
|---|---|
| **go-quicraft** | Raft: elections, log replication, snapshots |
| **go-qrdb** | Cluster formation, peer discovery, membership, replicated state |
| **go-quicbaas** | Composes them and exposes the SDK the platform consumes |
| **go-trusted-platform** (here) | A control-plane *view*: lifecycle verbs, status, node list, quorum verdict — and the API for all of it |

So: "my cluster will not form" is a question for the layers below. "platformd
will not tell me about my cluster" is this feature, and the answer today is that
it cannot.

---

## Prerequisites for a clustered deployment

1. **A build with the `cluster` tag.** It is in the default `BUILD_TAGS`, so a
   standard build has it. Run `make -s print-build-tags` for the derived set
   rather than copying a list — the tags are assembled in two stages.
   Without it, the cluster service is a stub that reports
   `"cluster service not enabled (build with -tags cluster)"`.
2. **A `quicbaas:` section configured for a multi-node deployment** — see below.
3. **An odd number of nodes.** Three or five. Quorum is
   `(total / 2) + 1`, so three nodes tolerate one failure and five tolerate two.
   An even count buys nothing.
4. **Network reachability between nodes** on whatever address you configure for
   Raft.

---

## Configuring a cluster

Cluster deployment is configured under **`quicbaas:`**, not under a `cluster:`
section. There is no `cluster:` section in the platform configuration file —
nothing in the platform parses one.

```yaml
quicbaas:
  transport: embedded
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 1                              # unique per node, never reused
  raft-address: node-a.example.com:7000   # this node's Raft address
  join-addresses:                         # peers; empty on the first node
    - node-b.example.com:7000
    - node-c.example.com:7000
  consistency-level: linearizable
```

On the second and third nodes, change `node-id` and `raft-address` and list the
other members in `join-addresses`.

### The setting people get wrong

**`storage-backend: raft` is not valid.** The accepted values are `memory`,
`file` and `pebble`, and anything else is rejected at startup with
*"invalid storage backend: must be 'memory', 'file', or 'pebble'"*. Raft is
enabled by the server mode plus `raft-address` and `join-addresses`, **not** by
the storage backend — clustered nodes still use `pebble` for storage.

The legacy [`configuration.md`](configuration.md) in this folder says otherwise.
It is wrong; the validator is right.

**`node-id` must be unique and must never be reused.** If you replace a node,
give the replacement a new id.

**`data-dir` and `wal-dir` are required for the `pebble` backend**, and startup
fails without them.

---

## Watching the cluster

Since platformd's cluster API is not wired, the signals you actually have are:

**Platform health.** `platformctl health --detailed` shows the platform's
components. Note that **there is no `cluster` component** — nothing registers
one — so a cluster problem will not appear there directly. What you may see is
the downstream effect: subsystems that depend on replicated state going
degraded.

**Node logs.** The coordinator and membership manager log every lifecycle
transition when they are running. The lines worth alerting on:

| Line | Means |
|---|---|
| `health check failed to get nodes` | The coordinator cannot see the cluster; status is about to go degraded |
| `join attempt failed` | A seed address did not work; other seeds are still being tried |
| `failed to leave cluster gracefully` | Shutdown proceeded anyway |
| `health monitor shutdown timed out` | The health loop did not stop within 10 s |

**The database and consensus layers' own tooling.** For "is the cluster
formed, who is the leader, is there quorum", that is where the answer lives
today.

---

## What the commands will do when they are connected

For planning, and to set expectations correctly.

### Founding a cluster

Run bootstrap on **exactly one** node:

```bash
platformctl cluster bootstrap \
    --node-id node-a \
    --listen-addr node-a.example.com:7000
```

**Only once, ever, per cluster.** Bootstrapping two nodes creates two separate
one-node clusters that cannot be merged. There is no recovery from that other
than destroying one and re-joining it.

### Adding nodes

```bash
platformctl cluster join \
    --node-id node-b \
    --listen-addr node-b.example.com:7000 \
    --join node-a.example.com:7000
```

Give more than one seed where you can — one comma-separated flag, not a repeated
flag:

```bash
    --join node-a.example.com:7000,node-b.example.com:7000
```

### Removing a node

```bash
platformctl cluster leave
platformctl cluster leave --force            # when the cluster is unreachable
platformctl cluster leave --node-id node-b   # remove a different node
```

**Leaving does not transfer leadership.** If the node you remove is the leader,
the cluster elects a new one after the departure rather than handing off
cleanly. Prefer removing followers, and expect a brief election if you remove
the leader.

### Looking at it

```bash
platformctl cluster status
platformctl cluster nodes
```

Two things about `cluster status` output worth knowing before you read it:

- **`Commit Index` and `Applied Index` are always `0`.** They are printed for
  shape; the response carries neither.
- **`Voter Count` is actually the healthy-node count.** The label is wrong.

Use `cluster nodes` for the node list — `cluster status --include-nodes` sets a
flag on the request but the table renders no nodes.

---

## Behaviour you should expect once it works

**Quorum is a majority.** `(total / 2) + 1`:

| Nodes | Quorum | Failures tolerated |
|---|---|---|
| 1 | 1 | 0 |
| 3 | 2 | 1 |
| 5 | 3 | 2 |
| 7 | 4 | 3 |

Below quorum the cluster reports **degraded** with a message of the form
`insufficient healthy nodes: 1/2 required`, and an explicit health check returns
a quorum-lost error naming both numbers.

**Node lists are cached for five seconds.** The cache is invalidated before any
authoritative read — status, health sweeps, the node list — so a status taken
right after a membership change is accurate. A dashboard polling faster than 5 s
may see the same snapshot twice.

**Status refreshes on a five-second ticker** as well as on demand, so a cluster
that loses quorum is noticed within about five seconds even if nobody asks.

**Cluster membership needs `cluster:write`.** On gRPC, `Bootstrap`, `Join` and
`Leave` need `cluster:write`, and status and the node list need
`cluster:read`. The `platform_cluster_*` MCP tools are not classified yet, so
MCP refuses them for every caller ([api.md](api.md) §7).

---

## Troubleshooting

**`platformctl cluster` says unknown command.**
Expected. The command tree is not registered on the binary. See the top of this
file.

**Every cluster REST call returns 503 with "cluster service not configured".**
Expected. No coordinator is wired into the daemon.

**Cluster gRPC calls return "cluster: Bootstrap not implemented".**
Expected — that is the registered stub answering.

**MCP `platform_cluster_status` returns "cluster: service provider not
configured".**
Expected, same cause.

**Startup fails with "cluster service not enabled (build with -tags cluster)".**
The binary was built without the `cluster` tag. It is in the default tag set, so
this means a custom build.

**Startup fails with "QuicBaaS service does not support cluster coordination".**
The tag is present but the database layer does not expose a coordinator. That is
a lower-layer capability question, not a platform configuration one.

**Startup fails with "invalid storage backend".**
You set `storage-backend: raft`. Use `pebble` — see the configuration section.

**Two nodes each think they are a one-node cluster.**
Bootstrap was run on both. There is no merge. Destroy one node's data directory
and join it to the other.

**The cluster is up but the platform reports nothing about it.**
That is this feature's current state, not a fault. Use the database and
consensus layers' own tooling until the coordinator is wired.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag as written, plus corrections to the
  legacy CLI doc
- [api.md](api.md) — every capability on every transport, and the sizeable list
  of things the legacy API reference claims that do not exist
- [architecture.md](architecture.md) — who owns what, and exactly which wires
  are missing
- [engineering.md](engineering.md) — the contract an implementer works from
- **go-qrdb** / **go-quicbaas** — cluster formation, peer discovery and
  replication: the half of this feature that actually forms a cluster
