# Cluster — Architecture

> **Status: NORMATIVE** · Scope: `pkg/cluster/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Ownership: read this before anything else

**This repository does not implement consensus, peer discovery, or cluster
formation.** It does not run Raft. It does not elect leaders. It does not
replicate a log, take snapshots, or manage a membership protocol.

| Concern | Owner | Reached through |
|---|---|---|
| Raft primitives — log replication, elections, snapshots, transport | **go-quicraft** | not directly; via go-qrdb |
| **Peer discovery, cluster formation, membership** | **go-qrdb** | `go-quicbaas/sdk/go` |
| Database operations, consistency levels, state replication | **go-qrdb** | `go-quicbaas/sdk/go` |
| Composition and the single SDK edge this repo consumes | **go-quicbaas** | `go-quicbaas/sdk/go` |
| **A control-plane view of the cluster: lifecycle verbs, status projection, node list, quorum verdict, and the multi-protocol API for all of it** | **this repo** (`pkg/cluster/`) | — |

go-trusted-platform imports `go-quicbaas/sdk/go` and nothing below it. That is a
law of the stack, not a preference, and it is machine-enforced by
`pkg/arch/layerguard_test.go`.

**What this repository's `pkg/cluster` actually is:** an *orchestration and
projection* layer. It defines what a cluster looks like to a platform operator
— `Bootstrap`, `Join`, `Leave`, `Status`, `Nodes`, a quorum verdict, a health
loop — and it defines the interface (`RaftOperator`) through which some lower
layer supplies the consensus facts. It does not supply them.

The other half of this feature — the half that actually forms a cluster — is
documented by go-qrdb and go-quicbaas. This document covers only this repo's
half and links to theirs rather than restating it. Where the legacy files in
this folder describe Raft election timeouts, log-entry layout, `AppendEntries`,
ReadIndex, snapshot compaction, or PebbleDB state machines, they are describing
**someone else's code**, and this document supersedes them.

## 2. The problem

An operator running a platform control plane needs to ask: *is this cluster
healthy, who is the leader, how many nodes are up, do we have quorum?* — and to
drive the three lifecycle transitions: found a cluster, add this node to one,
remove this node from one.

Those questions have answers inside the consensus engine, but not in a shape a
control plane can publish. The engine speaks in terms of voters, terms and
configuration entries. The operator asks about nodes, health and quorum.

## 3. The shape chosen

Three layers, each a Go interface, with the concrete consensus engine pushed to
the bottom and out of this repository:

```
       ┌────────────────────────────────────────────────────────────┐
       │  transports: gRPC · Unix · REST · MCP   (no QUIC, no CLI)  │
       └───────────────────────────┬────────────────────────────────┘
                                   │
       ┌───────────────────────────▼────────────────────────────────┐
       │  cluster.Coordinator            pkg/cluster/coordinator.go │
       │  lifecycle · status snapshot · quorum verdict              │
       │  · background health loop · leadership queries             │
       └───────────────────────────┬────────────────────────────────┘
                                   │
       ┌───────────────────────────▼────────────────────────────────┐
       │  cluster.MembershipManager      pkg/cluster/member.go      │
       │  node cache (5 s TTL) · leader tracking · waiter fan-out   │
       └───────────────────────────┬────────────────────────────────┘
                                   │
       ┌───────────────────────────▼────────────────────────────────┐
       │  cluster.RaftOperator           pkg/cluster/member.go      │
       │  AddVoter · RemoveServer · GetLeader · GetNodes · GetTerm  │
       │  ── THE SEAM. No implementation in this repository. ──     │
       └────────────────────────────────────────────────────────────┘
                                   │
                    supplied by the stack below, through
                    go-quicbaas/sdk/go → go-qrdb → go-quicraft
```

`RaftOperator` is the whole point of the design. It is deliberately small — nine
methods, all of them things a Raft implementation already knows — so that this
repository can express the operator's model of a cluster without importing, or
reimplementing, any part of the consensus engine.

The `Coordinator` adds exactly two things the engine does not provide:

- **A quorum verdict.** `quorumSize = (totalNodes / 2) + 1`, compared against
  the healthy count. That is the number an operator needs and the engine does
  not publish.
- **A background health loop.** A ticker (5 s by default) that refreshes the
  status snapshot so `Status` is cheap and a stale cluster is noticed without
  anyone asking.

### How the coordinator is obtained at runtime

`daemon.ClusterService` (built under the `cluster` build tag,
`pkg/api/daemon/cluster_service.go`) does **not** construct a coordinator. It
asks the QuicBaaS service for one:

```go
type clusterComponentsGetter interface {
	GetClusterCoordinator(ctx context.Context) (cluster.Coordinator, error)
}
```

It reaches that interface by walking `App.DAOFactory()` → `*quicbaas.Factory` →
`Client()` → `Service()` and type-asserting. If the assertion fails it returns
`"QuicBaaS service does not support cluster coordination (build with -tags cluster)"`.

**That is the SDK edge this feature consumes**, and it is why
`cluster.NewCoordinator` and `cluster.NewMembershipManager` — both exported,
both fully implemented — have **no caller in non-test code in this repository**.
They exist as the reference implementation of the interfaces and as the shape a
lower-layer coordinator must satisfy.

### Current wiring state — the part a reader must not get wrong

Verified by grep on 2026-08-18:

| Symbol | Callers outside tests |
|---|---|
| `cluster.NewCoordinator` | **none** |
| `cluster.NewMembershipManager` | **none** |
| `cluster.RaftOperator` implementations | **none in this repo** |
| `daemon.NewClusterService` | **none** |
| `daemon.Daemon.SetClusterService` | **none** |

The gRPC service the daemon actually registers is
`daemon.ClusterGRPCService` (`pkg/api/daemon/cluster_grpc_service.go`), whose
own doc comment says *"This stub returns Unimplemented for all methods until the
full cluster coordinator is wired in."* It does. The REST handlers wrap that
same stub, and MCP's `platform_cluster_*` tools return
`ErrClusterNotConfigured` because no provider is ever set.

**So today: the interfaces, the coordinator implementation, the state machine,
the node registry, the transports and the CLI package all exist, and no shipped
code path connects them to a consensus engine.** Every cluster call on every
transport returns "unimplemented" or "not configured". That is the honest state
of this feature, it is recorded here rather than in a footnote, and
[api.md](api.md) shows it per capability.

A second, fully-implemented `ClusterGRPCService` exists at
`pkg/api/grpc/cluster_service.go`, delegating to a `grpc.ClusterService`
interface with a richer request shape (cluster names, labels, selectors,
pagination). **It has no implementor and is not registered anywhere.** Two
service types with the same name in two packages, one stubbed and registered,
one complete and unregistered, is the single most confusing thing in this
feature — [engineering.md](engineering.md) §8.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Implement Raft in this repository** | Consensus is go-quicraft's, and cluster formation and peer discovery are go-qrdb's. A second implementation at Layer 5 would be a boundary violation, and a consensus engine is the last thing to have two of. |
| **Import go-qrdb or go-quicraft directly for their cluster types** | This repo imports `go-quicbaas/sdk/go` **only**, enforced by `pkg/arch/layerguard_test.go`. `RaftOperator` exists precisely so the dependency is an interface this repo declares rather than a package it imports. |
| **Expose the quicbaas/qrdb cluster API straight through** | The lower layer's model is a database cluster: voters, terms, configuration entries. The platform's model is nodes with health, an operator-facing quorum verdict, and a lifecycle. Projecting is what `Coordinator` is for, and it is why `ClusterStatus` carries `HasQuorum` and `HealthyCount`, which no Raft API returns. |
| **Skip the `Coordinator` layer — put lifecycle straight on `MembershipManager`** | The coordinator owns things membership does not: the running/stopped lifecycle, the health ticker, the atomically-published status snapshot, and the graceful-shutdown ordering (stop the monitor, then leave). Folding them into membership would make every status read hit Raft. |
| **Cache nothing — hit the engine on every query** | A dashboard polling node lists would hit consensus on every refresh. The membership manager caches for 5 s and exposes `InvalidateCache()`; `Coordinator.Nodes` and every health sweep call it, so freshness is explicit at the call sites that need it and cheap everywhere else. |
| **Cache with no invalidation hook** | Then a `Status` immediately after a `Join` would report the pre-join cluster. `InvalidateCache` is called before every authoritative read. |
| **A single node-state enum** | Two vocabularies exist deliberately: `NodeState` (membership: healthy/unhealthy/suspect/leaving) is what the cache tracks, and `ExtendedNodeState` (adds `unreachable`, and a liveness rule) is what a health-tracking registry needs. `ToNodeState()` converts one way; the extra state has no equivalent and collapsing them would lose it. |
| **Free-form state transitions** | `RaftClusterState` declares an explicit transition table and `CanTransitionTo` refuses anything not in it, so an illegal transition is `ErrInvalidStateTransition` at the point it is attempted rather than a corrupt state discovered later. Same-state transitions are allowed for idempotency. |
| **Blocking `WaitForLeader` on a polling loop in each caller** | Every caller would poll independently. The membership manager runs one 100 ms leader-check ticker and fans out to registered waiter channels, so N waiters cost one poller. |
| **Making `Leave` synchronous on leadership transfer** | Noted as a known simplification in the code: `membershipManager.Leave` removes the node without transferring leadership first. Recorded in [engineering.md](engineering.md) §7 as a limitation, not documented here as if it were a design. |

## 4. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `Coordinator` interface + implementation, `ClusterStatus`, `ClusterState` | `pkg/cluster/coordinator.go` | this repo |
| `MembershipManager` interface, `Node`, `NodeList`, `NodeState` | `pkg/cluster/types.go` | this repo |
| `membershipManager` implementation, `RaftOperator`, `RaftMemberInfo`, `RaftState` | `pkg/cluster/member.go` | this repo |
| `Config`, validation, functional `With*` copiers | `pkg/cluster/config.go` | this repo |
| `RaftClusterState` machine, transition table, `RaftStateManager` | `pkg/cluster/state.go` | this repo |
| `ExtendedNode`, `ExtendedNodeList`, `ExtendedNodeRegistry` | `pkg/cluster/node.go` | this repo |
| 37 typed errors | `pkg/cluster/errors.go` | this repo |
| Daemon service (build tag `cluster`) | `pkg/api/daemon/cluster_service.go` | this repo |
| Registered gRPC service (**a stub**) | `pkg/api/daemon/cluster_grpc_service.go` | this repo |
| REST adapter over that stub | `pkg/api/daemon/cluster_rest.go` | this repo |
| MCP tools and the tag-agnostic bridge | `pkg/api/mcp/cluster_tools.go`, `pkg/api/daemon/mcp_cluster.go`, `mcp_cluster_adapter.go` | this repo |
| Unregistered full gRPC service | `pkg/api/grpc/cluster_service.go`, `cluster_types.go` | this repo |
| CLI package (**not registered on any root command**) | `pkg/cli/commands/cluster/` | this repo |
| SDK client | `sdk/go/services/cluster/` | this repo |
| **Raft consensus, elections, log replication, snapshots** | **go-quicraft** | **not this repo** |
| **Peer discovery, cluster formation, membership protocol, state replication, consistency levels** | **go-qrdb** | **not this repo** |
| **The composed SDK this repo consumes** | **go-quicbaas** (`sdk/go`) | **not this repo** |

## 5. Data flow

### Bootstrap — founding a cluster

```
transport ──▶ ClusterService.Bootstrap(ctx)
                  │  not running ⇒ ErrServiceNotRunning
                  ▼
              Coordinator.Bootstrap(ctx)
                  │  not running ⇒ ErrCoordinatorNotRunning
                  ├─ status → ClusterStateBootstrapping
                  ├─ MembershipManager.Bootstrap(ctx)
                  │     ├─ already joined ⇒ ErrAlreadyJoined
                  │     ├─ RaftOperator.Bootstrap(ctx)   ◄── the stack below
                  │     └─ mark local node healthy, seed the cache
                  ├─ failure ⇒ status → Degraded + ErrorMessage; ErrBootstrapFailed
                  ├─ success ⇒ status → Running
                  └─ performHealthCheck()   (populate node count immediately)
```

### Join — adding this node

Same shape, through `MembershipManager.Join`, which tries each address in order
and returns `ErrJoinFailed` naming the first address only if **all** fail.

**`tryJoin` is a placeholder.** Its own comment says so: rather than dialling
the target and asking the leader to add it, it calls
`RaftOperator.AddVoter(ctx, ownNodeID, ownAdvertiseAddress)` **locally**. The
address argument is used only for validation and error reporting. A real
implementation would connect to the target, send a join request, and wait for
the leader to add it. This is a limitation, not a design.

### Status — the read path

```
Coordinator.Status(ctx)
    ├─ performHealthCheck()            ── always, so Status is never stale
    │     ├─ MembershipManager.InvalidateCache()
    │     ├─ GetNodes(ctx)             ── refreshes from RaftOperator.GetNodes
    │     ├─ quorumSize := (total / 2) + 1;  hasQuorum := healthy >= quorumSize
    │     ├─ GetLeader(ctx)            ── leaderID, or 0
    │     └─ atomically publish ClusterStatus{State, counts, LeaderID, HasQuorum}
    └─ return a COPY of the snapshot   ── callers cannot mutate coordinator state
```

The same `performHealthCheck` runs on the background ticker
(`DefaultCoordinatorHealthCheckInterval`, 5 s), bounded by half the interval, so
a `Status` call and the background loop cannot drift apart.

### The node cache

`membershipManager` keeps `map[uint64]*Node` with a **5-second TTL**
(`cacheDuration`, a hard-coded constant, not configuration). `refreshNodeCache`
merges `RaftOperator.GetNodes()` over it:

- a node present in Raft updates `LastSeen` and its leader flag,
- the leader's address is overwritten from `GetLeader()` when non-empty,
- a node **absent** from Raft is marked `NodeStateLeaving` — except the local
  node, which is exempt so a node that just joined is not immediately marked
  gone.

`GetNodes` returns **clones**, so a caller cannot mutate the cache.

### What is persisted

**Nothing, by this repository.** `Config.DataDir` (default `./data/cluster`) is
a configuration field that is validated as non-empty and then **never read by
any code in `pkg/cluster`** — no file is opened, created or written. Raft
persistence belongs to the layer below. Everything in `pkg/cluster` — the status
snapshot, the node cache, the state machine, the extended registry — is process
memory and dies with the process.

### What crosses a boundary

- **Process/host boundary**: every `RaftOperator` call, whatever the layer below
  does with it. `pkg/cluster` performs no I/O of its own — no sockets, no files,
  no `os/exec`.
- **Cluster communication** happens on `Config.ListenAddress` (default
  `0.0.0.0:7000`), advertised as `Config.AdvertiseAddress` when set, and is
  established by the layer below.

## 6. Trust boundaries

Cluster membership is a trust decision — a node admitted to the cluster
participates in replicated state — but **this repository does not make it**. The
controls that matter live below the `RaftOperator` seam, in go-qrdb and
go-quicraft: transport authentication, the barrier and sealing strategy, and
identity of the joining node. Do not document them here; see those repos.

Within this repo's half:

1. **`AddNode` and `RemoveNode` are leader-only**, checked before the call
   reaches `RaftOperator`. A follower gets `ErrNodeNotLeader` carrying the
   current leader's id so the caller can redirect. This is a routing guard, not
   an authorization control.
2. **`Join` addresses are operator input reaching a network dial.** The CLI
   validates `host:port` shape (`validateAddress` via `net.SplitHostPort`);
   `membershipManager.Join` rejects only the empty string. **There is no
   allow-list, no identity check and no attestation gate on a join address in
   this layer.**
3. **The cluster API is not in the authorization catalog.** `ClusterService` is
   **absent** from the gRPC scope catalog (`pkg/api/grpc/method_permissions.go`),
   and the `platform_cluster_*` tools are **absent** from the MCP permission map
   (`pkg/api/mcp/authz.go`). MCP refuses an unclassified tool (#300), but the
   gRPC catalog is default-allow, so **any validated token could call
   Bootstrap, Join and Leave over gRPC** if the service were wired.
   Today it is not, so the exposure is latent rather than live — but wiring the
   coordinator without adding scopes would make cluster lifecycle
   scope-unchecked. Recorded in [api.md](api.md) §6 and in the platform-wide
   question in [`docs/daemon/api.md`](../daemon/api.md) §5.
4. **`ClusterStatus` and the node list are operational disclosure**: node ids,
   addresses, leader identity, term, quorum state. Not secret, but not
   nothing — a reader learns the topology and which node to attack to lose
   quorum.
5. **`Leave` does not transfer leadership.** A leader that leaves forces an
   election rather than handing off. Availability, not confidentiality, but it
   is a property of the boundary.

## 7. What this feature deliberately does not do

- **It does not implement Raft.** No elections, no log replication, no
  snapshots, no `AppendEntries`, no ReadIndex. go-quicraft does, under go-qrdb.
- **It does not discover peers or form clusters.** go-qrdb does, reached through
  `go-quicbaas/sdk/go`.
- **It does not replicate application state.** Which platform data is replicated
  and under what consistency level is a go-qrdb question. The legacy
  `README.md` and `architecture.md` in this folder describe SDN, CA, DNS,
  device-profile and tenant replication as if this package performed it; it does
  not.
- **It does not persist anything.** `DataDir` is validated and unused here.
- **It does not define consistency levels.** `linearizable` / `strong` /
  `eventual` are `quicbaas.ConsistencyLevel` values, configured under the
  `quicbaas:` section, not the cluster's.
- **It does not remove a remote node from the API.** `MembershipManager.AddNode`
  and `RemoveNode` exist as Go calls; no transport exposes them
  ([api.md](api.md) §3). The legacy `api-reference.md` documents `GetNode`,
  `RemoveNode` and `TransferLeadership` RPCs. **None of them exists** — the
  proto declares five RPCs, and that is the whole service.
- **It does not transfer leadership.** No `TransferLeadership` anywhere.
- **It does not expose anything on QUIC.** There is no cluster opcode.
- **It does not ship a CLI.** `pkg/cli/commands/cluster` is complete and
  registered on no root command ([cli.md](cli.md)).
- **It does not enforce a node's right to join.** See §6.

## 8. Related

- [engineering.md](engineering.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/health/`](../health/) — the platform health registry. **There is no
  `cluster` health component**; `Coordinator.HealthCheck` is a Go call, not a
  registered checker
- Legacy files in this folder, superseded by this document where they conflict:
  `README.md`, `configuration.md`, `cli-usage.md`, `api-reference.md`. They
  document the lower layers' internals and an API surface that does not exist.
- The other half of this feature is documented by **go-qrdb** (cluster
  formation, peer discovery, replication) and **go-quicbaas** (the SDK edge this
  repo consumes). This repository does not document their code.
