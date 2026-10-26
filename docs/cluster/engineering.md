# Cluster — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/cluster/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

**Ownership first:** consensus, peer discovery and cluster formation are
**go-qrdb's** (over **go-quicraft**), consumed through `go-quicbaas/sdk/go`.
This package is the platform's orchestration and projection layer over an
externally supplied consensus engine. See [architecture.md](architecture.md) §1.

Every identifier below was read out of `pkg/cluster/`, `pkg/api/daemon/`,
`pkg/api/grpc/` and `pkg/cli/commands/cluster/` on 2026-08-18.

---

## 1. Package layout

| File | Holds |
|---|---|
| `pkg/cluster/types.go` | `NodeState`, `Node`, `NodeList`, `MembershipManager` |
| `pkg/cluster/coordinator.go` | `ClusterState`, `ClusterStatus`, `Coordinator`, `CoordinatorOption`, `NewCoordinator`, unexported `coordinator` |
| `pkg/cluster/member.go` | `RaftOperator`, `RaftMemberInfo`, `RaftState`, `NewMembershipManager`, unexported `membershipManager` |
| `pkg/cluster/config.go` | `Config`, defaults, `NewConfig`, `Validate`, `Clone`, the `With*` copiers |
| `pkg/cluster/state.go` | `RaftClusterState`, the transition table, `RaftClusterStatus`, `RaftStateManager`, `NewRaftStateManager` |
| `pkg/cluster/node.go` | `ExtendedNodeState`, `ExtendedNode`, `ExtendedNodeList`, `ExtendedNodeRegistry` |
| `pkg/cluster/errors.go` | 37 typed errors |

## 2. The three interfaces

### `RaftOperator` — the seam

```go
type RaftOperator interface {
	Bootstrap(ctx context.Context) error
	AddVoter(ctx context.Context, id uint64, address string) error
	AddNonvoter(ctx context.Context, id uint64, address string) error
	RemoveServer(ctx context.Context, id uint64) error
	GetLeader() (id uint64, address string, err error)
	GetNodes() ([]RaftMemberInfo, error)
	IsLeader() bool
	GetState() RaftState
	GetTerm() uint64
}
```

**No implementation of this interface exists in this repository outside tests.**
It is the contract the layer below satisfies. `RaftMemberInfo` is
`{ID uint64, Address string, Voter bool}`. `RaftState` is
`RaftStateFollower | RaftStateCandidate | RaftStateLeader | RaftStateShutdown`
(an `int32` enum, iota-ordered).

Note that `AddNonvoter` and `GetState` are declared and **never called** by
`membershipManager`.

### `MembershipManager` — 13 methods

`Bootstrap`, `Join(addresses)`, `Leave`, `AddNode(nodeID, address)`,
`RemoveNode(nodeID)`, `GetNodes` → `(NodeList, error)`, `InvalidateCache`,
`GetLeader`, `IsLeader`, `WaitForLeader`, `LocalNode`, `GetTerm`, `Close`.

`NewMembershipManager(config *Config, raftOp RaftOperator, logger *logging.Logger) (*membershipManager, error)`
returns the **unexported concrete type** — unusual for this codebase, and it
means callers outside the package receive a pointer they can only use through
the interface. The constructor **starts a goroutine** (the 100 ms leader-check
ticker) before returning, so a manager that is created must be `Close`d.

### `Coordinator` — 15 methods

`Start`, `Stop`, `IsRunning`, `Bootstrap`, `Join(addresses)`, `Leave`,
`Status` → `(*ClusterStatus, error)`, `Nodes` → `(NodeList, error)`,
`IsLeader`, `GetLeader`, `WaitForLeader`, `IsHealthy`, `HealthCheck`,
`Config`, `NodeID`.

```go
func NewCoordinator(config *Config, membership MembershipManager,
	logger *logging.Logger, opts ...CoordinatorOption) (Coordinator, error)
```

| Option | Sets | Default constant | Value |
|---|---|---|---|
| `WithCoordinatorHealthCheckInterval(d)` | health ticker period | `DefaultCoordinatorHealthCheckInterval` | `5s` |
| `WithCoordinatorLeaderWaitTimeout(d)` | leader wait bound | `DefaultCoordinatorLeaderWaitTimeout` | `30s` |
| `WithCoordinatorShutdownTimeout(d)` | graceful shutdown bound | `DefaultCoordinatorShutdownTimeout` | `10s` |

`NewCoordinator` returns `ErrNilConfig`, `ErrNilMembership` or `ErrNilLogger`
for nil arguments, then `config.Validate()`'s error. The initial published
status is `ClusterStateUninitialized`.

**`leaderWaitTimeout` is stored and never read.** `Coordinator.WaitForLeader`
delegates straight to `MembershipManager.WaitForLeader(ctx)`, which bounds on
the caller's context. The option exists and has no effect.

## 3. Configuration

`cluster.Config` is a **Go struct constructed programmatically**. It has no
`yaml`, `json` or `mapstructure` tags on any field, and there is **no
`cluster:` section in the platform configuration file.** Nothing in this repo
parses one.

| Field | Type | `NewConfig()` default | Validation |
|---|---|---|---|
| `NodeID` | `uint64` | `1` | `> 0` |
| `ListenAddress` | `string` | `"0.0.0.0:7000"` | non-empty |
| `AdvertiseAddress` | `string` | `""` | — (falls back to `ListenAddress`) |
| `JoinAddresses` | `[]string` | `nil` | — (empty ⇒ bootstrap node) |
| `DataDir` | `string` | `"./data/cluster"` | non-empty — **and then never read** |
| `HeartbeatInterval` | `time.Duration` | `DefaultHeartbeatInterval` = `100ms` | `> 0` |
| `ElectionTimeout` | `time.Duration` | `DefaultElectionTimeout` = `1s` | `> 0` **and** `>= 2 × HeartbeatInterval` |
| `SnapshotInterval` | `time.Duration` | `DefaultSnapshotInterval` = `5m` | `> 0` |
| `SnapshotThreshold` | `uint64` | `DefaultSnapshotThreshold` = `10000` | `> 0` |
| `MaxConcurrentStreams` | `int` | `DefaultMaxConcurrentStreams` = `256` | `> 0` |

Every validation failure is `ErrInvalidConfig{Field, Reason}`.

**`HeartbeatInterval`, `ElectionTimeout`, `SnapshotInterval`,
`SnapshotThreshold`, `MaxConcurrentStreams` and `DataDir` are validated and then
unused by anything in `pkg/cluster`.** They are the tuning surface the layer
below needs, carried through this struct. Do not document them as though this
package acts on them; it does not.

Accessors and copiers:

- `GetAdvertiseAddress()` — `AdvertiseAddress` if set, else `ListenAddress`.
- `IsBootstrap()` — `len(JoinAddresses) == 0`.
- `Clone()` — deep copy, including `JoinAddresses`. **`Clone` does not copy
  `AdvertiseAddress`.** That is a bug in `config.go`: every field is copied
  except that one, so `WithNodeID`, `WithDataDir` and every other `With*`
  copier silently drops a configured advertise address. Recorded here; the code
  is the defect.
- `WithNodeID`, `WithListenAddress`, `WithAdvertiseAddress`, `WithJoinAddresses`,
  `WithDataDir`, `WithHeartbeatInterval`, `WithElectionTimeout`,
  `WithSnapshotInterval`, `WithSnapshotThreshold`, `WithMaxConcurrentStreams` —
  all `Clone` then set one field, so all inherit the bug above except
  `WithAdvertiseAddress` itself.

### Where the operator-facing configuration actually lives

Cluster deployment is configured under **`quicbaas:`**, not `cluster:`
(`pkg/storage/quicbaas/config.go`):

| Key | Type | Notes |
|---|---|---|
| `quicbaas.storage-backend` | string | `memory` \| `file` \| `pebble`. **`raft` is NOT a valid value** |
| `quicbaas.data-dir` | string | required for `file`/`pebble` |
| `quicbaas.wal-dir` | string | required for `pebble`; defaults to `<data-dir>/wal` |
| `quicbaas.node-id` | uint64 | unique per node |
| `quicbaas.raft-address` | string | `host:port` advertised to peers; env `PLATFORMD_QUICBAAS_RAFT_ADDRESS`, flag `--raft-address` |
| `quicbaas.raft-listen-address` | string | `host:port` the Raft transport binds; empty binds `raft-address`; env `PLATFORMD_QUICBAAS_RAFT_LISTEN_ADDRESS`, flag `--raft-listen-address` |
| `quicbaas.join-addresses` | []string | every member as `id=host:port`, this node included; non-empty makes the node clustered |
| `quicbaas.deployment-id` | uint64 | required when clustered; the same on every member |
| `quicbaas.raft-tls-cert-file`, `raft-tls-key-file`, `raft-tls-ca-file` | string | required when clustered; Raft peer mTLS |
| `quicbaas.consistency-level` | `linearizable` \| `strong` \| `eventual` | default `linearizable` |
| `quicbaas.cache-size`, `compression`, `sync-writes`, `log-level`, `request-timeout` | | |
| `quicbaas.startup-timeout` | duration | default `2m`; liveness backstop for embedded-server startup |

**Raft addresses are configuration, never probed** (#93). `pkg/config/raft.go`
binds both keys to the file, the environment and `platformd serve` flags. A node
with `join-addresses` must advertise a routable `raft-address`. If it is
loopback, unspecified or empty, `Config.Validate` returns
`ErrRaftAdvertiseAddress`, which names the three ways to set it. A single node
may leave the address loopback. Free-port probing exists only in the test
constructors (`pkg/storage/quicbaas/testconfig.go`). The upstream embedded node
(go-quicbaas `pkg/server/qrdb_node.go`) still rewrites an empty
`raft-listen-address`, or `127.0.0.1:63000`, to `0.0.0.0:<port>`. Until that is
fixed upstream, an explicit non-default `raft-listen-address` is the only way to
keep the Raft bind off the wildcard.

**A clustered config is mapped onto go-quicbaas cluster mode, and checked
first** (#685). Formation is go-qrdb's, reached through go-quicbaas; the
platform only passes config through. `Config.IsClustered` is
`len(join-addresses) > 0`. For a clustered node, `ToQuicBaaSConfig` sets
`Server.Mode` to `ServerModeCluster` and copies `join-addresses`,
`deployment-id` and the three Raft TLS paths into `Raft`. A standalone node's
mapping is unchanged: those fields stay empty even when set. `validateCluster`
refuses, with typed errors, what go-quicbaas would otherwise accept silently:

| go-quicbaas behavior (`pkg/server`) | Platform check |
|---|---|
| An empty `Server.Mode` starts a standalone node | mode set from `join-addresses` |
| `buildClusterMembers` drops entries without `id=`; with none it starts a one-node cluster | `ErrRaftPeerAddress` on any entry that is not `id=host:port` |
| Bootstrap requires self in the members map | `ErrRaftSelfPeer` unless the list holds `node-id=raft-address` |
| `ParsePeers` keeps the last of two equal IDs | `ErrRaftDuplicatePeer` |
| `buildQRDBConfig` derives `DeploymentID` from `NodeID` when unset, so members disagree | `ErrRaftClusterField` on a zero `deployment-id` or `node-id` |
| No TLS files falls through to auto-enrolled or (without `-tags raft`) plaintext transport | `ErrRaftTLSRequired` names each missing `raft-tls-*-file` |

The TLS check is presence only; go-quicbaas reads the files at start and fails
with `RaftMTLSLoadError`. TPM-held Raft keys are out of scope until the issuer
of peer certificates is ruled on. `TestShippedExamples_LoadOnTheCurrentSchema`
(`pkg/app/example_configs_test.go`) loads every `configs/platform/cluster` and
`configs/platform/standalone` example through platformd's strict key check and
full decode, `Validate`, and the host-network and web-service checks, and
refuses a literal secret in any of them. `TestShippedClusterExamples_*`
(`pkg/app/templates_network_test.go`) prove the three servers form one cluster.

**`startup-timeout` is deliberately separate from `request-timeout`** (#270).
`request-timeout` bounds ONE DAO operation; startup constructs the data-plane
barrier, opens and closes the TPM, creates the system tenant and seeds five
roles. The budget used to be `request-timeout * 3`, so lowering the request
timeout silently retuned startup in a ratio nobody chose.

Two things to know when reading a startup failure:

- **The caller's context is normally the binding constraint, not this
  budget.** The embedded server's `Start` runs `initialize` synchronously and
  returns without blocking, so whatever context the daemon passes to
  `Start(ctx)` is what actually bounds first boot. `startup-timeout` only
  bounds a hang.
- **The two are reported as different errors on purpose.**
  `ErrStartupCanceled` names the caller's context and how long startup had
  been running; `ErrStartupTimeout` names the budget. They previously shared
  one message, which is how #270 came to be diagnosed as a budget problem
  when the caller's 30s deadline was the constraint and the budget had 56
  seconds left.

**The package's DAO tests share one embedded server** (#208). Booting a server
per test made bootstrap nearly all of the package's wall time, and that cost
grows with host load. `newSharedTestClient` (`shared_server_test.go`) boots
the server on first use and `TestMain` stops it. Before each test it deletes
every entity of the types the DAO tests write, which leaves the store in the
state a fresh server has. `TestSharedServer_FreshServerHoldsNoTestEntities`
pins that equivalence: if first boot ever seeds one of those types, that test
fails before any data is wiped. Tests whose subject is the server or client
lifecycle still boot their own server. Tests on the shared server must not
call `t.Parallel`.

**Correction to the deleted legacy `docs/cluster/configuration.md`:** that file documented
`storage-backend: raft` as the way to enable clustering. It is not.
`validateEmbeddedConfig` rejects anything but `memory`, `file` and `pebble` with
*"invalid storage backend: must be 'memory', 'file', or 'pebble'"*, and the code
comment on `StorageBackend` says explicitly *"Raft consensus is enabled
separately via server mode, not storage backend."* `RaftTestConfig` confirms it:
it sets `StorageBackendPebble` with a `RaftAddress`, commented *"Raft uses
pebble for storage."*

Clustering additionally requires the **`cluster` build tag**, which is in the
default `BUILD_TAGS` (`make -s print-build-tags` prints the derived set — the
tags are assembled in two stages, so any hand-copied list is wrong). Without it,
`daemon.NewClusterService` is the stub in `cluster_service_stub.go` and returns
`"cluster service not enabled (build with -tags cluster)"`.

## 4. State machines

Two, with different vocabularies, both in this package.

### `ClusterState` — the coordinator's published state (a `string`)

`uninitialized` → `bootstrapping` | `joining` → `running` ⇄ `degraded` →
`leaving` → `stopped`.

There is **no transition table and no guard** on `ClusterState`. The coordinator
assigns it directly at each step, and `performHealthCheck` flips between
`running` and `degraded` purely on quorum.

### `RaftClusterState` — a guarded state machine (a `string`)

`uninitialized`, `bootstrapping`, `joining`, `follower`, `candidate`, `leader`,
`leaving`, `shutdown`. `validRaftClusterTransitions` declares the legal edges;
`CanTransitionTo` allows same-state transitions for idempotency and refuses
anything else. `shutdown` is terminal.

Predicates: `IsValid`, `IsTerminal`, `IsOperational` (follower/candidate/leader),
`IsTransitioning` (bootstrapping/joining/leaving), `IsRaftRole`.
Helpers: `ParseRaftClusterState`, `AllRaftClusterStates`.

`RaftStateManager` (`NewRaftStateManager()`): `GetState`, `SetState`,
`GetStatus`, `UpdateStatus`, `WaitForState`, `OnStateChange`. `RaftClusterStatus`
carries `State`, `NodeID`, `LeaderID`, `Term`, `CommitIndex`, `AppliedIndex`,
`NodeCount`, `HealthyCount`, `LastHeartbeat`, `StartTime`, with `Uptime()` and
`IsHealthy()` (operational, and — unless leader — a heartbeat within 30 s).

**`RaftStateManager` has no caller anywhere in this repository, including
tests-in-anger.** It is a complete, unwired mechanism. `ErrInvalidClusterState`
and `ErrInvalidStateTransition` both take a `ClusterState`, so
`RaftClusterState` values are cast into the other type to construct them.

## 5. Node vocabularies

Three node types, deliberately distinct:

| Type | Where | State type | Purpose |
|---|---|---|---|
| `Node` | `types.go` | `NodeState` (`int32`) | What `MembershipManager` and `Coordinator` return |
| `RaftMemberInfo` | `member.go` | — | What `RaftOperator` returns: `{ID, Address, Voter}` |
| `ExtendedNode` | `node.go` | `ExtendedNodeState` (`string`) | Health-tracking registry entry |

`NodeState`: `NodeStateUnknown`, `NodeStateHealthy`, `NodeStateUnhealthy`,
`NodeStateSuspect`, `NodeStateLeaving`. `String()` maps unknown-or-out-of-range
to `"unknown"`.

`ExtendedNodeState`: `unknown`, `healthy`, `unhealthy`, **`unreachable`**,
`leaving`. `ToNodeState()` converts down; **`unreachable` has no `NodeState`
equivalent and becomes `NodeStateUnknown`.** That lossiness is the reason the
two types exist.

`Node.IsHealthy()` is a pure state check. **`ExtendedNode.IsHealthy()` is a
state check plus a liveness rule**: `LastSeen` must be within a hard-coded
**30 seconds**. The two methods do not agree, by design.

`NodeList` (`{Nodes []*Node, Leader *Node, Term uint64}`) offers `Count`,
`HealthyCount`, `FindByID`, `Healthy`.
`ExtendedNodeList` (`[]ExtendedNode`) offers `Leader`, `Followers`, `Healthy`,
`Count`, `ByID`, `ByAddress`, `ByRaftAddress`, `SortByID`, `SortByJoinTime`,
`Filter`.

`ExtendedNodeRegistry` (`NewExtendedNodeRegistry()`) is a mutex-guarded
`map[uint64]*ExtendedNode` with `Add`, `Remove`, `Get`, `List`, `UpdateState`,
`SetLeader`, `ClearLeader`, `Count`, `HealthyCount`, `UpdateLastSeen`,
`GetLeader`. Everything in and out is a `Clone`. **`SetLeader` clears every
other node's leader flag before setting the target's — and clears them even
when the target does not exist**, returning `ErrNodeNotFound` with the cluster
left leaderless in the registry's view. Recorded; the code is the defect.

**`ExtendedNodeRegistry` has no caller outside tests**, the same status as
`RaftStateManager`.

## 6. Error semantics

37 struct types in `errors.go`, all implementing `error`; those carrying a
`Cause` implement `Unwrap`. Match with `errors.As`.

### By operation

| Operation | Errors |
|---|---|
| `NewCoordinator` | `ErrNilConfig`, `ErrNilMembership`, `ErrNilLogger`, `ErrInvalidConfig` |
| `Coordinator.Start` | `ErrCoordinatorAlreadyRunning` |
| `Coordinator.Stop` | `ErrCoordinatorNotRunning` |
| every other `Coordinator` method | `ErrCoordinatorNotRunning` when not started |
| `Coordinator.Bootstrap` | `ErrBootstrapFailed{Reason, Cause}` |
| `Coordinator.Join` | `ErrNoJoinAddresses`, `ErrJoinFailed{NodeID, Address, Reason, Cause}` |
| `Coordinator.Leave` | `ErrLeaveFailed{NodeID, Reason, Cause}` |
| `Coordinator.Status` | `ErrStatusUnavailable` |
| `Coordinator.HealthCheck` | `ErrHealthCheckFailed{Reason, Cause}`, `ErrQuorumLost{Required, Available}`, `ErrNoLeader` |
| `membershipManager.*` | `ErrManagerClosed`, `ErrAlreadyJoined`, `ErrNotJoined` |
| `membershipManager.AddNode` | `ErrNodeNotLeader{NodeID, LeaderID}`, `ErrInvalidConfig`, `ErrInvalidAddress`, `ErrNodeAlreadyExists`, `ErrAddNodeFailed` |
| `membershipManager.RemoveNode` | `ErrNodeNotLeader`, `ErrInvalidConfig`, `ErrNodeNotFound`, `ErrRemoveNodeFailed` |
| `membershipManager.GetNodes` / `GetLeader` | `ErrClusterUnavailable{Reason}`, `ErrNoLeader` |
| `membershipManager.WaitForLeader` | `ErrLeadershipTimeout` |
| `membershipManager.tryJoin` | `ErrInvalidAddress`, `ErrTimeout{Operation}`, `ErrJoinFailed` |
| `ExtendedNodeRegistry` | `ErrNilNode`, `ErrInvalidNodeID`, `ErrNodeNotFound`, `ErrInvalidNodeState` |
| `RaftStateManager` | `ErrContextCancelled`, `ErrInvalidClusterState`, `ErrInvalidStateTransition` |

Declared and never returned by any code path:
`ErrClusterNotInitialized`, `ErrClusterAlreadyInitialized`,
`ErrConnectionFailed`, `ErrClusterNotReady`, `ErrLeadershipLost`.

### Fail-closed paths

- **`AddNode` / `RemoveNode` refuse on a non-leader**, before touching
  `RaftOperator`, returning `ErrNodeNotLeader` with the current leader's id so
  the caller can redirect.
- **`Bootstrap` and `Join` refuse when already joined** (`ErrAlreadyJoined`), so
  a second bootstrap cannot split the cluster from this layer.
- **`Join` with an empty address list is refused** at both the coordinator and
  the membership manager (`ErrNoJoinAddresses`).
- **`AddNode` refuses a duplicate node id** (`ErrNodeAlreadyExists`, checked
  against the cache) and **`RemoveNode` refreshes the cache before concluding a
  node does not exist**, so a stale cache cannot cause a spurious
  `ErrNodeNotFound`.
- **`HealthCheck` reports quorum loss as an error**, not as a degraded status:
  `ErrQuorumLost{Required, Available}`, and `ErrNoLeader` when there is no
  leader.
- **`RaftClusterState.SetState` refuses an illegal transition.**
- **Every coordinator method refuses when the coordinator is not running.**

### Not fail-closed

- **A failed lifecycle operation publishes `ClusterStateDegraded` with
  `ErrorMessage` and returns the error** — the coordinator stays running.
- **`Coordinator.Stop` logs and continues when `membership.Leave` fails.**
  Shutdown always completes.
- **`performHealthCheck` swallows a `GetLeader` error**, publishing `LeaderID: 0`
  rather than failing the sweep.
- **`Coordinator.IsLeader` returns `false` when not running** rather than
  erroring — safe, since false is the conservative answer.

## 7. Invariants and known limitations

### Invariants

1. **Lifecycle state is atomic and lock-free to read.** `running` and `healthy`
   are `atomic.Bool`; the status snapshot is an `atomic.Value` holding
   `*ClusterStatus`. `Status` reads never block a health sweep.
2. **`Status` returns a copy.** `statusCopy := *status` — a caller cannot mutate
   coordinator state.
3. **`updateStatus` is copy-on-write under `statusMu`**: load, copy, mutate the
   copy, store. Concurrent updates serialise; readers never see a partial write.
4. **`Coordinator.Start` recreates `stopChan`/`stoppedChan`**, so start → stop →
   start works.
5. **Shutdown ordering is fixed**: publish `leaving` → close `stopChan` → wait
   for the health monitor (bounded by `shutdownTimeout`) → `membership.Leave`
   (bounded again) → publish `stopped`.
6. **`Bootstrap` and `Join` run an immediate `performHealthCheck`** so the
   status carries a node count before the first ticker fires.
7. **`Coordinator.Nodes` and every health sweep call `InvalidateCache()` first.**
   Authoritative reads never serve a stale cache.
8. **`GetNodes` returns clones.**
9. **The local node is exempt from the leaving sweep.** `refreshNodeCache` marks
   nodes absent from Raft as `NodeStateLeaving` except `config.NodeID`, so a
   node that just joined is not immediately marked gone.
10. **The leader's address wins.** When `GetLeader` returns a non-empty address,
    it overwrites the cached address for that node id.
11. **One leader poller, N waiters.** `leaderCheckLoop` ticks at 100 ms and fans
    out to registered waiter channels with a non-blocking send; the waiter list
    is truncated after each notification. `WaitForLeader` deregisters its
    channel via `defer`.
12. **`Close` is single-shot** (`closed.Swap(true)`), returns nil on a repeat,
    stops the ticker, closes every waiter channel and nils the cache.
13. **No `time.Sleep` anywhere.** Every wait is a `select` over a ticker, a
    channel and a context.
14. **`pkg/cluster` performs no I/O.** No files, no sockets, no `os/exec`. Its
    only non-stdlib import is `pkg/logging`.

### Known limitations, recorded rather than hidden

1. **`tryJoin` is a placeholder.** Its comment lists what a real implementation
   would do — connect to the target, send a join request, wait for the leader to
   `AddVoter` — and then calls `AddVoter` **locally with this node's own id and
   advertise address**. The `address` argument is used only for validation and
   in the error. Joining therefore does not contact the target node from this
   layer.
2. **`Leave` does not transfer leadership.** The comment says *"If we're the
   leader, we need to transfer leadership first. For simplicity, we just remove
   ourselves."*
3. **`Config.Clone` drops `AdvertiseAddress`** — §3.
4. **`ExtendedNodeRegistry.SetLeader` clears all leader flags before verifying
   the target exists** — §5.
5. **`leaderWaitTimeout` is configurable and unused** — §2.
6. **`RaftStateManager` and `ExtendedNodeRegistry` have no production callers.**
7. **`AddNonvoter` and `GetState` are declared on `RaftOperator` and never
   called.**
8. **`NewMembershipManager` returns an unexported type** and starts a goroutine
   before returning.

## 8. The daemon and API layers

### The registered `ClusterGRPCService`

The daemon registers `pkg/api/grpc`'s `ClusterGRPCService` on the TCP server
and the Unix-socket server through `registerClusterGRPCService`
(`pkg/api/daemon/cluster_grpc_backend.go`, called at `daemon.go:954`), and
passes the same service to the QUIC category handler (`daemon.go:1284`), the
REST routes (`daemon.go:1595`) and the MCP provider (`daemon.go:1985`). The
stub that used to be registered in its place was deleted (#317).

Its `grpc.ClusterService` is `clusterGRPCBackend`, the daemon adapter over
`ClusterServicer`:

- The servicer is late-bound: `Daemon.SetClusterService` stores it in an
  `atomic.Pointer`. Unset, every method returns
  `ErrClusterServiceUnavailable` (`Unavailable`) on every transport.
- `ClusterServicer` acts on the serving node only, so `Leave` with another
  node's ID is `ErrLeaveNodeNotLocal`, and the bind/advertise fields of
  `Bootstrap` and `Join` and `Leave`'s `force` are not applied.
- `ListNodes` filters, sorts (`id`, `address`; anything else is
  `ErrUnsupportedNodeSortField`) and pages in the adapter, because the
  servicer returns the whole membership.
- [api.md](api.md) §3 and §5 give the per-RPC behaviour and the state
  projections.

The service carries a much richer request model — `ClusterBootstrapRequest{ClusterName, NodeName,
BindAddress, BindPort, AdvertiseAddress, AdvertisePort, Labels, Metadata}`,
`ClusterListNodesRequest{Roles, States, MatchLabels, Page, PageSize, SortBy,
Ascending}` — plus its own vocabularies (`ClusterStateType`, `NodeRoleType`,
`NodeStateType`, `HealthStatusType`) and its own error set
(`ErrNilClusterService`, `ErrMissingClusterName`, `ErrMissingNodeName`,
`ErrMissingSeedAddresses`, `ErrNodeAlreadyInCluster`, `ErrNodeNotInCluster`,
`ErrCannotLeaveAsLeader`, `ErrNoSeedReachable`, `ErrJoinTimeout`,
`ErrLeaveTimeout`, `ErrClusterOperationFailed`).

Its `mapError`:

| Error | Code |
|---|---|
| `ErrClusterServiceUnavailable` | `Unavailable` |
| `ErrLeaveNodeNotLocal`, `ErrUnsupportedNodeSortField` | `InvalidArgument` |
| `ErrClusterNotInitialized`, `ErrCannotLeaveAsLeader` | `FailedPrecondition` |
| `ErrClusterAlreadyInitialized`, `ErrNodeAlreadyInCluster` | `AlreadyExists` |
| `ErrNodeNotInCluster` | `NotFound` |
| `ErrNoSeedReachable` | `Unavailable` |
| `ErrJoinTimeout`, `ErrLeaveTimeout` | `DeadlineExceeded` |
| `ErrClusterOperationFailed` | `Internal` |
| anything else | `Internal` |

### `daemon.ClusterService` — build-tagged

`pkg/api/daemon/cluster_service.go` carries `//go:build cluster`;
`cluster_service_stub.go` carries `//go:build !cluster`. The tagged version:

- `NewClusterService(*app.App, *slog.Logger)` validates that the DAO factory is
  a `*quicbaas.Factory`, that the client is started, and that the service
  satisfies `clusterComponentsGetter`. Each failure is
  `ErrInvalidConfig{Reason}`.
- `RegisterGRPCServices(*grpc.Server)` is where the coordinator is actually
  fetched — `clusterSvc.GetClusterCoordinator(ctx)` — and stored. **It
  registers no gRPC service despite its name.**
- `Start`/`Stop` drive `Coordinator.Start`/`Stop`; `Name()` is `"cluster"`.
- The rest (`Bootstrap`, `Join`, `Leave`, `Status`, `Nodes`, `IsLeader`,
  `GetLeader`, `WaitForLeader`, `IsHealthy`, `HealthCheck`, `NodeID`, `Config`,
  `Coordinator`) delegates, wrapping failures as `ErrProvisionFailed` or
  `ErrShutdownFailed`.

**The stub's method signatures differ from the tagged version's** — `Status`,
`Nodes`, `GetLeader`, `WaitForLeader`, `Config` and `Coordinator` return
`interface{}` instead of the `cluster.*` types. Code that compiles against one
does not necessarily compile against the other.

### The tag-agnostic servicer types

`pkg/api/daemon/mcp_cluster.go` defines `ClusterServicer` plus
`ClusterStatusInfo` and `ClusterNodeInfo` — plain structs mirroring
`cluster.ClusterStatus` and `cluster.Node` — **so that this file does not import
`pkg/cluster`**, which only compiles under the `cluster` tag.
`mcp_cluster_adapter.go` (tagged) bridges `*ClusterService` to `ClusterServicer`
through the unexported `clusterCore` interface, which exists so the adapter is
unit-testable without a real coordinator.

`Daemon.SetClusterService(svc ClusterServicer)` stores it in the gRPC
backend. **Nothing calls it**, so every transport — the MCP
`platform_cluster_*` tools and the QUIC `0x90` sub-opcodes included, since both
call the registered gRPC service — returns `Unavailable`.

## 9. Persistence

**None in this repository.** `Config.DataDir` is validated non-empty and never
read. Raft log, snapshots and state-machine storage belong to the layer below;
their schema, compatibility and migration rules are go-qrdb's.

## 10. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/cluster/config_test.go` | Every validation rule, `Clone`, the `With*` copiers |
| Unit | `pkg/cluster/coordinator_test.go` | Lifecycle, quorum arithmetic, status publication, health loop |
| Unit | `pkg/cluster/member_test.go` | Cache TTL and invalidation, leader tracking, waiter fan-out, leader-only guards |
| Unit | `pkg/cluster/node_test.go` | `ExtendedNode*` types and the registry |
| Unit | `pkg/cluster/state_test.go` | The transition table and `RaftStateManager` |
| Unit | `pkg/cluster/errors_test.go` | Message formatting and `Unwrap` |
| Unit | `pkg/cluster/multinode_test.go` | Real coordinators and membership managers over one shared in-memory Raft group: formation, discovery, follower and majority loss, rejoin, leader failover |
| Unit | `pkg/sdn/cluster/multinode_test.go` | Per-node state managers over one store: concurrent reads agree, state outlives the writing node |
| Bench | `pkg/cluster/benchmark_test.go` | |
| Unit | `pkg/cli/commands/cluster/*_test.go` | Command wiring, flag validation, formatting helpers |

Make targets:

```sh
make test-pkg PKG=./pkg/cluster/
make test-pkg PKG=./pkg/sdn/cluster/
make stress-sdn-cluster                  # -run TestCluster ./stress/...
```

There is no cluster integration suite: the multi-node tests run in memory in
`make test`, with the leader-check ticks on `testing/synctest` time.

**Fault-injection seams.** `RaftOperator` is the seam: a fake that returns
`ErrClusterUnavailable`, an empty node list, no leader, or a leader that flips
between calls exercises every branch of the coordinator and the membership
manager without a consensus engine. `WithCoordinatorHealthCheckInterval`
compresses the health loop for tests; `clusterCore` fakes the MCP adapter.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. For cluster it is doubly
moot — the CLI is not registered at all ([cli.md](cli.md)).

## 11. Observability

### Log events (`pkg/logging`, from the coordinator and membership manager)

| Level | Event | Fields |
|---|---|---|
| info | `cluster coordinator starting` / `started successfully` / `stopping` / `stopped` | `node_id` |
| info | `bootstrapping new cluster` / `cluster bootstrapped successfully` | `node_id`, `address` |
| info | `joining cluster` / `joining existing cluster` | `node_id`, `addresses` / `join_addresses` |
| info | `joined cluster successfully` | `node_id`, `via_address` |
| info | `leaving cluster` / `left cluster successfully` | `node_id` |
| info | `adding node to cluster` / `node added successfully` | `node_id`, `address` |
| info | `removing node from cluster` / `node removed successfully` | `node_id` |
| warn | `join attempt failed` | `address`, `error` |
| **warn** | `health check failed to get nodes` | `error` |
| warn | `failed to leave cluster gracefully` | `error` |
| warn | `health monitor shutdown timed out` | `timeout` |
| debug | `membership manager created` / `closing membership manager` | `node_id`, `address` |

`daemon.ClusterService` adds `slog` lines at info for each lifecycle step and at
error for each failure, including `"Cluster service initialized"` with
`coordinator_ready` and `node_id`.

**`health check failed to get nodes` is the line to alert on** — it precedes the
status flipping to `degraded`.

### Metrics

None emitted. Quorum, node count and healthy count are read by polling
`Status`.

### Audit

No audit record type for cluster operations. Bootstrap, join, leave, add-node
and remove-node are info-level log lines only.

### Health

**There is no `cluster` component in the platform health registry.**
`Coordinator.HealthCheck` and `IsHealthy` are Go calls; nothing registers a
`health.HealthChecker` for the cluster, so `platformctl health --detailed` will
never show a cluster row. See [`docs/health/`](../health/).

## 12. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/health/`](../health/) — the registry the cluster does **not** report into
- **go-qrdb** — cluster formation, peer discovery, replication, consistency
  levels. **go-quicraft** — the Raft primitives. **go-quicbaas** — the SDK edge
  this repo consumes. Their halves of this feature are documented in their own
  repositories.
