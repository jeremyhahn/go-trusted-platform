# Cluster — API

> **Status: NORMATIVE** · Scope: cluster capabilities on every transport · Last verified: 2026-10-15
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. Read this before the tables

**The five operations are implemented, but nothing in production feeds them a
cluster yet.** The gRPC service the daemon registers is
`pkg/api/grpc.ClusterGRPCService`, backed by the daemon adapter
`clusterGRPCBackend` (`pkg/api/daemon/cluster_grpc_backend.go`) over the
daemon's `ClusterServicer`. REST, the QUIC category opcode and the MCP tools
all call that registered service, so every transport runs the gRPC code path.
They answer from whatever servicer `Daemon.SetClusterService` sets — and
nothing calls it in production (#334), so today gRPC, Unix, QUIC and MCP return
`Unavailable` and REST returns 503. The embedded registry's `Cluster` field is
never populated.

The tables below therefore document **two different things**, kept separate on
purpose:

- **the route** — whether a path, RPC name or tool name exists and is
  registered, and
- **the behaviour** — what a caller actually gets today.

A row that shows a route is not a claim that the capability works.
[architecture.md](architecture.md) §3 has the wiring evidence.

**Ownership.** Consensus, peer discovery and cluster formation are go-qrdb's
(over go-quicraft), reached through `go-quicbaas/sdk/go`. This API is the
platform's control-plane projection over them, not an interface to them.

## 2. The six transports

The transport model, QUIC frame format, canonical status bytes and the
platform-wide authorization picture live in
[`docs/daemon/api.md`](../daemon/api.md). In short: `sdk/go/protocol.go` declares
`ProtocolEmbedded`, `ProtocolUnix`, `ProtocolGRPC`, `ProtocolREST`,
`ProtocolQUIC`, `ProtocolMCP`, and **Unix is gRPC over a Unix domain socket**,
so gRPC and Unix share a column.

For cluster:

- **gRPC**: `platform.v1.ClusterService`, **5 RPCs** — `Bootstrap`, `Join`,
  `Leave`, `GetStatus`, `ListNodes` (`pkg/api/grpc/proto/cluster.proto`).
  `registerClusterGRPCService` registers it on the TCP server and the
  Unix-socket server (`daemon.go:946`).
- **REST**: `/api/v1/cluster/*`, registered by
  `RESTServer.SetClusterService` → `clusterRESTHandlers.registerClusterRoutes`
  under `restBasePath` = `/api/v1`. The daemon passes it the registered gRPC
  service (`daemon.go:1595`), so REST and gRPC run the same code.
- **QUIC**: category opcode `OpClusterCategory` (`0x90`), one sub-opcode per
  RPC (`sdk/go/wire/quicwire/cluster_opcodes.go`). `handleClusterCategory`
  (`pkg/api/daemon/quic_cluster.go`) looks the sub-opcode up in
  `clusterQUICHandlers` and calls the registered gRPC service
  (`daemon.go:1284`). `0x90` was the head of the never-implemented `OpJWT*`
  range; token issuance ships as `OpIAMTokenCreate` (`0xF9`).
- **MCP**: five `platform_cluster_*` tools (`pkg/api/mcp/cluster_tools.go`),
  each calling the registered gRPC service (`daemon.go:1985`).
- **Embedded**: `ServiceRegistry.Cluster` exists as a field
  (`sdk/go/transport/embedded/adapter.go`) but the only place a registry is
  constructed — `pkg/api/daemon/embedded_host.go`, shared by the GUI and the
  CLI — populates nine fields and **not** `Cluster`.

## 3. Capabilities

### Lifecycle and status — the five RPCs

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Bootstrap a cluster** | field exists, never populated — `MISSING — docs/13 G7` in practice | `platform.v1.ClusterService/Bootstrap` | `POST /api/v1/cluster/bootstrap` | `platform.v1.ClusterService/Bootstrap` | `0x90` / `ClusterSubBootstrap` `0x01` | `platform_cluster_bootstrap` |
| **Join a cluster** | ditto | `ClusterService/Join` | `POST /api/v1/cluster/join` | `ClusterService/Join` | `0x90` / `ClusterSubJoin` `0x02` | `platform_cluster_join` |
| **Leave a cluster** | ditto | `ClusterService/Leave` | `POST /api/v1/cluster/leave` | `ClusterService/Leave` | `0x90` / `ClusterSubLeave` `0x03` | `platform_cluster_leave` |
| **Cluster status** | ditto | `ClusterService/GetStatus` | `GET /api/v1/cluster/status` | `ClusterService/GetStatus` | `0x90` / `ClusterSubGetStatus` `0x04` | `platform_cluster_status` |
| **List nodes** | ditto | `ClusterService/ListNodes` | `GET /api/v1/cluster/nodes` | `ClusterService/ListNodes` | `0x90` / `ClusterSubListNodes` `0x05` | `platform_cluster_list_nodes` |

**Behaviour, for every row above:**

- **No servicer set (production today):** gRPC, Unix and MCP return
  `codes.Unavailable` with `"cluster service not configured"`
  (`ErrClusterServiceUnavailable`); QUIC returns `StatusUnavailable`; REST
  maps it to **503** (`clusterErrorToHTTP`).
- **Servicer set:** every transport returns the gRPC response, projected as in
  §5, or the gRPC refusal in its own status form (§6).

What each RPC does with the servicer:

| RPC | Servicer calls | Notes |
|---|---|---|
| `Bootstrap` | `Bootstrap`, then `Status` | `cluster.name` echoes `cluster_name`; `node` is the serving node. Bind/advertise addresses, labels and metadata are not applied — the node's own configuration decides them |
| `Join` | `Join(seed_addresses)`, then `Status` | `node` is the serving node; the same request fields are not applied |
| `Leave` | `Leave` | Removes the **serving** node. A non-empty `node_id` naming another node is refused (`ErrLeaveNodeNotLocal`, `InvalidArgument`). `timeout_seconds > 0` bounds the call; running out is `ErrLeaveTimeout`. `force` is not applied |
| `GetStatus` | `Status`, plus `Nodes` when `include_nodes` | `local_node` is the serving node — its full record when nodes are included; `leader_address` is filled only then |
| `ListNodes` | `Nodes` | Filters by `roles`, `states` and `selector.match_labels` (matched against node metadata), sorts by `id` or `address`, then pages (§5) |

### Everything else is a Go call with no wire form

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Add a node** (leader only) | `MembershipManager.AddNode(ctx, nodeID, address)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Remove a node** (leader only) | `MembershipManager.RemoveNode(ctx, nodeID)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Start / stop the coordinator** | `Coordinator.Start`, `Stop`, `IsRunning` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Is this node the leader?** | `Coordinator.IsLeader()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | in `platform_cluster_status` output only (`is_leader`) |
| **Get the leader** | `Coordinator.GetLeader(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | via `GetStatus`'s `leader_id` |
| **Wait for a leader** | `Coordinator.WaitForLeader(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Explicit health check / quorum verdict** | `Coordinator.HealthCheck(ctx)`, `IsHealthy()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Local node info / Raft term** | `MembershipManager.LocalNode()`, `GetTerm()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | term appears in `platform_cluster_list_nodes` output |
| **Invalidate the node cache** | `MembershipManager.InvalidateCache()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

`HasQuorum` and `HealthyCount` do reach the wire — inside the `GetStatus`
response — but there is no operation that returns the quorum **verdict**
(`ErrQuorumLost{Required, Available}`) as its own answer.

## 4. What does not exist, despite the legacy documentation

The deleted legacy `api-reference.md` documented an eight-RPC
service. The proto declares five. **These do not exist anywhere in the code:**

| Legacy claim | Reality |
|---|---|
| `rpc GetNode(GetNodeRequest)` | No such RPC |
| `rpc RemoveNode(RemoveNodeRequest)` | No such RPC. `MembershipManager.RemoveNode` is a Go call with no transport |
| `rpc TransferLeadership(...)` | **No leadership transfer exists anywhere in this repository** |
| `rpc Status(StatusRequest)` | The RPC is named `GetStatus` |
| `GET /api/v1/cluster/nodes/{id}` | Not registered |
| `DELETE /api/v1/cluster/nodes/{id}` | Not registered |
| `POST /api/v1/cluster/transfer-leadership` | Not registered |
| `GET /api/v1/cluster/nodes?healthy_only=true` | No query parameters are read; the handler passes an empty request |
| Rate limits (Bootstrap 1/min, Join 10/min, …) | **No rate limiting on cluster routes** |
| Message names `BootstrapRequest`, `JoinRequest`, `LeaveRequest`, `StatusRequest`, `ListNodesRequest` | The real names are `BootstrapClusterRequest`, `JoinClusterRequest`, `LeaveClusterRequest`, `GetClusterStatusRequest`, `ListClusterNodesRequest` |
| `node_id` is a `uint64` in the requests | `LeaveClusterRequest.node_id` is a **string**; `ClusterNode.id` and `ClusterInfo.leader_id` are **strings** |

The registered REST surface is exactly five routes:

```
POST /api/v1/cluster/bootstrap
POST /api/v1/cluster/join
POST /api/v1/cluster/leave
GET  /api/v1/cluster/status
GET  /api/v1/cluster/nodes
```

## 5. Request and response schemas

From `pkg/api/grpc/proto/cluster.proto` and the projections in
`pkg/api/grpc/cluster_service.go`.

### `BootstrapClusterRequest`

| Field | Type | Validated |
|---|---|---|
| `cluster_name` | string | **required** — `ErrMissingClusterName` / `InvalidArgument` |
| `node_name` | string | **required** — `ErrMissingNodeName` / `InvalidArgument` |
| `bind_address` | string | |
| `bind_port` | uint32 | |
| `advertise_address` | string | |
| `advertise_port` | uint32 | |
| `labels` | map<string,string> | |
| `metadata` | map<string,string> | |

Response: `{status, cluster: ClusterInfo, node: ClusterNode}`.

### `JoinClusterRequest`

Same fields minus `cluster_name`, plus `seed_addresses` (repeated string,
**required and non-empty** — `ErrMissingSeedAddresses` / `InvalidArgument`).
Response: `{status, cluster, node}`.

### `LeaveClusterRequest`

| Field | Type | Notes |
|---|---|---|
| `node_id` | **string** | May be empty, meaning the local node |
| `force` | bool | |
| `timeout_seconds` | uint32 | |

Response: `{status: {success, message}}`.

### `GetClusterStatusRequest`

`{include_nodes: bool}`. Response:
`{cluster: ClusterInfo, local_node: ClusterNode, nodes: []ClusterNode, timestamp}`.

### `ListClusterNodesRequest`

`{roles: []NodeRole, states: []NodeState, selector: {match_labels}, pagination: {page, page_size, sort_by, ascending}}`.
Response: `{nodes: []ClusterNode, total, pagination: {page, page_size, total_pages, total_items}}`.

**This is the only paginated cluster operation.** Over gRPC and Unix every
field is applied:

- `roles`, `states` and `selector.match_labels` must all match; an empty list
  or map matches every node.
- `sort_by` is `id` or `address`; empty keeps the servicer's order. Anything
  else is `ErrUnsupportedNodeSortField` (`InvalidArgument`). `ascending`
  false sorts descending.
- `page` is 1-based (0 means 1). `page_size` 0 returns every node on one page.
  A page past the end is empty, not an error.
- `total` and `total_items` count the nodes after filtering.

The REST handler passes an empty `ListClusterNodesRequest`, so over REST no
filter, sort or page selector applies.

### `ClusterInfo`

`id` (string), `name`, `state` (`ClusterState` enum), `leader_id` (**string**),
`leader_address`, `total_nodes` (uint32), `healthy_nodes` (uint32), `term`
(uint64), `created_at`, `last_election`, `metadata`.

### `ClusterNode`

`id` (**string**), `name`, `address`, `port` (uint32), `role` (`NodeRole`),
`state` (`NodeState`), `health` (`HealthStatus`), `version`, `joined_at`,
`last_heartbeat`, `labels`, `metadata`.

**Projection from the servicer.** Node IDs are `uint64` in the domain and
`ClusterServicer`; the adapter writes them as decimal strings (`7` → `"7"`).
A node's `address` is the host and `port` the port of its `host:port` address
(an address that does not split is kept whole, with port 0). `role` is
`LEADER` or `FOLLOWER`. `ClusterInfo.leader_address` is the leader's full
`host:port`. `created_at` is the coordinator's start time; `id` and
`last_election` are not populated. A status error message is carried as
`metadata["error_message"]`.

| Coordinator state | `ClusterState` |
|---|---|
| `bootstrapping`, `joining` | `INITIALIZING` |
| `running` | `HEALTHY` |
| `degraded` | `DEGRADED` |
| `uninitialized`, `leaving`, `stopped` | `UNAVAILABLE` |
| anything else | `UNSPECIFIED` |

| Node state | `NodeState` | `HealthStatus` |
|---|---|---|
| `healthy` | `ACTIVE` | `HEALTHY` |
| `suspect` | `UNREACHABLE` | `DEGRADED` |
| `unhealthy` | `FAILED` | `UNHEALTHY` |
| `leaving` | `LEAVING` | `UNSPECIFIED` |
| anything else | `UNSPECIFIED` | `UNSPECIFIED` |

### QUIC payloads

A request under `OpClusterCategory` is the sub-opcode byte followed by the
RPC's request message, MessagePack-encoded; the response payload is the RPC's
response message, encoded the same way.

### MCP tools

An MCP tool's arguments are the RPC's request message and its result is the
RPC's response message, both in protobuf JSON under the proto field names:
enums by name (`NODE_ROLE_LEADER`), 64-bit integers as strings. An argument the
request message does not declare is refused as `InvalidArgument` before the
servicer runs. The tool's input schema lists every request field and marks
`cluster_name` and `node_name` required on `platform_cluster_bootstrap`, and
`node_name` and `seed_addresses` on `platform_cluster_join` — the fields gRPC
validates (§6).

## 6. Status and error mapping

### REST — `clusterErrorToHTTP` (`pkg/api/daemon/cluster_rest.go`)

| Condition | HTTP |
|---|---|
| `ErrClusterNotConfigured` (nil service) | **503** |
| gRPC `Unimplemented`, `Unavailable` | **503** |
| `InvalidArgument` | 400 |
| `Unauthenticated` | 401 |
| `PermissionDenied` | 403 |
| `NotFound` | 404 |
| `AlreadyExists` | 409 |
| `FailedPrecondition` (`ErrClusterNotInitialized`, `ErrCannotLeaveAsLeader`) | 409 (#665) |
| anything else | 500 |

**Today every cluster REST call returns 503**, because no servicer is set and
the registered service returns `Unavailable`. With a servicer set, REST returns
200 with the gRPC response as JSON, or the status above for its error. The
handlers also return **400** for a request body that will not decode.

A nil service short-circuits before the call with
`{"error": "cluster service not configured"}` and 503.

### gRPC and Unix

Request validation in `pkg/api/grpc/cluster_service.go` returns
`InvalidArgument` for `ErrMissingClusterName`, `ErrMissingNodeName` and
`ErrMissingSeedAddresses` before the servicer is reached. Every other error
goes through `mapError`:

| Error | Code |
|---|---|
| `ErrClusterServiceUnavailable` (no servicer set) | `Unavailable` |
| `ErrLeaveNodeNotLocal`, `ErrUnsupportedNodeSortField` | `InvalidArgument` |
| `ErrNilClusterService` | `FailedPrecondition` |
| `ErrClusterNotInitialized`, `ErrCannotLeaveAsLeader` | `FailedPrecondition` |
| `ErrClusterAlreadyInitialized`, `ErrNodeAlreadyInCluster` | `AlreadyExists` |
| `ErrNodeNotInCluster` | `NotFound` |
| `ErrNoSeedReachable` | `Unavailable` |
| `ErrJoinTimeout`, `ErrLeaveTimeout` | `DeadlineExceeded` |
| `ErrClusterOperationFailed` | `Internal` |
| anything else | `Internal` |

**The domain error set in `pkg/cluster/errors.go` is not mapped by anything.**
`ErrQuorumLost`, `ErrNodeNotLeader`, `ErrNoLeader`, `ErrAlreadyJoined`,
`ErrNotJoined`, `ErrBootstrapFailed`, `ErrJoinFailed`, `ErrLeaveFailed` and the
rest have no transport projection of their own: a servicer error reaches
gRPC as `Internal` and REST as 500. Giving them codes means writing that
mapping — it does not exist to be reused.

### MCP

A tool returns the gRPC status its RPC gives, from the table above (#304). The
one MCP-only refusal is `Unavailable` (`ErrClusterNotConfigured`,
`pkg/api/mcp/cluster_tools.go`) from a tool registry whose provider serves no
ClusterService; the daemon always hands it the registered service.

### QUIC

A refusal comes back as the QUIC status its gRPC code maps to
(`grpcDelegateCodeToQUICStatus`, `pkg/api/daemon/quic_grpc_delegates.go`):
`InvalidArgument` → `StatusInvalidArgument`, `NotFound` → `StatusNotFound`,
`AlreadyExists` → `StatusAlreadyExists`, `PermissionDenied` →
`StatusPermissionDenied`, `Unavailable` → `StatusUnavailable`,
`DeadlineExceeded` → `StatusTimeout`, `Internal` → `StatusInternalError`.

**`FailedPrecondition` has no QUIC byte of its own:** it is sent as
`StatusInvalidRequest`, which the SDK reads back as `InvalidArgument`. So
`ErrClusterNotInitialized` and `ErrCannotLeaveAsLeader` reach a QUIC client as
`InvalidArgument`, not `FailedPrecondition`.

The handler refuses three cases itself: a handler with no cluster service is
`StatusUnavailable` (`ErrQUICServiceUnavailable{Service: "cluster"}`), an empty
payload (no sub-opcode) is `StatusInvalidRequest`, and an unknown sub-opcode is
`StatusNotImplemented`.

## 7. Authorization

| Transport | Requirement |
|---|---|
| gRPC / Unix | `GetStatus`, `ListNodes`: `cluster:read`. `Bootstrap`, `Join`, `Leave`: `cluster:write` (`pkg/api/grpc/method_permissions.go`). A caller without the scope gets `PermissionDenied` |
| MCP | The gRPC twin's scope (#304): `platform_cluster_status`, `platform_cluster_list_nodes`: `cluster:read`. `platform_cluster_bootstrap`, `platform_cluster_join`, `platform_cluster_leave`: `cluster:write` (`pkg/api/mcp/authz.go`). A caller without the scope gets `PermissionDenied` (`-32003`) and the tool never runs |
| QUIC | Each `0x90` sub-opcode requires its RPC's scope: `ClusterSubGetStatus`, `ClusterSubListNodes`: `cluster:read`; `ClusterSubBootstrap`, `ClusterSubJoin`, `ClusterSubLeave`: `cluster:write` (`pkg/api/quic/opcode_permissions.go`). A caller without the scope gets `StatusPermissionDenied` and the servicer is never called |
| REST | Whatever the daemon REST listener's middleware chain applies to `/api/v1` |
| Embedded | In-process; no token |

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)). On gRPC, membership
changes (`Bootstrap`, `Join`, `Leave`) need `cluster:write`, separate from the
read-only status calls; QUIC and MCP require the same pairs. Cluster nodes are
platform-level: no transport scopes them to a tenant. The platform-wide catalog totals
are in [`docs/daemon/api.md`](../daemon/api.md) §5.

## 8. SDK mapping

The `sdk/go` cluster client (`Cluster()`) issues gRPC method strings; each
transport adapter maps all five onto its own wire:

| Transport | SDK mapping |
|---|---|
| gRPC, Unix | the generated `ClusterServiceClient` |
| REST | `sdk/go/transport/rest/adapter.go`: method → `/api/v1/cluster/*` route |
| QUIC | `sdk/go/transport/quic/aab_cluster.go` (`clusterSubOpcodes`): method → `0x90` sub-opcode |
| MCP | `sdk/go/transport/mcp/cluster.go` (`clusterToolMap`): method → `platform_cluster_*` tool |
| Embedded | `sdk/go/transport/embedded/dispatch.go`: method → `ServiceRegistry.Cluster` — which the daemon never populates (§2) |

A client on QUIC or MCP gets the reply its gRPC call gives, and the refusal
code — except `FailedPrecondition` on QUIC (§6).
`pkg/api/daemon/cluster_quic_sdk_test.go` and `cluster_mcp_sdk_test.go` drive
every method through the SDK adapter against the daemon handler and compare
it with a direct gRPC call.

## 9. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`. Nothing here is marked
deprecated. `platform.v1.ClusterService` has one implementation,
`pkg/api/grpc/cluster_service.go`; the daemon stub that once answered every
RPC with `Unimplemented` was deleted (#317).

## 10. Related

- [architecture.md](architecture.md) — ownership, the `RaftOperator` seam, wiring state
- [engineering.md](engineering.md) — the two service types, error semantics, limitations
- [cli.md](cli.md) — the unregistered command tree
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC opcodes, the
  platform-wide authorization picture
- Legacy `api-reference.md` — deleted; §4 lists what it
  claimed that does not exist
- **go-qrdb** and **go-quicbaas** document the other half of this feature —
  cluster formation, peer discovery and the SDK edge. This repository does not
  document their APIs.
