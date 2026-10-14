# Cluster — API

> **Status: NORMATIVE** · Scope: cluster capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. Read this before the tables

**Every cluster capability on every transport is currently non-functional.**
The gRPC service the daemon registers is
`daemon.ClusterGRPCService`, whose every method returns `codes.Unimplemented`;
the REST handlers wrap that same stub; the MCP tools return
`ErrClusterNotConfigured` because no provider is ever wired. There is no QUIC
opcode, and the embedded registry's `Cluster` field is never populated.

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
  Registered on the TCP server (`daemon.go:885`) and the Unix-socket server
  (`:888`).
- **REST**: `/api/v1/cluster/*`, registered by
  `RESTServer.SetClusterService` → `clusterRESTHandlers.registerClusterRoutes`
  under `restBasePath` = `/api/v1`.
- **QUIC**: **no opcode.** Grepping `pkg/api/quic/` for `Cluster` returns
  nothing.
- **MCP**: five `platform_cluster_*` tools (`pkg/api/mcp/cluster_tools.go`).
- **Embedded**: `ServiceRegistry.Cluster` exists as a field
  (`sdk/go/transport/embedded/adapter.go`) but the only place a registry is
  constructed — `pkg/api/daemon/embedded_host.go`, shared by the GUI and the
  CLI — populates nine fields and **not** `Cluster`.

## 3. Capabilities

### Lifecycle and status — the five RPCs

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Bootstrap a cluster** | field exists, never populated — `MISSING — docs/13 G7` in practice | `platform.v1.ClusterService/Bootstrap` | `POST /api/v1/cluster/bootstrap` | `platform.v1.ClusterService/Bootstrap` | `MISSING — docs/13 G7` | `platform_cluster_bootstrap` |
| **Join a cluster** | ditto | `ClusterService/Join` | `POST /api/v1/cluster/join` | `ClusterService/Join` | `MISSING — docs/13 G7` | `platform_cluster_join` |
| **Leave a cluster** | ditto | `ClusterService/Leave` | `POST /api/v1/cluster/leave` | `ClusterService/Leave` | `MISSING — docs/13 G7` | `platform_cluster_leave` |
| **Cluster status** | ditto | `ClusterService/GetStatus` | `GET /api/v1/cluster/status` | `ClusterService/GetStatus` | `MISSING — docs/13 G7` | `platform_cluster_status` |
| **List nodes** | ditto | `ClusterService/ListNodes` | `GET /api/v1/cluster/nodes` | `ClusterService/ListNodes` | `MISSING — docs/13 G7` | `platform_cluster_list_nodes` |

**Behaviour today, for every row above:** gRPC and Unix return
`codes.Unimplemented` with `"cluster: <Method> not implemented"`; REST maps that
to **503** (`clusterErrorToHTTP`); MCP returns `ErrClusterNotConfigured`
(`"cluster: service provider not configured"`).

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

**This is the only paginated cluster operation**, and the pagination fields are
carried through to `ClusterListNodesRequest` by the unwired full service
(`pkg/api/grpc/cluster_service.go`). The registered stub reads none of them, and
the REST handler passes an empty `ListClusterNodesRequest`, so no filter or page
selector reaches anything today.

### `ClusterInfo`

`id` (string), `name`, `state` (`ClusterState` enum), `leader_id` (**string**),
`leader_address`, `total_nodes` (uint32), `healthy_nodes` (uint32), `term`
(uint64), `created_at`, `last_election`, `metadata`.

### `ClusterNode`

`id` (**string**), `name`, `address`, `port` (uint32), `role` (`NodeRole`),
`state` (`NodeState`), `health` (`HealthStatus`), `version`, `joined_at`,
`last_heartbeat`, `labels`, `metadata`.

**Note the type mismatch across layers:** `cluster.Node.ID` and
`cluster.Config.NodeID` are `uint64` in the domain, and `ClusterNode.id` is a
`string` on the wire. The bridge that would convert them —
`mcp_cluster_adapter.go` — keeps `uint64`; the unwired
`pkg/api/grpc/ClusterNodeInfo` uses `string`. Any wiring work has to pick one.

### MCP tool inputs

| Tool | Arguments |
|---|---|
| `platform_cluster_bootstrap` | `cluster_name` (string, optional) |
| `platform_cluster_join` | `seed_addresses` (array of `host:port`, **required**) |
| `platform_cluster_leave` | none |
| `platform_cluster_status` | `include_nodes` (bool, optional) |
| `platform_cluster_list_nodes` | none |

MCP outputs are JSON maps built in `pkg/api/daemon/mcp_cluster.go`:
`platform_cluster_status` returns `{cluster: {state, node_count, healthy_count,
leader_id, term, has_quorum, last_updated, started_at, error_message?}, node_id,
is_leader, timestamp}` plus `nodes` and `leader` when `include_nodes` is true.
`platform_cluster_list_nodes` returns `{nodes, total, term, leader?}`.

**The MCP shape is not the gRPC shape.** MCP projects
`cluster.ClusterStatus` (node counts, quorum) while gRPC projects `ClusterInfo`
(cluster id, name, election time). A client cannot assume one from the other.

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
| anything else | 500 |

**Today every cluster REST call returns 503**, because the underlying stub
returns `Unimplemented`. The handlers also return **400** for a request body
that will not decode.

A nil service short-circuits before the call with
`{"error": "cluster service not configured"}` and 503.

### gRPC — when the full service is wired

`pkg/api/grpc/cluster_service.go`'s `mapError`:

| Error | Code |
|---|---|
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
rest have no transport projection at all. Wiring the coordinator requires
writing that mapping — it does not exist to be reused.

### QUIC

Not applicable: no cluster opcode.

## 7. Authorization

| Transport | Requirement |
|---|---|
| gRPC / Unix | `GetStatus`, `ListNodes`: `cluster:read`. `Bootstrap`, `Join`, `Leave`: `cluster:write` (`pkg/api/grpc/method_permissions.go`). A caller without the scope gets `PermissionDenied` |
| MCP | **All five `platform_cluster_*` tools are refused for every caller.** They are not in the permission map (`pkg/api/mcp/authz.go`), so the default-deny `AuthorizeTool` returns `AuthErrorToolNotClassified` until each is classified |
| REST | Whatever the daemon REST listener's middleware chain applies to `/api/v1` |
| QUIC | n/a |
| Embedded | In-process; no token |

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)). On gRPC, membership
changes (`Bootstrap`, `Join`, `Leave`) need `cluster:write`, separate from the
read-only status calls. On MCP the lifecycle tools cannot be called at all until
someone maps them. The platform-wide catalog totals
are in [`docs/daemon/api.md`](../daemon/api.md) §5.

## 8. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`. Nothing here is marked
deprecated — but note that `pkg/api/grpc/cluster_service.go` and
`pkg/api/daemon/cluster_grpc_service.go` implement the **same** `platform.v1`
service with different completeness, and the richer request model
(labels, selectors, pagination) already exists in the proto. Any future wiring
decides which implementation the version means, and that is an owner decision,
not one to settle here.

## 9. Related

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
