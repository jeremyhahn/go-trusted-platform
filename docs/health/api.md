# Component Health — API

> **Status: NORMATIVE** · Scope: health capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

The transport model, the QUIC frame format and the platform-wide authorization
picture are documented once in [`docs/daemon/api.md`](../daemon/api.md) and are
not repeated here. In short: `sdk/go/protocol.go` declares `ProtocolEmbedded`,
`ProtocolUnix`, `ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`,
and **Unix is gRPC over a Unix domain socket**, so gRPC and Unix share a column.

For health specifically:

- **gRPC**: `platform.v1.PlatformDaemon/GetHealth`
  (`pkg/api/grpc/proto/daemon.proto`, implemented in
  `pkg/api/daemon/service.go`).
- **REST**: three routes, on two different listeners — see §2.
- **QUIC**: `OpHealth` (`0x00`), `OpLiveness` (`0x01`), `OpReadiness` (`0x02`),
  handled in `pkg/api/daemon/quic_service.go`. These are top-level opcodes, not
  a category.
- **MCP**: `platform_health`, `platform_liveness`, `platform_readiness`
  (`pkg/api/mcp/tools.go`, `registerHealthTools`).
- **Embedded**: reached through `ServiceRegistry.Daemon`
  (`sdk/go/transport/embedded/adapter.go`), which carries
  `platformv1.PlatformDaemonServer`.

## 2. The three REST health routes are not the same route

| Route | Registered by | Body shape |
|---|---|---|
| `GET /health` | `RESTServer.registerRoutes` (`pkg/api/daemon/rest_service.go`) | `HealthResponse{status, timestamp, components[]}` |
| `GET /api/v1/health` | same handler, `handleHealth` | identical to `/health` |
| `GET /api/v1/platform/health` | `PlatformRouter.registerHealthRoutes` (`pkg/webservice/v1/rest/platform/router.go`) | `HealthResponse{health: {healthy, status, message, services[], timestamp}}` |

**The two shapes are different and both are current.** `/health` and
`/api/v1/health` are the daemon's own REST listener and emit `components`;
`/api/v1/platform/health` is the webservice listener and emits
`health.services` with an extra boolean `healthy`, shaped to match the JS SDK's
`GetHealthResponse` so the WebUI dashboard can read `response.data.health.healthy`
directly.

`GET /health` at the root exists specifically for load balancers and service
discovery, which frequently cannot be pointed at a versioned path.

## 3. Capabilities

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Aggregate system health** | `ServiceRegistry.Daemon` → `GetHealth`; in-process `Registry.Check(ctx)`; `Daemon.HealthCheck(ctx)` | `PlatformDaemon/GetHealth` | `GET /health`, `GET /api/v1/health`, `GET /api/v1/platform/health` | `PlatformDaemon/GetHealth` | `OpHealth` (`0x00`) | `platform_health` |
| **Per-component health** | `Daemon.HealthCheckComponent(ctx, name)`; `Registry.CheckComponent(ctx, name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Liveness probe** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpLiveness` (`0x01`) | `platform_liveness` |
| **Readiness probe** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpReadiness` (`0x02`) | `platform_readiness` |
| **Register a checker** | `Daemon.RegisterHealthChecker(c)`; `Registry.Register(c)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Unregister a checker** | `Registry.Unregister(name)` (registry only; **no `Daemon` method**) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **List / count registered checkers** | `Registry.List()`, `Registry.Count()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

Two observations that matter more than the table:

**Only the aggregate check is on more than two transports.** Everything else —
naming a single component, listing what is registered, adding a checker at
runtime — is an in-process Go call with no wire form at all.

**Liveness and readiness exist only on QUIC and MCP.** The transports a
Kubernetes-style deployment would actually probe with (REST, gRPC) carry neither.
A deployment that wants an HTTP liveness probe today uses `GET /health` and
accepts that it is the aggregate check, not a liveness check.

## 4. Liveness and readiness do not consult the registry

This is the part that surprises people.

`handleLiveness` (`pkg/api/daemon/quic_service.go`) returns a **constant**:
`{healthy: true, status: "alive", timestamp: <now>}`. It reads nothing. That is
the correct semantics for liveness — "the process is answering" — but it means
a QUIC liveness probe is true for any daemon that can serve a frame.

`handleReadiness` returns `{healthy: true, status: "ready", components: {...}}`
where `components` is built by **nil-checking each wired service** and emitting
`"<name>": "ready"` for each non-nil one — `ca`, `vtpm`, `device`, `dns`, `sdn`,
`iam`, `kms`, `tpm2`, `container`, `attestation`, `vm`, `pxe`, `tenant`,
`overlay`, `gateway`, and the rest. It reports *wired*, not *working*, and
`healthy` is a constant `true`.

Only `handleHealthCheck` (`OpHealth`, `0x00`) consults `healthRegistry`, and
its projection is lossy: it flattens the four-state vocabulary to two, emitting
`"healthy"` or `"unhealthy"` per component, so **a degraded component appears
as `unhealthy` on QUIC**. The `Details` map is dropped entirely.

## 5. Request and response schemas

### Aggregate health

Requests carry no parameters anywhere except gRPC:

```protobuf
message GetHealthRequest { bool detailed = 1; }
```

`detailed` is accepted and **ignored by the server** — `Service.GetHealth`
never reads it. The CLI passes it (`platformctl health --detailed`) and uses it
only to decide whether to render the component table locally
([cli.md](cli.md) §3).

gRPC response (`platform.v1.GetHealthResponse`):

| Field | Type | Source |
|---|---|---|
| `status` | `HealthStatus` enum | `SystemHealth.Status` |
| `components[]` | `ComponentHealth` | one per registered checker |
| `timestamp` | `Timestamp` | `SystemHealth.Timestamp` |

`platform.v1.ComponentHealth` carries `name`, `status`, `message`, `last_check`
— **and nothing else. `ComponentHealth.Details` and `Duration` do not cross the
gRPC boundary at all**, which is why `platformctl health --detailed` cannot show
them.

REST `GET /api/v1/health` (`HealthResponse`):

```json
{
  "status": "degraded",
  "timestamp": "2026-08-18T09:14:22.113Z",
  "components": [
    { "name": "ca",  "status": "healthy",  "message": "CA service is healthy", "last_check": "2026-08-18T09:14:22.101Z" },
    { "name": "ntp", "status": "degraded", "message": "time-unsynced",         "last_check": "2026-08-18T09:14:22.108Z" }
  ]
}
```

REST `GET /api/v1/platform/health` (`HealthResponse{Health: PlatformHealth}`):

```json
{
  "health": {
    "healthy": false,
    "status": "degraded",
    "message": "one or more components are degraded",
    "services": [
      { "name": "ca",  "healthy": true,  "status": "healthy",  "message": "CA service is healthy", "lastCheck": "2026-08-18T09:14:22.101Z" },
      { "name": "ntp", "healthy": false, "status": "degraded", "message": "time-unsynced",         "lastCheck": "2026-08-18T09:14:22.108Z" }
    ],
    "timestamp": "2026-08-18T09:14:22.113Z"
  }
}
```

`message` is set by the handler, not by a checker: `"one or more components are
degraded"` for degraded, `"one or more components are unhealthy"` for unhealthy,
absent for healthy.

QUIC `OpHealth` response (`HealthCheckResponse`, MessagePack):

```
{ healthy: bool, status: "healthy"|"unhealthy", components: {"<name>": "healthy"|"unhealthy"}, timestamp: <unix> }
```

### Pagination

None, on any transport. The component set is bounded by `MaxCheckers` (default
100) and is returned whole.

## 6. Status and error mapping

Health has almost no error surface, because **every publishing path nil-checks
the registry and degrades to a static answer rather than failing**:

| Condition | Result |
|---|---|
| Registry wired, sweep completes | `SystemHealth.Status` as computed |
| **Registry not wired** (nil) | REST: `200` with `status: "healthy"` and no components. gRPC: falls back to per-service state from `Service.services`, worst case `HEALTH_STATUS_DEGRADED`. QUIC: `StatusOK` with `healthy: true` and no components |
| Registry closed | `SystemHealth.Status = unhealthy`, empty `Components` |
| A checker times out | that component `unknown`, `message: "health check timed out"`, `details.error` = the context error |
| `Daemon.HealthCheck` with nil registry | `daemon.ErrHealthRegistryNotConfigured` — **embedded Go path only**, never on a wire transport |

**An unwired registry reports healthy.** That is a fail-open path, and it is the
one behaviour in this feature worth flagging: a misconfiguration that leaves
`healthRegistry` nil produces a green health endpoint on a daemon that is not
actually checking anything. It is recorded here rather than changed, because
changing it is an owner decision.

QUIC status bytes for health follow the canonical table in
[`docs/daemon/api.md`](../daemon/api.md) §4. In practice the health handlers
return `StatusOK` (`0x00`), or `StatusInternalError` (`0x04`) if MessagePack
encoding fails.

## 7. Authorization

| Transport | Requirement |
|---|---|
| REST `/health`, `/api/v1/health` | None on the daemon's own listener |
| REST `/api/v1/platform/health` | **Authenticated caller holding `admin`** (#165). The whole `/api/v1/platform/**` subtree is gated; the component breakdown names which subsystem is degraded, which is reconnaissance |
| gRPC `PlatformDaemon/GetHealth` | **`PlatformDaemon` is not in the gRPC scope catalog** (`pkg/api/grpc/method_permissions.go`). The interceptor is default-allow: any validated token passes |
| QUIC `OpHealth`/`OpLiveness`/`OpReadiness` | Governed by `AuthorizeRequest`; no `scp` scope is defined for health |
| MCP | `platform_health`, `platform_liveness`, `platform_readiness` are mapped to the **empty permission string** in `pkg/api/mcp/authz.go` — explicitly "no auth required", and commented as such |
| Embedded | In-process; no token |

The MCP empty-string mapping is a **deliberate exemption**, not the
default-allow gap that affects unlisted tools. The three tools are in the
permission map with an empty requirement, which is a different statement from
being absent from it. See [`docs/daemon/api.md`](../daemon/api.md) §5 for the
platform-wide default-allow question.

Unauthenticated probes are the reason [architecture.md](architecture.md) §5
forbids secrets in `ComponentHealth.Details`. That constraint still binds:
`/health` and `/api/v1/health` on the daemon's own listener remain
unauthenticated, and the rule protects them. It is **not** weakened by
`/api/v1/platform/health` now being gated — a gate is an addition to that
constraint, never a licence to relax it, since the same `ComponentHealth`
values feed both listeners.

## 8. Related surfaces that are not this feature

- **`grpc.health.v1`** (`Health/Check`, `Health/Watch`) is served by
  `HealthGRPCService` and is a separate mechanism with a separate vocabulary —
  [architecture.md](architecture.md) §6. It does **not** read this registry.
- **`GET /api/v1/platform/metrics`** projects the same `SystemHealth` into the
  dashboard's service tiles alongside CPU/memory/disk. Documented with the
  daemon: [`docs/daemon/api.md`](../daemon/api.md).
- **Service lifecycle** (`/api/v1/platform/services/...`) is the daemon's, not
  this feature's.

## 9. Versioning

REST under `/api/v1`, plus the unversioned `/health` alias kept for load
balancers. gRPC package `platform.v1`. QUIC `ProtocolVersion` `0x01`. Nothing
in this surface is deprecated.
