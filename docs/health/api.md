# Component Health — API

> **Status: NORMATIVE** · Scope: health capabilities on every transport · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, or `MISSING — by design`
> where the absence is ruled (§3), never omitted.

---

## 1. The six transports

The transport model, the QUIC frame format and the platform-wide authorization
picture are documented once in [`docs/daemon/api.md`](../daemon/api.md) and are
not repeated here. In short: `sdk/go/protocol.go` declares `ProtocolEmbedded`,
`ProtocolUnix`, `ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`,
and **Unix is gRPC over a Unix domain socket**, so gRPC and Unix share a column.

For health specifically:

- **gRPC**: `platform.v1.PlatformDaemon/GetHealth`, `/Liveness` and
  `/Readiness` (`pkg/api/grpc/proto/daemon.proto`, implemented in
  `pkg/api/daemon/service.go`).
- **REST**: five routes, on two different listeners — see §2.
- **QUIC**: `OpHealth` (`0x00`), `OpLiveness` (`0x01`), `OpReadiness` (`0x02`),
  handled in `pkg/api/daemon/quic_service.go`. These are top-level opcodes, not
  a category.
- **MCP**: `platform_health`, `platform_liveness`, `platform_readiness`
  (`pkg/api/mcp/tools.go`, `registerHealthTools`).
- **Embedded**: reached through `ServiceRegistry.Daemon`
  (`sdk/go/transport/embedded/adapter.go`), which carries
  `platformv1.PlatformDaemonServer`.

## 2. The REST health routes are not the same route

| Route | Registered by | Body shape |
|---|---|---|
| `GET /health` | `healthprobe.Handlers.RegisterRoutes` (`pkg/api/healthprobe/healthprobe.go:97`), mounted on **both** listeners: the daemon's (`pkg/api/daemon/rest_service.go:263`) and the webservice root (`pkg/webservice/v1/router.go:120`) | `GetHealthResponse{status, components: [], timestamp}` |
| `GET /health/live` | same | `LivenessResponse{alive, timestamp}` |
| `GET /health/ready` | same | `ReadinessResponse{ready, status, timestamp}` |
| `GET /api/v1/health` | `RESTServer.handleHealth` (`pkg/api/daemon/rest_service.go:268`), daemon listener only | `HealthResponse{status, timestamp, components[]}` |
| `GET /api/v1/platform/health` | `PlatformRouter.registerHealthRoutes` (`pkg/webservice/v1/rest/platform/router.go`) | `HealthResponse{health: {healthy, status, message, services[], timestamp}}` |

**The three root routes are the probes.** They exist for load balancers,
orchestrators and service discovery, which frequently cannot be pointed at a
versioned path or hold a credential. Each body is the protojson of the matching
`PlatformDaemon` rpc's response, so a probe answers the same message on REST as
on gRPC; it carries the overall status only and never names a component (§4).
The status code carries the verdict: `200` when the probe passes, `503` when it
does not, with the same body either way.

**The other two shapes are different and both are current.** `/api/v1/health`
is the daemon's own REST listener and emits `components`;
`/api/v1/platform/health` is the webservice listener and emits
`health.services` with an extra boolean `healthy`, shaped to match the JS SDK's
`GetHealthResponse` so the WebUI dashboard can read `response.data.health.healthy`
directly.

## 3. Capabilities

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Aggregate system health** | `ServiceRegistry.Daemon` → `GetHealth`; in-process `Registry.Check(ctx)`, `health.Aggregate(ctx, reg)`; `Daemon.HealthCheck(ctx)` | `PlatformDaemon/GetHealth` | `GET /health`, `GET /api/v1/health`, `GET /api/v1/platform/health` | `PlatformDaemon/GetHealth` | `OpHealth` (`0x00`) | `platform_health` |
| **Per-component health** | `Daemon.HealthCheckComponent(ctx, name)`; `Registry.CheckComponent(ctx, name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Liveness probe** | `ServiceRegistry.Daemon` → `Liveness`; in-process `health.Liveness()` | `PlatformDaemon/Liveness` | `GET /health/live` | `PlatformDaemon/Liveness` | `OpLiveness` (`0x01`) | `platform_liveness` |
| **Readiness probe** | `ServiceRegistry.Daemon` → `Readiness`; in-process `health.Readiness(ctx, reg)` | `PlatformDaemon/Readiness` | `GET /health/ready` | `PlatformDaemon/Readiness` | `OpReadiness` (`0x02`) | `platform_readiness` |
| **Register a checker** | `Daemon.RegisterHealthChecker(c)`; `Registry.Register(c)` | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` |
| **Unregister a checker** | `Registry.Unregister(name)` (registry only; **no `Daemon` method**) | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` | `MISSING — by design` |
| **List / count registered checkers** | `Registry.List()`, `Registry.Count()` | `PlatformDaemon/GetHealth` → `components[]` | `GET /api/v1/health` → `components[]`; `GET /api/v1/platform/health` → `health.services[]` | `PlatformDaemon/GetHealth` → `components[]` | `MISSING — by design` | `MISSING — by design` |

Three observations that matter more than the table:

**Only the aggregate check and the two probes have a wire form.** Everything else — naming a single
component, listing what is registered, adding a checker at runtime — is an
in-process Go call with no wire form of its own.

**Checker registration is in-process only, by design.** A checker is Go code running inside `platformd`; a remote caller
has no checker to hand over, so registering and unregistering one have no
transport and never will. **Listing is served by the existing health
endpoint:** the aggregate response carries one `components[]` entry per
registered checker (§5), so its names are the list and its length is the count.
That is gRPC and Unix `PlatformDaemon/GetHealth` and REST `GET /api/v1/health`
(`components[]`), and REST `GET /api/v1/platform/health` (`health.services[]`).
QUIC `OpHealth` and MCP `platform_health` are unauthenticated probes that name
no component (§4), so listing on them is by design absent too. No new list or
count route is added.

**Every transport answers the probes from one source.** `pkg/health/probe.go`
defines `Liveness`, `Readiness` and `Aggregate`; gRPC
(`pkg/api/daemon/service.go:345`, `:352`), REST (`pkg/api/healthprobe`), QUIC
(`pkg/api/daemon/quic_service.go:966`–`976`) and MCP
(`pkg/api/daemon/mcp_service.go:1321`–`1351`) only encode the answer, so the
same registry state gives the same verdict on all six (one exception, an
unwired registry under gRPC `GetHealth`: §6). Point a liveness probe
at `GET /health/live` and a readiness probe at `GET /health/ready`. `GET /health`
is the aggregate and answers `503` while any component is degraded, which is
rarely what a load balancer should act on.

## 4. What each probe consults

Each probe is one function in `pkg/health/probe.go`, and every transport
encodes its result:

| Probe | Consults | Passes when | REST status | Body |
|---|---|---|---|---|
| Liveness (`health.Liveness`) | nothing | always: an answer proves the process is answering | always `200` | `{alive: true, timestamp}` |
| Readiness (`health.Readiness`) | one registry sweep | no component is `unhealthy`. A `degraded` component, or one whose check timed out (`unknown`), leaves the platform ready; a closed registry does not | `200` / `503` | `{ready, status, timestamp}` |
| Aggregate (`health.Aggregate`) | one registry sweep | the overall status is `healthy`: no component `unhealthy` or `degraded`. An `unknown` component does not move the overall status, so healthy plus unknown passes | `200` / `503` | `{status, components: [], timestamp}` |

`status` is the registry's overall status (architecture.md §2), mapped onto
`platform.v1.HealthStatus`; protojson spells it `HEALTH_STATUS_DEGRADED` and so
on. A degraded platform is therefore alive, ready, and not aggregate-healthy.

**A failed probe is an answer, not an error, on every transport.** gRPC returns
`OK` with `ready: false`; QUIC returns `StatusOK` with the verdict in the
payload; MCP returns the tool result; REST returns `503` with the same body it
sends with `200`. The Go SDK's REST transport reads a probe's `503` whose body
decodes as the rpc's response message as that response
(`sdk/go/transport/rest/health.go:40`), so `client.Readiness` gives
`ready: false` over REST exactly as it does over gRPC. Any other `503` — a
proxy's error page, or a non-probe method — stays `codes.Unavailable`.

The SDK's REST `Connect` checks the platform is reachable with
`GET /health/live` (`sdk/go/transport/rest/adapter.go:138`), not `/health`, so
a client can still connect to a platform that is up but degraded.

**The unauthenticated probes name no component.** QUIC `OpHealth`, MCP
`platform_health` and REST `/health` return the aggregate status with an empty
`components` list. The component breakdown is on gRPC `GetHealth`
(`platform:read`), `/api/v1/platform/health` (`admin`) and the daemon
listener's `/api/v1/health` (§7).

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

`platform.v1.ComponentHealth` (`pkg/api/grpc/proto/common.proto`) carries
`name`, `status`, `message`, `last_check` and a `map<string, string> details = 5`
field — **but `Service.GetHealth` never fills `details`, and there is no
`Duration` field, so `ComponentHealth.Details` and `Duration` do not cross the
gRPC boundary**, which is why `platformctl health --detailed` cannot show
them. No other transport carries them either: both REST breakdowns stop at the
message, and the probes carry no component.

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
absent for healthy and for unknown.

QUIC `OpHealth`, `OpLiveness` and `OpReadiness` answer with the same messages
as the rpcs — `GetHealthResponse` (no components), `LivenessResponse` and
`ReadinessResponse` — encoded with the QUIC payload codec
(`quicwire.EncodePayload`).

### Liveness and readiness

REST `GET /health/ready` on a platform with one unhealthy component (`503`):

```json
{ "ready": false, "status": "HEALTH_STATUS_UNHEALTHY", "timestamp": "2026-10-14T01:02:03Z" }
```

REST `GET /health/live` (always `200`):

```json
{ "alive": true, "timestamp": "2026-10-14T01:02:03Z" }
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
| **Registry not wired** (nil) | Every probe on REST, gRPC and QUIC: healthy, ready, alive (`200` on REST), no components. MCP: when no health service is wired at all, `platform_health`, `platform_liveness` and `platform_readiness` return `ErrServiceNotAvailable{Service: "health"}` (`pkg/api/daemon/mcp_service.go:1321`); a wired service with a nil registry answers healthy like the others. REST `/api/v1/health`: `200` with `status: "healthy"` and no components. gRPC `GetHealth`: falls back to per-service state from `Service.services`, worst case `HEALTH_STATUS_DEGRADED` — the one answer that can differ from the probes' |
| Registry closed | `SystemHealth.Status = unhealthy`, empty `Components` |
| A checker times out | that component `unknown`, `message: "health check timed out"`, `details.error` = the context error |
| A checker answers **after** its deadline | the same timeout result — a late answer is never reported as the component's status |
| `Daemon.HealthCheck` with nil registry | `daemon.ErrHealthRegistryNotConfigured` — **embedded Go path only**, never on a wire transport |

**An unwired registry reports healthy.** That is a fail-open path, and it is the
one behaviour in this feature worth flagging: a misconfiguration that leaves
`healthRegistry` nil produces a green health endpoint on a daemon that is not
actually checking anything. It is recorded here rather than changed, because
changing it is an owner decision.

QUIC status bytes for health follow the canonical table in
[`docs/daemon/api.md`](../daemon/api.md) §4. In practice the health handlers
return `StatusOK` (`0x00`) whatever the verdict, or `StatusInternalError`
(`0x04`) if payload encoding fails.

## 7. Authorization

| Transport | Requirement |
|---|---|
| REST `/health`, `/health/live`, `/health/ready` | **None, on both listeners.** The webservice mounts them on the root router (`pkg/webservice/v1/router.go:120`), outside the `/api/v1` authentication chain; the daemon listener serves them beside its other routes. They name no component (§4) |
| REST `/api/v1/health` | None. **Daemon listener only** — the webservice does not serve it. It lists every component with its status and message |
| REST `/api/v1/platform/health` | **Authenticated caller holding `admin`** (#165). The whole `/api/v1/platform/**` subtree is gated; the component breakdown names which subsystem is degraded, which is reconnaissance |
| gRPC `PlatformDaemon/GetHealth` | **Authenticated caller holding `platform:read`** (#768), in the gRPC scope catalog (`pkg/api/grpc/method_permissions.go`). The catalog is default-deny. `grpc.health.v1.Health/List` and `/Watch` need the same permission; only `grpc.health.v1.Health/Check`, the aggregate probe, is served without a token |
| gRPC `PlatformDaemon/Liveness`, `PlatformDaemon/Readiness` | **None.** In `preAuthMethods` (`pkg/api/grpc/method_permissions.go:67`–`68`) and in the TCP listener's `grpcTCPSkipMethods` (`pkg/api/daemon/transport_auth.go:96`–`97`). Each answers a boolean — readiness the overall status too — never a component name, so it discloses no more than `Health/Check` |
| QUIC `OpHealth`/`OpLiveness`/`OpReadiness` | **None.** In `preAuthOpcodes` (`pkg/api/quic/opcode_permissions.go:137`), the only opcodes besides `OpIAMAuthenticate` served without credentials. All three name no component |
| MCP | `platform_health`, `platform_liveness`, `platform_readiness` are mapped to the **empty permission string** in `pkg/api/mcp/authz.go` — explicitly "no auth required", and commented as such |
| Embedded | In-process; no token |

The MCP empty-string mapping is a **deliberate exemption**. The three tools are
in the permission map with an empty requirement, which is a different
statement from being absent from it: the map is default-deny, so an absent tool
is refused. See [`docs/daemon/api.md`](../daemon/api.md) §5 for the
platform-wide catalogs.

Unauthenticated probes are the reason [architecture.md](architecture.md) §5
forbids secrets in `ComponentHealth.Details` and `Message`. That constraint
still binds: `/api/v1/health` on the daemon's own listener remains
unauthenticated and carries each component's message, and the rule protects
it. It is **not** weakened by
`/api/v1/platform/health` now being gated — a gate is an addition to that
constraint, never a licence to relax it, since the same `ComponentHealth`
values feed both listeners.

## 8. Related surfaces that are not this feature

- **`grpc.health.v1`** (`Health/Check`, `Health/List`, `Health/Watch`) is
  served by `HealthGRPCService`, a separate interface with a separate
  vocabulary — [architecture.md](architecture.md) §6. It **does** read this
  registry, through one `platform` checker: an unhealthy overall status answers
  `NOT_SERVING`, degraded stays `SERVING`, and any named service answers
  `NOT_FOUND`. `Check` is unauthenticated; `List` and `Watch` need
  `platform:read` (`pkg/api/grpc/method_permissions.go:651`–`652`).
- **`GET /api/v1/platform/metrics`** projects the same `SystemHealth` into the
  dashboard's service tiles alongside CPU/memory/disk. Documented with the
  daemon: [`docs/daemon/api.md`](../daemon/api.md).
- **Service lifecycle** (`/api/v1/platform/services/...`) is the daemon's, not
  this feature's.

## 9. Versioning

REST under `/api/v1`, plus the unversioned `/health`, `/health/live` and
`/health/ready` probes for load balancers and orchestrators. gRPC package `platform.v1`. QUIC `ProtocolVersion` `0x01`. Nothing
in this surface is deprecated.
