# Trusted Reverse Proxy — API

> **Status: NORMATIVE** · Scope: proxy routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G<n>`, never omitted.

---

## 1. What this API is

**The proxy's configuration plane, served by `platformd`.** Fourteen
capabilities over routes, backend pools and the zone matrix. It is *not* the
data path — the request path lives in `gatewayd`, has no API of its own, and is
described in [architecture.md](architecture.md) §5.2.

Every transport delegates to **one** shared implementation,
`grpcapi.ProxyGRPCService` over `daemon.proxyStoreService` over
`daemon.ProxyStore` (`pkg/api/daemon/daemon.go:501`). Semantics, validation and
error mapping are identical across transports by construction, not by
convention.

**The store is in-process and not persisted.** Routes and pools do not survive
a `platformd` restart — [architecture.md](architecture.md) §5.1.

## 2. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. Full model:
[`docs/daemon/api.md`](../daemon/api.md) §1.

| Transport | How proxy is reached |
|---|---|
| Embedded | `ServiceRegistry.Proxy` (`platformv1.ProxyServiceServer`), dispatched by gRPC method string through the O(1) map in `sdk/go/transport/embedded/dispatch.go: registerProxyHandlers` — all 14 methods registered |
| Unix | **gRPC over the platformd Unix domain socket.** `RegisterProxyServiceServer` is called on both the TCP and the UDS gRPC server, so every RPC name below works unchanged |
| gRPC | `platform.v1.ProxyService`, 14 RPCs (`pkg/api/grpc/proto/proxy.proto`) |
| REST | base path `/api/v1/proxy` (`pkg/api/rest/proxy_handlers.go: RegisterRoutes`, wired by `RESTServer.SetProxyService`) |
| QUIC | `OpProxyCategory` = **`0x2F`**, an alias of `OpGatewayCategory`; the sub-opcode is `payload[0]` and the MessagePack request is `payload[1:]`. Sub-range **`0x20`–`0x2D`** routes to the proxy handler (`pkg/api/daemon/quic_service.go: IsProxySubOpcode`) |
| MCP | 14 tools, `proxy_*` (`pkg/api/mcp/proxy_tools.go`) |

Because gRPC and Unix are the same service surface, they share a column below.

**QUIC wire format**: requests and responses are the `platform.v1` protobuf
messages encoded directly, **keyed on exact Go field names** (the same
convention as the EAB and config-delivery category handlers) — not the
snake_case proto names.

## 3. Capability matrix — routes

| Capability | Embedded | Unix / gRPC | REST | QUIC (under `0x2F`) | MCP | `scp` |
|---|---|---|---|---|---|---|
| Create route | `ProxyService/CreateRoute` | `CreateRoute` | `POST /api/v1/proxy/routes` | `ProxySubRouteCreate` (`0x20`) | `proxy_route_create` | `proxy:write` |
| Get route | `ProxyService/GetRoute` | `GetRoute` | `GET /api/v1/proxy/routes/{id}` | `ProxySubRouteGet` (`0x21`) | `proxy_route_get` | `proxy:read` |
| Update route | `ProxyService/UpdateRoute` | `UpdateRoute` | `PUT /api/v1/proxy/routes/{id}` | `ProxySubRouteUpdate` (`0x22`) | `proxy_route_update` | `proxy:write` |
| Delete route | `ProxyService/DeleteRoute` | `DeleteRoute` | `DELETE /api/v1/proxy/routes/{id}` | `ProxySubRouteDelete` (`0x23`) | `proxy_route_delete` | `proxy:delete` |
| List routes | `ProxyService/ListRoutes` | `ListRoutes` | `GET /api/v1/proxy/routes` | `ProxySubRouteList` (`0x24`) | `proxy_route_list` | `proxy:read` |

Schemas: `CreateProxyRouteRequest{route}` → `CreateProxyRouteResponse{route, version}`;
`GetProxyRouteRequest{id}` → `GetProxyRouteResponse{route}`;
`UpdateProxyRouteRequest{id, route}` → `UpdateProxyRouteResponse{route, version}`;
`DeleteProxyRouteRequest{id}` → `DeleteProxyRouteResponse{version}`;
`ListProxyRoutesRequest{}` → `ListProxyRoutesResponse{routes, version}`.

`ProxyRoute` = `{id, hosts[], path_prefix, pool_id, auth, strip_prefix,
preserve_host, passthrough_tcp}`.
`ProxyAuthRequirements` = `{mode, require_idevid, allowed_zones[],
backend_zone, require_attestation, attestation_max_age_nanos, required_roles[],
required_scopes[], opa_policy, token_zone}`.

**`attestation_max_age_nanos` is nanoseconds**, not seconds and not a duration
string. Likewise `idle_conn_timeout_nanos` on a pool.

**`passthrough_tcp` must be false.** The field exists so the wire can carry a
`true` and have the server reject it (`ErrTCPPassthroughUnsupported` →
`InvalidArgument` / 400) rather than silently dropping it.

**On `UpdateRoute`, `request.id` and `route.id` must match when both are set**
(`ErrRouteIDMismatch`); when `route.id` is empty, `request.id` identifies the
route. Same rule for pools (`ErrPoolIDMismatch`).

## 4. Capability matrix — backend pools

| Capability | Embedded | Unix / gRPC | REST | QUIC (under `0x2F`) | MCP | `scp` |
|---|---|---|---|---|---|---|
| Create pool | `ProxyService/CreatePool` | `CreatePool` | `POST /api/v1/proxy/pools` | `ProxySubPoolCreate` (`0x25`) | `proxy_pool_create` | `proxy:write` |
| Get pool | `ProxyService/GetPool` | `GetPool` | `GET /api/v1/proxy/pools/{id}` | `ProxySubPoolGet` (`0x26`) | `proxy_pool_get` | `proxy:read` |
| Update pool | `ProxyService/UpdatePool` | `UpdatePool` | `PUT /api/v1/proxy/pools/{id}` | `ProxySubPoolUpdate` (`0x27`) | `proxy_pool_update` | `proxy:write` |
| Delete pool | `ProxyService/DeletePool` | `DeletePool` | `DELETE /api/v1/proxy/pools/{id}` | `ProxySubPoolDelete` (`0x28`) | `proxy_pool_delete` | `proxy:delete` |
| List pools | `ProxyService/ListPools` | `ListPools` | `GET /api/v1/proxy/pools` | `ProxySubPoolList` (`0x29`) | `proxy_pool_list` | `proxy:read` |

`ProxyPool` = `{id, backends[], balancer, tls, max_idle_conns_per_host,
idle_conn_timeout_nanos}`; `ProxyBackend` = `{url, weight}`;
`ProxyBackendTLS` = `{trust_class, mtls_client_cert}`.

**`DeletePool` fails while any route references the pool** —
`ErrProxyPoolInUse{ID, Routes}` → `FailedPrecondition` / **409**, and the
referencing route IDs are in the message.

**`weight` is accepted, stored and never used** by the round-robin balancer
([architecture.md](architecture.md) §3).

## 5. Capability matrix — configuration lifecycle

| Capability | Embedded | Unix / gRPC | REST | QUIC (under `0x2F`) | MCP | `scp` |
|---|---|---|---|---|---|---|
| Get merged config | `ProxyService/GetProxyConfig` | `GetProxyConfig` | `GET /api/v1/proxy/config` | `ProxySubConfigGet` (`0x2A`) | `proxy_config` | `proxy:read` |
| Get store status | `ProxyService/GetProxyStatus` | `GetProxyStatus` | `GET /api/v1/proxy/status` | `ProxySubStatusGet` (`0x2B`) | `proxy_status` | `proxy:read` |
| Reload (bump version) | `ProxyService/ReloadProxyConfig` | `ReloadProxyConfig` | `POST /api/v1/proxy/reload` | `ProxySubReload` (`0x2C`) | `proxy_config_reload` | `proxy:write` |
| Get zone matrix | `ProxyService/GetZoneMatrix` | `GetZoneMatrix` | `GET /api/v1/proxy/zone-matrix` | `ProxySubZoneMatrix` (`0x2D`) | `proxy_zone_matrix` | `proxy:read` |

`GetProxyConfigResponse{routes[], pools[], version}` — this is what
`proxysvc.ConfigSyncer` fetches.
`GetProxyStatusResponse{version, route_count, pool_count, updated_at}` where
`updated_at` is **Unix seconds**.
`ReloadProxyConfigResponse{version}`.
`GetProxyZoneMatrixResponse{zones[], pairs[]}` where `ProxyZonePair` is
`{from, to, services[]}` and an empty `services` list means all services.

`GetZoneMatrix` returns `Unavailable` / **503**
(`ErrProxyZoneMatrixUnavailable`) when platformd has no zone service wired —
not an empty matrix. An empty matrix and an absent zone service mean different
things, and a syncing gatewayd must not mistake the second for the first.

## 6. Nothing is MISSING — and one thing has no API at all

**All fourteen capabilities exist on all six transports.** For a Tier 1
capability row that is the required state (00 L11), and for this feature it
actually holds — unlike the LB and IPAM halves of the adjacent gateway surface
([`docs/gateway/api.md`](../gateway/api.md) §4–5).

What has no API on any transport, and is therefore a real gap rather than a
transport hole:

| Capability | State |
|---|---|
| Read a running gatewayd engine's status (listeners, bound addresses, reload count) | `MISSING — docs/13 G7` — `proxy.Engine.Status()` is in-process only |
| Read a running gatewayd engine's counters (requests, denied, errors, bytes) | `MISSING — docs/13 G7` — `proxy.Engine.Metrics()` is in-process only |
| Read a gatewayd's proxy sync state | `MISSING — docs/13 G7` — `proxysvc.Handler.HealthSnapshot()` and `ConfigSyncer.Status()` are in-process only |
| Push a configuration to a gatewayd | Not a gap: the direction of authority is deliberate. platformd publishes, gatewayd polls ([architecture.md](architecture.md) §5.1) |

The first three mean an operator can read what the fleet *should* be running
and cannot read what any gateway *is* running, over any transport. The gateway
control-plane liaison routes (`/api/v1/gateway/state`,
`/api/v1/gateway/telemetry`) carry gateway state but no proxy engine state
([`docs/gateway/api.md`](../gateway/api.md) §8).

## 7. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form, minted by the broker from the subject's resolved
permissions. Enforcement is per operation: gRPC `RequireScope`, QUIC
`AuthorizeRequest`, MCP `AuthorizeTool`. Platform-wide picture:
[`docs/daemon/api.md`](../daemon/api.md) §5.

**`ProxyService` is fully covered in both catalogs — one of the few surfaces
where that is true.**

- gRPC (`pkg/api/grpc/method_permissions.go`): **all 14 RPCs mapped**, resource
  `proxy`, actions `read` / `write` / `delete`. `GatewayService`, by contrast,
  has 9 of its 24 mapped.
- MCP (`pkg/api/mcp/authz.go`): **all 14 tool names mapped**, same resource and
  actions. There is no duplicated tool family here, so none of the
  authorization asymmetry that affects the dns and vtpm surfaces
  ([`docs/vtpm/api.md`](../vtpm/api.md) §5).

Both catalogs are default-allow for unlisted entries; that does not bite this
feature because nothing is unlisted.

The `scp` column in §3–5 is the required scope per capability.

## 8. Status and error mapping

The gRPC codes are assigned once, in `ProxyGRPCService.mapError`, and each
transport projects them:

| Cause | gRPC code | REST | QUIC status byte |
|---|---|---|---|
| `ErrProxyRouteNotFound`, `ErrProxyPoolNotFound` | `NotFound` | 404 | `StatusNotFound` (`0x02`) |
| `ErrProxyRouteExists`, `ErrProxyPoolExists` | `AlreadyExists` | 409 | `StatusAlreadyExists` (`0x06`) |
| `ErrProxyPoolInUse` | `FailedPrecondition` | 409 | — |
| `ErrProxyZoneMatrixUnavailable` | `Unavailable` | 503 | `StatusUnavailable` (`0x0A`) |
| `*proxy.ConfigError` (any validation sentinel), `proxy.ErrNoListeners` | `InvalidArgument` | 400 | `StatusInvalidArgument` (`0x09`) |
| `ErrMissingRouteID`, `ErrMissingPoolID`, `ErrMissingRoute`, `ErrMissingPool`, `ErrRouteIDMismatch`, `ErrPoolIDMismatch` | `InvalidArgument` | 400 | `StatusInvalidArgument` (`0x09`) |
| `ErrNilProxyService` (backend not wired) | `FailedPrecondition` | 409 | — |
| anything else | `Internal` (wrapped in `ErrProxyOperationFailed{Operation, Cause}`) | 500 | `StatusInternalError` (`0x04`) |
| token invalid | `Unauthenticated` | 401 | `StatusUnauthorized` (`0x03`) |
| missing `proxy:*` scope | `PermissionDenied` | 403 | `StatusPermissionDenied` (`0x07`) |

REST maps via `proxyGRPCCodeToHTTPStatus` and defaults to 500 for an unmapped
code; the body is `{"error": "<message>"}`.

QUIC-only errors, before the request reaches the shared service:
`ErrProxyServiceNotConfigured` (`StatusUnavailable`),
`ErrProxyMissingSubOpcode` and `ErrProxyUnknownSubOpcode` (a proxy-category
frame with an empty payload or a sub-opcode outside `0x20`–`0x2D`),
`ErrProxyDecodingFailed`, `ErrProxyEncodingFailed`.

**`FailedPrecondition` becomes 409 on REST, not 412.** A pool still in use and
a duplicate ID are the same HTTP status from the client's point of view; read
the message body to tell them apart.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB); a very large
`GetProxyConfig` response on a fleet with thousands of routes would hit it
before any other limit.

## 9. Pagination

**There is none, on any transport.** `ListProxyRoutesRequest` and
`ListProxyPoolsRequest` are empty messages; `GetProxyConfigRequest` likewise.
Every list returns the full set with the current version. The result sets are
bounded by how many routes an operator has configured, which is small — but
this is a stated absence, not an oversight to rediscover.

## 10. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. **Nothing in this surface is deprecated.**

Two shapes worth knowing before writing a client:

- **`OpProxyCategory` is an alias, not a distinct opcode.** It equals
  `OpGatewayCategory` (`0x2F`). A QUIC client dispatching on top-level opcodes
  sees gateway and proxy as one category and must read `payload[0]`.
- **Sub-opcode values collide with top-level opcodes by design.** `0x20` under
  `0x2F` is `ProxySubRouteCreate`; `0x20` at top level is something else
  entirely. The rule and the full category table are in
  [`docs/daemon/api.md`](../daemon/api.md) §4 — this document does not repeat
  them.

## 11. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC frames, status bytes, the authorization picture
- [`docs/gateway/api.md`](../gateway/api.md) — the gateway half of §R's row
- [`docs/sdn/api.md`](../sdn/api.md) — zone CRUD, which this surface only reads
