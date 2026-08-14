# Proxy API Reference

Multi-protocol API documentation for the reverse-proxy configuration
service. platformd is the source of truth for proxy routes and backend
pools; gatewayd instances sync this configuration (via the SDK client)
and run the proxy engine (`pkg/proxy`). platformd never runs the engine
itself.

## Supported Protocols

| Protocol | Transport | Port | Documentation |
|----------|-----------|------|---------------|
| REST | HTTPS | 8443 | [api-reference-rest.md](api-reference-rest.md) |
| gRPC | TCP | 10443 | [api-reference-grpc.md](api-reference-grpc.md) |
| QUIC | UDP | 9444 | [api-reference-quic.md](api-reference-quic.md) |
| MCP | stdio/HTTP | 9445 | [api-reference-mcp.md](api-reference-mcp.md) |
| Unix Socket | Unix | /run/platformd.sock | [api-reference-unix.md](api-reference-unix.md) |

All transports delegate to one shared service (`ProxyGRPCService` over the
daemon `ProxyStore`), so semantics, validation and error mapping are
identical on every protocol. Validation is delegated to
`pkg/proxy Config.Validate` — the single source of truth for
configuration rules.

## Operations

### Routes

| Operation | Description |
|-----------|-------------|
| CreateRoute | Create a route mapping host/path pairs to a backend pool |
| GetRoute | Retrieve a route by ID |
| UpdateRoute | Replace an existing route |
| DeleteRoute | Delete a route |
| ListRoutes | List all routes with the config version |

### Backend Pools

| Operation | Description |
|-----------|-------------|
| CreatePool | Create a backend pool |
| GetPool | Retrieve a pool by ID |
| UpdatePool | Replace an existing pool |
| DeletePool | Delete a pool (denied while routes reference it) |
| ListPools | List all pools with the config version |

### Configuration Lifecycle

| Operation | Description |
|-----------|-------------|
| GetProxyConfig | Full merged route/pool configuration + version counter |
| GetProxyStatus | Store status (version, counts, last update time) |
| ReloadProxyConfig | Bump the version so gatewayd instances re-sync |
| GetZoneMatrix | SDN zone names + compiled allowed (from, to) pairs |

## Versioning

Every successful mutation and every reload monotonically increments the
`version` counter. gatewayd pollers compare a single integer to detect
changes. In JSON transports the uint64 version travels as a string
(protojson convention).

## Data Model

Messages mirror `pkg/proxy` config types 1:1 (proto:
`pkg/api/grpc/proto/proxy.proto`):

- `ProxyRoute` — `id`, `hosts`, `path_prefix`, `pool_id`, `auth`,
  `strip_prefix`, `preserve_host`, `passthrough_tcp` (must be false)
- `ProxyAuthRequirements` — `mode` (`public` | `mtls` | `token` |
  `mtls-or-token`), `require_idevid`, `allowed_zones`, `backend_zone`,
  `require_attestation`, `attestation_max_age_nanos`, `required_roles`,
  `required_scopes`, `opa_policy`, `token_zone` (operator-assigned zone
  for token-authenticated principals on zone-enforcing routes)
- `ProxyPool` — `id`, `backends` (`url`, `weight`), `balancer`, `tls`
  (`trust_class`, `mtls_client_cert`), `max_idle_conns_per_host`,
  `idle_conn_timeout_nanos`

## Authorization Scopes

| Scope | Operations |
|-------|-----------|
| `proxy:read` | GetRoute, ListRoutes, GetPool, ListPools, GetProxyConfig, GetProxyStatus, GetZoneMatrix |
| `proxy:write` | CreateRoute, UpdateRoute, CreatePool, UpdatePool, ReloadProxyConfig |
| `proxy:delete` | DeleteRoute, DeletePool |

## Error Semantics

| Condition | gRPC | HTTP | QUIC |
|-----------|------|------|------|
| Unknown route/pool | `NotFound` | 404 | `StatusNotFound` (0x02) |
| Duplicate route/pool ID | `AlreadyExists` | 409 | `StatusAlreadyExists` (0x06) |
| Pool referenced by routes | `FailedPrecondition` | 409 | `StatusInvalidRequest` (0x01) |
| Validation failure (pkg/proxy) | `InvalidArgument` | 400 | `StatusInvalidArgument` (0x09) |
| Zone service not wired | `Unavailable` | 503 | `StatusUnavailable` (0x0A) |

## CLI

```bash
platformctl proxy route add --id web --path-prefix / --pool web-pool --auth-mode public
platformctl proxy route list
platformctl proxy pool add --id web-pool --backend https://10.0.0.10:8443=2
platformctl proxy status
platformctl proxy reload
platformctl proxy zone-matrix
```

The CLI honors the global `--protocol` / `--endpoint` flags and goes
through the SDK client (`sdk/go/services/proxy`).
