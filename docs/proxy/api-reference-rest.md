# Proxy REST API Reference

REST endpoints for the reverse-proxy configuration service.

| Property | Value |
|----------|-------|
| Base URL | `https://<host>:8443` |
| Content type | `application/json` (protojson) |
| Handler | `pkg/api/rest/proxy_handlers.go` |

Request bodies decode via protojson (snake_case or camelCase field names
accepted); responses are protojson with camelCase names and 64-bit
integers as strings.

## Endpoints

### Routes

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/proxy/routes` | Create route (201) |
| GET | `/api/v1/proxy/routes` | List routes |
| GET | `/api/v1/proxy/routes/{id}` | Get route |
| PUT | `/api/v1/proxy/routes/{id}` | Replace route (ID from URL) |
| DELETE | `/api/v1/proxy/routes/{id}` | Delete route |

### Pools

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/proxy/pools` | Create pool (201) |
| GET | `/api/v1/proxy/pools` | List pools |
| GET | `/api/v1/proxy/pools/{id}` | Get pool |
| PUT | `/api/v1/proxy/pools/{id}` | Replace pool (ID from URL) |
| DELETE | `/api/v1/proxy/pools/{id}` | Delete pool |

### Configuration Lifecycle

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/proxy/config` | Full merged config + version |
| GET | `/api/v1/proxy/status` | Store status |
| POST | `/api/v1/proxy/reload` | Bump the config version |
| GET | `/api/v1/proxy/zone-matrix` | SDN zone matrix |

## Examples

Create a pool:

```bash
curl -sk -X POST https://platform:8443/api/v1/proxy/pools \
  -H 'Content-Type: application/json' \
  -d '{"pool":{"id":"web-pool","backends":[{"url":"https://10.0.0.10:8443","weight":2}]}}'
```

Create a route:

```bash
curl -sk -X POST https://platform:8443/api/v1/proxy/routes \
  -H 'Content-Type: application/json' \
  -d '{"route":{"id":"web","path_prefix":"/","pool_id":"web-pool","auth":{"mode":"public"}}}'
```

Update a route (ID comes from the URL; a body `route.id`, when present,
must match):

```bash
curl -sk -X PUT https://platform:8443/api/v1/proxy/routes/web \
  -H 'Content-Type: application/json' \
  -d '{"route":{"path_prefix":"/app","pool_id":"web-pool","auth":{"mode":"mtls"}}}'
```

Fetch the merged config (gatewayd sync path):

```bash
curl -sk https://platform:8443/api/v1/proxy/config
```

## Error Responses

Errors are returned as `{"error": "<message>"}` with the HTTP status
from the shared error mapping: 400 invalid argument / body, 404 not
found, 409 duplicate or pool-in-use, 503 service or zone source
unavailable, 500 internal.
