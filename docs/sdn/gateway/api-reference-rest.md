# Gateway REST API Reference

Base URL: `https://localhost:8443/api/v1/sdn/gateway`

All endpoints require mTLS / platform JWT authentication. Handlers:
`pkg/api/rest/gateway_handlers.go`, `gateway_lb_handlers.go`,
`gateway_perf_handlers.go`.

## Gateway Status and Mode

```http
GET /api/v1/sdn/gateway/status     # Gateway status (modes, tier, health)
PUT /api/v1/sdn/gateway/mode       # Set active modes
```

Mode request body: `{"modes": ["overlay", "edge", "transit"]}` — the
list replaces the active mode set.

## BGP Endpoints

```http
GET    /api/v1/sdn/gateway/bgp/status               # Speaker status
GET    /api/v1/sdn/gateway/bgp/peers                # List peers
GET    /api/v1/sdn/gateway/bgp/prefixes             # List announced prefixes
POST   /api/v1/sdn/gateway/bgp/prefixes             # Announce a prefix
DELETE /api/v1/sdn/gateway/bgp/prefixes/{prefix}    # Withdraw a prefix
```

Announce body: `{"prefix": "2602:F5BB::/36", "next_hop": "10.0.0.1"}`
(`next_hop` optional). The prefix path parameter is URL-encoded.

## IPAM Endpoints

```http
POST   /api/v1/sdn/gateway/ipam/pools               # Create pool
GET    /api/v1/sdn/gateway/ipam/pools               # List pools
GET    /api/v1/sdn/gateway/ipam/pools/{id}          # Get pool
PUT    /api/v1/sdn/gateway/ipam/pools/{id}          # Update pool
DELETE /api/v1/sdn/gateway/ipam/pools/{id}          # Delete pool

POST   /api/v1/sdn/gateway/ipam/allocations         # Allocate IP
GET    /api/v1/sdn/gateway/ipam/allocations         # List allocations
DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}    # Release IP
```

Allocate body: `{"pool_id": "pool1", "device_id": "vm-123",
"hostname": "webserver"}` (`hostname` optional).

## Load Balancer Endpoints

```http
GET    /api/v1/sdn/gateway/lb/status                              # LB health
POST   /api/v1/sdn/gateway/lb/vips                                # Add VIP
GET    /api/v1/sdn/gateway/lb/vips                                # List VIPs
GET    /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}    # Get VIP
DELETE /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}    # Remove VIP
PUT    /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends  # Replace backends
```

VIPs are identified by `(protocol, address, port)`. Backends are
`{"address": ..., "port": ..., "weight": ...}` objects; the backends
PUT replaces the set atomically.

## Performance Endpoints

```http
POST /api/v1/sdn/gateway/perf/flows        # Timed flow install (MUTATES bridge)
GET  /api/v1/sdn/gateway/perf/datapath     # Live datapath counters
GET  /api/v1/sdn/gateway/perf/conntrack    # Conntrack table summary
```

`perf/flows` requires `sdn:write`; it installs ephemeral flows in perf
table 250 (cookie `0xf1be00ff00000000`), times the install, then
removes them. The datapath and conntrack endpoints are read-only.

## Error Codes

HTTP status codes: 400 (invalid parameters), 401 (unauthorized),
404 (pool/allocation/VIP not found), 409 (already exists),
503 (gateway service not available).

## See Also

- [gRPC API Reference](api-reference-grpc.md)
- [Operations Guide](operations.md)
