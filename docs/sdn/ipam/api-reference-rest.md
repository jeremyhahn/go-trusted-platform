# IPAM REST API Reference

IPAM endpoints live under the gateway REST surface
(`pkg/api/rest/gateway_handlers.go`), served on HTTPS port 8443 with
mTLS / platform JWT authentication.

## Pool Endpoints

```http
POST   /api/v1/sdn/gateway/ipam/pools          # Create pool
GET    /api/v1/sdn/gateway/ipam/pools          # List pools
GET    /api/v1/sdn/gateway/ipam/pools/{id}     # Get pool
PUT    /api/v1/sdn/gateway/ipam/pools/{id}     # Update pool
DELETE /api/v1/sdn/gateway/ipam/pools/{id}     # Delete pool
```

### Create a Pool

```http
POST /api/v1/sdn/gateway/ipam/pools
Content-Type: application/json

{
  "id": "prod-v4",
  "name": "prod-v4",
  "cidr": "10.0.0.0/24",
  "gateway": "10.0.0.1",
  "zone": "trusted",
  "description": "production IPv4",
  "lease_seconds": 86400
}
```

`name` and `cidr` are required; `id` is generated when omitted; `cidr`
is immutable after creation.

## Allocation Endpoints

```http
POST   /api/v1/sdn/gateway/ipam/allocations        # Allocate IP
GET    /api/v1/sdn/gateway/ipam/allocations        # List allocations
DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}   # Release IP
```

### Allocate an IP

```http
POST /api/v1/sdn/gateway/ipam/allocations
Content-Type: application/json

{
  "pool_id": "prod-v4",
  "device_id": "vm-123",
  "hostname": "webserver"
}
```

`hostname` is optional. List supports a pool filter query parameter.

## Error Codes

HTTP status codes: 400 (invalid CIDR/parameters), 404 (pool or
allocation not found), 409 (pool already exists / has allocations),
503 (gateway service not available).

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway REST API Reference](../gateway/api-reference-rest.md)
