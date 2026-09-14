# IPAM REST API Reference

IPAM endpoints are served by two stacks with the same paths and object
shapes: the webservice (`pkg/webservice/v1/rest/gateway/ipam.go`, always
mounted when the gateway service exists — this is the surface the WebUI
uses) and the daemon's standalone REST server
(`pkg/api/rest/gateway_handlers.go`, only when `EnableREST` is set). The
webservice wraps each response body shown below in the standard platform
envelope (`{code, error, success, payload}`); the daemon stack returns it
bare.

On the webservice the whole surface is admin-gated: pool create, update
and delete are operator controls over the address plan, so every endpoint
below requires an authenticated caller holding `admin` and answers 401 or
403 otherwise.

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

HTTP status codes: 400 (invalid CIDR/parameters, **and deleting a pool
that still has allocations**), 404 (pool or allocation not found), 409
(pool already exists, pool name taken, CIDR overlaps, IP already
allocated), 429 (pool exhausted), 503 (gateway service not available).

A pool that still has allocations is reported as **400, not 409**. The
service returns `ErrPoolHasAllocations` as gRPC `FailedPrecondition`
(`pkg/api/daemon/gateway_grpc_service.go`), and the shared REST mapping
groups `FailedPrecondition` with `InvalidArgument` onto 400
(`pkg/webservice/v1/rest/internal/protorest/protorest.go`). The 409 codes
above all come from `AlreadyExists`. Changing this to 409 would mean
changing that shared mapping for every REST surface in the platform, not
just IPAM — see issue #665.

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway REST API Reference](../gateway/api-reference-rest.md)
