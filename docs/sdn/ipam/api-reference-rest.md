# IPAM REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The IPAM REST routes of the webservice and of platformd.

IPAM endpoints are served by two stacks with the same paths and object
shapes: the webservice (`pkg/webservice/v1/rest/gateway/ipam.go`, always
mounted when the gateway service exists — this is the surface the WebUI
uses) and the daemon's standalone REST server
(`pkg/api/rest/gateway_handlers.go:536`, when `EnableREST` is set — the
default). The
webservice wraps each response body shown below in the standard platform
envelope (`{code, error, success, payload}`); the daemon stack returns it
bare.

On the webservice the whole surface is admin-gated: pool create, update
and delete are operator controls over the address plan, so every endpoint
below requires an authenticated caller holding `admin` and answers 401 or
403 otherwise (`pkg/webservice/v1/router.go:749`).

The webservice also keeps an older, smaller IPAM surface under
`/api/v1/gateway/ipam/` (`pkg/webservice/v1/rest/gateway/router.go:70`): list
pools, list, allocate and release allocations, with release as
`DELETE /api/v1/gateway/ipam/allocations`. It carries the same admin gate.

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
  "id": "lab",
  "name": "lab",
  "cidr": "10.4.9.0/24",
  "gateway": "10.4.9.1",
  "zone": "lab",
  "description": "lab zone pool",
  "default_lease_duration_nanos": 86400000000000,
  "reserved": ["10.4.9.1/32"],
  "range_start": "10.4.9.50",
  "range_end": "10.4.9.254"
}
```

`name` and `cidr` are required; `id` is generated when omitted; `cidr`
is immutable after creation. `reserved` lists never-allocatable prefixes
(the gateway is always reserved); `range_start` and `range_end` bound
dynamic allocation and are set together. Responses carry the same three
fields.

### Update a Pool

`PUT /api/v1/sdn/gateway/ipam/pools/{id}` is a partial update: omitted
fields keep the pool's values. For the window, a present `reserved` list
replaces the reservations (`[]` clears them) and a present `range_start` or
`range_end` replaces that bound (`""` clears it); a range left with one
bound is refused with 400.

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

`hostname` is optional. No REST route takes a requested address: allocation
is always dynamic. `GET .../allocations?pool_id=<id>` filters by pool;
`GET .../pools?zone=<zone>` filters pools by zone.

## Error Codes

Webservice HTTP status codes: 400 (invalid CIDR/parameters, a reserved address, a
reserved prefix or range that does not fit the pool, **and deleting a pool
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

The daemon stack maps errors itself (`writeGatewayError`,
`pkg/api/rest/gateway_handlers.go:1103`) and differs in two places: a pool that
still has allocations is **409**, and an exhausted pool is **503**.

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway REST API Reference](../../gateway/api.md)
