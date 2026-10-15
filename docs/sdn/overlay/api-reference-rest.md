# VXLAN Overlay REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The overlay REST routes.

## Overview

Two REST stacks serve the overlay, and which one runs depends on how
platformd starts:

| Property | Webservice (platformd with the webservice) | Daemon-only REST (`serve --enable-rest`) |
|----------|--------------------------------------------|------------------------------------------|
| Base Path | `/api/v1/overlay` | `/api/v1/sdn/overlay` |
| Handlers | `pkg/webservice/v1/rest/overlay/router.go`, backed by the gRPC `OverlayService` | `pkg/api/rest/overlay_handlers.go`, backed by `pkg/api/daemon/overlay_rest_adapter.go` |
| Authentication | platform session, admin role | mTLS (the daemon-only mode refuses to start without `--enable-mtls`) |
| Response body | the platform envelope (`{code, error, success, payload}`) around the protobuf message | bare JSON |

The webservice sets the daemon's own REST server off
(`pkg/daemon/commands/serve.go`). Both stacks drive the one overlay
controller every other transport uses.

## Webservice Endpoints

| Method and path | gRPC method | Notes |
|-----------------|-------------|-------|
| `GET /api/v1/overlay/status` | `GetOverlayStatus` | |
| `GET /api/v1/overlay/vteps` | `ListVTEPs` | |
| `GET /api/v1/overlay/vteps/{nodeId}` | `GetVTEP` | |
| `GET /api/v1/overlay/vnis` | `ListVNIs` | |
| `POST /api/v1/overlay/vnis` | `CreateVNI` | body is `CreateVNIRequest`; `201` |
| `DELETE /api/v1/overlay/vnis/{vni}` | `DeleteVNI` | `{vni:[0-9]+}`: a non-numeric VNI is `404` |
| `GET /api/v1/overlay/tunnels?vni=N` | `ListTunnels` | `vni` optional (0 = all) |
| `GET /api/v1/overlay/tunnels/stats?remote_vtep=IP&vni=N` | `GetTunnelStats` | |
| `GET /api/v1/overlay/macs?vni=N` | `ListRemoteMACs` | `vni` optional (0 = all) |
| `DELETE /api/v1/overlay/macs?mac=MAC&vni=N` | `ForgetMAC` | |

```http
POST /api/v1/overlay/vnis
Content-Type: application/json

{"config": {"vni": 1000100, "vlan": 100}}
```

`vni` is required (1-16777215) and `vlan` is optional (0-4094). The
`name` and `labels` fields of `VNIConfig` are accepted and not stored.
gRPC status codes map to HTTP statuses: `InvalidArgument` is `400`,
`NotFound` `404`, `Unavailable` `503`.

## Daemon-only REST Endpoints

### Status

```http
GET /api/v1/sdn/overlay/status
```

Returns the overlay status: node ID, VTEP IP, VTEP/VNI/tunnel/remote-MAC
counts, health flag, VXLAN port, underlay MTU, and a timestamp.

### VTEP Endpoints

```http
GET /api/v1/sdn/overlay/vteps
```

Returns `{"vteps": [...], "count": N, "timestamp": ...}` where each VTEP
carries `node_id`, `ip`, `healthy`, `last_seen`, `vnis`, `mac_count`,
`bytes_sent`, `bytes_recv`.

```http
GET /api/v1/sdn/overlay/vteps/{node_id}
```

Returns one VTEP by node ID. `404` when unknown.

### VNI Endpoints

```http
GET /api/v1/sdn/overlay/vnis
```

Returns `{"vnis": [...], "count": N, "timestamp": ...}`.

```http
POST /api/v1/sdn/overlay/vnis
Content-Type: application/json

{
  "vni": 1000100,
  "vlan": 100
}
```

Creates a VNI. `vni` is required (1-16777215); `vlan` is optional (0-4094,
0 maps no VLAN). `name` and `labels` are accepted and not stored. Returns
`201` with the created VNI, or `400` for a VNI or VLAN out of range.

```http
DELETE /api/v1/sdn/overlay/vnis/{vni}
```

Deletes a VNI. Returns an action response
(`resource_type: "vni"`, `action: "delete"`, `success: true`).

### Tunnel Endpoints

```http
GET /api/v1/sdn/overlay/tunnels
GET /api/v1/sdn/overlay/tunnels?vni=1000100
```

Lists VXLAN tunnels, optionally filtered by VNI. Each tunnel carries
`local_vtep`, `remote_vtep`, `vni`, `state`, `bytes_tx`, `bytes_rx`. This
stack has no tunnel statistics route.

### MAC Endpoints

```http
GET /api/v1/sdn/overlay/macs
GET /api/v1/sdn/overlay/macs?vni=1000100
```

Lists MACs learned from remote VTEPs (`mac`, `vni`, `remote_vtep`,
`learned_at`), optionally filtered by VNI.

```http
DELETE /api/v1/sdn/overlay/macs/{mac}?vni=1000100
```

Removes a learned MAC from the FDB. The MAC in the path may be
URL-encoded; `vni` is passed as a query parameter.

### Error Responses

| Status | Meaning |
|--------|---------|
| 400 | Invalid VNI / VLAN / MAC / node ID, missing required field |
| 404 | VTEP, VNI, or MAC not found |
| 503 | Overlay service not available |

## See Also

- [API Reference](api-reference.md) — Overview and data types
- [gRPC API Reference](api-reference-grpc.md)
- [SDN API](../api.md#6-vxlanevpn-overlay) — every overlay capability on every transport
