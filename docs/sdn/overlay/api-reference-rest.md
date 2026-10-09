# VXLAN Overlay REST API Reference

## Overview

| Property | Value |
|----------|-------|
| Base Path | `/api/v1/sdn/overlay` |
| Port | 8443 (HTTPS) |
| Authentication | mTLS / platform JWT |

Handlers: `pkg/api/rest/overlay_handlers.go`.

## Endpoints

### Status

```http
GET /api/v1/sdn/overlay/status
```

Returns the overlay status: node ID, VTEP IP, VTEP/VNI/tunnel/remote-MAC
counts, IPsec `unpeered_vteps`, health flag, VXLAN port, underlay MTU, and a
timestamp.

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
  "vlan": 100,
  "name": "production-web",
  "labels": {"env": "prod"}
}
```

Creates a VNI. `vni` is required; returns `201` with the created VNI.

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
`local_vtep`, `remote_vtep`, `vni`, `state`, `bytes_tx`, `bytes_rx`.

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

## Error Responses

Errors use the standard platform error envelope. Notable statuses:

| Status | Meaning |
|--------|---------|
| 400 | Invalid VNI / MAC / node ID, missing required field |
| 404 | VTEP, VNI, or MAC not found |
| 503 | Overlay service not available |

## See Also

- [API Reference](api-reference.md) — Overview and data types
- [gRPC API Reference](api-reference-grpc.md)
