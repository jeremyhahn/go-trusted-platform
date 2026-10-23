# VXLAN Overlay MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The overlay tools of the platform MCP server.

## Overview

| Property | Value |
|----------|-------|
| Transport | MCP (stdio / HTTPS, port 9445) |
| Tool source | `pkg/api/mcp/overlay_tools.go` |
| Result | `CallToolResult`; the tool's JSON output is its text block ([daemon api.md](../../daemon/api.md) §1 "MCP tool results") |

The overlay MCP tools mirror the overlay CLI/gRPC surface. Every tool answers
from the overlay controller the gRPC, REST and QUIC overlay services use
(`pkg/api/daemon/overlay_mcp_bindings.go`).

Each tool requires the scope its gRPC twin requires (`pkg/api/mcp/authz.go`):
`sdn:read` for the status, list, get and `overlay_tunnel_stats` tools,
`sdn:write` for `overlay_vni_create` and `overlay_mac_forget`, and
`sdn:delete` for `overlay_vni_delete`.

The SDK MCP transport (`sdk/go/transport/mcp/overlay.go`) maps every
`OverlayService` method onto these tools, so `Overlay()` works over MCP.

## Tools

### overlay_status

Get the current status of the overlay network including node ID, VTEP
IP, and counts of VTEPs, VNIs, tunnels, and remote MACs.

No arguments.

### overlay_vtep_list

List all known VTEP endpoints in the overlay network.

No arguments.

### overlay_vtep_get

Get detailed information about a specific VTEP by its node ID.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| node_id | string | yes | The node ID of the VTEP to retrieve |

### overlay_vni_list

List all configured VNIs in the overlay network.

No arguments.

### overlay_vni_create

Create a new VNI for overlay network segmentation.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| vni | integer | yes | The VNI number (1-16777215) |
| vlan | integer | no | The VLAN ID to map to this VNI (0-4094) |
| name | string | no | Accepted but not stored: the overlay keeps no VNI name (gRPC drops it too) |

### overlay_vni_delete

Delete a VNI from the overlay network.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| vni | integer | yes | The VNI number to delete |

### overlay_tunnel_list

List all VXLAN tunnels with an optional VNI filter.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| vni | integer | no | Optional VNI to filter tunnels by |

### overlay_tunnel_stats

Get one tunnel's counters (bytes sent and received), the tunnel gRPC
`GetTunnelStats` returns.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| remote_vtep | string | yes | The remote VTEP IP address |
| vni | integer | no | The tunnel's VNI; 0 or omitted selects the first tunnel to the remote VTEP |

### overlay_mac_list

List learned remote MAC addresses with an optional VNI filter.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| vni | integer | no | Optional VNI to filter MAC addresses by |

### overlay_mac_forget

Remove a learned MAC address from the forwarding table.

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| mac | string | yes | The MAC address to forget (e.g., 00:11:22:33:44:55) |
| vni | integer | yes | The VNI the MAC address belongs to |

## Errors

Tool failures return typed overlay errors; the controller's own errors are
mapped onto them, so an MCP caller sees the class a gRPC caller sees:

| Code | Class | Cause |
|------|-------|-------|
| `OVERLAY_SERVICE_UNAVAILABLE` | Unavailable | No overlay controller (overlay disabled) |
| `OVERLAY_CONTROLLER_NOT_RUNNING` | FailedPrecondition | Controller stopped (`overlay_status` still answers, `healthy: false`) |
| `OVERLAY_NODE_ID_REQUIRED`, `OVERLAY_VNI_REQUIRED`, `OVERLAY_MAC_REQUIRED`, `OVERLAY_REMOTE_VTEP_REQUIRED` | InvalidArgument | Required argument missing |
| `OVERLAY_INVALID_REMOTE_VTEP` | InvalidArgument | Remote VTEP is not an IP address |
| `OVERLAY_INVALID_VNI` | InvalidArgument | VNI outside 1-16777215 |
| `OVERLAY_INVALID_VLAN` | InvalidArgument | VLAN outside 0-4094 |
| `OVERLAY_INVALID_MAC` | InvalidArgument | Malformed or rejected MAC address |
| `OVERLAY_VNI_ALREADY_EXISTS` | AlreadyExists | VNI already configured |
| `OVERLAY_VTEP_NOT_FOUND`, `OVERLAY_VNI_NOT_FOUND`, `OVERLAY_MAC_NOT_FOUND`, `OVERLAY_TUNNEL_NOT_FOUND` | NotFound | No such VTEP, VNI, learned MAC or tunnel |

## See Also

- [API Reference](api-reference.md) — Overview and data types
