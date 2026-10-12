# VXLAN Overlay MCP API Reference

## Overview

| Property | Value |
|----------|-------|
| Transport | MCP (stdio / HTTPS, port 9445) |
| Tool source | `pkg/api/mcp/overlay_tools.go` |

The overlay MCP tools mirror the overlay CLI/gRPC surface.

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
| name | string | no | Optional human-readable name |

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

Tool failures return typed overlay errors, e.g. overlay service not
available, overlay controller not running, node ID / VNI / MAC required.

## See Also

- [API Reference](api-reference.md) — Overview and data types
