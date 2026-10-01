# SDN MCP API Reference

Transport: MCP (stdio / HTTP, port 9445).

Tool definitions live in `pkg/api/mcp/tools.go`. OAuth scopes
(`sdn:read`, `sdn:write`, `sdn:delete`) are mapped per tool in
`pkg/api/mcp/authz.go` for the bridge, port-state, port, and policy
tools; tools without a mapping defer to the tool registry.

## Tools

### Bridges

| Tool | Description |
|------|-------------|
| `sdn_list_bridges` | List all OVS bridges |
| `sdn_create_bridge` | Create an OVS bridge |
| `sdn_delete_bridge` | Delete an OVS bridge |

### Ports

| Tool | Description |
|------|-------------|
| `sdn_add_port` | Add a port to an OVS bridge |
| `sdn_delete_port` | Delete a port from an OVS bridge |
| `sdn_get_port_state` | Get the state of an OVS port |
| `sdn_set_port_state` | Set the state of an OVS port |
| `sdn_get_port_stats` | Get statistics for a port |
| `sdn_authenticate_port` | Authenticate a port (802.1X style) |
| `sdn_revoke_port_auth` | Revoke port authentication |

### Flows

| Tool | Description |
|------|-------------|
| `sdn_add_flow` | Add a flow rule to a bridge |
| `sdn_delete_flow` | Delete a flow rule from a bridge |
| `sdn_list_flows` | List all flows on a bridge |
| `sdn_flush_flows` | Delete all flows on a bridge |
| `sdn_get_flow_stats` | Get flow statistics for a bridge |

### VLANs

| Tool | Description |
|------|-------------|
| `sdn_create_vlan` | Create a VLAN on a bridge |
| `sdn_delete_vlan` | Delete a VLAN from a bridge |
| `sdn_list_vlans` | List all VLANs on a bridge |

### Policies

| Tool | Description |
|------|-------------|
| `sdn_apply_policy` | Apply a network policy to a bridge |
| `sdn_get_policy` | Get a network policy |
| `sdn_list_policies` | List all network policies |

### Related Tool Families

- Underlay zones: `gateway_zone_list`, `gateway_zone_create`,
  `gateway_zone_update`, `gateway_zone_delete` (the zone object and its rules
  are in [api.md](api.md) §5; there is no assign tool — networks are zones)
- Overlay: `overlay_*` tools — see
  [overlay/api-reference-mcp.md](overlay/api-reference-mcp.md)
- Load balancer: `gateway_lb_status`, `gateway_lb_vip_add`,
  `gateway_lb_vip_remove`, `gateway_lb_vip_get`, `gateway_lb_vip_list`,
  `gateway_lb_vip_set_backends`
- Performance: `gateway_perf_flows`, `gateway_perf_datapath`,
  `gateway_perf_conntrack`

## Input Schemas

Each tool declares a JSON schema for its arguments in
`pkg/api/mcp/tools.go`; argument names mirror the CLI flags (bridge ID,
port name, flow match fields, policy fields).

## Errors

Failures return typed SDN errors, e.g. `SDN_SERVICE_UNAVAILABLE`,
`SDN_BRIDGE_NOT_FOUND`, `SDN_PORT_NOT_FOUND`, `SDN_FLOW_NOT_FOUND`,
`SDN_POLICY_NOT_FOUND`, and `*_REQUIRED` validation errors.

## See Also

- [API Reference](api-reference.md) — Overview and data types
