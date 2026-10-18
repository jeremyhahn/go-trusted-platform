# SDN MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15

> The SDN tools of the platform MCP server.

Transport: MCP (stdio / HTTPS, port 9445).

Tool definitions live in `pkg/api/mcp/tools.go`. Each tool's OAuth scope
(`sdn:read`, `sdn:write` or `sdn:delete`) is mapped in `pkg/api/mcp/authz.go`
and is the scope of its gRPC twin (`pkg/api/grpc/method_permissions.go`). A
tool with no mapping is refused before it runs (`AuthErrorToolNotClassified`);
every SDN tool has one.

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
| `sdn_set_port_state` | Set a port's admin state (`up`/`down`) and optional ingress policing (`ingress_rate` bps, `ingress_burst` bits) and egress shaping (`egress_rate` bps, `egress_burst` bits) |
| `sdn_get_port_stats` | Get statistics for a port (`port_name`); scope `sdn:read` |
| `sdn_authenticate_port` | Refused, see below; scope `sdn:write` |
| `sdn_revoke_port_auth` | Refused, see below; scope `sdn:write` |

The port-authentication tools carry gRPC's scope, `sdn:write`, and refuse
every call with `policy.ErrPortAuthNotEnforced`, class `FailedPrecondition`,
as gRPC does: nothing enforces port authentication on the switch, so answering
"authenticated" or "revoked" would be a false security claim. A caller without
`sdn:write` is denied first (`PermissionDenied`). What is missing before the
switch can enforce it is in [api.md](api.md) §4. Until #304 the tools carried no
scope and were refused as unclassified. The SDK's MCP transport does not map
`AuthenticatePort` or `RevokePortAuth`; it answers `Unimplemented`.

### Flows

| Tool | Scope | Description |
|------|-------|-------------|
| `sdn_add_flow` | `sdn:write` | Add a flow rule to a bridge; answers `{"success": true, "flow": <Flow>}` |
| `sdn_delete_flow` | `sdn:delete` | Delete a flow rule (`flow_id`) from a bridge |
| `sdn_list_flows` | `sdn:read` | List all flows on a bridge |
| `sdn_flush_flows` | `sdn:write` | Delete all flows on a bridge; answers `deleted_count` |
| `sdn_get_flow_stats` | `sdn:read` | Get the statistics of one flow (`bridge_name`, `flow_id`) |

`sdn_add_flow` takes the gRPC `FlowConfig` fields as its arguments, under
their proto names: `table`, `priority`, `match`, `actions`, `idle_timeout`,
`hard_timeout` and `metadata`, with the bridge as `bridge_name`. Enums are
given by name (`FLOW_TABLE_0`, `FLOW_ACTION_OUTPUT`) or number. The body is
decoded strictly: an unknown field, a wrong type or an unknown enum name is
refused with `InvalidArgument` before anything reaches the switch, and so is
an argument outside `FlowConfig` other than `bridge_name` and the token (a
misspelt `mtch`, or a `flow` wrapper). Until #304
the tool read a `flow` argument its schema never declared, so every MCP flow
reached the switch with no match and no actions while the tool answered
success, and `sdn_get_flow_stats` took no `flow_id` and always failed.

### VLANs

| Tool | Scope | Description |
|------|-------|-------------|
| `sdn_create_vlan` | `sdn:write` | Create a VLAN on a bridge; answers `{"success": true, "vlan": <VLAN>}` |
| `sdn_delete_vlan` | `sdn:delete` | Delete a VLAN from a bridge |
| `sdn_list_vlans` | `sdn:read` | List all VLANs on a bridge |

The flow, VLAN and port-statistics tools call the same `SDNService` as gRPC,
so they answer what gRPC answers and fail with its error class: `NotFound`
for an unknown bridge, port, flow or VLAN, `InvalidArgument` for a missing
bridge or a VLAN ID outside 1–4095. SDN objects carry no tenant on any
transport: every caller holding the scope sees and changes every bridge's
flows and VLANs.

### Policies

| Tool | Description |
|------|-------------|
| `sdn_apply_policy` | Apply a network policy; the arguments are the REST create-policy body (`name` required, plus `type`, `priority`, `enabled`, `rules`, `targets`, `schedule`) |
| `sdn_get_policy` | Get a network policy by ID or name (`policy_id`) |
| `sdn_list_policies` | List network policies, optionally filtered by `type` and `target_id`; returns `{"policies": [...]}` |
| `sdn_delete_policy` | Delete a network policy by ID or name (`policy_id`); scope `sdn:delete` |

The policy tools call the same SDN service as REST and gRPC, so they return
the REST policy object (`id`, `name`, `type`, `priority`, `status`, `rules`,
`targets`, …) and see every policy created on any other transport. A get or
delete of an unknown policy fails with `SDN_POLICY_NOT_FOUND` naming the
requested policy.

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
