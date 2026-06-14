# SDN MCP API Reference

Endpoint: `localhost:9445` or stdio

The Model Context Protocol (MCP) enables AI/LLM integration with SDN operations.

## Tools

### sdn_create_bridge

Create a new OVS bridge.

```json
{
  "name": "sdn_create_bridge",
  "description": "Create a new Open vSwitch bridge",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string", "description": "Bridge name"}
    },
    "required": ["name"]
  }
}
```

Example:
```json
{"name": "br0"}
```

Response:
```json
{"uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "br0"}
```

### sdn_get_bridge

Get bridge details.

```json
{
  "name": "sdn_get_bridge",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"}
    },
    "required": ["name"]
  }
}
```

### sdn_delete_bridge

Delete an OVS bridge.

```json
{
  "name": "sdn_delete_bridge",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"}
    },
    "required": ["name"]
  }
}
```

### sdn_list_bridges

List all bridges.

```json
{
  "name": "sdn_list_bridges",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

Response:
```json
{
  "bridges": [
    {"uuid": "a1b2c3d4...", "name": "br0"},
    {"uuid": "b2c3d4e5...", "name": "br1"}
  ]
}
```

### sdn_add_port

Add port to a bridge.

```json
{
  "name": "sdn_add_port",
  "inputSchema": {
    "type": "object",
    "properties": {
      "bridge": {"type": "string"},
      "name": {"type": "string"}
    },
    "required": ["bridge", "name"]
  }
}
```

### sdn_delete_port

Remove port from bridge.

```json
{
  "name": "sdn_delete_port",
  "inputSchema": {
    "type": "object",
    "properties": {
      "bridge": {"type": "string"},
      "port": {"type": "string"}
    },
    "required": ["bridge", "port"]
  }
}
```

### sdn_get_port_state

Get port admin state.

```json
{
  "name": "sdn_get_port_state",
  "inputSchema": {
    "type": "object",
    "properties": {
      "port": {"type": "string"}
    },
    "required": ["port"]
  }
}
```

Response:
```json
{"port": "eth0", "state": "up", "of_port": 1}
```

### sdn_set_port_state

Set port admin state.

```json
{
  "name": "sdn_set_port_state",
  "inputSchema": {
    "type": "object",
    "properties": {
      "port": {"type": "string"},
      "state": {"type": "string", "enum": ["up", "down"]}
    },
    "required": ["port", "state"]
  }
}
```

### sdn_get_port_stats

Get port statistics.

```json
{
  "name": "sdn_get_port_stats",
  "inputSchema": {
    "type": "object",
    "properties": {
      "port": {"type": "string"}
    },
    "required": ["port"]
  }
}
```

### sdn_add_flow

Add OpenFlow rule.

```json
{
  "name": "sdn_add_flow",
  "inputSchema": {
    "type": "object",
    "properties": {
      "bridge": {"type": "string"},
      "priority": {"type": "integer"},
      "match": {
        "type": "object",
        "properties": {
          "in_port": {"type": "integer"},
          "eth_src": {"type": "string"},
          "eth_dst": {"type": "string"},
          "eth_type": {"type": "integer"},
          "ipv4_src": {"type": "string"},
          "ipv4_dst": {"type": "string"}
        }
      },
      "actions": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "type": {"type": "string"},
            "port": {"type": "integer"},
            "vlan": {"type": "integer"}
          }
        }
      }
    },
    "required": ["bridge", "priority", "match", "actions"]
  }
}
```

### sdn_delete_flow

Delete OpenFlow rule.

```json
{
  "name": "sdn_delete_flow",
  "inputSchema": {
    "type": "object",
    "properties": {
      "bridge": {"type": "string"},
      "match": {"type": "object"}
    },
    "required": ["bridge", "match"]
  }
}
```

### sdn_list_flows

List flows on bridge.

```json
{
  "name": "sdn_list_flows",
  "inputSchema": {
    "type": "object",
    "properties": {
      "bridge": {"type": "string"}
    },
    "required": ["bridge"]
  }
}
```

### sdn_create_vlan

Create VLAN.

```json
{
  "name": "sdn_create_vlan",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vlan_id": {"type": "integer", "minimum": 1, "maximum": 4094},
      "name": {"type": "string"}
    },
    "required": ["vlan_id"]
  }
}
```

### sdn_delete_vlan

Delete VLAN.

```json
{
  "name": "sdn_delete_vlan",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vlan_id": {"type": "integer"}
    },
    "required": ["vlan_id"]
  }
}
```

### sdn_list_vlans

List VLANs.

```json
{
  "name": "sdn_list_vlans",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

### sdn_apply_policy

Apply security policy to port.

```json
{
  "name": "sdn_apply_policy",
  "inputSchema": {
    "type": "object",
    "properties": {
      "port": {"type": "string"},
      "tenant_id": {"type": "string"},
      "vlan": {"type": "integer"},
      "acls": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "priority": {"type": "integer"},
            "match": {"type": "object"},
            "action": {"type": "object"}
          }
        }
      }
    },
    "required": ["port", "tenant_id"]
  }
}
```

### sdn_get_policy

Get port policy.

```json
{
  "name": "sdn_get_policy",
  "inputSchema": {
    "type": "object",
    "properties": {
      "port": {"type": "string"}
    },
    "required": ["port"]
  }
}
```

### sdn_list_policies

List all policies.

```json
{
  "name": "sdn_list_policies",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

## Resources

### sdn://bridges

List of all bridges.

```json
{
  "uri": "sdn://bridges",
  "name": "SDN Bridges",
  "mimeType": "application/json"
}
```

### sdn://bridges/{name}

Bridge details.

```json
{
  "uri": "sdn://bridges/br0",
  "name": "Bridge br0",
  "mimeType": "application/json"
}
```

### sdn://bridges/{name}/ports

Ports on a bridge.

### sdn://bridges/{name}/flows

Flows on a bridge.

### sdn://vlans

List of VLANs.

### sdn://policies

List of policies.

## Usage with Claude

```
User: Create a bridge called br0 and add port eth0 to it

Claude: I'll create the bridge and add the port.

[Calls sdn_create_bridge with name="br0"]
[Calls sdn_add_port with bridge="br0", name="eth0"]

Done. Created bridge br0 and added port eth0.
```

## Stdio Mode

For local integration:

```bash
platformctl mcp sdn --stdio
```

The MCP server communicates via stdin/stdout using JSON-RPC.

## Network Zone Tools

| Tool | Description |
|------|-------------|
| `gateway_zone_list` | List all SDN network trust zones, optionally filtered by `lifecycle_role` |
| `gateway_zone_create` | Create a new network trust zone (required: `name`) |
| `gateway_zone_update` | Update policy settings of an existing zone (required: `name`) |
| `gateway_zone_delete` | Delete a zone by name (required: `name`) |
| `gateway_zone_assign` | Assign a network segment to a zone (required: `network`, `zone`) |

All create/update tools return `restart_required: true` when a policy-relevant
field change requires the flow matrix to be recompiled.

Note: `pxe_authorize_device` now accepts `target_zone` (zone name string) instead
of the former `target_vlan` (integer). The daemon resolves the zone name to a VLAN
ID via the configured network map.
