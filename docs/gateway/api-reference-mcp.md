# Gateway MCP API Reference

Gateway MCP tools expose the same service-layer operations as the other
transports.

| Tool | Description |
|---|---|
| `gateway_status` | Gateway node status. |
| `gateway_mode_set` | Deprecated compatibility mode setter. |
| `gateway_snapshot` | Read one gateway snapshot. |
| `gateway_snapshots` | List reported gateway snapshots. |
| `gateway_admitted_vtep` | Read one admitted overlay VTEP by IP address. |
| `gateway_admitted_vteps` | List admitted overlay VTEPs. |

The overlay snapshot object carries admitted VTEPs and ND counters. The direct
admitted-VTEP tools return the same VTEP shape as the snapshot overlay list.
