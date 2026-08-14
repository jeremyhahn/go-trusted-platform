# BGP MCP API Reference

BGP operations are exposed as gateway MCP tools
(`pkg/api/mcp/gateway_tools.go`), served via MCP (stdio / HTTP, port
9445).

## Tools

| Tool | Description |
|------|-------------|
| `gateway_bgp_status` | BGP speaker status (ASN, router ID, peers, prefixes) |
| `gateway_bgp_peers` | List configured BGP peers |
| `gateway_bgp_announce` | Announce a prefix (args: `prefix`, optional `next_hop`) |
| `gateway_bgp_withdraw` | Withdraw an announced prefix (args: `prefix`) |
| `gateway_bgp_prefixes` | List announced prefixes |

Peer configuration is YAML-driven (see [Configuration](configuration.md));
there are no peer-management tools.

## See Also

- [Gateway MCP API Reference](../gateway/api-reference-mcp.md)
- [CLI Usage](cli-usage.md)
