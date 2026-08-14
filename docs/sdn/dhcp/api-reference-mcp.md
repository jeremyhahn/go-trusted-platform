# DHCP MCP API Reference

The DHCP service does **not** currently expose MCP tools. It is an
in-process service configured via the `sdn.dhcp` YAML section; no DHCP
tools are registered with the platform MCP server.

Pool and allocation state is available through the IPAM MCP tools — see
[IPAM MCP API Reference](../ipam/api-reference-mcp.md).

For the in-process Go interface see [API Reference](api-reference.md).
