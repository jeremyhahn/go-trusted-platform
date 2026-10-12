# NTP MCP API Reference

| Property | Value |
|----------|-------|
| Endpoint | `host:9445` (HTTPS) or stdio |
| Tools | `ntp_status`, `ntp_sources`, `ntp_step` |
| Registration | `pkg/api/mcp/ntp_tools.go` |
| Provider | `pkg/api/daemon/mcp_ntp.go` |
| SDK mapping | `sdk/go/transport/mcp/adapter.go` |

## Tools

| Tool | Input schema | Scope | Description |
|------|--------------|-------|-------------|
| `ntp_status` | `{}` | `ntp:read` | Clock synchronization state: synced flag, stratum, leap status, offset, root dispersion, last sync, mode, reachable source count, anomaly, and any advertised NTS-KE name clients cannot usefully dial — refused by the allow list or unresolvable here (`serve_name_findings`) |
| `ntp_sources` | `{}` | `ntp:read` | Every configured source with selection state, stratum, poll interval, reachability register, last receive time, measured offset |
| `ntp_step` | `{}` | `ntp:write` | Force an immediate correction. Fails when no source is reachable rather than moving the clock on stale data |

None of the tools take arguments.

Scopes come from the MCP tool catalog (`pkg/api/mcp/authz.go`), which
mirrors the gRPC method catalog.

## Results

Tool executors return the generated `platform.v1` response messages
verbatim, so a result is the same JSON object the REST endpoints emit:

```json
{
  "status": {
    "synced": true,
    "stratum": 3,
    "leap_status": "Normal",
    "mode": "both",
    "sources_reachable": 1,
    "sources_total": 2
  }
}
```

The SDK MCP adapter decodes tool results straight into the pb replies,
so the tool JSON and the wire shape stay in lockstep by construction.

## Dispatch

Tool routing is map-based (`ntpToolExecutors`) for O(1) lookup, matching
the platform's dispatch convention. `dispatchNTPTool` returns
`handled=false` for foreign tool names so the registry's chain of
dispatchers is unaffected.

## Errors

When the node has no `ntp:` section, every tool returns
`ErrServiceNotAvailable{Service: "ntp"}`, which the SDK adapter
translates to gRPC `Unavailable`. Control-socket failures and the
no-reachable-source conflict propagate with the same classes documented
in [api-reference-grpc.md](api-reference-grpc.md).

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolMCP),
    platform.WithMCPAddr("https://cp.example.com:9445")))

ntpClient := ntp.NewClientFromGRPC(client.NTP())
status, err := ntpClient.Status(ctx)
```
