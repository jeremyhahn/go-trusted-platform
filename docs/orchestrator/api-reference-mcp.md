# Orchestrator MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-22
> The `orchestrator_*` MCP tools, their arguments, scopes and wire conventions.

| Property | Value |
|----------|-------|
| Endpoint | `https://host:9445` |
| Tools | `orchestrator_*` (`registerOrchestratorTools`, `pkg/api/mcp/orchestrator_tools.go`) |
| Dispatch | `orchestratorToolExecutors` map, one executor per tool |
| Backend | the same `OrchestratorGRPCService` the other transports call (`pkg/api/daemon/mcp_orchestrator.go`) |
| SDK mapping | `grpcMethodToMCPToolMap` (`sdk/go/transport/mcp/adapter.go`) |

## Tools

| Tool | RPC | Scope | Arguments (required in bold) |
|------|-----|-------|------------------------------|
| `orchestrator_health` | `Health` | `orchestrator:read` | none |
| `orchestrator_agent_list` | `ListAgents` | `orchestrator:read` | **`tenant_id`**, `status`, `host`, `backend`, `page` |
| `orchestrator_agent_get` | `GetAgent` | `orchestrator:read` | **`tenant_id`**, **`agent_id`** |
| `orchestrator_agent_disable` | `DisableAgent` | `orchestrator:write` | **`tenant_id`**, **`agent_id`** |
| `orchestrator_agent_enable` | `EnableAgent` | `orchestrator:write` | **`tenant_id`**, **`agent_id`** |
| `orchestrator_session_list` | `ListSessions` | `orchestrator:read` | `status`, `job_id`, `agent_id`, `page` |
| `orchestrator_session_close` | `CloseSession` | `orchestrator:write` | **`session_id`** |
| `orchestrator_job_list` | `ListJobs` | `orchestrator:read` | **`tenant_id`**, `statuses`, `page` |
| `orchestrator_job_get` | `GetJob` | `orchestrator:read` | **`tenant_id`**, **`job_id`** |
| `orchestrator_job_cancel` | `CancelJob` | `orchestrator:write` | **`tenant_id`**, **`job_id`** |

`page` is an object `{"limit": n, "offset": n}`; `statuses` is an array of
strings. A caller without the tool's scope is refused before the tool runs.

## Wire conventions

- Arguments are the RPC request's fields under their proto names; the result
  is the RPC response.
- A gRPC status becomes the JSON-RPC error code of its class
  (`sdk/go/wire/mcpwire`), and the SDK maps it back. A daemon whose MCP
  provider has no orchestrator service answers `UNAVAILABLE`
  (`ErrServiceNotAvailable`, service `orchestrator`).

```json
{"name": "orchestrator_job_list",
 "arguments": {"tenant_id": "t1", "statuses": ["running", "failed"],
               "page": {"limit": 20, "offset": 0}}}
```
