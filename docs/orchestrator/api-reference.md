# Orchestrator API Reference

> **Status: REFERENCE** · Last verified: 2026-10-22
> The orchestrator transport map, RPCs, scopes, validation and errors.

platformd serves `platform.v1.OrchestratorService`
(`pkg/api/grpc/proto/orchestrator.proto`): the platform's view of the
go-quicbaas agent fleet — its agents, their sessions and the jobs they run.
The fleet itself belongs to go-quicbaas; platformd reaches it only through
the go-quicbaas SDK's `Orchestrator()` client.

One implementation backs every transport: `OrchestratorGRPCService`
(`pkg/api/daemon/orchestrator_grpc_service.go`) calls the service layer
`orchestrator.Service` (`pkg/orchestrator/service.go`), and the service layer
is the only code that calls the SDK client. Validation and error mapping are
therefore the same on every transport.

| Transport | Reference | Entry point |
|-----------|-----------|-------------|
| REST | [api-reference-rest.md](api-reference-rest.md) | `/api/v1/orchestrator/*` |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | `platform.v1.OrchestratorService` (TCP `:10443`) |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | `0x66` sub-opcodes `0x01`-`0x0A` |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | `orchestrator_*` tools |
| Unix | [api-reference-unix.md](api-reference-unix.md) | `platform.v1.OrchestratorService` over `/run/platformd.sock` |

The Go SDK reaches the service with `platform.Client.Orchestrator()` on any
transport, and `platformctl orchestrator` wraps it:

```
platformctl orchestrator health
platformctl orchestrator agent list --tenant t1 [--status s] [--host h] [--backend b] [--limit n] [--offset n]
platformctl orchestrator agent get|disable|enable <agent-id> --tenant t1
platformctl orchestrator session list [--status s] [--job j] [--agent a] [--limit n] [--offset n]
platformctl orchestrator session close <session-id>
platformctl orchestrator job list --tenant t1 [--status s]... [--limit n] [--offset n]
platformctl orchestrator job get|cancel <job-id> --tenant t1
```

## RPCs and scopes

| RPC | Scope | Required fields |
|-----|-------|-----------------|
| `Health` | `orchestrator:read` | none |
| `ListAgents` | `orchestrator:read` | `tenant_id` |
| `GetAgent` | `orchestrator:read` | `tenant_id`, `agent_id` |
| `DisableAgent` | `orchestrator:write` | `tenant_id`, `agent_id` |
| `EnableAgent` | `orchestrator:write` | `tenant_id`, `agent_id` |
| `ListSessions` | `orchestrator:read` | none |
| `CloseSession` | `orchestrator:write` | `session_id` |
| `ListJobs` | `orchestrator:read` | `tenant_id` |
| `GetJob` | `orchestrator:read` | `tenant_id`, `job_id` |
| `CancelJob` | `orchestrator:write` | `tenant_id`, `job_id` |

The list RPCs take an optional `page` (`limit`, `offset`) and answer a `page`
(`total`, and the `limit` and `offset` the server applied). A `limit` of `0`
takes the server's default; a negative `limit` or `offset` is refused.
`ListAgents` filters on `status`, `host` and `backend`; `ListSessions` on
`status`, `job_id` and `agent_id`; `ListJobs` on any of `statuses`.

## Errors

| Cause | gRPC status |
|-------|-------------|
| The node has no go-quicbaas orchestrator client (`orchestrator.ErrNotConfigured`) | `UNAVAILABLE` |
| A required field is empty (`ErrMissingField`) or a page is negative (`ErrInvalidPage`) | `INVALID_ARGUMENT`, naming the field |
| The SDK answers invalid input | `INVALID_ARGUMENT` |
| The SDK answers not found | `NOT_FOUND` |
| The SDK answers conflict or already exists | `FAILED_PRECONDITION` |
| The SDK answers forbidden / unauthorized | `PERMISSION_DENIED` / `UNAUTHENTICATED` |
| The SDK answers unavailable | `UNAVAILABLE` |
| Any other failure | `INTERNAL` |

`orchestrator.Classify` sorts each error into a kind and
`orchestratorErrToGRPC` maps the kind to its code. Each transport carries the
code in its own form: an HTTP status on REST, a status byte on QUIC, a
JSON-RPC error class on MCP.

## Integration suite

`make integration-test-orchestrator` (`test/integration/orchestrator/`) runs
one scenario over the CLI and all five SDK transports: health, every list
with each filter and paging, `NOT_FOUND` for unknown agents, sessions and
jobs on every lookup and mutation, and `INVALID_ARGUMENT` for a missing
tenant, a missing session id and a negative page.
