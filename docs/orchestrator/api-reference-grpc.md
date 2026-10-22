# Orchestrator gRPC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-22
> `platform.v1.OrchestratorService`: methods, messages and status codes.

| Property | Value |
|----------|-------|
| Endpoint | `host:10443` (TLS) |
| Service | `platform.v1.OrchestratorService` (`pkg/api/grpc/proto/orchestrator.proto`) |
| Implementation | `OrchestratorGRPCService` (`pkg/api/daemon/orchestrator_grpc_service.go`) |
| Service layer | `orchestrator.Service` (`pkg/orchestrator/service.go`) |

## Methods

| Method | Request | Response | Scope |
|--------|---------|----------|-------|
| `Health` | `OrchestratorHealthRequest` | `OrchestratorHealthResponse` | `orchestrator:read` |
| `ListAgents` | `ListOrchestratorAgentsRequest` | `ListOrchestratorAgentsResponse` | `orchestrator:read` |
| `GetAgent` | `GetOrchestratorAgentRequest` | `GetOrchestratorAgentResponse` | `orchestrator:read` |
| `DisableAgent` | `DisableOrchestratorAgentRequest` | `DisableOrchestratorAgentResponse` | `orchestrator:write` |
| `EnableAgent` | `EnableOrchestratorAgentRequest` | `EnableOrchestratorAgentResponse` | `orchestrator:write` |
| `ListSessions` | `ListOrchestratorSessionsRequest` | `ListOrchestratorSessionsResponse` | `orchestrator:read` |
| `CloseSession` | `CloseOrchestratorSessionRequest` | `CloseOrchestratorSessionResponse` | `orchestrator:write` |
| `ListJobs` | `ListOrchestratorJobsRequest` | `ListOrchestratorJobsResponse` | `orchestrator:read` |
| `GetJob` | `GetOrchestratorJobRequest` | `GetOrchestratorJobResponse` | `orchestrator:read` |
| `CancelJob` | `CancelOrchestratorJobRequest` | `CancelOrchestratorJobResponse` | `orchestrator:write` |

## Messages

| Message | Fields |
|---------|--------|
| `OrchestratorHealthResponse` | `healthy`, `status`, `components` (component → status), `timestamp` (Unix seconds) |
| `OrchestratorAgent` | `id`, `tenant_id`, `name`, `host`, `backend`, `model`, `agent_type`, `status`, `last_seen`, `registered_at`, `metadata` |
| `OrchestratorSession` | `session_id`, `backend`, `model`, `status`, `created_at`, `last_active`, `job_id`, `runner`, `agent_id` |
| `OrchestratorJob` | `job_id`, `state`, `description`, `task_count`, `completed`, `failed`, `started_at`, `updated_at`, `error`, `task_id`, `runner` |
| `OrchestratorPage` | `limit`, `offset` |
| `OrchestratorPageInfo` | `total`, `limit`, `offset` (the values applied) |

`DisableAgent` answers `agent_id`, `disabled`, `disabled_at`; `EnableAgent`
`agent_id`, `enabled`; `CloseSession` `session_id`, `closed`; `CancelJob`
`job_id`, `cancelled`.

## Status codes

See [api-reference.md §Errors](api-reference.md#errors). A missing required
field is `INVALID_ARGUMENT` whose message names it
(`orchestrator: tenant_id is required`).

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolGRPC),
    platform.WithGRPCAddr("localhost:10443"),
    platform.WithTLSConfig(tlsConfig)))
jobs, err := client.Orchestrator().ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{
    TenantId: "t1",
    Statuses: []string{"running"},
    Page:     &platformv1.OrchestratorPage{Limit: 20},
})
```
