# Orchestrator REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-23
> The `/api/v1/orchestrator` routes, their parameters and HTTP statuses.

| Property | Value |
|----------|-------|
| Endpoint | `https://host:8443` |
| Base path | `/api/v1/orchestrator` |
| Handlers | `OrchestratorHandlers` (`pkg/api/rest/orchestrator_handlers.go`) |
| Served by | webservice v1 router (`pkg/webservice/v1/router.go`), daemon REST listener (`pkg/api/daemon/rest_service.go`) |
| SDK routes | `sdk/go/transport/rest/orchestrator.go` |

Every route calls the same `OrchestratorGRPCService` the other transports
call. Responses are the RPC response in the proto3 JSON mapping.

## Serving and authorization

The webservice v1 router (`orchestratorRoutes`, `pkg/webservice/v1/router.go`)
serves the routes from the same `OrchestratorHandlers` the daemon REST listener
mounts. When the daemon has no orchestrator service the webservice does not
mount them.

A request passes three checks, in this order:

1. **Admin role gate.** The routes sit in the webservice's admin-gated
   group: no session is `401`, a session without the admin role is `403`.
2. **Scope.** Each route needs the scope in the table below:
   `orchestrator:read` for reads, `orchestrator:write` for disable, enable,
   close and cancel. A token without it is `403`. Under the legacy JWT
   handler, which carries no scopes, the role gate alone decides.
3. **Tenant.** A route naming `{tenant_id}` serves an admin of that tenant
   and an admin of the system tenant, and answers `403` to any other caller
   (`tenant.AuthorizeTenantAccess`, [tenant API](../tenant/api.md)). The
   caller's tenant is the session's tenant. `/health` and `/sessions` name
   no tenant.

## Routes

| Method | Path | RPC | Scope |
|--------|------|-----|-------|
| `GET` | `/health` | `Health` | `orchestrator:read` |
| `GET` | `/tenants/{tenant_id}/agents` | `ListAgents` | `orchestrator:read` |
| `GET` | `/tenants/{tenant_id}/agents/{agent_id}` | `GetAgent` | `orchestrator:read` |
| `POST` | `/tenants/{tenant_id}/agents/{agent_id}/disable` | `DisableAgent` | `orchestrator:write` |
| `POST` | `/tenants/{tenant_id}/agents/{agent_id}/enable` | `EnableAgent` | `orchestrator:write` |
| `GET` | `/sessions` | `ListSessions` | `orchestrator:read` |
| `DELETE` | `/sessions/{session_id}` | `CloseSession` | `orchestrator:write` |
| `GET` | `/tenants/{tenant_id}/jobs` | `ListJobs` | `orchestrator:read` |
| `GET` | `/tenants/{tenant_id}/jobs/{job_id}` | `GetJob` | `orchestrator:read` |
| `POST` | `/tenants/{tenant_id}/jobs/{job_id}/cancel` | `CancelJob` | `orchestrator:write` |

## Parameters

The request is built from three sources, merged in this order: an optional
JSON body, the query string, then the path variables. Query parameters are
the request's proto field names; a nested field is dotted and a repeated
field repeats. A parameter that is not a field of the request is `400`.

```
GET /api/v1/orchestrator/tenants/t1/agents?status=active&page.limit=20&page.offset=40
GET /api/v1/orchestrator/tenants/t1/jobs?statuses=running&statuses=failed
```

The SDK sends filters and paging in the JSON body and refuses an empty path
field (`tenant_id`, `agent_id`, `session_id`, `job_id`) with
`INVALID_ARGUMENT` before sending.

## Statuses

| Condition | HTTP status |
|-----------|-------------|
| Success | `200` |
| `INVALID_ARGUMENT`, or a bad body or query parameter | `400` |
| `UNAUTHENTICATED`, or no session | `401` |
| `PERMISSION_DENIED`; a session without the admin role or the route's scope; a `{tenant_id}` that is neither the caller's tenant nor a system-tenant caller | `403` |
| `NOT_FOUND` | `404` |
| `FAILED_PRECONDITION` | `409` |
| `UNAVAILABLE`, or the daemon REST listener has no orchestrator service | `503` |
| `INTERNAL` | `500` |
