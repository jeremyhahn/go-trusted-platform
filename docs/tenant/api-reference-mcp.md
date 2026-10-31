# Platform Tenancy — MCP Tool Reference

> **Status: NORMATIVE** · Scope: `pkg/api/mcp/tenant_tools.go` · Last verified: 2026-10-27
> Conflicts with this document are defects. Fix them here first.
> Transport matrix, scopes and error mapping: [api.md](api.md) §5–7.

Every tool calls the daemon's shared `TenantGRPCServer`. The result is one JSON
object in the `CallToolResult` text. A failure is a tool error (`isError: true`)
whose text is the error. The SDK MCP transport (`sdk/go/transport/mcp/tenant.go`)
consumes exactly these shapes.

Shared shapes:

- **tenant** — `{id, name, display_name, state, created_at, updated_at,
  compute_quota, network_quota, storage_quota}`, plus `dek_path`, `labels` and
  `annotations` when set. `state` is one of `created`, `active`, `suspended`,
  `deleting`, `deleted`. Times are RFC 3339.
- **compute** — `{max_vms, max_containers, max_vcpus, max_memory_mb}`.
- **network** — `{max_bridges, max_ports, max_bandwidth_mbps}`.
- **storage** — `{max_volumes_gb, max_snapshots}`.
- **status** — `{success, message}`, merged into the result of a mutating tool.

## Lifecycle

| Tool | Arguments | Result |
|---|---|---|
| `tenant_list` | `limit` (0 or less means 100), `offset` | `{tenants: [tenant], count, total}` — `count` is the page size, `total` all tenants |
| `tenant_get` | `tenant_id` | tenant |
| `tenant_get_by_name` | `name` | tenant |
| `tenant_create` | `name` (required), `display_name`, `labels`, `annotations`, flat quota limits (below) | status + `{tenant}` |
| `tenant_update` | `tenant_id` (required), `display_name`, `labels`, `annotations` | status + `{tenant}` |
| `tenant_delete` | `tenant_id` | status + `{tenant_id}` |
| `tenant_suspend` | `tenant_id` | status + `{tenant_id}` |
| `tenant_resume` | `tenant_id` | status + `{tenant_id}` |

`tenant_create` and `tenant_update` wrap the tenant in a `tenant` field; the
read tools return the tenant itself. Suspending a suspended tenant and resuming
an active one succeed ([engineering.md](engineering.md) §2).

## Quotas and usage

| Tool | Arguments | Result |
|---|---|---|
| `tenant_get_quotas` | `tenant_id` | `{tenant_id, compute, network, storage}` |
| `tenant_update_quotas` | `tenant_id` (required), `max_vms`, `max_containers`, `max_vcpus`, `max_memory_mb`, `max_bridges`, `max_ports`, `max_bandwidth_mbps`, `max_volumes_gb`, `max_snapshots` | status + `{tenant_id, compute, network, storage}` (the limits sent) |
| `tenant_get_usage` | `tenant_id` | `{tenant_id, usage: {vms, containers, vcpus, memory_mb, disk_gb, bridges, ports, bandwidth_mbps, volumes, snapshots}, timestamp}` |
| `tenant_check_quota` | `tenant_id`, `resource_type`, `amount` (positive) | `{tenant_id, resource_type, amount, available, message}` |
| `tenant_sync` | — | status |

Quota limits are **flat arguments**, not nested `compute` / `network` /
`storage` objects. On `tenant_update_quotas` a limit left out, or sent as `0`,
keeps the current limit, so MCP cannot lower a limit to `0` ([api.md](api.md) §3).

`tenant_check_quota` answers an exceeded quota with `available: false` and the
reason in `message`. Any other failure, an unknown tenant included, is a tool
error ([engineering.md](engineering.md) §5.3).

## DEK and barrier

| Tool | Arguments | Result |
|---|---|---|
| `tenant_rotate_dek` | `tenant_id`, `background` | `{success, tenant_id, old_version, new_version, timestamp, message}` |
| `tenant_get_dek_status` | `tenant_id` | `{tenant_id, path, version, algorithm, status, is_default, usage_count, bytes_used, max_usage_count, max_bytes_used, warning_percent, usage_percent, needs_rotation, ...}` |
| `platform_tenant_barrier_init` | `tenant_id`, `threshold`, `shares` | status + `{tenant_id}` |
| `platform_tenant_barrier_unseal` | `tenant_id`, `key` | status + `{tenant_id}` |
| `platform_tenant_barrier_seal` | `tenant_id` | status + `{tenant_id}` |
| `platform_tenant_barrier_status` | `tenant_id` | the barrier status, keyed by `tenant_id` |

On platformd, `tenant_rotate_dek` and `tenant_get_dek_status` always return the
tool error *"DEK isolation is not enabled"*: the daemon runs the tenant manager
with DEK isolation off ([configuration.md](configuration.md)).

Every tool needs the scope [api.md](api.md) §5 names for it.
