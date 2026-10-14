# Platform Tenancy — API

> **Status: NORMATIVE** · Scope: tenant routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Tenant` carries the service in-process.

gRPC: `TenantService`, 19 RPCs (`pkg/api/grpc/proto/tenant.proto`).
REST: base path `/api/v1/tenants` (`pkg/webservice/v1/rest/tenant/router.go`).
QUIC: tenant management opcodes in the `0xDB`–`0xEB` range, plus a **tenant
barrier category opcode `0x9E`** that multiplexes the per-tenant barrier
sub-operations.
MCP: 19 tools in two naming families — see §5.

---

## 2. Tenant lifecycle

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List tenants | `GET /api/v1/tenants` | `ListTenants` | `0xDB`–`0xEB` range | `tenant_list` | ✅ |
| Create tenant | `POST /api/v1/tenants` | `CreateTenant` | as above | `tenant_create` | ✅ |
| Get tenant | `GET /api/v1/tenants/{id}` | `GetTenant` | as above | `tenant_get` | ✅ |
| Get tenant by name | `GET /api/v1/tenants/by-name/{name}` | `GetTenantByName` | as above | `tenant_get_by_name` | ✅ |
| Update tenant | `PUT /api/v1/tenants/{id}` | `UpdateTenant` | as above | `tenant_update` | ✅ |
| Delete tenant | `DELETE /api/v1/tenants/{id}` | `DeleteTenant` | as above | `tenant_delete` | ✅ |
| Suspend tenant | `POST /api/v1/tenants/{id}/suspend` | `SuspendTenant` | as above | `tenant_suspend` | ✅ |
| Resume tenant | `POST /api/v1/tenants/{id}/resume` | `ResumeTenant` | as above | `tenant_resume` | ✅ |
| Sync tenants | `POST /api/v1/tenants/sync` | `Sync` | as above | `tenant_sync` | ✅ |

`by-name` is a separate route because tenant IDs and tenant names are different
keys; `{id}` will not match a name.

---

## 3. Quotas and usage

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Get quotas | `GET /api/v1/tenants/{id}/quotas` | `GetQuotas` | `0xDB`–`0xEB` | `tenant_get_quotas` | ✅ |
| Update quotas | `PUT /api/v1/tenants/{id}/quotas` | `UpdateQuotas` | as above | `tenant_update_quotas` | ✅ |
| Get usage | `GET /api/v1/tenants/{id}/usage` | `GetUsage` | as above | `tenant_get_usage` | ✅ |
| Check quota | `POST /api/v1/tenants/{id}/quota-check` | `CheckQuota` | as above | `tenant_check_quota` | ✅ |

`quota-check` is a `POST` because it carries a prospective allocation in the
body: it answers "would this fit", not "what is the current usage". That is
`usage`.

---

## 4. Key material

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Rotate tenant DEK | `POST /api/v1/tenants/{id}/dek/rotate` | `RotateTenantDEK` | `0xDB`–`0xEB` | `tenant_rotate_dek` | ✅ |
| Tenant DEK status | `GET /api/v1/tenants/{id}/dek` | `GetTenantDEKStatus` | as above | `tenant_get_dek_status` | ✅ |

**Retired by #708.** The per-tenant VLAN range and OVS bridge are gone, and
with them `ValidateVLAN` / `GetBridgeName` on every transport: the REST routes
`POST /api/v1/tenants/{id}/vlan/validate` and `GET /api/v1/tenants/{id}/bridge`
(and their `validate-vlan` / `bridge` twins on the daemon REST server), the
gRPC methods, the MCP tools `tenant_validate_vlan` and `tenant_get_bridge`, and
QUIC opcodes `0xE7` and `0xE8`, which stay reserved and answer
`StatusNotImplemented`. `Tenant` no longer carries `ovs_bridge`, `vlan_start`
or `vlan_end` (proto fields 5–7 reserved), and `CreateTenantRequest` no longer
takes `vlan_range_start` / `vlan_range_end` (fields 3–4 reserved). A tenant's
network identity becomes a VRF ([architecture.md](architecture.md)).

---

## 5. Per-tenant barrier

QUIC reaches these through the **tenant barrier category opcode `0x9E`**, which
multiplexes the per-tenant barrier sub-operations
(`pkg/api/daemon/quic_service.go:616`). The barrier model — lifecycle, seal
strategies, and how a tenant barrier differs from the platform barrier — is in
[`docs/barrier/`](../barrier/architecture.md#two-barriers).

| Capability | REST | gRPC / Unix | QUIC (under `0x9E`) | MCP | Embedded |
|---|---|---|---|---|---|
| Init barrier | `POST /api/v1/tenants/{id}/barrier/init` | `InitTenantBarrier` | ✅ | `platform_tenant_barrier_init` | ✅ |
| Unseal barrier | `POST /api/v1/tenants/{id}/barrier/unseal` | `UnsealTenantBarrier` | ✅ | `platform_tenant_barrier_unseal` | ✅ |
| Seal barrier | `POST /api/v1/tenants/{id}/barrier/seal` | `SealTenantBarrier` | ✅ | `platform_tenant_barrier_seal` | ✅ |
| Barrier status | `GET /api/v1/tenants/{id}/barrier` (daemon REST server: `.../barrier/status`) | `GetTenantBarrierStatus` | ✅ | `platform_tenant_barrier_status` | ✅ |

**The MCP naming is inconsistent within this one feature.** Fifteen tools use
a bare `tenant_*` prefix; the four barrier tools use `platform_tenant_barrier_*`.
Both conventions exist repo-wide — 119 of the 447 declared tool names carry the
`platform_` prefix and 328 do not (counted before the other #708 changes) — but tenancy is where the split lands inside a
single capability. A client enumerating `tenant_*` will not find the barrier
tools.

**Barrier operations may be unsupported.** `ErrBarrierNotSupported` exists
because per-tenant barriers are not available in every configuration. Handle the
capability being absent; do not assume a barrier.

---

## 6. Tenant-scoped IAM lives elsewhere

`pkg/webservice/v1/rest/iam/router.go` registers a **second, parallel tenant
route tree** under `/api/v1/iam`:

```
/api/v1/iam/tenants
/api/v1/iam/tenants/{tenant}
/api/v1/iam/tenants/{tenant}/users
/api/v1/iam/tenants/{tenant}/roles
/api/v1/iam/tenants/{tenant}/policies
/api/v1/iam/tenants/{tenant}/apps
```

Those are **IAM's tenant scoping**, not platform tenancy: they scope users,
roles, policies and applications to a tenant. Creating a tenant at
`POST /api/v1/iam/tenants` is not the same operation as
`POST /api/v1/tenants`, which creates the platform tenant with its quotas, DEK
and per-tenant barrier.

**Two routes create something called a tenant.** Which is authoritative, and
whether the IAM tree should defer to the platform one, is raised as an owner
question in the migration report. See [`docs/iam/`](../iam/).

---

## 7. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`TenantService` is fully scoped on gRPC** (`pkg/api/grpc/method_permissions.go`):

| Permission | RPCs |
|---|---|
| `tenant:read` | `GetTenant`, `GetTenantByName`, `ListTenants`, `GetQuotas`, `CheckQuota`, `GetUsage`, `GetTenantBarrierStatus`, `GetTenantDEKStatus` |
| `tenant:write` | `CreateTenant`, `UpdateTenant`, `UpdateQuotas`, `SuspendTenant`, `ResumeTenant`, `Sync`, `InitTenantBarrier`, `SealTenantBarrier`, `UnsealTenantBarrier`, `RotateTenantDEK` |
| `tenant:delete` | `DeleteTenant` |

The barrier and DEK calls are key-custody operations, so `tenant:write` is the
grant to guard.

**Every tenant MCP tool is refused.** None of the `tenant_*` or
`platform_tenant_barrier_*` tools is in the MCP permission map, so
`AuthorizeTool` answers `AuthErrorToolNotClassified` for every caller until
they are classified.

### QUIC requires the tenant scopes (#767)

The QUIC guard authorizes every frame against
`pkg/api/quic/opcode_permissions.go` before dispatch
([`docs/daemon/api.md`](../daemon/api.md) §5). The tenancy opcodes carry the
`tenant` resource:

| Action | Opcodes |
|---|---|
| `tenant:read` | `OpTenantList`, `OpTenantGet`, `OpTenantGetByName`, `OpTenantGetQuotas`, `OpTenantGetUsage`, `OpTenantCheckQuota`, `OpTenantGetDEKStatus`; barrier category `0x9E` sub `TenantBarrierSubStatus` |
| `tenant:write` | `OpTenantCreate`, `OpTenantUpdate`, `OpTenantSuspend`, `OpTenantResume`, `OpTenantUpdateQuotas`, `OpTenantSync`, `OpTenantRotateDEK`; barrier subs `Init`, `Unseal`, `Seal` |
| `tenant:delete` | `OpTenantDelete` |

The `iam` scopes do not open these opcodes. IAM tenant *records*
(`PlatformIAMService` tenant methods) have their own QUIC category,
`OpIAMCategory` (`0x51`), under the `iam` scopes —
[`docs/iam/api.md`](../iam/api.md) §8. Before #767 the SDK sent those IAM calls
on the `OpTenant*` bytes, so the catalog checked `iam:*` for platform tenancy
operations and an IAM tenant call reached `TenantService`.

### REST is gated on the `admin` role (#165)

`/api/v1/tenants/**` requires an authenticated caller holding `admin`. That
covers tenant create, delete, suspend and resume, quota updates, `POST
/{id}/dek/rotate`, and `POST /{id}/barrier/{init,unseal,seal}`.

The REST gate is role-based; the gRPC and MCP positions are the scope catalogs
above.

Note the two tenant surfaces are different things. `/api/v1/tenants` is the
tenancy data plane gated here; `/api/v1/iam/tenants` is the tenant *record*
control plane, which #159 additionally restricts to the system tenant. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | Tenant cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidRequest`, `ErrInvalidID` |
| `0x02` | `StatusNotFound` | 404 | `ErrTenantNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | `ErrStorageFailed`, `ErrDEKOperationFailed`, `ErrBarrierOperationFailed` |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrTenantExists` |
| `0x08` | `StatusResourceExhausted` | 429 | `ErrQuotaExceeded`, `ErrResourceLimitReached` |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrConfigValidation` |
| `0x0A` | `StatusUnavailable` | 503 | Tenant service not wired in |
| `0x0B` | `StatusNotImplemented` | 501 | `ErrBarrierNotSupported` |

`ErrInvalidState` and `ErrInvalidTransition` map to 409: the request is
well-formed and the tenant is in a state that does not permit it. Same-state
transitions succeed (idempotency), so "suspend an already-suspended tenant"
returns 200, not 409.

---

## 9. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The two
parallel tenant route trees in §6 are a duplication awaiting an owner ruling,
not a deprecation.
