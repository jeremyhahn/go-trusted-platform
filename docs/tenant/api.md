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

gRPC: `TenantService`, 21 RPCs (`pkg/api/grpc/proto/tenant.proto`).
REST: base path `/api/v1/tenants` (`pkg/webservice/v1/rest/tenant/router.go`).
QUIC: tenant management opcodes in the `0xDB`–`0xEB` range, plus a **tenant
barrier category opcode `0x9E`** that multiplexes the per-tenant barrier
sub-operations.
MCP: 21 tools in two naming families — see §5.

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

## 4. Network and key material

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Validate VLAN | `POST /api/v1/tenants/{id}/vlan/validate` | `ValidateVLAN` | `0xDB`–`0xEB` | `tenant_validate_vlan` | ✅ |
| Get bridge name | `GET /api/v1/tenants/{id}/bridge` | `GetBridgeName` | as above | `tenant_get_bridge` | ✅ |
| Rotate tenant DEK | `POST /api/v1/tenants/{id}/dek/rotate` | `RotateTenantDEK` | as above | `tenant_rotate_dek` | ✅ |
| Tenant DEK status | `GET /api/v1/tenants/{id}/dek` | `GetTenantDEKStatus` | as above | `tenant_get_dek_status` | ✅ |

---

## 5. Per-tenant barrier

QUIC reaches these through the **tenant barrier category opcode `0x9E`**, which
multiplexes the per-tenant barrier sub-operations
(`pkg/api/daemon/quic_service.go:616`).

| Capability | REST | gRPC / Unix | QUIC (under `0x9E`) | MCP | Embedded |
|---|---|---|---|---|---|
| Init barrier | `POST /api/v1/tenants/{id}/barrier/init` | `InitTenantBarrier` | ✅ | `platform_tenant_barrier_init` | ✅ |
| Unseal barrier | `POST /api/v1/tenants/{id}/barrier/unseal` | `UnsealTenantBarrier` | ✅ | `platform_tenant_barrier_unseal` | ✅ |
| Seal barrier | `POST /api/v1/tenants/{id}/barrier/seal` | `SealTenantBarrier` | ✅ | `platform_tenant_barrier_seal` | ✅ |
| Barrier status | `GET /api/v1/tenants/{id}/barrier` | `GetTenantBarrierStatus` | ✅ | `platform_tenant_barrier_status` | ✅ |

**The MCP naming is inconsistent within this one feature.** Seventeen tools use
a bare `tenant_*` prefix; the four barrier tools use `platform_tenant_barrier_*`.
Both conventions exist repo-wide — 119 of the 449 declared tool names carry the
`platform_` prefix and 330 do not — but tenancy is where the split lands inside a
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
/api/v1/iam/tenants/{tenant}/groups
/api/v1/iam/tenants/{tenant}/roles
/api/v1/iam/tenants/{tenant}/policies
/api/v1/iam/tenants/{tenant}/apps
```

Those are **IAM's tenant scoping**, not platform tenancy: they scope users,
groups, roles, policies and applications to a tenant. Creating a tenant at
`POST /api/v1/iam/tenants` is not the same operation as
`POST /api/v1/tenants`, which allocates a VLAN, a bridge, a keyspace and a DEK.

**Two routes create something called a tenant.** Which is authoritative, and
whether the IAM tree should defer to the platform one, is raised as an owner
question in the migration report. See [`docs/iam/`](../iam/).

---

## 7. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.

**`TenantService` is not in the gRPC scope catalog.**
`pkg/api/grpc/method_permissions.go` maps 185 methods across eleven services;
tenancy is not among them, and a method absent from the map carries no required
scope — the interceptor allows it once the token is validated.

**No tenant MCP tool is in the authorization map either.** Of the 449 declared
tool names, 71 carry a required permission; none of the 21 tenant tools do.

So **any validated token can create, suspend, delete and re-quota a tenant, and
init, seal or unseal a per-tenant barrier**, on gRPC, Unix, MCP and embedded.
Barrier operations in particular are key-custody operations. This is raised as
an owner question in the migration report and is not decided here.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | Tenant cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidRequest`, `ErrInvalidID` |
| `0x02` | `StatusNotFound` | 404 | `ErrTenantNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | `ErrStorageFailed`, `ErrBridgeOperationFailed`, `ErrDEKOperationFailed`, `ErrBarrierOperationFailed` |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrTenantExists` |
| `0x08` | `StatusResourceExhausted` | 429 | `ErrQuotaExceeded`, `ErrResourceLimitReached`, `ErrVLANAllocationFailed` |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidVLANRange`, `ErrConfigValidation` |
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
