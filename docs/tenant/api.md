# Platform Tenancy — API

> **Status: NORMATIVE** · Scope: tenant routes on every transport · Last verified: 2026-10-15
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

**An update changes limits, never usage (#304).** `UpdateQuotas` starts from
the tenant's current quotas and overwrites only the sections the request
carries; a section left out keeps its limits. The manager takes only limits
from any request, so the usage counters survive every update. The gRPC
`ComputeQuota` message has no disk field: a gRPC, QUIC, MCP or Unix update keeps
the stored `MaxDiskGB`, and only the daemon REST server
(`pkg/api/rest/tenant_handlers.go`, `max_disk_gb`) sets it.

---

## 4. Key material

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Rotate tenant DEK | `POST /api/v1/tenants/{id}/dek/rotate` | `RotateTenantDEK` | `0xDB`–`0xEB` | `tenant_rotate_dek` | ✅ |
| Tenant DEK status | `GET /api/v1/tenants/{id}/dek` | `GetTenantDEKStatus` | as above | `tenant_get_dek_status` | ✅ |

The rotate body is optional: `{"background": true}` asks for a background
rotation, the same `background` field the gRPC `RotateTenantDEKRequest`
carries, and an empty body rotates in the foreground. The tenant always comes
from the path (#304).

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
/api/v1/iam/tenants/{tenant}/groups
/api/v1/iam/tenants/{tenant}/roles
/api/v1/iam/tenants/{tenant}/policies
/api/v1/iam/tenants/{tenant}/apps
```

Those are **IAM's tenant scoping**, not platform tenancy: they scope users,
groups, roles, policies and applications to a tenant. Creating a tenant at
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

**MCP carries the same scopes (#304).** Each tenant tool requires the scope of
its `TenantService` method (`toolPermissionCatalog`, `pkg/api/mcp/authz.go`):

| Permission | Tools |
|---|---|
| `tenant:read` | `tenant_get`, `tenant_get_by_name`, `tenant_list`, `tenant_get_quotas`, `tenant_check_quota`, `tenant_get_usage`, `platform_tenant_barrier_status`, `tenant_get_dek_status` |
| `tenant:write` | `tenant_create`, `tenant_update`, `tenant_update_quotas`, `tenant_suspend`, `tenant_resume`, `tenant_sync`, `platform_tenant_barrier_init`, `platform_tenant_barrier_seal`, `platform_tenant_barrier_unseal`, `tenant_rotate_dek` |
| `tenant:delete` | `tenant_delete` |

Every tool calls the daemon's shared `TenantGRPCServer`, so an MCP call gets
the answer and the error code its gRPC method gives for the same input. A tool
refuses a caller whose token carried no tenant binding — the legacy
bool-validation auth path — with `PermissionDenied`
(`ErrTenantCallerUnbound`), before the server is reached.

### The tenant binding (#304)

The scope is necessary, not sufficient. `TenantService` keeps a tenant-bound
caller to its own tenant (`pkg/api/daemon/tenant_grpc_authz.go`), on gRPC, QUIC
and MCP alike — the rule the REST guards apply:

| Request | Admitted | Otherwise |
|---|---|---|
| names a tenant (get, update, delete, quotas, usage, suspend, resume, DEK, barrier) | the caller's own tenant, or the system tenant | `PermissionDenied`, `ErrTenantForbidden` |
| acts across tenants (`ListTenants`, `CreateTenant`, `Sync`) | the system tenant | `PermissionDenied`, `ErrTenantSystemOnly` |
| looks a tenant up by name (`GetTenantByName`) | the caller's own tenant, or the system tenant for any name | `PermissionDenied`, `tenant.ErrNameLookupDenied` |

**Lookup by name resolves first, then decides (#304).** The CLI is
name-keyed, so every verb starts with `GetTenantByName`; a tenant acting on
itself must be able to resolve its own name. The server resolves the name, then
applies one rule, `tenant.AuthorizeNameLookup` (`pkg/tenant/access.go`), to the
caller's tenant from the token or certificate (on REST, the session's claim; see
below), never from a request field. Another tenant's name and a name that does not exist get the
same `tenant.ErrNameLookupDenied`, so a tenant learns nothing about which names
exist. Only the system tenant and an unbound caller see `NotFound` for a
missing name.

**REST applies the same rule in a per-route guard.** `GET
/api/v1/tenants/by-name/{name}` is guarded by
`SessionGuard.RequireOwnTenantNameOrSystem`
(`pkg/webservice/v1/middleware/iam/guard.go`), not by the system-only guard.
The guard reads the caller from the REST session's authenticated tenant claim,
resolves the name through `TenantGRPCServer.GetTenantByName`, and calls
`tenant.AuthorizeNameLookup`. A tenant resolves its own name; the system
tenant resolves any name without the extra lookup. Another tenant's name and an
unknown name both get `403` with the `tenant.ErrNameLookupDenied` message, so
the two answers are identical. The shared server check never reads the REST
session: behind the guard, the REST caller reads as unbound to
`TenantGRPCServer`. This guard and `tenant.AuthorizeNameLookup` are the
platform's own tenant-scope check, which moves to go-qrdb under the IAM
clean-up row for tenant scope in [SPEC.md §Interfaces](../SPEC.md#interfaces).

The SDK REST transport (`sdk/go/transport/rest/adapter.go`) carries
`GetTenantByName`, `GetQuotas`, `UpdateQuotas` and `GetUsage` on the routes in
§2–3, so `platformctl tenant` runs over REST like every other transport. It
also carries `CheckQuota`, `Sync`, `RotateTenantDEK` and `GetTenantDEKStatus`
(§2–4): the quota check keeps `resource` and `amount` in the POST body, and the
DEK rotation keeps `background` there.

The SDK QUIC transport (`sdk/go/transport/quic/adapter.go`) carries every
§2–4 method, `CheckQuota` (`0xE6`), `Sync` (`0xE9`), `RotateTenantDEK`
(`0xEA`) and `GetTenantDEKStatus` (`0xEB`) included, and the §5 barrier methods
under `0x9E`. The SDK MCP transport (`sdk/go/transport/mcp/tenant.go`) carries
every §2–5 method on the MCP tools those sections name: quota limits travel as the
tools' flat `max_*` arguments, the quota check's `resource` as
`resource_type`, and the tools' state names and RFC 3339 times decode back onto
the gRPC replies. On `tenant_update_quotas` a zero limit keeps the tenant's
current limit, so MCP cannot lower a limit to 0.

The caller's tenant is the token's `tenant_id` claim, or the mTLS certificate.
The system tenant is the platform's operating tenant (`App.TenantID`); with none
set, no tenant-bound caller acts across tenants. A caller with no tenant-bound
identity — the Unix-socket operator, or a daemon run with `SkipIAMValidation` —
is served. The check runs after `tenant_id` is validated and before the manager
is called, so a refused request touches no DEK and no barrier.

`InitTenantBarrier` refuses a non-zero `threshold` or `shares` with
`InvalidArgument` (`ErrTenantBarrierShamirUnsupported`). The barrier is
initialized with the deterministic init credential and returns no shares, so a
Shamir request was previously ignored while the call reported success.

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

The REST gate is role-based; the gRPC, QUIC and MCP positions are the scope
catalogs above, with the tenant binding behind them.

### The daemon REST server checks the scope and the binding (#304)

The daemon listener serves the tenant routes too (`pkg/api/rest/tenant_handlers.go`,
wired by `RESTServer.SetTenantHandlers`). Before #304 they had no guard, so any
caller past the mTLS handshake reached every tenant. Each route now runs through
`restapi.ScopeGuard` (`pkg/api/rest/route_scope.go`), which authenticates the
caller with a `Bearer` platform token and its `DPoP` proof, or else with the
verified client certificate, admitted as an operator of the certificate's tenant
holding `*:*` ([`docs/daemon/api.md`](../daemon/api.md) §5). The route requires
its RPC's scope, then applies the `TenantService` rule to the authenticated
caller, never to a request field:

| Daemon REST route | Scope | Who may call |
|---|---|---|
| `GET /api/v1/tenants` | `tenant:read` | the system tenant |
| `POST /api/v1/tenants` | `tenant:write` | the system tenant |
| `POST /api/v1/tenants/sync` | `tenant:write` | the system tenant |
| `GET /api/v1/tenants/name/{name}` | `tenant:read` | the tenant of that name, or the system tenant for any name |
| `GET /api/v1/tenants/{id}`, `.../quotas`, `.../usage`, `.../dek/status`, `.../barrier/status`; `POST .../check-quota` | `tenant:read` | tenant `{id}`, or the system tenant |
| `PUT /api/v1/tenants/{id}`, `PUT .../quotas`; `POST .../suspend`, `.../resume`, `.../dek/rotate`, `.../barrier/init`, `.../barrier/unseal`, `.../barrier/seal` | `tenant:write` | tenant `{id}`, or the system tenant |
| `DELETE /api/v1/tenants/{id}` | `tenant:delete` | tenant `{id}`, or the system tenant |

An invalid `Bearer` token is `401`; a connection with no client certificate is
refused at the TLS handshake, which requires one (`EnableREST` requires
`EnableMTLS`), so it never reaches a route. A missing scope is `403`. A refusal by
the binding is `403`, and its `error` text is the message gRPC returns with
`PermissionDenied`: `ErrTenantForbidden`, `ErrTenantSystemOnly` or
`tenant.ErrNameLookupDenied`. The by-name route resolves the name first, then
calls `tenant.AuthorizeNameLookup`. Another tenant's name and an unknown name
therefore get the same `403`, and only the system tenant sees `404`. The
certificate operator's `*:*` grant is the platform's own, and the IAM clean-up
row for transport checks in [SPEC.md §Interfaces](../SPEC.md#interfaces) moves
it to the go-qrdb decision point.

The system tenant is `App.TenantID`, the same one the gRPC server uses. Every
caller on this listener is authenticated, so the unbound caller that gRPC
serves has no daemon REST counterpart. Both transports call the same exported
rules in `pkg/tenant/access.go`: `AuthorizeTenantAccess`, `AuthorizeCrossTenant`
and `AuthorizeNameLookup`. `pkg/api/daemon/rest_tenant_authz_test.go` runs the
system tenant, the caller's own tenant and another tenant through both
transports for every route.

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

---

## 10. Invitations

`InvitationService`, 7 RPCs (`pkg/api/grpc/proto/invitation.proto`). The
invitation model — redemption, initial-admin invitations, time — is in
[architecture.md](architecture.md). QUIC and MCP call the daemon's gRPC
servicer (`pkg/api/daemon/invitation_grpc_service.go`), so a call gets the
answer and the error code gRPC gives for the same input (#704). REST is served
by `pkg/webservice/v1/rest/invitation`.

| Capability | REST | gRPC / Unix | QUIC (under `0x51`) | MCP | Scope |
|---|---|---|---|---|---|
| Create | `POST /api/v1/invitations` | `CreateInvitation` | sub `0x10` | `platform_invitation_create` | `invitation:write` |
| Get | `GET /api/v1/invitations/{id}` | `GetInvitation` | sub `0x11` | `platform_invitation_get` | `invitation:read` |
| Get by token | `GET /api/v1/invitations/token/{token}` | `GetInvitationByToken` | sub `0x12` | `platform_invitation_get_by_token` | pre-auth |
| List | `GET /api/v1/invitations` | `ListInvitations` | sub `0x13` | `platform_invitation_list` | `invitation:read` |
| Revoke | `POST /api/v1/invitations/{id}/revoke` | `RevokeInvitation` | sub `0x14` | `platform_invitation_revoke` | `invitation:write` |
| Accept | `POST /api/v1/invitations/accept` | `AcceptInvitation` | sub `0x15` | `platform_invitation_accept` | pre-auth |
| Delete | `DELETE /api/v1/invitations/{id}` | `DeleteInvitation` | sub `0x16` | `platform_invitation_delete` | `invitation:delete` |

**Get by token and Accept are pre-auth on every transport.** The invitation
token in the request is the credential; the invitee holds no platform session
yet. They are on the gRPC pre-auth list, QUIC's `preAuthSubOpcodes`
(`pkg/api/quic/opcode_permissions.go`) and the MCP open tools, and REST serves
them outside the `admin` gate ([`docs/auth/architecture.md`](../auth/architecture.md)).
REST gates the operator half on the `admin` role; gRPC, QUIC and MCP require
the scope in the table.

**QUIC shares `OpIAMCategory` (`0x51`) with the IAM tenant records** (`0x01`–
`0x05`, IAM group update `0x06` and IAM role update `0x07`, [`docs/iam/api.md`](../iam/api.md) §5a): no free opcode byte remained,
so the invitation sub-opcodes start at `0x10` (`InvitationSub*`,
`sdk/go/wire/quicwire/invitation_opcodes.go`). The daemon dispatches them
through a map to the servicer (`pkg/api/daemon/quic_invitation.go`).

**MCP tools take the request and return the response as protojson** with proto
field names: IDs are decimal strings, enums travel by name
(`INVITATION_STATUS_PENDING`), times as RFC 3339. An argument the request does
not have is refused. `platform_invitation_list` takes `status_filter` and
`email_filter` as the gRPC request does.

**Error codes on gRPC, QUIC and MCP.** The servicer maps the service's typed errors:
`ErrInvitationNotFound` is `NotFound`, `ErrInvalidInvitation` is
`InvalidArgument` (a zero `user_id` on Accept among them),
`ErrEmailAlreadyRegistered` is `AlreadyExists`, and an expired, accepted or
revoked invitation, or a wrong status, is `FailedPrecondition`. Anything else is
`Internal` and logged. A daemon with no invitation service answers
`Unimplemented` on all three. Before #704 every gRPC error was `Unknown`.

**The Go SDK** reaches the service through `Invitation()` (and `EAB()` for
`EABService`). Its QUIC adapter maps every method in
`sdk/go/transport/quic/aab_invitation.go` and its MCP adapter in
`sdk/go/transport/mcp/invitation.go`.
