# IAM — API

> **Status: NORMATIVE** · Scope: IAM routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.IAM` carries the service in-process.

gRPC: `PlatformIAMService`, **41 RPCs** — the largest service in the platform
(`pkg/api/grpc/proto/iam.proto`).
REST: `/api/v1/iam`, in **two parallel trees** — see §2.
QUIC: users `0xA9`–`0xAD`, roles `0xB5`–`0xBA`, groups `0xBB`–`0xBF`, extended
`0xF6`–`0xFB`, tenant records under the `OpIAMCategory` (`0x51`) category.
MCP: 25 `iam_*` tools.

---

## 2. Every REST route exists twice

`pkg/webservice/v1/rest/iam/router.go` registers each capability under an
unscoped path **and** a tenant-scoped path, both dispatching to the same handler:

| Capability | Unscoped | Tenant-scoped |
|---|---|---|
| Users | `/api/v1/iam/users` | `/api/v1/iam/tenants/{tenant}/users` |
| Groups | `/api/v1/iam/groups` | `/api/v1/iam/tenants/{tenant}/groups` |
| Roles | `/api/v1/iam/roles` | `/api/v1/iam/tenants/{tenant}/roles` |
| Policies | `/api/v1/iam/policies` | `/api/v1/iam/tenants/{tenant}/policies` |
| Applications | `/api/v1/iam/apps` | `/api/v1/iam/tenants/{tenant}/apps` |

**Which tenant an unscoped call operates on is not visible from the route.** It
is the tenant of the verified session. An unscoped route may name its tenant in
the `tenant_id` query parameter: the own-tenant guard refuses it with `403`
unless it is the session's tenant, so a foreign tenant is never answered from
the session's tenant under the same id (#401). A scoped route that also carries
`?tenant_id=` must name the path's tenant there; a different one is refused
with `403`, never resolved in favour of either. A tenant named in the request
body — `tenant_id`, or the JS SDK's `tenantId` — is refused the same way: the
handler decodes it with the rest of the body and answers `403` unless it is
the tenant the route acts on (the path's `{tenant}`, otherwise the session's),
before anything is read or written. That holds on both route forms and on the
list routes, whose optional GET body the handler reads for exactly this
reason. A body naming no tenant is served. For anything multi-tenant, use the `/tenants/{tenant}/...` form so
the target is explicit — the CLI takes the same position by making
`<tenant-id>` a required positional argument.

The Go SDK's REST transport sends the item operations — Get, Update, Delete,
AssignRole, RevokeRole, AddGroupMember, RemoveGroupMember on users, roles and
groups — to the tenant-scoped form, so the request's `tenant_id` reaches the
guard exactly as it does on gRPC (#401). Update is the `PUT` on the item; the
SDK previously had no route for it and posted to an unserved
`/api/v1/platformiam/update*`. An empty `tenant_id` is refused with
`InvalidArgument` before anything is sent. The REST handlers answer a single
user, role, group or tenant as the bare resource; the SDK places it in the
reply's resource field (`IAMUserResponse.user`, ...), so Create, Get and Update
return the resource over REST as they do over gRPC. Create and List still use the
unscoped form, but they carry the request's `tenant_id` in the body, so a
foreign tenant is refused there and surfaces as `PermissionDenied`, as on
gRPC; an empty one acts on the session's tenant.

Rows below give the unscoped path; the tenant-scoped equivalent always exists.

---

## 3. Users

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create user | `POST /api/v1/iam/users` | ✅ | `0xA9`–`0xAD` | `iam_create_user` | ✅ |
| List users | `GET /api/v1/iam/users` | ✅ | as above | `iam_list_users` | ✅ |
| Get user | `GET /api/v1/iam/users/{id}` | ✅ | as above | `iam_get_user` | ✅ |
| Update user | `PUT /api/v1/iam/users/{id}` | ✅ | as above | `MISSING — docs/13 G7` | ✅ |
| Delete user | `DELETE /api/v1/iam/users/{id}` | ✅ | as above | `iam_delete_user` | ✅ |
| Assign role to user | `POST /api/v1/iam/users/{id}/roles/{role}` | ✅ | `0xB5`–`0xBA` | `iam_assign_role` | ✅ |
| Revoke role from user | `DELETE /api/v1/iam/users/{id}/roles/{role}` | ✅ | as above | `iam_revoke_role` | ✅ |

`iam_update_user` does not exist — user updates are REST, gRPC, QUIC and
embedded only.

## 4. Groups

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create group | `POST /api/v1/iam/groups` | ✅ | `0xBB`–`0xBF` | `iam_create_group` | ✅ |
| List groups | `GET /api/v1/iam/groups` | ✅ | as above | `iam_list_groups` | ✅ |
| Get group | `GET /api/v1/iam/groups/{id}` | ✅ | as above | `iam_get_group` | ✅ |
| Update group | `PUT /api/v1/iam/groups/{id}` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |
| Delete group | `DELETE /api/v1/iam/groups/{id}` | ✅ | as above | `iam_delete_group` | ✅ |
| Add group member | `POST /api/v1/iam/groups/{id}/members/{user}` | ✅ | ✅ | `iam_add_group_member` | ✅ |
| Remove group member | `DELETE /api/v1/iam/groups/{id}/members/{user}` | ✅ | ✅ | `iam_remove_group_member` | ✅ |

**Group membership is present on every transport except the CLI**, where both
verbs are unimplemented stubs — see [cli.md](cli.md) §4.

## 5. Roles, policies and applications

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Role CRUD | `/api/v1/iam/roles`, `/roles/{id}` | ✅ | `0xB5`–`0xBA` | `iam_create_role`, `iam_get_role`, `iam_list_roles`, `iam_delete_role` | ✅ |
| Update role | `PUT /api/v1/iam/roles/{id}` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |
| Policy CRUD | `/api/v1/iam/policies`, `/policies/{id}` | ✅ | `0xF6`–`0xFB` | `MISSING — docs/13 G7` | ✅ |
| **Validate policy** | `POST /api/v1/iam/policies/validate` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |
| **Test policy** | `POST /api/v1/iam/policies/test` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |
| Application CRUD | `/api/v1/iam/apps`, `/apps/{id}` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |
| Rotate app secret | `POST /api/v1/iam/apps/{id}/rotate` | ✅ | ✅ | `MISSING — docs/13 G7` | ✅ |

**Policies and applications have no MCP tools at all.** Twenty-five `iam_*`
tools cover users, groups, roles, tenants and tokens — and neither the
authorization policies themselves nor OAuth applications.

`/policies/validate` and `/policies/test` are registered **before**
`/policies/{id}`, so `validate` and `test` are not swallowed as policy ids.

## 6. Tenants, tokens and authentication

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create tenant (IAM scoping) | `POST /api/v1/iam/tenants` | ✅ | `0x51` sub `0x01` | `iam_create_tenant` | ✅ |
| List / get / update / delete tenant | `/api/v1/iam/tenants[/{tenant}]` | ✅ | `0x51` subs `0x03` / `0x02` / `0x04` / `0x05` | `iam_list_tenants`, `iam_get_tenant`, `iam_delete_tenant` | ✅ |
| Authenticate | `MISSING — docs/13 G7` | ✅ | ✅ | `iam_authenticate` | ✅ |
| Create token | `MISSING — docs/13 G7` | ✅ | JWT/auth `0x90`–`0x97` | `iam_create_token` | ✅ |
| Verify token | `MISSING — docs/13 G7` | ✅ | as above | `iam_verify_token` | ✅ |
| Revoke token | `MISSING — docs/13 G7` | ✅ | as above | `iam_revoke_token` | ✅ |
| Check permission | `MISSING — docs/13 G7` | ✅ | ✅ | `iam_check_permission` | ✅ |

**Token issuance, verification and revocation have no REST route** under
`/api/v1/iam`. Login and refresh are served by a separate authentication router
(`pkg/webservice/v1/router/authentication.go` — `login`, `refreshToken`), and
WebAuthn by `pkg/webservice/v1/router/webauthn.go`.

**`POST /api/v1/iam/tenants` is not `POST /api/v1/tenants`.** The first creates
an IAM scoping boundary for users, groups, roles and policies. The second
allocates a VLAN, a bridge, a keyspace and a DEK
([`docs/tenant/`](../tenant/)). Two routes, one word, two meanings — raised as an
owner question.

---

## 7. The WebAuthn user mirror

A user created through the WebAuthn registration flow is **mirrored** into the
stack's IAM tenant by `QuicBaaSUserMirror`
(`pkg/webservice/v1/rest/iam/mirror.go`) so that `/api/v1/iam/users` surfaces
them.

That is a synchronisation point between two stores. Its own doc comment warns
that the mirror must be given **the same `IAMClient` the REST IAM router uses**,
"so both surfaces speak to the same tenant store". Given different clients, the
two diverge silently.

If a user exists in one surface and not the other, this is the first place to
look.

---

## 8. Authorization

**REST is gated at the route.** Every `/api/v1/iam/**` route requires an
authenticated caller holding the `admin` role, and the tenant-lifecycle routes
(`/api/v1/iam/tenants*`) additionally require the caller to be in the system
tenant. Denials are `401` (no session) and `403` (wrong role or wrong tenant).
The router refuses to build without those guards, so the surface is either
gated or absent. Details and rationale:
[architecture.md §Authorization Flow](architecture.md#authorization-flow) and
[`docs/auth/architecture.md` §6c](../auth/architecture.md).

That gate is REST-only; the gRPC, QUIC and MCP pictures follow.

**The tenant binding is on every transport (#401).** A tenant-bound caller is
served only from its own tenant:

| Transport | Caller's tenant | Request names another tenant | Request names no tenant |
|---|---|---|---|
| REST | the session — token `tenant_id` claim, or the mTLS certificate | `403` from `RequireOwnTenant`, on `/tenants/{tenant}/...` and on an unscoped route's `?tenant_id=`; `403` `ErrConflictingQueryTenant` for a `?tenant_id=` on `/tenants/{tenant}/...` that differs from the path; `403` `ErrForeignBodyTenant` from the handler for a body `tenant_id` / `tenantId` | unscoped routes use the session tenant |
| gRPC, QUIC | the platform token's `tenant_id` claim, or the mTLS certificate | `PermissionDenied`, `ErrIAMTenantForbidden` | `InvalidArgument`, `tenant_id` is required |
| Unix | none — peer-credential operator | served (the operator is not tenant-bound) | `InvalidArgument` |
| MCP | — | refused: no `iam_*` tool is in the authorization map (below) | refused |

On REST the extractor the guard reads is `RequestedTenant`
(`pkg/webservice/v1/rest/iam/router.go`): the path's `{tenant}`, otherwise the
`tenant_id` query. Every IAM route except the tenant-record routes, which are
system-tenant only, is behind it. On a scoped route the query never overrides
the path: a `tenant_id` query naming a tenant other than the path's `{tenant}`
is refused with `403` before the handler runs (`consistentTenant`,
`pkg/webservice/v1/rest/iam/handlers.go`). The same tenant in both, or no
query, is served. The guard does not read the body; each
handler decodes it once and refuses a body tenant that differs from the one
the route acts on (`ownBodyTenant`, `pkg/webservice/v1/rest/iam/handlers.go`),
before any IAM lookup or write.

On gRPC and QUIC the check is `authorizeIAMTenant`
(`pkg/api/daemon/iam_tenant_authz.go`). It covers every user, role, group,
policy and application RPC. It does not cover the tenant-lifecycle RPCs, nor
`CheckPermission` and the token RPCs. A daemon run with `SkipIAMValidation`
has no caller identity and serves the named tenant.

Through the Go SDK's REST transport, an item operation reaches the scoped form
(§2). The `403` surfaces as `PermissionDenied` and a missing tenant as
`InvalidArgument`, the same codes gRPC returns.

**`PlatformIAMService` is in the gRPC scope catalog** with **41 methods
mapped** — the largest entry in the catalog, resource `iam`, actions
`read`/`write`/`delete`.

**QUIC carries the same `iam` pairs (#767).** IAM tenant records travel under
their own category, `OpIAMCategory` (`0x51`): sub-opcodes `IAMSubTenantCreate`
`0x01` and `IAMSubTenantUpdate` `0x04` need `iam:write`, `IAMSubTenantGet`
`0x02` and `IAMSubTenantList` `0x03` need `iam:read`, `IAMSubTenantDelete`
`0x05` needs `iam:delete`. The daemon delegates them to `IAMGRPCService`
(`pkg/api/daemon/quic_iam_category.go`). Before #767 the SDK sent these calls
on the `OpTenant*` bytes, which dispatch to the platform `TenantService`
([`docs/tenant/`](../tenant/)): an IAM tenant call reached the wrong service,
and the catalog could not give one byte both meanings' scopes.

**None of the 25 `iam_*` MCP tools is in the MCP authorization map, so every
one of them is refused.** Of 428 registered tools, 94 carry a permission; no
IAM tool is among them, and since #300 `AuthorizeTool` **denies** a tool absent
from the map (`AuthErrorToolNotClassified`, `-32603` on the wire) rather than
allowing it. The 25 are enumerated in `knownUnclassified`
(`pkg/api/mcp/authz_completeness_test.go`) and classifying them is #304's IAM
tranche — each needs the `resource:action` its gRPC method already carries, and
the tenant-lifecycle tools cannot be expressed correctly until MCP can carry
tenant scope (#299).

So `CreateUser` over gRPC requires an `iam` scope, while `iam_create_user`,
`iam_assign_role`, `iam_create_token` and `iam_delete_user` over MCP are
**non-functional for every caller** until classified. The escalation this
section previously described — any valid token minting credentials through
`iam_create_token` — was closed by #300; what remains is a capability gap, not
a hole (#412).

---

## 9. Status and error mapping

| QUIC byte | Name | REST | IAM cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed user, role or policy document |
| `0x02` | `StatusNotFound` | 404 | Unknown user, group, role, policy, app or tenant |
| `0x03` | `StatusUnauthorized` | 401 | Authentication failed; token invalid or revoked |
| `0x04` | `StatusInternalError` | 500 | Backend failure |
| `0x06` | `StatusAlreadyExists` | 409 | Name already in use |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `iam:*` scope; permission check denied |
| `0x09` | `StatusInvalidArgument` | 400 | Policy failed validation |
| `0x0A` | `StatusUnavailable` | 503 | IAM not wired into the daemon (`iam_service_stub.go`) |

`ValidatePolicy` returning a rejection is a **200 with a negative result**, not a
400 — validation is the operation, and "this policy is invalid" is its answer.
Distinguish that from a 400 for a malformed request body.

---

## 10. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The two
parallel tenant trees in §2 and the two meanings of "tenant" in §6 are
duplications awaiting an owner ruling.
