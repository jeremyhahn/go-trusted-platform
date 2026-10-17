# IAM — API

> **Status: NORMATIVE** · Scope: IAM routes on every transport · Last verified: 2026-10-14
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
QUIC: 22 IAM opcodes (`sdk/go/wire/quicwire/protocol.go`) — users
`0xA9`–`0xAD`, roles `0xB5`–`0xBA`, groups `0xBB`–`0xBF`, and the extended
range `0xF6`–`0xFB` — plus tenant records under the `OpIAMCategory` (`0x51`)
category (`iam_opcodes.go`). The full byte map is §5a.
MCP: 25 `iam_*` tools; 21 answer through `IAMGRPCService`, `iam_verify_token`
through `IAMTokenService`, and 3 refuse (§8).

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
| Create user | `POST /api/v1/iam/users` | ✅ | `0xA9` | `iam_create_user`, `iam:write` | ✅ |
| List users | `GET /api/v1/iam/users` | ✅ | `0xAC` | `iam_list_users`, `iam:read` | ✅ |
| Get user | `GET /api/v1/iam/users/{id}` | ✅ | `0xAB` | `iam_get_user`, `iam:read` | ✅ |
| Update user | `PUT /api/v1/iam/users/{id}` | ✅ | `0xAD` | `MISSING — docs/13 G7` | ✅ |
| Delete user | `DELETE /api/v1/iam/users/{id}` | ✅ | `0xAA` | `iam_delete_user`, `iam:delete` | ✅ |
| Assign role to user | `POST /api/v1/iam/users/{id}/roles/{role}` | ✅ | `0xB9` | `iam_assign_role`, `iam:write` | ✅ |
| Revoke role from user | `DELETE /api/v1/iam/users/{id}/roles/{role}` | ✅ | `0xBA` | `iam_revoke_role`, `iam:write` | ✅ |

`iam_update_user` does not exist — user updates are REST, gRPC, QUIC and
embedded only.

Create user takes an email and no required username. The IAM SDK refuses an
empty username, so every transport (REST, gRPC, Unix, QUIC, MCP) derives it
from the email's local part (`alice@acme.test` → `alice`), or uses the whole
address when it has no local part (`UsernameFromEmail` in
`pkg/webservice/v1/rest/iam/mirror.go`). REST also accepts an explicit
`username`.

## 4. Groups

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create group | `POST /api/v1/iam/groups` | ✅ | `0xBB` | `iam_create_group`, `iam:write` | ✅ |
| List groups | `GET /api/v1/iam/groups` | ✅ | `0xBE` | `iam_list_groups`, `iam:read` | ✅ |
| Get group | `GET /api/v1/iam/groups/{id}` | ✅ | `0xBD` | `iam_get_group`, `iam:read` | ✅ |
| Update group | `PUT /api/v1/iam/groups/{id}` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| Delete group | `DELETE /api/v1/iam/groups/{id}` | ✅ | `0xBC` | `iam_delete_group`, `iam:delete` | ✅ |
| Add group member | `POST /api/v1/iam/groups/{id}/members/{user}` | ✅ | `0xBF` | `iam_add_group_member`, `iam:write` | ✅ |
| Remove group member | `DELETE /api/v1/iam/groups/{id}/members/{user}` | ✅ | `0xF6` | `iam_remove_group_member`, `iam:write` | ✅ |

**Group membership is present on every transport except the CLI**, where both
verbs are unimplemented stubs — see [cli.md](cli.md) §4.

## 5. Roles, policies and applications

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Role CRUD | `/api/v1/iam/roles`, `/roles/{id}` | ✅ | `0xB5` create, `0xB6` delete, `0xB7` get, `0xB8` list | `iam_create_role` `iam:write`, `iam_get_role` `iam:read`, `iam_list_roles` `iam:read`, `iam_delete_role` `iam:delete` | ✅ |
| Update role | `PUT /api/v1/iam/roles/{id}` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| Policy CRUD | `/api/v1/iam/policies`, `/policies/{id}` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| **Validate policy** | `POST /api/v1/iam/policies/validate` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| **Test policy** | `POST /api/v1/iam/policies/test` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| Application CRUD | `/api/v1/iam/apps`, `/apps/{id}` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |
| Rotate app secret | `POST /api/v1/iam/apps/{id}/rotate` | ✅ | `MISSING` | `MISSING — docs/13 G7` | ✅ |

**Policies and applications have no MCP tools and no QUIC opcodes.**
Twenty-five `iam_*` tools cover users, groups, roles, tenants, tokens and the
permission check — neither the authorization policies themselves nor OAuth
applications. QUIC has no IAM policy, application, role-update or
group-update byte; the SDK's QUIC transport cannot reach those RPCs.

`/policies/validate` and `/policies/test` are registered **before**
`/policies/{id}`, so `validate` and `test` are not swallowed as policy ids.

## 5a. QUIC IAM opcodes

Every IAM byte the daemon dispatches (`handleIAMOperation`,
`pkg/api/daemon/quic_iam.go`; `handleIAMCategory`,
`pkg/api/daemon/quic_iam_category.go`). The constants are in
`sdk/go/wire/quicwire/protocol.go` and `iam_opcodes.go`.

| Byte | Constant | Operation |
|---|---|---|
| `0xA9` | `OpIAMUserCreate` | Create user |
| `0xAA` | `OpIAMUserDelete` | Delete user |
| `0xAB` | `OpIAMUserGet` | Get user |
| `0xAC` | `OpIAMUserList` | List users |
| `0xAD` | `OpIAMUserUpdate` | Update user |
| `0xB5` | `OpIAMRoleCreate` | Create role |
| `0xB6` | `OpIAMRoleDelete` | Delete role |
| `0xB7` | `OpIAMRoleGet` | Get role |
| `0xB8` | `OpIAMRoleList` | List roles |
| `0xB9` | `OpIAMRoleAssign` | Assign role to user |
| `0xBA` | `OpIAMRoleRevoke` | Revoke role from user |
| `0xBB` | `OpIAMGroupCreate` | Create group |
| `0xBC` | `OpIAMGroupDelete` | Delete group |
| `0xBD` | `OpIAMGroupGet` | Get group |
| `0xBE` | `OpIAMGroupList` | List groups |
| `0xBF` | `OpIAMGroupAddMember` | Add group member |
| `0xF6` | `OpIAMGroupRemoveMember` | Remove group member |
| `0xF7` | `OpIAMCheckPermission` | Check permission |
| `0xF8` | `OpIAMAuthenticate` | Authenticate (daemon-native, not `IAMGRPCService`) |
| `0xF9` | `OpIAMTokenCreate` | Create token — refused, `StatusNotImplemented` |
| `0xFA` | `OpIAMTokenRevoke` | Revoke token — refused, `StatusNotImplemented` |
| `0xFB` | `OpIAMTokenVerify` | Verify token |
| `0x51` | `OpIAMCategory` | Tenant records; sub-opcode in `payload[0]`: `0x01` create, `0x02` get, `0x03` list, `0x04` update, `0x05` delete. `0x10`–`0x16` are `InvitationService` ([`docs/tenant/api.md`](../tenant/api.md) §10) |

The bytes between the IAM ranges belong to other services: `0xB0`–`0xB4` are
SDN and `0xF0`–`0xF5` are DEK operations.

## 6. Tenants, tokens and authentication

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create tenant (IAM scoping) | `POST /api/v1/iam/tenants` | ✅ | `0x51` sub `0x01` | `iam_create_tenant`, `iam:write` | ✅ |
| List / get / update / delete tenant | `/api/v1/iam/tenants[/{tenant}]` | ✅ | `0x51` subs `0x03` / `0x02` / `0x04` / `0x05` | `iam_list_tenants` `iam:read`, `iam_get_tenant` `iam:read`, `iam_delete_tenant` `iam:delete`; update `MISSING` | ✅ |
| Authenticate | `MISSING — docs/13 G7` | `MISSING` — no RPC | `0xF8`, daemon-native | `iam_authenticate`, open, refused, `Unimplemented` | ✅ |
| Create token | refused by the SDK: `ErrNoRESTRoute` | refused, `Unimplemented` | `0xF9`, refused, `StatusNotImplemented` | `iam_create_token`, `iam:write`, refused | refused |
| Verify token | refused by the SDK: `ErrNoRESTRoute` | ✅ | `0xFB` | `iam_verify_token`, `iam:read` | ✅ |
| Revoke token | refused by the SDK: `ErrNoRESTRoute` | refused, `Unimplemented` | `0xFA`, refused, `StatusNotImplemented` | `iam_revoke_token`, `iam:write`, refused | refused |
| Check permission | `POST /api/v1/iam/permissions/check`, `/tenants/{tenant}/permissions/check` | ✅ | `0xF7` | `iam_check_permission`, `iam:read` | ✅ |

**`iam_authenticate` is refused** with `ErrIAMAuthenticationViaOIDC`
(`Unimplemented`): `PlatformIAMService` has no Authenticate RPC and the IAM
service holds no credentials to check. Users sign in through the broker's OIDC
flows, which issue the platform token.

**Token issuance, verification and revocation have no REST route** under
`/api/v1/iam`. Login and refresh are served by a separate authentication
router (`pkg/webservice/v1/router/authentication.go` — `login`, `refreshToken`),
and WebAuthn by `pkg/webservice/v1/router/webauthn.go`. Create and revoke token
are OIDC flows, refused on every transport (below); verify token is served on
gRPC, QUIC, MCP and the embedded transport, not REST. The Go SDK's REST
transport refuses the three methods before any request is sent, returning
`ErrNoRESTRoute`, whose gRPC status is `Unimplemented` (`restRefusedMethods`,
`sdk/go/transport/rest/iam.go`).

**Check permission asks the policy enforcement point for a live decision.** The
body carries `subject_id`, `action` and `resource`, all required, and optional
`roles`, `groups`, `context` and `attributes`. The subject is checked within the
tenant the route acts on. A deny is a `200` with `allowed: false`, not an error.
A body `tenant_id` naming another tenant gets `403`. A missing field gets `400`.
A daemon with no PEP wired gets `503`. Through the Go SDK the same refusals
surface as `PermissionDenied`, `InvalidArgument` and `Unavailable`.

**Verify token checks the token for real, through one service function.**
gRPC (TCP and Unix), QUIC, MCP and the embedded transport all call
`IAMTokenService.Verify` (`pkg/api/daemon/iam_token_service.go`). It uses the
validator the daemon authenticates requests with: the broker platform-token
validator when platform tokens are enabled (signature against the issuer JWKS,
issuer, audience, expiry, and revocation through the liveness authority in
online and hybrid authz modes), otherwise the local gRPC/QUIC validator
(platform JWT verifiers, then QuicBaaS).

- A valid token answers `valid: true` with `user_id`, `tenant_id`, `scopes`
  and `expires_at`.
- A rejected token answers `valid: false` with `reason`: `malformed`,
  `expired`, `bad_signature`, `revoked`, `wrong_issuer`, `wrong_audience`, or
  `rejected` when the legacy QuicBaaS validator gives no finer class.
- A blank token is `ErrIAMMissingParameter` (`InvalidArgument`). A daemon
  with no validator wired is `ErrIAMTokenVerifierNotConfigured`
  (`Unavailable`), and so is an unreachable validator or liveness authority.
  None of these answers valid.
- The token is never echoed in the answer and never logged.

**Create token and revoke token are refused on every transport** with
`ErrIAMTokenViaOIDC` ("iam token create/revoke is handled via OIDC flows, not
the IAM service"): `Unimplemented` on gRPC, `StatusNotImplemented` on QUIC,
the same error from the MCP tools and the embedded transport. The SDK IAM
client has no token issue or revoke operation; platform tokens are issued and
revoked by the broker's OIDC flows. Nothing reports a token created or
revoked.

gRPC, QUIC, embedded and MCP IAM calls other than verify token are served by
`IAMGRPCService` (`pkg/api/daemon/iam_grpc_service.go`), which exists only when
the daemon has a QuicBaaS IAM service. The daemon builds that service's IAM and
PEP clients once and hands the same two to the gRPC service, the MCP service
provider (`createMCPServer`, `pkg/api/daemon/daemon.go`) and the MCP auth
adapter. Without a QuicBaaS IAM service — a build without the `iam` tag, a
daemon run with `SkipIAMValidation` or without an application, or an IAM
service that failed to start — every such call answers
`ErrIAMServiceNotAvailable` (`FailedPrecondition` on gRPC and MCP,
`StatusUnavailable` on QUIC), while `iam_verify_token` still verifies.

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

**The daemon listener serves the tenant-scoped IAM routes (#949).**
`SetIAMHandlers` (`pkg/api/daemon/rest_service.go`) mounts
`/api/v1/iam/tenants` and `/api/v1/iam/tenants/{tenant}/...` on the daemon's
REST listener, over the SDK IAM client and PEP the other transports use. There
the guards are `IAMRouteGuards` (`pkg/api/rest/iam_guard.go`) over the daemon's
scope guard: a bearer token or mTLS peer, `iam:read` for reads and the
read-only checks, `iam:write` for the rest, `401` without a caller and `403`
without the scope or for another tenant. The flat aliases of §2 are not
mounted there, since they fall back to a browser session's tenant; a flat
claim is recorded as divergent under #452 in the daemon's route-claims test.

| Daemon REST route | Scope | Caller |
|---|---|---|
| `GET /api/v1/iam/tenants`, `GET /api/v1/iam/tenants/{tenant}` | `iam:read` | system tenant |
| `POST`, `PUT`, `DELETE /api/v1/iam/tenants[/{tenant}]` | `iam:write` | system tenant |
| `GET /api/v1/iam/tenants/{tenant}/{users,groups,roles,policies,apps}[/...]` | `iam:read` | `{tenant}` |
| `POST /api/v1/iam/tenants/{tenant}/{permissions/check,policies/validate,policies/test}` | `iam:read` | `{tenant}` |
| every other `/api/v1/iam/tenants/{tenant}/...` write | `iam:write` | `{tenant}` |

That gate is REST-only; the gRPC, QUIC and MCP pictures follow.

**The tenant binding is on every transport (#401).** A tenant-bound caller is
served only from its own tenant:

| Transport | Caller's tenant | Request names another tenant | Request names no tenant |
|---|---|---|---|
| REST | the session — token `tenant_id` claim, or the mTLS certificate | `403` from `RequireOwnTenant`, on `/tenants/{tenant}/...` and on an unscoped route's `?tenant_id=`; `403` `ErrConflictingQueryTenant` for a `?tenant_id=` on `/tenants/{tenant}/...` that differs from the path; `403` `ErrForeignBodyTenant` from the handler for a body `tenant_id` / `tenantId` | unscoped routes use the session tenant |
| gRPC, QUIC | the platform token's `tenant_id` claim, or the mTLS certificate | `PermissionDenied`, `ErrIAMTenantForbidden` | `InvalidArgument`, `tenant_id` is required |
| Unix | none — peer-credential operator | served (the operator is not tenant-bound) | `InvalidArgument` |
| MCP | the token's `tenant_id` claim, from the MCP authorized context | `PermissionDenied`, `ErrIAMTenantForbidden` | `InvalidArgument`, `tenant_id` is required |

These tenant checks, and the unbound Unix peer-credential operator, are the
platform's own; the IAM clean-up rows in [SPEC.md §Interfaces](../SPEC.md#interfaces)
move them to go-qrdb, and `RequireOwnTenant` stays until go-qrdb #683 lands.

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

On gRPC, QUIC and MCP the check is `authorizeIAMTenant`
(`pkg/api/daemon/iam_tenant_authz.go`); MCP reaches it because its IAM tools
answer through the same `IAMGRPCService` methods. It covers every user, role,
group, policy and application RPC, `CheckPermission`, and `GetTenant`,
`UpdateTenant` and `DeleteTenant`. `CreateTenant` and `ListTenants` act
across tenants, so they admit the system tenant only, the rule REST applies
with `RequireSystemTenant`: `authorizeSystemCaller` (same file) refuses any
other tenant-bound caller with `PermissionDenied` (`ErrTenantSystemOnly`), and
the unbound Unix operator is admitted. The daemon hands the service its
system tenant with `SetSystemTenant`; without one, no tenant-bound caller is
admitted. The token RPCs carry no tenant check. The platform `TenantService` lifecycle RPCs have their own binding,
`authorizeTenant` (`pkg/api/daemon/tenant_grpc_authz.go`,
[`docs/tenant/api.md`](../tenant/api.md) §7). A daemon run with `SkipIAMValidation`
has no caller identity and serves the named tenant.

Both read the caller's tenant through `callerTenant`, which also reads the
validated MCP token (#304), so a tool that reaches these services binds its
caller as gRPC does.

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

**Twenty-two of the 25 `iam_*` MCP tools are in the MCP authorization map
(#304)**, each with the `resource:action` of the `PlatformIAMService` method
it answers through (`pkg/api/grpc/method_permissions.go`;
`toolPermissionCatalog`, `pkg/api/mcp/authz.go`):

| Scope | Tools |
|---|---|
| `iam:write` | `iam_create_user`, `iam_create_role`, `iam_assign_role`, `iam_revoke_role`, `iam_create_group`, `iam_add_group_member`, `iam_remove_group_member`, `iam_create_tenant` |
| `iam:delete` | `iam_delete_user`, `iam_delete_role`, `iam_delete_group`, `iam_delete_tenant` |
| `iam:read` | `iam_get_user`, `iam_list_users`, `iam_get_role`, `iam_list_roles`, `iam_get_group`, `iam_list_groups`, `iam_get_tenant`, `iam_list_tenants`, `iam_check_permission`, `iam_verify_token` |

A caller without the tool's scope is denied before the tool runs. Each tool
gives the result and error class of its gRPC method: the tool calls that
method (`iam_verify_token` calls `IAMTokenService.Verify`, as gRPC does), and `IAMGRPCService` maps an SDK error by category (invalid input to
`InvalidArgument`, not found to `NotFound`, and so on) rather than to
`Internal`.

Since #300 `AuthorizeTool` **denies** a tool absent from the map
(`AuthErrorToolNotClassified`, `-32603` on the wire) rather than allowing it.
Every one of the 487 registered tools is in the map: 475 carry a
`resource:action` permission and 12 are classified open (`""`) (measured from
`NewToolRegistry(...).ListTools()` against `toolPermissionCatalog`;
`TestEveryRegisteredToolIsClassified` fails if a registered tool has no entry).
Since #304 the classified tools include 32 VM and container tools
([`docs/compute/api.md`](../compute/api.md) §7). `iam_create_token` and
`iam_revoke_token` carry `iam:write`, the scope of gRPC `CreateToken` and
`RevokeToken`; like their twins they refuse every caller (§6).
`iam_authenticate` is open: it is the credential exchange that would issue a
token, so it cannot require one, and QUIC lists its twin `0xF8` in
`preAuthOpcodes` for the same reason. It too refuses (§6). The escalation this
section once described — any valid token minting credentials through
`iam_create_token` — was closed by #300, and since #304 that tool no longer
pretends to mint anything (#412).

`iam_create_tenant` and `iam_list_tenants` are not tenant-bound (above): an
`iam:write` or `iam:read` caller of any tenant can create or list tenant
records over MCP, as over gRPC and QUIC.

The platform tenant tools (`tenant_*`, `platform_tenant_barrier_*`) are
classified, with the tenant binding behind them
([`docs/tenant/api.md`](../tenant/api.md) §7).

**The TPM and vTPM tools are #304's first tranche.** Each classified tool
carries the scope of its gRPC method, and its errors carry the same gRPC class
(`mapTPMError`, `mapVTPMError` in `pkg/api/daemon/`):

| Tools | Scope |
|---|---|
| `platform_tpm_{info,ek,ek_cert,srk,iak,pcrs,eventlog,random,nv_read,make_credential}` | `tpm:read` |
| `platform_tpm_{provision,ek_create,ek_import_cert,srk_create,iak_create,nv_write,activate_credential,seal}` | `tpm:write` |
| `platform_tpm_unseal` | `tpm:write` — stricter than gRPC `Unseal` (`tpm:read`): an unseal tool never takes a read scope on MCP |
| `platform_tpm_{clear,nv_delete,ek_delete,srk_delete,iak_delete}` | `tpm:delete` |
| `vtpm_{get,validate,export,get_bundle_path,get_tpm_socket_path,get_nvram_path,is_running}`, `vtpm_template_{get,list}` | `vtpm:read` |
| `vtpm_import`, `vtpm_template_{create,clone}` | `vtpm:write` |
| `vtpm_template_delete` | `vtpm:delete` |
| `vtpm_bundle_{create,get,list,delete,quote,pcr_read,pcr_extend,seal,unseal}` | the scope of the `vtpm_*` twin each one runs ([`docs/vtpm/api.md`](../vtpm/api.md) §5) |

`platform_tpm_{capabilities,platform,nv_list,certify}` (`tpm:read`) and
`platform_tpm_pcr_extend` (`tpm:write`) take their QUIC or gRPC twin's scope;
[`docs/tpm/api-reference-mcp.md`](../tpm/api-reference-mcp.md) is the full
list. `platform_tpm_ek_delete` and `platform_tpm_srk_delete` flush a persistent
handle, which deletes nothing, as gRPC `DeleteEK`/`DeleteSRK` do.
`platform_tpm_iak_delete` refuses with `FailedPrecondition`, as `iak_delete`
and gRPC `DeleteAK` do (#704).

**The KMS and secret MCP tools are classified (#304).** Each of the 20 `kms_*`
and 6 `secret_*` tools carries the scope of the gRPC method it mirrors
(`pkg/api/grpc/method_permissions.go`), so it answers a caller holding that
scope and refuses everyone else with `PermissionDenied` before the handler
runs:

| Scope | MCP tools |
|---|---|
| `kms:read` | `kms_get_key`, `kms_list_keys`, `kms_export_public_key`, `kms_get_key_metadata`, `kms_get_key_policy`, `kms_supported_algorithms`, `kms_backend_status`, `kms_decrypt`, `kms_verify`, `kms_random` |
| `kms:write` | `kms_generate_key`, `kms_rotate_key`, `kms_revoke_key`, `kms_update_key_metadata`, `kms_set_key_policy`, `kms_encrypt`, `kms_sign`, `kms_generate_data_key`, `kms_generate_wrapped_data_key` |
| `kms:delete` | `kms_delete_key` |
| `secrets:read` | `secret_get`, `secret_get_rotation_policy` |
| `secrets:write` | `secret_store`, `secret_set_rotation_policy` |
| `secrets:list` | `secret_list` |
| `secrets:delete` | `secret_delete` |

`kms_decrypt`, `kms_generate_data_key` and `secret_get` answer key or secret
material, so they reach only a holder of their scope; no handler logs it. The
`kms:*` and `secrets:*` scopes are advertised in the MCP OAuth metadata, which
lists the scopes the authorization map consults.

#304's attestation tranche classified the five manifest tools with their gRPC
methods' scopes: `attestation_get_manifest`, `attestation_list_manifests` and
`attestation_verify_manifest` need `attestation:read`,
`attestation_create_manifest` needs `attestation:write`, and
`attestation_delete_manifest` needs `attestation:delete`. The ten other
attestation tools had no backend and were deleted
([`docs/attestation/api.md`](../attestation/api.md) §5). #704 bound five
more to `AttestationService`, each with its gRPC method's scope:
`attestation_get_quote` and `attestation_verify_quote` need `attestation:read`;
`attestation_collect_host`, `attestation_collect_vm` and
`attestation_collect_container` need `attestation:write`.

**#304 DNS tranche: the DNS tools bound to `DNSService` require their gRPC
method's scope.** Each tool calls the gRPC servicer over the daemon's DNS
service (`dnsTools`, `pkg/api/mcp/dns_tools.go`), so it answers and fails as
gRPC does; [`docs/dns/api.md`](../dns/api.md) §3 has the detail.

| MCP tool | gRPC method | Scope |
|---|---|---|
| `dns_zone_create` | `CreateZone` | `dns:write` |
| `dns_zone_get` | `GetZone` | `dns:read` |
| `dns_zone_list` | `ListZones` | `dns:read` |
| `dns_zone_update` | `UpdateZone` | `dns:write` |
| `dns_zone_delete` | `DeleteZone` | `dns:delete` |
| `dns_record_create` | `AddRecord` | `dns:write` |
| `dns_record_get` | none; served from `ListRecords` | `dns:read` |
| `dns_record_list` | `ListRecords` | `dns:read` |
| `dns_record_update` | `UpdateRecord` | `dns:write` |
| `dns_record_delete` | `DeleteRecord` | `dns:delete` |
| `dns_lookup` | `Resolve` | `dns:read` |
| `dns_zone_sign` | `SignZone` | `dns:write` |
| `dns_zone_dnssec_status` | `GetDNSSECStatus` | `dns:read` |
| `dns_register` | `Register` | `dns:write` |

`DNSService` carries no caller tenant on gRPC: the DNS service acts in the
tenant the daemon configured it with, and a zone of another tenant is
`NotFound`. The MCP tools inherit exactly that; they add no tenant binding of
their own.

**EAB tools answer under the scope of their gRPC twin (#304).** The eleven
`platform_eab_*` tools are classified in `toolPermissionCatalog`
(`pkg/api/mcp/authz.go`) with exactly the pair `EABService` carries in
`pkg/api/grpc/method_permissions.go`; a caller without it gets
`AuthErrorPermissionDenied` and the tool never runs.

| Scope | MCP tool | gRPC method |
|---|---|---|
| `eab:write` | `platform_eab_create_credential` | `CreateCredential` |
| `eab:write` | `platform_eab_revoke_credential` | `RevokeCredential` |
| `eab:write` | `platform_eab_mark_credential_used` | `MarkCredentialUsed` |
| `eab:write` | `platform_eab_cleanup_expired_credentials` | `CleanupExpiredCredentials` |
| `eab:read` | `platform_eab_get_credential` | `GetCredential` |
| `eab:read` | `platform_eab_get_credential_by_key_id` | `GetCredentialByKeyID` |
| `eab:read` | `platform_eab_list_credentials` | `ListCredentials` |
| `eab:read` | `platform_eab_validate_credential` | `ValidateCredential` |
| `eab:read` | `platform_eab_get_credential_qr_code` | `GetCredentialQRCode` |
| `eab:read` | `platform_eab_get_enrollment_url` | `GetEnrollmentURL` |
| `eab:delete` | `platform_eab_delete_credential` | `DeleteCredential` |

EAB carries no caller-tenant binding on any transport: gRPC and MCP serve the
`tenant_id` the request names, so `eab:*` is store-wide. Details:
[`docs/eab/api.md` §5](../eab/api.md).

**SDN tranche of #304: eleven SDN tools carry their gRPC scope.** Each has the
`resource:action` of its `SDNService` twin in
`pkg/api/grpc/method_permissions.go`, beside the bridge, port, port-state and
policy tools that already had one:

| MCP tool | Scope | gRPC twin |
|---|---|---|
| `sdn_add_flow` | `sdn:write` | `AddFlow` |
| `sdn_delete_flow` | `sdn:delete` | `DeleteFlow` |
| `sdn_flush_flows` | `sdn:write` | `FlushFlows` |
| `sdn_list_flows` | `sdn:read` | `ListFlows` |
| `sdn_get_flow_stats` | `sdn:read` | `GetFlowStats` |
| `sdn_create_vlan` | `sdn:write` | `CreateVLAN` |
| `sdn_delete_vlan` | `sdn:delete` | `DeleteVLAN` |
| `sdn_list_vlans` | `sdn:read` | `ListVLANs` |
| `sdn_get_port_stats` | `sdn:read` | `GetPortStats` |
| `sdn_authenticate_port` | `sdn:write` | `AuthenticatePort` |
| `sdn_revoke_port_auth` | `sdn:write` | `RevokePortAuth` |

`FlushFlows` takes `sdn:write`, not the `delete` the verb rule would give it:
where gRPC and the verb rule differ, gRPC wins. `sdn_authenticate_port` and
`sdn_revoke_port_auth` were classified by #304. A caller holding
`sdn:write` gets the refusal gRPC gives: both tools, like the service, return
`policy.ErrPortAuthNotEnforced` (`FailedPrecondition`), because nothing
enforces port authentication on the switch
([`docs/sdn/api.md`](../sdn/api.md) §4). A caller without the scope is denied
first. SDN
objects carry no tenant on gRPC or MCP, so the scope is the whole check.

**LUKS tools carry their gRPC scopes (#304).** All ten `platform_luks_*`
tools are in the MCP authorization map, each with the scope its `LUKSService`
method carries (`pkg/api/grpc/method_permissions.go`):

| MCP tool | Scope |
|---|---|
| `platform_luks_status`, `platform_luks_list_slots`, `platform_luks_info`, `platform_luks_test_unlock` | `luks:read` |
| `platform_luks_enroll_passphrase`, `platform_luks_enroll_fido2`, `platform_luks_enroll_tpm`, `platform_luks_enroll_recovery`, `platform_luks_change_passphrase` | `luks:write` |
| `platform_luks_remove_key` | `luks:delete` |

`platform_luks_test_unlock` takes `luks:read` from gRPC `TestUnlock` and
answers as gRPC does: whether the keyslot exists, with no key tried
([`docs/luks/api.md`](../luks/api.md) §5). LUKS carries no tenant on any
transport.

**The IDevID and IAK tools are #304's device-identity tranche.** All 17 are
served by the daemon's shared `IDevIDGRPCService`, so each answers with its
gRPC method's message and error class, under that method's scope from
`pkg/api/grpc/method_permissions.go`. The IAK tools take the `idevid` resource,
as their gRPC methods do:

| Tools | Scope |
|---|---|
| `idevid_{info,exists,get_cert}`, `iak_{info,exists,get_cert}` | `idevid:read` |
| `idevid_{generate,csr,install_cert,create_ldevid}`, `iak_{generate,csr,install_cert}` | `idevid:write` |
| `idevid_{delete,delete_cert}`, `iak_{delete,delete_cert}` | `idevid:delete` |

`idevid_delete` and `iak_delete` refuse with `FailedPrecondition`
(`ErrDeviceIdentityKeyNotDeletable`) and change nothing. Before #304 they, and
gRPC `DeleteIDevID`/`DeleteIAK`, reported a deletion while the key stayed in the
TPM. `*_delete_cert` removes the certificate. Device identities belong to the
node's TPM and carry no tenant on any transport. `device_attributes` takes
`idevid:read` and `activate_credential` takes `idevid:write`, the scopes of
gRPC `GetDeviceAttributes` and `ActivateCredential`, whose TPM calls they make.

**The switch, cluster and registry MCP tools are classified (#304).** Each
carries the scope of its gRPC twin in `SwitchService`, `ClusterService` and
`RegistryService` (`pkg/api/grpc/method_permissions.go`); a caller without it
gets `PermissionDenied` (`-32003`) and the tool never runs:

| MCP tool | Scope | gRPC twin |
|---|---|---|
| `switch_list_ports` | `switch:read` | `ListPorts` |
| `switch_port_status` | `switch:read` | `GetPortStatus` |
| `switch_enable_port` | `switch:write` | `EnablePort` |
| `switch_disable_port` | `switch:write` | `DisablePort` |
| `switch_set_vlan` | `switch:write` | `SetPortVLAN` |
| `platform_cluster_status` | `cluster:read` | `GetStatus` |
| `platform_cluster_list_nodes` | `cluster:read` | `ListNodes` |
| `platform_cluster_bootstrap` | `cluster:write` | `Bootstrap` |
| `platform_cluster_join` | `cluster:write` | `Join` |
| `platform_cluster_leave` | `cluster:write` | `Leave` |
| `platform_registry_status` | `registry:read` | `Status` |
| `platform_registry_list` | `registry:read` | `List` |
| `platform_registry_inspect` | `registry:read` | `Inspect` |
| `platform_registry_delete` | `registry:delete` | `Delete` |

None of the three is tenant-scoped on any transport: switch ports, cluster
nodes and registry artifacts are platform-level, and the gRPC services carry
no tenant either.

**Each daemon and provisioning operation needs one permission on gRPC, QUIC
and MCP (#304, #317).** The daemon tools and opcodes read the same
`daemon.Service` the gRPC `PlatformDaemon` serves; the provisioning tools and
sub-opcodes call the same `configdelivery.Service` as gRPC
`ConfigDeliveryService`, and their errors carry its gRPC class. Each scope is
the one in `pkg/api/grpc/method_permissions.go`, and
`TestDaemonProvisionScopeParity` (`pkg/api/mcp/daemon_provision_parity_test.go`)
fails if the three catalogs drift apart:

| Operation | Scope | gRPC | QUIC | MCP tool |
|---|---|---|---|---|
| Status | `platform:read` | `GetStatus` | `0x89` | `platform_daemon_status` |
| Version | `platform:read` | `GetVersion` | `0x8A` | `platform_daemon_version` |
| List services | `platform:read` | `ListServices` | `0x8B` | `platform_daemon_list_services` |
| Get service | `platform:read` | `GetServiceStatus` | `0x8C` | `platform_daemon_get_service` |
| Start / stop / restart service | `platform:write` | `StartService`, `StopService`, `RestartService` | `0x8D`-`0x8F` | `platform_daemon_{start,stop,restart}_service` |
| List protocols | `platform:read` | none | `0x98` | `platform_daemon_list_protocols` |
| List / get sessions | `provisioning:read` | `ListSessions`, `GetSession` | `0xCF` `0x06`, `0x07` | `provision_list_sessions`, `provision_get_session` |
| Fulfill session | `provisioning:write` | `FulfillSession` | `0xCF` `0x05` | `provision_fulfill_session` |
| Get nonce | open | `GetNonce` | `0xCF` `0x01` | `provision_get_nonce` |
| Fetch config | open | `FetchConfig` | `0xCF` `0x02` | `provision_fetch_config` |
| Sign digest | open | `SignDigest` | `0xCF` `0x03` | `provision_sign_digest` |
| Poll session | open | `PollSession` | `0xCF` `0x04` | `provision_poll_session` |

The four device-side provisioning operations are open on every transport: the
device holds no platform token, and `configdelivery.Service` checks its proof
itself (the EAB HMAC, the single-use nonce and the EK binding; the random
session ID is the poll capability). QUIC serves them through its existing
pre-auth sub-opcode list (`preAuthSubOpcodes`), the one the diskless boot
sub-opcodes use. The lifecycle tools reach the same `StartService`,
`StopService` and `RestartService` as gRPC, which refuse every configured
service with `FailedPrecondition` (#317, [`docs/daemon/api.md`](../daemon/api.md)
§2). List protocols has no gRPC twin; QUIC files it
under `platform:read` with the other daemon reads, and its REST route is gated
on the admin role, which carries no scope. Provisioning sessions record a
tenant, but gRPC does not bind the caller to it, so neither does QUIC nor MCP:
`provisioning:read` lists every tenant's sessions. The admin-role REST gate and
the platform-declared `provisioning:*` permissions are departures that the IAM
clean-up rows in [SPEC.md §Interfaces](../SPEC.md#interfaces) move to go-qrdb.

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
