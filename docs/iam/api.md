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

gRPC: `PlatformIAMService`, **34 RPCs** — the largest service in the platform
(`pkg/api/grpc/proto/iam.proto`).
REST: `/api/v1/iam`, in **two parallel trees** — see §2.
QUIC: 16 IAM opcodes (`sdk/go/wire/quicwire/protocol.go`) — users
`0xA9`–`0xAD`, roles `0xB5`–`0xBA`, and the extended range `0xF7`–`0xFB` —
plus tenant records under the `OpIAMCategory` (`0x51`) category
(`iam_opcodes.go`). The full byte map is §5a.
MCP: 19 `iam_*` tools; 15 answer through `IAMGRPCService`, `iam_verify_token`
through `IAMTokenService`, and 3 refuse (§8).

---

## 2. Every REST route exists twice

`pkg/webservice/v1/rest/iam/router.go` registers each capability under an
unscoped path **and** a tenant-scoped path, both dispatching to the same handler:

| Capability | Unscoped | Tenant-scoped |
|---|---|---|
| Users | `/api/v1/iam/users` | `/api/v1/iam/tenants/{tenant}/users` |
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
AssignRole, RevokeRole on users and roles — to the tenant-scoped form, so the request's `tenant_id` reaches the
guard exactly as it does on gRPC (#401). Update is the `PUT` on the item; the
SDK previously had no route for it and posted to an unserved
`/api/v1/platformiam/update*`. An empty `tenant_id` is refused with
`InvalidArgument` before anything is sent. The REST handlers answer a single
user, role or tenant as the bare resource; the SDK places it in the
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

## 4. Groups

**There are no IAM groups.** go-quicbaas v0.13 removed them, and every
transport followed: the group RPCs and their field numbers are `reserved` in
`iam.proto`, and QUIC opcodes `0xBB`–`0xBF` and `0xF6` stay reserved so an old
client gets "unknown opcode" rather than a different operation. Access is
granted through roles. `CheckPermission` / `TestPolicy` still accept a
subject's `groups`, because the SDK policy subject carries them for ABAC
conditions.

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
Nineteen `iam_*` tools cover users, roles, tenants, tokens and the permission
check — neither the authorization policies themselves nor OAuth applications.
QUIC has no IAM policy, application or role-update byte; the SDK's QUIC
transport cannot reach those RPCs.

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
| `0xF7` | `OpIAMCheckPermission` | Check permission |
| `0xF8` | `OpIAMAuthenticate` | Authenticate (daemon-native, not `IAMGRPCService`) |
| `0xF9` | `OpIAMTokenCreate` | Create token — refused, `StatusNotImplemented` |
| `0xFA` | `OpIAMTokenRevoke` | Revoke token — refused, `StatusNotImplemented` |
| `0xFB` | `OpIAMTokenVerify` | Verify token |
| `0x51` | `OpIAMCategory` | Tenant records; sub-opcode in `payload[0]`: `0x01` create, `0x02` get, `0x03` list, `0x04` update, `0x05` delete |

The bytes between the IAM ranges belong to other services: `0xB0`–`0xB4` are
SDN and `0xF0`–`0xF5` are DEK operations.

## 6. Tenants, tokens and authentication

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create tenant (IAM scoping) | `POST /api/v1/iam/tenants` | ✅ | `0x51` sub `0x01` | `iam_create_tenant`, `iam:write` | ✅ |
| List / get / update / delete tenant | `/api/v1/iam/tenants[/{tenant}]` | ✅ | `0x51` subs `0x03` / `0x02` / `0x04` / `0x05` | `iam_list_tenants` `iam:read`, `iam_get_tenant` `iam:read`, `iam_delete_tenant` `iam:delete`; update `MISSING` | ✅ |
| Authenticate | `MISSING — docs/13 G7` | `MISSING` — no RPC | `0xF8`, daemon-native | `iam_authenticate`, refused, `Unimplemented`, unclassified | ✅ |
| Create token | refused by the SDK: `ErrNoRESTRoute` | refused, `Unimplemented` | `0xF9`, refused, `StatusNotImplemented` | `iam_create_token`, refused, unclassified | refused |
| Verify token | refused by the SDK: `ErrNoRESTRoute` | ✅ | `0xFB` | `iam_verify_token`, `iam:read` | ✅ |
| Revoke token | refused by the SDK: `ErrNoRESTRoute` | refused, `Unimplemented` | `0xFA`, refused, `StatusNotImplemented` | `iam_revoke_token`, refused, unclassified | refused |
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
an IAM scoping boundary for users, roles and policies. The second
allocates a VLAN, a bridge, a keyspace and a DEK
([`docs/tenant/`](../tenant/)). Two routes, one word, two meanings — raised as an
owner question.

---

## 6. The WebAuthn user mirror

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

## 7. Authorization

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
| MCP | the token's `tenant_id` claim, from the MCP authorized context | `PermissionDenied`, `ErrIAMTenantForbidden` | `InvalidArgument`, `tenant_id` is required |

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
policy and application RPC, `CheckPermission`, and `GetTenant`,
`UpdateTenant` and `DeleteTenant`. It does not cover `CreateTenant`,
`ListTenants` or the token RPCs. The platform `TenantService` lifecycle RPCs have their own binding,
`authorizeTenant` (`pkg/api/daemon/tenant_grpc_authz.go`,
[`docs/tenant/api.md`](../tenant/api.md) §7). A daemon run with `SkipIAMValidation`
has no caller identity and serves the named tenant.

Both read the caller's tenant through `callerTenant`, which also reads the
validated MCP token (#304), so a tool that reaches these services binds its
caller as gRPC does.

Through the Go SDK's REST transport, an item operation reaches the scoped form
(§2). The `403` surfaces as `PermissionDenied` and a missing tenant as
`InvalidArgument`, the same codes gRPC returns.

**`PlatformIAMService` is in the gRPC scope catalog** with **34 methods
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

**Sixteen of the 19 `iam_*` MCP tools are in the MCP authorization map
(#304)**, each with the `resource:action` of the `PlatformIAMService` method
it answers through (`pkg/api/grpc/method_permissions.go`;
`toolPermissionCatalog`, `pkg/api/mcp/authz.go`):

| Scope | Tools |
|---|---|
| `iam:write` | `iam_create_user`, `iam_create_role`, `iam_assign_role`, `iam_revoke_role`, `iam_create_tenant` |
| `iam:delete` | `iam_delete_user`, `iam_delete_role`, `iam_delete_tenant` |
| `iam:read` | `iam_get_user`, `iam_list_users`, `iam_get_role`, `iam_list_roles`, `iam_get_tenant`, `iam_list_tenants`, `iam_check_permission`, `iam_verify_token` |

A caller without the tool's scope is denied before the tool runs. Each tool
gives the result and error class of its gRPC method: the tool calls that
method (`iam_verify_token` calls `IAMTokenService.Verify`, as gRPC does), and `IAMGRPCService` maps an SDK error by category (invalid input to
`InvalidArgument`, not found to `NotFound`, and so on) rather than to
`Internal`.

Since #300 `AuthorizeTool` **denies** a tool absent from the map
(`AuthErrorToolNotClassified`, `-32603` on the wire) rather than allowing it.
Of 469 registered tools, 435 carry a `resource:action` permission, 11 are
classified open (`""`), and the other 23 are absent from the map and refused
(measured from `NewToolRegistry(...).ListTools()` against
`toolPermissionCatalog`; the 23 are exactly `knownUnclassified`). Since #304
the classified tools include 29 VM and container tools ([`docs/compute/api.md`](../compute/api.md) §7). Three IAM tools stay out of it on purpose and are enumerated in
`knownUnclassified` (`pkg/api/mcp/authz_completeness_test.go`):
`iam_create_token`, `iam_revoke_token` and `iam_authenticate`. They refuse on
every transport (§6), and `iam_authenticate` has no gRPC method to take a
scope from, so no scope may unlock them. The escalation this section once
described — any valid token minting credentials through `iam_create_token` —
was closed by #300, and since #304 that tool no longer pretends to mint
anything (#412).

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
| `platform_tpm_{clear,nv_delete}` | `tpm:delete` |
| `vtpm_{get,validate,export,get_bundle_path,get_tpm_socket_path,get_nvram_path,is_running}`, `vtpm_template_{get,list}` | `vtpm:read` |
| `vtpm_import`, `vtpm_template_{create,clone}` | `vtpm:write` |
| `vtpm_template_delete` | `vtpm:delete` |
| `vtpm_bundle_{create,get,list,delete,quote,pcr_read,pcr_extend,seal,unseal}` | the scope of the `vtpm_*` twin each one runs ([`docs/vtpm/api.md`](../vtpm/api.md) §5) |

Still refused, with the reason:

- `platform_tpm_{ek,srk,iak}_delete` — they flush a persistent handle, which
  deletes nothing; gRPC `DeleteEK`/`DeleteSRK`/`DeleteAK` do the same. Making
  them evict is an owner decision, not a classification.
- `platform_tpm_{capabilities,platform,nv_list,pcr_extend,certify}` — no gRPC
  or REST twin to take a scope from.

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
attestation tools in `knownUnclassified` have no backend and stay refused
([`docs/attestation/api.md`](../attestation/api.md) §5).

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
| `dns_reverse_lookup` | none; no backend | unclassified, refused |

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
`sdn_revoke_port_auth` left `knownUnclassified` with #304. A caller holding
`sdn:write` gets the refusal gRPC gives: both tools, like the service, return
`policy.ErrPortAuthNotEnforced` (`FailedPrecondition`), because nothing
enforces port authentication on the switch
([`docs/sdn/api.md`](../sdn/api.md) §4). A caller without the scope is denied
first. SDN
objects carry no tenant on gRPC or MCP, so the scope is the whole check.

**LUKS tools carry their gRPC scopes (#304).** Nine of the ten
`platform_luks_*` tools are in the MCP authorization map, each with the scope
its `LUKSService` method carries (`pkg/api/grpc/method_permissions.go`):

| MCP tool | Scope |
|---|---|
| `platform_luks_status`, `platform_luks_list_slots`, `platform_luks_info` | `luks:read` |
| `platform_luks_enroll_passphrase`, `platform_luks_enroll_fido2`, `platform_luks_enroll_tpm`, `platform_luks_enroll_recovery`, `platform_luks_change_passphrase` | `luks:write` |
| `platform_luks_remove_key` | `luks:delete` |
| `platform_luks_test_unlock` | unclassified, refused |

`platform_luks_test_unlock` stays in `knownUnclassified`: it tries no key, so
its answer proves nothing ([`docs/luks/api.md`](../luks/api.md) §5). LUKS
carries no tenant on any transport.

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
| List protocols | `platform:read` | none | `0x98` | `platform_daemon_list_protocols`: unclassified, refused |
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
`provisioning:read` lists every tenant's sessions.

---

## 8. Status and error mapping

| QUIC byte | Name | REST | IAM cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed user, role or policy document |
| `0x02` | `StatusNotFound` | 404 | Unknown user, role, policy, app or tenant |
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

## 9. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The two
parallel tenant trees in §2 and the two meanings of "tenant" in §5 are
duplications awaiting an owner ruling.
