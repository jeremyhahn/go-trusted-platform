# IAM (re-export frontage) — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/webservice/v1/rest/iam/`, `pkg/api/daemon/iam_*`, `pkg/cli/commands/iam/`, `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. There is no `pkg/iam` in this repository

Verified 2026-08-18. Identity and access management belongs to the stack —
go-qrdb owns the identity model and the single RBAC decision point, go-quicbaas
composes IAM/OIDC — and this repository re-exports it as the platform product's
IAM surface (docs/00 L5).

`pkg/webservice/v1/rest/iam/doc.go` states the design in its own words: the
package *"serves as a protocol adapter that translates REST requests to gRPC
calls against the underlying QuicBaaS IAM service."*

What is local:

| Location | Role |
|---|---|
| `pkg/webservice/v1/rest/iam/` | REST adapter — `handlers.go`, `router.go`, `types.go`, `errors.go`, `adapter.go`, `adapter_helpers.go`, `mirror.go` |
| `pkg/api/daemon/iam_service.go`, `iam_grpc_service.go` | Service and gRPC wiring |
| `pkg/api/daemon/iam_service_stub.go` | The stub used when IAM is not wired |
| `pkg/api/daemon/iam_health_checker.go` | Health |
| `pkg/api/grpc/iam_service.go`, `iam_types.go` | gRPC `PlatformIAMService` |
| `pkg/api/quic/iam_handlers.go`, `pkg/api/daemon/quic_iam.go` | QUIC |
| `pkg/cli/commands/iam/` | CLI |
| `pkg/auth/` | **Not IAM** — `mtls.go`, `validator.go`, `interface.go`: transport-level authentication |

**`pkg/auth/` is authentication at the transport, not IAM.** mTLS and token
validation. Do not extend it into an authorization engine — the platform is a
broker-token *validator*, not a token-authorization decision point.

## 2. The user mirror — where two identity stores meet

`pkg/webservice/v1/rest/iam/mirror.go` defines `QuicBaaSUserMirror`, and its doc
comment is the clearest statement of a real structural fact:

> *"Used by the WebAuthn registration flow to mirror a newly-created platform
> user into the QuicBaaS IAM tenant so `/api/v1/iam/users` surfaces them."*

So a platform user created through WebAuthn registration is **copied** into the
stack's IAM tenant. That is a synchronisation point, and synchronisation points
drift:

- `NewQuicBaaSUserMirror(client IAMClient)` — its doc says *"Pass the same
  IAMClient the REST IAM router uses so both surfaces speak to the same tenant
  store."* If they are given different clients, the two surfaces diverge and
  nothing detects it.
- The `IAMUserMirror` interface lives in the **service** package while the
  implementation lives in the **REST** package, deliberately, so the service
  layer does not import the REST layer.

**A user that exists in one store and not the other is the failure mode to look
for** when "the user was created but does not appear in `/api/v1/iam/users`".

What keeps the two stores in step (#641; the why is in
[architecture.md](architecture.md) §"What keeps the mirror working"):

| Guarantee | Where | Typed error |
|---|---|---|
| A new IAM tenant carries the built-in roles the mirror names | `tenant.Manager.CreateTenant` → `EnsureDefaultRoles` → SDK `iam.RoleClient.Reconcile` (`pkg/tenant/manager.go`) | `tenant.ErrDefaultRolesFailed`; the IAM tenant is rolled back |
| A role named on a user (`admin`) is sent to the SDK as that role's ID, which the SDK requires | `restiam.ResolveRoleIDs` / `ResolveRoleID` (`pkg/webservice/v1/rest/iam/role_ids.go`), called by `CreateUser`, `AssignRole` and `RevokeRole` on `QuicBaaSIAMAdapter` (REST and the mirror) and on `IAMGRPCService` (CLI, Unix, gRPC, QUIC, MCP) | `restiam.ErrRoleNotFound` (gRPC `NotFound`, REST 404), `restiam.ErrRoleListFailed`, `restiam.ErrMissingRole`; nothing is written |
| `update --roles` replaces the user's roles (the SDK update carries none) | `restiam.SetUserRoles`, called before the field update by `IAMHandlers.UpdateUser` (through `QuicBaaSIAMAdapter.SetUserRoles`) and `IAMGRPCService.UpdateUser` | resolution errors as above, nothing written; `restiam.ErrUserRolesSyncFailed` for a failed assign or revoke, roles assigned first |
| A registered tenant owner is in the IAM tenant | `TenantUserService.RegisterNewUser` (`pkg/platform/service/tenant_user.go`) mirrors the owner with `iamMirrorRoles` (`admin`) | `service.ErrIAMMirrorFailed`; the platform user and the tenant are deleted |
| A platform user missing from its IAM tenant is mirrored once | `service.IAMUserReconciler.Reconcile` (`pkg/platform/service/iam_user_reconcile.go`), started in the background by `HandlerRegistry.startIAMUserReconcile` (`pkg/webservice/v1/registry.go`); membership is read through `QuicBaaSUserMirror.MirroredEmails` and compared by lower-cased email | `service.ErrIAMReconcileFailed` only when the platform user store cannot be read; per-user and per-tenant failures are logged with `user_id` and counted in `IAMUserReconcileReport.Failed` |

`tenant.NewManager` refuses a config without `IAMRoleClient`
(`ErrInvalidRequest`), so no wiring can create a tenant that cannot hold users.

## 3. Two tenant route trees

`pkg/webservice/v1/rest/iam/router.go` registers a **complete second copy** of
the user, group, role, policy and application surface under a tenant path:

```
/api/v1/iam/users                       /api/v1/iam/tenants/{tenant}/users
/api/v1/iam/groups                      /api/v1/iam/tenants/{tenant}/groups
/api/v1/iam/roles                       /api/v1/iam/tenants/{tenant}/roles
/api/v1/iam/policies                    /api/v1/iam/tenants/{tenant}/policies
/api/v1/iam/apps                        /api/v1/iam/tenants/{tenant}/apps
```

Both trees dispatch to the **same handler functions** (`r.handlers.CreateUser`
and so on). The tenant-scoped form carries the tenant in the path; the
unscoped form gets it from somewhere else — context, token, or a default.

**Which tenant an unscoped call operates on is not visible from the route.** For
anything multi-tenant, use the `/tenants/{tenant}/...` form so the target is
explicit.

Separately, `/api/v1/iam/tenants` **creates a tenant** — and that is not the
same operation as `POST /api/v1/tenants`, which allocates a VLAN, a bridge, a
keyspace and a DEK ([`docs/tenant/`](../tenant/)). Two routes, one word, two
meanings. Raised as an owner question.

## 4. Exported surface

- **gRPC** `PlatformIAMService` — **41 RPCs**, the largest service in the
  platform (`pkg/api/grpc/proto/iam.proto`).
- **REST** — the two trees above, ~44 routes.
- **QUIC** — user `0xA9`–`0xAD`, role `0xB5`–`0xBA`, group `0xBB`–`0xBF`,
  extended `0xF6`–`0xFB`.
- **MCP** — 25 `iam_*` tools.
- **CLI** — `platformctl iam` with `user`, `group`, `role`, `policy`, `app`.
- **SDK** — `sdk/go/services/iam`.

## 5. Two unimplemented CLI verbs

`pkg/cli/commands/iam/group*.go` marks two verbs "(not yet implemented)":

- `platformctl iam group add-member <tenant-id> <group-id> <user-id>`
- `platformctl iam group remove-member <tenant-id> <group-id> <user-id>`

**Group membership cannot be changed from the CLI.** The REST routes exist
(`POST`/`DELETE /api/v1/iam/groups/{id}/members/{user}` and the tenant-scoped
form), as do `iam_add_group_member` and `iam_remove_group_member` on MCP. Use
those.

Every other IAM CLI verb is implemented.

## 6. Invariants

1. **The platform validates tokens; it does not decide authorization.** RBAC
   decisions belong to go-qrdb through the stack. `pkg/auth` validates; it does
   not adjudicate.
2. **Policy validation is a separate operation from policy creation.**
   `ValidatePolicy` and `TestPolicy` exist as their own routes and CLI verbs so
   a policy can be checked before it is applied — and `TestPolicy` evaluates it
   against a concrete request.
3. **Application secrets are rotated, not read.** `RotateAppSecret` /
   `rotate-secret` exists; there is no "get secret".
4. **CLI verbs are tenant-explicit.** `iam user get <tenant-id> <user-id>` takes
   the tenant as a positional argument. That is the CLI making the ambiguity in
   §3 impossible.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/webservice/v1/rest/iam/*_test.go`, `pkg/api/daemon/iam_*_test.go`, `pkg/cli/commands/iam/*_test.go` | Adapter translation, route registration, handler behaviour |
| Integration | `test/integration/iam/` | Against a running daemon and a real IAM backend |

`iam_service_stub.go` is what the daemon uses when IAM is not wired — the
fixture that lets other subsystems be tested without an IAM backend.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`iam_health_checker.go` reports IAM health. Authentication and authorization
outcomes are audit events; **tokens, secrets and application client secrets must
never be logged**, and `rotate-secret` output in particular is a credential.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/tenant/`](../tenant/) — platform tenancy, which is a different thing
  from IAM's tenant scoping
- [`docs/ca/`](../ca/) · [`docs/kms/`](../kms/) — the other stack re-export
  frontages
- Deep dives carried over and not re-verified in this pass:
  [`docs/auth/`](../auth/) — invitation flow, OAuth2 architecture, quicbaas IAM
