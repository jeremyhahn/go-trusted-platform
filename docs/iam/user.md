# IAM — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Managing users, roles, policies and OAuth applications. Internals are
> in [engineering.md](engineering.md).

---

## What this is

The platform's identity surface: users, roles, authorization policies and
OAuth applications, all scoped by tenant. There are no groups — go-quicbaas
removed them; grant access through roles.

**The platform does not implement IAM.** It re-exports the stack's — go-qrdb
owns the identity model and the single RBAC decision point, go-quicbaas composes
IAM/OIDC. The REST package's own documentation calls itself *"a protocol adapter
that translates REST requests to gRPC calls against the underlying QuicBaaS IAM
service"*.

---

## The word "tenant" means two different things

This is the thing to get straight first.

| | `platformctl tenant` / `POST /api/v1/tenants` | `POST /api/v1/iam/tenants` |
|---|---|---|
| Creates | A **platform tenant**: a VLAN, a bridge, a keyspace and a DEK, plus a quota | An **IAM scope** for users, roles, policies and apps |
| Feature | [`docs/tenant/`](../tenant/) | this one |

They are not the same operation and creating one does not create the other. If
you want network and storage isolation, you want the platform tenant.

---

## Everything is tenant-explicit at the CLI

```bash
platformctl iam user list --tenant tenant-a
platformctl iam user get  tenant-a u-0f21
```

`create`, `update` and `list` take `--tenant`; `get`, `delete` and the role verbs
take the tenant as a **positional argument**. That is deliberate — the REST
surface has unscoped routes whose tenant comes from context, and the CLI does
not let you be vague.

---

## Users

```bash
platformctl iam user create --tenant tenant-a \
    --email ops@example.com --name "Ops" \
    --roles operator \
    --attributes department=infra,region=eu

platformctl iam user get    tenant-a u-0f21
platformctl iam user list   --tenant tenant-a
platformctl iam user delete tenant-a u-0f21
```

**`update` replaces; it does not merge.** `--roles` and `--attributes` each
overwrite the whole list. This will bite:

```bash
# WRONG if the user already had other roles - this removes them
platformctl iam user update --tenant tenant-a --user-id u-0f21 --roles admin

# RIGHT for adding a role
platformctl iam user assign-role tenant-a u-0f21 admin
```

Use `assign-role` and `revoke-role` for incremental changes. Use `update
--roles` only when you mean "these and no others".

---

## Policies — validate and test before you apply

```bash
platformctl iam policy validate --tenant tenant-a ...
platformctl iam policy test     --tenant tenant-a ...
platformctl iam policy create   --tenant tenant-a ...
```

`validate` checks the policy document is well formed. `test` evaluates it
against a concrete request and reports what it would decide.

**Use both.** An authorization policy applied without testing is how an
administrator locks themselves out of the platform they administer, and the
recovery path from that is not pleasant.

Note that a `validate` call reporting an invalid policy is a **successful
request with a negative result**, not an error — the operation worked and the
answer was no.

---

## OAuth applications

```bash
platformctl iam app register --tenant tenant-a --name "Ops Console" \
    --redirect-uris https://console.example.com/callback

platformctl iam app list --tenant tenant-a
platformctl iam app rotate-secret tenant-a c-9a3f
```

`--grant-types` defaults to `authorization_code` and `--response-types` to
`code`. Those are the safe modern defaults; widening them — implicit flow,
password grant — is a decision, not a convenience.

**There is no way to read an application's secret.** `rotate-secret` is the only
way to obtain one, and it invalidates the previous value. That is deliberate:
a secret that can be read repeatedly is a secret that gets copied.

---

## Where users come from

Users can be created directly, or arrive through **WebAuthn registration**. A
WebAuthn-registered user is **mirrored** into the stack's IAM tenant so
`/api/v1/iam/users` shows them.

That mirror is a synchronisation point. If a user exists in one surface and not
the other — registered successfully but absent from `iam user list` — the mirror
is the first thing to check.

For a new registration (the user who creates the tenant), the mirror is not
optional. If the IAM tenant cannot take the user, the registration fails, and
nothing is left behind to clean up: no platform user and no tenant. The user
can retry once IAM is reachable.

Users registered while the mirror was failing are repaired when the daemon
starts: it mirrors every platform user missing from its IAM tenant, in the
background. The log line `IAM user reconcile finished` reports how many users
were scanned, already present, mirrored and failed; each failure has its own
`IAM reconcile failed to mirror user` line with the `user_id`. Restarting the
daemon retries the failures and leaves everyone else alone.

---

## Troubleshooting

**A user's roles disappeared after an update.**
`update --roles` replaces the list. Use `assign-role` to add.

**A user registered but does not appear in `iam user list`.**
The WebAuthn mirror. The mirror and the REST IAM router must be given the same
IAM client, or the two surfaces diverge. A daemon restart runs the startup
reconcile, which mirrors the missing user; if it does not, its
`IAM reconcile failed to mirror user` log line names the user and the cause.

**Registration fails with "failed to mirror user ... into IAM tenant".**
The IAM tenant refused the new owner, and the registration was rolled back. The
daemon log line `failed to mirror new owner into IAM tenant` carries the cause.
An `iam.role: not_found` cause means the tenant is missing its default roles,
which every new tenant is now given at creation.

**A REST call operated on the wrong tenant.**
The unscoped routes (`/api/v1/iam/users` and friends) get their tenant from
context, the token or a default — it is not in the path. Use
`/api/v1/iam/tenants/{tenant}/users` instead.

**You created a "tenant" and it has no VLAN or DEK.**
You created an IAM scope, not a platform tenant. See the top of this document.

**Everything returns 503.**
IAM is not wired into the daemon — the daemon is running its IAM stub.

**A policy behaves differently from what you expected.**
Run `iam policy test` against the exact request. Do not reason about it from the
document.

---

## One thing to be aware of

Every `PlatformIAMService` gRPC method requires an `iam` scope — 34 of them, the
largest entry in the scope catalog. **Each `iam_*` MCP tool requires the scope
of the gRPC method it answers through** (`iam:read`, `iam:write` or
`iam:delete`), and a caller bound to one tenant is served only from that
tenant, except for creating and listing tenant records. `iam_authenticate`, `iam_create_token` and `iam_revoke_token` are
refused for every caller ([api.md](api.md) §8).

Tokens are never issued or revoked through IAM. `iam_create_token` and
`iam_revoke_token`, and their gRPC and QUIC twins, refuse with "handled via
OIDC flows"; platform tokens come from the broker ([api.md](api.md) §6).

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — what this repository owns (very little)
- [`docs/tenant/`](../tenant/) — platform tenancy, the other meaning of "tenant"
- [`docs/auth/`](../auth/) — invitation flow and OAuth2 architecture
