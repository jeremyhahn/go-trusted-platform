# Security Primitives and Policy Engine — API

> **Status: NORMATIVE** · Scope: `pkg/security/`, `pkg/policy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. Nothing in this section is exposed on any transport

There is no `PolicyService` on gRPC, no `/api/v1/policy/*` or
`/api/v1/security/*` route group, no QUIC opcode category, and no MCP tool for
policy management, rate limiting or input validation. Verified 2026-08-18.

`pkg/policy/opa` is an **in-process library** consumed by
`pkg/sdn/gateway/proxysvc`. `pkg/security/ratelimit` and
`pkg/security/validation` are libraries with **no consumers at all**
([architecture.md](architecture.md) §3).

The transport model, the QUIC frame format, the status-byte vocabulary and the
platform-wide authorization catalogs are defined once in
[`docs/daemon/api.md`](../daemon/api.md).

---

## 2. Capabilities

| Capability | Embedded (Go) | Unix | gRPC | REST | QUIC | MCP |
|---|---|---|---|---|---|---|
| Initialize a policy engine | `opa.NewOPAEngine()` + `Initialize(ctx, *config.PolicyConfig)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Load a policy | `(*OPAEngine).LoadPolicy(ctx, name, content)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Unload a policy | `(*OPAEngine).UnloadPolicy(ctx, name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| List policies | `(*OPAEngine).ListPolicies()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Get one policy | `(*OPAEngine).GetPolicy(name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Evaluate a policy | `(*OPAEngine).Evaluate(ctx, name, input)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Evaluate with external data | `(*OPAEngine).EvaluateWithData(ctx, name, input, data)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Reload policies from disk | `(*OPAEngine).Reload(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Engine statistics | `(*OPAEngine).Stats()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Watch a policy directory | `opa.NewFileWatcher(dir)`, `opa.NewWatchedEngine(engine, dir)` | `MISSING` — local by nature | `MISSING` — local by nature | `MISSING` — local by nature | `MISSING` — local by nature | `MISSING` — local by nature |
| Evaluate a proxy route policy | `proxysvc.OPAEvaluator.Evaluate(ctx, policy, input)` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Rate-limit a key | `ratelimit.Limiter.Allow` / `AllowN` / `Wait` / `WaitN` | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer |
| Reset rate-limit state | `ratelimit.Limiter.Reset` / `ResetAll` | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer |
| Rate-limiter statistics | `(*TokenBucketLimiter).Stats()`, `(*SlidingWindowLimiter).Stats()`, `.GetKeyStats(key)` | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer |
| Validate a value | `validation.Validator.Validate(value)` and the nine constructors | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer |
| Sanitize a string / path / SQL identifier | `(*Sanitizer).SanitizeString`, `(*PathSanitizer).SanitizePath`, `(*SQLSanitizer).Escape*`, `StripHTML`, `SanitizePath`, `StripControl`, `StripNonPrintable` | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer | `MISSING` — no consumer |

Two distinct kinds of absence in that table, and the difference matters:

- **`MISSING — docs/13 G7`** on the nine policy-engine rows is a genuine
  re-export gap. `docs/00` L5 obliges this repository to re-export the composed
  surface through its SDK, CLI, web and API; nine policy operations exist and
  none is reachable. Whether policy management *should* be remotely reachable is
  an owner decision — an endpoint that loads arbitrary Rego is an admission-rule
  write primitive ([architecture.md](architecture.md) §6.1) — so this is
  recorded, not proposed.
- **`MISSING` — no consumer** on the `pkg/security` rows is not a transport gap.
  Those packages have no in-process caller either. Exposing them remotely would
  be meaningless; the gap is that nothing uses them at all.
- **`MISSING` — local by nature** on the watcher row: a filesystem watcher on
  one node's directory has no remote meaning.

---

## 3. What *is* exposed, elsewhere

Do not conclude from §2 that the platform has no policy API. It has several,
owned by other features:

| Surface | Where |
|---|---|
| IAM ABAC policies — create, list, get, update, delete, validate, test | [`docs/iam/api.md`](../iam/api.md); REST `/api/v1/iam/tenants/{tenant}/policies*` |
| Attestation policy configuration and evidence verification | [`docs/attestation/`](../attestation/) |
| Proxy route configuration, including each route's `auth.opa-policy` name | [`docs/proxy/`](../proxy/) |
| Registry attestation gating (`registry status --attestation`) | [`docs/registry/`](../registry/) |
| The transport authorization catalogs (`scp` enforcement) | [`docs/daemon/api.md`](../daemon/api.md) §5 |

The IAM policy routes are the go-qrdb RBAC/ABAC decision point re-exported
through this repository. They are **not** this engine.

---

## 4. Error mapping

Because there is no transport, there is no status-code mapping. Errors surface
in-process:

| Failure | Surface |
|---|---|
| Engine not initialised / already initialised | `ErrEngineNotInitialized`, `ErrEngineAlreadyInitialized` |
| Missing or invalid policy directory | `ErrPolicyDirNotFound`, `ErrPolicyLoadFailed` |
| Unparsable or uncompilable policy | `ErrInvalidPolicy`, `ErrPolicyCompilationFailed` |
| Unknown policy at evaluation | `ErrPolicyNotFound` |
| Nil input | `ErrInvalidInput` |
| Rego evaluation or store failure | `ErrEvaluationFailed` |
| Gateway assembly with OPA disabled | `proxysvc.ErrOPADisabled` |

At the proxy boundary these collapse to two audit reasons: **`opa_denied`** for
a false decision and **`opa_error`** for an evaluation error. Both deny. Neither
detail reaches the client — violations are logged and audited server-side only.

The full typed-error inventory is in [engineering.md](engineering.md) §4.

---

## 5. Versioning and deprecation

Nothing here has a wire format to version. Two things to know:

- `PolicyBundle.Version` is a declared field that nothing populates.
- `config.PolicyEngineRego` (`"rego"`) is an accepted `engine` value with **no
  implementation**. `OPAEngine` is the only engine; nothing dispatches on
  `Engine`. Treat it as reserved.

---

## 6. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports and the authorization catalogs
- [`docs/iam/api.md`](../iam/api.md) — the policy API that does exist
- [`docs/proxy/`](../proxy/) — the one consumer of this engine
