# Security Primitives and Policy Engine — CLI

> **Status: NORMATIVE** · Scope: `pkg/security/`, `pkg/policy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

**No CLI surface: neither `pkg/security/` nor `pkg/policy/` is reachable from
any `platformctl` verb.** Verified against `pkg/cli/commands/root.go` on
2026-08-18 — the 42 registered command groups include no `policy`, `opa`,
`ratelimit` or `validation` group, and no existing group carries a subcommand
that loads, lists, evaluates or tests a Rego policy.

The reason differs per package:

- **`pkg/policy/opa`** is embedded in `gatewayd` and configured by the `opa:`
  section of the gateway's configuration ([engineering.md](engineering.md) §5).
  Policies are files; `Initialize` reads the directory at startup and the shipped
  consumer does not reload. Managing policies is managing files, plus a restart.
- **`pkg/security/ratelimit`** and **`pkg/security/validation`** are libraries
  with no callers at all ([architecture.md](architecture.md) §3). There is
  nothing running for a CLI verb to inspect.

---

## What an operator actually does

| Task | How, today |
|---|---|
| Add or replace a policy | Write a `.rego` file into the configured `policy-dir` and restart the gateway. A directory policy overrides an embedded one of the same file name. |
| See which policies are loaded | No CLI, no API. `OPAEngine.ListPolicies()` is in-process only. |
| Check a policy compiles | `opa` upstream tooling, or start the gateway — assembly fails closed on an unparsable policy, which is a blunt but reliable check. |
| Test a decision before deploying | `opa eval` upstream, against the same `.rego` file and an input document. |
| See evaluation counts | No CLI, no API. `OPAEngine.Stats()` is in-process only. |

---

## Gaps, recorded

1. **No policy management verbs.** `PolicyEngine` exposes `LoadPolicy`,
   `UnloadPolicy`, `ListPolicies`, `GetPolicy`, `Reload` and `Evaluate` — six
   operations an operator would plausibly want, none reachable from
   `platformctl`. A `platformctl policy list|get|validate|test|reload` group is
   the obvious shape; it does not exist and is not proposed here.
2. **No way to test a policy against the running engine.** `Evaluate` is the
   natural dry-run verb and has no surface.
3. **`Reload` exists and nothing calls it.** The shipped consumer loads once at
   startup ([architecture.md](architecture.md) §5), so a policy change requires
   a gateway restart.
4. **CLI parity suite.** `conventions/feature-docs.md` §4 requires every verb
   here to have a matching `CommandDefinition`. **This repository defines no
   `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the
   requirement is unmet repo-wide. It is moot for this section, which has no
   verbs.

---

## Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/proxy/`](../proxy/) — the gateway that loads these policies
- [`docs/daemon/cli.md`](../daemon/cli.md) §2 — the persistent `platformctl` flag set
