# Security Primitives and Policy Engine — Architecture

> **Status: NORMATIVE** · Scope: `pkg/security/`, `pkg/policy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. This is a cross-cutting section, scoped honestly

`docs/security/` is not one feature. It covers two unrelated package trees that
happen to be the platform's *local* security machinery, as opposed to the
security capabilities re-exported from the stack:

| Tree | What is actually there (2026-08-18) | State |
|---|---|---|
| `pkg/security/ratelimit/` | Two rate limiters — token bucket and sliding window — behind one `Limiter` interface | Complete, tested (95.6% coverage), **zero importers in this repository** |
| `pkg/security/validation/` | Input validators and sanitizers — string, numeric, email, URL, IP, CIDR, UUID, XSS, SQL injection, path traversal | Complete, tested (98.7% coverage), **zero importers in this repository** |
| `pkg/policy/opa/` | An embedded Open Policy Agent engine with six built-in Rego policies and a file watcher | Complete, tested (92.1% coverage), **one importer**: `pkg/sdn/gateway/proxysvc` |

**Where the platform's security actually happens is mostly elsewhere**, and this
document links rather than duplicates:

| Concern | Folder |
|---|---|
| Certificate and token authentication | [`docs/auth/`](../auth/) |
| Identity, RBAC, ABAC policies, the single decision point | [`docs/iam/`](../iam/) |
| Keys, DEKs, crypto operations | [`docs/kms/`](../kms/) |
| Certificate issuance and revocation | [`docs/ca/`](../ca/) |
| Attestation evidence and its policies | [`docs/attestation/`](../attestation/) |
| Edge-gateway authorization chain | [`docs/proxy/`](../proxy/) |
| SDN port authentication (a separate engine, `pkg/sdn/policy/`, not OPA) | [`docs/sdn/`](../sdn/) |
| Config secret resolution | [`docs/secrets/`](../secrets/) |
| The transport authorization catalogs | [`docs/daemon/api.md`](../daemon/api.md) §5 |

Nothing in this folder makes an authentication or an identity decision.

---

## 2. `pkg/policy/opa` — the part that is load-bearing

### The problem

The platform admits workloads and proxies requests on the strength of evidence:
a TPM quote, an image digest, a set of PCR values, a client identity. Encoding
"which evidence is acceptable" as Go conditionals means every policy change is a
release.

### The shape chosen

**An embedded OPA engine with Rego policies, defaulting to deny.**

- Policies are **compiled into the binary** (`//go:embed policies/*.rego`) so a
  node with no policy directory still has working defaults.
- An operator policy directory **overlays** the embedded set: a directory policy
  with the same file name wins, because `loadPoliciesFromDir` runs first and
  `loadEmbeddedPolicies` skips names that already exist.
- Every evaluation queries two rules in the policy's package: `allow` (the
  decision) and `violations` (the explanation).
- **When `allow` produces no result, the configured default action applies**,
  and the platform default is `deny` (`config.DefaultPolicyAction ==
  DefaultActionDeny`).

Six embedded policies:

| File / policy name | Rego package | Subject |
|---|---|---|
| `host.rego` | `attestation.host` | Host attestation evidence |
| `vm.rego` | `attestation.vm` | VM attestation evidence |
| `container.rego` | `attestation.container` | Container admission |
| `image.rego` | `attestation.image` | Image admission |
| `quote.rego` | `attestation.quote` | TPM quote acceptance |
| `proxy_authz.rego` | `proxy.authz` | Edge-proxy request authorization |

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Hard-code admission rules in Go** | Every policy change becomes a release, and the rules end up scattered across the packages that enforce them. Rego keeps them in one declarative place, reviewable as text. |
| **Run OPA as a sidecar** | An admission decision on the boot path cannot depend on another process being up. The engine is in-process and its defaults are in the binary. |
| **Ship no default policies** | A node with an empty policy directory would then have nothing to evaluate. `//go:embed` guarantees a floor. |
| **Let the operator directory be additive only** | Then a broken default could not be replaced without a build. Same-name override is the escape hatch. |
| **Default to allow when a policy is silent** | An undefined `allow` rule is the commonest Rego mistake. `DefaultPolicyAction` is `deny`, and `proxysvc.NewOPAEvaluator` hard-codes `DefaultAction: "deny"` regardless of configuration. |
| **Fail open when the engine will not initialise** | `NewOPAEvaluator` returns initialisation errors so the proxy **fails closed at assembly time** rather than denying every request at runtime with an opaque error. |
| **Use this engine as the platform's token/RBAC decision point** | There is exactly one RBAC decision point in the portfolio, in go-qrdb. This engine does workload admission, attestation-evidence and proxy-authz policy — never `scp` claim authorization. |
| **Use OPA for SDN port authentication** | SDN port authentication is a separate engine in `pkg/sdn/policy/`, a port state machine, not a Rego evaluation. |

---

## 3. `pkg/security` — primitives with no callers

### What they are

`pkg/security/ratelimit` and `pkg/security/validation` are two self-contained,
well-tested, dependency-free libraries. `ratelimit` offers a `Limiter` interface
with `Allow` / `AllowN` / `Wait` / `WaitN` / `Reset` / `ResetAll` / `Close` and
two implementations. `validation` offers a `Validator` interface, a
`ValidationResult` accumulator, nine concrete validators, and three sanitizers.

### What they are not

**They are not wired into anything.** Grepping the repository for
`go-trusted-platform/pkg/security/` on 2026-08-18 returns no non-test importer —
the only matches are coverage-log lines. No transport applies a rate limit from
this package. No handler sanitizes input with it.

That is worth stating plainly rather than implying coverage the platform does
not have:

- **There is no rate limiting on the platform's API surfaces from this
  package.** Whatever rate limiting exists is elsewhere or absent. A brute-force
  attempt against, say, EAB KeyIDs is not throttled by `pkg/security/ratelimit`.
- **There is no input sanitization applied from this package.** Handlers
  validate what they validate individually.

The packages are honest, tested building blocks awaiting a decision about where
they belong. Documenting them as if they were deployed would be worse than
documenting the gap.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Lock-based token bucket** | Per-key limiting on a hot path with a global mutex serialises unrelated keys. The implementation uses per-key entries with atomics. |
| **A single limiter algorithm** | Token bucket smooths bursts against a rate; sliding window enforces a hard count per interval. Different endpoints want different shapes, so both exist behind one interface. |
| **Unbounded per-key state** | A per-key limiter keyed on client IP is a memory-growth bug. Both limiters carry `CleanupInterval` and `MaxIdleTime` and evict idle entries. |
| **Validate by panicking or by returning the first error** | `ValidationResult` accumulates errors so a form can be reported in one pass; `Validator` returns a single error for the simple case. Both exist deliberately. |
| **Allow-list-free path sanitization** | `PathSanitizerOptions` defaults to `AllowAbsolute: false`, `MaxDepth: 10`, `AllowDotFiles: false`, and a disallowed-extension list covering executables and scripts. Deny-by-shape, not by hope. |

---

## 4. Component boundaries

| Piece | Location | Owner |
|---|---|---|
| `Limiter` interface, `TokenBucketLimiter`, `SlidingWindowLimiter` | `pkg/security/ratelimit/` | this repo — **unused** |
| `Validator`, `ValidationResult`, nine validators | `pkg/security/validation/validators.go` | this repo — **unused** |
| `Sanitizer`, `PathSanitizer`, `SQLSanitizer` | `pkg/security/validation/sanitize.go` | this repo — **unused** |
| `PolicyEngine` / `PolicyWatcher` interfaces, `OPAEngine`, `FileWatcher`, `WatchedEngine` | `pkg/policy/opa/` | this repo |
| Six embedded Rego policies | `pkg/policy/opa/policies/*.rego` | this repo |
| `PolicyConfig` (`engine`, `policy-dir`, `default-action`) | `pkg/config/attestation.go` | this repo |
| `OPAEvaluator`, `OPAConfig` — the one production consumer | `pkg/sdn/gateway/proxysvc/opa.go` | this repo — [`docs/proxy/`](../proxy/) |
| `proxy.PolicyEvaluator` — the seam that keeps `pkg/proxy` free of the OPA runtime | `pkg/proxy/policy.go` | this repo |
| **The OPA runtime** (`github.com/open-policy-agent/opa/v1`) | third party | **not this repo** |
| **The RBAC decision point** | go-qrdb, via go-quicbaas | **not this repo** — [`docs/iam/`](../iam/) |
| **SDN port authentication** | `pkg/sdn/policy/` — a state machine, not OPA | this repo, **different feature** |
| **Attestation evidence collection and verification** | `pkg/attestation/` | this repo, **different feature** |

The §R capability rows touched are *"TPM attestation of nodes and workloads"*
(the engine evaluates the evidence) and the gateway/proxy row (the engine
authorizes proxied requests).

---

## 5. Data flow

### A proxied request evaluated against `proxy_authz`

1. `gatewayd` assembles a `proxysvc.OPAEvaluator` at startup:
   `opa.NewOPAEngine()` then `Initialize(ctx, &config.PolicyConfig{PolicyDir:
   cfg.PolicyDir, DefaultAction: "deny"})`.
   **Initialisation failures are returned**, so a missing policy directory or an
   unparsable policy stops assembly.
2. `Initialize` stats the directory, loads `*.rego` from it, loads the embedded
   set for names not already present, and compiles everything into one
   `ast.Compiler`.
3. A request arrives. `pkg/proxy`'s auth chain reads the route's
   `auth.opa-policy` name; an empty name means no policy check.
4. `OPAEvaluator.Evaluate(ctx, policy, input)` calls
   `OPAEngine.Evaluate`, which builds two queries from the policy's package
   path — `data.<pkg>.allow` and `data.<pkg>.violations` — and evaluates both
   against the input document.
5. The result is projected onto the chain's `(allowed, violations, error)`
   contract. **The chain fails closed**: a false decision denies with
   `"opa_denied"`, an evaluation error denies with `"opa_error"`.
6. Violations are logged and audited server-side, **never returned to the
   client**.

### Policy reload

`FileWatcher` (fsnotify) watches a directory, debounces changes, and invokes an
`OnPolicyChange(name, content, deleted)` callback. `WatchedEngine` pairs an
`OPAEngine` with a watcher. `OPAEngine.Reload(ctx)` re-reads the configured
directory.

**`proxysvc.OPAEvaluator` does not use the watcher.** Its doc comment is
explicit: *"Policies are loaded once at startup."* Changing a policy file on a
running gateway has no effect until restart.

### What is persisted

Nothing. Policies live in the binary and on disk; the engine's store is
`inmem.New()`; statistics are in-process atomics.

---

## 6. Trust boundaries

1. **The policy directory is a trust boundary.** Anything in it that parses as
   Rego is compiled and can override an embedded policy of the same name.
   **Write access to that directory is equivalent to write access to the
   platform's admission rules.** There is no signature check, no checksum
   allow-list, and no provenance requirement — `PolicyBundle.Checksum` is
   computed *after* loading, for identification, not for verification.

2. **Default deny, in two places.** `config.DefaultPolicyAction` is
   `DefaultActionDeny`, and `proxysvc.NewOPAEvaluator` hard-codes
   `DefaultAction: "deny"` irrespective of configuration. A policy whose `allow`
   rule is undefined denies. **`DefaultActionAllow` exists as a valid
   configuration value** — setting it turns every silent policy into a permit.

3a. **The host packet filter is derived, not authored.** `pkg/sdn/gateway/services/hostfw`
   renders `inet tp_host` (input policy drop) from the daemons' listener
   inventory plus declared peers and tunnels — see
   [`docs/gateway/architecture.md`](../gateway/architecture.md) §The host packet
   filter. A listener nobody declared is unreachable; the filter is the only
   control in front of host-addressed traffic, which OVS cannot see.

3. **Fail closed at assembly, not at request time.** `NewOPAEvaluator` returns
   initialisation errors. A gateway with a broken policy does not start; it does
   not start and deny everything with an opaque error.

4. **`Evaluate` errors are not decisions.** A nil input, an unknown policy name,
   an uninitialised engine or a Rego evaluation failure returns
   `(nil, error)` — never `(allowed=false, nil)`. Callers must treat an error as
   a denial; `pkg/proxy` does.

5. **The `violations` query is best-effort.** Its error is discarded
   (`if err == nil && ...`); an evaluation that fails to produce violations
   still returns the `allow` decision. Absence of violations does not mean
   absence of a problem.

6. **`EvaluateWithData` writes caller-supplied data into the shared store.**
   Each key becomes a storage path (`/key`), added or replaced in a transaction
   on the engine's single `inmem` store. **Two concurrent evaluations with
   different `data` for the same key race.** Use `Evaluate` unless you need
   external data and can guarantee it is stable.

7. **The engine is not an authorization decision point for tokens.** It decides
   workload admission, attestation-evidence acceptance and proxy authorization.
   `scp` claim enforcement is the interceptors' job
   ([`docs/daemon/api.md`](../daemon/api.md) §5).

8. **`pkg/security` protects nothing today** because nothing calls it. Do not
   cite `pkg/security/validation` as the reason an input is safe, or
   `pkg/security/ratelimit` as the reason an endpoint is throttled.

9. **`SQLSanitizer` is escaping, not parameterisation.** `EscapeString`,
   `EscapeIdentifier` and `ValidateIdentifier` exist; escaping is strictly worse
   than a bound parameter and should be the last resort, not the pattern.

10. **Daemon key custody: the server key never leaves the keystore (#33).** The
   daemon's mTLS server key is generated and held in the platform CA keystore.
   The listeners present it through a `crypto.Signer`. Before #33 it was
   written as a PEM bundle to `/tmp/platformd-integration/tls`.
   - **The admin bootstrap bundle is the one argued on-disk key.** It lives at
     `<platform-dir>/tls/client-bundle.pem` (0600, in a 0700 directory) because
     a separate process (`platformctl`) needs it for the first mTLS connection.
     **Read access to that file is admin access to the daemon API.**
   - The CA bundle beside it is public.
   - The QEMU migration tls-creds directory is a second on-disk key. QEMU reads
     its credentials from files, so that key is not a daemon key.

   Detail: [`docs/daemon/architecture.md`](../daemon/architecture.md) §Daemon
   TLS identity and key custody.

---

## 7. What this section deliberately does not do

10. **The overlay IPsec key never leaves the PKCS#11 module (#709).** charon
    (`trusted-platform-strongswan`) authenticates IKEv2 with a P-256 key held
    behind the go-xkms module and signs through `p11-kit-client.so`; no key
    file exists on the node. The boundaries around it:
    - *The VICI socket* (`/run/charon.vici`) is mode 0600 owned by the
      account platformd runs as (root on installer-built nodes, the `charon`
      service's default). Whoever can write to it can install SAs and
      policies; the `charon` service re-owns it after every (re)start and
      refuses to start without that account, and platformd refuses a socket
      its uid does not own.
    - *The p11-kit socket* (`/run/p11-kit/xkms.sock`) is mode 0660, group
      `strongswan`. A member can sign with the IKE key.
    - *charon runs as `strongswan`* with `CAP_NET_ADMIN` only. It loads its
      plugins, the PKCS#11 provider among them, before dropping root.
    - *Fail closed.* charon `need`s the module host, so it never runs without
      its key store; the SAs are ESP-required transport policies, so a tunnel
      that is not established carries nothing; PSK authentication cannot be
      compiled out, so connections say `auth = pubkey`.
    - *The p11-kit version is pinned at 0.26 or newer.* A 0.26 client against
      an older server silently corrupts `CKA_ID` and labels, so the apk
      dependencies, the module-host build and the service start refuse an older
      server. See [`docs/sdn/engineering.md`](../sdn/engineering.md) §9.2 and
      §9.6.

- **It does not authenticate anyone.** [`docs/auth/`](../auth/).
- **It does not decide RBAC.** There is one decision point and it is in
  go-qrdb. [`docs/iam/`](../iam/).
- **It does not collect or verify attestation evidence.** It evaluates evidence
  someone else collected. [`docs/attestation/`](../attestation/).
- **It does not authenticate SDN ports.** That is `pkg/sdn/policy/`, a separate
  engine. [`docs/sdn/`](../sdn/).
- **It does not verify policy provenance.** No signing, no allow-list.
- **It does not hot-reload policies in the shipped consumer.** The watcher
  exists; `proxysvc` loads once at startup.
- **It does not expose any API.** No REST route, no gRPC service, no QUIC
  opcode, no MCP tool, no CLI verb. [api.md](api.md), [cli.md](cli.md).
- **It does not rate-limit or sanitize anything**, because nothing imports
  those packages. §3.

---

## 8. Corrections against the code

Recorded per `conventions/feature-docs.md` §7 — the code wins.

| Stale statement | Where | Reality (2026-08-18) |
|---|---|---|
| A `pkg/security/audit/` package with `AuditEvent`, `AuditLogger`, `logger.go`, `middleware.go`, `audit.NewLogger(...)`, `audit.NewEvent()...Build()` | legacy `docs/security/README.md` | **`pkg/security/audit` does not exist.** `pkg/security` contains exactly two subpackages: `ratelimit` and `validation`. The audit package appears in a stale build coverage log; the source is gone. |
| `ratelimit.NewTokenBucket(1000, 100)` | legacy `docs/security/README.md` | The constructor is `NewTokenBucketLimiter(config LimitConfig) (*TokenBucketLimiter, error)`. |
| `ratelimit.NewSlidingWindow(100, time.Minute)` | legacy `docs/security/README.md` | The constructor is `NewSlidingWindowLimiter(config SlidingWindowConfig) (*SlidingWindowLimiter, error)`. |
| `validation.StripXSS(html)` | legacy `docs/security/README.md` | No such function. The XSS surface is `StripHTML(input string, allowedTags []string) string` and `NewXSSValidator(field string) *XSSValidator`. |
| `validation.ValidateEmail(email)` | legacy `docs/security/README.md` | No such function. The email surface is `NewEmailValidator(field string) *EmailValidator` implementing `Validator`. |
| `safe := validation.SanitizePath(input)` (single return) | legacy `docs/security/README.md` | `SanitizePath(path string) (string, error)` returns two values. There is also a method form, `(*PathSanitizer).SanitizePath(input string) (string, error)`. |
| Coverage "Rate limiting 82%+, Audit 69%+, Validation 86%+" | legacy `docs/security/README.md` | Current build log: ratelimit 95.6%, validation 98.7%, `pkg/policy/opa` 92.1%. Audit is not measured because it does not exist. |
| The README does not mention `pkg/policy/opa` at all | legacy `docs/security/README.md` | It is the only part of this section with a production consumer. |

---

## 9. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/proxy/`](../proxy/) — the one production consumer of the OPA engine
- [`docs/attestation/`](../attestation/) — the evidence the attestation policies evaluate
- [`docs/auth/`](../auth/) · [`docs/iam/`](../iam/) — authentication and authorization
- [`docs/sdn/`](../sdn/) — port authentication, a different engine
