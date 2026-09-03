# Security Primitives and Policy Engine — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/security/`, `pkg/policy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Package layout

`pkg/policy/` has exactly one subpackage. `pkg/security/` has exactly two.
There is **no `pkg/security/audit`** — see [architecture.md](architecture.md) §8.

| Path | Files | Importers in this repo |
|---|---|---|
| `pkg/policy/opa/` | `engine.go`, `types.go`, `errors.go`, `embed.go`, `watcher.go`, `policies/*.rego` | `pkg/sdn/gateway/proxysvc` |
| `pkg/security/ratelimit/` | `types.go`, `token_bucket.go`, `sliding_window.go`, `errors.go` | **none** |
| `pkg/security/validation/` | `types.go`, `validators.go`, `sanitize.go`, `errors.go` | **none** |

---

## 2. `pkg/policy/opa` — exported surface

### Interfaces (`types.go`)

```go
type PolicyEngine interface {
    Initialize(ctx context.Context, config *config.PolicyConfig) error
    LoadPolicy(ctx context.Context, name string, content []byte) error
    UnloadPolicy(ctx context.Context, name string) error
    Evaluate(ctx context.Context, policyName string, input map[string]interface{}) (*EvaluationResult, error)
    EvaluateWithData(ctx context.Context, policyName string, input, data map[string]interface{}) (*EvaluationResult, error)
    ListPolicies() []*PolicyBundle
    GetPolicy(name string) (*PolicyBundle, error)
    Reload(ctx context.Context) error
    Close() error
    IsInitialized() bool
}

type PolicyWatcher interface {
    Start(ctx context.Context) error
    Stop() error
    OnPolicyChange(callback func(name string, content []byte, deleted bool))
    IsRunning() bool
}
```

### Types (`types.go`)

```go
type EvaluationResult struct {
    Allowed    bool
    Reason     string
    PolicyName string
    Timestamp  time.Time
    Input      map[string]interface{}
    Violations []Violation
    Duration   time.Duration
    Bindings   map[string]interface{}
}

type Violation struct {
    Rule     string
    Message  string
    Severity ViolationSeverity
    Details  map[string]interface{}
}

type ViolationSeverity string
const (
    SeverityInfo     ViolationSeverity = "info"
    SeverityWarning  ViolationSeverity = "warning"
    SeverityError    ViolationSeverity = "error"
    SeverityCritical ViolationSeverity = "critical"
)

type PolicyBundle struct {
    Name, Version, Content, Package, Path, Checksum string
    LoadedAt time.Time
}

type PolicyChangeEvent struct {
    Name      string
    Content   []byte
    Deleted   bool
    Timestamp time.Time
}

type DecisionLog struct {
    ID, PolicyName, RequestID, Source string
    Timestamp time.Time
    Input     map[string]interface{}
    Result    *EvaluationResult
}

type EngineStats struct {
    PolicyCount           int
    EvaluationCount       int64
    AllowedCount          int64
    DeniedCount           int64
    ErrorCount            int64
    AverageEvaluationTime time.Duration
    LastEvaluationTime    time.Time
    InitializedAt         time.Time
}
```

**`EvaluationResult.Bindings` is declared and never populated.**
**`DecisionLog` is declared and never constructed** — there is no decision
logging in this package. Both verified 2026-08-18.

### Engine (`engine.go`)

```go
type OPAEngine struct { /* config, policies, compiler, store, atomics, mu */ }
func NewOPAEngine() *OPAEngine
func (e *OPAEngine) Stats() EngineStats
```

Plus the ten `PolicyEngine` methods. `NewOPAEngine` takes no arguments and
initialises `policies` and an `inmem.New()` store; everything else comes from
`Initialize`.

Unexported behaviour worth knowing:

| Symbol | Value / effect |
|---|---|
| `defaultAllowQuery` | `"allow"` — the decision rule name |
| `defaultViolationsQuery` | `"violations"` — the explanation rule name |
| `regoFileExtension` | `".rego"` |
| `maxPolicyNameLength` | `256` |
| `policyNameRegex` | `^[a-zA-Z][a-zA-Z0-9_-]*$` |
| `embeddedPolicies` | `//go:embed policies/*.rego` |

**`validatePolicyName` is enforced only by `LoadPolicy`.** Policies loaded from a
directory or from the embedded FS take their name from the filename with no
validation, so a file named `1-bad name.rego` loads even though the same name
would be rejected through the API.

### Watcher (`watcher.go`)

```go
type FileWatcher struct { /* fsnotify-backed */ }
func NewFileWatcher(watchDir string) (*FileWatcher, error)
func (w *FileWatcher) Start(ctx context.Context) error
func (w *FileWatcher) Stop() error
func (w *FileWatcher) OnPolicyChange(callback func(name string, content []byte, deleted bool))
func (w *FileWatcher) IsRunning() bool

type WatchedEngine struct { /* engine + watcher */ }
func NewWatchedEngine(engine *OPAEngine, watchDir string) (*WatchedEngine, error)
func (we *WatchedEngine) Start(ctx context.Context) error
func (we *WatchedEngine) Stop() error
func (we *WatchedEngine) Engine() *OPAEngine
```

Changes are debounced before the callback fires.

### The production consumer

`pkg/sdn/gateway/proxysvc/opa.go`:

```go
type OPAConfig struct {
    Enabled   bool   `yaml:"enabled"`
    PolicyDir string `yaml:"policy-dir,omitempty"`
}

type OPAEvaluator struct { /* engine *opa.OPAEngine */ }
func NewOPAEvaluator(ctx context.Context, cfg *OPAConfig) (*OPAEvaluator, error)
func (e *OPAEvaluator) Evaluate(ctx context.Context, policy string, input map[string]any) (bool, []string, error)

var _ proxy.PolicyEvaluator = (*OPAEvaluator)(nil)
```

`NewOPAEvaluator` returns `&ErrOPADisabled{}` for a nil or disabled config, and
**hard-codes `DefaultAction: "deny"`** in the `config.PolicyConfig` it builds —
the operator's `default-action` does not reach it.

The seam it satisfies, in `pkg/proxy/policy.go`:

```go
type PolicyEvaluator interface {
    Evaluate(ctx context.Context, policy string, input map[string]any) (allowed bool, violations []string, err error)
}
```

This exists *"so this package does not link the OPA runtime"*. The chain fails
closed: a false decision denies with `"opa_denied"`, an evaluation error denies
with `"opa_error"`.

---

## 3. `pkg/policy/opa` — invariants

1. **`Initialize` is once-only.** A second call returns
   `ErrEngineAlreadyInitialized`. Nil config returns `ErrNilConfig`.
2. **A configured `PolicyDir` must exist and be a directory**, or `Initialize`
   returns `ErrPolicyDirNotFound`. An empty `PolicyDir` skips directory loading
   entirely — the embedded policies still load.
3. **Directory policies win over embedded ones of the same name.**
   `loadPoliciesFromDir` runs first; `loadEmbeddedPolicies` skips existing names.
4. **A bad embedded policy is silently skipped**; a bad directory policy is a
   hard `ErrInvalidPolicy` / `ErrPolicyLoadFailed`. Deliberate asymmetry: the
   operator's input is validated strictly, the shipped defaults must never brick
   startup.
5. **`LoadPolicy` and `UnloadPolicy` require an initialised engine**
   (`ErrEngineNotInitialized`) and recompile the whole module set afterwards.
6. **Compilation is all-or-nothing.** `recompile` parses every bundle and
   compiles them together; one bad module fails the set with
   `ErrPolicyCompilationFailed`.
7. **`Evaluate` never returns a decision alongside an error.** Uninitialised
   engine, nil input, unknown policy or Rego failure all return `(nil, err)`.
8. **The query path is derived from the policy's Rego package**, not its name:
   `data.<package without the leading "data.">.allow` and `.violations`.
9. **The default action applies only when `allow` yields no result at all.** A
   policy that explicitly evaluates `allow` to `false` denies regardless of the
   default, and `Reason` is left empty. When the default applies, `Reason` is
   `"no matching rules, applied default action: <action>"`.
10. **The `violations` query's error is discarded.** Absence of violations does
    not imply absence of a problem.
11. **Statistics are atomics**; `Evaluate` is safe under concurrency. **`data`
    passed to `EvaluateWithData` is written into the shared `inmem` store** and
    two concurrent calls with different values for the same key race.
12. **`ListPolicies` returns copies**; `GetPolicy` returns the live pointer.
13. **`Checksum` is computed after load, for identification.** It is not
    verified against anything.

---

## 4. `pkg/policy/opa` — error semantics

Sixteen typed structs in `errors.go`, all value receivers; match with
`errors.As`.

| Error | Fields | Returned when |
|---|---|---|
| `ErrEngineNotInitialized` | — | Any operation before `Initialize`, or a nil compiler |
| `ErrEngineAlreadyInitialized` | — | Second `Initialize` |
| `ErrNilConfig` | — | Nil `*config.PolicyConfig` |
| `ErrPolicyDirNotFound` | `Path` | Configured dir missing or not a directory |
| `ErrPolicyLoadFailed` | `Name`, `Path`, `Reason` | Directory read or file read failed |
| `ErrInvalidPolicy` | `Name`, `Reason` | `ast.ParseModule` failed |
| `ErrPolicyCompilationFailed` | `Name`, `Errors` | Compiler reported failures |
| `ErrEmptyPolicyContent` | `Name` | `LoadPolicy` with zero-length content |
| `ErrInvalidPolicyName` | `Name`, `Reason` | Empty, > 256 chars, or regex mismatch |
| `ErrPolicyNotFound` | `Name` | `Evaluate` / `GetPolicy` / `UnloadPolicy` on an unknown name |
| `ErrPolicyAlreadyExists` | `Name` | Declared; not returned by any method |
| `ErrInvalidInput` | `Reason` | Nil input map |
| `ErrEvaluationFailed` | `PolicyName`, `Reason` | Store transaction or Rego evaluation failed |
| `ErrQueryFailed` | `Query`, `Reason` | Declared; not returned by any method |
| `ErrWatcherNotStarted` | — | Watcher operation before `Start` |
| `ErrWatcherAlreadyStarted` | — | Second `Start` |
| `ErrWatcherFailed` | `Reason` | fsnotify error |

### Fail-closed paths

- **Assembly.** `NewOPAEvaluator` propagates `Initialize` errors, so a gateway
  with a missing policy directory or an unparsable policy does not start.
- **Evaluation.** Every failure path returns an error, and `pkg/proxy` maps an
  error to a deny (`"opa_error"`).
- **Silent policy.** No `allow` result ⇒ the default action, which is `deny` in
  `config.DefaultPolicyAction` **and** hard-coded to `"deny"` in
  `NewOPAEvaluator`.
- **Compilation.** One bad module fails the whole set rather than loading a
  partial policy tree.

### Fail-open paths

- **`config.DefaultActionAllow` is a valid configuration value.** Setting
  `attestation.policy.default-action: allow` turns every silent policy into a
  permit. `proxysvc` is immune because it hard-codes deny; other consumers of
  `PolicyConfig` are not.
- **A malformed *embedded* policy is skipped silently**, so a build error in a
  shipped default reduces coverage without any signal.
- **`PolicyConfig.Validate` accepts an entirely empty config** (`Engine`,
  `PolicyDir` and `DefaultAction` all empty) and returns nil. It only requires
  `PolicyDir` when `Engine` is set.
- **The `violations` query error is discarded.**

---

## 5. Configuration

`config.PolicyConfig` (`pkg/config/attestation.go`), reached as
`attestation.policy`:

```go
type PolicyConfig struct {
    Engine        string `yaml:"engine"`
    PolicyDir     string `yaml:"policy-dir"`
    DefaultAction string `yaml:"default-action"`
}
```

| Key | Valid values | `DefaultPolicyConfig()` |
|---|---|---|
| `engine` | `opa` (`PolicyEngineOPA`), `rego` (`PolicyEngineRego`) | `opa` (`DefaultPolicyEngine`) |
| `policy-dir` | any existing directory | `/etc/trusted-platform/policies` |
| `default-action` | `allow` (`DefaultActionAllow`), `deny` (`DefaultActionDeny`) | `deny` (`DefaultPolicyAction`) |

`Validate()` returns nil when all three are empty; otherwise it rejects an
unknown engine (`ErrInvalidPolicyEngine`), a set engine with no policy directory
(`ErrEmptyPolicyDir`), and an unknown action (`ErrInvalidDefaultAction`).

**`PolicyEngineRego` is an accepted value with no implementation.** `OPAEngine`
is the only engine in the repository; nothing dispatches on `Engine`.

The gateway's own section is `proxysvc.OPAConfig`:

```yaml
opa:
  enabled: true
  policy-dir: /etc/trusted-platform/policies   # optional overlay
```

No environment variable configures either. Verified 2026-08-18.

---

## 6. `pkg/security/ratelimit` — exported surface

```go
type Limiter interface {
    Allow(key string) bool
    AllowN(key string, n int) bool
    Wait(ctx context.Context, key string) error
    WaitN(ctx context.Context, key string, n int) error
    Reset(key string)
    ResetAll()
    Close() error
}

type LimitConfig struct {
    Rate            float64
    Burst           int
    CleanupInterval time.Duration
    MaxIdleTime     time.Duration
}
func DefaultLimitConfig() LimitConfig            // 10/s, burst 20, cleanup 5m, idle 10m
func (c LimitConfig) Validate() error

type SlidingWindowConfig struct {
    WindowSize      time.Duration
    MaxRequests     int64
    CleanupInterval time.Duration
    MaxIdleTime     time.Duration
}
func DefaultSlidingWindowConfig() SlidingWindowConfig  // 1m window, 100 req, cleanup 5m, idle 10m
func (c SlidingWindowConfig) Validate() error

type TokenBucketLimiter struct{ /* ... */ }
func NewTokenBucketLimiter(config LimitConfig) (*TokenBucketLimiter, error)
func (tbl *TokenBucketLimiter) Stats() TokenBucketStats

type SlidingWindowLimiter struct{ /* ... */ }
func NewSlidingWindowLimiter(config SlidingWindowConfig) (*SlidingWindowLimiter, error)
func (swl *SlidingWindowLimiter) Stats() SlidingWindowStats
func (swl *SlidingWindowLimiter) GetKeyStats(key string) (KeyStats, bool)

type TokenBucketStats struct{ /* ... */ }
type SlidingWindowStats struct{ /* ... */ }
type KeyStats struct{ /* ... */ }
```

Both types implement `Limiter`. Both run a background `cleanupLoop` evicting
entries idle longer than `MaxIdleTime`, and both stop it on `Close`.

Each limiter also carries an unexported sweep observer — a `func()` fixed at
construction (`newSlidingWindowLimiterWithSweepObserver`,
`newTokenBucketLimiterWithSweepObserver`) and invoked after every completed
sweep. It is nil on both exported constructors, so it changes neither the
exported surface nor runtime behaviour; it exists so the package's own tests can
wait on a real sweep instead of racing the cleanup goroutine with a sleep
(issue #196).

Errors: `ErrRateLimitExceeded`, `ErrInvalidRate{Rate}`, `ErrInvalidBurst{Burst}`,
`ErrKeyNotFound`, `ErrContextCanceled`, `ErrInvalidWindowSize{Size}`,
`ErrInvalidCleanupInterval{Interval}`, `ErrLimiterClosed`.

Invariants:
- `Validate` rejects non-positive `Rate`, `Burst`, `MaxRequests`, `WindowSize`
  and `CleanupInterval`. `MaxIdleTime` is **not** validated.
- `SlidingWindowConfig.Validate` reports a bad `MaxRequests` as
  `ErrInvalidBurst`, not as a window-specific error — a small wart, matched by
  the tests.
- After `Close`, `AllowN` / `WaitN` refuse (`ErrLimiterClosed` on the waiting
  forms).
- Per-key state is created on first use and evicted when idle.
- Safe for concurrent use; the token bucket path is atomics-based, not
  mutex-serialised across keys.

---

## 7. `pkg/security/validation` — exported surface

```go
type Validator interface{ Validate(value any) error }
type ValidatorFunc func(value any) error

type ValidationResult struct { Valid bool; Errors []ValidationError }
func (r ValidationResult) IsValid() bool
func (r ValidationResult) Error() string          // first error, or ""
func (r *ValidationResult) AddError(err ValidationError)
func (r *ValidationResult) Merge(other ValidationResult)
func NewValidResult() ValidationResult
func NewInvalidResult(errors ...ValidationError) ValidationResult
```

Constraint structs: `StringConstraints` (16 fields), `NumericConstraints` (6),
`SanitizerOptions` (9), `PathSanitizerOptions` (7).

Validators, all returning a type implementing `Validator`:

```go
func NewStringValidator(field string, constraints StringConstraints) *StringValidator
func NewEmailValidator(field string) *EmailValidator
func NewURLValidator(field string, allowedSchemes []string, requireHost bool) *URLValidator
func NewIPValidator(field string, allowIPv4, allowIPv6 bool) *IPValidator
func NewCIDRValidator(field string) *CIDRValidator
func NewUUIDValidator(field string) *UUIDValidator
func NewXSSValidator(field string) *XSSValidator
func NewSQLInjectionValidator(field string) *SQLInjectionValidator
func NewCompositeValidator(validators ...Validator) *CompositeValidator
```

Sanitizers:

```go
func NewSanitizer(options SanitizerOptions) *Sanitizer
func NewDefaultSanitizer() *Sanitizer
func (s *Sanitizer) SanitizeString(input string) string

func NewPathSanitizer(options PathSanitizerOptions) *PathSanitizer
func NewDefaultPathSanitizer() *PathSanitizer
func (p *PathSanitizer) SanitizePath(input string) (string, error)

func NewSQLSanitizer() *SQLSanitizer
func (s *SQLSanitizer) EscapeString(input string) string
func (s *SQLSanitizer) EscapeIdentifier(input string) string
func (s *SQLSanitizer) ValidateIdentifier(input string) error

func StripHTML(input string, allowedTags []string) string
func SanitizePath(path string) (string, error)
func StripControl(s string) string
func StripNonPrintable(s string) string
```

Defaults:
- `DefaultSanitizerOptions()` — trim, strip HTML, escape HTML, strip null bytes,
  normalize newlines. `StripSQLKeywords` and `StripJavaScript` are **off**.
- `DefaultPathSanitizerOptions()` — `AllowAbsolute: false`, `MaxDepth: 10`,
  `AllowDotFiles: false`, and a disallowed-extension list:
  `.exe .dll .so .dylib .sh .bat .cmd .ps1 .vbs .js .php .py .rb .pl`.

Errors: `ErrValidationFailed`, `ErrFieldRequired`, `ErrFieldTooLong`,
`ErrFieldTooShort`, `ErrInvalidFormat`, `ErrInvalidValue`, `ErrPathTraversal`,
`ErrDangerousContent`, `ErrOutOfRange`, `ErrInvalidPattern`, `ErrInvalidEmail`,
`ErrInvalidURL`, `ErrInvalidIP`, `ErrSQLInjection`, `ErrXSSDetected`.

**Note the two `SanitizePath`s**: a package-level function and a
`*PathSanitizer` method, both `(string) (string, error)`. The function uses the
defaults; the method uses the receiver's options.

---

## 8. Persistence

Nothing in this section persists state.

- OPA policies: in the binary (`embed.FS`) and on disk (read-only from the
  engine's point of view). The engine's store is `inmem.New()`.
- Rate-limiter state: in-process maps, evicted on idle, lost on restart.
- Validation: stateless.

There is therefore no schema, no migration, and no compatibility rule beyond
Rego's own.

---

## 9. Test strategy

| Layer | Location | Covers | Coverage |
|---|---|---|---|
| OPA engine | `pkg/policy/opa/engine_test.go`, `types_test.go`, `errors_test.go` | Initialize guards, directory/embedded precedence, load/unload/recompile, evaluation and default action, stats | 92.1% |
| OPA proxy policy | `pkg/policy/opa/proxy_authz_test.go` | The `proxy.authz` policy's allow/deny behaviour |  |
| OPA watcher | `pkg/policy/opa/watcher_test.go` | Start/stop, debounce, change callbacks |  |
| Rate limiting | `pkg/security/ratelimit/*_test.go` | Both algorithms: allow, allowN, wait, cancellation, reset, close, per-key isolation, replenishment, window rotation, cleanup, concurrency, stats | 95.3% |
| Validation | `pkg/security/validation/*_test.go` | Every validator and sanitizer, every error | 98.7% |

Fault-injection seams:
- `PolicyEngine` and `PolicyWatcher` — substitute a failing engine or watcher.
- `proxy.PolicyEvaluator` — one method; this is how `pkg/proxy` is tested
  without the OPA runtime.
- `Limiter` and `Validator` — one and one method respectively.
- The rate limiters' sweep observer (§6) — makes the background cleanup sweep an
  observable event, so cleanup tests synchronise on the sweep itself rather than
  on a wall-clock budget.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. It is moot here — this
section has no CLI verbs ([cli.md](cli.md)).

**Coverage is not usage.** `pkg/security/ratelimit` and
`pkg/security/validation` are among the best-covered packages in the repository
and neither has a non-test importer ([architecture.md](architecture.md) §3).

---

## 10. Observability

- **`OPAEngine.Stats()`** is the only instrumentation: policy count, evaluation
  count, allowed/denied/error counts, average and last evaluation time,
  initialisation time. It is **in-process only** — no metric is exported and no
  API returns it.
- **`EvaluationResult.Duration`** carries per-evaluation latency to the caller.
- **`DecisionLog` is declared and never constructed.** There is no decision log.
- **Violations are logged and audited by `pkg/proxy`, server-side, and never
  returned to the client** ([`docs/proxy/`](../proxy/)).
- **Rate-limiter statistics** (`TokenBucketStats`, `SlidingWindowStats`,
  `KeyStats`) exist and are unexported to any metrics system, because nothing
  constructs a limiter.

**Do not log a policy input document verbatim.** Attestation and proxy inputs
carry identities, certificate details and quote material.

---

## 11. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/proxy/`](../proxy/) — the consumer, and the `opa_denied` / `opa_error` contract
- [`docs/attestation/`](../attestation/) — the evidence the attestation policies evaluate
- [`docs/sdn/`](../sdn/) — port authentication, a separate engine
