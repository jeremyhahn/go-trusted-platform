# Component Health — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/health/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

Every identifier below was read out of `pkg/health/` and `pkg/api/daemon/` on
2026-08-18.

---

## 1. Package layout

| File | Holds |
|---|---|
| `pkg/health/checker.go` | `HealthChecker` |
| `pkg/health/registry.go` | `Registry`, `RegistryOption`, `NewRegistry`, unexported `registryImpl` |
| `pkg/health/types.go` | `HealthStatus`, the four status constants, `ComponentHealth`, `SystemHealth`, `RegistryConfig`, `DefaultRegistryConfig` |
| `pkg/health/errors.go` | Six typed errors |

## 2. Exported surface

### Interfaces

```go
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) ComponentHealth
}

type Registry interface {
	Register(checker HealthChecker) error
	Unregister(name string) error
	Check(ctx context.Context) SystemHealth
	CheckComponent(ctx context.Context, name string) (ComponentHealth, error)
	List() []string
	Count() int
	Close() error
}
```

`Check` returns no error. A registry that is closed, or empty, still returns a
usable `SystemHealth` — see §4.

### Constructor and options

`NewRegistry(opts ...RegistryOption) Registry`

| Option | Sets | Default |
|---|---|---|
| `WithMaxCheckers(max int)` | `RegistryConfig.MaxCheckers` | `100` |
| `WithDefaultTimeout(timeout time.Duration)` | `RegistryConfig.DefaultTimeout` | `30 * time.Second` |

`DefaultRegistryConfig() RegistryConfig` returns those two defaults.
**`MaxCheckers: 0` means unlimited**, and the cap is only enforced when it is
greater than zero.

### Status

```go
type HealthStatus = quicbaas.HealthCheckStatus   // a type ALIAS, not a definition
```

| Constant | Value |
|---|---|
| `StatusHealthy` | `quicbaas.HealthCheckStatusHealthy` |
| `StatusDegraded` | `quicbaas.HealthCheckStatusDegraded` |
| `StatusUnhealthy` | `quicbaas.HealthCheckStatusUnhealthy` |
| `StatusUnknown` | `"unknown"` — platform-local, declared as `HealthStatus` |

Because `HealthStatus` is an alias, a `health.HealthStatus` **is** a
`quicbaas.HealthCheckStatus` to the compiler. No conversion is needed at the
quicbaas boundary, and none should be written.

### Result types

`ComponentHealth`:

| Field | Type | JSON | Notes |
|---|---|---|---|
| `Name` | `string` | `name` | Must match the checker's `Name()` |
| `Status` | `HealthStatus` | `status` | |
| `Message` | `string` | `message,omitempty` | Human-readable |
| `LastChecked` | `time.Time` | `last_checked` | |
| `Duration` | `time.Duration` | `duration_ns` | **Nanoseconds on the wire** |
| `Details` | `map[string]any` | `details,omitempty` | See [architecture.md](architecture.md) §5 for what must not go here |

`SystemHealth`:

| Field | Type | JSON | Notes |
|---|---|---|---|
| `Status` | `HealthStatus` | `status` | Derived, see §4 |
| `Components` | `[]ComponentHealth` | `components` | **Sorted by `Name`** |
| `Timestamp` | `time.Time` | `timestamp` | Taken before the sweep starts |
| `TotalDuration` | `time.Duration` | `total_duration_ns` | Wall clock for the whole sweep |
| `HealthyCount` | `int` | `healthy_count` | |
| `DegradedCount` | `int` | `degraded_count` | |
| `UnhealthyCount` | `int` | `unhealthy_count` | |
| `UnknownCount` | `int` | `unknown_count` | Includes timeouts **and** any status the switch does not recognise |

## 3. Error semantics

All six are struct types implementing `error`. None is a sentinel value, so
match them with `errors.As`, not `errors.Is` on a package variable.

| Error | Fields | Returned by | When |
|---|---|---|---|
| `ErrRegistryClosed` | — | `Register`, `Unregister`, `CheckComponent`, `Close` | The registry is closed. `Close` returns it on a **second** call. |
| `ErrInvalidCheckerName` | `Name`, `Reason` | `Register` | `checker == nil` (`Reason: "checker cannot be nil"`) or `Name() == ""` (`Reason: "name cannot be empty"`) |
| `ErrCheckerAlreadyRegistered` | `Name` | `Register` | A checker with that name already exists |
| `ErrRegistryFull` | `MaxCheckers` | `Register` | `MaxCheckers > 0` and the map is at capacity |
| `ErrCheckerNotRegistered` | `Name` | `Unregister` | No such name |
| `ErrComponentNotFound` | `Name` | `CheckComponent` | No such name |

**`Unregister` and `CheckComponent` return different errors for the same
condition** (`ErrCheckerNotRegistered` vs `ErrComponentNotFound`). That is the
code; do not "fix" it in a doc.

### Fail-closed paths

- **`Register` fails closed on a duplicate name.** It never overwrites. A second
  subsystem registering as `ca` is rejected rather than silently replacing the
  first, which would erase a component from every subsequent report.
- **`Register` fails closed at capacity.** Over `MaxCheckers`, registration is
  refused rather than evicting an existing checker.
- **`Check` on a closed registry reports `StatusUnhealthy`**, not `unknown` and
  not an error. A closed registry means the daemon is shutting down, and
  reporting healthy during shutdown is the failure this avoids.
- **A timed-out check reports `StatusUnknown`, not `StatusUnhealthy`.** This is
  deliberately *not* fail-closed at component level — see
  [architecture.md](architecture.md) §2 — but the aggregation compensates: if
  every component is unknown and none is healthy, the system is `unknown`.

### Crossing the SDK and transport boundaries

Nothing in this package's error set reaches a transport. The daemon converts
`SystemHealth` into its own response shapes and, for the paths that can fail,
returns `daemon.ErrHealthRegistryNotConfigured` (`"health registry not
configured"`) when `Daemon.healthRegistry` is nil. Mapping is in
[api.md](api.md) §6.

## 4. Invariants

1. **`Check` never returns an error and never blocks past the timeout.** With no
   checkers registered it returns `StatusHealthy` with an empty `Components`
   slice; on a closed registry it returns `StatusUnhealthy`. In both cases
   `TotalDuration` is set.
2. **Checkers run in parallel, each with its own deadline.** `Check` derives
   `context.WithTimeout(ctx, DefaultTimeout)` per checker, not once for the
   sweep.

   **The deadline wins once it passes.** `executeCheck`'s select can find the
   checker's answer and the expired deadline ready in the same instant, and Go
   chooses among ready cases uniformly at random, so the select only records
   whether an answer arrived. `checkOutcome(checker, answer, ctx.Err())` — one
   call, one decision — reports that answer only while `ctx.Err()` is nil, and
   otherwise records the timeout. A checker cannot be relied on to honour its
   own context; enforcing the deadline is the registry's job (issue #221).
3. **The registry lock is not held while checkers run.** `Check` snapshots the
   map under `RLock`, releases it, then fans out. A checker may therefore call
   back into the registry without deadlocking.
4. **`Components` is sorted by `Name`.** Output is deterministic across calls
   even though completion order is not.
5. **`List()` is sorted.** `Count()` is the map length.
6. **Overall status is computed, never stored**, by `calculateOverallStatus`:

   ```
   UnhealthyCount > 0                        → StatusUnhealthy
   DegradedCount  > 0                        → StatusDegraded
   UnknownCount   > 0 && HealthyCount == 0   → StatusUnknown
   otherwise                                 → StatusHealthy
   ```

   Note the third line: **a mix of unknown and healthy components reports
   healthy.** One probe that timed out does not degrade a node whose other
   components answered.
7. **Registration is idempotent only in the failure direction.** Registering the
   same name twice is an error, not a no-op.
8. **`Close` is single-shot.** The first call clears the map and returns nil; a
   second returns `ErrRegistryClosed`. The `closed` flag is an `atomic.Bool`
   swapped once.
9. **A `nil` checker is rejected**, and `NewServiceHealthChecker`-family
   constructors in `pkg/api/daemon/` return a **typed nil pointer** for a nil
   service — `registerHealthCheckers` nil-checks the returned pointer before
   registering.
10. **Concurrency.** `registryImpl` is safe for concurrent use: `sync.RWMutex`
    over the map, `atomic.Bool` for `closed`. `Register`/`Unregister` re-check
    `closed` after taking the write lock, closing the race with a concurrent
    `Close`.

## 5. Writing a checker

```go
type myChecker struct{ svc *MyService }

func (c *myChecker) Name() string { return "my-service" }

func (c *myChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	h := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}
	if !c.svc.IsRunning() {
		h.Status = health.StatusUnhealthy
		h.Message = "service is not running"
		h.Details["running"] = false
		h.Duration = time.Since(start)
		return h
	}
	h.Status = health.StatusHealthy
	h.Message = "service is healthy"
	h.Duration = time.Since(start)
	h.Details["response_time_ms"] = float64(h.Duration.Microseconds()) / 1000.0
	return h
}
```

Rules the existing checkers all follow, and a new one must:

- **Return, never panic.** A panicking checker takes down the goroutine, not
  the sweep, but the result is lost and the component silently disappears.
- **Honour `ctx`.** The registry will time you out at 30 s by default and report
  `unknown`; a probe with its own bound should be shorter.
  `NTPServiceHealthChecker` sets `ntpHealthTimeout = 5 * time.Second` internally
  for exactly this reason.
- **Set `Name`, `Status`, `LastChecked` and `Duration` on every return path**,
  including error paths.
- **Distinguish "not running" (unhealthy) from "running but complaining"
  (degraded).** `ServiceHealthChecker` does this: `!IsRunning()` is unhealthy;
  a non-nil `HealthCheckable.HealthCheck` error is degraded.
- **Nil-guard the wrapped service.** Every checker in `pkg/api/daemon/` returns
  unhealthy with `"<x> service reference is nil"` rather than dereferencing.
- **Never put secrets in `Details`** ([architecture.md](architecture.md) §5).

## 6. The registered components

`Daemon.registerHealthCheckers` (`pkg/api/daemon/daemon.go`) registers each
checker only when its service is non-nil, so the component set varies by
deployment.

| Name | Constructor | Reports |
|---|---|---|
| `ca` | `NewCAServiceHealthChecker(*CAGRPCService)` | initialised, identity, root/intermediate subject and validity window; **degraded within 30 days of root expiry**, unhealthy after |
| `sdn` | `NewSDNServiceHealthChecker(*SDNService)` | OVS client wired; bridge and port counts |
| `ntp` | `NewNTPServiceHealthChecker(NTPBackend)` | synced, stratum, leap status, offset, dispersion, reachable/total sources, anomaly — see [`docs/ntp/`](../ntp/) |
| `kms` | `NewKMSServiceHealthChecker(*KMSService)` | running; `kms_server_ready` |
| `iam` | `NewIAMServiceHealthChecker(*IAMService)` | running |
| `tenant` | `NewTenantServiceHealthChecker(*TenantService)` | running |
| `quic` | `NewQUICServerHealthChecker(*quic.Server)` | running; listen address; active/total connections, requests handled, errors |
| `rest` | `NewRESTServiceHealthChecker(*RESTServer)` | running; listen address; TLS, CORS, compression flags |
| `mcp` | `NewMCPServiceHealthChecker(*mcp.Server)` | running |

Plus the generic `NewServiceHealthChecker(ManagedService)`, which names itself
from `ManagedService.Name()` and consults `HealthCheckable` when implemented.

**A registration failure is logged and swallowed** — `registerHealthCheckers`
calls `d.logger.Warn("Failed to register X health checker", ...)` and moves on.
A duplicate or over-capacity checker therefore produces a warning line and a
missing component, not a startup failure. It ends by logging
`"Health checkers registered"` with the final `Count()`.

## 7. Daemon-level surface

`pkg/api/daemon/daemon.go` exposes the registry:

| Method | Returns |
|---|---|
| `(*Daemon) HealthRegistry() health.Registry` | The registry, or nil |
| `(*Daemon) HealthCheck(ctx) (*health.SystemHealth, error)` | `ErrHealthRegistryNotConfigured` when unwired |
| `(*Daemon) HealthCheckComponent(ctx, name) (*health.ComponentHealth, error)` | `ErrHealthRegistryNotConfigured`, or the registry's `ErrComponentNotFound` |
| `(*Daemon) RegisterHealthChecker(checker health.HealthChecker) error` | `ErrHealthRegistryNotConfigured` when unwired |

The registry is injected into the surfaces that publish it:
`Service.SetHealthRegistry` (gRPC), `PlatformRouter.SetHealthRegistry` (REST),
`WithQUICHealthRegistry` (QUIC). **Every one of those call sites nil-checks the
registry and falls back to a static healthy answer**, which is why an unwired
daemon reports healthy rather than erroring — recorded in [api.md](api.md) §6.

`Daemon.Close` calls `healthRegistry.Close()`.

## 8. Configuration

`pkg/health` reads **no configuration file, no environment variable, and no
config key.** `RegistryConfig` is set programmatically through
`RegistryOption`s.

`Daemon` constructs the registry with `health.NewRegistry()` — **no options** —
so the shipped defaults are always `MaxCheckers: 100` and
`DefaultTimeout: 30s`. There is no way to change them from a config file today.

## 9. Persistence

None. No schema, no key layout, no migration. `SystemHealth` is computed per
call and discarded.

## 10. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/health/registry_test.go`, `types_test.go`, `errors_test.go` | Registration rules, capacity, close semantics, parallel sweep, timeout → `unknown`, aggregation, sorting |
| Unit | `pkg/api/daemon/health_checker*_test.go`, `iam_health_checker*_test.go`, `ntp_health_checker_test.go` | Each concrete checker, including nil-service and degraded paths |
| Unit | `pkg/webservice/v1/rest/platform/handlers_test.go`, `router_test.go` | REST projection of `SystemHealth` |

`pkg/health` has no external dependency and no build tag, so `go test
./pkg/health/...` runs anywhere.

**Fault-injection seams.** The interface is the seam: a fake `HealthChecker`
that returns each status exercises aggregation, and `WithMaxCheckers(1)`
exercises `ErrRegistryFull`. No mocking framework is needed and none is used.

The timeout path uses `gatedChecker`, which answers only when the test releases
it and deliberately ignores its context — what a checker that does not honour
its own deadline looks like from the registry. Nothing races two durations, so the deadline is
the only thing that can end the wait and a loaded host only makes the test
slower. The precedence rule itself is pinned by `TestCheckOutcome`, a table over
answer × deadline with no clock in it at all; that is the regression guard for
#221, because the branch executeCheck's select takes is chosen at random and
cannot be driven from a test.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, not only here.

## 11. Observability

- **Log events.** This package logs nothing — it has no logger. The daemon logs
  `"Failed to register <X> health checker"` at warn on each registration
  failure and `"Health checkers registered"` with a `count` field at info once
  registration completes.
- **Metrics.** No metric is emitted from `pkg/health`. Component health is
  surfaced through `GET /api/v1/platform/metrics`, which projects the same
  `SystemHealth` into the dashboard's service tiles
  ([`docs/daemon/api.md`](../daemon/api.md)).
- **Audit records.** None. Health probes are not audited, which is a
  consequence of their being unauthenticated.
- **The debugging entry point** is `ComponentHealth.Details`. Every shipped
  checker sets `response_time_ms` on its healthy path, so a slow component is
  visible without extra instrumentation.

## 12. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — the transport model, opcodes and authorization
- [`docs/ntp/`](../ntp/) — the `ntp` component, and why an unsynchronized clock is reported here
