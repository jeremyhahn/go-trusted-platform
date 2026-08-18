# Component Health — Architecture

> **Status: NORMATIVE** · Scope: `pkg/health/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

`platformd` is one process running a dozen subsystems — CA, KMS, SDN, IAM,
tenancy, time, and four transport servers. "Is the daemon up?" is almost never
the question an operator or a load balancer actually has. The useful question is
*which* subsystem is degraded, and a single boolean cannot answer it.

Two failure modes follow from getting this wrong:

- A daemon that answers `200 OK` while its CA certificate expired yesterday.
- A health check that blocks forever because one subsystem's probe hangs, taking
  the whole health endpoint — and therefore the load balancer's view of the
  node — down with it.

## 2. The shape chosen

A **registry of named checkers**, probed **in parallel**, each under its **own
timeout**, aggregated into a four-state verdict.

- Anything that can be unhealthy implements `HealthChecker` — `Name()` plus
  `Check(ctx) ComponentHealth` — and registers itself under a unique name.
- `Registry.Check` fans out to every registered checker concurrently and
  collects results into a `SystemHealth`.
- A checker that does not answer within the registry timeout is reported as
  `unknown` with the message `health check timed out`. It does not stall the
  others and it does not block the caller.
- The overall verdict is derived, never stored: any unhealthy component makes
  the system unhealthy; otherwise any degraded component makes it degraded.

The status vocabulary is **not** this package's. `HealthStatus` is a type alias
for `quicbaas.HealthCheckStatus`, so healthy/degraded/unhealthy mean the same
thing here as everywhere else in the stack. `unknown` is the one platform-local
addition, and it exists precisely because "the probe did not answer" is not the
same claim as "the component is broken".

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **A single boolean `healthy` for the daemon** | Answers the question nobody asks. An operator paged at 03:00 needs the component name, and a boolean cannot carry it. `SystemHealth` keeps the per-component list and the four counts. |
| **Sequential checks** | Total latency would be the sum of every probe. With a CA probe that reads certificates and an NTP probe that polls a control socket, the health endpoint becomes the slowest thing in the process. `Registry.Check` fans out with a `WaitGroup` and a buffered result channel. |
| **One shared timeout for the whole sweep** | A single hung checker would consume the budget and starve the rest, so one broken subsystem would blank out the report for all of them. Each check gets its own `context.WithTimeout` from `DefaultTimeout`. |
| **Three states (healthy / degraded / unhealthy)** | A probe that timed out is not evidence that the component is down; reporting it as `unhealthy` manufactures an outage. `StatusUnknown` keeps "we do not know" distinct from "it is broken", and `calculateOverallStatus` deliberately does **not** let unknowns alone make the system unhealthy. |
| **Defining a platform-local status enum** | Would fork the stack's health vocabulary and force translation at every boundary. `HealthStatus` is an alias of the quicbaas SDK type, so the values interoperate by construction. |
| **Reimplementing liveness/readiness/startup probes here** | The Kubernetes-style probe primitives are the quicbaas SDK's (`quicbaas.HealthChecker`). This package adds only what the shared framework lacks: parallel timeout-bounded sweeps, per-component queries, `Details`-bearing results, and aggregate counts. |
| **A push model — components report status when it changes** | A component that has crashed reports nothing, which is indistinguishable from a component that is fine. Pull-on-demand means an unresponsive component is visible as a timeout. |
| **Letting `Register` overwrite an existing name** | Two subsystems silently sharing a name would erase one of them from every report. `ErrCheckerAlreadyRegistered` makes the collision loud at wiring time. |

## 3. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `HealthChecker` interface | `pkg/health/checker.go` | this repo |
| `Registry` interface and implementation | `pkg/health/registry.go` | this repo |
| `ComponentHealth`, `SystemHealth`, `RegistryConfig` | `pkg/health/types.go` | this repo |
| Typed registry errors | `pkg/health/errors.go` | this repo |
| **The status vocabulary** (`quicbaas.HealthCheckStatus`) | `go-quicbaas/sdk/go` | **not this repo** |
| **Liveness / readiness / startup probe primitives** (`quicbaas.HealthChecker`) | `go-quicbaas/sdk/go` | **not this repo** |
| The concrete checkers (`ca`, `sdn`, `ntp`, `kms`, `iam`, `tenant`, `quic`, `rest`, `mcp`) | `pkg/api/daemon/health_checker.go`, `iam_health_checker.go`, `ntp_health_checker.go` | this repo, daemon feature |
| Registration and lifecycle | `pkg/api/daemon/daemon.go` (`registerHealthCheckers`) | this repo, daemon feature |
| REST / gRPC / QUIC / MCP exposure | `pkg/webservice/v1/rest/platform/`, `pkg/api/daemon/` | this repo — see [`docs/daemon/`](../daemon/) |
| **`grpc.health.v1` standard health service** | `pkg/api/daemon/health_grpc_service.go` | this repo, **separate mechanism** — see §6 |

`pkg/health` imports exactly one thing beyond the standard library:
`go-quicbaas/sdk/go`. It knows nothing about transports, HTTP, gRPC, or the
daemon. That is what makes it testable without standing up a daemon.

## 4. Data flow

```
caller (REST / gRPC / QUIC / MCP / embedded Go)
    │
    ▼
Registry.Check(ctx)
    │
    ├── snapshot the checker map under RLock, release the lock
    │      (checkers run without holding the registry lock)
    │
    ├── one goroutine per checker
    │      ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
    │      result := checker.Check(ctx)          ◄── or timeout → StatusUnknown
    │
    ├── collect into SystemHealth.Components, tally the four counts
    ├── sort components by name (deterministic output)
    └── calculateOverallStatus → SystemHealth.Status
```

**Nothing is persisted.** Every call re-probes; there is no cache, no
last-known-good, and no background sweep inside this package. A result is a
measurement taken at `Timestamp`, valid for that instant only.

The one long-lived state is the checker map itself, which lives in process
memory for the daemon's lifetime and is cleared by `Close`.

Nothing crosses a process or host boundary from inside this package. A
*checker* may — `NTPServiceHealthChecker` polls chronyd's control socket, and
`CAServiceHealthChecker` reads certificates — but that is the checker's
business, which is exactly why each one is separately timeout-bounded.

## 5. Trust boundaries

This feature holds no keys, mints no tokens, and makes no tenancy decision. It
has one security-relevant property, and it is about **disclosure**:

**`ComponentHealth.Details` is operational detail that reaches unauthenticated
callers.** On MCP, `platform_health`, `platform_liveness` and
`platform_readiness` are mapped to the **empty permission string** in
`pkg/api/mcp/authz.go` — deliberately, so a probe never needs a credential. The
REST `/health` route on the daemon's own listener is likewise reachable without
a token. The details a checker publishes are therefore public:

- the CA checker publishes the root subject common name and validity window,
- the QUIC checker publishes the listen address and connection counters,
- the REST checker publishes the listen address and whether TLS is on,
- the NTP checker publishes stratum, offset and source counts.

None of this is secret material, and it is intentionally on the public side of
the line. **A new checker must not put key material, tokens, tenant
identifiers, or subject identities into `Details`** — that is the boundary, and
it is enforced by review rather than by code.

The second property is availability: a checker is untrusted code from the
registry's point of view. It may hang. The per-check timeout is what stops that
from becoming a denial of service on the health endpoint.

## 6. Two health mechanisms, deliberately separate

The daemon serves standard **`grpc.health.v1`** (`HealthGRPCService`) alongside
this registry. They are different things and neither wraps the other:

| | `pkg/health` registry | `grpc.health.v1` |
|---|---|---|
| Consumer | operators, dashboards, `platformctl health` | load balancers, service meshes, gRPC clients |
| Vocabulary | healthy / degraded / unhealthy / unknown | SERVING / NOT_SERVING / SERVICE_UNKNOWN / UNKNOWN |
| Granularity | per component, with `Details` | per gRPC service name, boolean |
| Interface | `health.HealthChecker` (`Name`, `Check`) | `daemon.HealthChecker` (`HealthCheck(ctx) error`) |
| Streaming | no | yes (`Watch`, 1 s poll) |

**The two `HealthChecker` interfaces are different types with the same name.**
`health.HealthChecker` returns a `ComponentHealth`; `daemon.HealthChecker`
returns only an `error`. This is the single most common confusion in this area,
and it is recorded here rather than fixed, because collapsing them would force
either the load balancer path to carry `Details` or the operator path to lose
them.

The bridge that does exist runs the other way: a `ManagedService` that
implements `daemon.HealthCheckable` has its `HealthCheck` called by
`ServiceHealthChecker.Check`, and a non-nil error downgrades that component to
**degraded**, not unhealthy — the service is running, it just reported a
problem.

## 7. What this feature deliberately does not do

- **It does not define health states.** Those are the quicbaas SDK's, consumed
  by alias. Only `StatusUnknown` is local.
- **It does not implement liveness, readiness or startup probes.** Those
  primitives are the quicbaas SDK's. The daemon's `platform_liveness` and
  `platform_readiness` surfaces do not consult this registry at all — liveness
  is a constant, readiness is a nil-check over wired services
  ([api.md](api.md) §4).
- **It does not run a background sweep.** There is no periodic poller, no
  history, no trend, no alerting. Every result is on demand.
- **It does not persist anything.** No store, no schema, no migration.
- **It does not know any component.** The concrete checkers live in
  `pkg/api/daemon/`; this package would compile if every one of them were
  deleted.
- **It does not restart, repair or degrade anything.** It reports. Service
  lifecycle is the daemon's ([`docs/daemon/`](../daemon/)).
- **It does not authenticate.** Probes are deliberately unauthenticated; see §5.
