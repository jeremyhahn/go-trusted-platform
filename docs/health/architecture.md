# Component Health — Architecture

> **Status: NORMATIVE** · Scope: `pkg/health/` · Last verified: 2026-10-14
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
- **The deadline is authoritative once it passes.** A checker that answers late
  is still reported as timed out: its answer describes the component at an
  unknown point past where the registry stopped waiting. See §5.
- The overall verdict is derived, never stored: any unhealthy component makes
  the system unhealthy; otherwise any degraded component makes it degraded.
- The probe verdicts are derived from that one sweep, once, in
  `pkg/health/probe.go`, and every transport encodes them ([api.md](api.md) §4):
  - **liveness** consults nothing — the process answering is the proof;
  - **readiness** passes unless the overall status is unhealthy, so a degraded
    component or an unanswered check leaves the node in rotation, and a
    closed registry takes it out;
  - **aggregate** passes only when the overall status is healthy — no
    component unhealthy or degraded. Unknowns do not move the overall status,
    so healthy components mixed with unknown ones still pass.

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
| **Reimplementing the liveness/readiness/startup probe primitives here** | The Kubernetes-style probe primitives are the quicbaas SDK's (`quicbaas.HealthChecker`). This package adds only what the shared framework lacks: parallel timeout-bounded sweeps, per-component queries, `Details`-bearing results, aggregate counts, and the platform's three verdicts over this registry (`probe.go`). |
| **Each transport computing its own probe answer** | That is how it was until #452: QUIC answered liveness with a constant and readiness with a nil-check over wired services, and REST and gRPC had no probe at all, so one daemon gave different answers per transport. `Liveness`, `Readiness` and `Aggregate` are defined once here; a transport only encodes the `Probe`. |
| **A push model — components report status when it changes** | A component that has crashed reports nothing, which is indistinguishable from a component that is fine. Pull-on-demand means an unresponsive component is visible as a timeout. |
| **Letting `Register` overwrite an existing name** | Two subsystems silently sharing a name would erase one of them from every report. `ErrCheckerAlreadyRegistered` makes the collision loud at wiring time. |

## 3. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `HealthChecker` interface | `pkg/health/checker.go` | this repo |
| `Registry` interface and implementation | `pkg/health/registry.go` | this repo |
| `ComponentHealth`, `SystemHealth`, `RegistryConfig` | `pkg/health/types.go` | this repo |
| Typed registry errors | `pkg/health/errors.go` | this repo |
| Probe verdicts (`Liveness`, `Readiness`, `Aggregate`) | `pkg/health/probe.go` | this repo |
| **The status vocabulary** (`quicbaas.HealthCheckStatus`) | `go-quicbaas/sdk/go` | **not this repo** |
| **Liveness / readiness / startup probe primitives** (`quicbaas.HealthChecker`) | `go-quicbaas/sdk/go` | **not this repo** |
| The concrete checkers (`ca`, `sdn`, `sdn-addressing`, `ntp`, `kms`, `iam`, `tenant`, `quic`, `rest`, `mcp`) | `pkg/api/daemon/health_checker.go`, `iam_health_checker.go`, `ntp_health_checker.go`, `sdn_address_health_checker.go` | this repo, daemon feature |
| Registration and lifecycle | `pkg/api/daemon/daemon.go` (`registerHealthCheckers`) | this repo, daemon feature |
| REST / gRPC / QUIC / MCP exposure | `pkg/api/healthprobe/` (the root REST probes, on both listeners), `pkg/webservice/v1/rest/platform/`, `pkg/api/daemon/` | this repo — see [api.md](api.md) and [`docs/daemon/`](../daemon/) |
| **`grpc.health.v1` standard health service** | `pkg/api/daemon/health_grpc_service.go` | this repo, **separate interface over this registry** — see §6 |

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

**Health is served to unauthenticated callers, and is shaped for it.** The
probes — REST `/health`, `/health/live` and `/health/ready` on both listeners,
gRPC `Liveness`, `Readiness` and `grpc.health.v1.Health/Check`, the QUIC probe
opcodes, and the MCP `platform_health`, `platform_liveness` and
`platform_readiness` tools (mapped to the **empty permission string** in
`pkg/api/mcp/authz.go`) — answer without a credential, deliberately, so a probe
never needs one. They carry the overall status only, never a component name.

The breakdown is gated — gRPC `GetHealth` needs `platform:read`,
`/api/v1/platform/health` needs `admin` — with one exception: `/api/v1/health`
on the daemon's own listener is unauthenticated and lists every component with
its status and message. `Details` crosses no wire transport today, but it is
written as public all the same, so a projection that adds it leaks nothing:

- the CA checker publishes the root subject common name and validity window,
- the QUIC checker publishes the listen address and connection counters,
- the REST checker publishes the listen address and whether TLS is on,
- the NTP checker publishes stratum, offset, source counts, and any
  advertised NTS-KE server name clients cannot usefully dial — the name, and
  either the address and allow list that refuse it or the resolver's error.
  None of it is secret: the node already reveals which prefixes it answers by
  answering on them, and a name that does not resolve is a fact any client
  discovers by asking.

None of this is secret material, and it is intentionally on the public side of
the line. **A new checker must not put key material, tokens, tenant
identifiers, or subject identities into `Details` or `Message`** — that is the boundary, and
it is enforced by review rather than by code.

The second property is availability: a checker is untrusted code from the
registry's point of view. It may hang. The per-check timeout is what stops that
from becoming a denial of service on the health endpoint.

For the same reason a checker's answer is trusted only while its budget is
intact. `executeCheck` waits on the checker and on the deadline together, and
both can become ready in the same instant — Go picks among ready select cases
uniformly at random, so the branch the runtime took is not evidence of anything.
The branch therefore only records whether an answer arrived; the single
`checkOutcome` call decides, from that answer and the sampled deadline error,
and an answer observed past the deadline is recorded as the timeout.

Without that rule a check that overruns its deadline **and then completes** has
its late answer reported at face value — measured on a loaded host as a 200 ms
check reporting healthy against a 50 ms deadline (issue #221).

Note the exact scope. A checker that never returns is reported correctly with or
without this rule: it never sends a result, so the deadline is the only ready
case. What the rule protects against is the **degrading** component — one slow
enough to blow its budget, which is reported healthy on a coin flip once it
finally answers. That is the more common failure in a fleet and the harder one
to notice.

The conservative direction is deliberate: a genuinely fast check that the
runtime could not observe in time is reported `unknown`, which says "we do not
know" rather than manufacturing either an outage or an all-clear.

## 6. Two health interfaces over one registry

The daemon serves standard **`grpc.health.v1`** (`HealthGRPCService`) beside
this registry's own surfaces, and it answers from this registry.
`daemon.go` registers one checker, named `platform`
(`daemonHealthCheckerName`), that wraps the registry
(`NewRegistryHealthChecker`): an **unhealthy** overall status answers
`NOT_SERVING`, while **degraded** (and unknown) stays `SERVING` so a degraded
node is not drained from a load balancer. `Check` with an empty service name
returns that overall verdict. No service names are registered, so any named
`Check` answers `NOT_FOUND` — deliberately, so an unauthenticated caller cannot
enumerate the daemon's services (#337).

| | `pkg/health` registry | `grpc.health.v1` |
|---|---|---|
| Consumer | operators, dashboards, `platformctl health` | load balancers, service meshes, gRPC clients |
| Vocabulary | healthy / degraded / unhealthy / unknown | SERVING / NOT_SERVING / SERVICE_UNKNOWN / UNKNOWN |
| Granularity | per component, with `Details` | one overall verdict (empty service name), boolean |
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
- **It does not implement the probe primitives or a startup probe.** Those
  are the quicbaas SDK's. It derives only the platform's liveness, readiness
  and aggregate verdicts over this registry (`probe.go`, §2); every
  transport's probe — `platform_liveness` and `platform_readiness` included —
  answers from them ([api.md](api.md) §4).
- **It does not run a background sweep.** There is no periodic poller, no
  history, no trend, no alerting. Every result is on demand.
- **It does not persist anything.** No store, no schema, no migration.
- **It does not know any component.** The concrete checkers live in
  `pkg/api/daemon/`; this package would compile if every one of them were
  deleted.
- **It does not restart, repair or degrade anything.** It reports. Service
  lifecycle is the daemon's ([`docs/daemon/`](../daemon/)).
- **It does not authenticate.** Probes are deliberately unauthenticated; see §5.
