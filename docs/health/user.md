# Component Health — Using It

> **Status: NORMATIVE** · Scope: `pkg/health/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

The platform runs many subsystems in one process. Health tells you **which one**
is unhappy, not merely whether the process is alive.

Every subsystem reports one of four states:

| State | Means |
|---|---|
| `healthy` | Working |
| `degraded` | Running, but reporting a problem — a certificate near expiry, a clock that has not converged |
| `unhealthy` | Not working |
| `unknown` | Its probe did not answer in time. Not the same as broken |

The platform's overall state is the worst thing it found, with one exception:
**a mix of `unknown` and `healthy` reports `healthy`.** One slow probe does not
condemn a node whose other components answered.

---

## Prerequisites

A running `platformd` you can reach, and a `platformctl` context pointing at it.
No configuration is needed to turn health on — the daemon registers its checkers
at startup and there is nothing to enable.

---

## The first thing to run

```bash
platformctl health
```

That gives you the verdict. When it is anything but healthy, ask which
component:

```bash
platformctl health --detailed
```

```
Overall Health: degraded

Component Health:

COMPONENT  STATUS    MESSAGE
ca         healthy   CA service is healthy
kms        healthy   KMS service is healthy
ntp        degraded  time-unsynced
quic       healthy   QUIC server is healthy
rest       healthy   REST server is healthy
```

---

## Getting the detail behind a message

`--detailed` shows the message. It does **not** show the diagnostic fields —
stratum, certificate expiry date, listen address, connection counts. Those exist
but do not survive the trip through the CLI's transport.

To see them, ask the HTTP endpoint:

```bash
curl -s https://platform.example.com/api/v1/health | jq .
```

or, if you are talking to the web/dashboard listener — **which requires an
authenticated `admin`** since #165 gated `/api/v1/platform/**`:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://platform.example.com/api/v1/platform/health | jq .health
```

The two return **different shapes**. `/api/v1/health` gives you
`{status, components[]}`; `/api/v1/platform/health` gives you
`{health: {healthy, status, message, services[]}}`. Both are current; pick one
and stay with it.

**Which one is unauthenticated matters and is not symmetric.** The
component-by-component breakdown tells a reader which subsystem is degraded,
which is useful to somebody choosing where to push, so the dashboard listener's
copy is gated. The load-balancer path below is not — see
[`docs/auth/architecture.md`](../auth/architecture.md) §6c for the full public
set and the reason attached to each entry.

---

## Which components you will see

The list depends on what the node runs — a checker is only registered when its
subsystem is wired.

| Component | Goes degraded when | Goes unhealthy when |
|---|---|---|
| `ca` | Configured but not fully initialised; root certificate expires within 30 days; the trusted root cannot be read | Not initialised at all; root or intermediate certificate has expired |
| `ntp` | The clock is not synchronised, or a large correction was seen after first boot | chronyd's control socket cannot be reached |
| `sdn` | — | The OVS client is not initialised |
| `kms`, `iam`, `tenant` | A custom health check reported a problem | The service is not running |
| `quic`, `rest`, `mcp` | — | The server is not running |

The two worth setting an alert on are **`ca` degraded** and **`ntp` degraded**.
Both are advance warnings of a hard failure: a CA whose root expires in 29 days
will stop issuing in 29 days, and a node whose clock is wrong will fail
attestation, ACME issuance and token validation without any of those failures
naming the clock. See [`docs/ntp/user.md`](../ntp/user.md).

---

## Wiring health into a load balancer

Point it at the unversioned root path:

```
GET https://platform.example.com/health
```

It exists precisely because load balancers frequently cannot be pointed at a
versioned path, and it returns the same aggregate answer as `/api/v1/health`.

Two things to know before you rely on it:

**It always returns HTTP 200.** The verdict is in the body's `status` field, not
in the status code. A load balancer that keys on the status code will never mark
the node down. Configure it to match on the body, or accept that it is a
liveness check rather than a health check.

**There is no HTTP readiness endpoint.** Liveness and readiness probes exist
only on QUIC and MCP ([api.md](api.md) §3). If your orchestrator wants an HTTP
readiness path, `/health` is what you have.

---

## Checking health from an AI/MCP client

Three tools, none of which require a permission:

| Tool | Returns |
|---|---|
| `platform_health` | The aggregate check, per component |
| `platform_liveness` | A constant "alive" — it reads nothing |
| `platform_readiness` | Which subsystems are **wired**, not whether they work |

`platform_readiness` is the one people misread. It reports that a subsystem was
configured and constructed, not that it is functioning. For "is it working?",
use `platform_health`.

---

## Troubleshooting

**`platformctl health` exits 0 but the platform is unhealthy.**
It always exits 0. Parse the output instead:

```bash
test "$(platformctl --output json health | jq -r .status)" = "healthy"
```

**Health says healthy but a subsystem is clearly broken.**
Check that the subsystem has a checker at all — the component list only contains
subsystems that registered one. If a name you expect is missing from
`--detailed`, either the service was not wired on this node, or its registration
failed. A failed registration is logged at warn with
`Failed to register <name> health checker`; the daemon does not abort for it.

**Everything says healthy and the component list is empty.**
The health registry is not wired into the surface you queried. That path reports
healthy by construction — it is not evidence of anything. Confirm the component
list is non-empty before trusting a green answer.

**A component reports `unknown` with "health check timed out".**
Its probe did not answer within the registry's 30-second budget. This usually
means the subsystem is blocked on something external — a device, a socket, a
remote service. The other components' results in the same response are still
valid; the timeout is isolated to the one component.

**`ntp` is degraded with `time-unsynced`.**
The node's clock cannot be trusted. Do not ignore this: certificate validity,
attestation freshness and token expiry all depend on it.
[`docs/ntp/user.md`](../ntp/user.md) has the recovery path.

**`ca` is degraded with "Root certificate expires soon".**
Fewer than 30 days remain on the CA root. Plan the rotation now; the component
goes `unhealthy` the moment it actually expires, and issuance stops.

**A component is `unhealthy` with "... service reference is nil".**
The checker was registered but its underlying service was never wired. That is a
daemon configuration problem, not a fault in the subsystem.

**A gRPC load balancer says the node is not serving, but `platformctl health`
says healthy.**
Those are two different mechanisms. Load balancers speak `grpc.health.v1`, which
reports per gRPC service name and does not consult the component registry at
all. Disagreement between them is expected, not a bug —
[architecture.md](architecture.md) §6.

---

## Where to go next

- [cli.md](cli.md) — every flag on `platformctl health`
- [api.md](api.md) — every capability on every transport, including what is missing
- [architecture.md](architecture.md) — why parallel, why four states, why two mechanisms
- [`docs/daemon/`](../daemon/) — service lifecycle, metrics, logs
- [`docs/ntp/`](../ntp/) — the `ntp` component in depth
