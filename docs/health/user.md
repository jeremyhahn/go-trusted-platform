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

That gives you the verdict, and names every component that is not healthy:

```
Overall Health: degraded

[WARNING] ntp: DEGRADED — time-unsynced

[INFO] Run with --detailed for every component.
```

For the full table, healthy components included:

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
stratum, certificate expiry date, listen address, connection counts. Checkers
record them in `Details`, but no transport carries `Details` today
([api.md](api.md) §5); the message is the most any endpoint returns.

The HTTP endpoints return the same per-component messages. On the daemon's
own listener:

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
copy is gated. The daemon listener's `/api/v1/health` is not, and the
load-balancer probes below carry no component at all — see
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

Three unversioned probes answer on both the daemon's REST listener and the
webservice port, without a credential:

```
GET https://platform.example.com/health/live    # liveness: restart the node if this fails
GET https://platform.example.com/health/ready   # readiness: take it out of rotation if this fails
GET https://platform.example.com/health         # aggregate: every component healthy
```

**The status code is the verdict.** Each answers `200` when the probe passes
and `503` when it does not, so a load balancer that keys on the status code
does the right thing. The body says the same thing in JSON, for example
`{"ready": false, "status": "HEALTH_STATUS_UNHEALTHY", "timestamp": "…"}`.

**Use `/health/ready` for rotation, not `/health`.** Readiness fails only when a
component is unhealthy. `/health` fails while any component is merely
degraded — an NTP source lost, say — and would pull a working node.

**The probes name no component.** For the breakdown, use
`/api/v1/platform/health` with an admin credential, or
`platformctl health --detailed`.

---

## Checking health from an AI/MCP client

Three tools, none of which require a permission. Each answers what the
matching REST probe does:

| Tool | Returns |
|---|---|
| `platform_health` | The aggregate status, with no components |
| `platform_liveness` | `alive: true` — it reads nothing; an answer is the proof |
| `platform_readiness` | `ready`, and the overall status: ready unless a component is unhealthy |

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
