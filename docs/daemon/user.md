# Platform Daemon — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Running and operating the platform daemon. Internals are in
> [engineering.md](engineering.md).

---

## What this is

`platformd` is the platform. It runs as a **control-plane** node or a **worker**
— that is configuration, not a different binary — and serves every capability
over six transports at once.

`gatewayd` is the same idea for the **edge** role, and has its own feature
folder ([`docs/gateway/`](../gateway/)).

---

## The six binaries, and which ones you run

| Binary | You run it |
|---|---|
| `platformd` | As a service. This is the platform. |
| `gatewayd` | As a service, on edge nodes. |
| `platformctl` | Interactively. It is also the desktop GUI. |
| `pxeboot` | As a container, for network boot. |
| `platform-initrd` | **Never directly.** Dracut calls it during early boot. |
| `deployer-pin` | Interactively, for deployer pin management. |

---

## First contact

```bash
platformctl status
platformctl health
platformctl version
platformctl --output json status
```

Then find out what is actually serving:

```bash
curl -s https://platform.example.com/api/v1/platform/protocols
```

**`/protocols` answers "is QUIC even on".** It is the fastest way to explain why
a client cannot connect on a transport you assumed was running.

---

## Transports

```bash
platformctl --transport unix status       # gRPC over a Unix socket
platformctl --transport rest status
platformctl --transport quic status
```

`--transport embedded` hosts platformd inside `platformctl` itself, with the
node's own configuration and the calling user's credentials, and opens no
network listener — run it as root on the node ([cli.md](cli.md) §2.3).

Precedence for every setting is **flag > environment > config file > default**,
so `PLATFORMCTL_TRANSPORT=quic` sets it for a shell and `--transport rest`
overrides it for one command.

`--server` implies a remote context — it changes more than the address. Use
`--server-name` when the certificate's name differs from the address you dial.

---

## Managing services

```bash
platformctl service --help

curl -s        https://platform.example.com/api/v1/platform/services
curl -s        https://platform.example.com/api/v1/platform/services/dns
curl -s -X POST https://platform.example.com/api/v1/platform/services/dns/start
curl -s -X POST https://platform.example.com/api/v1/platform/services/dns/stop
curl -s -X POST https://platform.example.com/api/v1/platform/services/dns/restart
```

**A service that is off answers 503, not 404.** Across the whole platform, 503
means "this capability exists and is not running or not wired in" — configuration,
not a crash. That distinction is deliberate and is the first thing to check when
a feature "does not exist".

---

## Changing configuration without locking yourself out

This is the most important operational habit on this platform. Configuration
changes program a datapath and enforce attestation policy — a bad one is how you
lose access.

```bash
# 1. Snapshot first
curl -s -X POST https://platform.example.com/api/v1/platform/config/snapshots

# 2. Validate the change before applying it
curl -s -X POST https://platform.example.com/api/v1/platform/config/validate -d @new-config.yaml

# 3. Apply, then reload
curl -s -X POST https://platform.example.com/api/v1/platform/config/reload

# 4. If it went wrong
curl -s        https://platform.example.com/api/v1/platform/config/snapshots
curl -s -X POST https://platform.example.com/api/v1/platform/config/snapshots/<id>/rollback
```

**Snapshots and rollback exist only on REST.** There is no gRPC, QUIC or CLI
equivalent. If your operational tooling is gRPC-based, this is the one thing you
have to reach for over HTTP.

---

## Logs, metrics and events

```bash
curl -s https://platform.example.com/api/v1/platform/logs
curl -s https://platform.example.com/api/v1/platform/logs/services
curl -s https://platform.example.com/api/v1/platform/logs/stream
curl -s https://platform.example.com/api/v1/platform/metrics
curl -s https://platform.example.com/api/v1/platform/system
```

`StreamEvents`, `StreamLogs` and `StreamMetrics` are the gRPC streaming
equivalents.

`ListEntityTypes` and `DumpEntityType` (gRPC) enumerate and dump the stored
entity types — a debugging surface, and `DumpEntityType` streams because a dump
is unbounded.

---

## Health, liveness and readiness are three different questions

| Question | Means |
|---|---|
| **Liveness** | The process is alive. Restart it if this fails. |
| **Readiness** | It is ready to serve. Take it out of rotation if this fails, but do not restart it. |
| **Health** | The composite view. |

On QUIC these are `0x00`, `0x01` and `0x02`; on MCP, `platform_health`,
`platform_liveness` and `platform_readiness`.

**Wiring a load balancer to liveness instead of readiness** sends traffic to a
node that is up and not ready. It is a common mistake and the platform gives you
the right probe.

---

## Troubleshooting

**A capability returns 503.**
Not wired in, or the service is stopped. `GET /api/v1/platform/services`.

**A client cannot connect on a transport.**
`GET /api/v1/platform/protocols` — that transport may not be serving.

**A QUIC client gets a liveness response when it asked for something else.**
It sent a sub-opcode at top level. The QUIC opcode space has category opcodes
whose sub-opcodes are carried in the payload, so `0x01` at top level is
`OpLiveness` regardless of what you meant. See [api.md](api.md) §4.

**A QUIC log line names an operation that does not match what happened.**
Two opcode names are dead but still in the name table, so manifest and report
fetches are mislabelled. Trust the handler, not the label.

**A connection dropped with no error.**
It should not — panicking handlers are recovered into an internal-error response
on both QUIC and gRPC specifically so a client never sees a bare EOF. A genuine
bare EOF is a different problem.

**Configuration changed and something broke.**
Roll back to a snapshot. If you did not take one, that is the lesson.

---

## One thing to be aware of

`PlatformDaemon` has 17 RPCs and **16 of them carry no required scope** —
including `Shutdown`, `UpdateConfig` and `StopService`. The gRPC scope catalog
covers 185 of 461 RPCs and the MCP authorization map covers 71 of 449 tools, and
**both default to allow** for anything unlisted.

In practice that means a valid token is close to an administrative credential on
several surfaces. Treat token issuance accordingly until the default is
revisited. The full picture is in [api.md](api.md) §5, and it is raised for the
owner as the largest single question this documentation migration surfaced.

---

## Where to go next

- [cli.md](cli.md) — global flags, the 41 command groups, the six binaries
- [api.md](api.md) — the transport model and the **canonical QUIC
  category-opcode table**
- [architecture.md](architecture.md) — how one daemon serves six transports
- [`docs/gateway/`](../gateway/) — the `gatewayd` binary and the edge role
