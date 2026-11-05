# Component Health — CLI

> **Status: NORMATIVE** · Scope: `platformctl health` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

Read out of `pkg/cli/commands/health.go` and `pkg/cli/commands/root.go` on
2026-08-18.

---

## 1. Command

```
platformctl health    Show platform health status
```

**One verb, no subcommands, no positional arguments.** It is registered directly
on the `platformctl` root (`root.go:163`), not under a command group.

## 2. Flags

| Flag | Short | Type | Default | Required | Meaning |
|---|---|---|---|---|---|
| `--detailed` | `-d` | bool | `false` | no | Print the per-component table as well as the overall verdict |

Without `--detailed` you get the overall verdict **plus a line naming every
component that is not healthy** — its name, its status, and its message. The
full per-component table, healthy components included, needs `--detailed`.

The component list is fetched either way: `--detailed` is passed through to the
RPC as `GetHealthRequest.Detailed`, which the server ignores, and it gates the
table rendering client-side.

The unhealthy lines exist because a bare "Overall Health: DEGRADED" names
nothing, so finding the cause took a second command that an operator had to
know to run. A fleet ran time-unsynced from enrolment that way (#509): the
`ntp` component was reporting `time-unsynced` the whole time, one flag away
from being read.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go`), precedence
**flag > environment > config file > built-in default**:

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**Which verbs work without a server.** `health` is a client verb: it needs a
reachable `platformd`. `--transport embedded` runs the services in-process and
is the only way to use it with no daemon listening.

## 3. Output

`runHealth` calls `daemonsvc.Client.GetHealthDomain(ctx, detailed)` — the
gRPC `PlatformDaemon.GetHealth` RPC — and renders by `--output`:

| `--output` | Rendering |
|---|---|
| `json`, `yaml` | The whole `daemonsvc.HealthInfo` document, components included regardless of `--detailed` |
| `table` | Coloured overall line, then one line per non-healthy component; with `--detailed`, the full `Component / Status / Message` table instead |
| anything else | `cli.ErrInvalidOutputFormat` |

The non-healthy component lines are colour-coded the same way the overall line
is — `unhealthy` renders as an error, everything else that is not healthy as a
warning — and are followed by a pointer to `--detailed`. A component with no
message is still named with its status, so the operator learns WHICH component
is wrong even when it says nothing. A healthy platform prints none of this.

The overall line is colour-coded by status:

| Status | Rendered as |
|---|---|
| `daemonsvc.HealthStatusHealthy` | success (green) |
| `daemonsvc.HealthStatusDegraded` | warning (yellow) |
| `daemonsvc.HealthStatusUnhealthy` | error (red) |
| anything else — in practice `unknown`, which arrives as `daemonsvc.HealthStatusUnspecified` (`"UNKNOWN"`) | info |

The SDK spells the statuses in upper case: `HEALTHY`, `DEGRADED`,
`UNHEALTHY`, `UNKNOWN` (`sdk/go/services/daemon/types.go`). That is what the
overall line prints and what `--output json` carries in `status`.

`--output json` is the form to parse. The `table` renderer is for humans and its
columns are not a stable interface.

**The table shows three columns — `Component`, `Status`, `Message`.**
`ComponentHealth.Details`, the field that carries the actually diagnostic
content (stratum, certificate expiry, listen address, connection counts), is
**not rendered in table form at all**, and `HealthInfo` as returned by the gRPC
projection does not carry it either. No other transport carries it today
([api.md](api.md) §5).

## 4. Exit codes

`0` on success. Non-zero when the RPC fails or the output format is invalid,
with the structured error rendered by the `platformctl` error path. There is no
exit-code encoding of the health verdict: **`platformctl health` exits 0 on an
unhealthy platform.** Script against `--output json` and the `status` field, not
against `$?`.

## 5. Examples

```bash
# Overall verdict only
platformctl health

# Overall verdict plus the per-component table
platformctl health --detailed

# Machine-readable, over the Unix socket
platformctl --transport unix --output json health

# Against a remote daemon
platformctl --server platform.example.com:<grpc-port> --output json health

# No daemon running: run the services in-process
platformctl --transport embedded health --detailed

# Gate a script on the verdict (exit status will NOT do it for you)
test "$(platformctl --output json health | jq -r .status)" = "HEALTHY"
```

## 6. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| A single named component | No CLI verb. Embedded Go (`Daemon.HealthCheckComponent`) only — [api.md](api.md) §3 |
| `ComponentHealth.Details` | No transport carries it — [api.md](api.md) §5 |
| Liveness / readiness probes | REST `GET /health/live` / `/health/ready`, gRPC `PlatformDaemon/Liveness` / `Readiness`, QUIC `OpLiveness` / `OpReadiness`, MCP `platform_liveness` / `platform_readiness` |
| Registering or removing a checker | Embedded Go only (`Daemon.RegisterHealthChecker`) |
| Listing registered checker names | Embedded Go only (`Registry.List`) |

## 7. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so that
requirement is unmet — repo-wide, not only for health. It is recorded here
rather than quietly marked satisfied.
