# Time Synchronization — CLI

> **Status: NORMATIVE** · Scope: `platformctl ntp` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

Every verb and flag below was read out of `pkg/cli/commands/ntp/` on 2026-08-18.

---

## 1. Command group

```
platformctl ntp             Time synchronization status and control
platformctl ntp status      Show the node's clock synchronization state
platformctl ntp sources     List configured time sources
platformctl ntp step        Force an immediate clock correction (operator recovery)
```

Three verbs. **None takes a positional argument, and none defines a local
flag.** Everything is driven by the `platformctl` persistent flags.

The group is registered on the `platformctl` root
(`pkg/cli/commands/root.go:185`).

### Global flags

Precedence is **flag > environment > config file > built-in default**.

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

**Correction to the in-code help text.** The package comment on
`pkg/cli/commands/ntp/ntp.go` says *"the global `--protocol` flag selects REST,
gRPC, QUIC, MCP, or the Unix socket"*, and `newNTPClient` refers to
`--protocol/--endpoint`. **Neither flag exists.** The transport selector is
`--transport` and the address is `--server`. The behaviour described is correct;
the flag names in the comment are not.

**Which verbs work without a server.** All three are client verbs — they go
through `cli.NewBaseCommand` and need a reachable `platformd`.
`--transport embedded` runs the services in-process and is the only way to use
them with no daemon listening. **Note that the embedded transport has no NTP
route** ([api.md](api.md) §3), so `--transport embedded` will not reach the NTP
service.

**Timeout.** Every verb applies a fixed 30-second context deadline
(`defaultCLITimeout`). It is not configurable.

---

## 2. `platformctl ntp status`

Show the node's clock synchronization state: synced flag, stratum, leap status,
current offset, root dispersion, last sync time, mode, and how many configured
sources are reachable.

No flags, no arguments.

```bash
platformctl ntp status
platformctl ntp status -o json
```

Table output (`FIELD` / `VALUE`):

```
FIELD                 VALUE
synced                true
stratum               3
leap status           Normal
offset (s)            0.000114237
root dispersion (s)   0.001204811
root delay (s)        0.004327118
last sync             2026-08-18T09:12:40Z
mode                  both
reference             time-a.example.com
sources               2/3 reachable
anomaly               false
```

Two rendering details that matter when reading the output:

- **`last sync` prints `never`** when the timestamp is zero or negative. An
  unsynchronized node is unambiguous rather than showing an epoch date.
- **`anomaly reason` is only printed when non-empty.** Its absence means no
  anomaly, not a truncated table.
- **`nts name unreachable` and `nts name unresolvable` appear once per
  advertised NTS-KE name clients cannot usefully dial** (#509). The first
  names the name, the address and the allow list that refuses it; the second
  names the name and the resolver's own error. Both are serving-side
  misconfigurations, so `synced` above can be `true` beside either. Their
  absence means there is no finding.

Offsets are rendered with nine decimal places (nanosecond resolution).

With `-o json` or `-o yaml` the raw `platform.v1.NTPStatus` message is printed
instead of the table.

---

## 3. `platformctl ntp sources`

List every configured time source with its selection state, stratum, poll
interval, reachability register, last receive time, and measured offset.

No flags, no arguments.

```bash
platformctl ntp sources
platformctl ntp sources -o json
```

Table columns: `ADDRESS`, `MODE`, `STATE`, `STRATUM`, `POLL`, `REACH`,
`LAST RX`, `OFFSET`.

```
ADDRESS               MODE    STATE      STRATUM  POLL  REACH  LAST RX  OFFSET
time-a.example.com    server  selected   2        64s   255    21s      0.000114237
time-b.example.com    server  combined   2        64s   255    34s      0.000208441
pool.example.net      server  unreachable 0       64s   0      0s       0.000000000
```

Reading it:

- **`STATE`** is chronyd's verdict, expanded from its single-character column:
  `selected` (`*`), `combined` (`+`), `excluded` (`-`), `unreachable` (`?`),
  `falseticker` (`x`), `jittery` (`~`), `unknown` for anything chrony adds
  later.
- **`REACH` is an 8-bit shift register, printed in decimal.** `255` means the
  last eight polls all succeeded; `0` means nothing has been heard from that
  source. Anything in between is a partially reachable source — `127` means the
  most recent poll failed.
- **`POLL` is already in seconds.** chrony reports it as a log2 exponent; the
  CLI decodes it.
- **`falseticker` is the interesting state**: chronyd believes that source
  disagrees with the majority. On a platform where time is a trust primitive,
  a falseticker is worth investigating, not ignoring.

---

## 4. `platformctl ntp step`

Force chronyd to step the clock immediately instead of slewing.

No flags, no arguments.

```bash
platformctl ntp step
```

Prints the post-step status, in the same table as `ntp status`.

**This is an operator recovery action, gated by the `ntp:write` scope** — the
only NTP verb that mutates anything. `status` and `sources` need `ntp:read`.

**It fails when no time source is reachable** rather than moving the clock on
stale data. That failure surfaces as a conflict (gRPC `Aborted`, HTTP 409, QUIC
`StatusAlreadyExists`) with the message
`ntp: no reachable time source (N configured)`.

Think before running it. Stepping the clock moves every validity window on the
node at once: certificates become valid or invalid, tokens expire or un-expire,
and attestation freshness is re-evaluated against the new time. Slewing is the
normal correction path; stepping is for the case where the offset is too large
to slew out in useful time.

---

## 5. Exit codes and errors

`0` on success. Non-zero on failure, with the error wrapped by the command:

| Verb | Wrapper message |
|---|---|
| `status` | `failed to get NTP status` |
| `sources` | `failed to list NTP sources` |
| `step` | `failed to step the clock` |

An unrecognised `--output` value yields `cli.ErrInvalidOutputFormat`.

**`ntp status` exits 0 on an unsynchronized node.** The verdict is in the
`synced` field, not the exit status. Script against `-o json`:

```bash
test "$(platformctl ntp status -o json | jq -r .synced)" = "true"
```

`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface.

---

## 6. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Render or apply `chrony.conf` | Not exposed anywhere. Happens at bring-up (`App.StartNTP`); change the `ntp:` section and restart platformd |
| Run the startup gate on demand | Not exposed. Bring-up only |
| Write the system clock back to the RTC | Not exposed. Set `ntp.rtc.write-back` and let the gate do it |
| Read the cached last status without polling | Embedded Go only (`Service.LastStatus()`) |
| Add, remove or disable a time source at runtime | Not exposed, by design — [architecture.md](architecture.md) §2 |

---

## 7. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so that
requirement is unmet — repo-wide, not only for NTP. The multi-protocol parity
that does exist for this surface is `make integration-test-ntp`.
