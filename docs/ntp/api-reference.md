# NTP (Time Synchronization) API Reference

Time is a trust primitive on this platform. TPM attestation freshness,
ACME (RFC 8555) issuance, DANE/DNSSEC signature windows, and JWT
`exp`/`nbf` are all meaningless against a wrong clock — a node that
boots years slow silently corrupts every one of them.

platformd does **not** implement the NTP protocol. chrony runs as a
packaged OpenRC service; platformd renders `chrony.conf`, manages the
service, polls chrony's control socket for sync state, and exposes that
state over every transport.

One implementation backs all of them: `NTPGRPCService`
(`pkg/api/daemon/ntp_grpc_service.go`) wraps `ntp.Service`
(`pkg/ntp/service.go`) and is registered on gRPC TCP + UDS, dispatched
by the QUIC category handler, mounted by both REST routers, and shared
with the MCP tools — so semantics and error mapping are identical
everywhere.

| Transport | Reference | Entry point |
|-----------|-----------|-------------|
| REST | [api-reference-rest.md](api-reference-rest.md) | `/api/v1/ntp/*` |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | `platform.v1.NTPService` (TCP `:10443`) |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | `0x50` (`OpNTPCategory`) sub-opcodes `0x01`-`0x03` |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | `ntp_status`, `ntp_sources`, `ntp_step` |
| Unix | [api-reference-unix.md](api-reference-unix.md) | `platform.v1.NTPService` over `/run/platformd.sock` |

## Operations

| Operation | Scope | Description |
|-----------|-------|-------------|
| `GetStatus` | `ntp:read` | synced, stratum, leap status, offset, root dispersion/delay, last sync, mode, reachable/total sources, anomaly |
| `ListSources` | `ntp:read` | per-source address, mode, state, stratum, poll interval, reach register, last receive, offset |
| `Step` | `ntp:write` | operator recovery: force an immediate correction. Refused with a conflict when no source is reachable |

## Service resolution

The daemon reads the backend from `App.NTPService`, which
`App.StartNTP` populates only when the configuration carries an `ntp:`
section (`pkg/app/ntp.go`). Following the platform's
explicit-configuration convention, an absent section means platformd
never touches chrony — and every transport then returns a typed
`Unavailable` error ("ntp service is not configured on this node"),
never `Unimplemented`, never a panic.

## Startup gate

`StartNTP` runs **after** network bring-up (`initSDN`) and **before**
TPM/CA initialization. When `consume.startup-gate.block-until-synced`
is true it polls chrony's control socket on a ticker until the clock
converges or the timeout expires:

| `on-timeout` | Behavior |
|--------------|----------|
| `warn-and-continue` (default) | The node boots and the `ntp` health component reports `time-unsynced`, so fleet monitoring surfaces it instead of the drift going unnoticed |
| `fail-startup` | Bring-up aborts with `ErrNTPStartupGate` wrapping `ntp.ErrSyncTimeout` |

## Health

The `ntp` health component (`pkg/api/daemon/ntp_health_checker.go`) is
registered whenever the backend exists:

| Condition | Status | Message |
|-----------|--------|---------|
| Synced, stratum 1-15, no anomaly | healthy | `clock synchronized` |
| Not synchronized | degraded | `time-unsynced` |
| Large correction after the first-boot correction | degraded | `time-unsynced: <reason>` |
| Control socket unreachable | unhealthy | `time-unsynced: <error>` |

## Security invariants

- `serve.listen-networks` is an explicit CIDR allow-list. `0.0.0.0/0`
  and `::/0` are rejected by configuration validation — an open NTP
  server is a reflection-amplification source.
- Consume-only nodes render `port 0`, so they never listen on 123.
- chrony's UDP command port is disabled (`cmdport 0`); the platform
  reads state over the local Unix control socket only.
- Internal control-plane time uses NTS (RFC 8915) with a platform
  CA-issued certificate resolved from `kms://` URIs. A URI that is
  still unresolved when chronyd needs the material on disk is a hard
  error (`ErrUnresolvedNTSMaterial`), never a silent downgrade to
  unauthenticated time.
- `makestep 1.0 3` allows the first three updates to step the clock so a
  node whose RTC is years wrong converges immediately. A large
  correction observed *after* that is flagged as an anomaly rather than
  silently accepted.
- `Step` is gated by `ntp:write` on every transport and refuses when no
  source is reachable.

## Configuration

See [device-templates.md](../device-templates.md#time-synchronization-ntp)
for the full `ntp:` schema and the per-role defaults.

## Testing

```sh
make test-ntp              # unit tests across every transport
make coverage-ntp          # coverage report
make bench-ntp             # benchmarks
make integration-test-ntp  # multi-protocol suite in the devcontainer
```
