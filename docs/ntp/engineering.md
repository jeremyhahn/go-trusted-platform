# Time Synchronization — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/ntp/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

Every identifier below was read out of `pkg/ntp/`, `pkg/app/ntp.go` and
`pkg/api/daemon/` on 2026-08-18.

---

## 1. Package layout

| File | Holds |
|---|---|
| `pkg/ntp/config.go` | `Config` and the whole `ntp:` schema, `Mode`, `TimeoutAction`, validation |
| `pkg/ntp/service.go` | `Service`, `Option`s, `FileSystem`, lifecycle, gate, anomaly detection |
| `pkg/ntp/control.go` | `Controller`, `CommandRunner`, `Tracking`, `chronyc` CSV parsing |
| `pkg/ntp/chronyconf.go` | `Paths`, `DefaultPaths`, `Render`, `ManagedHeader` |
| `pkg/ntp/types.go` | `Status`, `Source`, `SourceState`, `SourceMode`, thresholds |
| `pkg/ntp/errors.go` | 22 typed errors |

## 2. Exported surface

### Constructor and options

```go
func NewService(config *Config, opts ...Option) (*Service, error)
```

Returns `ErrNilConfig` for a nil config, and the validation error for a
malformed one. **Validation happens at construction**, so a bad `ntp:` section
is rejected before anything touches the host.

| Option | Overrides | Production default |
|---|---|---|
| `WithController(Controller)` | the chrony control client | `NewController(paths.CommandSocket, runner)` |
| `WithRunner(CommandRunner)` | the system command runner | `execRunner{}` (`os/exec`) |
| `WithFileSystem(FileSystem)` | filesystem access | `osFileSystem{}` |
| `WithPaths(Paths)` | the chrony filesystem layout | `DefaultPaths()` |
| `WithServiceName(string)` | the OpenRC service name | `DefaultServiceName` = `"chronyd"` |
| `WithLogger(*slog.Logger)` | the logger | `slog.Default()` |
| `WithPollInterval(time.Duration)` | the startup-gate poll cadence | `DefaultPollInterval` = `2s` |

The options exist so unit tests substitute the runner, filesystem and control
client. **Production callers use the defaults**; `pkg/app/ntp.go` passes only
`WithLogger`.

### Service methods

| Method | Contract |
|---|---|
| `Config() *Config` | The configuration as given |
| `Mode() Mode` | `serve`, `consume`, or `both` |
| `Apply(ctx) error` | Render, enable, restart-if-changed. `ErrDisabled` when inactive |
| `Status(ctx) (*Status, error)` | Poll `tracking` + `sources`. `ErrDisabled` when inactive |
| `Sources(ctx) ([]Source, error)` | Poll `sources`. `ErrDisabled` when inactive |
| `Step(ctx) (*Status, error)` | Refuse if no source is reachable, else `makestep` and re-`Status` |
| `WaitForSync(ctx) error` | Block until synced or the gate expires. Returns nil immediately when the gate is disabled |
| `LastStatus() *Status` | The last observed status without contacting chronyd. **nil before the first successful poll** |

### Interfaces (the test seams)

```go
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type Controller interface {
	Tracking(ctx context.Context) (*Tracking, error)
	Sources(ctx context.Context) ([]Source, error)
	MakeStep(ctx context.Context) error
}

type FileSystem interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
}
```

`NewController(socket string, runner CommandRunner) Controller` returns the
production `chronyc` implementation; a nil runner falls back to `os/exec`.

### Rendering

```go
func Render(cfg *Config, paths Paths) (string, error)
func DefaultPaths() Paths
const ManagedHeader = "# Managed by go-trusted-platform (pkg/ntp). Do not edit by hand."
```

`Render` re-validates and refuses a disabled config
(`ErrRenderFailed{Cause: ErrDisabled{}}`), so a caller cannot render a file the
service would refuse to apply.

### Types

`Status` — the platform's view of chronyd's tracking state:

| Field | Type | JSON | Notes |
|---|---|---|---|
| `Synced` | `bool` | `synced` | chronyd is disciplining the clock |
| `Stratum` | `uint32` | `stratum` | `0` = unsynchronized, `16` = unusable |
| `LeapStatus` | `string` | `leap_status` | `"Normal"`, `"Insert second"`, `"Delete second"`, `"Not synchronised"` |
| `OffsetSeconds` | `float64` | `offset_seconds` | Positive = system clock ahead of reference |
| `RootDispersion` | `float64` | `root_dispersion` | Bounds the maximum error |
| `RootDelay` | `float64` | `root_delay` | |
| `LastSync` | `time.Time` | `last_sync` | Zero when never |
| `Mode` | `string` | `mode` | Echoes the configured role |
| `ReferenceID` | `string` | `reference_id` | chronyd's hex reference id |
| `ReferenceName` | `string` | `reference_name` | |
| `SourcesReachable` | `uint32` | `sources_reachable` | |
| `SourcesTotal` | `uint32` | `sources_total` | |
| `Anomaly` | `bool` | `anomaly` | Latched, see §6 |
| `AnomalyReason` | `string` | `anomaly_reason,omitempty` | |

```go
func (s *Status) Healthy() bool {
	return s.Synced && !s.Anomaly && s.Stratum > UnsyncedStratum && s.Stratum < MaxStratum
}
```

**`Healthy()` is the single definition of "this node's clock can be trusted."**
Do not re-derive it from the fields.

`Source` — one configured source: `Address`, `Mode`, `State`, `Stratum`,
`PollSeconds`, `Reach`, `LastRxSeconds`, `OffsetSeconds`, `Reachable`.

| Vocabulary | Values | Parsed from |
|---|---|---|
| `SourceState` | `selected`, `combined`, `excluded`, `unreachable`, `falseticker`, `jittery`, `unknown` | chronyc column `*`, `+`, `-`, `?`, `x`, `~` |
| `SourceMode` | `server`, `peer`, `refclock`, `unknown` | chronyc column `^`, `=`, `#` |

Both parsers are map lookups and both fall back to `unknown` for a value chrony
adds in future. **They never fail.**

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `LeapNotSynchronised` | `"Not synchronised"` | The primary "am I synchronized?" signal |
| `UnsyncedStratum` | `0` | chronyd has no reference |
| `MaxStratum` | `16` | First stratum meaning "unusable" |
| `LargeStepThreshold` | `1 * time.Second` | Post-convergence correction that is an anomaly |
| `DefaultGateTimeout` | `120 * time.Second` | Applied when `startup-gate.timeout` is omitted |
| `DefaultLocalStratum` | `10` | Orphan-mode stratum when `serve.local-stratum` is omitted |
| `DefaultServiceName` | `"chronyd"` | |
| `DefaultPollInterval` | `2 * time.Second` | Startup-gate poll cadence |

## 3. Configuration

The `ntp:` section. **A nil `*Config` means the section is absent and platformd
leaves chrony completely alone.**

```yaml
ntp:
  enabled: true
  mode: both                       # serve | consume | both
  consume:
    upstream:
      - address: time-a.example.com
        pool: false
        prefer: true
        iburst: true
        nts: true
      - address: pool.example.net
        pool: true
        iburst: true
    startup-gate:
      block-until-synced: true
      timeout: 120s                # omitted ⇒ DefaultGateTimeout
      on-timeout: warn-and-continue # warn-and-continue | fail-startup
    orphan-fallback: true
  serve:
    listen-networks:               # explicit CIDRs; NEVER 0.0.0.0/0 or ::/0
      - 10.20.0.0/16
    local-stratum: 10              # 1..15; omitted ⇒ DefaultLocalStratum
    nts:
      enabled: true
      cert-uri: kms://platform/ntp/nts-server.crt
      key-uri: kms://platform/ntp/nts-server.key
      server-names:                # DNS names clients dial this NTS-KE
        - cp.example.internal      # server as; DNS only, never an address
      port: 4460                   # NTS-KE TCP port; omitted ⇒ DefaultNTSKEPort
  rtc:
    write-back: true
```

### Keys

| Key | Type | Required | Default |
|---|---|---|---|
| `ntp.enabled` | bool | — | `false` (zero value) |
| `ntp.mode` | `serve` \| `consume` \| `both` | when enabled | none — `ErrInvalidMode` if unset |
| `ntp.consume` | object | when the mode consumes | `ErrMissingConsumeSection` |
| `ntp.consume.upstream[].address` | string | yes per entry | `ErrEmptyUpstreamAddress` |
| `ntp.consume.upstream[].pool` | bool | — | `false` → `server` directive; `true` → `pool` |
| `ntp.consume.upstream[].prefer` | bool | — | `false` |
| `ntp.consume.upstream[].iburst` | bool | — | `false` |
| `ntp.consume.upstream[].nts` | bool | — | `false` |
| `ntp.consume.startup-gate.block-until-synced` | bool | — | `false` |
| `ntp.consume.startup-gate.timeout` | duration | — | `120s` |
| `ntp.consume.startup-gate.on-timeout` | `warn-and-continue` \| `fail-startup` | — | `warn-and-continue` |
| `ntp.consume.orphan-fallback` | bool | — | `false` |
| `ntp.serve` | object | when the mode serves | `ErrMissingServeSection` |
| `ntp.serve.listen-networks` | []CIDR | when the mode serves | `ErrNoListenNetworks` if empty |
| `ntp.serve.local-stratum` | int 1–15 | — | `10` |
| `ntp.serve.nts.enabled` | bool | — | `false` |
| `ntp.serve.nts.cert-uri` | secret ref | when NTS serving | `ErrMissingNTSMaterial` |
| `ntp.serve.nts.key-uri` | secret ref | when NTS serving | `ErrMissingNTSMaterial` |
| `ntp.serve.nts.server-names` | []string | — | empty; DNS names only, `ErrInvalidNTSServerName` |
| `ntp.serve.nts.port` | int 1–65535 | — | `4460` (IANA NTS-KE); `ErrInvalidNTSKEPort` |
| `ntp.rtc.write-back` | bool | — | `false` |

**There are no NTP environment variables.** The section is YAML only; there is
no `PLATFORM_NTP_*` override anywhere in the code. Precedence is whatever the
platform config loader applies to the file as a whole
(`conventions/configuration.md`).

### Derived accessors

| Accessor | Returns |
|---|---|
| `Active()` | `c != nil && c.Enabled` |
| `Mode.Serves()` | mode is `serve` or `both` |
| `Mode.Consumes()` | mode is `consume` or `both` |
| `GateTimeout()` | the configured timeout, or `DefaultGateTimeout` when nil/zero/negative |
| `GateEnabled()` | active **and** consuming **and** `block-until-synced` |
| `TimeoutAction()` | the configured action, or `ActionWarnAndContinue` |
| `RTCWriteBack()` | `rtc.write-back` |
| `LocalStratum()` | the configured stratum, or `DefaultLocalStratum` when unset/zero |
| `NTSServing()` | active **and** serving **and** `serve.nts.enabled` |
| `NTSKEPort()` | the configured `serve.nts.port`, or `DefaultNTSKEPort` when unset/zero |

### Validation rules

`Config.Validate()` — **a disabled or absent section always validates**, because
it does nothing.

Consume side (`validateConsume`):
- `consume` must be present.
- `upstream` non-empty **or** `orphan-fallback: true`, else `ErrNoUpstream`.
- each address non-blank (`ErrEmptyUpstreamAddress`).
- each address free of ` `, `\t`, `\r`, `\n`, `#` (`ErrInvalidUpstreamAddress`)
  — a `chrony.conf` injection guard.
- `on-timeout`, when present, must be a known action
  (`ErrInvalidTimeoutAction`).
- when the gate blocks, `timeout` must not be negative
  (`ErrInvalidGateTimeout`).

Serve side (`validateServe`):
- `serve` must be present.
- `listen-networks` non-empty (`ErrNoListenNetworks`).
- no entry may be `0.0.0.0/0` or `::/0`, and no parsed prefix may have
  `Bits() == 0` (`ErrUnrestrictedListenNetwork`).
- every entry must parse as a `netip.Prefix` (`ErrInvalidListenNetwork`).
- `local-stratum`, when non-zero, must be 1–15 (`ErrInvalidLocalStratum`).
- when NTS is enabled, both `cert-uri` and `key-uri` must be non-blank
  (`ErrMissingNTSMaterial`).
- when NTS is enabled, every `server-names` entry must be a bare DNS name:
  non-empty, not an IP address, and free of ` `, `\t`, `\r`, `\n`, `#`, `/`
  and `:` (`ErrInvalidNTSServerName`). An address is refused rather than
  accepted, because platform certificates carry DNS SANs only and a client
  configured with an address could never validate the handshake — see
  §"Naming the NTS server" below. The list is not validated when NTS
  serving is off: the field is inert there and failing startup over an
  unused value would be the worse outcome.

### Naming the NTS server

`Config.NTSServerNames()` returns the trimmed, non-empty entries on a node
that actually serves NTS, and nothing otherwise.

RFC 8915 key establishment is a TLS handshake, and a chronyd client verifies
the NTS-KE certificate against **the name in its own `server` directive**.
Platform certificates are DNS-only by standing ruling, so:

- a consuming node's `ntp.consume.upstream[].address` with `nts: true` must
  be a DNS name the served certificate carries. An IP address there can
  never validate — chronyd retries the handshake indefinitely, the node
  never synchronises, and every boot burns the full startup gate. That is
  the failure #509 measured on the fleet.
- a serving node lists those names in `ntp.serve.nts.server-names`.
  `pkg/app` puts them in the certificate's SANs (see §"NTS certificate
  identity" below); this package only reads them back for validation.

`Render` is unaffected: it writes the configured address verbatim, and the
injection guard (`ErrInvalidUpstreamAddress`) is what keeps a name from
carrying extra directives.

### Reconciling advertised names with the allow list

`serve.nts.server-names` and `serve.listen-networks` are enforced against
different things — the name the client wrote, and the packet's source address
— and nothing ties them together. A name that resolves outside the allow list
produces a successful handshake followed by refused time. `pkg/ntp/servename.go`
is the check:

| Symbol | Contract |
|---|---|
| `ServeNameFindingKind` | `ServeNameUnreachable` (`"nts-name-unreachable"`) and `ServeNameUnresolvable` (`"nts-name-unresolvable"`) — the stable markers monitoring alerts on, alongside `TimeUnsyncedMessage` |
| `ServeNameFinding` | the kind, the name, and then whichever half applies: the resolved address plus the rendered allow list for unreachable, the resolver's own error for unresolvable. `String()` is the operator sentence the health message, the wire and the log line share, and it does NOT repeat the kind — callers prefix that so the marker appears once |
| `ServeNameResolution` | one name's lookup outcome: `Addrs` and `Err`. The two finding kinds are built from these two halves |
| `Config.EvaluateServeNames(map[string]ServeNameResolution)` | pure. A name ABSENT from the map yields nothing — nothing was attempted for it. A name that was looked up and failed, or answered with no addresses, is `ServeNameUnresolvable`. A name whose addresses ALL fall outside every parseable allow prefix is `ServeNameUnreachable`. An unparseable allow entry is skipped, not counted as a non-match |
| `NameResolver` | `LookupNetIP(ctx, network, host)`. `*net.Resolver` satisfies it; `DefaultNameResolver()` returns the host resolver |
| `Service.CheckServeNames(ctx, resolver)` | resolves every advertised name, logs each finding at WARN with its kind, and latches the set behind `Service.serveNames` (an atomic pointer, like the anomaly state). Findings replace the previous set wholesale, so a reconciled zone or a recovered resolver clears the component at the next provisioning or renewal |
| `Service.ServeNameFindings()` | the latched copy; `Status` reads it without taking the service lock |

**Why two kinds and not one.** An unresolvable name has no address, so
reporting it as an allow-list refusal would assert something the data does not
support — the same conflation the collector avoids for `time_synced`. Both are
findings because both leave clients unable to dial the name: on this fleet
nodes forward the internal zone through the control plane, so a name the
control plane cannot resolve is one no node can reach. They have different
fixes (publish the record versus reconcile the allow list), so they carry
different markers and the health message never collapses them.

`Status.ServeNameFindings` carries them to every transport and to the `ntp`
health component. It does **not** affect `Status.Healthy()`: the clock may be
fine and the fault is on the serving side.

Callers, both in `pkg/app`:

- `App.StartNTP` → `App.CheckNTSServeNames`, immediately after `Apply` — the
  allow list chronyd will enforce has just been rendered.
- `App.reissueNTSCertificate` → the same, after a successful deploy — the
  certificate just installed advertises the names.

`App.CheckNTSServeNames` is a no-op without an NTP service or without NTS
serving, is non-fatal by construction, and takes its resolver from
`App.ntsNameResolver` (nil ⇒ the host resolver; tests substitute their own).

One timing note: `StartDNS` runs before `StartNTP` in `App.Init`, so a
control plane serving its own internal zone can resolve its own names by the
time the check runs. A resolver that is nonetheless unavailable at that
instant produces an `nts-name-unresolvable` finding that is TRUE at that
instant and clears at the next renewal or platformd restart.

### NTS certificate identity

Certificate issuance is `pkg/app`'s, not this package's
([architecture.md](architecture.md) §3). Two functions there read the
configuration above:

| Function | Answers |
|---|---|
| `App.ntsCertificateNames()` | the CN and the full DNS SAN set to ISSUE: this node's hostname, its FQDN, then every configured server name, deduplicated. The CN stays the FQDN, so the subject is unchanged from earlier releases |
| `App.ntsExpectedHostnames()` | the names to VERIFY the served certificate against: the FQDN and every configured server name. Deliberately narrower — the bare hostname is issued because it costs nothing, but nothing dials it, and requiring it would leave the renewal target permanently due against a CA that normalises SANs |

`App.ntsServedCertInvalid` verifies the certificate chronyd is actually
serving against **every** expected name. A certificate valid for the node's
own FQDN but missing the alias nodes dial is one every client rejects, so it
is due for reissue rather than healthy until expiry.

## 4. Rendered `chrony.conf`

`Render` emits, in order:

1. `ManagedHeader` and a `# mode: <mode>` line.
2. **Upstream** (consuming only): one `server`/`pool` line per source with
   `iburst`, `prefer`, `nts` flags appended in that order.
3. **Discipline**: `driftfile <paths.DriftFile>`, then `makestep 1.0 3`, then
   `rtcsync` when `rtc.write-back`.
4. **Server side**:
   - not serving ⇒ `port 0`, and nothing else.
   - serving ⇒ one `allow <cidr>` per entry; `local stratum <n>` when
     `orphan-fallback`; `ntsservercert` / `ntsserverkey` / `ntsdumpdir` /
     `ntsport <NTSKEPort()>` when NTS serving. No NTS-KE `bindaddress` is
     rendered, so chronyd accepts NTS-KE on every local address; the renewal
     sweep reads the served certificate over loopback on the same port.
5. **Control**: `bindcmdaddress <paths.CommandSocket>`, `cmdport 0`.

`firstBootStepUpdates = 3` and `firstBootStepThresholdSeconds = "1.0"` are the
`makestep` arguments and are unexported constants, not configuration.

### Paths

`Paths` is a struct of platform layout constants, **not part of the YAML
schema**, overridable only through `WithPaths` in tests:

| Field | `DefaultPaths()` | Mode |
|---|---|---|
| `ConfigFile` | `/etc/chrony/chrony.conf` | `0644` — carries no secrets |
| `DriftFile` | `/var/lib/chrony/chrony.drift` | chronyd's |
| `NTSMaterialDir` | `/etc/chrony/nts.d` | dir `0755` |
| `NTSDumpDir` | `/var/lib/chrony` | dir `0755` |
| `CommandSocket` | `/run/chrony/chronyd.sock` | chronyd's |

`NTSMaterialDir` is a versioned store: each deploy writes a fresh
content-addressed version directory (`v-<sha256[:16]>/nts-server.crt`
`0644`, `nts-server.key` `0600`) and atomically retargets the `current`
symlink — the single commit point, so chronyd can never observe a
certificate from one version beside a key from another. The
`Paths.NTSCertFile()` / `Paths.NTSKeyFile()` methods return the stable
`current/`-relative paths rendered into chrony.conf; the superseded version
directory is removed after a successful swap.

`Service.RotateNTSMaterial` takes the renewed private key as a
`*memguard.MemoryEnclave`, not a `[]byte`: the plaintext is borrowed inside
`Open` for the store write and the digest that supersedes it, so no
unprotected copy of a rotated key exists in the service at any point. A nil,
empty, or destroyed enclave is rejected — `ErrNTSKeyEnclaveUnavailable`
fails the rotation closed rather than publishing an empty key file.

## 5. Error semantics

All 29 are struct types. Match with `errors.As` (or `errors.Is` on a zero-value
struct, which the daemon does for `ErrDisabled{}`). Those wrapping a cause
implement `Unwrap`.

### Configuration (construction time, fatal to bring-up)

| Error | Fields | Condition |
|---|---|---|
| `ErrNilConfig` | — | `NewService(nil, …)` |
| `ErrInvalidMode` | `Mode` | Not `serve`/`consume`/`both` |
| `ErrMissingConsumeSection` | `Mode` | Mode consumes, section absent |
| `ErrMissingServeSection` | `Mode` | Mode serves, section absent |
| `ErrNoUpstream` | — | No upstream and no orphan fallback |
| `ErrEmptyUpstreamAddress` | `Index` | Blank address |
| `ErrInvalidUpstreamAddress` | `Address` | Whitespace or `#` in the address |
| `ErrNoListenNetworks` | — | Serving with an empty allow-list |
| `ErrInvalidListenNetwork` | `Network`, `Cause` | Unparseable CIDR |
| `ErrUnrestrictedListenNetwork` | `Network` | `0.0.0.0/0`, `::/0`, or `Bits() == 0` |
| `ErrInvalidLocalStratum` | `Stratum` | Outside 1–15 |
| `ErrMissingNTSMaterial` | `Field` | NTS enabled without cert or key |
| `ErrInvalidNTSServerName` | `Name`, `Reason` | A `serve.nts.server-names` entry that cannot become a DNS SAN |
| `ErrInvalidNTSKEPort` | `Port` | `serve.nts.port` outside 1–65535 |
| `ErrInvalidTimeoutAction` | `Action` | Unknown `on-timeout` |
| `ErrInvalidGateTimeout` | `Seconds` | Negative gate timeout |

A serve-name/allow-list mismatch is deliberately **not** an error: it is a
health finding. Failing startup or renewal over it would take a control plane
offline for a condition an operator must resolve by a policy decision the
platform does not own.

### Runtime

| Error | Fields | Condition | Maps to |
|---|---|---|---|
| `ErrDisabled` | — | Section absent or disabled | `Unavailable` / 503 |
| `ErrRenderFailed` | `Cause` | Template render failed | `Internal` / 500 |
| `ErrWriteConfigFailed` | `Path`, `Cause` | `chrony.conf` or NTS material unwritable | `Internal` / 500 |
| `ErrUnresolvedNTSMaterial` | `Field`, `Value` | Value still a `kms://`/`secret://`/`file://` reference | `Internal` / 500 |
| `ErrServiceCommandFailed` | `Service`, `Action`, `Output`, `Cause` | `rc-update` / `rc-service` failed | `Internal` / 500 |
| `ErrControlUnavailable` | `Command`, `Output`, `Cause` | `chronyc` failed — usually chronyd is down | `Unavailable` / 503 |
| `ErrMalformedControlOutput` | `Command`, `Line`, `Want`, `Got` | CSV had too few fields | `Internal` / 500 |
| `ErrSyncTimeout` | `Seconds` | The startup gate expired | `DeadlineExceeded` / 504 |
| `ErrNoReachableSource` | `Total` | `Step` with nothing reachable | `Aborted` / **409** |
| `ErrStepRefused` | `Output` | chronyd answered `makestep` with `500 Failure`: it does not control the clock (`-x`, or no `CAP_SYS_TIME`) | `Aborted` / **409** |
| `ErrRTCWriteFailed` | `Output`, `Cause` | `hwclock --systohc` failed | never surfaced — logged only |
| `ErrInvalidNTSVersionLink` | `Target` | The material store's `current` link points at something the store did not generate | `Internal` / 500 |
| `ErrRotatedNTSMaterialLost` | `Cause` | The published pair no longer matches the last rotation; restart to re-resolve from the KMS | `Internal` / 500 |
| `ErrNTSKeyEnclaveUnavailable` | `Cause` | A rotation's key enclave was destroyed or never allocated | `Internal` / 500 |

Plus `daemon.ErrNTPNotConfigured` (`"ntp service is not configured on this
node"`), returned by every transport when the backend is nil — see §8.

### Fail-closed paths

- **A malformed `ntp:` section refuses to start the node.** `App.StartNTP`
  returns the construction error, which is fatal. An operator configuration bug
  is not a transient condition.
- **An unresolved NTS reference fails the NTP service.**
  `ErrUnresolvedNTSMaterial` is returned from `Apply` rather than writing the
  literal URI string and letting chronyd serve unauthenticated time. Serving
  time without NTS when the operator asked for NTS is the silent downgrade this
  prevents.
- **`Step` refuses without a reachable source.** `ErrNoReachableSource` rather
  than stepping the clock toward stale data.
- **An unconfigured backend returns `Unavailable`, never `Unimplemented` and
  never a panic.** "Not configured" and "broken" are different answers.
- **A missing `ntp:` section is a no-op, not a default.** The platform does not
  install time synchronization a deployment did not ask for.

### Not fail-closed, on purpose

- **`Apply` failure does not stop bring-up.** `StartNTP` logs
  `"NTP: failed to configure chrony: %v"` and returns nil. The node boots; the
  health component reports the degraded state.
- **The gate default is warn-and-continue.** See
  [architecture.md](architecture.md) §2.
- **RTC write-back failure is logged, not fatal.** The system clock is already
  correct.
- **Source enumeration failure does not fail `Status`.** Counts come back zero
  and a debug line is logged.

## 6. Invariants

1. **A nil or disabled config means chrony is never touched.** Every method
   short-circuits on `Config.Active()`.
2. **`Apply` is idempotent.** It byte-compares the rendered text against the
   existing file; unchanged **and** the service reports running ⇒ no restart. A
   platformd restart never disturbs a converged clock.
3. **`rc-update add` is always run**, before the change check. It is idempotent
   in OpenRC, so this is safe on every boot and guarantees the service survives
   reboot even when the config did not change.
4. **`Validate()` runs twice** — once in `NewService`, once inside `Render`. A
   caller cannot render a configuration the service would refuse.
5. **The anomaly latch is one-way.** `detectAnomaly` ignores the first
   successful sync (a years-wrong RTC being repaired is expected), then flags
   the first correction exceeding `LargeStepThreshold` and **never clears it**
   for the life of the process. Restart platformd to clear it. This is
   deliberate: a transient hostile correction must not vanish from the health
   surface a minute later.
6. **`firstSyncDone` and `anomaly` are atomics, `lastStatus` is an
   `atomic.Pointer[Status]`.** Status reads never take a lock.
7. **`Status` always re-polls.** There is no cache on that path.
   `LastStatus()` is the explicit cached read and returns nil before the first
   successful poll.
8. **`Healthy()` is the only trust predicate.** `Synced && !Anomaly && 0 <
   Stratum < 16`.
9. **Every host interaction goes through `CommandRunner`.** Nothing in the
   package calls `os/exec` directly except `execRunner`.
10. **CSV parsing is total.** `parseUint32`, `parseInt64`, `parseFloat` and
    `parseUnixFloat` return zero values on malformed input rather than
    erroring; only a **short record** produces `ErrMalformedControlOutput`
    (`tracking` needs 14 fields, `sources` needs 10). A blank line in `sources`
    output is skipped.
11. **`chronyc` is invoked with `-c -n`.** `-c` selects CSV; `-n` suppresses
    reverse DNS so a broken resolver never stalls a status poll.
12. **Poll intervals are decoded from chrony's log2 form.**
    `pollIntervalSeconds` returns `1 << exponent`, and `0` for an exponent
    outside 0–31.
13. **The startup gate polls on a ticker, never `time.Sleep`.**
    `WaitForSync` selects over `gateCtx.Done()` and `ticker.C`.

## 7. The API-layer contract

`pkg/api/daemon/ntp_service.go` defines the seam every transport shares:

```go
type NTPBackend interface {
	Status(ctx context.Context) (*ntp.Status, error)
	Sources(ctx context.Context) ([]ntp.Source, error)
	Step(ctx context.Context) (*ntp.Status, error)
}

var _ NTPBackend = (*ntp.Service)(nil)
```

`NTPGRPCService` (`pkg/api/daemon/ntp_grpc_service.go`) wraps it and is
registered on **both** the TCP gRPC server and the Unix-socket gRPC server, and
is handed to the QUIC category handler, both REST routers and the MCP tool
registry. `SetBackend` wires it after construction; `Backend()` reads it back —
`registerHealthCheckers` uses `Backend()` to decide whether to register the
`ntp` health component.

`requireBackend()` returns `codes.Unavailable` with
`ErrNTPNotConfigured{}.Error()` when the backend is nil.

### Projections

`ntpStatusToPb` maps `*ntp.Status` → `platform.v1.NTPStatus`. Note two field
renames on the wire: `LastSync` (a `time.Time`) becomes `last_sync_unix` (an
`int64`, **0 when never**), and `ReferenceID` becomes `reference_id`.
`ntpSourcesToPb` maps `[]ntp.Source` → `[]*platform.v1.NTPSource`, stringifying
`Mode` and `State`.

### Error mapping — `ntpErrToGRPC`

| Domain error | gRPC code |
|---|---|
| `ntp.ErrDisabled`, `daemon.ErrNTPNotConfigured` | `Unavailable` |
| `ntp.ErrNoReachableSource` | `Aborted` |
| `ntp.ErrStepRefused` | `Aborted` |
| `ntp.ErrControlUnavailable` | `Unavailable` |
| `ntp.ErrMalformedControlOutput` | `Internal` |
| `ntp.ErrSyncTimeout` | `DeadlineExceeded` |
| anything else | `Internal` |

**`Aborted` is chosen for `ErrNoReachableSource` specifically because it maps to
HTTP 409 Conflict** in both REST listeners
(`protorest`: `case codes.AlreadyExists, codes.Aborted:` → 409;
`pkg/api/rest/ntp_handlers.go`: `codes.Aborted: http.StatusConflict`). That is
the documented REST contract for "you asked me to step and there is nothing to
step towards."

**Correction:** the doc comment on `NTPRouter.step`
(`pkg/webservice/v1/rest/ntp/router.go`) says protorest maps the service's
*`FailedPrecondition`* status onto 409. It does not — `FailedPrecondition` maps
to **400**, and the service returns `Aborted`. The behaviour (409) is right; the
comment names the wrong code. Recorded here; the comment is the defect.

QUIC statuses come from `ntpQUICStatus` (`pkg/api/daemon/quic_ntp.go`), which
maps `Aborted` → `StatusAlreadyExists`, the wire's conflict status. Full table
in [api.md](api.md) §5.

## 8. Bring-up policy

`pkg/app/ntp.go`:

```go
type ErrNTPStartupGate struct{ Cause error }   // Unwrap() returns the ntp.ErrSyncTimeout
```

`App.StartNTP(ctx)`:

1. `!app.NTPConfig.Active()` ⇒ return nil. Nothing happens.
2. `newNTPService(...)` — a construction error is **returned** (fatal).
3. `app.NTPService = concrete` — the API-layer backend. The test seam
   deliberately leaves it nil when a substitute is supplied, so **no fake ever
   reaches a transport**.
4. `Apply` failure ⇒ log at error, return nil (boot continues).
5. `WaitForSync` failure ⇒ `handleNTPGateTimeout`.

`handleNTPGateTimeout` returns `ErrNTPStartupGate` only when the cause is an
`ntp.ErrSyncTimeout` **and** `TimeoutAction() == ActionFailStartup`. Any other
cause is logged at error and swallowed. Warn-and-continue logs at warn, naming
the four affected subsystems.

## 9. Persistence

No database, no schema, no migration. The durable artefacts are files, listed in
[architecture.md](architecture.md) §4. Compatibility rule: **`chrony.conf` is
regenerated, never migrated.** A file carrying `ManagedHeader` is overwritten
whenever the render output differs.

## 10. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/ntp/config_test.go` | Every validation rule and accessor default |
| Unit | `pkg/ntp/chronyconf_test.go`, `templates_test.go` | Rendered directives per mode; the allow-list; `port 0`; `cmdport 0` |
| Unit | `pkg/ntp/control_test.go` | CSV parsing, short records, poll-interval decoding, state/mode vocabularies |
| Unit | `pkg/ntp/service_test.go` | Apply idempotency, gate policy, anomaly latch, `Step` refusal, RTC write-back |
| Unit | `pkg/ntp/errors_test.go` | Message formatting, nil-cause tolerance, `Unwrap` |
| Unit | `pkg/cli/commands/ntp/*_test.go` | Command wiring against a fake client |
| Unit | `pkg/webservice/v1/rest/ntp/*_test.go` | Route registration and status mapping |
| Unit | `pkg/api/daemon/ntp_health_checker_test.go` | Health projection of each status |
| Bench | `pkg/ntp/benchmark_test.go` | `make bench-ntp` |
| Integration | devcontainer, `make integration-test-ntp` | Multi-protocol parity against a real chronyd (see below) |

Make targets (`Makefile`):

```sh
make test-ntp              # unit tests across every transport
make coverage-ntp          # coverage report → build/coverage/ntp.html
make bench-ntp             # benchmarks
make integration-test-ntp  # multi-protocol suite in the devcontainer
```

`NTP_TAGS` pins the build-tag set the surface needs:
`iam rest quic mcp cluster codec_json codec_msgpack codec_cbor`.

**The integration chronyd.** `test/integration/config.yaml` carries an `ntp:`
section (consume mode, one loopback upstream, no startup gate), so the shared
platformd renders `/etc/chrony/chrony.conf` and serves the NTP surface on every
transport. The devcontainer is Debian without OpenRC, so platformd's
`rc-update add chronyd` fails and is logged; the runner
(`run-integration-tests.sh` `start_chronyd`) then starts `chronyd -x` on the
rendered file. `-x` keeps chronyd off the system clock, which the container
shares with the CI host. Before it, `start_ntp_reference` starts a second
`chronyd -x` that serves the loopback upstream as a `local stratum 8` reference
with no command socket, and the runner waits (`chronyc waitsync`) until the
daemon's chronyd has synchronised to it. The reference's config is
`/etc/chrony/reference.conf` and its pid file `/run/chrony/reference.pid`: the
chrony AppArmor profile loaded on the CI host also confines chronyd in the
privileged container and lets it read only `/etc/chrony/` and write only
`/run/chrony/`, so a config elsewhere fails with `Permission denied` even for
root. A reference that does not start stops the run (`FATAL`). Without that source the clock never
converged, the `ntp` component stayed degraded, and every transport's aggregate
health answered not-healthy (#949). Both chronyds run `-x`, so a `Step` the ntp
suite issues moves only chronyd's view, never the clock: no suite can move a
clock.

**Fault-injection seams.** `WithRunner` fakes `chronyc`/`rc-service` output
(including malformed CSV and non-zero exit), `WithFileSystem` keeps rendering
in memory, `WithController` bypasses `chronyc` entirely, and `WithPollInterval`
shortens the gate. **No unit test touches the real clock, the real RTC, or a
real chronyd.**

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 11. Observability

### Log events (`slog`, from `pkg/ntp` and `pkg/app`)

| Level | Event | Fields |
|---|---|---|
| info | `ntp: chrony restarted with platform-rendered configuration` | `service`, `config`, `mode` |
| debug | `ntp: chrony configuration unchanged and daemon running` | `config` |
| info | `ntp: clock synchronized` | `stratum`, `offset_seconds`, `reference` |
| debug | `ntp: waiting for chrony control socket` | `error` |
| **warn** | `ntp: large clock correction after initial sync` | `offset_seconds`, `reference` |
| debug | `ntp: source enumeration failed` | `error` |
| info | `ntp: system time written back to the hardware clock` | |
| warn | `ntp: hardware clock write-back failed` | `error` |
| error | `NTP: failed to configure chrony: %v` | |
| warn | `NTP: <timeout> — continuing startup with the node flagged time-unsynced; …` | |

**`ntp: large clock correction after initial sync` is the one to alert on.** It
is the only log line that means "a failing oscillator or a hostile time source."

gRPC-side: `NTPGRPCService` logs `ntp status query failed`, `ntp source
enumeration failed`, and — at info — `ntp clock stepped by operator request`
with `stratum` and `offset_seconds`.

### Metrics

None emitted from `pkg/ntp`. Time state is observed by polling `GetStatus` or
by reading the `ntp` health component's `Details`.

### Audit

`Step` is the only mutation and it is logged at info by the gRPC service, on
every transport, since all of them route through that one implementation. There
is no separate audit record type for NTP.

### The health component

`NTPServiceHealthChecker` (`pkg/api/daemon/ntp_health_checker.go`), registered
as `ntp` when `d.ntpGRPCService.Backend() != nil`:

| Condition | Status | Message |
|---|---|---|
| `Status.Healthy()` | `healthy` | `clock synchronized` |
| `Status.Anomaly` | `degraded` | `time-unsynced: <reason>`, plus `details.anomaly = true` |
| Not synced, no anomaly | `degraded` | `time-unsynced` |
| Backend call failed | **`unhealthy`** | `time-unsynced: <error>` |
| Backend reference nil | `unhealthy` | `ntp backend reference is nil` |

`Details` carries `synced`, `stratum`, `leap_status`, `offset_seconds`,
`root_dispersion`, `sources_reachable`, `sources_total`, `mode`,
`response_time_ms`.

`TimeUnsyncedMessage = "time-unsynced"` is the exported constant fleet
monitoring keys on. `ntpHealthTimeout = 5 * time.Second` bounds the control-socket
poll so a wedged chronyd never stalls the health endpoint.

**`NewNTPServiceHealthChecker` returns nil for a nil backend**, so a node with
no `ntp:` section has **no `ntp` component at all** rather than a permanently
unhealthy one.

## 12. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/health/`](../health/) — the registry the `ntp` component lives in
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC opcodes, authorization
- [`docs/ca/`](../ca/) — ACME issuance, which an unsynchronised clock breaks
- [`docs/attestation/`](../attestation/) — quote freshness, which an unsynchronised clock breaks
