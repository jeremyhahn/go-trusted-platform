# Managed Switch Provisioning — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/switch/`, `pkg/webservice/v1/rest/switch/`, `pkg/api/daemon/switch_grpc_service.go`, `pkg/api/daemon/quic_switch.go`, `sdk/go/services/switch/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

This is the file an implementing agent works from. Every identifier below was
read out of the source on 2026-08-18.

---

## 1. Package layout

The Go package is `switchmgmt`, not `switch` — `switch` is a keyword. The
directory is `pkg/switch/`. Importers alias it:
`switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"`.

| File | Holds |
|---|---|
| `types.go` | `Configurator`, `Manager`, `SSHExecutor`, `Config`, `VLANConfig`, `PortConfig`, `PortStatus`, `PortMode`, `SwitchVendor`, `ConfigureResult` |
| `service.go` | `Service`, `NewService`, `Service.Manager`, `Service.Close` |
| `factory.go` | `ConfiguratorFactory`, `configuratorRegistry`, `NewConfigurator` |
| `manager_factory.go` | `ManagerFactory`, `managerRegistry`, `NewManager` |
| `ssh_manager.go` | `sshManager`, `newSSHManager`, `newSSHManagerWithExecutor`, `buildConfigCommands`, `validateSSHManagerConfig`, all output parsers |
| `ssh.go` | `sshExecutor`, `NewSSHExecutor`, `loadSSHKey`, `newKnownHostsStore`, `hostKeyOwner`, `hostKeyScope` |
| `cisco_nexus.go` | `ciscoNexusConfigurator`, `GenerateVLANCommands`, `GeneratePortCommands`, `ExpandPortRange`, `validateConfig`, `ValidateVLANConfig`, `ValidatePortConfig`, `containsError`, `joinInts` |
| `noop.go` | `NewNoopConfigurator` |
| `noop_manager.go` | `NewNoopManager` |
| `errors.go` | 15 typed errors |

## 2. Exported surface

### 2.1 Interfaces

```go
type Configurator interface {
    ConfigureVLANs(ctx context.Context, vlans []VLANConfig) error
    ConfigurePorts(ctx context.Context, ports []PortConfig) error
    Configure(ctx context.Context, config *Config) error
    Verify(ctx context.Context, config *Config) error
    Close() error
}

type Manager interface {
    SetPortVLAN(ctx context.Context, port string, vlanID uint16) error
    GetPortVLAN(ctx context.Context, port string) (uint16, error)
    GetPortStatus(ctx context.Context, port string) (*PortStatus, error)
    ListPorts(ctx context.Context) ([]*PortStatus, error)
    EnablePort(ctx context.Context, port string) error
    DisablePort(ctx context.Context, port string) error
    Close() error
}

type SSHExecutor interface {
    Execute(ctx context.Context, command string) (string, error)
    Close() error
}
```

### 2.2 Constructors and factories

| Symbol | Signature | Notes |
|---|---|---|
| `NewService` | `([]Config, *slog.Logger) (*Service, error)` | One `Manager` per config. On any failure it closes the managers already built before returning. |
| `NewManager` | `(*Config, *slog.Logger) (Manager, error)` | **A nil config returns `NewNoopManager()`, not an error.** |
| `NewConfigurator` | `(*Config, *slog.Logger) (Configurator, error)` | **A nil config returns `NewNoopConfigurator()`, not an error.** |
| `NewSSHExecutor` | `(context.Context, *Config) (SSHExecutor, error)` | Dials; see §3 |
| `NewNoopManager` | `() Manager` | Every method returns nil / zero values |
| `NewNoopConfigurator` | `() Configurator` | Every method returns nil |

No functional options exist in this package (grepped 2026-08-18). Everything
is configured through `Config`.

`Service.Manager(name)` returns `ErrManagerNotFound{Name}` for an unknown name.
`Service.Close()` closes every manager and returns the **first** error while
still attempting the rest.

### 2.3 Command generation and parsing helpers (exported)

| Symbol | Signature | Used in production? |
|---|---|---|
| `GenerateVLANCommands` | `([]VLANConfig) []string` | yes — `ciscoNexusConfigurator.ConfigureVLANs` |
| `GeneratePortCommands` | `([]PortConfig) ([]string, error)` | yes — `ciscoNexusConfigurator.ConfigurePorts` |
| `ExpandPortRange` | `(string) ([]string, error)` | yes — port command generation and `Verify` |
| `ValidateVLANConfig` | `(VLANConfig) error` | **no — test-only** |
| `ValidatePortConfig` | `(PortConfig) error` | **no — test-only** |

`ValidateVLANConfig` and `ValidatePortConfig` are exported and have **no
non-test caller** (grepped 2026-08-18). Nothing in the construction or
configuration path enforces the 1–4094 VLAN range, the trunk-needs-VLANs rule
or the access-needs-a-VLAN rule that they implement. If you want those checks,
call them; do not assume the framework does. This corrects the legacy
`configuration.md`, which presented VLAN-range validation as happening at
startup.

### 2.4 Types

```go
type Config struct {
    Name           string       `yaml:"name"`
    Vendor         SwitchVendor `yaml:"vendor"`
    Host           string       `yaml:"host"`
    Port           int          `yaml:"port"`
    User           string       `yaml:"user"`
    Password       string       `yaml:"password,omitempty" secret:"true"`
    SSHKey         string       `yaml:"ssh_key,omitempty"`
    KnownHostsPath string       `yaml:"known_hosts_path,omitempty"`
    VLANs          []VLANConfig `yaml:"vlans"`
    Ports          []PortConfig `yaml:"ports"`
}
```

`PortStatus` carries `Port`, `Mode` (`PortModeAccess` / `PortModeTrunk`),
`AccessVLAN uint16`, `TrunkVLANs []uint16`, `NativeVLAN uint16` (from
`Trunking Native Mode VLAN:`), `Enabled`, `LinkUp`, `Description`. Every
transport carries `native_vlan` (gRPC/QUIC/Unix `SwitchPortStatus.native_vlan`
field 8, REST and the Go SDK through the JSON struct, MCP `switch_port_status`). `ConfigureResult` (`VLANsCreated`, `PortsConfigured`,
`Warnings`) is declared and **never constructed or returned** by any method —
it is vocabulary for a future batching API.

Vendors: `VendorCiscoNexus = "cisco-nexus"`, `VendorNoop = "noop"`. That is the
complete set.

## 3. SSH: what `NewSSHExecutor` actually requires

```
NewSSHExecutor(ctx, config)
  config == nil                 → ErrNilConfig{}
  config.SSHKey == ""           → ErrSSHConnectionFailed{Cause: ErrInvalidConfig{
                                    Field:"ssh_key", Reason:"must be set"}}
  config.KnownHostsPath == ""   → ErrSSHConnectionFailed{Cause: ErrInvalidConfig{
                                    Field:"known_hosts_path",
                                    Reason:"must be set; switch SSH requires pinned host keys"}}
  loadSSHKey  → os.ReadFile → secure.NewBufferFromBytes → keys.ParsePEM
  newKnownHostsStore(filepath.Dir(KnownHostsPath)) → filestorage.New → knownhosts.NewBackendStore
  session.Dial{Host, Port, User, Key, HostKeyScope: scope.Service,
               HostKeyOwner: Name-or-Host, KnownHostsStore}
```

Four facts that are easy to get wrong:

1. **`Config.Password` is never read by the SSH path.** There is no password
   authentication. The field exists and is carried through config.
2. **`known_hosts_path` names a file, but the store is rooted at its
   *directory*.** `newKnownHostsStore` does `filepath.Dir(path)` and builds a
   file-backed store there. A flat OpenSSH `known_hosts` file is not consumed:
   *"the known_hosts API … expects per-pin envelopes"*, written by the xkms
   tooling.
3. **Key ownership transfers on success.** `session.Dial` takes the key; on
   every error path the caller calls `key.Destroy()`. If you add a failure
   branch, destroy the key.
4. **Host-key pins are addressed by `scope.Service` and owned by
   `Name`-or-`Host`** — the same convention `pkg/sdn/fabric/nexus` uses, *"so a
   switch's pin is addressed the same way across both code paths."* Changing
   `Config.Name` changes the pin owner and invalidates the pin.

## 4. The password/key validation contradiction

Two validators exist and they disagree:

| Validator | Called from | Requires |
|---|---|---|
| `validateSSHManagerConfig` | `newSSHManager` (the `Manager` path) | `Host`, `User`, and **`SSHKey` *or* `Password`** |
| `validateConfig` | `newCiscoNexusConfigurator` (the `Configurator` path) | `Host`, `User`, and **`SSHKey`** |

`NewSSHExecutor`, which both paths eventually use, requires `SSHKey` **and**
`KnownHostsPath`.

Consequence: a switch configured with `user` + `password` and no `ssh_key`
**constructs a `Manager` successfully** and then fails on the first port
operation with `ssh connection failed to <host>: switchmgmt: invalid config:
field ssh_key: must be set`. Neither validator checks `KnownHostsPath` at all,
so a key-only config also constructs and fails at first use.

This is a real defect in failure timing, not in safety — the operation still
fails closed. It is documented rather than smoothed over because it turns a
config error into a runtime error at the worst moment: the first device
activation.

## 5. Invariants

1. **Connections are lazy and reused.** `ensureConnected` returns immediately
   if `m.executor != nil`; otherwise it dials and caches. **It is not
   concurrency-safe** — `sshManager` holds no lock, so two goroutines calling
   `SetPortVLAN` on the same manager can both dial and one executor leaks.
   Serialise per switch at your call site.
2. **`Manager` methods are single-operation.** No retries, no backoff, no
   polling loops.
3. **Runtime commands do not persist.** `buildConfigCommands` wraps interface
   commands with `configure terminal` … `end` and nothing else.
   **Bootstrap** commands (`GenerateVLANCommands`, `GeneratePortCommands`) end
   with `exit` then `copy running-config startup-config` and **do** persist.
4. **Every command's output is checked.** `SetPortVLAN`, `EnablePort`,
   `DisablePort`, `ConfigureVLANs` and `ConfigurePorts` call `containsError`
   on each response and abort the sequence on the first hit. `GetPortVLAN`,
   `GetPortStatus` and `ListPorts` do not — they parse instead.
5. **`Configure` is not transactional.** VLANs are applied fully before ports
   begin; a failure leaves the switch partially configured with no rollback.
   `Verify` is a separate, explicit call and `Configure` never invokes it.
6. **`Configure` skips empty sections.** No VLANs configured means no VLAN
   commands are sent; the same for ports.
7. **Port ranges expand client-side.** `ExpandPortRange("Eth1/3-5")` yields
   `["Eth1/3","Eth1/4","Eth1/5"]`. A name with no `/` (e.g. `mgmt0`) and a name
   with `/` but no `-` are returned unchanged in a one-element slice. The
   generated command list therefore has one `interface` block per physical
   port, not one per range.
8. **The VLAN bound is 4094 and it is enforced in four places** — the CLI
   (`ErrInvalidVLANID`), REST (`ErrInvalidVLANID`), QUIC (`switchMaxVLANID`
   constant, `ErrSwitchInvalidVLANID`) and MCP (`ErrSwitchInvalidVLAN`). Zero
   is rejected everywhere as "missing". `Manager.SetPortVLAN` itself does
   **not** range-check; the bound is a transport-layer contract.
9. **Port names are never validated.** No length limit, no character
   allow-list, no format check, at any layer. See
   [architecture.md](architecture.md) §5.4.
10. **`Service` keys on `Name`, falling back to `Host`.** Two switches with the
    same name silently collapse to one map entry.

## 6. Error semantics

### 6.1 Typed errors (`pkg/switch/errors.go`)

| Error | Fields | Returned when |
|---|---|---|
| `ErrNilConfig` | — | `NewSSHExecutor` or `Configure`/`Verify` got a nil config |
| `ErrInvalidConfig` | `Field`, `Reason` | Config validation, in both validators |
| `ErrSSHConnectionFailed` | `Host`, `Cause` | Dial, key load, or known-hosts store construction failed. `Unwrap` → cause |
| `ErrSwitchConnectionFailed` | `Host`, `Cause` | Declared; **no non-test caller** |
| `ErrCommandFailed` | `Command`, `Output`, `Cause` | `sshExecutor.Execute` non-zero exit; `Output` carries stderr |
| `ErrSSHCommandFailed` | `Command`, `Output`, `Cause` | `Manager` command failure, and the wrapped cause inside `ErrPortVLANSetFailed` |
| `ErrSSHParseOutputFailed` | `Command`, `Output`, `Reason` | Any parser failure; **carries the raw switch output** |
| `ErrPortVLANSetFailed` | `Port`, `VLANID`, `Cause` | `SetPortVLAN` |
| `ErrVLANConfigFailed` | `VLANID`, `Cause` | `ConfigureVLANs` — note `VLANID` is always `0` here, the code does not attribute the failing VLAN |
| `ErrPortConfigFailed` | `Port`, `Cause` | `ConfigurePorts` — `Port` is always `""` for the same reason |
| `ErrUnsupportedVendor` | `Vendor` | Vendor absent from either registry |
| `ErrVerificationFailed` | `Details` | `Verify` could not find a VLAN or interface in switch output |
| `ErrInvalidPortRange` | `Port`, `Reason` | `ExpandPortRange` — empty spec, unparseable bound, or start > end |
| `ErrPortNotFound` | `Port` | Declared; **never returned by the SSH driver** — see §8 |
| `ErrVLANNotFound` | `VLANID` | Declared; **no non-test caller** |
| `ErrManagerNotFound` | `Name` | `Service.Manager` on an unregistered name |

Every error carrying a `Cause` implements `Unwrap`, so `errors.Is`/`errors.As`
reach the underlying failure.

### 6.2 Transport mapping

| Layer | Not found | Invalid input | Service absent | Other failure |
|---|---|---|---|---|
| REST (`pkg/webservice/v1/rest/switch/`) | 404 `ErrSwitchNotFound`; `ErrPortOperationFailed` via `handlePortError` | 400 `ErrMissingSwitchName`, `ErrMissingPortName`, `ErrInvalidRequestBody`, `ErrMissingVLANID`, `ErrInvalidVLANID` | 503 from `requireService` catch-all | 500 `ErrPortOperationFailed`, `ErrListPortsFailed` |
| gRPC (`switch_grpc_service.go`) | `codes.NotFound` via `mapSwitchError` / `mapPortError` | `codes.InvalidArgument` `"switch_name is required"` / `"port_name is required"` | `codes.FailedPrecondition` `"switch service not initialized"` | `codes.Internal` |
| QUIC (`quic_switch.go`) | `StatusNotFound` `ErrSwitchNotFoundQUIC` | `StatusInvalidArgument` `ErrQUICMissingField`, `ErrSwitchInvalidVLANID`; `StatusInvalidRequest` on decode failure | `StatusUnavailable` `ErrQUICServiceUnavailable{Service:"switch"}` | `StatusInternalError` `ErrQUICOperationFailed` |
| MCP (`switch_tools.go`) | driver error passed through | `SWITCH_NAME_REQUIRED`, `SWITCH_PORT_NAME_REQUIRED`, `SWITCH_INVALID_VLAN` | `SWITCH_SERVICE_UNAVAILABLE` | driver error passed through |
| SDK (`sdk/go/services/switch/`) | `ErrUnexpectedStatus{StatusCode, Body}` | same | same | `ErrListPortsFailed`, `ErrGetPortStatusFailed`, `ErrSetPortVLANFailed`, `ErrEnablePortFailed`, `ErrDisablePortFailed` |

**`ErrServiceNil` is declared in the REST error set and never returned** — the
nil-service case is handled one level up by `requireService`, which never
constructs the handlers at all.

### 6.3 Fail-closed paths

| Path | Behaviour |
|---|---|
| Host-key verification | **Fail-closed, no TOFU.** No `known_hosts_path` ⇒ no connection. |
| Missing SSH key | Refuse to dial. |
| Unknown vendor | `ErrUnsupportedVendor`; `NewService` aborts and closes what it built. |
| Unregistered switch name | `ErrManagerNotFound` → 404 / `codes.NotFound` / `StatusNotFound`. |
| VLAN out of range | Rejected at all four transports before reaching the driver. |
| Any command output matching `containsError` | The command sequence aborts; remaining commands are not sent. |
| Service not wired | 503 / `FailedPrecondition` / `StatusUnavailable` / `SWITCH_SERVICE_UNAVAILABLE`, plus a startup warning and a `Configured: false` entry on `GET /api/v1/platform/service-registry`. |

**One path fails open**: `NewManager(nil, …)` and `NewConfigurator(nil, …)`
return no-op implementations that silently succeed. That is intentional for
"no switch configured", and it means a nil config is indistinguishable from a
working switch at the call site.

## 7. Adding a vendor

Two map entries and one factory. Nothing else changes.

```go
// pkg/switch/types.go
const VendorAristaEOS SwitchVendor = "arista-eos"

// pkg/switch/manager_factory.go
var managerRegistry = map[SwitchVendor]ManagerFactory{
    VendorCiscoNexus: newSSHManager,
    VendorAristaEOS:  newAristaEOSManager,
    VendorNoop:       newNoopManagerFactory,
}
```

Rules:

1. **Reuse `sshManager` if the CLI dialect matches.** It already serves Cisco
   IOS, IOS-XE, NX-OS and Arista EOS commands; a new identifier that maps to
   `newSSHManager` costs one line. Write a new driver only when the commands or
   the output format genuinely differ.
2. **A new driver implements `Manager`, and separately `Configurator` if it
   needs bootstrap setup.** The two registries are independent — a vendor may
   appear in one and not the other, and `NewConfigurator` will return
   `ErrUnsupportedVendor` for a vendor that only has a `Manager`.
3. **Go through `SSHExecutor`.** Do not open your own SSH connection: the
   enclave key handling and host-key pinning live in `NewSSHExecutor` and
   re-implementing them re-introduces the TOFU hole.
4. **Take an injectable executor for tests.** Follow
   `newSSHManagerWithExecutor` / `newCiscoNexusWithExecutor`.
5. **Emit your own parse errors as `ErrSSHParseOutputFailed`** with the raw
   output attached — that field is the only debugging tool an operator has for
   a dialect mismatch.
6. **Populate `LinkUp` and `Description` in `GetPortStatus`** if your dialect
   exposes them. The Cisco path does not, and that gap is documented in
   [architecture.md](architecture.md) §6 rather than repeated per driver.
7. **Return `ErrPortNotFound` when the port does not exist.** The REST and gRPC
   layers already map it to 404; the Cisco driver never produces it, so that
   mapping is currently dead code that your driver can bring to life.

## 8. Output parsing contract

| Parser | Input command | Extracts |
|---|---|---|
| `parseAccessVLANFromSwitchport` | `show interfaces <port> switchport` | Access VLAN, via `(?i)access\s+mode\s+vlan:\s*(\d+)` |
| `parseSwitchportOutput` | same | `Mode` (operational mode preferred, administrative as fallback), `AccessVLAN`, `TrunkVLANs`, `Enabled` (from the literal `switchport: enabled`) |
| `parseInterfaceStatusTable` | `show interfaces status` | Per-port `Port`, `Enabled`, `LinkUp`, `Mode`, `AccessVLAN`, `Description` |
| `parseTrunkVLANList` | — | Comma-separated VLAN list; unparseable entries are silently dropped |

`parseInterfaceStatusTable` finds the header by searching for a line containing
`port`, `status` and `vlan` (case-insensitive), derives column offsets from it
with `indexOrEnd`, and slices every following line. It skips blank lines and
separator lines (more than half dashes). A missing header is
`ErrSSHParseOutputFailed{Reason:"header line not found"}`. Status words
recognised: `connected` (enabled + link up), `notconnect` / `not connect`
(enabled, link down), `disabled` (neither); **anything else defaults to
`Enabled: true`**. A VLAN column reading `trunk` or `routed` sets
`PortModeTrunk`.

`parseSwitchportOutput` **never returns an error** — it returns whatever it
could extract. That is why `ErrPortNotFound` is unreachable from
`GetPortStatus`.

## 9. Configuration

Platform config, `pkg/app/app.go:334`:

```yaml
switches:
  - name: core-01
    vendor: cisco-nexus
    host: switch-core-01.example.com
    port: 22
    user: automation
    ssh_key: /etc/trusted-platform/switch/core-01.key
    known_hosts_path: /etc/trusted-platform/switch/known_hosts/core-01
    vlans:
      - id: 100
        name: provisioning
        subnet: 203.0.113.0/24
        description: "Device provisioning VLAN"
      - id: 200
        name: trusted
        subnet: 198.51.100.0/24
    ports:
      - port: Eth1/1-10
        mode: access
        access_vlan: 100
        description: "Provisioning rack 1"
      - port: Eth1/48
        mode: trunk
        vlans: [100, 200]
        description: "Uplink"
```

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | no | falls back to `host` | Registry key **and** host-key pin owner |
| `vendor` | string | yes | — | `cisco-nexus` or `noop` |
| `host` | string | yes (SSH vendors) | — | |
| `port` | int | no | — | Passed to `session.Dial` as-is; **`pkg/switch` supplies no default of 22** |
| `user` | string | yes (SSH vendors) | — | |
| `ssh_key` | string | **yes in practice** | — | `validateSSHManagerConfig` will accept `password` instead; `NewSSHExecutor` will not (§4) |
| `known_hosts_path` | string | **yes in practice** | — | Not checked by either validator; enforced at dial time |
| `password` | string | no | — | Tagged `secret:"true"`; **not used for authentication** |
| `vlans[]` | list | no | — | Bootstrap only |
| `ports[]` | list | no | — | Bootstrap only |

`vlans[].id`, `.name`, `.subnet`, `.description`; `ports[].port`, `.mode`
(`access` \| `trunk`), `.vlans`, `.access_vlan`, `.native_vlan`, `.mtu`,
`.description`. `ValidatePortConfig` (called by `GeneratePortCommands` for
every port) requires a trunk's native VLAN to be in its allowed list, refuses a
native VLAN on an access port, and bounds the MTU to 1500–9216.

**There are no switch-specific environment variables** (grepped 2026-08-18).

**The `secret:"true"` tag is declarative here.** `pkg/bootstrap.SecretStructTag`
names it, but nothing in non-test code walks it, so the secret-URI schemes
(`kms://`, `xkms://`, `env://`, `file://`, `idevid://`, `dynamic://`,
`remote-kms://`) are **not resolved for this field** by anything in this
feature. The legacy `configuration.md` described `kms://` password resolution as
working, and also cited a `platformctl secrets set` command — **no `secrets`
command group exists** on `platformctl` (`pkg/cli/commands/root.go`). Both
corrections are recorded here.

What *is* real: `pkg/config/snapshot.go` redacts any config key whose name
contains `password` (among other hints) to `••••` in the config snapshot
returned to the WebUI and to non-privileged callers.

## 10. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit — SSH driver | `pkg/switch/ssh_manager_test.go` | Every `Manager` method against a mocked `SSHExecutor` |
| Unit — SSH session | `pkg/switch/ssh_test.go` | Key loading, known-hosts store, fail-closed guards |
| Unit — Cisco configurator | `pkg/switch/cisco_nexus_test.go` | Command generation, range expansion, `Verify`, `ValidateVLANConfig`/`ValidatePortConfig` |
| Unit — registries | `pkg/switch/factory_test.go`, `manager_test.go` | Vendor dispatch, nil-config no-op behaviour |
| Unit — no-op | `pkg/switch/noop_test.go` | No-op driver |
| Unit — errors and types | `pkg/switch/errors_test.go`, `types_test.go` | Error formatting, validation |
| Transport | `pkg/webservice/v1/rest/switch/{handlers,router}_test.go`, `pkg/webservice/v1/device/handler_switch_test.go`, `pkg/cli/commands/switch/switch_test.go`, `sdk/go/services/switch/client_test.go` | Routing, encoded port names, device-activation integration, CLI, SDK |

**Fault-injection seam:** `SSHExecutor`. `newSSHManagerWithExecutor` and
`newCiscoNexusWithExecutor` exist for exactly this and are the only supported
way to test a driver without hardware. Above the driver, `Manager` itself is
the seam — `NewNoopManager()` satisfies it.

There is no integration suite against real switch hardware in this repository.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, not only here.

## 11. Observability

- **Logging.** Every command is logged at **Debug** with the full command
  string (`"ssh set port vlan"`, `"ssh enable port"`, `"ssh disable port"`,
  `"ssh list ports"`, `"executing vlan command"`, `"executing port command"`).
  Successful mutations are logged at **Info** by the QUIC handler with switch,
  port and VLAN. Failures are logged at **Error** by the REST, gRPC and QUIC
  layers with switch, port and error. `Service.Close` logs a failed manager
  close at Error and continues.
- **Debug logging exposes the CLI session.** It does not log the key or the
  password, but it does log every command sent to the fabric. Treat
  `logging.level: debug` on a control-plane node as sensitive.
- **Metrics.** None. `pkg/switch` declares no counters or gauges.
- **Audit.** None. A VLAN move is not written to an audit record by this
  feature.
- **Health.** `GET /api/v1/platform/service-registry` reports whether the
  switch REST surface was wired, with the reason string
  *"switch service not configured by daemon — REST surface is dark"* when it
  was not. That is the fastest way to tell "no switch configured" from
  "switch unreachable".
- **Never log**: `Config.Password`, the contents of `Config.SSHKey`.

## 12. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/`](../sdn/) — the virtual datapath, and `pkg/sdn/fabric` for multi-switch fabrics
- [`docs/device/`](../device/) — the activation path that calls `SetPortVLAN`
