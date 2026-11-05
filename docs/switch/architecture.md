# Managed Switch Provisioning — Architecture

> **Status: NORMATIVE** · Scope: `pkg/switch/`, `pkg/webservice/v1/rest/switch/`, `pkg/api/daemon/switch_grpc_service.go`, `pkg/api/daemon/quic_switch.go`, `sdk/go/services/switch/` · Last verified: 2026-10-27
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

Zero-touch provisioning assumes a machine can reach the platform on a
restricted network before it has an identity, and a different network after it
proves one. On virtual interfaces the platform programs that transition itself.
On **physical ports of a physical switch** it cannot: the switch is a separate
device with its own operating system, its own credentials, and a CLI as its
only stable interface.

So the platform needs to drive a third-party box, over SSH, as part of a
security-critical transition — and the credential that lets it do so is an
administrator credential on the network fabric. That credential is the whole
problem. Anything that can move a port between VLANs can move any port to any
VLAN.

## 2. The shape chosen

**Two interfaces, split by lifecycle, over one vendor-dispatch registry each.**

| Interface | When it runs | What it does |
|---|---|---|
| `Configurator` | Bootstrap, once | Creates VLANs and sets port modes from a declarative `Config` — `ConfigureVLANs`, `ConfigurePorts`, `Configure`, `Verify` |
| `Manager` | Runtime, per operation | Single-port operations — `SetPortVLAN`, `GetPortVLAN`, `GetPortStatus`, `ListPorts`, `EnablePort`, `DisablePort` |

`Service` is a **named registry of `Manager`s**, one per configured switch,
keyed by `Config.Name` (falling back to `Config.Host`). `Service.Manager(name)`
is the only thing the API layers hold — they never see a factory, a config, or
an SSH session.

Vendor dispatch is two maps, not two switch statements:

```go
var configuratorRegistry = map[SwitchVendor]ConfiguratorFactory{
    VendorCiscoNexus: newCiscoNexusConfigurator,
    VendorNoop:       newNoopConfiguratorFactory,
}
var managerRegistry = map[SwitchVendor]ManagerFactory{
    VendorCiscoNexus: newSSHManager,
    VendorNoop:       newNoopManagerFactory,
}
```

Two vendors exist: `cisco-nexus` and `noop`. `newSSHManager` produces a driver
whose CLI dialect the package documents as *"compatible with Cisco IOS, IOS-XE,
NX-OS, Arista EOS, and similar platforms"* — one vendor **identifier**, several
device families that happen to speak the same commands.

**SSH is fail-closed on the host key.** `NewSSHExecutor` refuses to dial
without both an `ssh_key` and a `known_hosts_path`, and verifies the switch
host key against pinned envelopes. There is no trust-on-first-use path. The
private key is sealed into an enclave-backed buffer before it is parsed and is
destroyed on every error path.

### 2.1 Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Trust the switch host key on first connect (TOFU)** | The first connection is exactly when a man-in-the-middle is cheapest, and the thing being handed over is a fabric administrator credential. `NewSSHExecutor` fails closed: *"It fails closed when no host-key pins are provisioned: the legacy insecure host-key-ignore behaviour is gone."* Operators pre-populate pin envelopes via the xkms tooling. |
| **Hold the SSH private key as a `[]byte`** | A fabric admin key sitting in ordinary heap memory outlives its use and lands in core dumps. `loadSSHKey` seals the PEM into a `secure.Buffer`, parses through `keys.ParsePEM`, and hands ownership to the session; every failure path calls `key.Destroy()`. |
| **One interface covering both setup and runtime** | Setup is declarative, whole-switch, and writes `copy running-config startup-config`. Runtime is imperative, single-port, and must not persist. Merging them would make an activation-time VLAN move a config-save event on a production switch. `Service` deliberately exposes only `Manager(name)` and `Close()` and holds no `Configurator`; the only `Configurator` caller is the bootstrap orchestrator (§4.1). |
| **A vendor `switch` statement** | Adding a vendor would touch dispatch logic in two places and grow a branch each time. Two registries mean a new vendor is one map entry plus one factory ([engineering.md](engineering.md) §7). |
| **A per-vendor structured API (NETCONF, gNMI, REST)** | Real fleets are heterogeneous and older switches carry none of them. The CLI is the one interface every candidate device has. The cost is output parsing, which is confined to five regexes and one fixed-width table parser and is the acknowledged weak point (§6). |
| **Eager SSH connection at service construction** | A daemon would fail to start because a switch was rebooting. `ensureConnected` dials on first use and reuses the session afterwards. The cost is that a bad credential is not discovered until the first port operation. |
| **Cache `ListPorts` results** | Network state changes outside the platform — a human on the console, another automation system. A stale port map would be used to decide where a machine gets to talk. Every read goes to the switch. |
| **Connection pooling across `Manager`s on the same host** | Each `Manager` owns one session and one config. Sharing would mean shared failure and shared teardown for switches that are independently configured. |
| **Do nothing when no switch is configured** | Silence is indistinguishable from breakage. `requireService` records the surface as unconfigured, installs a 503 catch-all under `/api/v1/switches/`, logs a warning, and reports it on `GET /api/v1/platform/service-registry`. |

## 3. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Interfaces, config and status types | `pkg/switch/types.go` | this repo |
| Named `Manager` registry | `pkg/switch/service.go` | this repo |
| Vendor dispatch | `pkg/switch/factory.go`, `manager_factory.go` | this repo |
| SSH `Manager` and output parsing | `pkg/switch/ssh_manager.go` | this repo |
| Cisco NX-OS `Configurator`, command generation, port-range expansion | `pkg/switch/cisco_nexus.go` | this repo |
| SSH session, key sealing, host-key pinning | `pkg/switch/ssh.go` | this repo |
| No-op driver | `pkg/switch/noop.go`, `noop_manager.go` | this repo |
| Typed errors | `pkg/switch/errors.go` | this repo |
| REST handlers and router | `pkg/webservice/v1/rest/switch/` | this repo |
| gRPC `SwitchService` implementation | `pkg/api/daemon/switch_grpc_service.go` | this repo |
| QUIC sub-opcode table (delegates to the gRPC servicer) | `pkg/api/daemon/quic_switch.go` | this repo |
| QUIC sub-opcode constants | `sdk/go/wire/quicwire/switch_opcodes.go` | this repo |
| MCP tools (call the gRPC servicer) | `pkg/api/mcp/switch_tools.go` | this repo |
| Embedded dispatch (calls the gRPC servicer) | `sdk/go/transport/embedded/dispatch.go` (`registerSwitchHandlers`) | this repo |
| SDK accessor `Client.Switch()` and per-transport mappings | `sdk/go/client.go`, `sdk/go/transport/*/` ([`docs/sdk/api.md`](../sdk/api.md) §1) | this repo |
| REST-only SDK client | `sdk/go/services/switch/client.go` | this repo |
| CLI | `pkg/cli/commands/switch/` | this repo |
| Bootstrap-time invocation | `pkg/bootstrap/orchestrator.go` (`configureSwitch`, `buildSwitchConfig`) | this repo, separate feature |
| **Enclave-backed SSH keys, sessions, `known_hosts` pin store** | `go-quicbaas/sdk/go/xkms/{secure,ssh/keys,ssh/knownhosts,ssh/scope,ssh/session,storage/file}` | **go-quicbaas** — consumed through its SDK |
| **Bridges, ports, flows, VLAN programming on the host datapath, 802.1X port authentication** | `pkg/sdn/` — [`docs/sdn/`](../sdn/) | this repo, **separate feature** |
| **Multi-switch fabric convergence, LAG/MC-LAG** | `pkg/sdn/fabric/` — [`docs/sdn/`](../sdn/) | this repo, **separate feature** (see §7) |
| **Device records that name a switch and port** | `pkg/device/` — [`docs/device/`](../device/) | this repo, separate feature |

The `docs/00 §R` capability row is the SDN row — *"SDN — bridges, ports, flows,
IDevID port authentication, VXLAN/EVPN overlay, IPAM, physical switch
management"*, **Tier 1** — reached through `services/switch` alongside
`services/sdn` and `services/overlay`.

Transport mechanics — the six-transport model, the QUIC category-opcode table,
status-byte vocabulary and the authorization catalogs — live in
[`docs/daemon/api.md`](../daemon/api.md) and are not repeated here.

## 4. Data flow

### 4.1 Bootstrap: declarative switch setup

`pkg/bootstrap/orchestrator.go` runs switch configuration as **phase 1**, after
discovery and before the bootstrap container is deployed. It is optional: the
phase runs only `if o.config.Switch != nil`.

```
Orchestrator.Run
  └─ phase 1 (optional)  configureSwitch
       ├─ buildSwitchConfig(bootstrap.SwitchConfig) → switchmgmt.Config
       ├─ switchmgmt.NewConfigurator(cfg, logger)   → vendor registry
       ├─ Configurator.Configure(ctx, cfg)
       │    ├─ ConfigureVLANs  →  GenerateVLANCommands
       │    │     configure terminal / vlan N / name … / description … /
       │    │     exit / copy running-config startup-config
       │    └─ ConfigurePorts  →  GeneratePortCommands
       │          configure terminal / interface … (ranges expanded) /
       │          switchport mode … / switchport {access vlan|trunk allowed vlan} … /
       │          no shutdown / exit / copy running-config startup-config
       └─ defer Configurator.Close()
```

**Both generated command sets end with `copy running-config startup-config`.**
Bootstrap switch configuration is persisted to the switch's startup
configuration and survives a reload. That is the intended behaviour and it is
also why this path is bootstrap-only.

`Configure` is not transactional. `ConfigureVLANs` runs to completion before
`ConfigurePorts` starts, and a failure part-way leaves the switch in a partial
state — see [engineering.md](engineering.md) §5.

### 4.2 Runtime: a single port moves

```
caller (CLI / REST / gRPC / QUIC / MCP)
   └─ Service.Manager(switchName)          → ErrManagerNotFound if unregistered
        └─ sshManager.SetPortVLAN(ctx, port, vlan)
             ├─ ensureConnected → NewSSHExecutor (first call only)
             │    ├─ loadSSHKey → secure.Buffer → keys.ParsePEM
             │    ├─ newKnownHostsStore(dir of known_hosts_path)
             │    └─ session.Dial (TCP + handshake + host-key verify, one call)
             ├─ "configure terminal"
             ├─ "interface <port>"
             ├─ "switchport mode access"
             ├─ "switchport access vlan <id>"
             └─ "end"
```

Each command's output is checked by `containsError` before the next one is
sent. **Runtime port moves do not write `copy running-config
startup-config`** — a VLAN move is running-config only and is lost on switch
reload. That asymmetry with §4.1 is deliberate: activation state belongs to the
platform, not to switch NVRAM.

### 4.3 Where a runtime move comes from

The device activation path calls into this feature:

```
POST /api/v1/device/activate       (docs/device/)
   ├─ Handler.prepareSwitchTransition
   │    ├─ switch name + port from the request context (not from the profile)
   │    └─ SwitchServiceProvider.Manager(switchName)   → ErrSwitchNotConfigured
   └─ Handler.commitSwitchTransition
        ├─ Manager.GetPortVLAN(ctx, port)              (informational; warns if already admitted)
        ├─ Manager.SetPortVLAN(ctx, port, admittedVLAN)
        └─ on either failure: revertAndVerify
             ├─ Manager.SetPortVLAN(ctx, port, provisioningVLAN)
             └─ Manager.GetPortVLAN read-back         → ErrSwitchPortIndeterminate if not closed
```

The activation path fails closed: the SSH command sequence is not atomic, so a
failed read or move forces the port back to the provisioning VLAN and verifies
it by read-back (`pkg/webservice/v1/device/handler.go`). Only a verified revert
lets the plain `ErrSwitchVLANTransitionFailed` stand.

The switch name and port are read from the unexported context keys
`contextKeySwitchName` / `contextKeySwitchPort`; no production code sets them
(only `handler_switch_test.go` does), so today `prepareSwitchTransition` skips
the move on every activation even when a switch service is wired.

`SwitchServiceProvider` is declared in `pkg/webservice/v1/device` as a
one-method interface (`Manager(name) (switchmgmt.Manager, error)`), which
`*switchmgmt.Service` satisfies structurally. The gRPC servicer takes the same
interface (`device.SwitchServiceProvider`), and the QUIC, MCP and embedded
transports call that servicer, so no transport holds a second switch
interface.

**Nothing is persisted by this feature.** There is no datastore, no cache and
no local state. The switch is the source of truth for every read.

## 5. Trust boundaries

**Switch administrator credentials are a trust boundary.** Specifically:

1. **The SSH private key is fabric-admin material.** `Config.SSHKey` names a
   PEM file on the platform node. Anything that can read it can reconfigure the
   fabric. It is read once per session, sealed immediately into an
   enclave-backed `secure.Buffer`, parsed, and destroyed — but the file on disk
   is still a file on disk. Protect it like a CA key.
2. **Host-key verification is fail-closed and pin-based.** Pins are stored as
   envelopes under the directory containing `known_hosts_path`, addressed by
   `scope.Service` and owned by the switch's `Name` (falling back to `Host`) —
   the same addressing `pkg/sdn/fabric/nexus` uses, so one switch has one pin
   identity across both code paths. **A flat OpenSSH `known_hosts` file is not
   consumed**; the API expects per-pin envelopes written by the xkms tooling.
3. **`Config.Password` is a trap.** The field exists, is tagged
   `secret:"true"`, and `validateSSHManagerConfig` accepts a config that
   supplies a password and no key. **`NewSSHExecutor` never reads it.** A
   password-only switch config constructs successfully and fails at the first
   port operation with `ssh_key … must be set`. See
   [engineering.md](engineering.md) §4.
4. **Command construction is string interpolation.** `SetPortVLAN` builds
   `interface %s` from the caller's port name with no escaping or allow-list.
   The VLAN id is bounded (1–4094) at three separate entry points; **the port
   name is not validated anywhere**. The blast radius is limited by the SSH
   session running a single command per `Execute` and by the switch CLI not
   being a shell, but a port name is untrusted input reaching a device CLI.
   Treat `port_name` as privileged input and constrain it at your edge.
5. **Switch operations are scoped on gRPC, QUIC and MCP.** All three
   catalogs are default-deny. `SwitchService` reads need `switch:read` and the
   three mutators need `switch:write` in the gRPC scope catalog; QUIC (#767)
   and the `switch_*` MCP tools (#304) require the same pairs.
   Recorded in [api.md](api.md) §7.
6. **Disabling a port is a denial-of-service primitive.** `DisablePort` issues
   `shutdown`. Treat `switch:write` as a grant over the physical fabric.
7. **The bootstrap path writes NVRAM.** `Configure` persists with
   `copy running-config startup-config`. A wrong bootstrap config is not undone
   by rebooting the switch.

## 6. Known weak points

These are properties of the chosen design, stated so nobody rediscovers them as
surprises.

- **Error detection is a substring heuristic.** `containsError` returns true if
  the command output contains `error`, `invalid`, or `% ` (case-insensitive).
  A port whose description contains the word "error" will make an otherwise
  successful command look failed. It is deliberately over-eager — a false
  failure is safer than a silent misconfiguration — but it is not a parser.
- **Output parsing is regex and fixed-width columns.** `ListPorts` locates a
  header line containing `port`, `status` and `vlan`, derives column offsets
  from it, and slices every subsequent line. A vendor that renames a column or
  wraps output breaks the parse and returns `ErrSSHParseOutputFailed` with the
  raw output attached.
- **`GetPortStatus` never reports link state or description.**
  `parseSwitchportOutput` sets only `Port`, `Mode`, `AccessVLAN`, `TrunkVLANs`,
  `NativeVLAN` and `Enabled`. `LinkUp` and `Description` are left at their zero values, so a
  single-port status always reports `link_up: false` and an empty description.
  `ListPorts` *does* populate both from the `show interfaces status` table. The
  two paths disagree on the same port; the list is the one to believe.
- **`GetPortStatus` cannot 404 correctly.** `parseSwitchportOutput` returns
  `(status, nil)` for any input, so a nonexistent port yields a zero-valued
  `PortStatus` rather than `ErrPortNotFound`. The REST handlers map
  `ErrPortNotFound` to 404 on every port operation (`handlePortError`) — that
  mapping is currently unreachable from the SSH driver.
- **Lookups are one SSH round trip per command**, and `SetPortVLAN` sends five.
  There is no batching.

## 7. What this feature deliberately does not do

- **It does not manage the host datapath.** Bridges, ports, flows, VLANs on OVS
  and the 802.1X / IDevID port-authentication engine are
  [`docs/sdn/`](../sdn/). This feature drives a *physical* switch over SSH; SDN
  programs the *virtual* one in the kernel.
- **It does not converge a fabric.** `pkg/sdn/fabric/` has its own multi-switch
  manager with LAG and MC-LAG handling and its own Nexus driver. `pkg/switch/`
  is single-switch, single-port, and knows nothing about peers. The two share
  only the host-key pin addressing convention.
- **It does not decide when a port should move.** Device activation does
  ([`docs/device/`](../device/)); this feature executes.
- **It does not persist anything.** No datastore, no cache, no state file.
- **It does not discover switches.** Switches come from the `switches:` block
  of the platform configuration and nowhere else.
- **It does not expose `Configurator` at runtime.** `Service` hands out
  `Manager` only. VLAN creation is a bootstrap operation.
- **It does not retry.** Every method performs one operation and returns. There
  are no retry loops and no backoff.

## 8. Deployment reality: the surface is dark by default

Three wiring seams exist — `switchmgmt.NewService`,
`HandlerRegistryParams.SwitchService`, and
`(*SwitchGRPCService).SetSwitchService` — and **none of them has a caller
anywhere in the repository**.
The gRPC service is registered with an explicit nil backend under the comment
*"Create the Switch gRPC service. It has no switch backend yet, so every
method answers Unavailable (not configured); the QUIC opcodes, the MCP tools
and the embedded transport call this same servicer."* (`pkg/api/daemon/daemon.go:1049`). The consequence is concrete and worth
stating plainly:

- REST `/api/v1/switches/...` returns **503** carrying the machine-readable
  `"reason": "SERVICE_NOT_CONFIGURED"` discriminator alongside the prose
  *"switch service not configured by daemon — REST surface is dark"*, the
  daemon logs a warning at startup, and
  `GET /api/v1/platform/service-registry` reports the surface as
  `Configured: false`.
- gRPC returns `codes.Unavailable` with reason `SERVICE_NOT_CONFIGURED` —
  `"switch service is not configured on this node"`.
- QUIC, MCP and embedded call that servicer, so they return the same
  `Unavailable` (`StatusUnavailable` on QUIC).

The `switches:` configuration block is parsed into `app.App.SwitchConfigs`
(`pkg/app/app.go:371`) and, today, nothing constructs a `Service` from it. The
bootstrap `Configurator` path (§4.1) is separate and does run — it builds its
config from `bootstrap.SwitchConfig`, not from `App.SwitchConfigs`.

This is recorded as fact, not as a plan. Wiring it is a code change with an
owner; documenting it as working would be worse than documenting it as dark.

## 9. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/`](../sdn/) — the virtual datapath and port authentication
- [`docs/device/`](../device/) — the activation path that calls `SetPortVLAN`
- [`docs/bootstrap/`](../bootstrap/) — the orchestrator phase that runs `Configurator`
