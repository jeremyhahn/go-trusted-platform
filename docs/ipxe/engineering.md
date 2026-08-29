# iPXE Network Boot — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/ipxe/`, `cmd/pxeboot` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was read out of the named file on 2026-08-18.

---

## 1. Package layout

| File | Holds |
|---|---|
| `config.go` | `ServerConfig` (alias `Config`), `BootEntry`, `DefaultServerConfig`, `DefaultConfig`, `Validate`, `GetServerIP`, the `Default*` constants |
| `server.go` | `Server`, `NewServer`, `Start`, `Stop`, `WaitForReady`, `IsRunning`, `ServerIP`, `HTTPServer`, `RunWithSignals` |
| `dhcp_server.go` | `DHCPServer`, `DHCPConfig`, `NewDHCPServer`, `DHCPServerOption`, `WithIPAllocator`, `WithPacketConnFactory`, `SetConnFactory`, `SetAllocator`, `GetAllocator`, `PacketConnFactory`, `DefaultPacketConnFactory`, `DefaultBootFilenameByArch` |
| `dhcp_rawconn_linux.go` | `ServerRawConn` over `AF_PACKET` (build-tagged Linux) |
| `dhcp_rawconn_stub.go` | The non-Linux `ServerRawConn` stub, same method set |
| `ipam_allocator.go` | `IPAllocator`, `InMemoryAllocator`, `IPAMAllocator`, `NewInMemoryAllocator`, `NewIPAMAllocator` |
| `tftp_server.go` | `TFTPServer`, `NewTFTPServer`, `Start`; firmware URLs and cache resolution |
| `http_server.go` | `HTTPServer`, `NewHTTPServer`, `SetDeviceLookup`, `Start`, `DeviceLookup` |
| `script_generator.go` | `ScriptGenerator`, `DeviceBootInfo`, `NewScriptGenerator`, `GenerateScript`, `GenerateDefaultMenu` |
| `iso.go` | `ExtractBootFiles` |
| `testenv.go` | `TestEnv`, `TestEnvConfig`, `DefaultTestEnvConfig`, `NewTestEnv`, `Setup`, `Start`, `Stop`, `Cleanup`, `TapName`, `ServerIP`, `ServerConfig`, `Network` |
| `errors.go` | Sentinels, IPAM error types, `MessageError`, `WrappedError`, `SentinelCauseError` |

`cmd/pxeboot/main.go` builds a `container.ServerConfig` and calls
`container.NewServer` — it does **not** import `pkg/ipxe`.

## 2. Exported surface

### Lifecycle

```go
func NewServer(cfg *ServerConfig, logger *logging.Logger) (*Server, error)
func (s *Server) Start(ctx context.Context) error
func (s *Server) Stop() error
func (s *Server) WaitForReady(timeout time.Duration) error
func (s *Server) IsRunning() bool
func (s *Server) ServerIP() net.IP
func (s *Server) HTTPServer() *HTTPServer
func (s *Server) RunWithSignals(ctx context.Context) error
```

`NewServer` does four things before it constructs anything: validates the
config, resolves the server IP through `GetServerIP`, and **mutates the config
in place** to fill `ExternalURL` (`http://<ip>:<httpPort>`) and `IPXEScript`
(`<ExternalURL>/boot.ipxe`) when either is empty. It creates the DHCP server
only when `EnableDHCP` is set.

### DHCP

```go
func NewDHCPServer(cfg *DHCPConfig, logger *logging.Logger, opts ...DHCPServerOption) (*DHCPServer, error)
func WithIPAllocator(allocator IPAllocator) DHCPServerOption
func WithPacketConnFactory(factory PacketConnFactory) DHCPServerOption
func DefaultBootFilenameByArch() map[uint16]string
```

`PacketConnFactory` has one method,
`CreateConn(iface string, serverIP net.IP, useRawSocket bool) (net.PacketConn, error)`.
`DefaultPacketConnFactory` returns `NewServerRawConn(iface, serverIP, 67)` when
`useRawSocket`, else a `net.ListenUDP("udp4", :67)`.

### Allocation

```go
type IPAllocator interface {
    Allocate(ctx context.Context, mac net.HardwareAddr, hostname string) (net.IP, error)
    Release(ctx context.Context, mac net.HardwareAddr) error
    GetLease(ctx context.Context, mac net.HardwareAddr) (*lease, error)
    Renew(ctx context.Context, mac net.HardwareAddr) error
}

func NewInMemoryAllocator(rangeStart, rangeEnd net.IP, leaseTime time.Duration) *InMemoryAllocator
func NewIPAMAllocator(allocator ipam.Allocator, poolID string, leaseTime time.Duration) (*IPAMAllocator, error)
```

`IPAMAllocator` adds `PoolID()`, `LeaseCount()` and `SyncFromIPAM(ctx)`.

**`IPAllocator` cannot be implemented outside this package.** `GetLease`
returns `*lease`, and `lease` is unexported. The interface is exported, the
option that accepts it (`WithIPAllocator`) is exported, and no external caller
can satisfy it. Either `lease` should be exported or `GetLease` should leave
the interface — recorded as a defect, not resolved here.

### HTTP

```go
type DeviceLookup func(mac string) (*DeviceBootInfo, error)
func NewHTTPServer(cfg *ServerConfig, logger *logging.Logger) *HTTPServer
func (s *HTTPServer) SetDeviceLookup(lookup DeviceLookup, gen *ScriptGenerator)
func (s *HTTPServer) Start(ctx context.Context) error
```

`SetDeviceLookup` must be called **before** `Start`: the `/boot/device/` route
is registered only when both `deviceLookup` and `scriptGen` are non-nil at
`Start` time. Setting them afterwards has no effect on an already-running mux.

### Scripts

```go
func NewScriptGenerator(serverAddr string, logger *slog.Logger) *ScriptGenerator
func (g *ScriptGenerator) GenerateScript(info *DeviceBootInfo) string
func (g *ScriptGenerator) GenerateDefaultMenu(entries []BootEntry) string
```

`DeviceBootInfo` fields: `MAC`, `Role`, `Hostname`, `KernelURL`, `InitrdURL`,
`ConfigServerURL`, `BootstrapStrategy`, `ExtraKernelArgs`. `GenerateScript`
emits `#!ipxe`, then a `kernel` line carrying `platform_config=`,
`platform_role=`, `platform_hostname=` and `bootstrap_strategy=` for whichever
fields are non-empty plus every `ExtraKernelArgs` entry verbatim, then `initrd`,
then `boot`.

**`ExtraKernelArgs` entries are concatenated with a space and no escaping.**
An argument containing a space becomes two arguments; an argument containing a
newline breaks the script. Callers own the quoting.

### ISO

```go
func ExtractBootFiles(isoPath string) (extractDir, kernelPath, initrdPath, modloopPath, kernelArgs string, err error)
```

Creates a temp directory (`ipxe-iso-*`), removes it on error, and returns it to
the caller to remove on success. **A caller that ignores `extractDir` leaks a
directory holding an extracted ISO.**

## 3. Invariants

1. **`Validate` requires at least one boot entry.** An empty `BootEntries`
   slice is `ErrNoBootEntries`, and `NewServer` refuses to construct. A boot
   server with no menu is a misconfiguration, not an empty menu.
2. **`BootEntry.Validate` requires `Name`, `Description`, and at least one of
   `ISOURL`, `Kernel`, `Initrd`.**
3. **DHCP validation is conditional.** `validateDHCP` runs only when
   `EnableDHCP`; it then requires an interface (falling back to
   `ServerConfig.Interface`), a parseable range start and end, and a positive
   lease time, and parses `DHCPSubnetMask`, `DHCPGateway` and `DHCPDNS` when
   non-empty.
4. **`Start` is not re-entrant.** A second `Start` on a running server returns
   *"server is already running"*; `running` is an `atomic.Bool` guarded by a
   mutex for the transition.
5. **Service startup is concurrent and best-effort per service.** HTTP, TFTP and
   DHCP each run in their own goroutine and push to a buffered `errChan` of
   capacity 3. A failure in one does not stop the others; `WaitForReady`
   (default 10 s, polled every 100 ms) is how a caller learns the server came
   up.
6. **The TFTP server fails to start without `ipxe.efi`.** `loadFirmware` treats
   the x86-64 EFI binary as required and `ipxe32.efi` / `undionly.kpxe` as
   optional — a missing optional binary logs a warning and leaves clients of
   that architecture unable to boot.
7. **Firmware is cached on disk and served from memory.** `loadFirmwareFile`
   reads the cache path first and only downloads on a read failure; the
   in-memory `firmware` map is the read path for TFTP requests, guarded by
   `firmwareMu`. **A cached file is never revalidated.**
8. **`bootFilenameForArch` consults the map first, then falls back.** An empty
   string in the map counts as absent.
9. **PXE detection and iPXE detection are different tests.** `isPXEClient`
   matches option 60 with a `PXEClient` prefix **or** the mere presence of
   option 93. `isIPXEClient` matches option 77 user class equal to `iPXE`.
10. **Every PXE reply carries option 60 and option 43.** `OptClassIdentifier`
    is set to `PXEClient`, and option 43 carries
    `{0x06, 0x01, 0x08, 0xFF}` — `PXE_DISCOVERY_CONTROL` bit 3, then the PXE
    option END. Removing either reintroduces the PXE-E18 loop on UEFI firmware.
11. **`GetServerIP` has a fixed precedence**: an IP extractable from
    `ExternalURL`, then `DHCPServerIP`, then the first non-loopback IPv4 address
    on `Interface`, then the first non-loopback IPv4 on any up, non-loopback
    interface. All four are IPv4-only.
12. **Route registration order matters.** `/boot/device/` is registered before
    `/boot/`, so a device script is not swallowed by the boot-entry handler.
13. **The `/data/` and `/files/` routes are conditional** on `DataDir` and
    `LocalFilesDir` being non-empty. Setting `DataDir: ""` disables the endpoint
    entirely — which is why a chainload can succeed and the subsequent
    kernel fetch 404.
14. **`/config/*` returns 503 when `InstallsDir` is empty**, because values are
    stored under it.

## 4. Configuration

`ServerConfig` is a **Go struct, not a YAML surface.** `pkg/ipxe` has no
config-file loader and reads **no environment variables**. Callers construct it:
`pkg/bootstrap/container` from `cmd/pxeboot` flags plus a manifest,
`pkg/compute/pxe` from platform config, `testenv.go` from
`DefaultTestEnvConfig`.

| Field | Type | `DefaultServerConfig()` |
|---|---|---|
| `Interface` | string | `""` |
| `HTTPPort` | int | `DefaultHTTPPort` = `8080` |
| `TFTPPort` | int | `DefaultTFTPPort` = `69` |
| `ExternalURL` | string | `""` → auto-detected by `NewServer` |
| `LocalFilesDir` | string | `/var/lib/ipxe` |
| `InstallsDir` | string | `/data/installs` |
| `DataDir` | string | `""` → `InstallsDir`'s parent when unset; `""` after explicit clearing disables `/data/` |
| `EnableDHCP` | bool | `false` |
| `DHCPInterface` | string | `""` → falls back to `Interface` |
| `DHCPRangeStart` / `DHCPRangeEnd` | string | `""` (**required when `EnableDHCP`**) |
| `DHCPSubnetMask` | string | `DefaultSubnetMask` = `255.255.255.0` |
| `DHCPGateway`, `DHCPDNS` | string | `""` |
| `DHCPLeaseTime` | `time.Duration` | `DefaultLeaseTime` = 1 h |
| `DHCPServerIP` | string | `""` → auto-detected |
| `DHCPRespondToAll` | bool | `false` |
| `TFTPServerName` | string | `""` |
| `BootFilename` | string | `ipxe.efi` |
| `BootFilenameByArch` | `map[uint16]string` | `nil` → `DefaultBootFilenameByArch()` at startup; an **explicit empty map** disables arch-aware selection |
| `IPXEScript` | string | `""` → auto-detected |
| `BootEntries` | `[]BootEntry` | `[]` (**must be non-empty to validate**) |
| `ProxyCACertPool` | `*x509.CertPool` | `nil` → system pool |

**Readiness.** `Server.Ready()` returns a channel closed once every enabled listener has bound. Each sub-server binds (`net.Listen`, `net.ListenPacket`, the DHCP conn factory) *before* it serves, so a bind failure is synchronous, is recorded, and is returned from `Server.Start` rather than swallowed — `Start` previously returned nil after the monitor stopped the server, which masked a bind failure from every caller. The bootstrap container binds its device-script listener only after `Ready()` closes, so that port answering means all four listeners are up.

`DefaultBootFilenameByArch()`:

| Option-93 value | Constant | Filename |
|---|---|---|
| `0x0000` | `archBIOSx86` | `undionly.kpxe` |
| `0x0006` | `archEFIx86` | `ipxe32.efi` |
| `0x0007` | `archEFIx64` | `ipxe.efi` |
| `0x0009` | `archEFIBC` | `ipxe.efi` |

Other constants: `readyCheckInterval` 100 ms, `defaultReadyTimeout` 10 s,
`tftpTimeout` 5 s, `httpTimeout` 60 s, HTTP `ReadTimeout` / `WriteTimeout` 30 s,
proxy client timeout 5 min, `maxInstallLogUploadBytes` 16 MiB,
`maxConfigValueBytes` 256 KiB.

Firmware sources — `https://boot.ipxe.org/x86_64-efi/ipxe.efi`,
`https://boot.ipxe.org/i386-efi/ipxe.efi`,
`https://boot.ipxe.org/undionly.kpxe` — cached under
`<user cache dir>/go-trusted-platform/firmware/`, falling back to
`/var/cache/go-trusted-platform/firmware/`.

`DefaultTestEnvConfig()` builds an isolated bridge: `pxe-br` /
`tap-pxe-client`, subnet `10.99.99.0/24`, server and gateway `10.99.99.1`,
DHCP range `10.99.99.100`–`10.99.99.200`, DNS `8.8.8.8`, ports 8080 and 69,
`LocalFilesDir` `/var/lib/ipxe`. `TestEnvConfig.Validate` rejects a server IP or
either range endpoint outside the subnet.

## 5. Error semantics

Sentinels (`errors.go`): `ErrNoServerIP`, `ErrNoAvailableIPs`,
`ErrInvalidConfig`, `ErrFirmwareNotFound`, `ErrInvalidInterface`,
`ErrInvalidIPRange`, `ErrInvalidPort`, `ErrNoBootEntries`,
`ErrInvalidBootEntry`, `ErrLeaseNotFound`, `ErrLeaseExpired`.

Structured: `ErrIPAMAllocationFailed{PoolID, MAC, Cause}`,
`ErrIPAMInvalidIP{IP, Reason}`, `ErrIPAMReleaseFailed{IP, MAC, Cause}`,
`ErrIPAMRenewFailed{IP, MAC, Cause}` — the first, third and fourth implement
`Unwrap() error`.

Wrappers: `MessageError{Msg}`, `WrappedError{Msg, Err}` with `Unwrap() error`,
and `SentinelCauseError{Sentinel, Cause}` with
`Unwrap() []error{Sentinel, Cause}` — so `errors.Is(err, ErrInvalidConfig)` and
`errors.As` on the cause both work on the same value. This is the package's
dominant error shape: nearly every validation failure is a
`SentinelCauseError` pairing a sentinel with a `MessageError` describing the
field.

### Fail-closed and fail-open paths

| Path | Behaviour | Closed / open |
|---|---|---|
| `NewServer` with a nil or invalid config | Refuses to construct | **closed** |
| `Validate` with no boot entries | `ErrNoBootEntries` | **closed** |
| `Validate` with an unresolvable `Interface` | `ErrInvalidInterface` | **closed** |
| TFTP with `ipxe.efi` unavailable | `Start` fails | **closed** |
| TFTP with `ipxe32.efi` / `undionly.kpxe` unavailable | Warns, starts anyway | **open** — clients on those architectures fail silently at DISCOVER |
| TFTP request for an unknown filename | `ErrFirmwareNotFound` wrapped in `SentinelCauseError` | **closed** |
| Cached firmware file present | Served without revalidation | **open** — see [architecture.md](architecture.md) §6.3 |
| `/proxy/…` with a non-HTTPS scheme | 400 | closed on scheme |
| `/proxy/https/…` to any host | Fetched, TLS verified, relayed | **open** — no host allowlist |
| `/config/mac/…` malformed path or `..` | 400 | closed on shape |
| `/config/mac/…` from any client | Read or written, unauthenticated | **open** |
| `/installs/…` upload over 16 MiB | Rejected | closed |
| `/installs/…` upload | Written via `.partial` + atomic rename | closed on partial reads |
| DHCP request from a non-PXE client | Ignored unless `DHCPRespondToAll` | **closed by default** |
| A service goroutine dies | Pushed to `errChan`; the others keep running | **open** |

**The three open rows in the middle are the feature's security posture, not
bugs to fix locally.** They are stated as trust boundaries in
[architecture.md](architecture.md) §6 and the mitigation is network isolation.

## 6. Persistence

| What | Where | Notes |
|---|---|---|
| DHCP leases (in-memory allocator) | process memory | lost on restart |
| DHCP leases (IPAM allocator) | the platform IPAM | `SyncFromIPAM(ctx)` rebuilds the local view |
| Install logs | `<InstallsDir>/{hostname}/{filename}` | 16 MiB cap, `.partial` + rename |
| Per-MAC config values | `<InstallsDir>/config/mac/{mac}/{key}` | 256 KiB cap, plain bytes, no interpretation |
| iPXE firmware | `<cache dir>/go-trusted-platform/firmware/` | 0755 dir, 0644 files |
| Extracted ISO boot files | `os.MkdirTemp("", "ipxe-iso-*")` | caller removes |

**Path shape is the compatibility contract.** `{mac}` is lowercase hex with
dashes, 12–17 characters (`configMACPathRegexp`); `{key}` is
`[a-z0-9][a-z0-9._\-]{0,64}`. `autoinstall.sh` and the bootstrap orchestrator
both hard-code these shapes, so changing the regex breaks both ends at once.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/ipxe/*_test.go` | Config validation and defaults, DHCP packet construction and option handling, arch→bootfile mapping, raw-conn framing, TFTP handler, every HTTP route, script generation, allocator behaviour, ISO extraction |
| Integration | `test/integration/ipxe/` | Real bridge, real TAP, real QEMU client |
| End to end | `platformctl iso test pxe` | Real network boot of a real ISO, **requires root** |

Seams for fault injection:

- `PacketConnFactory` — `WithPacketConnFactory` or `SetConnFactory` substitutes
  the DHCP socket without a network.
- `IPAllocator` — `WithIPAllocator` or `SetAllocator`, though see §2 on the
  unexported `lease`.
- `DeviceLookup` — a plain func, so a test supplies a table.
- `ServerConfig.ProxyCACertPool` — point the proxy at a test CA.
- `TestEnv` — `NewTestEnv` / `Setup` / `Start` / `Stop` / `Cleanup` builds and
  tears down the whole isolated network.
- `dhcp_rawconn_stub.go` — the package compiles and unit-tests on non-Linux.

**Parity gap.** `conventions/feature-docs.md` §4 requires every `cli.md` verb to
have a matching `CommandDefinition` in the integration parity suite. **No
`CommandDefinition` type exists in this repository** (grepped repo-wide,
2026-08-18), so the requirement is unmet repo-wide.

## 8. Observability

- **Every HTTP request is logged.** `loggingMiddleware` wraps the mux and emits
  method, path, status, duration and remote address. That log is the fastest way
  to answer "did the client actually ask for the kernel?".
- **DHCP logs at start** with interface, server IP and range; per-request
  decisions (PXE detected, iPXE detected, filename chosen, IP allocated) are
  logged as the request is handled.
- **TFTP logs** the read request, the remote address and the byte count, and
  warns on an unknown filename.
- **Firmware provenance is logged**: "Loaded firmware from cache" with the path,
  or "Downloading firmware" with the URL. If you are debugging a boot that
  behaves unexpectedly, check which of the two you got.
- `GET /health` is the liveness endpoint.
- There are **no metrics** in this package — no counters for leases issued,
  boot files served, or proxy fetches. A deployment that needs them derives
  them from the request log.
- **Do not log the contents of `/config/mac/{mac}/installer.yaml`.** The merged
  per-node installer config can contain a LUKS passphrase, a root password and
  EAB credentials. The current handler logs only the path, which is correct.

## 9. Corrections against the pre-convention documents

The code wins. These are defects in the older files, recorded rather than
silently fixed.

| Claim | Where | Reality in code |
|---|---|---|
| `POST /install-log/<mac>/<status>` uploads the install log; `<status>` is `success` or `failed` | old `architecture.md` | **No such route.** The route is `PUT /installs/{hostname}/{filename}`, and `GET /installs/…` browses. There is no status segment and the key is a hostname, not a MAC. |
| The file layout is `config.go`, `errors.go`, `server.go`, `dhcp_server.go`, `dhcp_rawconn_*.go`, `tftp_server.go`, `http_server.go`, `testenv.go`, `iso.go` | old `architecture.md` | Missing `script_generator.go` and `ipam_allocator.go`, which are where per-device boot and lease allocation actually live. |
| The HTTP endpoint table | old `architecture.md` | Omitted `/boot/device/`, `/data/`, `/installs/` and the fact that `/files/` and `/data/` are conditional on config. `/proxy/https/*` is really `/proxy/` with the scheme as the first path segment. |
| Firmware is cached in `~/.cache/go-trusted-platform/firmware/` | old `architecture.md` | `os.UserCacheDir()` first — which honours `$XDG_CACHE_HOME` — and `/var/cache/go-trusted-platform/firmware/` when the process has no per-user cache dir (root, container, system service). |
| TFTP serves `ipxe.efi` (64-bit) and `ipxe32.efi` (32-bit) | old `architecture.md` | Three binaries: `undionly.kpxe` is also served, for legacy-BIOS ROMs, and arch selection is the whole point. |
| `cmd/pxeboot` runs the `pkg/ipxe` server | implied throughout | It runs `pkg/bootstrap/container`, which wraps `ipxe.Server` and adds manifest-driven script generation. |

**Not a correction, but a divergence worth flagging:**
[`docs/provisioning/api.md`](../provisioning/api.md) §1 records the PXE QUIC
opcodes as `0xFC`–`0xFF`. `pkg/api/quic/protocol.go` also defines
`OpPXEListDevices` `0xEC`, `OpPXEGetDevice` `0xED`, `OpPXERegisterDevice`
`0xEE` and `OpPXEUpdateState` `0xEF`. Eight opcodes, not four. Raised against
`docs/provisioning/`, which owns that table.

## 10. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [configuration.md](configuration.md) · [testing.md](testing.md) · [README.md](README.md) — pre-convention detail
- [`docs/provisioning/`](../provisioning/) — the PXE control plane and its transport matrix
- [`docs/installer/`](../installer/) — what the booted kernel does next
- [`docs/daemon/api.md`](../daemon/api.md) — the platform transport model
