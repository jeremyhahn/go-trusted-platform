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
`ConfigServerURL`, `BootstrapStrategy`, `ExtraKernelArgs`, `Architecture`,
`BootImageURL`.
`GenerateScript` emits `#!ipxe`, the architecture guard when `Architecture` is
set, then the same bounded-retry boot block `/boot.ipxe` uses (`bootBlock`,
20 attempts): a `kernel` line carrying `platform_config=`, `platform_role=`,
`platform_hostname=` and `bootstrap_strategy=` for whichever fields are
non-empty plus every `ExtraKernelArgs` entry verbatim, then `initrd`, then
`boot`. When `BootImageURL` is set the block loads that signed UKI instead:
`kernel <BootImageURL>` with no arguments and no `initrd` line, then `boot`.
The UKI runs the command line signed into it; under Secure Boot systemd-stub
ignores load options in any case. The bootstrap container sets it for an
installed `diskless-nbd` node
([bootstrap engineering](../bootstrap/engineering.md#the-diskless-nbd-runtime-path)).

iPXE carries no enrollment of its own, on any architecture or boot model.
Every node enrols through the same `enroll-01` or `endorse-01` client: a disk
node in `platformd`'s first boot, a `diskless-nbd` node in the installer,
before it first attaches its export, so it holds the IDevID the export admits
([installer engineering](../installer/engineering.md#enrolling-before-the-attach)).

A `DeviceLookup` returns `ErrDeviceNotFound` for a MAC it has no assignment
for; `/boot/device/<mac>.ipxe` answers that with 404 and any other lookup
error with 500. The route accepts the MAC dashed (iPXE's `${mac:hexhyp}`) or
with colons.

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
   lease time, and parses `DHCPSubnetMask` when non-empty. `DHCPGateway` and
   every `DHCPDNS` entry go through `ParseDHCPv4`, which refuses anything that
   is not IPv4 with `DHCPAddressError` (it matches `ErrInvalidConfig`):
   `buildDHCPConfig` uses the same parse, so an IPv6 gateway is refused rather
   than dropped from the offer as a nil `To4()`.
4. **`Start` is not re-entrant.** A second `Start` on a running server returns
   *"server is already running"*; `running` is an `atomic.Bool` guarded by a
   mutex for the transition.
5. **Service startup is concurrent and best-effort per service.** HTTP, TFTP and
   DHCP each run in their own goroutine and push to a buffered `errChan` of
   capacity 3. A failure in one does not stop the others; `WaitForReady`
   (default 10 s, polled every 100 ms) is how a caller learns the server came
   up.
6. **The TFTP server fails to start without `ipxe.efi`.** `loadFirmware` treats
   the x86-64 EFI binary as required and `ipxe32.efi` / `undionly.kpxe` /
   `snponly-aarch64.efi` as optional — a missing optional binary logs a
   warning and leaves clients of that architecture unable to boot.
7. **Firmware is cached on disk and served from memory.** `loadFirmwareFile`
   reads the cache path first and only downloads on a read failure; the
   in-memory `firmware` map is the read path for TFTP requests, guarded by
   `firmwareMu`. **A cached file is never revalidated.** With a
   `FirmwareSigner`, `storeFirmware` signs an `.efi` binary on its way into
   the map; a signing failure is `FirmwareSignError` and fails startup, since
   an unsigned binary would be rejected by the client anyway.
8. **`bootFilenameForArch` consults the map first, then falls back.** An empty
   string in the map counts as absent.
9. **PXE detection and iPXE detection are different tests.** `isPXEClient`
   matches option 60 with a `PXEClient` or `U-Boot` prefix **or** the mere
   presence of option 93. `isIPXEClient` matches option 77 user class equal
   to `iPXE`.
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
    kernel fetch 404. The same holds for a Pi's HTTP boot: with no `DataDir` the
    EEPROM's `boot.img` request is a 404 and the Pi boots nothing from the
    network. Both `http.Server` timeouts are 30 s, which also bounds how long a
    large `boot.img` may take to transfer.
14. **`/config/*` returns 503 when `InstallsDir` is empty**, because values are
    stored under it.
18. **`/boot.ipxe` has one shape per configuration.** With a `DeviceLookup`
    wired it first chains `boot/device/${mac:hexhyp}.ipxe`, so a known device
    boots what it was assigned and an unknown one (404) falls through. Then:
    one entry with a kernel and an initrd is booted inline; several entries
    whose architectures are all set and distinct are dispatched by
    `${buildarch}` to per-architecture boot blocks, unattended (an
    architecture with no entry gets the menu); anything else chains the
    menu. Every inline boot, per-device ones included, is the same
    bounded-retry block.
15. **A boot entry with an `Architecture` is served only to that
    architecture.** `EntriesForArchitecture` keeps entries whose
    `Architecture` is empty or equals the iPXE `${buildarch}` the client
    reports (`x86_64`, `arm64`, `i386`); `/menu.ipxe?arch=` filters with it,
    and a single-entry `/boot.ipxe` carries an `iseq ${buildarch}` guard that
    chains to the filtered menu instead of handing an x86 kernel to an arm64
    client.
    An `x86_64` entry is also served to `i386` clients
    (`ClientArchitectures`): a legacy-BIOS server chains `undionly.kpxe`, a
    32-bit iPXE whose `${buildarch}` is `i386`, and boots the 64-bit kernel
    it fetches. An explicit `i386` entry claims `i386` for itself.

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
| `DHCPGateway` | string | `""` (no router option) |
| `DHCPDNS` | `[]string` | `nil` (no option 6) |
| `DHCPLeaseTime` | `time.Duration` | `DefaultLeaseTime` = 1 h |
| `DHCPServerIP` | string | `""` → auto-detected |
| `DHCPRespondToAll` | bool | `false` |
| `TFTPServerName` | string | `""` |
| `BootFilename` | string | `ipxe.efi` |
| `BootFilenameByArch` | `map[uint16]string` | `nil` → `DefaultBootFilenameByArch()` at startup; an **explicit empty map** disables arch-aware selection |
| `FirmwareSigner` | `EFISigner` | `nil`; when set, every `.efi` firmware binary is Authenticode-signed with it before it is served (the on-disk cache stays the upstream bytes) — required for a client whose firmware verifies what it loads, such as U-Boot with the platform's db preseeded |
| `FirmwareOverrides` | `map[string]string` | `nil`; served filename → local file, loaded ahead of the cache and never downloaded; an unreadable entry is `FirmwareOverrideError` at startup. The arm64 iPXE is one (`make ipxe-build`): upstream's halts under U-Boot's polled EFI |
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
| `0x000b` | `archEFIAArch64` | `snponly-aarch64.efi` |
| `0x0016` | `archUBootARM64` | `snponly-aarch64.efi` |

`0x000b` is the RFC 4578 EFI AArch64 client; `0x0016` is IANA's "ARM 64
U-Boot", which a stock U-Boot sends when its `DHCP_PXE_CLIENTARCH` was left
at the default. The platform's own U-Boot builds send `0x000b`
(`build/docker/uboot-builder/configs/common-efi.config`). A request with no
option 93 whose vendor class is `U-Boot.armv8` is treated as `0x000b` too:
U-Boot's vendor class is a non-visible Kconfig symbol, so it cannot be made to
say `PXEClient`, and `isPXEClient` accepts a `U-Boot` prefix beside
`PXEClient`.

The binary behind `snponly-aarch64.efi` must be the platform's own build
(`build/docker/ipxe-builder`, served through `FirmwareOverrides`), not the
upstream download the name defaults to: iPXE's EFI nap is WFI, U-Boot's EFI
timers fire only inside boot-service calls, so upstream's binary halts at
its banner with the vCPU idle. The platform build selects `NAP_NULL` and is
otherwise upstream's snponly configuration.

Other constants: `readyCheckInterval` 100 ms, `defaultReadyTimeout` 10 s,
`tftpTimeout` 5 s, `httpTimeout` 60 s, HTTP `ReadTimeout` / `WriteTimeout` 30 s,
proxy client timeout 5 min, `maxInstallLogUploadBytes` 16 MiB,
`maxConfigValueBytes` 256 KiB.

Firmware sources — `https://boot.ipxe.org/x86_64-efi/ipxe.efi`,
`https://boot.ipxe.org/i386-efi/ipxe.efi`,
`https://boot.ipxe.org/undionly.kpxe`,
`https://boot.ipxe.org/arm64-efi/snponly.efi` (served as
`snponly-aarch64.efi`) — cached under
`<user cache dir>/go-trusted-platform/firmware/`, falling back to
`/var/cache/go-trusted-platform/firmware/`.

`DefaultTestEnvConfig()` builds an isolated bridge: `pxe-br` /
`tap-pxe-client`, subnet `10.99.99.0/24`, server and gateway `10.99.99.1`,
DHCP range `10.99.99.100`–`10.99.99.200`, DNS `8.8.8.8`, ports 8080 and 69,
`LocalFilesDir` `/var/lib/ipxe`. `TestEnvConfig.Validate` rejects a server IP or
either range endpoint outside the subnet, and an interface name over the
kernel's 15 characters. The environment's DHCP server is the one `Server`
builds — the UDP socket with `SO_BROADCAST` (#649), the per-architecture
bootfile map — and answers every client (`RespondToAll`), because on its
isolated bridge it is the only DHCP server and the booted OS's own client
needs a lease too. `FirmwareSigner` and `FirmwareOverrides` pass through
to the `ServerConfig`.

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
| DHCP packet with an empty or all-zero `chaddr` | Ignored before dispatch; no lease, no reply | closed |
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
| Integration | `test/integration/ipxe/`, `make integration-test-ipxe` (slices `-dhcp`, `-tftp`, `-http`) | The real server in process on `127.0.0.1`, no VM and no outside network: HTTP routes, TFTP downloads, and DHCP DISCOVER/OFFER and REQUEST/ACK over loopback. `TestMain` points `FirmwareUpstream` at a local fixture server (each file is compared byte for byte after TFTP) and `ProxyCACertPool` at a local TLS upstream for `/proxy/https/`. `TestIPXEDHCPToHTTPChain` follows the DHCP answer: the non-iPXE boot file over TFTP, then the iPXE URL → `boot.ipxe` → menu → entry script. The runner sets `IPXE_DHCP_ENABLED=1`, `TestMain` starts DHCP on `lo` at a free UDP port, and a DHCP test fails without it. Nothing in the suite skips; a setup failure fails the run |
| End to end | `platformctl iso test pxe` | Real network boot of a real ISO, **requires root** |
| End to end, aarch64 | `test/integration/netboot/`, `make integration-test-netboot` | QEMU virt booted from the platform's U-Boot (`-bios`) on the harness bridge: DHCP arch `0x000b` → signed `snponly-aarch64.efi` → per-architecture script → signed kernel + initrd → Alpine; the stand-in for a Raspberry Pi from U-Boot onward |

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
| `/boot.ipxe` chains `/boot/device/<mac>.ipxe` when a `DeviceLookup` is wired | [architecture.md](architecture.md) §5 data flow, until 2026-09-22 | Nothing chained it: the per-device route was mounted and answered, but no script a node booted ever asked for it, so every device booted the shared entry. `/boot.ipxe` now chains it first (invariant 18). The per-device script also lacked the retry loop `/boot.ipxe` had; both now render the same block. |
| `platformctl iso test pxe` builds `DefaultTestEnvConfig()` | [cli.md](cli.md) §3, until 2026-09-22 | It built its own copy from `testenv.DefaultNetworkConfig()`, whose bridge subnet is a `/28`, while leasing `.100`–`.200`: every unicast reply to a client (the TFTP data) left through the host's default route, and the command's `qemu.Config` had no disk, which `Validate` refuses. Neither run had ever completed. The command now uses `ipxe.NewTestEnv` — which in turn named its unused second TAP 21 characters long, over the kernel's 15 — and gives the client a disk. Fixed with the aarch64 work (#686). |

**Resolved divergence:** [`docs/provisioning/api.md`](../provisioning/api.md)
§1 recorded the PXE QUIC opcodes as `0xFC`–`0xFF`, while
`sdk/go/wire/quicwire/protocol.go` defines eight (`0xEC`–`0xEF` too). Since #704
that table names the opcode per method, including the seven `0xCF` subs
`0x30`–`0x36`.

## 10. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- configuration.md · testing.md · README.md — pre-convention detail, now deleted; these five files hold it
- [`docs/provisioning/`](../provisioning/) — the PXE control plane and its transport matrix
- [`docs/installer/`](../installer/) — what the booted kernel does next
- [`docs/daemon/api.md`](../daemon/api.md) — the platform transport model
