# Installer — API

> **Status: NORMATIVE** · Scope: installer, initrd, ISO and QEMU capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The headline

**The installer has no platform API surface.** There is no `/api/v1/install`,
no `/api/v1/iso`, no `InstallerService` or `ISOService` in
`pkg/api/grpc/proto/`, no `OpInstall*` or `OpISO*` opcode in
`sdk/go/wire/quicwire/protocol.go`, and no `install_*` or `iso_*` MCP tool — all four
grepped 2026-08-18.

That is a **decision, not a gap.** Installation runs on install media, before
the node has an identity to authenticate with and before the transports exist
to carry a request. The remote pieces that *do* need an API — device
authorisation, config delivery, remote Secure Boot digest signing — are owned by
provisioning and documented in
[`docs/provisioning/api.md`](../provisioning/api.md).

Every row below is therefore `MISSING — docs/13 G7` on five transports and
`✅` on the embedded one, except where the row explicitly belongs to another
feature. The rows exist anyway, because omitting them would leave the reader
unable to tell "absent by design" from "not yet written".

**The transport model itself is [`docs/daemon/api.md`](../daemon/api.md)** —
the six protocol constants, the QUIC frame and status vocabulary, the category
opcode table, and the platform-wide authorization picture. This file does not
repeat any of it.

---

## 2. Installation

`Embedded` here means an in-process Go call, not a `ServiceRegistry` entry:
`ServiceRegistry` (`sdk/go/transport/embedded/adapter.go`) has **no installer,
ISO or initrd field**, so there is no embedded *transport* route either — the
packages are imported and called directly by `platformctl` and
`platform-initrd`.

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Install a system | `installer.NewInstaller(logger, cfg, opts...)` → `Install(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Wire install-time remote DB signing | `installer.WithRemoteSignContext(*RemoteSignContext)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Release installer resources | `Installer.Close()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Partition / LUKS / LVM / mount | `installer.NewDiskManager(logger, *DiskConfig)` (`DiskManager`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Install a base OS | `installer.NewOSInstaller(logger, *OSConfig)` (`OSInstaller`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Build a UKI | `installer.NewUKIBuilderAdapter(logger)` / `NewDracutUKIBuilder(logger)` → `BuildUKI` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Rebuild + re-sign a UKI | `installer.NewUKIRebuilder(logger, cfg, opts...)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Enrol a FIDO2 key for LUKS | `installer.NewFIDO2Enrollment(*FIDO2EnrollmentConfig)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Detect a FIDO2 device | `installer.DetectFIDO2Device()`, `installer.IsFIDO2Available()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Unlock LUKS with FIDO2 | `installer.NewFIDO2Unlock(device, debug)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Warm-reset the machine | `installer.HardReset()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Check NIC hardware offload | `installer.CheckHWOffloadSupport(io.Reader)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

## 3. Configuration and profiles

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Load installer config | `installer.LoadConfig(path)`, `installer.LoadInstallConfig(path)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Save installer config | `installer.SaveConfig(cfg, path)`, `installer.WriteInstallConfig(cfg, path)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Built-in defaults | `installer.DefaultConfig()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Merge with defaults | `installer.MergeWithDefaults(cfg, defaults)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Validate config | `(*installer.Config).Validate()`, `installer.ValidateConfig(cfg)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Validate Secure Boot config | `(*installer.SecureBootConfig).Validate()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Serialise config | `installer.ConfigToYAML`, `installer.ConfigFromYAML`, `installer.GenerateInstallConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| List profiles | `installer.ListProfiles()`, `installer.ListProfilesWithDescriptions()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Get a profile | `installer.GetProfile(name)`, `installer.GetProfileWithDescription(name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Validate a profile name | `installer.ValidateProfileName(name)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate a config from a profile | `installer.GenerateConfigFromProfile(name, overrides)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

Device profiles carried on the ISO are a **different noun** — those live in
`pkg/iso/config.go` (`LoadDeviceProfileFromFile`, `SaveDeviceProfileToFile`) and
belong to [`docs/device/`](../device/). Installer profiles are the four embedded
YAML templates.

## 4. ISO production

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Download the base ISO | `iso.DownloadISO(ctx, *ISOConfig)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Extract an ISO | `iso.ExtractISO(ctx, *ISOConfig)`, `iso.ExtractWithProgress` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Verify an extraction | `iso.VerifyExtraction(isoDir)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Check disk space for extraction | `iso.CheckDiskSpace(isoPath, destDir)`, `iso.GetDiskUsage`, `iso.GetAvailableSpace` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Customise an ISO | `iso.NewCustomizer(*PlatformISOConfig, logger)` → `CustomizeAll(ctx)`; step methods `ModifyInitramfs`, `CopyPlatformdBinary`, `CopyPlatformctlBinary`, `CopyPlatformInitrdBinary`, `CopyPlatformConfig`, `CopyCABundle`, `CopySecureBootKeys`, `CopyDracutModule`, `CopyFIPSArtifacts`, `CopyWebUI`, `BuildPreFetchRepository`, `GenerateAutoinstallScript`, `GenerateInstallConfig`, `ConfigureBootloader`, `UpdateEFIBootloader`, `EmbedDeviceProfileNetworkConfig`, `EmbedPlatformAPIConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Build a bootable ISO | `iso.NewBuilder(logger)` (`ISOBuilder`: `BuildISO`, `ValidateISO`) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Pre-fetch packages for offline install (**not available in a `fips` build** — the APKINDEX `Q1` checksum is SHA-1 by format; see [cli.md](cli.md#pre-fetch-is-unavailable-in-a-fips-build)) | `iso.NewPreFetchBuilder(*PreFetchConfig, logger)`, `iso.CollectRequiredPackages` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Inject kernel modules into the initramfs | **unexported** — `(*Customizer).injectNetworkModules`, reached only through `NewCustomizer` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate per-profile network config | `iso.NewNetworkConfigGenerator`, `NewSystemdNetworkdConfigGenerator`, `NewDnsmasqConfigGenerator`, `NewNetworkConfigWriter` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Load / save an ISO build config | `iso.LoadISOBuildConfig`, `iso.SaveISOBuildConfig`, `iso.DefaultISOBuildConfig`, `iso.DefaultISOConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Validate the platformd binary name | `iso.ValidatePlatformdBinaryName(path)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate the module-signing key | `secureboot.GenerateModuleSigningKey(ctx, *ModuleSigningKeyConfig)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

**The Go functions exist and the CLI calls them locally.** `iso create` runs the
whole pipeline; `iso download`, `iso extract`, `iso customize`, `iso build` and
the `iso profile` verbs run its steps one at a time ([cli.md](cli.md) §4). No
daemon protocol carries them.

## 5. Boot-time unlock

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Build a boot manager | `initrd.NewManager(*Platform, logger)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Initialise the boot environment | `Manager.Initialize(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Detect boot mode | `Manager.DetectMode(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Unlock all volumes | `Manager.UnlockVolumes(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Normal boot | `Manager.Boot(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Install-time strategy setup | `Manager.Install(ctx, password)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Recovery boot | `Manager.Recovery(ctx)`, `Manager.InteractiveRecovery(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Register a strategy | `Manager.RegisterStrategy(UnlockStrategy)`, `(*StrategyChain).Add` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Run the strategy chain | `(*StrategyChain).Execute`, `.ExecuteInstall`, `.List`, `.Count`, `.Remove` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Detect a TPM | `initrd.NewTPMDetector(logger)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Prepare a disk from the initrd | `initrd.NewDiskPreparer(device, mountPoint, logger)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Manage multiple encrypted drives | `initrd.NewMultiDriveManager(...)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

Six strategy constructors — `NewKeyfileStrategy`, `NewTPMPCRStrategy`,
`NewTPMUpgradeStrategy`, `NewTPMNoPCRStrategy`, `NewFIDO2Strategy`,
`NewPasswordStrategy` — are embedded-only on the same terms; their priorities
are in [engineering.md](engineering.md) §5.

**LUKS itself does have a transport surface**: `pkg/api/grpc/proto/luks.proto`
and the QUIC LUKS category opcode `0x9C`
([`docs/daemon/api.md`](../daemon/api.md) §4), reached from
`platformctl luks`. That is the *running-system* LUKS surface, not the
initrd's — an initrd that could be driven over the network would defeat the
point of measuring the boot chain.

## 6. Test harness

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Create a test VM | `qemu.NewVM(*Config, logger)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Start / wait / stop a test VM | `(*VM).Start(ctx, mode)`, `.Wait()`, `.Stop()`, `.StopWithTimeout(d)`, `.ForceStop()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Create a test disk | `(*VM).CreateDisk()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Drive the QEMU monitor | `(*VM).ConnectMonitor`, `.Monitor()`, `.Pause`, `.Resume`, `.Reset`, `.VMStatus` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Enrol Secure Boot keys into OVMF NVRAM | `qemu.NewSecureBootEnroller(*SecureBootEnrollerConfig, logger)` → `EnrollKeys`, `IsEnrolled`, `ValidateEnrollment`, `GetEnrollmentStatus`, `InitializeNVRAM` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Run a software TPM | `swtpm.NewSWTPM(*Config, logger)` → `Initialize`, `Start`, `Stop`, `WaitForSocket`, `IsInitialized`, `SocketPath`, `PID`; `swtpm.StopExisting(dir)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

`qemu.BootMode` is `BootModeInstall` (`install`), `BootModeBoot` (`boot`) and
`BootModePXE` (`pxe`). The vTPM *product* surface — bundles, templates and
runtime TPM ops over all six transports — is a different feature
([`docs/vtpm/api.md`](../vtpm/api.md)); `pkg/qemu` + `pkg/swtpm` here are the
installer's test harness only.

## 7. Capabilities that belong to another feature

Documented here as rows so the reader can find them, with the owning folder
named. **Do not treat this table as the installer's API.**

| Capability | Owned by | Where it is documented |
|---|---|---|
| Remote Secure Boot digest signing | Config delivery (`ConfigDeliveryService.SignDigest`) | [`docs/provisioning/api.md`](../provisioning/api.md) §3 — gRPC, QUIC (`0xCF`) and MCP; **no REST** |
| Fetch a per-node install config before enrolment | Config delivery (`FetchConfig`, `GetNonce`) | [`docs/provisioning/api.md`](../provisioning/api.md) §3 |
| Authorize / quarantine / retry a machine being provisioned | `PXEService` | [`docs/provisioning/api.md`](../provisioning/api.md) §2 |
| Report install completion | `PXEService.WebhookComplete`, `POST /api/v1/pxe/webhook/complete` | [`docs/provisioning/api.md`](../provisioning/api.md) §2 |
| Upload the install log | iPXE HTTP server, `PUT /installs/{hostname}/{filename}` | [`docs/ipxe/api.md`](../ipxe/api.md) §3 |
| Serve the network boot | iPXE DHCP/TFTP/HTTP | [`docs/ipxe/api.md`](../ipxe/api.md) |
| Running-system LUKS operations | `LUKSService`, QUIC `0x9C` | [`docs/daemon/api.md`](../daemon/api.md) §4 |
| BMC virtual-media boot of the ISO | `BMCService`, QUIC `0x9F`, 23 `platform_bmc_*` MCP tools | [`docs/provisioning/api.md`](../provisioning/api.md) §5 |

**The installer certificate authorizes only the install-completion webhook
(Codex 8200).** On gRPC the mTLS interceptor admits it only to
`PXEService/WebhookComplete`, and every other method returns
`PermissionDenied`. On REST it reaches only `POST /api/v1/pxe/webhook/complete`,
which authenticates the certificate itself. Every scope-guarded route refuses it
because it carries no scope. QUIC and MCP have no certificate-bound webhook
route: their webhook operation is scope-guarded like every other one, so they
refuse the installer certificate. Only the operator's admin certificate is
granted the platform API; see
[`docs/auth/architecture.md`](../auth/architecture.md) §5, *The two mTLS
principals*.

**The daemon REST listener enforces the boundary itself (Codex 8242).** Many
daemon REST routes have no scope guard, among them
`POST /api/v1/services/{service}/stop` and `DELETE /api/v1/kms/keys/{id}`, so a
check that ran only where the guard runs would leave them open. A listener
middleware (`installerBoundaryMiddleware`, `pkg/api/daemon/rest_service.go`)
therefore answers 403 to a verified client certificate that is not the operator
(installer, gateway or device) on every route except the machine-facing
allowlist `installerMachineRoutes`. That allowlist covers the health and
readiness probes (`/health`, `/health/live`, `/health/ready`,
`/api/v1/health`), the public CA material (`/api/v1/ca/info`, `crl`,
`bundle`), gatewayd's four control-plane routes under `/api/v1/gateway/`, which
bind the request to the gateway the certificate names, and the device
config-delivery routes (`provisioning/config/nonce`, `provisioning/config`,
`provisioning/sign`, `provisioning/sessions/{sessionID}/poll`), which
authenticate the device themselves. A bearer header does not lift the refusal.
A request with no verified certificate goes to the route's own checks as
before. The completion webhook is served by the webservice listener, not this
one.

## 8. Errors as they would cross a transport

There is no transport, so there is no wire mapping to record. For the day one
is added, the mapping implied by
[`docs/daemon/api.md`](../daemon/api.md) §4's status vocabulary and the typed
errors in [engineering.md](engineering.md) §6 would be:

| QUIC byte | Name | REST | Installer cause |
|---|---|---|---|
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidConfig`, `ErrSecureBootConfig` |
| `0x02` | `StatusNotFound` | 404 | `ErrProfileNotFound`, `ErrISONotFound`, `ErrDirectoryNotFound`, `ErrKernelImageNotFound` |
| `0x04` | `StatusInternalError` | 500 | `ErrDiskOperation`, `ErrEncryption`, `ErrOSInstall`, `ErrUKIBuild`, `ErrBuildFailed`, `ErrExtractionFailed` |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrDirectoryAlreadyExists` |
| `0x07` | `StatusPermissionDenied` | 403 | `ErrSecureBoot`, `ErrModulesUnsigned` |
| `0x0A` | `StatusUnavailable` | 503 | `ErrTPM` when no TPM device is present |

This table is **illustrative**. Nothing in the code produces these codes today.

## 9. Authorization

Not applicable. Every capability above requires local root on the machine being
installed or on the build host. No `scp` claim gates any of it, because no token
is presented — the only credential in play during Phase A is the EAB credential
the node presents *to* the control plane for `SignDigest` and `FetchConfig`,
which provisioning owns and documents.

**Physical access to the install media and to a node between installation and
first boot is the authorization boundary.** See
[architecture.md](architecture.md) §6.

## 10. Versioning

No routes, so nothing to version and nothing deprecated. The version surfaces
that do matter for compatibility are on disk, not on a wire, and are listed in
[engineering.md](engineering.md) §8: the ESP seal filenames and the LUKS keyslot
indices. Changing either breaks every already-installed node.
