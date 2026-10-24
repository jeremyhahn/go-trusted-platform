# Bootstrap — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/bootstrap/`, `pkg/firstboot/`, `pkg/boot/`, `pkg/barrier/`, `pkg/api/rest/init_handlers.go` · Last verified: 2026-10-19
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was read out of the packages named above on 2026-10-19.
> Where the legacy files in this folder disagree with the code, the code wins and
> the correction is recorded in §12.

---

## 1. Package layout

`pkg/bootstrap/` — day-zero orchestration plus the platform-side trust surface:

| File | Holds |
|---|---|
| `orchestrator.go` | `Orchestrator`, the phase sequence, `BootstrapResult`, the HTTP health checker |
| `orchestrator_dryrun.go` | `DryRun`, `DryRunResult`, `SwitchPlan` |
| `orchestrator_errors.go` | Phase-level and seeding typed errors |
| `pxe_config.go` | `BootstrapConfig` and everything it contains; load and `Validate` |
| `pxe_errors.go` | Config-validation typed errors |
| `discovery.go` | `DiscoverNodes`, `DiscoveredNode`, `DiscoveryOptions`, `buildBMCConfig` |
| `board_controller.go` | `BoardController`, `hasBoardManagement` |
| `virtual_media.go` | Virtual-media boot, per-MAC staging, CP CA-bundle and SPKI capture |
| `install_log_poller.go` | `InstallLogPoller`, `InstallLogResult` |
| `iso_stager.go` | `ISOStager` implementations and freshness metadata |
| `seeder.go` | `Seeder`, template upload, profile creation |
| `config_inheritance.go` | `ApplyNetworkIdentity`, `ApplyNodeIdentity`, `DeviceIdentity` |
| `container/` | `Manifest`, `ManifestEntry`, `BuildManifest`, `LoadManifest`, the container-side `Server` |
| `nbd/` | The NBD-over-TLS export server for `diskless-nbd` roots (§2) |
| `deployer/` | `Deployer`, `DeployConfig`, `DeployResult`, the Linux backend, pinned SSH, netboot media staging |
| `deployer_adapter.go` | `NewLinuxDeployerAdapter` — the only translation from platform config to `deployer.DeployConfig` |
| `dane_publisher.go` | `DANEPublisher`, `DANEDNSService` |
| `rollover.go` | `RolloverManager`, `RolloverPhase` |
| `cert_reloader.go` | `CertReloader` |
| `bundle_provider.go` | `CABundler`, `CABundleAdapter` |
| `secrets.go` | Secret-URI scheme and strategy constants, `IsSecretURI`, `ExpandShortKMSPath` |
| `config_writer.go` | `ConfigWriter`, `SecretUpdate` |
| `config.go` | `Config`, `NoiseServerConfig`, `DefaultConfig` |
| `network_plan.go` | `BootstrapConfig.NetworkPlan`, the switch config, the retired-key check (`ErrRetiredKey`, `ErrSwitchPortClass`) |
| `node_platform.go` | Node platform, architecture and Pi boot model (`PlatformRaspberryPi`, `BootModelDiskless`, `BootModelDisklessNBD`), netboot-media validation |
| `node_resolve_rules.go` | Per-node config checks: merged addresses and IDevID, the diskless install-target refusal |
| `control_plane_identity.go` | `ControlPlaneTLSName`, `ControlPlaneAddresses`, the control-plane port and per-node TLS names |
| `bmc_trust.go` | `NewBootstrapBMCTLSProvider`, the per-node BMC trust config |
| `media_read_probe.go` | `MediaReadProbe`, `MediaReadResult`, `MediaReadBaseline`: the advisory smbd media-read watch |
| `console_transcript.go` | `ConsoleTranscript`: the per-attempt SOL transcript |
| `console_diagnostics.go` | The media-read wait and the forensic upload of a failed attempt |
| `secret_fields.go` | `PlaintextSecretFields`: plaintext secrets found by walking the config schema |
| `errors.go` | The bulk of the typed error set |

`pkg/firstboot/` — the node-side first boot: `strategy.go`
(`FirstbootSealStrategy`), `executor.go` (`Executor`, `TPMDetector`, `TPMType`),
`types.go` (`Config`, path constants, sentinels), `errors.go` (error shapes).

`pkg/boot/` — the initramfs binary's commands: `commands/boot.go`,
`commands/recovery.go`, `commands/manager.go`, `commands/root.go`, and
`config/config.go` (`BootConfig`, `InstallerPassword`), kept dependency-light on
purpose so `platform-initrd` stays small.

`pkg/barrier/` — `Manager` and `Config`, a wrapper over the quicbaas SDK's
barrier and ceremony clients.

## 2. Exported surface

### Orchestration

```go
func NewOrchestrator(params OrchestratorParams) (*Orchestrator, error)
func (o *Orchestrator) Run(ctx context.Context) (*BootstrapResult, error)
func (o *Orchestrator) Discover(ctx context.Context) ([]DiscoveredNode, error)
func (o *Orchestrator) DryRun(ctx context.Context) (*DryRunResult, error)
func (o *Orchestrator) ControlPlaneCAPool(ctx context.Context) (*x509.CertPool, error)
func (o *Orchestrator) ControlPlaneTLSName() (string, error)
func (o *Orchestrator) ControlPlaneAddresses(node *DiscoveredNode) []string
```

`OrchestratorParams` fields: `Config`, `ConfigPath`, `BMCFactory`, `Logger`,
`Deployer`, `HealthChecker`, `ConfigServerReadiness`, `TrustConfig`,
`SkipVirtualMediaMount`. A nil `ConfigServerReadiness` selects the real HTTP
probe of the container's `/health` and boot-script endpoints. `Config` and
`BMCFactory` are required — a nil either way returns `ErrNilOrchestratorConfig`
or `ErrNilBMCFactory`. `Orchestrator.SkipVirtualMediaMount` is a public field and
may be set after construction.

Collaborator interfaces, all defined in this package so a caller can substitute:

```go
type Deployer interface {
    Deploy(ctx context.Context, manifest *container.Manifest) error
    Teardown(ctx context.Context) error
}
type HealthChecker interface { Check(ctx context.Context, address string) error }
type ServerNameHealthChecker interface { CheckServerName(ctx context.Context, address, serverName string) error }
type ConfigServerReadiness interface {
    WaitReady(ctx context.Context, baseURL string) error
    WaitDeviceScriptReady(ctx context.Context, baseURL string) error
}
type BoardController interface {
    PowerOn(ctx context.Context) error
    PowerOff(ctx context.Context) error
    PowerReset(ctx context.Context) error
    PowerCycle(ctx context.Context) error
    PowerStatus(ctx context.Context) (bmc.PowerState, error)
    SetBootDevice(ctx context.Context, device bmc.BootDevice, persistent bool) error
    MountVirtualMedia(ctx context.Context, spec *bmc.MediaSpec) error
    UnmountVirtualMedia(ctx context.Context) error
    ClearUEFIBootEntries(ctx context.Context) error
    Close() error
}
type ISOStager interface {
    StageVirtualMediaISO(ctx context.Context, localISOPath string) (smbURL string, err error)
}
```

`var _ BoardController = (bmc.Client)(nil)` is a compile-time assertion: if the
BMC client drops a method the orchestrator needs, the build fails rather than a
run.

### Configuration and discovery

```go
func LoadBootstrapConfig(path string) (*BootstrapConfig, error)
func (c *BootstrapConfig) Validate() error
func (c *BootstrapConfig) ValidateDefinition() error
func (c *BootstrapConfig) NetworkPlan() (*netplan.Plan, error)
func (c *BootstrapConfig) EffectiveBackupsDir() (string, error)
func (d *DeployerConfig) EffectiveDataDir() string
func (d *DeployerConfig) EffectiveSMBHost() string
func (d *DeployerConfig) EffectiveRedeployMode() RedeployMode
func (n *NodeConfig) EffectiveBootMethod() string
func (n *NodeConfig) IsBMCManaged() bool
func (n *NodeConfig) IsManual() bool
func (n *NodeConfig) HasBoardManagement() bool
func (n *NodeConfig) PrimaryMAC() string
func (n *NodeConfig) StaticIPv4s() []string
func (n *NodeConfig) UnmarshalYAML(value *yaml.Node) error
func DiscoverNodes(ctx context.Context, nodes []NodeConfig, logger *slog.Logger, opts ...DiscoveryOptions) ([]DiscoveredNode, error)
```

`Validate` is `ValidateDefinition` plus the check that the deployer's netboot
media build is on disk; work that only reads the config (resolving each node's
platform config) calls `ValidateDefinition`.

Constants: `RoleControlPlane`, `RoleGateway`, `RoleWorker`; `BootMethodPXE`,
`BootMethodVirtualMedia`; `RedeployAlways`, `RedeployIfStale`, `RedeployNever`;
`DefaultDeployerDataDir` (re-exported from `deployer.DefaultRemoteDataDir`).

### Seeding and config merge

```go
func NewSeeder(params SeederParams) *Seeder
func (s *Seeder) Seed(ctx context.Context) error
func (s *Seeder) ProfileIDs() map[string]uint64
func ApplyNodeIdentity(m map[string]interface{}, node *NodeConfig) error
func ApplyNetworkIdentity(global *PlatformGlobalConfig, target *DeviceIdentity) *DeviceIdentity
```

### Trust surface

```go
func NewDANEPublisher(dnsService DANEDNSService, config *dnsconfig.DANEConfig, logger *logging.Logger) *DANEPublisher
func (p *DANEPublisher) PublishForCertificate(ctx, leafCert, caCert *x509.Certificate, hostname string, port uint16, zoneName string) error
func (p *DANEPublisher) PublishRecords(ctx context.Context, zoneName string, records []*entities.TLSARecord) error
func (p *DANEPublisher) PrePublishRollover(ctx context.Context, newCert *x509.Certificate, hostname string, port uint16, zoneName string) error
func (p *DANEPublisher) RemoveForHostname(ctx context.Context, hostname string, port uint16, zoneName string) error

func NewRolloverManager(publisher *DANEPublisher, reloader *CertReloader, config *dnsconfig.DANEConfig, logger *logging.Logger) *RolloverManager
func (m *RolloverManager) BeginRollover(ctx, newCert *x509.Certificate, newTLSCert *tls.Certificate, hostname string, port uint16, zoneName string) error
func (m *RolloverManager) Phase() RolloverPhase
func (m *RolloverManager) Wait(ctx context.Context) error

func NewCertReloader(initial *tls.Certificate) (*CertReloader, error)
func (r *CertReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error)
func (r *CertReloader) Reload(newCert *tls.Certificate) error
func (r *CertReloader) Current() *tls.Certificate

func NewCABundleAdapter(ca CABundler) *CABundleAdapter
func (a *CABundleAdapter) CABundle() ([]byte, error)

func NewBootstrapBMCTLSProvider(trustCfg *trust.Config, logger *slog.Logger) (bmc.TLSProvider, *xkmsbootstrap.MemoryPinStore, error)
```

`RolloverPhase` values: `RolloverIdle`, `RolloverPrePublish`, `RolloverActivated`,
`RolloverComplete`.

**Wiring status, verified on 2026-10-19.** `DANEPublisher` is
constructed in production (`app.ensureDANEPublisher`, shared with the
SDK-registered publisher adapter so there is exactly one DNS-write path).
`CertReloader` is constructed in production (`pkg/webservice/webserver_v1.go`)
and wired to `tls.Config.GetCertificate`. `platformd serve` registers each
webservice's `ReloadCertificate` through `App.RegisterWebServiceCertInstaller`,
and issuance calls it after a successful reissue, so a renewed certificate
reaches the live listener through `Reload`. `CABundleAdapter` is constructed in
`platformd serve` to feed the Noise listener. **`RolloverManager` has no
production caller at all**: the BMC certificate hooks (`pkg/app/bmc_cert_init.go`,
`pkg/app/bmc_enroll.go`) call `PrePublishRollover` and `PublishForCertificate`
on the publisher directly. Treat `RolloverManager` as an
implemented-but-unwired component, not as the live rollover path.

### Secrets

```go
const ( SchemeKMS; SchemeRemoteKMS; SchemeEnv; SchemeIDevID; SchemeFile; SchemeDynamic; SchemeXKMS;
        SchemeCredential; SchemeAutoGen )
const ( StrategyKMS; StrategyRemoteKMS; StrategyEnv; StrategyIDevID; StrategyFile;
        StrategyDynamic; StrategyXKMS; StrategyLiteral; StrategyPlainText )
const SecretStructTag = "secret"
func IsSecretURI(s string) bool
func ExpandShortKMSPath(path, tenantID, nodeID string) string
func PlaintextSecretFields(doc []byte, schema reflect.Type) ([]string, error)

func NewConfigWriter(path string, logger *slog.Logger) (*ConfigWriter, error)
func (w *ConfigWriter) Backup() (string, error)
func (w *ConfigWriter) Restore(backupPath string) error
func (w *ConfigWriter) UpdateSecretReferences(updates []SecretUpdate) error
func (w *ConfigWriter) DryRun(updates []SecretUpdate) ([]SecretUpdate, error)
func (w *ConfigWriter) Path() string
```

Resolution itself is **not** implemented here: the package doc states that
"secret resolution and config walking are delegated to the unified qrdb-SDK
`ResolverRegistry` / `ConfigProcessor`". `pkg/bootstrap` owns only the scheme
vocabulary, the `secret:"true"` struct tag, and the YAML rewriter.

`PlaintextSecretFields` (`secret_fields.go`) reads the tag: it walks a YAML
document against the struct it loads into and returns the paths
(`bmc.password`, `switches[1].password`) of every tagged field holding a
literal rather than an `IsSecretURI` reference. Keys match by yaml,
mapstructure or json name or field name, case-insensitively; inline and
squashed structs, anchors and merge keys are followed; unknown keys are
ignored. It fails with `ErrSecretSchemaNotStruct` or `ErrSecretDocumentParse`.
The diskless image build uses it against `app.App` to keep plaintext
credentials out of the public root ([factory-image](../factory-image/architecture.md)).

### First boot

```go
func NewExecutor(ctx context.Context, config *Config, logger *logging.Logger) (*Executor, error)
func (e *Executor) Run(ctx context.Context) error
func (e *Executor) TPM() xkmssdk.TrustedPlatformModule
func (e *Executor) Config() *Config
func (e *Executor) Close() error

func NewTPMDetector(logger *logging.Logger) *TPMDetector
func (d *TPMDetector) DetectTPMType() (TPMType, string, error)
func (d *TPMDetector) DetectOrStartTPM(swtpmStateDir string) (TPMType, string, bool, error)

func NewFirstbootSealStrategy(executor *Executor, luksHandler luks.Handler, logger *logging.Logger) *FirstbootSealStrategy
func (s *FirstbootSealStrategy) Name() string           // "Firstboot-Seal"
func (s *FirstbootSealStrategy) Priority() int          // 0 — highest
func (s *FirstbootSealStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool
func (s *FirstbootSealStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error
func (s *FirstbootSealStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error

func ProcessFirstbootMarkers(efiPath string) error
func CopyTmpfsToRoot(efiPath string) error
func DefaultConfig() *Config
```

`firstboot.Config` fields: `PCRSelection []uint`, `TPMAutoUnseal bool`,
`LuksTPMOnly bool`, `LuksDevice string`, `SwtpmStateDir string`,
`EFIMountPoint string`, `ConfigPath string`, `Debug bool`.
**`DefaultConfig` deliberately leaves `PCRSelection` nil** — there is no
hard-coded PCR set; it must come from configuration or the CLI flag.

### Barrier

`pkg/barrier.Manager` — its signatures, including the ceremony methods
bootstrap calls (`CeremonyInitialize`, `CeremonyStatus`, `BeginClaimCert`,
`CompleteClaimCert`, `BeginClaimShare`, `CompleteClaimShare`), and the
seal-strategy constants are documented in
[`docs/barrier/engineering.md` §2](../barrier/engineering.md#2-barriermanager)
and [§3](../barrier/engineering.md#3-configuration).

### NBD export server (`pkg/bootstrap/nbd`)

This is the boot-server half of `boot_model: diskless-nbd` (#689). The design
is in [architecture.md](architecture.md#nbd-export-server-diskless-nbd).

```go
const BootModel = "diskless-nbd"
const DefaultPort = 10809

func NewServer(cfg Config) (*Server, error)
func (s *Server) Serve(ctx context.Context, ln net.Listener) error
func (s *Server) Close() error

func Attach(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Export, error)
func ServerFromCmdline(cmdline string) (ServerAddr, bool, error)
func NewClientConfig(ctx context.Context, server ServerAddr, anchor *trust.Anchor, idevid tls.Certificate) (ClientConfig, error)
func OpenMetadataFile(volumeDir, identity, name string) (*MetadataFile, error)
```

`Attach` is the node's side of the negotiation below. It is specified with the
node contract in [installer engineering](../installer/engineering.md), and its
refusals are `ErrServerRefused`, `ErrTLSHandshake` and `ErrProtocol`.
`ServerFromCmdline` reads `platform_nbd_server`
([kernel-cmdline §4](../reference/kernel-cmdline.md#nbd-root-parameter)) and
refuses with `ErrCmdline`; the installer's `nbd` target calls it.
`NewClientConfig` builds `Attach`'s configuration from it; nothing calls
`NewClientConfig` or `Attach` yet.

`Config` holds the following fields:

- `Certificate`: the server's TLS certificate.
- `Anchor`: a `*trust.Anchor`, the platform anchor.
- `Identities`: the hostnames of the manifest's `diskless-nbd` entries.
- `VolumeDir` and `VolumeSize`: where volumes live and the size each is
  created at.
- `HandshakeTimeout`: default 30 s. It bounds the whole negotiation, the TLS
  handshake included; transmission has no deadline.
- `Logger`.

`Serve` returns `nil` when its context is cancelled or `Close` is called. In
either case it first closes the listener and every open connection, then
waits for their goroutines.

**Negotiation.** Only fixed newstyle is accepted. The server greets with
`NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES`. A client whose flags lack
`NBD_FLAG_C_FIXED_NEWSTYLE`, or carry an unknown bit, is disconnected. The
options are:

| Option | Before TLS | After TLS |
|---|---|---|
| `NBD_OPT_STARTTLS` | `ACK`, then the TLS 1.3 handshake | `NBD_REP_ERR_INVALID` |
| `NBD_OPT_GO`, `NBD_OPT_INFO` | `NBD_REP_ERR_TLS_REQD` | `NBD_INFO_EXPORT` (plus `NBD_INFO_NAME`, `NBD_INFO_BLOCK_SIZE` when asked), then `ACK`; `GO` enters transmission |
| `NBD_OPT_EXPORT_NAME` | connection closed (this option has no error reply) | export size and flags, then transmission |
| `NBD_OPT_ABORT` | `ACK`, close | `ACK`, close |
| any other | `NBD_REP_ERR_TLS_REQD` | `NBD_REP_ERR_UNSUP` |

**Client verification.** The TLS configuration asks for a client certificate
and verifies it in `VerifyConnection`. That callback reads `Anchor.CAPool` for
this handshake and calls `x509.Certificate.Verify` with `ExtKeyUsageClientAuth`
and the presented intermediates. This is the same check attestation caller
admission makes, and there is no second trust store. A CA rotation on disk
applies to the next handshake.

**Refusals.** Each one ends the connection, or refuses the option, with the
typed error that `serveConn` returns and `Serve` logs:

| Condition | On the wire | Typed error |
|---|---|---|
| client flags lack fixed newstyle or carry unknown bits | closed after the flags | `ErrUnsupportedClientFlags` |
| an option before `STARTTLS` | `NBD_REP_ERR_TLS_REQD`; `EXPORT_NAME` closes | `ErrTLSRequired` |
| no client certificate | TLS alert | `ErrClientCertificateRequired` |
| chain does not verify against the anchor | TLS alert | `ErrClientCertificateUntrusted` |
| anchor unreadable or empty | TLS alert | `ErrTrustAnchor` (wraps `trust.ErrAnchorUnavailable` / `ErrAnchorEmpty`) |
| verified identity not a `diskless-nbd` node | TLS alert | `ErrUnknownIdentity` |
| export name neither empty nor the identity | `NBD_REP_ERR_POLICY`; `EXPORT_NAME` closes | `ErrExportNotPermitted` |
| volume cannot be created or opened | `NBD_REP_ERR_PLATFORM`; `EXPORT_NAME` closes | `ErrVolume` |
| bad magic, oversized option, truncated message, `HandshakeTimeout` passed | closed | `ErrProtocol` |
| any other handshake failure | closed | `ErrTLSHandshake` |

**Transmission.** Requests are served in order on each connection, and every
reply is a simple reply. The export flags are `HAS_FLAGS | SEND_FLUSH |
SEND_FUA | SEND_TRIM`. The largest payload is 32 MiB.

| Command | Behaviour | Error codes |
|---|---|---|
| `READ` | reads the range | `EINVAL` out of range, over 32 MiB or unknown flags; `EIO` on a read failure |
| `WRITE` | writes the payload; with `FUA`, fsyncs before replying | `ENOSPC` past the end; `EINVAL` over 32 MiB (payload discarded) or unknown flags; `EIO` |
| `FLUSH` | fsyncs the volume | `EIO` |
| `TRIM` | punches a hole (`FALLOC_FL_PUNCH_HOLE`), or writes zeros where the filesystem cannot, so a trimmed range reads back as zeros | `EINVAL` out of range; `EIO` |
| `DISC` | fsyncs, closes the volume and the connection; no reply | — (a failed fsync ends the session with `ErrVolume`) |
| any other | — | `EINVAL` |

**Volumes.** A volume lives at `<VolumeDir>/<identity>.img`. The directory is
`0700` and each file `0600`. It is created with `O_EXCL` and truncated to
`VolumeSize` on the first attach. After that it keeps its own size, so changing
`VolumeSize` affects only new devices. Creation is serialised so that two first
attaches cannot race. `VolumeSize` must be positive and a multiple of 512. An
identity is accepted only as a DNS hostname (letters, digits, `-` and `.`), so
it can never name a path outside `VolumeDir`.

**Container wiring.** `container.NewServer` builds the export server only when
the manifest has a `diskless-nbd` entry; the identities are those entries'
hostnames, each once. Its settings are `ServerConfig.NBD`
(`container.NBDConfig`), set from pxeboot flags, which the entrypoint sets
from `BOOTSTRAP_NBD_*`:

| `NBDConfig` field | pxeboot flag | Entrypoint variable | Default | Required |
|---|---|---|---|---|
| `ListenAddr` | `--nbd-listen` | `BOOTSTRAP_NBD_LISTEN` | `<dhcp-server-ip>:10809` | — |
| `VolumeDir` | `--nbd-volume-dir` | `BOOTSTRAP_NBD_VOLUME_DIR` | `<data-dir>/nbd` | — |
| `VolumeSize` | `--nbd-volume-size` | `BOOTSTRAP_NBD_VOLUME_SIZE` | none | yes, bytes, a multiple of 512 |
| `CAFile` | `--nbd-ca-file` | `BOOTSTRAP_NBD_CA_FILE` | none | yes, the platform CA bundle |
| `CertFile` | `--nbd-cert` | `BOOTSTRAP_NBD_CERT` | none | yes |
| `KeyFile` | `--nbd-key` | `BOOTSTRAP_NBD_KEY` | none | yes |

A manifest with no `diskless-nbd` entry needs none of them, and no NBD port
opens. With one, a missing or malformed field fails `NewServer` with
`ErrInvalidServerConfig` (`nbd.listen_addr`, `nbd.volume_size`, `nbd.ca_file`,
`nbd.cert_file`, `nbd.key_file`), an unreadable or mismatched certificate and
key with `ErrNBDCredentials`, and a value the export server refuses with
`nbd.ErrInvalidConfig`. `Start` binds the NBD listener after the iPXE
listeners and before the device-script port, so the port the deploy gate
probes answers only once a `diskless-nbd` root is reachable; a failed bind is
`ErrServerStartFailed` and the device-script port never opens. `Stop` closes
the export server.

`bootstrap.yaml` accepts `boot_model: diskless-nbd` on a Raspberry Pi
(`BootModelDisklessNBD`, in `validPiBootModels`); a generic node is refused
with `ErrInvalidNodePlatform` on `boot_model`. The model reaches the
container manifest per MAC, and `nodeBootArgs` adds
`platform_boot_model=diskless-nbd` and `platform_nbd_server=<host>:<port>` to
the set's installer arguments. The address is `NBDConfig.ListenAddr`; an empty
or wildcard host (`:10809`, `0.0.0.0`, `::`) becomes the DHCP server IP, the
container's address on the provisioning segment. When no dialable address
follows, the node's device script fails with `ErrNBDServerAddress`. The
export's identity is not on the line: the server takes it from the verified
IDevID. The set needs no diskless root. The deployer does not set the `BOOTSTRAP_NBD_*`
variables yet: the volume size, the server certificate and the CA bundle have
no `bootstrap.yaml` source. Until they do, a deploy whose manifest names a
`diskless-nbd` node fails closed when the container starts, with
`ErrInvalidServerConfig`. The installer's `nbd` target installs a
`diskless-nbd` node onto `/dev/nbd0` once the export is attached, and refuses
(`ErrorTypeNBDTarget`) before it formats anything when it is not; it never
clears this model's TPM, which holds the IDevID the export attaches with ([installer engineering](../installer/engineering.md#the-installer-target-nbd)).

### The diskless-nbd runtime path

A `diskless-nbd` node boots the installer until its export holds an install,
then boots the UKI the install wrote. Its device script decides which on every
request (`deviceBootInfo`, `pkg/bootstrap/container/server.go`) by reading the
export's [metadata area](../installer/engineering.md#the-nbd-metadata-area)
with `nbd.OpenMetadataFile(NBDConfig.VolumeDir, <hostname>, "EFI/BOOT/<file>")`,
where `<file>` is `uki.BootFileName` for the media set's architecture
(`BOOTX64.EFI`, `BOOTAA64.EFI`):

| Export | Device script |
|---|---|
| none, or blank (`nbd.ErrNotInstalled`) | the installer, as above |
| holds the UKI | `kernel http://<device-script listener>/boot/uki/<mac>.efi`, then `boot`: no `initrd` line, no arguments |
| partitioned but unreadable (`nbd.ErrMetadataArea`) | HTTP 500; the node is never handed the installer, which would format the export |

`GET /boot/uki/{mac}.efi` is served on the device-script listener beside
`/boot/device/{mac}.ipxe` (`deviceScriptMux`). It streams that one file from
the export, as `application/octet-stream` with its `Content-Length`. It answers
400 for a malformed MAC, 404 for a MAC not in the manifest
(`ErrMACNotInManifest`), one that is not `diskless-nbd` (`ErrNotDisklessNBD`)
or one whose export holds no install, and 500 for an unreadable area. Only a
manifest MAC's own export is read, and only that path in it.

The UKI's command line is the signed one the installer embedded
(`platform_nbd_server` and the root parameters,
[kernel-cmdline](../reference/kernel-cmdline.md)); the script passes none,
and under Secure Boot systemd-stub ignores load options anyway. The boot after
this needs the initrd half, which is **Planned** (`pkg/initrd`): attach
`/dev/nbd0`, unlock the LUKS2 root on `/dev/nbd0p2` from the seal in
`/dev/nbd0p1`, and activate the volume group inside it, since the UKI carries
no `rd.luks.*` or `rd.lvm.*`.

## 3. Invariants

1. **The phase sequence is fixed and the result names the phase.** Every phase
   failure is wrapped in `ErrBootstrapFailed{Phase, Cause}`, and
   `BootstrapResult` is returned *alongside* the error so a partial run is still
   readable. `Run` returns `Phase: "complete"` only on full success.

2. **The control plane is provisioned before anything is seeded.** `Run` returns
   `ErrNoControlPlaneNode` rather than proceeding without one, both at
   provisioning and at seed time.

3. **Control-plane count is 1, or odd and ≥ 3.** `Validate` rejects 0, 2, and any
   even count with `ErrInvalidControlPlaneCount`. This is a quorum rule, not a
   style preference.

4. **A node has an identity or it does not provision.** Either `bmc_address` or
   at least one MAC, unless `skip_install: true`. Enforced by
   `ErrNodeMissingIdentity`.

5. **MAC uniqueness across the fleet.** Duplicate MACs are `ErrDuplicateMAC`;
   duplicate `bmc_address` values are rejected by `ErrInvalidBootstrapConfig`.
   Addresses are unique too, but in the *merged* configs: `checkNodeConfigs`
   resolves every node (with no hardware identity) and refuses an address two
   nodes both assign, on an interface, bridge, bond, bond zone VLAN, VLAN or the
   platform VRF (`ErrDuplicateNodeAddress`). It also refuses a `tpm.idevid`
   model and serial two nodes both carry (`ErrDuplicateIDevIDSerial`), since
   the pair names the device in its IDevID certificate. A `diskless` node is
   left out of that check (`keepsConfigSerial`): platformd replaces its
   config's serial with its EK-derived name on every boot
   (`applyDisklessNodeIdentity`), so the serial every node of a media set
   shares never reaches a certificate. A `diskless-nbd` node boots its own
   root and keeps its serial. The same pass refuses a diskless
   node (`diskless` or `diskless-nbd`, not `skip_install`) whose merged config
   keeps `install-target: image` (`ErrDisklessImageTarget`, also raised by
   every resolve of that node). It runs first in `Run` and `Deploy` (phase
   `discovery`, before any BMC or container is touched), at the end of the
   dry-run, and after `ResolveNodeConfigs`, whichever nodes were asked for. A
   node that fails to resolve for any other reason is skipped there and left to
   per-MAC staging's fall-back.

6. **`skip_install` nodes participate in everything except installation.** No
   discovery, no ISO staging, no power operations; still validated, still seeded,
   still health-gated, marked `skipped` in the result.

7. **A node without board management gets zero hardware operations.** No power,
   no boot device, no media. Combining that with `boot_method: virtual-media` is
   a config error (`ErrVirtualMediaRequiresBoardManagement`), caught at validation
   and again defensively at provision time.

8. **Discovery is concurrent and all-or-nothing.** `DiscoverNodes` fans out one
   goroutine per BMC-managed node and returns the first
   `ErrNodeDiscoveryFailed`. A BMC MAC-discovery failure is survivable *only*
   when the operator supplied MACs, in which case it degrades to a warning.

8a. **The node's hardware identity comes off its BMC client, not off
    `SystemInfo`.** Discovery calls `bmc.Client.HardwareIdentity` — the value
    that client feeds to `quirks.ResolveIdentity` — and parks it on
    `DiscoveredNode.HardwareIdentity`. `resolveNodeConfig` and
    `Seeder.buildMergedConfig` write it into both config-delivery paths as
    `hardware-manufacturer` / `hardware-model` / `hardware-part-number`, so the
    installed OS selects the entry the BMC side already selected. Rebuilding
    the identity from `SystemInfo` would resolve a different entry — the two
    surfaces read different fields (see
    [`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md)).
    A BMC that answers but names nothing writes empty keys, so both sides land
    on `Default()`; a BMC that could not be read writes nothing, so a
    hand-pinned identity survives a transport hiccup.

8b. **Every template read goes through `BootstrapConfig.TemplatePath`.** It
    is the single seam that resolves a relative `templates:` entry against
    the bootstrap YAML's own directory (`Orchestrator.configDir`, and the
    `SeederParams.ConfigDir` the orchestrator hands the seeder), leaving an
    absolute path as written. Five readers share it: `resolveNodeConfig`
    (the `--dry-run` plan, the virtual-media per-node config, and the
    control-plane TLS name) and the seeder's `uploadTemplates` and
    `buildMergedConfig`. Before #172 the seeder's two readers indexed
    `config.Templates` directly and read relative paths against the process
    working directory, so the same entry could name one file in the staged
    config and a different one in the uploaded template and seeded profile,
    and `--dry-run` validated a resolution the real run did not use. Do not
    reintroduce a direct `config.Templates[role]` read.

8c. **An incomplete identity is propagated and logged at WARN, never
    silently dropped.** The IPMI path returns a vendor-only identity with a
    *nil* error when the FRU is definitively unavailable, so incompleteness
    is checked on the value rather than inferred from the error.
    `readHardwareIdentity` names the missing fields and reports
    `board_entry_reachable`, because an identity without both `Model` and
    `PartNumber` can only ever reach a manufacturer-wide entry — a
    difference that shows up as behaviour on a console, not as an error.
    A retryable failure is re-read before the partial is staged, and the
    answer kept across attempts is the one resolving the **most specific**
    quirk (`quirks.MoreSpecific`), with populated-field count only breaking a
    tie between equally specific answers — two equally complete readings of
    one board can resolve different entries.

8d. **Discovery reads the identity before `SystemInfo`, through the
    orchestrator's `bmcFactory`.** `Orchestrator.discover` passes its
    injected factory as `DiscoveryOptions.ClientFactory` (nil falls back to
    `bmc.NewDefaultClientFactory`), the same seam every other BMC call site
    in the package uses. The order matters: `HardwareIdentity` re-runs
    Redfish discovery fresh, while `GetSystemInfo` is served the client's
    negative cache. Read the other way round, a discovery blip failed
    `GetSystemInfo`, the identity retry recovered discovery, and the node
    kept no system info (#206). Read identity-first, system info rides the
    recovered discovery; when discovery never recovers, `GetSystemInfo`
    returns the cached failure at once. Both stay best effort — a client the
    factory cannot build costs the node its system info and identity, not its
    discovery. Do not reintroduce a locally built factory in
    `discoverBMCNode`: the recovery path is only testable through the seam
    (`TestOrchestratorDiscover_SystemInfoRidesRecoveredDiscovery`).

9. **Provisioning is concurrent within a phase and sequential across phases.**
   `provisionControlPlane` and `provisionRemainingNodes` both fan out through
   `provisionNodes`, which returns only after **every** node has finished — an
   early failure must not end the phase, and with it the run's PXE and
   registration services, under a sibling still installing. One failure is
   returned as that node's `ErrNodeProvisionFailed`; several as
   `ErrNodesProvisionFailed{Failures}`, in node order. Any failure still aborts
   the run at that phase.

10. **Override keys that duplicate authoritative fields are rejected, not
    merged.** Class A (`os.hostname`, `network.interfaces`, `bmc.address`,
    `bmc.username`, `bmc.password`, `bmc.protocol`) is rejected on *presence*.
    Class B (`domain`, `hostmaster`, `tenant-id`/`tenant_id`, `environment`) is
    rejected only when the value equals the corresponding non-empty platform
    global. Both produce `ErrForbiddenOverrideKey` carrying file and line.

11. **Merge precedence is fixed**: role template → platform global identity →
    external `overrides_file` → inline `overrides` → `ApplyNodeIdentity`.
    Platform globals overwrite unconditionally (templates ship non-empty example
    placeholders); node identity overwrites unconditionally (validation
    guarantees overrides never carry those keys).

12. **Config is published under every known MAC.** The node cannot be trusted to
    know which NIC will come up as `eth0`.

13. **Trust material is captured before it is used.** `ControlPlaneCAPool` fetches
    once and caches; the seeder and health checker verify against that pool.
    Operations that establish trust material refuse to run without it
    (`ErrCABundleRequired`). Every node's post-install health wait
    (`awaitPostInstallHealth`, shared by the PXE, virtual-media and unmanaged
    paths) captures the bundle first — for a gateway or worker it is already
    cached from Phase 3 — `awaitControlPlaneCAPool` retries
    "not up yet" failures on the health cadence, and a bundle that fails
    capture-then-verify, an empty bundle, or a control plane with no address
    or TLS name is terminal — and only then probes. The capture runs only when the
    orchestrator built the health checker itself; an injected `HealthChecker`
    owns its own trust, as it already does for `propagateCAPool`. Seeding
    (`seedTemplatesWithSeeder`) calls `ControlPlaneCAPool` before constructing
    the seeder and fails with `ErrCABundleRequired{Cause}` when the bundle
    cannot be captured; `Seeder.Seed` refuses a nil pool the same way. There is
    no system-pool fallback anywhere on the control-plane path.

13a. **The control plane is verified by name, dialed by address.** Identity
    certificates carry DNS SANs only, so a client that dials the control plane by
    IP must say which name it expects. `controlPlaneTLSName` resolves that name
    once per orchestrator — the `webservices[i].certificate.subject.cn` (else the
    first `sans.dns`) of the entry whose `tls-port` is `platform.control_plane_port`
    (default `8443`) in the merged control-plane
    config from `resolveNodeConfig`, logged at INFO with its config key; when the
    merged config carries none, `cp.` + `platform.domain`, logged at WARN; never
    the node hostname; `ControlPlaneTLSNameUnknownError` when neither exists —
    and it is the `ServerName` of the post-install health probe and the
    pre-teardown health gate (`ServerNameHealthChecker`, via `healthProbe`)
    and of the seeder, and the `VerifyOptions.DNSName` of the bundle capture
    and the SPKI pin capture. Seeding captures the pool before it picks the
    address to upload to, so a `registration.json` that lands during the
    capture wait is the address it uses. Callers outside the package that use
    `ControlPlaneCAPool` — `platformctl bootstrap status` — get the same name
    from `ControlPlaneTLSName` and the same addresses from
    `ControlPlaneAddresses`; the pool alone does not verify a control-plane
    certificate dialed by hostname or IP.

13b. **Trust material is captured only from the operator-declared address.**
    `fetchControlPlaneCABundle` and `fetchControlPlaneSPKIPin` dial the
    control plane's static IPv4 from `nodes[].interfaces` and nothing else. The
    bootstrap config is the authenticated statement of where the control plane
    is; `registration.json` is an unauthenticated PUT to the deployer's sink
    that anyone on the provisioning network can overwrite, and capture-then-
    verify only proves a bundle is self-consistent with whatever endpoint served
    it — an attacker who could choose that endpoint would have their own CA
    pinned. A control plane with no static IPv4 is rejected at discovery
    (`ControlPlaneStaticIPRequiredError`, from `discover`, so `Run` and
    `Discover` fail the same way; `DryRun` plans without discovering and does
    not yet report it); there is no fallback. Only **after** the pool is pinned
    do connections dial the control plane wherever it is reachable — the
    pre-teardown gate and `bootstrap status` through `controlPlaneDialCandidates`
    (`registration.json` IP, declared static IPv4s, hostname), the post-install
    probe through `candidateHealthAddresses` (the same order, plus the BMC and
    install-log addresses), the seeder at the first of registration IP, static
    IPv4, hostname that resolves: every one of those verifies against the pinned
    pool for the control plane's TLS name, so a redirected registration produces
    a TLS failure (and, where candidates are tried, the next candidate), never
    trust.

13c. **Gateways and workers are verified by name too (#655).** A node's platform
    listener (`nodeWebserviceTLSPort`, 9443) serves a leaf the control-plane CA
    issued through `device-attest-01`, with DNS SANs only. `postInstallTLSName`
    gives the post-install probe the control plane's name for the control plane
    and `nodeTLSName` for every other role: the subject CN, else first DNS SAN,
    of the `tls-port: 9443` entry — a `webservices:` list entry or the singular
    `webservice:` block — in the node's merged role template from
    `resolveNodeConfig`, logged at INFO with its config key. There is no
    fallback name: a template that names no such listener, or no template, is
    `NodeTLSNameUnknownError` before any probe runs. The probe verifies against
    the same captured pool as the control plane's, so a leaf from the node's
    local CA fails. Every shipped gateway and compute template therefore sets
    `certificate.acme.challenge: device-attest-01` on that listener;
    `TestShippedNodeTemplates_PlatformListenerIsIssuedByTheControlPlane` walks
    `configs/platform/templates/`, resolves each one's name through
    `nodeTLSName` and requires the challenge, and fails on any template file it
    cannot classify by role.

14. **Teardown is gated on control-plane health.** A failed gate skips teardown.
    A failed teardown is a warning.

15. **BMC enrollment never aborts a run.** Every attempt appends a
    `BMCEnrollOutcome`, success or failure.

16. **First boot is idempotent by artefact, not by flag.** The probe is
    `installer.luks` present **and** `seal-platform.pub` absent. A second boot
    with seal artefacts present skips TPM provisioning and sealing and unlocks
    from the preserved key, reporting the degraded state.

17. **The installer container is wiped only after the seal has proven itself.**
    First boot never wipes it, even when sealing succeeds: `Unlock` keeps
    `sealingSucceeded` false, so `closeInstaller` always preserves
    `installer.luks`. The next boot's `platform-initrd` destroys it
    (`sealConfirmation`, `pkg/boot/commands/sealconfirm.go`) only when the
    container is mounted and the root unlocked with the TPM-PCR strategy
    (`shouldConfirmSeal`). On any earlier failure it is preserved so the next
    boot can retry.

18. **`RolloverManager` is single-flight.** A second `BeginRollover` while a
    rollover is in progress returns `ErrRolloverInProgress`. Phase transitions
    use an atomic; `CertReloader` swaps an `atomic.Pointer` so TLS handshakes
    never take a lock.

19. **The pre-unseal REST surface accepts only its own state.** `/init` in
    `uninitialized`, `/unseal` in `sealed` or `unsealing`; anything else is 409.
    The one exception: an init service that implements `BarrierInitReplayer`
    answers an identical repeat of the init it already completed with the same
    response, so a lost admin bundle can be fetched again. `/init` is rate limited
    (429, `ErrInitRateLimited`).
    `/healthz` is always callable and reports `ready` only in `unsealed`. See
    [`docs/barrier/api.md` §2](../barrier/api.md#2-the-barrier-gate).

20. **The media-read watch is ADVISORY: it enriches the diagnosis and never
    aborts an attempt.** After power-on is verified, the orchestrator polls the
    bootstrap container's `/media/status` — the pxeboot media watcher's
    cumulative record, sampled every 250 ms, of descriptors on the staged ISO —
    for `defaultMediaReadWindow` (a package constant, 7 min, set from the
    2026-08-29 measurement on node-02: power-on → first per-MAC
    `installer.yaml` GET ≈ 6 min 15 s, install-log upload ≈ 10 min 30 s).
    Evidence, when it appears, is the
    ISO's `smbd` record for the node's own BMC address (`MediaReadProbe.Client`;
    Debian smbd titles each worker `smbd: client [ip]`, Alpine/musl smbd
    titles it `smbd[ip]` — carried in `/proc/<pid>/comm` and truncated by the
    kernel to 15 bytes, so a captured client may be an IP prefix, matched as
    one; only when no worker is titled does every `smbd` worker count)
    showing more activity — open events plus
    position changes — than the baseline taken while the chassis is confirmed
    off, between the power-off and the power-on (`MediaReadProbe.Baseline`,
    compared only against the same watcher instance) with a `last_activity`
    inside this attempt (`MediaReadProbe.Since`, recorded at the same instant,
    with the install-log poller's two-second slack); an observation ends the
    window early, and stale or foreign-process activity never counts.
    Foreign-node activity is excluded only as far as attribution reaches: a
    truncated capture is a prefix, so BMCs sharing it (a /24 management
    subnet) can vouch for each other — gotcha 8. **Absence of evidence is NOT evidence of a failed boot on this
    fleet, which is why the watch cannot gate.** Measured 2026-08-30 (#126,
    run 7): the ATEN BMC's ISO reads never appear as held smbd descriptors —
    zero opens across three full installs at 250 ms sampling, and zero on an
    independent 3-second `smbstatus` watch through the successful run-4
    install — while a deliberately held descriptor on the staged ISO IS
    recorded within one sample. The premise "smbd holds a descriptor while
    the host reads" is false for this SMB client (rapid open/read/close
    bursts or otherwise), not a plumbing defect; gating on it aborted and
    power-cycled three demonstrably healthy installs mid-write. A
    never-observed window is therefore a WARN (with a console-transcript
    snapshot) and the attempt falls through to the install-log wait — the
    authoritative signal — with the fact recorded; when the install log never
    appears, `ErrInstallLogNotFound.MediaNeverObserved` adds "the media
    watcher also never saw the ISO opened" to the final diagnosis. A
    container that does not serve `/media/status` (404), or one that never
    answers it usefully within the window (outage, 5xx including the
    watcher's own "no fresh sample" 503, garbage), is the same fall-through
    with "evidence unavailable" logged instead. Fast POST-halt detection may
    return behind evidence that actually exists on this fleet (SMB
    session-level read counters, network byte counters) — it must never come
    back on held-fd evidence alone. **Every attempt records the host's serial
    console.** Before the power cycle the orchestrator opens SOL through
    `bmc.Client.Console` on a BMC client of its own (the SOL receive loop
    takes over its client's RMCP+ socket, so it can never share the client
    the power commands go through) and streams it for the whole boot window;
    when the attempt ends — never-read, install log found, or install log
    missing — the transcript is uploaded to the sink as
    `/installs/<host>/console-attempt<N>.log` and its URL plus the last 40
    lines (`ConsoleTranscript`, escape sequences stripped) ride in
    `ErrInstallLogNotFound`. The upload runs on a context of its own,
    detached from the attempt's, which has typically expired by the time a
    forensic artifact is worth uploading (#126), and it gets **three
    attempts on three fresh connections** rather than one (#136). One
    attempt was the defect: `net/http` will not re-dial a **PUT** once any
    request byte is on the wire (`Request.isReplayable` excludes it), so a
    connection the far side had silently discarded consumed the whole
    deadline and lost the transcript — while the install-log poller and the
    media-read probe, both sitting in polling loops against the same sink,
    never noticed and reported it reachable. The upload keeps no idle
    connections for the same reason. Every failed attempt logs the size
    attempted and the phase it stalled in (`stalled_in=` — connecting,
    sending the body, or awaiting the response), so a future stall says
    where the time went instead of only that a deadline passed. A console
    that cannot be opened is a WARN and the attempt continues without it. **BIOS POST is not
    redirected to SOL on this fleet** (verified silent on COM1 and COM2
    through a full POST, 2026-08-29; the OS console is live on payload
    instance 1), so the transcript begins with the first thing an OS prints,
    and an empty transcript with zero media reads means "the firmware halted
    before the OS, or console redirection is disabled in BIOS" — the error
    says exactly that and never "booted from disk". Output with zero media
    reads is whatever the host booted instead, quoted.

21. **`--dry-run` reads every reachable BMC's System Event Log.** A log that has
    stopped recording (`EventLog.Full()`) and any memory fault on record
    (`EventLog.MemoryFaults()`, grouped per DIMM with the last message and time)
    become `DryRunNodeResult.Warnings`, folded into `DryRunResult.Warnings`. They
    never change readiness; a board with no log surface
    (`bmc.ErrUnsupportedOperation`) is silent, a failed read is itself a warning.

22. **A resolved config is deterministic.** Resolving the same `bootstrap.yaml`
    twice yields byte-identical YAML. `network.dns.search-domains` (the
    resolv.conf search list the installer writes) is in configuration order: the
    node's `domain`, its internal domain (`internal-domain` or `internal_domain`),
    then `platform.domain` and `platform.internal_domain`; a repeat keeps its
    first position and blanks are dropped (`Orchestrator.setSearchDomains`). It
    was once built from a Go map, so its order changed from run to run.

23. **A rollover never leaves the served certificate without a TLSA record**
    (RFC 7671 §8.1). Completion removes the old records at the name and keeps
    the one pre-published for the new certificate. If the new certificate
    cannot be loaded, the server keeps the old one, so the rollover is
    withdrawn: the pre-published record is removed, the old records stay, and
    `Wait` returns `ErrCertReloadFailed`. With key reuse the new record is
    published before the old ones are removed; a reload or publish failure
    leaves the zone as it was and is returned by both `BeginRollover` and
    `Wait`.

## 4. Error semantics

Every error in this feature is a typed struct or a package sentinel;
`fmt.Errorf` is not used. `Unwrap` is implemented wherever a cause exists, so
`errors.As` reaches the root.

### Config and validation (`pxe_errors.go`, `errors.go`)

| Error | Returned when |
|---|---|
| `ErrConfigFileNotFound{Path}` | `bootstrap.yaml` or a referenced overrides file is absent |
| `ErrParseYAML{Path, Err}` | YAML parse failure, or home-directory expansion failure |
| `ErrInvalidBootstrapConfig{Reason}` | No nodes; duplicate `bmc_address` |
| `ErrMissingRequiredField{Field}` | `deployer.host`, `platform.domain`, `environment` (from `NetworkPlan`), `nodes[].hostname`, `switch.port_assignments[].port`, `iso_path` when virtual media is used, `config path`; `deployer.user`, `deployer.ssh_key` and `deployer.container_image` when the deployer adapter is built |
| `ErrInvalidPort{Field, Port, Reason}` | A deployer or control-plane port outside 1-65535, the two container ports equal, or a derived device-script port past 65535; `dns.internal.port` at node-config resolution |
| `ErrInvalidNodePlatform{Hostname, Field, Value, Reason}` | An unknown `platform`, `architecture`, `model` or `boot_model`, Pi-only fields on a generic node, a `bmc_address` on a Pi, a malformed Pi `serial` |
| `ErrNetbootMediaRequired{Hostname, Reason, Err}` | `deployer.netboot_media_dir` unset or unusable, or the build lacks what a PXE-installed node boots (`validateNetbootMedia`) |
| `ErrSwitchPortClass{Port, Class, Cause}` | A `switch.port_assignments[]` class the plan cannot realise |
| `ErrRetiredKey{Path, Key, Line, Use}` | A retired literal-number key in `bootstrap.yaml` (`checkRetiredKeys`) |
| `ErrNodeDiscoveryFailed{Hostname, Cause}`, `ErrMACDiscoveryFailed{BMCAddress, Cause}` | BMC MAC discovery for a node failed |
| `ErrNodeConfigResolveFailed{Hostname, Cause}`, `ErrUnknownNode{Hostname}` | A node's merged config cannot be resolved; a hostname asked for is not in `bootstrap.yaml` |
| `ErrInvalidNodeRole{Hostname, Role}` | Role is not `control-plane`/`gateway`/`worker` |
| `ErrNodeMissingIdentity{Hostname}` | Neither `bmc_address` nor `macs` on an installing node |
| `ErrDuplicateMAC{MAC, Hostnames}` | The same MAC on two nodes |
| `ErrDuplicateNodeAddress{Address, Hostname, Where, OtherHostname, OtherWhere}` | Two nodes' merged configs assign the same address |
| `ErrDuplicateIDevIDSerial{Model, Serial, Hostname, OtherHostname}` | Two nodes that keep their config's serial (not `diskless`) carry the same `tpm.idevid` model and serial |
| `ErrDisklessImageTarget{Hostname, BootModel}` | A diskless node's merged config keeps `install-target: image` |
| `ErrInvalidControlPlaneCount{Count}` | Count is 0, 2, or even |
| `ErrInvalidBootMethod{Hostname, Value}` | `boot_method` is neither `pxe` nor `virtual-media` |
| `ErrVirtualMediaRequiresBMC{Hostname}` | `virtual-media` without `bmc_address` |
| `ErrVirtualMediaRequiresBoardManagement{Hostname}` | `virtual-media` on a node with no management block |
| `ErrInvalidBMCTrust{Hostname, Strategy}` | A `bmc_trust` entry outside `dane`/`spki`/`ca-file`. `tofu` gets a dedicated message explaining it cannot verify a BMC (#83) |
| `ErrForbiddenOverrideKey{Source, Line, Hostname, KeyPath, UseField}` | An override duplicates an authoritative field |
| `ErrNilConfigMap{}`, `ErrConfigKeyNotMap{Hostname, Key}`, `ErrInterfaceConvertFailed{Hostname, Cause}` | `ApplyNodeIdentity` cannot inject identity |

### Orchestration (`orchestrator_errors.go`)

`ErrBootstrapFailed{Phase, Cause}`, `ErrPhaseTimeout{Phase, Timeout}`,
`ErrNodeProvisionFailed{Hostname, Role, Cause}`,
`ErrNodesProvisionFailed{Failures}`, `ErrHealthCheckFailed{Address, Cause}`,
`HealthWaitTimeoutError{Cause, LastProbe}` (unwraps to both — `errors.Is` on the
context error still works, and the message carries the last probe failure, e.g.
an `x509` verification error, instead of a bare deadline),
`CABundleUnavailableError{Hostname, Attempts, Cause, LastErr}` (same shape, for
the pre-probe capture),
`ControlPlaneStaticIPRequiredError{Hostname}`, `ControlPlaneTLSNameUnknownError{}`,
`NodeTLSNameUnknownError{Hostname, Role, TLSPort, Cause}`,
`ErrControlPlaneHealthGateFailed{Timeout, Cause}`,
`ErrContainerDeployFailed{Host, Cause}`,
`ErrContainerServiceNotServing{Host, BaseURL, Listener, Cause}` (§4 *Paths
that fail closed*), `ErrContainerTeardownFailed{Host, Cause}`,
`ErrDeployerNotConfigured{}`,
`ErrNilOrchestratorConfig{}`, `ErrNilBMCFactory{}`, `ErrNoControlPlaneNode{}`,
`ErrDryRunBMCUnreachable{Hostname, BMCAddress, Cause}`, `ErrDryRunNoNodes{}`.

Seeding: `ErrSeedFailed{Cause}`, `ErrMissingSeederAddr{}`,
`ErrTemplateNotFoundForRole{Role}`, `ErrTemplateFileNotFound{Role, Path}`,
`ErrTemplateReadFailed{Role, Path, Cause}`,
`ErrTemplateYAMLParseFailed{Role, Path, Cause}`,
`ErrTemplateJSONConvertFailed{Role, Cause}`,
`ErrTemplateUploadFailed{Role, StatusCode, Cause}`,
`ErrTemplateMergeFailed{Hostname, Role, Cause}`,
`ErrProfileCreateFailed{Hostname, StatusCode, Cause}`,
`ErrProfileIDParseFailed{Hostname, Cause}`.

Trust capture: `ErrCABundleInvalid{URL}`, `ErrCABundleVerifyFailed{URL, Cause}`,
`ErrCABundleRequired{Operation, Cause}`, `ErrNoPeerCertificates{Endpoint}`,
`ErrCABundleEmpty{}`.

Boot and install: `ErrVirtualMediaBootFailed{Hostname, Cause}`,
`ErrISOStagingFailed{LocalPath, RemoteHost, Cause}`,
`ErrISOStageFreshnessCheck{Path, Cause}`, `ErrInvalidStageMeta{Field, Value}`,
`ErrBootDeviceSetFailed{Hostname, Device, Cause}`,
`ErrPowerControlFailed{Hostname, Operation, Cause}`,
`ErrPowerStateVerificationFailed{Hostname, Expected, Actual, Retries}`,
`ErrBootFromDiskDetected{Hostname, Attempt}`,
`ErrBootRetryExhausted{Hostname, MaxRetries, Cause}`,
`ErrBMCReconnect{Hostname, Operation, Cause}`,
`ErrInstallLogNotFound{Hostname, URL, Cause, Console, MediaNeverObserved}`,
`ErrMediaStatusUnavailable{URL, StatusCode}` (§3 invariant 20; `Console`
is a `*ConsoleTranscript` — the uploaded transcript URL and its last lines,
what silence means on this hardware, or why there is none — whose
`Summary()` is appended to the message; `MediaNeverObserved` appends the
advisory never-observed note),
`ErrInstallFailed{Hostname, ExitCode, LogURL}`,
`ErrRegistrationFetch{URL, Cause}`, `ErrBMCEnrollFailed{Cause}`.

Trust publication: `ErrDANEPublishFailed{Zone, Cause}`,
`ErrTLSAComputeFailed{CN, Cause}`, `ErrCertReloadFailed{Cause}`,
`ErrRolloverInProgress{Hostname}`, `ErrNoiseServerFailed{Cause}`,
`ErrInvalidConfig{Field, Reason}`.

Secrets and config rewriting: `ErrInvalidYAMLPath`, `ErrPathNotFound`,
`ErrBackupFailed`, `ErrBackupNotFound`, `ErrRestoreFailed`, `ErrWriteFailed`,
`ErrAtomicWriteFailed`, `ErrIndexOutOfBounds`, `ErrUnexpectedNodeType`,
`ErrEmptyPath`, `ErrEmptyUpdates`, `ErrNilLogger`, `ErrDryRunMode{UpdateCount}`,
`ErrSecretNotFound`, `ErrSecretStoreFailed`, `ErrInvalidURI`, `ErrAutoGenFailed`,
`ErrEnvVarNotFound`, `ErrRemoteKMSUnavailable`, `ErrDecryptionFailed`,
`ErrInvalidPINLength`, `ErrPINGeneration`.

Generic shapes used where nothing else fits: `MessageError{Msg}` and
`WrappedError{Msg, Err}` — both defined per package (`bootstrap`, `firstboot`,
`pkg/cli/commands/bootstrap`; `bootstrap/container` has its own
`MessageError`), plus `CommandOutputError` and `SentinelCauseError` in
`firstboot`.

### First boot sentinels

`ErrNoTPMDevice`, `ErrNoTPMConfig`, `ErrAlreadySealed`, `ErrSealingFallbackUsed`,
`ErrNoLUKSKey`, `ErrInvalidKeySize`, `ErrTPMNotAvailable`,
`ErrSSRKNotAccessible`, `ErrPlatformSRKNotAccessible`.

### Barrier

See [`docs/barrier/engineering.md` §6](../barrier/engineering.md#6-errors).

### Paths that fail closed

These refuse rather than degrade. Changing any of them is a security change.

| Path | Behaviour |
|---|---|
| Deployer and switch SSH | `deployer.NewSSHClient` returns `ErrInvalidDeployConfig{Field:"known_hosts_path"}` when no pin directory is configured. No trust-on-first-use exists. |
| Control-plane CA bundle capture | The served chain must verify against the fetched bundle, or `ErrCABundleVerifyFailed`; the bundle is never stored. Session tickets are disabled so the capture cannot be skipped by resumption. |
| Trust material that depends on the bundle | `ErrCABundleRequired{Operation}` rather than proceeding over an unverified connection. |
| `platformctl bootstrap status` | Reports `unknown` when no verified CA pool is available. It does not probe over an unverified TLS connection to produce a green result. |
| First-boot sealing | `ErrSealingFallbackUsed` on a plain-key fallback, so the caller exits non-zero and first boot re-runs. The `TRUSTED_PLATFORM` firmware variable is **not** set in that state. |
| Barrier pre-unseal surface | Only `/healthz`, `/init`, `/unseal` are bound. Wrong state is 409; an unwired backend is 503, never a silent success. |
| BMC trust | An unknown `bmc_trust` strategy is a validation error, not an ignored value. |
| Deploy phase (Phase 2) | **Both** container listeners must be up before the phase reports success, or `ErrContainerServiceNotServing` naming which one is not: the config server must answer `/boot.ipxe` and the device-script port must answer `/boot/device/{mac}.ipxe`, both with an iPXE script. Both halves are IDENTITY checks, not liveness ones, because the container runs `--net=host`: when an unrelated service already owns one of these ports — the reported failure — it accepts the connection and answers happily, so a TCP dial, or a 2xx from the generic `{"status":"healthy"}` that `/health` returns, would call the port healthy while pxeboot's own listener never bound. A boot script is distinctive; a health status is not. The device-script listener binds **last**, only after the iPXE server reports HTTP, TFTP and DHCP all bound, which is what makes answering it a complete readiness signal for all four: probing a port that comes up first would pass while a TFTP or DHCP bind failure was still in flight, and the node would then PXE-boot into nothing because TFTP is what serves the firmware. Each listener now binds before it serves, so a bind failure is synchronous and `ipxe.Server.Start` returns it instead of nil. A started container is not a running service — `docker run -d` printing an ID proves only creation, and `docker inspect` reports `Running` while supervisord has retired pxeboot inside it. Checking only `/health` is not enough either: the two listeners start in separate goroutines and the probe returns on first success, so a probe fired right after `docker run` can see `/health` answer just before the device-script bind fails, which is the bind that fails. The check runs even when `deployer.container_image` is empty and Phase 2 is otherwise skipped, so an operator-managed container is verified on the same terms. |

**Deliberately fail-open, and why:** BMC MAC discovery falls back to
operator-supplied MACs; per-MAC config staging falls back to the ISO-baked
default; registration lookup falls back to the declared static IP and then the
hostname; BMC enrollment failures are recorded and skipped; container teardown
failure is a warning. Each is a convenience path that cannot grant trust — none
of them decide whether something is trusted.

Per-MAC config staging stays on that list, but it is no longer the only thing
standing between a dead container and a wrongly-installed fleet: Phase 2 now
refuses to report success unless the config server answers, so staging is
reached only when the endpoint was serving at deploy time. The fall-back
remains what it was classified as — a per-node convenience for a reachable
server that has no config for this MAC — rather than the silent fleet-wide
default it became when the server was down. Making the staging call itself
fatal would flip that classification and is a separate decision.

## 5. Configuration

Two distinct configuration files, easily confused:

### `bootstrap.yaml` — the day-zero fleet description

Consumed only by `platformctl bootstrap`. Top level: `deployer`, `environment`,
`zones` (optional), `switch` (optional), `platform`, `templates`, `nodes`,
`iso_path`, `backups_dir`.

The network is the reference network's: `NetworkPlan` resolves `zones` onto the
built-in zones and derives the plan from `environment` with `pkg/sdn/netplan`,
the only place numbering is derived. The switch phase builds its
`switchmgmt.Config` from that plan (`buildSwitchConfig`): one VLAN per zone,
named after it, and each assigned port programmed with its class's mode,
allowed VLANs, native VLAN and MTU 9216. The dry-run `SwitchPlan` is built from
the same function, so what `--dry-run` prints is what Phase 1 applies.
`LoadBootstrapConfig` is otherwise lax YAML, so the retired literal-number keys
are refused explicitly (`checkRetiredKeys`, `ErrRetiredKey` with file and line)
rather than silently ignored.

| Key | Type | Default | Notes |
|---|---|---|---|
| `deployer.host` | string | **required** | Validation fails without it |
| `deployer.user`, `deployer.ssh_key` | string | — | Required by the deployer adapter |
| `deployer.known_hosts_path` | string | — | **Required in practice**: SSH fails closed without it |
| `deployer.container_runtime` | string | `docker` | Applied by `DeployConfig.ApplyDefaults` |
| `deployer.container_image` | string | — | Empty means Phase 2 is skipped entirely |
| `deployer.data_dir` | string | `/tmp/bootstrap` | `DefaultDeployerDataDir` |
| `deployer.redeploy_mode` | string | `if-stale` | `always`, `if-stale`, `never`; unrecognised values normalise to `if-stale` |
| `deployer.smb_host` | string | `deployer.host` | The address the BMC uses for the SMB share; also preferred for the install-log base URL |
| `deployer.bootstrap_interface` | string | container default `eth0` | Sets `BOOTSTRAP_INTERFACE` |
| `deployer.bootstrap_bind_host` | string | every interface | Sets `BOOTSTRAP_BIND_HOST` (pxeboot `--bind-host`): the address the container's HTTP and TFTP servers bind. Must be an IP address (`ErrInvalidConfig` at load). DHCP never binds it — see [`docs/ipxe/engineering.md`](../ipxe/engineering.md) |
| `deployer.bootstrap_server_ip` | string | container default | Sets `BOOTSTRAP_SERVER_IP`: the address advertised as DHCP server and next server, and the one the device-script listener binds; must be an address the deployer host already holds on a first bootstrap |
| `deployer.bootstrap_http_port` | int | `8080` | Sets `BOOTSTRAP_HTTP_PORT`. The container's HTTP service — per-MAC config endpoint, install-log sink, `/health` — and the port the orchestrator builds its own URLs against (`installLogBaseURL`) |
| `deployer.bootstrap_device_script_port` | int | `bootstrap_http_port` + 1 | Sets `BOOTSTRAP_DEVICE_SCRIPT_PORT`. The container's second listener, `/boot/device/{mac}.ipxe` and `/boot/uki/{mac}.efi`. Set it when something else on the deployer already owns the derived port |
| `deployer.bootstrap_dhcp_start` / `_end` | string | container defaults | `BOOTSTRAP_DHCP_START` / `BOOTSTRAP_DHCP_END` |
| `deployer.bootstrap_gateway`, `deployer.bootstrap_dns` | string | container defaults (gateway `192.0.2.1`) | `BOOTSTRAP_GATEWAY`, `BOOTSTRAP_DNS` |
| `deployer.bootstrap_no_router` | bool | `false` | `BOOTSTRAP_NO_ROUTER`: the container's DHCP offers and acks carry no router option (3), for an isolated provisioning VLAN whose boot server does not route. Set together with `bootstrap_gateway` it is `deployer.ErrNoRouterWithGateway` at load, and the entrypoint refuses the same pair with exit status 2 |
| `deployer.bootstrap_apk_mirror` | string | public mirror | `BOOTSTRAP_APK_MIRROR`; required on networks with no outbound internet |
| `deployer.netboot_media_dir` | string | — | A netboot media build (`container.NetbootMedia`: `netboot-media.yaml`, `SHA256SUMS`, `media/<set>/…`, the Pi TFTP tree, the db-signed arm64 iPXE, and optionally `http_boot`, the Pi's signed `boot.img`/`boot.sig`/`pubkey.bin`), relative to `bootstrap.yaml`. **Required** for a Linux deployer: the image carries no installer media. `validateNetbootMedia` checks, before anything deploys, that the build carries what each PXE-installed node boots — its architecture's default set, or for a Pi the `aarch64-rpi` set, the TFTP tree and the arm64 iPXE. The deployer copies it into `data_dir` as laid out, skipping the upload when the staged `SHA256SUMS` is the build's and still verifies, and removing what the build owns first otherwise |
| `deployer.proxy_dhcp` | bool | `false` | `BOOTSTRAP_PROXY_DHCP`: the container answers PXE clients with boot options and no lease, for a segment with its own DHCP server |
| `deployer.boot_node` | bool | `false` | Boot-node mode: the container is the segment's long-running netboot server. `docker run` gets `--restart unless-stopped` and a second volume, `firmware_cache_dir` → `/var/cache/go-trusted-platform/firmware`; Phase 7 skips the health gate and teardown, so neither the container nor `data_dir` is removed by a run. A re-run replaces the container (`rm -f` of the container only) and keeps both volumes; under `if-stale` a running container without the restart policy or the cache mount counts as stale. `if-stale` stays the default here, and it compares the image, the volumes and the restart policy, not the `BOOTSTRAP_*` environment: after changing a setting such as `bootstrap_no_router` or `proxy_dhcp`, force the replacement with `redeploy_mode: always`. `platformctl bootstrap teardown` still removes the container and `data_dir` and leaves the cache. `data_dir` must be absolute, not `/`, and not under `/tmp`, `/run` or `/dev/shm` (`deployer.ErrInvalidBootNodeConfig` at load) |
| `deployer.firmware_cache_dir` | string | `<data_dir>-firmware` | Boot-node only: the host directory holding pxeboot's iPXE firmware cache. Same path rules as `data_dir`, and must not overlap it, because teardown deletes `data_dir`. Set without `boot_node` it is `ErrInvalidBootNodeConfig` |
| `deployer.pxe_service_host` | string | gateway role | Which node should host PXE after hand-off. Parsed only: no phase reads it today, so nothing hands PXE off and `boot_node` does not consult it |
| `environment.id` | int | **required** | Environment number _E_ (2–40) |
| `environment.base`, `environment.ula`, `environment.overrides` | | `10.0.0.0/8`, none, none | `netplan.Environment` |
| `zones[]` | list | built-ins | `zone.ZoneConfig`: policy tuning and owner-defined zones |
| `switch.port_assignments[]` | list | — | `{port, class, description}`; `class` is a `zone.PortClass` the plan can realise (`ErrSwitchPortClass` otherwise) |
| `platform.domain` | string | **required** | |
| `platform.internal_domain`, `hostmaster`, `tenant_id`, `environment`, `upstream_dns`, `bootstrap_strategy` | | | Injected into merged device configs. `internal_domain` also becomes `quicbaas.spiffe-trust-domain`, and the seeder creates the `quicbaas:` section when the role template has none: platformd rejects at load an embedded-server config without the key ([daemon configuration](../daemon/configuration.md#required-keys-at-load)) |
| `platform.health_timeout` | duration | `25m` | How long the post-install health probe waits for a freshly installed node to answer. Omit the key to take the default; a Go duration string (`30m`, `1h`) overrides it. The key cannot be set to `0` — yaml.v3 rejects a bare `0` for a duration field, so "unset" is expressed by leaving the key out |
| `platform.control_plane_port` | int | `8443` (`DefaultControlPlanePort`) | TLS port of the control plane's webservice — the `webservices[].tls-port` its role template declares. The orchestrator dials it to capture the CA bundle and SPKI pin and to seed templates, selects the control plane's TLS name from the webservice entry on it, and tries it first in the post-install and `bootstrap status` health probes (then `9443`, `443`). Addresses are joined with `net.JoinHostPort`, so IPv6 literals work. Outside 1-65535 is `ErrInvalidPort` at config load; omit or `0` for the default |
| `templates` | map role→path | — | Missing role means the node is skipped at profile creation with a warning |
| `iso_path` | string | — | Required when any installing node uses `virtual-media` |
| `backups_dir` | string | `backups` beside `bootstrap.yaml` | A relative path is resolved against `bootstrap.yaml`'s directory and `~` is expanded, both at load |
| `nodes[].hostname` | string | **required** | |
| `nodes[].role` | string | **required** | |
| `nodes[].macs` (legacy `mac`) | list/string | — | The scalar form is migrated automatically and merged into the slice |
| `nodes[].bmc_address`, `bmc_user`, `bmc_password`, `bmc_protocol`, `bmc_encryption_key` | string | protocol `redfish` | `bmc_protocol` is `redfish`, `ipmi` or `auto`; unset or any other value is Redfish, and only `auto` probes the BMC (`bmc.DetectProtocol`), failing discovery with `ErrMACDiscoveryFailed` when nothing answers. `bmc_password` and `bmc_encryption_key` carry `secret:"true"` |
| `nodes[].bmc_trust` | list | the platform's `trust.bmc` scope | `dane`, `spki`, `ca-file`, `tofu`: the `ClassBMC` allowlist, queried from `pkg/trust` (`StrategyAllowedForClass`); anything else is `ErrInvalidBMCTrust`. `tofu` was barred under #83 and is allowed again since go-xkms#139 made it endpoint pinning |
| `nodes[].bmc_spki_pin` | string | — | Hex SHA-256 of the BMC SPKI; implies the `spki` strategy when no chain is declared |
| `nodes[].bmc_enroll` | bool | `false` | Opts the node into the enrollment phase |
| `nodes[].boot_method` | string | `pxe` | `pxe` or `virtual-media` |
| `nodes[].skip_install` | bool | `false` | Already-deployed node |
| `nodes[].platform` | string | — (generic server) | `raspberrypi`; without it `model` and `serial` are rejected. A Pi has no BMC, so `bmc_address` is rejected on it (`ErrInvalidNodePlatform`) |
| `nodes[].model` | string | — | **Required** for `raspberrypi`: `rpi4`, `rpi400`, `cm4`, `rpi3b+`, `rpi5` (`rpinetboot.Models`) |
| `nodes[].architecture` | string | `aarch64` for a Pi, else `x86_64` | `x86_64` or `aarch64`; a Pi must be `aarch64` (`EffectiveArchitecture`) |
| `nodes[].serial` | string | — | Pi only: up to eight hex digits, the bootloader's serial; names the node's per-device TFTP directory |
| `nodes[].boot_model` | string | `sd` for a Pi, empty for a generic server | `sd` for Pi SD-card install, or `diskless` for a stateless node whose root comes from the media set's squashfs+verity artifacts; carried per MAC in the container manifest, and its device script adds `platform_boot_model=diskless` (`ErrDisklessUnavailable` when the set has no diskless root); or, on a Pi only, `diskless-nbd` for a root exported by the boot server over NBD-over-TLS, whose device script adds `platform_boot_model=diskless-nbd` and `platform_nbd_server` (the export server's address; `ErrNBDServerAddress` when none is dialable) to the set's installer arguments |
| `nodes[].interfaces` | list | — | Authoritative for `network.interfaces` |
| `nodes[].overrides`, `nodes[].overrides_file` | map / path | — | File merged first, inline wins; the per-node place for addresses (`network.platform-vrf.address`, `network.vlans`, `network.bonds`), which no two nodes may share |
| `nodes[].switch_port` | string | — | Recorded for operator verification. There is no post-enrollment port move: a hypervisor trunk's native VLAN is provisioning |

The container's two ports are configurable, and one setting moves both the
server's binding and the URLs the orchestrator points at it. They were not: the
device-script listener was hardcoded to HTTP+1 at the bind and
`installLogBaseURL` returned a literal `:8080`. A deployer that already had
something on 8081 — an ordinary thing on the shared jumpbox the Linux deployer
documents — therefore killed pxeboot on bind with no way to move it.

Both ports are validated at config load: an explicit value must be in 1-65535, the two effective ports must differ, and `bootstrap_http_port: 65535` with the device-script port unset is refused because it would derive 65536. Catching these at load rather than at bind is the same principle as the deploy gate — a port problem should not first appear as a container that came up with nothing serving.

The control plane's webservice port is `platform.control_plane_port`, the same
setting for seeding, CA-bundle and SPKI capture, TLS-name selection and both
health probes; before #93 it was a package variable fixed at `8443`. The other
probe candidates, `9443` (compute) and `443` (gateway), are the role templates'
webservice ports and stay constants: the discovered node does not carry its
port, so the probe tries each (`BootstrapConfig.HealthProbePorts`).

Each node's dnsmasq forwards to the control plane's internal DNS zone
(`network.dns.upstream-dns`: `<cp-ip>#<port>` on other roles, `127.0.0.1#<port>`
on the control plane itself). The port is the control plane's own
`dns.internal.port`, read from its merged config — the setting platformd's DNS
service binds — so the forwarder and the listener cannot disagree; before #93 it
was a literal `9053`. A control-plane config that leaves it unset gets
`dns.DefaultInternalPort` (`9053`), the DNS service's own default. A value that
is not a port in 1-65535 fails node-config resolution with `ErrInvalidPort`
(field `dns.internal.port`), not a silent default.

### Platform config — the daemon's own bootstrap block

```yaml
bootstrap:
  noise:
    enabled: false        # default
    listen-addr: ":9999"  # default
    max-connections: 100  # default
    read-timeout: 10s     # default
    write-timeout: 10s    # default
```

`bootstrap.Config` / `NoiseServerConfig`, defaults from
`bootstrap.DefaultConfig()`. The listener starts only when
`bootstrap.noise.enabled` is true; a construction or start failure is logged as
a warning and the daemon continues without it.

Trust configuration (`trust.bootstrap` / `trust.bmc`, and the unconfigured
platform anchor) and DANE
publication (`dns.dane.*`) are owned elsewhere — see
[`docs/trust/engineering.md`](../trust/engineering.md#4-configuration) for the full key list and
[`docs/dns/dane.md`](../dns/dane.md) for the record semantics. The keys this
feature depends on are `strategies`, `server-url`, `hostname`, `bundle-path`,
`per-method-timeout`, `install-to-system-trust`, and the `dane`/`noise`/`spki`
sub-blocks.

**Environment variables.** The Go packages read none directly. The container
entrypoint consumes `BOOTSTRAP_INTERFACE`, `BOOTSTRAP_SERVER_IP`,
`BOOTSTRAP_HTTP_PORT`, `BOOTSTRAP_DEVICE_SCRIPT_PORT`,
`BOOTSTRAP_DHCP_START`, `BOOTSTRAP_DHCP_END`, `BOOTSTRAP_GATEWAY`,
`BOOTSTRAP_NO_ROUTER`, `BOOTSTRAP_DNS`, `BOOTSTRAP_APK_MIRROR`, the optional
`BOOTSTRAP_BIND_HOST`, and — for a netboot media build — `BOOTSTRAP_TFTP_DIR`,
`BOOTSTRAP_ARM64_IPXE` and `BOOTSTRAP_PROXY_DHCP`, all set from the deployer
block. The image's `pxeboot-env.sh`, sourced by the entrypoint, applies the
defaults and assembles the gateway and the optional four into one
`BOOTSTRAP_PXEBOOT_ARGS`, since an unset supervisord `%(ENV_*)s` would leave a
bare flag; under `BOOTSTRAP_NO_ROUTER=true` it passes no `--dhcp-gateway`, and
pxeboot then sends no router option. The NBD export server's `BOOTSTRAP_NBD_*` variables join
`BOOTSTRAP_PXEBOOT_ARGS` the same way; the deployer does not set them yet
(§2, *NBD export server*). An
unset port is omitted from the `docker run` command entirely so the entrypoint's
own default applies, and `BOOTSTRAP_DEVICE_SCRIPT_PORT` defaults to
`BOOTSTRAP_HTTP_PORT + 1` there, matching the offset pxeboot applies when its
flag is unset. On
the installed node, `PLATFORMD_DEBUG` is written into the daemon's environment
file by first boot. `platformctl` persistent flags have their own `PLATFORMCTL_*`
variables ([cli.md](cli.md) §1).

**Precedence.** Flag > environment > config file > built-in default, per the
platform convention. Inside `bootstrap.yaml` the merge precedence is the one in
§3.11. PCR selection: `platformctl firstboot` takes `--pcrs`, else `seal-pcrs`
(top level, `tpm.` or `installer.`) from `config.yaml`, and refuses to run with
neither; the seal strategy prefers the installer TPM config's `seal-pcrs` over
that selection. At every later boot `platform-initrd` takes `--pcrs` >
`pcr-banks` on the EFI partition (written by first boot) > `seal-pcrs` in
`config.yaml`.

## 6. Persistence

### On the deployer host

```
<data_dir>/                     # default /tmp/bootstrap, bind-mounted as /data
├── manifest.yaml               # MAC → role → hostname
├── netboot-media.yaml, SHA256SUMS      # the staged netboot media build's index
├── media/<set>/                # each media set: kernel, installer initramfs,
│                               #   modloop, payload.list, cdrom/
├── rpi-tftp/, firmware/        # the Pi TFTP tree, the db-signed arm64 iPXE
├── http-boot/                  # the Pi's signed HTTP boot: boot.img, boot.sig,
│                               #   pubkey.bin — served at /data/http-boot/ (the
│                               #   EEPROM's HTTP_PATH=data/http-boot); only when
│                               #   the build had --fleet-key
├── <platform>.iso              # staged for virtual-media, served over SMB
└── installs/                   # pxeboot's InstallsDir
    ├── <key>/install.log       # forensic sink, key is a MAC or a hostname
    ├── <key>/registration.json # PUT by platformd, MAC- or hostname-keyed
    └── config/mac/<mac>/{hostname,installer.yaml,ca-bundle.pem,bootstrap-spki-pin}
```

The per-MAC config sits under `installs/` (`pkg/ipxe/http_server.go`
`handleConfig`), though its URL is `/config/mac/<mac>/<key>`. An upload to
`/installs/mac/<mac>/<file>` and one to `/installs/<host>/<file>` both land in
`installs/<key>/<file>`.

The MAC in a path is dash-separated and lower-cased. Staging is a PUT; reading is
a GET. Nothing here is encrypted — see [architecture.md](architecture.md) trust
boundary 4.

### On the node's EFI partition

| Path | Written by | Meaning |
|---|---|---|
| `<efi>/tpm2/installer.luks` | installer | Encrypted container: LUKS key, recovery key, config |
| `<efi>/tpm2/seal-platform.pub` / `.priv` | first boot | The production seal. **Presence is the "already provisioned" marker.** |
| `<efi>/tpm2/seal-upgrade.pub` / `.priv` | nothing in production | Read by the `TPM-Upgrade` strategy every boot, which declines when the files are absent (`pkg/initrd/strategy_tpm_upgrade.go:117-118`). Both writers are unreached: `writeUpgradeSealedObjects` (`pkg/firstboot/executor.go:763-774`) is called only from `Executor.Run`, which nothing calls, and nothing calls `TPMUpgradeStrategy.CreateUpgradeSeal` (`pkg/initrd/strategy_tpm_upgrade.go:304`). First boot deletes any it finds (`pkg/firstboot/strategy.go:1401-1402`). No device has one today. |
| `<efi>/tpm2/pcr-banks` | first boot | `seal-pcrs` (recorded only, `pkg/firstboot/strategy.go:1335`; never applied to the seal, which uses the platform policy, `strategy.go:1302`), `platform-pcr`, `platform-pcr-bank`, `golden-pcrs`, `keystore-srk-handle` (the seal parent — the **Platform KeyStore SRK**, default `0x81000002`; never the SSRK, whose absence-of-platform-binding made platformd re-provision destructively, #61), `keystore-platform-policy` (HOW the seal authorized the parent SRK — the unseal replays this mode instead of assuming; absent defaults to `false`, the seal side's default), `ssrk-handle` |
| `<efi>/tpm2/pcr-seal-values.txt` | first boot | PCR values at seal time, for debugging |
| `<efi>/tpm2/swtpm-state/` | first boot | Software-TPM state, when a software TPM is in use |
| `<efi>/tpm2/ppi-clear-attempted` | first boot | Loop guard for firmware-level TPM clear escalation |

So a kernel or firmware change that moves the bound PCRs ends at the
`Password` prompt, then `ErrTPMSealPolicyDrift` from platformd — see
[architecture.md](architecture.md) trust boundary 5. *Planned, not
implemented (go-xkms #1443):* `TPM-Upgrade` stays; upgraded images are built
and signed centrally and staged, not rebuilt on the device; the bound PCR set
becomes configurable per board, default 7 and 11; the upgrade seal gets a
named policy approved for the predicted PCR values.

Seal blobs are written `0600`; the metadata files are `0644`. On the root
filesystem, `/var/lib/trusted-platform/.initialized` is the platform-initialized
marker and `/var/lib/trusted-platform/.seal-retry-needed` records a degraded
first boot. `firstboot.RecoveryKeyPath` (`/root/luks-recovery.txt`) is where the
executor writes the recovery key when it extracted one; the `escrow` strategy
instead stages the passphrase at a tmpfs handoff path for the daemon to move
into the tenant secret store, and shreds the tmpfs copy afterwards.

### Compatibility rules

- `nodes[].mac` (scalar) is still accepted and merged into `macs`. Do not remove
  the shadow unmarshaller without a migration.
- `SealStrategySoftware` is an alias of `SealStrategyPassphrase`; both validate.
- The seeder reads a profile ID from either the enveloped REST response
  (`{code, success, payload}`) or a bare object. A template upload's ID is
  read from the envelope only.
- Profile IDs are JSON **strings** on the wire because a `uint64` exceeds the
  precision of a double. Parsing failure is fatal (`ErrProfileIDParseFailed`) —
  without the ID there is no enrollment.
- The install-log poller probes MAC-keyed paths first and falls back to the
  hostname path for older ISOs.

## 7. Known gaps

Recorded because a reader will otherwise assume they are covered.

1. **Seal confirmation needs a later `TPM-PCR` boot.** First boot never wipes
   `installer.luks` (`sealingSucceeded` is never set in
   `pkg/firstboot/strategy.go`). `platform-initrd boot` wipes it only after a
   boot that unlocked the root with `TPM-PCR`
   (`pkg/boot/commands/sealconfirm.go`); until such a boot, `luks-key.bin`
   stays inside the container.
2. **`RolloverManager` is unwired** (§2). RFC 7671 pre-publication rollover is
   implemented and reachable only from tests.
3. *Closed.* `CertReloader.Reload` is reached in production: a reissued
   webservice certificate is swapped into the live listener (§2, *Wiring
   status*).
4. **BMC TOFU pins are process-lifetime only.** A certificate change between runs
   is invisible. Publish BMC TLSA records instead of relying on TOFU.
5. **The install-log poller has no internal deadline.** Callers pass a bounded
   context (`bootProbeTimeout`, 15 minutes per node); unit tests that reach the
   poller must serve the install log from a fake sink (§9) or they wait that
   long. The poller is reached on every attempt — the media-read watch ahead
   of it is advisory (§3 invariant 20, #126) — so a host that never boots the
   media spends the advisory window plus the poll window before the retry
   loop moves on.
6. **The canonical trust modes are stubs.** `bootstrap auto|dane|noise|spki`
   return `PendingBootstrapBackendError`; only `direct` does work, and that work
   is limited to checking that the `--bundle` path exists and is not a
   directory. It neither parses the PEM nor records the bundle anywhere,
   though its help text says it does (`pkg/cli/commands/bootstrap/canonical_modes.go`).
7. **Media-read attribution assumes the BMC's SMB source address is its
   `bmc_address`, and that smbd retitles its workers.** `MediaReadProbe.Client`
   is matched against the worker title pkg/ipxe reads from `/proc` — Debian's
   `smbd: client [ip]`, or Alpine/musl's `smbd[ip]` carried in the 15-byte
   comm, where a truncated capture (`smbd[198.51.100`, measured live) is an IP
   prefix and is matched as one, so on a /24 management subnet several BMCs
   can share a truncated prefix and vouch for each other. A BMC reading the
   share from another address is never attributed (harmless now that the
   watch is advisory; a per-node override would fix it and the config does
   not carry one). A Samba that does not retitle leaves every worker untagged
   and the watch degrades to counting all smbd activity.
8. **The console transcript cannot see POST.** SOL on the mini fleet carries
   nothing until an OS starts printing (§3 invariant 20), so a host that halts
   in firmware — the failing-DIMM case the media-read watch was built for — leaves
   an empty transcript, and the diagnosis stops at "halted before the OS, or
   console redirection disabled in BIOS". Reading the POST screen itself would
   need the board controller's console image; the ATEN preview was tried and
   rejected (it is a stored frame that does not refresh without an iKVM
   session, and produced a false diagnosis), so there is no screen capture in
   the tree. The transcript is also bounded at 1 MiB per attempt (the oldest
   half is dropped past that) and is only as trustworthy as the BMC's SOL
   routing: a quirk entry with the wrong `SOLPayloadInstance` yields a silent
   transcript that looks exactly like a halted host.

## 8. Observability

**Log events.** Every orchestrator step logs under the `bootstrap:` prefix with
`slog` attributes — `hostname`, `role`, `boot_method`, `phase`, `error`, plus
per-phase specifics (`smb_url`, `exit_code`, `profile_id`, `macs_total`,
`config_bytes`, `spki_captured`). First boot writes a fixed `[FIRSTBOOT-SEAL]`
banner sequence to stderr because in the initramfs the kernel console is often
the only channel; `platform-initrd boot` additionally mirrors numbered
breadcrumbs (`step01` … `step08`, with `step04a`/`step04b` for the PCR-selection
fallbacks) to `/run/platform-initrd-boot.log` so a hang before the pivot can be
localised afterwards.

**Forensics.** `dumpFirstbootForensics` runs deferred on every return from first
boot's `Unlock`, success or failure. It snapshots the kernel ring buffer, block
topology, device-mapper state, mounts, the kernel command line, the TPM device
nodes and the interfaces into `firstboot-runs/<UTC stamp>/` in the still-mounted
installer container, and points `firstboot-runs/latest` at it. The install log itself is uploaded to the deployer's HTTP sink and
is the authoritative record of what the installer did.

**The two signals that mean different things.** The install log says *the
installer finished*; the HTTPS health probe says *the daemon is serving*. The
node-uploaded `registration.json` is written early in first boot, before the
daemon is listening, so it is used only to resolve the address to probe — never
as a health signal on its own. Conflating them is the bug the health checker's
doc comment exists to prevent.

**The probe needs the trust anchor before it runs.** The health checker verifies
TLS with ordinary chain validation and starts on the system pool; the control
plane's CA is captured into it by `propagateCAPool`. Probing a freshly installed
control plane before that capture fails every probe with `x509: certificate
signed by unknown authority` for the whole post-install health window and, until
#107, reported only `context deadline exceeded`. The wait now captures first, then probes, and
the error carries the last failure of every candidate address
(`HealthProbeFailures` when there is more than one). Within one address, a port
that answered and failed TLS or returned a bad status is reported over a port
that refused the dial, and a probe cut off by the deadline keeps the previous
round's failure. Until #655 a gateway or worker was probed by address with no
expected name, so its DNS-only leaf never verified and every healthy node timed
out reporting `x509: cannot validate certificate for <ip> because it doesn't
contain any IP SANs`.

**No metric names are defined by this feature.** Progress is the phase name in
`BootstrapResult`; there is no counter or gauge to scrape.

**What must not be logged.** BMC passwords, `bmc_encryption_key`, the LUKS key,
the recovery passphrase, and resolved secret values. `secrets resolve` masks by
default and `secrets verify` hides values unless explicitly asked; the first-boot
code logs only the first bytes of a key hash, never the key.

## 9. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/bootstrap/*_test.go` | Config load and validation, forbidden-override detection with line numbers, MAC union, merge precedence, dry-run planning and SEL pre-flight warnings, seeder profile-ID parsing, DANE record derivation, rollover phases, cert reloader, virtual-media retry, advisory media-read watch and console transcript (`virtual_media_never_read_test.go`, against a scripted sink, `bmc.MockClient` and a scripted console), trust capture, post-install health of a gateway and worker against an `httptest` server on `127.0.0.1:0` serving a DNS-only leaf from a test CA (`post_install_health_noncp_test.go`) |
| Unit | `pkg/firstboot/*_test.go`, `pkg/boot/commands/*_test.go` | Types, executor helpers, PCR-bank and PCR-list parsing, the seal parent, the event log, closing the installer mapping, seal confirmation, TPM manager retry, the diskless boot path |
| Integration | `test/integration/`, `make integration-test-bootstrap` | Real deploy host, real container, real BMC paths |

**`pkg/bootstrap` runs in `make test`, `make test-race` and `make coverage`**
(measured 2026-08-29: 3.3s plain, 4.5s under `-race`, full tag set). It was in
`TEST_EXCLUDE` from 2026-08-14 to 2026-08-29 (#88) because every `Run()` test
reached the unmanaged-node path, which talks to the bootstrap container's HTTP
sink at `http://<deployer host>:<bootstrap_http_port>` — 30s of config-server
readiness probing and then `bootProbeTimeout` (15 minutes) of install-log
polling per node with nothing listening. The `Run()` tests now build the
orchestrator through `newRunOrchestrator`, which starts an `httptest` sink
(`newFakePxebootSink`) answering `/health`, the per-MAC config `PUT`s and a
successful `install.log`, and points the fixture's `deployer.host` and
`deployer.bootstrap_http_port` at it — so `installLogBaseURL`, the default
health checker and the deploy-phase serving gate all derive the same URL
through the real config path. The sink is strict: unsanitized MACs, unknown
config keys, or an `install.log` for a node the config does not declare fail
the test, and so does any other request.
`pkg/firstboot`, `pkg/boot/commands` and the root `pkg/cli/commands` package
remain in `TEST_EXCLUDE`, so their tests run in no unit stage. The entries are
end-anchored, so `pkg/cli/commands/bootstrap` is discovered by `make test`; it
is also named in `TEST_UNIT_PKGS` (#134).

**Fault-injection seams.** `OrchestratorParams.Deployer` and `.HealthChecker` are
interfaces; `BMCFactory` is injectable; `ISOStager` is an interface;
`DANEPublisher` depends on the narrow `DANEDNSService` rather than the whole DNS
service; a test points one orchestrator at a test server's ephemeral port
through its own `config.Platform.ControlPlanePort` (no package state, so the
tests stay parallel-safe), and `Orchestrator.pollTicker` lets a test
drive the health and power-verification poll cadence instead of waiting the
real intervals for it (`waitForHealth`, `waitForHealthAny` and
`awaitControlPlaneCAPool` probe once immediately and build their ticker only
after a failed attempt, so a hook on ticker construction fires exactly after the
first failure), and `mediaReadWindow` / `bootProbeWindow` shrink the
media-read and install-log windows, and `consoleOpener` substitutes a scripted
reader for the SOL session. The two windows mean different things and a test
must size them separately: shrinking `mediaReadWindow` makes the watch expire,
which is the scenario in several tests, but a test whose install log IS served
must leave `bootProbeWindow` wide, because there the window expiring is not the
behaviour under test — it is a scheduling accident that costs a boot retry and
an extra console session (issue #214). A shrunk `mediaReadWindow` has a second
hazard: the probe's first `/media/status` sample runs inside it, and on a loaded
runner a loopback round trip can outlive a 20 ms window, so the sample is cut
short and the probe reports evidence *unavailable* (the #197 rule) rather than
*never observed*. `mediaReadHTTPClient` exists so a test can hand the probe a
client whose exchanges the window cannot cut short — the never-observed tests
use a transport that detaches each request from its context, which makes "the
window closed with evidence" true by construction instead of by scheduler luck
(issue #262, third instance). `SkipVirtualMediaMount` is an operational escape
hatch that doubles as a test seam.

**Parity gap.** `../handbook/software/conventions/feature-docs.md` §4 requires every `cli.md` verb to
have a matching `CommandDefinition` in the integration parity suite. **No
`CommandDefinition` type exists in this repository** (searched again 2026-10-19), so the
requirement is unmet repo-wide, not only here.

## 10. Concurrency

Discovery, node provisioning and the control-plane health gate each fan out one
goroutine per node and write results by index or over a buffered channel, so
completion order never reorders them. Discovery (`discovery.go`) and the health
gate (`controlPlaneHealthGate`) send into a channel sized to the node count,
close it from a waiter goroutine, and drain; discovery stores each result into a
pre-sized slice by index. `provisionNodes`, which provisions both the control
plane and the remaining nodes, runs each node under `sync.WaitGroup.Go` and
records its error by index before `Wait`.
`CertReloader` holds the live certificate in an `atomic.Pointer` and
`RolloverManager` its phase in an `atomic.Uint32`; `barrier.Manager` tracks
initialized, sealed and unsealing with `atomic.Bool` and signals readiness by
closing the channel of the current `readyGate` generation, swapped through an
`atomic.Pointer` on seal. Mutexes remain where several fields change together:
the health checker's `WithCAPool` rebuilds its HTTP clients from the new pool
under `mu` and closes the old clients' idle connections, the orchestrator guards
the captured control-plane CA pool with `cpCAMu`, and the console transcript and
diagnostics buffers have their own locks.

`Orchestrator` itself is **not** safe for concurrent `Run` calls: `o.discovered`
is a plain field. One orchestrator, one run. Within a run, `o.cpCAPool` is
guarded by a mutex and capture attempts are serialized by a one-slot semaphore
(`acquireCAFetchGate`, selected against the waiter's context), because the
concurrently provisioned control-plane nodes each wait on the same pool: the
first waiter captures, the rest find it cached and make no request, and a queued
waiter still ends on its own deadline. The health
checker swaps its whole `http.Client` under its mutex when the pool arrives, and
`Check` takes the client under the same mutex, so a live `http.Transport` is
never reconfigured underneath a probe.

## 11. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/provisioning/`](../provisioning/) — the ISO, the iPXE server and the installer this feature drives
- [`docs/bmc/`](../bmc/) — the `BoardController` implementation and the enrollment ceremony
- [`docs/ca/`](../ca/) — CA issuance and the authenticated bundle route
- [`docs/dns/dane.md`](../dns/dane.md) — TLSA record semantics
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, status bytes, authorization
- [`docs/barrier/`](../barrier/) — the barrier lifecycle, the gate and `platformctl barrier`
- The legacy files this folder held (overview.md, pxe-bootstrap.md, config-reference.md, config-delivery.md, deployer.md, dane.md, configuration.md, day-zero.md, manual-nodes.md, switch-management.md, api-reference-rest.md, README.md) are deleted. These five files hold their content.

## 12. Corrections to the legacy documents in this folder

The legacy files are deleted. This table records what they got wrong, so a
reader who has an old copy open knows which statement to distrust.

| Legacy statement | Code says |
|---|---|
| configuration.md, overview.md: the Noise server listens on `:9446` | `bootstrap.DefaultConfig()` sets `listen-addr: ":9999"`. In the Go code `9446` is the barrier gate's loopback port (`apidaemon.DefaultInitOnlyHTTPAddr`), not the Noise server's. |
| day-zero.md (before #708): the provisioning network is configured under a `provisioning_network:` key | `BootstrapConfig` has no such field (day-zero.md later showed `environment:`). The provisioning zone is derived from the top-level `environment:` (offset 5), and `Validate` fails without an environment. |
| day-zero.md: "Add new entries and re-run. Existing nodes are skipped." | Nothing skips an already-installed node automatically. `skip_install: true` is the explicit opt-out; without it the node is reprovisioned. |
| pxe-bootstrap.md: phases numbered 0–7 with "Watch" as phase 6 | The phase constants are `discovery`, `switch`, `deploy`, `control-plane`, `seed`, `remaining-nodes`, `bmc-enroll`, `health-gate`, `teardown`. Install-log watching is part of per-node provisioning, not a separate phase. |
| pxe-bootstrap.md: per-MAC staging publishes `hostname` and `installer.yaml` | Client (non-control-plane) nodes additionally receive `ca-bundle.pem` and `bootstrap-spki-pin`. |
| api-reference-rest.md: the bootstrap endpoint's errors are 404 and 500 | The handler also returns **503** when the CA is not initialised, and **400** for an unparseable `algorithm` value. |
| README.md, overview.md: four strategies (DANE, Noise, SPKI, Embedded) | The `bootstrap` class allows five — `dane`, `noise`, `spki`, `embedded`, `tofu` — and the `bmc` class allows `dane`, `spki`, `ca-file`, `tofu` (`tofu` was removed from `bmc` in #83 and restored after go-xkms#139 made it endpoint pinning). |
| overview.md: "Rollover Manager: orchestrates RFC 7671 pre-publication rollover" | Implemented, but with no production caller (§7.2). The live path calls the publisher directly. |
| config-reference.md and others: examples use RFC 1918 addresses and site-specific hosts | The five files in this folder use `example.com` / `<install-dir>` placeholders only. |
