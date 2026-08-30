# Bootstrap — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/bootstrap/`, `pkg/firstboot/`, `pkg/boot/`, `pkg/barrier/`, `pkg/api/rest/init_handlers.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was read out of the packages named above on 2026-08-18.
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
| `deployer/` | `Deployer`, `DeployConfig`, `DeployResult`, Linux and Cisco backends, pinned SSH |
| `deployer_adapter.go` | `NewLinuxDeployerAdapter` — the only translation from platform config to `deployer.DeployConfig` |
| `dane_publisher.go` | `DANEPublisher`, `DANEDNSService` |
| `rollover.go` | `RolloverManager`, `RolloverPhase` |
| `cert_reloader.go` | `CertReloader` |
| `bundle_provider.go` | `CABundler`, `CABundleAdapter` |
| `secrets.go` | Secret-URI scheme and strategy constants, `IsSecretURI`, `ExpandShortKMSPath` |
| `config_writer.go` | `ConfigWriter`, `SecretUpdate` |
| `config.go` | `Config`, `NoiseServerConfig`, `DefaultConfig` |
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
```

`OrchestratorParams` fields: `Config`, `ConfigPath`, `BMCFactory`, `Logger`,
`Deployer`, `HealthChecker`, `TrustConfig`, `SkipVirtualMediaMount`. `Config` and
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
func (c *BootstrapConfig) ProvisioningSubnet() *installer.SubnetConfig
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

**Wiring status, verified by grep on 2026-08-18.** `DANEPublisher` is
constructed in production (`app.ensureDANEPublisher`, shared with the
SDK-registered publisher adapter so there is exactly one DNS-write path).
`CertReloader` is constructed in production and wired to
`tls.Config.GetCertificate`; nothing calls `Reload` outside tests, so the
hot-swap path is present and never exercised. `CABundleAdapter` is constructed in
`platformd serve` to feed the Noise listener. **`RolloverManager` has no
production caller at all** — the BMC certificate hooks call
`PrePublishRollover` and `PublishForCertificate` on the publisher directly. Treat
`RolloverManager` as an implemented-but-unwired component, not as the live
rollover path.

### Secrets

```go
const ( SchemeKMS; SchemeRemoteKMS; SchemeEnv; SchemeIDevID; SchemeFile; SchemeDynamic; SchemeXKMS )
const ( StrategyKMS; StrategyRemoteKMS; StrategyEnv; StrategyIDevID; StrategyFile;
        StrategyDynamic; StrategyXKMS; StrategyLiteral; StrategyPlainText )
const SecretStructTag = "secret"
func IsSecretURI(s string) bool
func ExpandShortKMSPath(path, tenantID, nodeID string) string

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

```go
func NewManager(sdk quicbaassdk.Client, config *Config, logger *slog.Logger) (*Manager, error)
func (m *Manager) SyncStatus(ctx context.Context) error
func (m *Manager) Initialize(ctx context.Context, secret string) error
func (m *Manager) InitializeShamir(ctx context.Context, secret string, threshold, shares int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error)
func (m *Manager) Unseal(ctx context.Context, secret string) error
func (m *Manager) UnsealWithShare(ctx context.Context, share string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error)
func (m *Manager) Seal(ctx context.Context) error
func (m *Manager) Rekey(ctx context.Context, threshold, total int) (*quicbaassdk.QRDBBarrierRekeyResponse, error)
func (m *Manager) Status(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error)
func (m *Manager) CeremonyInitialize(ctx context.Context, config *CeremonyConfig) (*CeremonyInitResult, error)
func (m *Manager) CeremonyStatus(ctx context.Context) (*CeremonyStatusInfo, error)
func (m *Manager) BeginClaimCert(ctx context.Context, username string) (*CeremonyChallenge, error)
func (m *Manager) CompleteClaimCert(ctx context.Context, username, nonceHex string, signature []byte) (*CeremonyClaimCertResult, error)
func (m *Manager) BeginClaimShare(ctx context.Context, username string) (*CeremonyChallenge, error)
func (m *Manager) CompleteClaimShare(ctx context.Context, username, nonceHex string, signature []byte) ([]byte, error)
func (m *Manager) WaitReady(ctx context.Context) error
func (m *Manager) IsSealed() bool
func (m *Manager) IsInitialized() bool
```

Seal-strategy constants: `SealStrategyNone`, `SealStrategyPassphrase`,
`SealStrategySoftware` (a backward-compatible alias of passphrase),
`SealStrategyShamir`, `SealStrategyTPM2`, `SealStrategyPKCS11`;
`DefaultSealStrategy = SealStrategySoftware`.

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

9. **Provisioning is concurrent within a phase and sequential across phases.**
   `provisionControlPlane` and `provisionRemainingNodes` both fan out and return
   the first error.

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
    (`ErrCABundleRequired`).

14. **Teardown is gated on control-plane health.** A failed gate skips teardown.
    A failed teardown is a warning.

15. **BMC enrollment never aborts a run.** Every attempt appends a
    `BMCEnrollOutcome`, success or failure.

16. **First boot is idempotent by artefact, not by flag.** The probe is
    `installer.luks` present **and** `seal-platform.pub` absent. A second boot
    with seal artefacts present skips TPM provisioning and sealing and unlocks
    from the preserved key, reporting the degraded state.

17. **The installer container is wiped only after sealing succeeded.** On any
    failure it is preserved so the next boot can retry.

18. **`RolloverManager` is single-flight.** A second `BeginRollover` while a
    rollover is in progress returns `ErrRolloverInProgress`. Phase transitions
    use an atomic; `CertReloader` swaps an `atomic.Pointer` so TLS handshakes
    never take a lock.

19. **The pre-unseal REST surface accepts only its own state.** `/init` in
    `uninitialized`, `/unseal` in `sealed`; anything else is 409. `/healthz` is
    always callable and reports `ready` only in `unsealed`.

20. **A virtual-media boot proves the firmware read the media before it waits
    on the installer.** After power-on is verified, the orchestrator polls the
    bootstrap container's `/media/status` — the pxeboot media watcher's
    cumulative record, sampled every 250 ms, of descriptors on the staged ISO,
    which smbd holds only while the host is pulling sectors through the BMC —
    for `defaultMediaReadWindow` — a package constant, 7 min, set from the
    2026-08-29 measurement on lab-node-2 (X10SDV, `SYS-5018D-FN8T-AS001`, ATEN FW
    4.00): power-on → first per-MAC `installer.yaml` GET ≈ 6 min 15 s, install-log
    upload ≈ 10 min 30 s, first ISO read shortly before the 6-minute mark.
    Evidence is the
    ISO's `smbd` record for the node's own BMC address (`MediaReadProbe.Client`;
    smbd titles each worker `smbd: client [ip]`, and only when no worker is
    titled does every `smbd` worker count) showing more activity — open events plus
    position changes — than the baseline taken while the chassis is confirmed
    off, between the power-off and the power-on (`MediaReadProbe.Baseline`,
    compared only against the same watcher instance) with a `last_activity`
    inside this attempt (`MediaReadProbe.Since`, recorded at the same instant,
    with the install-log poller's two-second slack) — so a read
    that started and ended between two polls still counts, while a read by
    the still-running previous boot, an idle descriptor held across the
    cycle, another process reading the ISO after the baseline, and another
    node's BMC reading the same ISO concurrently do not. No
    such evidence within the window is `ErrMediaNeverRead`, the attempt is
    abandoned, and the retry loop
    (with its attempt-2 NVRAM clear) takes the next attempt; the run fails in
    minutes instead of `defaultBootRetryMax × bootProbeTimeout`. A container
    that does not serve `/media/status` (404), or one that never answers it
    usefully within the window (outage, 5xx including the watcher's own
    "no fresh sample" 503, garbage), leaves the gate open —
    missing evidence is never read as a failure; the install-log wait is then
    the only signal, as before. **Every attempt records the host's serial
    console.** Before the power cycle the orchestrator opens SOL through
    `bmc.Client.Console` on a BMC client of its own (the SOL receive loop
    takes over its client's RMCP+ socket, so it can never share the client
    the power commands go through) and streams it for the whole boot window;
    when the attempt ends — never-read, install log found, or install log
    missing — the transcript is uploaded to the sink as
    `/installs/<host>/console-attempt<N>.log` and its URL plus the last 40
    lines (`ConsoleTranscript`, escape sequences stripped) ride in
    `ErrMediaNeverRead` / `ErrInstallLogNotFound`. A console that cannot be
    opened is a WARN and the attempt continues without it. **BIOS POST is not
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
| `ErrMissingRequiredField{Field}` | `deployer.host`, `platform.domain`, provisioning subnet, `iso_path` when virtual media is used, `config path` |
| `ErrInvalidNodeRole{Hostname, Role}` | Role is not `control-plane`/`gateway`/`worker` |
| `ErrNodeMissingIdentity{Hostname}` | Neither `bmc_address` nor `macs` on an installing node |
| `ErrDuplicateMAC{MAC, Hostnames}` | The same MAC on two nodes |
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
`ErrHealthCheckFailed{Address, Cause}`,
`ErrControlPlaneHealthGateFailed{Timeout, Cause}`,
`ErrContainerDeployFailed{Host, Cause}`,
`ErrContainerTeardownFailed{Host, Cause}`,
`ErrNilOrchestratorConfig{}`, `ErrNilBMCFactory{}`, `ErrNoControlPlaneNode{}`,
`ErrDryRunBMCUnreachable{Hostname, BMCAddress, Cause}`, `ErrDryRunNoNodes{}`.

Seeding: `ErrSeedFailed{Cause}`, `ErrMissingSeederAddr{}`,
`ErrTemplateNotFoundForRole{Role}`, `ErrTemplateFileNotFound{Role, Path}`,
`ErrTemplateReadFailed`, `ErrTemplateYAMLParseFailed`,
`ErrTemplateJSONConvertFailed`, `ErrTemplateUploadFailed{Role, StatusCode, Cause}`,
`ErrTemplateMergeFailed{Hostname, Role, Cause}`,
`ErrProfileCreateFailed{Hostname, StatusCode, Cause}`,
`ErrProfileIDParseFailed{Hostname, Cause}`.

Trust capture: `ErrCABundleInvalid{URL}`, `ErrCABundleVerifyFailed{URL, Cause}`,
`ErrCABundleRequired{Operation}`, `ErrNoPeerCertificates{Endpoint}`,
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
`ErrInstallLogNotFound{Hostname, URL, Cause, Console}`,
`ErrMediaNeverRead{Hostname, ISO, Window, Console}`,
`ErrMediaStatusUnavailable{URL, StatusCode}` (§3 invariant 20; `Console`
is a `*ConsoleTranscript` — the uploaded transcript URL and its last lines,
what silence means on this hardware, or why there is none — and its
`Summary()` is appended to both messages),
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
`pkg/cli/commands/bootstrap`), plus `CommandOutputError` and
`SentinelCauseError` in `firstboot`.

### First boot sentinels

`ErrNoTPMDevice`, `ErrNoTPMConfig`, `ErrAlreadySealed`, `ErrSealingFallbackUsed`,
`ErrNoLUKSKey`, `ErrInvalidKeySize`, `ErrTPMNotAvailable`,
`ErrSSRKNotAccessible`, `ErrPlatformSRKNotAccessible`.

### Barrier

Package sentinels plus `ManagerError{Op, Err}` and `ConfigError{Field, Message}`.
The pre-unseal REST handlers use `ErrInitNotPermitted{Current}`,
`ErrUnsealNotPermitted{Current}`, `ErrBarrierInitServiceUnavailable{}`,
`ErrBarrierUnsealServiceUnavailable{}`.

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

Consumed only by `platformctl bootstrap`. Top level: `deployer`, `switch`
(optional), `fabric` (optional), `subnets`, `platform`, `templates`, `nodes`,
`iso_path`, `backups_dir`.

| Key | Type | Default | Notes |
|---|---|---|---|
| `deployer.target` | string | — | `linux` or `cisco` |
| `deployer.host` | string | **required** | Validation fails without it |
| `deployer.user`, `deployer.ssh_key` | string | — | Required by the deployer adapter |
| `deployer.known_hosts_path` | string | — | **Required in practice**: SSH fails closed without it |
| `deployer.container_runtime` | string | `docker` | Applied by `DeployConfig.ApplyDefaults` |
| `deployer.container_image` | string | — | Empty means Phase 2 is skipped entirely |
| `deployer.data_dir` | string | `/tmp/bootstrap` | `DefaultDeployerDataDir` |
| `deployer.redeploy_mode` | string | `if-stale` | `always`, `if-stale`, `never`; unrecognised values normalise to `if-stale` |
| `deployer.smb_host` | string | `deployer.host` | The address the BMC uses for the SMB share; also preferred for the install-log base URL |
| `deployer.bootstrap_interface` | string | container default `eth0` | Sets `BOOTSTRAP_INTERFACE` |
| `deployer.bootstrap_server_ip` | string | container default | Sets `BOOTSTRAP_SERVER_IP`; must be an address the deployer host already holds on a first bootstrap |
| `deployer.bootstrap_http_port` | int | `8080` | Sets `BOOTSTRAP_HTTP_PORT`. The container's HTTP service — per-MAC config endpoint, install-log sink, `/health` — and the port the orchestrator builds its own URLs against (`installLogBaseURL`) |
| `deployer.bootstrap_device_script_port` | int | `bootstrap_http_port` + 1 | Sets `BOOTSTRAP_DEVICE_SCRIPT_PORT`. The container's second listener, `/boot/device/{mac}.ipxe`. Set it when something else on the deployer already owns the derived port |
| `deployer.bootstrap_dhcp_start` / `_end` | string | container defaults | `BOOTSTRAP_DHCP_START` / `BOOTSTRAP_DHCP_END` |
| `deployer.bootstrap_gateway`, `deployer.bootstrap_dns` | string | container defaults | `BOOTSTRAP_GATEWAY`, `BOOTSTRAP_DNS` |
| `deployer.bootstrap_apk_mirror` | string | public mirror | `BOOTSTRAP_APK_MIRROR`; required on networks with no outbound internet |
| `deployer.pxe_service_host` | string | gateway role | Which node hosts PXE after hand-off |
| `deployer.transfer_protocol`, `transfer_server`, `container_image_path`, `config_file`, `app_id`, `image_file` | string | — | Cisco-target fields |
| `subnets[]` | list | **required** | One entry must set `role: provisioning` |
| `platform.domain` | string | **required** | |
| `platform.internal_domain`, `hostmaster`, `tenant_id`, `environment`, `upstream_dns`, `networks`, `bootstrap_strategy` | | | Injected into merged device configs |
| `templates` | map role→path | — | Missing role means the node is skipped at profile creation with a warning |
| `iso_path` | string | — | Required when any installing node uses `virtual-media` |
| `backups_dir` | string | a `~`-relative default | `~` expanded at load; set it explicitly rather than relying on the default |
| `nodes[].hostname` | string | **required** | |
| `nodes[].role` | string | **required** | |
| `nodes[].macs` (legacy `mac`) | list/string | — | The scalar form is migrated automatically and merged into the slice |
| `nodes[].bmc_address`, `bmc_user`, `bmc_password`, `bmc_protocol`, `bmc_encryption_key` | string | protocol `redfish` when unset or `auto` | `bmc_password` and `bmc_encryption_key` carry `secret:"true"` |
| `nodes[].bmc_trust` | list | platform default | `dane`, `spki`, `ca-file` — **not** `tofu` (#83) |
| `nodes[].bmc_spki_pin` | string | — | Hex SHA-256 of the BMC SPKI; implies the `spki` strategy when no chain is declared |
| `nodes[].bmc_enroll` | bool | `false` | Opts the node into the enrollment phase |
| `nodes[].boot_method` | string | `pxe` | `pxe` or `virtual-media` |
| `nodes[].skip_install` | bool | `false` | Already-deployed node |
| `nodes[].interfaces` | list | — | Authoritative for `network.interfaces` |
| `nodes[].overrides`, `nodes[].overrides_file` | map / path | — | File merged first, inline wins |
| `nodes[].switch_port`, `nodes[].post_enrollment` | | | Recorded; consumed by the switch and post-enrollment paths |

The container's two ports are configurable, and one setting moves both the
server's binding and the URLs the orchestrator points at it. They were not: the
device-script listener was hardcoded to HTTP+1 at the bind and
`installLogBaseURL` returned a literal `:8080`. A deployer that already had
something on 8081 — an ordinary thing on the shared jumpbox that `target: linux`
documents — therefore killed pxeboot on bind with no way to move it.

Both ports are validated at config load: an explicit value must be in 1-65535, the two effective ports must differ, and `bootstrap_http_port: 65535` with the device-script port unset is refused because it would derive 65536. Catching these at load rather than at bind is the same principle as the deploy gate — a port problem should not first appear as a container that came up with nothing serving.

Still not configurable: the control-plane webservice is assumed on `8443` for
seeding (`cpWebservicePort`) and for the CLI health probe.

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

Trust configuration (`trust.default` / `trust.bmc` / `trust.internal`) and DANE
publication (`dns.dane.*`) are owned elsewhere — see
[configuration.md](configuration.md) for the full key list and
[`docs/dns/dane.md`](../dns/dane.md) for the record semantics. The keys this
feature depends on are `strategies`, `server-url`, `hostname`, `bundle-path`,
`per-method-timeout`, `install-to-system-trust`, and the `dane`/`noise`/`spki`
sub-blocks.

**Environment variables.** The Go packages read none directly. The container
entrypoint consumes `BOOTSTRAP_INTERFACE`, `BOOTSTRAP_SERVER_IP`,
`BOOTSTRAP_HTTP_PORT`, `BOOTSTRAP_DEVICE_SCRIPT_PORT`,
`BOOTSTRAP_DHCP_START`, `BOOTSTRAP_DHCP_END`, `BOOTSTRAP_GATEWAY`,
`BOOTSTRAP_DNS` and `BOOTSTRAP_APK_MIRROR`, all set from the deployer block. An
unset port is omitted from the `docker run` command entirely so the entrypoint's
own default applies, and `BOOTSTRAP_DEVICE_SCRIPT_PORT` defaults to
`BOOTSTRAP_HTTP_PORT + 1` there, matching the offset pxeboot applies when its
flag is unset. On
the installed node, `PLATFORMD_DEBUG` is written into the daemon's environment
file by first boot. `platformctl` persistent flags have their own `PLATFORMCTL_*`
variables ([cli.md](cli.md) §1).

**Precedence.** Flag > environment > config file > built-in default, per the
platform convention. Inside `bootstrap.yaml` the merge precedence is the one in
§3.11. For PCR selection at first boot: CLI `--pcrs` > `pcr-banks` on the EFI
partition > `seal-pcrs` in configuration; with none of the three, first boot
refuses to run.

## 6. Persistence

### On the deployer host

```
<data_dir>/                     # default /tmp/bootstrap, bind-mounted as /data
├── manifest.yaml               # MAC → role → hostname
├── vmlinuz, initramfs, autoinstall.sh   # extracted from the container image
├── <platform>.iso              # staged for virtual-media, served over SMB
├── installs/<key>/install.log  # forensic sink, key is a MAC or a hostname
├── installs/<host>/registration.json
└── config/mac/<mac>/{hostname,installer.yaml,ca-bundle.pem,bootstrap-spki-pin}
```

The MAC in a path is dash-separated and lower-cased. Staging is a PUT; reading is
a GET. Nothing here is encrypted — see [architecture.md](architecture.md) trust
boundary 4.

### On the node's EFI partition

| Path | Written by | Meaning |
|---|---|---|
| `<efi>/tpm2/installer.luks` | installer | Encrypted container: LUKS key, recovery key, config |
| `<efi>/tpm2/seal-platform.pub` / `.priv` | first boot | The production seal. **Presence is the "already provisioned" marker.** |
| `<efi>/tpm2/seal-upgrade.pub` / `.priv` | first boot | Non-PCR seal for kernel upgrades. Presence signals a re-seal is needed. |
| `<efi>/tpm2/pcr-banks` | first boot | `seal-pcrs`, `platform-pcr`, `platform-pcr-bank`, `golden-pcrs`, `keystore-srk-handle` (the seal parent — the **Platform KeyStore SRK**, default `0x81000002`; never the SSRK, whose absence-of-platform-binding made platformd re-provision destructively, #61), `keystore-platform-policy` (HOW the seal authorized the parent SRK — the unseal replays this mode instead of assuming; absent defaults to `false`, the seal side's default), `ssrk-handle` |
| `<efi>/tpm2/pcr-seal-values.txt` | first boot | PCR values at seal time, for debugging |
| `<efi>/tpm2/swtpm-state/` | first boot | Software-TPM state, when a software TPM is in use |
| `<efi>/tpm2/ppi-clear-attempted` | first boot | Loop guard for firmware-level TPM clear escalation |

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
- The seeder tolerates both the enveloped REST response (`{code, success,
  payload}`) and a bare object, for templates and profile IDs alike.
- Profile IDs are JSON **strings** on the wire because a `uint64` exceeds the
  precision of a double. Parsing failure is fatal (`ErrProfileIDParseFailed`) —
  without the ID there is no enrollment.
- The install-log poller probes MAC-keyed paths first and falls back to the
  hostname path for older ISOs.

## 7. Known gaps

Recorded because a reader will otherwise assume they are covered.

1. **No seal-confirmation handshake.** `luks-key.bin` is preserved indefinitely
   inside `installer.luks`, and the container is not wiped until sealing
   succeeds — but nothing proves the seal actually unseals before the wipe. The
   code says so in place; the fix is a real unseal test gated ahead of deletion.
2. **`RolloverManager` is unwired** (§2). RFC 7671 pre-publication rollover is
   implemented and reachable only from tests.
3. **`CertReloader.Reload` has no production caller.** The hot-swap is installed
   in the TLS config and never triggered.
4. **BMC TOFU pins are process-lifetime only.** A certificate change between runs
   is invisible. Publish BMC TLSA records instead of relying on TOFU.
5. **The install-log poller has no internal deadline.** Callers pass a bounded
   context (`bootProbeTimeout`, 15 minutes per node); unit tests that reach the
   poller must serve the install log from a fake sink (§9) or they wait that
   long. Since #102 the poller is only reached after the media-read gate (§3
   invariant 20), so a host that never boots the media no longer spends it.
6. **`platformctl bootstrap deploy` cannot succeed against a Linux target.**
   Its `buildDeployConfig` sets neither `ManifestPath` nor `KnownHostsPath`, so
   `LinuxDeployer.Deploy` fails at `DeployConfig.Validate()` with
   `ErrInvalidDeployConfig{Field:"manifest_path"}` — and would fail immediately
   afterwards on the missing host-key pins. The `run` path goes through
   `NewLinuxDeployerAdapter`, which sets both. Use `bootstrap run` (see
   [cli.md](cli.md) §4).
7. **The canonical trust modes are stubs.** `bootstrap auto|dane|noise|spki`
   return `PendingBootstrapBackendError`; only `direct` does work, and that work
   is limited to validating that the supplied bundle path is a readable file.
8. **Media-read attribution assumes the BMC's SMB source address is its
   `bmc_address`, and that smbd retitles its workers.** `MediaReadProbe.Client`
   is matched against the `smbd: client [ip]` process title pkg/ipxe reads from
   `/proc`. A BMC reading the share from another address is never attributed
   and reports never-read (fail-safe, but wrong; a per-node override would fix
   it and the config does not carry one). A Samba that does not retitle leaves
   every worker untagged and the gate degrades to counting all smbd activity —
   concurrent nodes can then vouch for each other again.
9. **The console transcript cannot see POST.** SOL on the mini fleet carries
   nothing until an OS starts printing (§3 invariant 20), so a host that halts
   in firmware — the failing-DIMM case the media-read gate exists for — leaves
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
breadcrumbs (`step01` … `step07`) to `/run/platform-initrd-boot.log` so a hang
before the pivot can be localised afterwards.

**Forensics.** `dumpFirstbootForensics` snapshots the kernel ring buffer, block
topology and LUKS state into the still-mounted installer container on every entry
to first boot. The install log itself is uploaded to the deployer's HTTP sink and
is the authoritative record of what the installer did.

**The two signals that mean different things.** The install log says *the
installer finished*; the HTTPS health probe says *the daemon is serving*. The
node-uploaded `registration.json` is written early in first boot, before the
daemon is listening, so it is used only to resolve the address to probe — never
as a health signal on its own. Conflating them is the bug the health checker's
doc comment exists to prevent.

**No metric names are defined by this feature.** Progress is the phase name in
`BootstrapResult`; there is no counter or gauge to scrape.

**What must not be logged.** BMC passwords, `bmc_encryption_key`, the LUKS key,
the recovery passphrase, and resolved secret values. `secrets resolve` masks by
default and `secrets verify` hides values unless explicitly asked; the first-boot
code logs only the first bytes of a key hash, never the key.

## 9. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/bootstrap/*_test.go` | Config load and validation, forbidden-override detection with line numbers, MAC union, merge precedence, dry-run planning and SEL pre-flight warnings, seeder profile-ID parsing, DANE record derivation, rollover phases, cert reloader, virtual-media retry, media-read gate and console transcript (`virtual_media_never_read_test.go`, against a scripted sink, `bmc.MockClient` and a scripted console), trust capture |
| Unit | `pkg/firstboot/*_test.go`, `pkg/boot/commands/*_test.go` | Types, executor helpers, PCR-list parsing |
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
`pkg/firstboot`, `pkg/boot/commands` and `pkg/cli/commands/*` remain excluded.

**Fault-injection seams.** `OrchestratorParams.Deployer` and `.HealthChecker` are
interfaces; `BMCFactory` is injectable; `ISOStager` is an interface;
`DANEPublisher` depends on the narrow `DANEDNSService` rather than the whole DNS
service; `cpWebservicePort` is a package variable specifically so a test server's
ephemeral port can be substituted, and `Orchestrator.pollTicker` lets a test
drive the health and power-verification poll cadence instead of waiting the
real intervals for it, and `mediaReadWindow` / `bootProbeWindow` shrink the
media-read and install-log windows, and `consoleOpener` substitutes a scripted
reader for the SOL session. `SkipVirtualMediaMount` is an operational escape
hatch that doubles as a test seam.

**Parity gap.** `conventions/feature-docs.md` §4 requires every `cli.md` verb to
have a matching `CommandDefinition` in the integration parity suite. **No
`CommandDefinition` type exists in this repository** (grepped 2026-08-18), so the
requirement is unmet repo-wide, not only here.

## 10. Concurrency

Discovery, control-plane provisioning, remaining-node provisioning and the health
gate each fan out one goroutine per node over a buffered channel, close the
channel from a waiter goroutine, and drain. Discovery writes results into a
pre-sized slice by index, so ordering is stable regardless of completion order.
`CertReloader` and `RolloverManager` use atomics rather than mutexes;
`barrier.Manager` tracks initialized/sealed with `atomic.Bool` and signals
readiness by closing a channel. The health checker guards its TLS config swap
with a mutex because it mutates a live `http.Transport`.

`Orchestrator` itself is **not** safe for concurrent `Run` calls: `o.discovered`
and `o.cpCAPool` are plain fields. One orchestrator, one run.

## 11. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/provisioning/`](../provisioning/) — the ISO, the iPXE server and the installer this feature drives
- [`docs/bmc/`](../bmc/) — the `BoardController` implementation and the enrollment ceremony
- [`docs/ca/`](../ca/) — CA issuance and the authenticated bundle route
- [`docs/dns/dane.md`](../dns/dane.md) — TLSA record semantics
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, status bytes, authorization
- [`docs/cli/barrier.md`](../cli/barrier.md) — the barrier verbs beyond init and unseal
- Legacy narrative kept in place: [overview.md](overview.md), [pxe-bootstrap.md](pxe-bootstrap.md), [config-reference.md](config-reference.md), [config-delivery.md](config-delivery.md), [deployer.md](deployer.md), [dane.md](dane.md), [configuration.md](configuration.md), [day-zero.md](day-zero.md), [manual-nodes.md](manual-nodes.md), [switch-management.md](switch-management.md), [api-reference-rest.md](api-reference-rest.md)

## 12. Corrections to the legacy documents in this folder

Recorded rather than silently fixed, so a reader who has the old page open knows
which statement to distrust.

| Legacy statement | Code says |
|---|---|
| [configuration.md](configuration.md), [overview.md](overview.md): the Noise server listens on `:9446` | `bootstrap.DefaultConfig()` sets `listen-addr: ":9999"`. There is no `9446` anywhere in the Go code. |
| [day-zero.md](day-zero.md): the provisioning network is configured under a `provisioning_network:` key | `BootstrapConfig` has no such field. Provisioning network comes from `subnets:` with `role: provisioning`, and `Validate` fails without one. |
| [day-zero.md](day-zero.md): "Add new entries and re-run. Existing nodes are skipped." | Nothing skips an already-installed node automatically. `skip_install: true` is the explicit opt-out; without it the node is reprovisioned. |
| [pxe-bootstrap.md](pxe-bootstrap.md): phases numbered 0–7 with "Watch" as phase 6 | The phase constants are `discovery`, `switch`, `deploy`, `control-plane`, `seed`, `remaining-nodes`, `bmc-enroll`, `health-gate`, `teardown`. Install-log watching is part of per-node provisioning, not a separate phase. |
| [pxe-bootstrap.md](pxe-bootstrap.md): per-MAC staging publishes `hostname` and `installer.yaml` | Client (non-control-plane) nodes additionally receive `ca-bundle.pem` and `bootstrap-spki-pin`. |
| [api-reference-rest.md](api-reference-rest.md): the bootstrap endpoint's errors are 404 and 500 | The handler also returns **503** when the CA is not initialised, and **400** for an unparseable `algorithm` value. |
| [README.md](README.md), [overview.md](overview.md): four strategies (DANE, Noise, SPKI, Embedded) | The `default` class allows five — `dane`, `noise`, `spki`, `embedded`, `tofu` — and the `bmc` class allows `dane`, `spki`, `ca-file` (`tofu` was removed from `bmc` in #83). |
| [overview.md](overview.md): "Rollover Manager: orchestrates RFC 7671 pre-publication rollover" | Implemented, but with no production caller (§7.2). The live path calls the publisher directly. |
| [config-reference.md](config-reference.md) and others: examples use RFC 1918 addresses and site-specific hosts | Replace with `example.com` / `<install-dir>` placeholders when editing. The five files in this folder use placeholders only. |
