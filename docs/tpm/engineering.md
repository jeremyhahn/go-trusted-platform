# Physical TPM 2.0 — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/app/`, `pkg/vtpm/target.go`, `pkg/api/daemon/`, `pkg/api/quic/tpm_handlers.go`, `pkg/api/tpmnv/`, `pkg/webservice/v1/rest/tpm/`, `pkg/api/mcp/`, `pkg/cli/commands/tpm/`, `sdk/go/services/tpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

This is the file an implementing agent works from. Every identifier below was
read out of the source on 2026-08-18.

---

## 1. Where the code is

There is **no `pkg/tpm/` package**. The feature is spread across the layers it
serves:

| Location | Holds |
|---|---|
| `pkg/app/app.go` | `App.OpenTPM`, `App.InitTPM`, `App.TPM`, `App.TPMConfig`, `App.TPMCertStore`, `newKeyBackend` |
| `pkg/vtpm/target.go` | `ResolveTPMTarget` and the target error set — shared with the vTPM feature |
| `pkg/initrd` | `NewTPMDetector`, `DetectTPMType`, `initrd.SoftwareTPM` — the `auto` detection path |
| `pkg/api/daemon/tpm_grpc_service.go` | `TPMGRPCService` — the gRPC `TPMService` implementation |
| `pkg/api/daemon/idevid_grpc_service.go`, `idevid_ldevid.go` | `IDevIDService` — device identity |
| `pkg/api/daemon/quic_service.go` | opcode dispatch; `handleTPM2Category` |
| `pkg/api/quic/tpm_handlers.go` | `TPM2Handler`, the `SubOpTPM2*` constants, TPM2 sentinel errors |
| `pkg/api/tpmnv/nv.go` | `Read`, `Write`, `Define`, `Undefine`, `BuildAttributes` |
| `pkg/webservice/v1/rest/tpm/` | `TPMRouter`, `Handlers` |
| `pkg/api/mcp/tpm_tools.go`, `tpm_tools_exec.go` | the 31 `platform_tpm_*` tools |
| `pkg/cli/commands/tpm/` | the `platformctl tpm` tree |
| `sdk/go/services/tpm/` | `Client`, the domain types, the converters |
| `test/integration/tpm/` | the six-transport parity suite |

**Dead code, do not extend:** `pkg/api/rest/tpm_handlers.go` defines a second,
richer `TPMHandlers` with `RegisterRoutes` on absolute `/api/v1/tpm/...` paths
(`make-credential`, `activate-credential`, `certify`, `capabilities`,
`csr/idevid`, `csr/ldevid`, `platform`, `pcrs/extend`, `nv/*`). `NewTPMHandlers`
is constructed **only in its own tests**. The registered REST surface is
`pkg/webservice/v1/rest/tpm` (wired at `pkg/webservice/v1/router.go`,
`tpmRoutes`). Those extra routes are **not served**.

## 2. The SDK edge

```go
quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
```

Types consumed: `TrustedPlatformModule`, `TPMConfig`, `DefaultTPMConfig`,
`TPMParams`, `NewTPM2`, `TPMKeyBackend`, `TPMCertificateStorer`, `EKConfig`,
`SRKConfig`, `Password`, `ErrTPMNotInitialized`, `NewTPM2BackendWithTPM`,
`TPM2BackendExternalConfig`.

`TPMParams` is constructed in `App.OpenTPM` with `Backend`, `BlobStore`,
`CertStore`, `Config`, `DebugSecrets`, `FQDN`, `Logger`.

`TrustedPlatformModule` methods this repo calls (the full set — anything else is
not used here): `Info`, `Config`, `FixedProperties`, `EKAttributes`,
`IAKAttributes`, `IDevIDAttributes`, `PlatformSRKAttributes`, `ReadHandle`,
`ReadPCRs`, `IsPlatformPCRExtended`, `CreatePlatformPolicy`,
`PlatformPolicyDigest`, `PlatformPolicyDigestHash`, `CreateIDevID`,
`CreateTCG_CSR_IDEVID`, `FactoryResetWithClear`, `ForceClear`, `Transport`,
`Close`.

**Adding a TPM capability starts upstream.** If `TrustedPlatformModule` lacks
it, it is added to go-xkms and surfaced through `go-quicbaas/sdk/go/xkms`
first. The one sanctioned exception already taken is NV (§5), and it is an
exception because the interface exposes the raw transport for exactly this.

## 3. Target resolution — `pkg/vtpm/target.go`

```go
const TPMDeviceAuto = "auto"

type TPMTarget int
const (
        TPMTargetHardware TPMTarget = iota
        TPMTargetSwtpm
        TPMTargetSimulator
)

type ResolvedTPMTarget struct { /* Target, Device */ }

func ResolveTPMTarget(cfg *xkmssdk.TPMConfig, logger *logging.Logger) (*ResolvedTPMTarget, error)
```

Rules, in evaluation order:

| `tpm.simulator` | `tpm.device` | Result |
|---|---|---|
| `true` | ignored | `TPMTargetSimulator` |
| `false` | `""` or `auto` | runtime detection: swtpm socket first, then `/dev/tpmrm0`, then `/dev/tpm0` |
| `false` | `*.sock` | `TPMTargetSwtpm` — the socket **must** exist and **must** be a socket |
| `false` | anything else | `TPMTargetHardware` — the path **must** exist and **must** be a device |

Errors:

| Error | Means |
|---|---|
| `ErrNilTPMConfig` | Called with no TPM configuration — a wiring bug |
| `ErrNoTPMDetected` | `auto` and the detector found nothing (wraps the detector error) |
| `ErrHardwareTPMUnavailable` | Hardware was demanded and is not usable (wraps `os.Stat` or `ErrNotCharDevice`) |
| `ErrSwtpmSocketUnavailable` | swtpm was demanded and the socket is absent or is not a socket (wraps `ErrNotUnixSocket`) |
| `ErrNotCharDevice` | The configured hardware path exists but is not a device node |
| `ErrNotUnixSocket` | The configured socket path exists but is not a socket |

All six implement `Unwrap` where they carry a cause.

**Fail-closed statement.** Explicit configuration never degrades. Hardware
demanded and absent is a startup failure, not a fallback to swtpm; swtpm
demanded and absent is a startup failure, not a fallback to `/dev/tpmrm0`. This
is the single most important invariant in the feature, because a silent
downgrade is invisible in every downstream artefact.

## 4. Boot invariants — `pkg/app/app.go`

1. **`OpenTPM` is idempotent with respect to the handle.** It constructs
   `App.TPM` only when nil. It always runs the platform-PCR check afterwards.
2. **`InitTPM` is idempotent.** It calls `OpenTPM` first and only provisions
   when the TPM is not already provisioned.
3. **The platform PCR is re-extended on every boot.** `IsPlatformPCRExtended`
   → `CreatePlatformPolicy`. PCRs are volatile; without this, every
   platform-sealed secret is unreachable after a power cycle. The failure path
   is a `WrappedError` with `"failed to restore platform policy"`.
4. **Unresolved secret references fail closed before the TPM is touched.**
   `assertNoUnresolvedKMSURI` is applied to `TPMConfig.SSRK.HierarchyAuth` and
   `TPMConfig.EK.HierarchyAuth`. A `kms://` URI submitted as hierarchy auth
   would be rejected by the TPM as an oversized buffer and could corrupt
   hierarchy state.
5. **The SO PIN is mirrored into `TPMConfig.SSRK`/`.EK` `HierarchyAuth`** when
   those are empty, so a reboot against an already-provisioned TPM presents the
   same auth it was provisioned with.
6. **SRK policy drift is detected, not ignored.** `InitTPM` compares the stored
   `srkAttrs.TPMAttributes.Public.AuthPolicy.Buffer` against the live
   `PlatformPolicyDigest`; a mismatch triggers re-provisioning, because
   `TPM2_Seal` under a stale policy fails at use time with an unhelpful policy
   error.
7. **Recovery escalates and does not loop.** `FactoryResetWithClear(nil)` →
   on lockout/bad-auth, UEFI PPI `ForceClear` plus a warm reset written to
   `/proc/sysrq-trigger` → on a second pass, proceed to provisioning without
   rebooting again.
8. **Both identity common names default to the hostname** — `<hostname>-iak`
   and `<hostname>-idevid` — when not configured; an operator-configured
   `tpm.iak.cn` / `tpm.idevid.cn` is preserved (`applyTPMIdentityCNs`,
   `pkg/app/tpm_identity_cn.go`). The IAK half is the contract #78 restored:
   go-xkms#137 (adopted with go-xkms v0.9.4-alpha) made `IAKAttributes()`
   honour a configured CN, and the #74 interim that left the IAK CN empty
   became the fatal it once avoided — on a fresh provision `CreateIAK`
   caches attributes built straight from the config, so an empty CN reaches
   the certificate store and is rejected (`certstore: invalid key
   attributes`), which is how the Raspberry Pi stand-in found it.

   **Migration (#78).** A node provisioned under the interim holds its IAK
   certificate under go-xkms's `default-device-id`. On every boot that did
   not just provision, `migrateInterimIAKCertificate`
   (`pkg/app/tpm_iak_migration.go`) runs before the identity-completeness
   check: if nothing is stored under the IAK's CN and something is stored
   under the interim name, and that certificate's public key is the
   resident IAK's, the entry is copied to the new name. The interim entry
   stays (inert once the new name resolves). A public-key mismatch is
   logged and left alone; only a store read or write error is fatal. A
   node that was never provisioned, or already migrated, does nothing.

9. **TPM identity certificates are persisted to the certificate store, not
   NVRAM** — `tpm.idevid.cert-handle` and `tpm.iak.cert-handle` are both
   currently ignored, so all four of the persistence calls #62 added resolve
   to the store.

   > **INTERIM (#80) — a configured `idevid.cert-handle` or
   > `iak.cert-handle` is cleared, so identity certificates are stored in the
   > platform certificate store rather than TPM NVRAM.**
   >
   > go-xkms `writeCertToNVRAM` defines its NV index with
   > `NT: tpm2.TPMNT(0x01)` — **`TPM_NT_COUNTER`**. A counter index accepts a
   > data size of exactly **8 bytes**, so the TPM rejects every
   > certificate-sized define with `TPM_RC_SIZE` on parameter 2. Certificate
   > storage requires `TPM_NT_ORDINARY` (`0x00`). Measured against the
   > reference simulator: counter/1500 fails, counter/8 succeeds,
   > ordinary/1500 succeeds, and ordinary fails only above
   > `TPM_PT_NV_INDEX_MAX` (2048).
   >
   > So this is **not** a certificate-size problem and **not** a chunking
   > problem — the write loop already chunks correctly against
   > `TPM_PT_NV_BUFFER_MAX` (1024). It fails at 512 bytes just the same.
   >
   > `applyCertHandleNVInterim` (`pkg/app/tpm_cert_nv.go`) clears the handle
   > with a warning. Zero is what makes the path *work* rather than fail
   > differently: for each identity the Provision call and the read accessor
   > both branch on `CertHandle == 0`, so it sends the write and the read to
   > the certificate store together. That store is constructed on every boot
   > anyway, as the documented NVRAM fallback.
   >
   > **Both identities are covered** because `writeCertToNVRAM` is shared:
   > IDevID is the live failure (every shipped template sets its handle),
   > while IAK carries the identical latent trap for any configuration that
   > sets `iak.cert-handle`.
   >
   > A second reason the store is the safer route: an NV index is capped at
   > `TPM_PT_NV_INDEX_MAX`, so a certificate above it could never be
   > persisted through NVRAM even once the counter bug is fixed. The store
   > has no such ceiling (`TestCertStoreHasNoNVSizeCeiling`).
   >
   > Fixed upstream by **go-xkms#138**. NV persistence returns when that fix
   > is adopted here.
   > Tracked as **#81**, including migrating nodes provisioned under the
   > interim.
10. **`tpm.entropy` rebinds `App.Random` to the TPM.** Otherwise `rand.Reader`.

## 5. NVRAM — `pkg/api/tpmnv`

`TrustedPlatformModule` does not expose NV. Both the gRPC service and the QUIC
handler reach NV through the module's raw go-tpm transport, and the command
construction lives in one package so the two cannot diverge.

```go
func Read(tr transport.TPM, index uint32, size, offset uint16, password []byte) ([]byte, error)
func Write(tr transport.TPM, index uint32, data []byte, offset uint16, password []byte) error
func Define(tr transport.TPM, index uint32, size uint16, attrNames []string, nvAuth, ownerAuth []byte) error
func Undefine(tr transport.TPM, index uint32, ownerAuth []byte) error
func BuildAttributes(names []string) tpmgo.TPMANV
```

- `maxNVChunk = 512`. Reads and writes larger than that are chunked, because
  `TPM_PT_NV_BUFFER_MAX` varies from single-digit bytes to 1024 across vendors.
- **The auth hierarchy is derived from the index's own public attributes**, read
  with `NVReadPublic` before every operation: `AUTHREAD` authorizes against the
  index's `AuthValue`, `OWNERREAD` through the owner hierarchy, `PPREAD` through
  the platform hierarchy. This is why NV works identically against hardware and
  swtpm.

## 6. gRPC service — `TPMGRPCService`

```go
type TPMGRPCService struct {
        platformv1.UnimplementedTPMServiceServer
        tpm    quicbaassdk.TrustedPlatformModule
        logger *logging.Logger
        mu     sync.RWMutex
}

func NewTPMGRPCService(logger *logging.Logger) *TPMGRPCService
func (s *TPMGRPCService) SetTPM2Service(tpm quicbaassdk.TrustedPlatformModule)
```

- The handle is guarded by `sync.RWMutex` and may be set after construction.
  **Every RPC returns `codes.Unavailable` when the handle is nil** — this is the
  fail-closed behaviour for "the daemon started without a TPM".
- `Info` is a pass-through: `resp.Properties["info"]` carries go-xkms's verbatim
  multi-line report, and the structured fields (`Manufacturer`, `MaxNvramSize`,
  `FipsMode`, `Capabilities`, NV index list) come from `FixedProperties`. A
  `FixedProperties` failure is soft — logged as a warning, structured fields left
  empty, text fallback still returned. **Dashboards must consume the structured
  fields, not parse the text blob.**
- **`mapError` classifies by substring, not by type.** It matches
  `"not found" | "does not exist" | "no such"` → `NotFound`,
  `"already exists" | "duplicate"` → `AlreadyExists`,
  `"invalid" | "required" | "must be" | "cannot be"` → `InvalidArgument`,
  `"permission" | "denied" | "unauthorized" | "forbidden" | "authorization"` →
  `PermissionDenied`, `"TPM" | "tpm" | "handle"` → `FailedPrecondition`,
  else `Internal`. This is fragile: an upstream error-string change silently
  reclassifies a status code. Treat the mapping as advisory, not contractual,
  and do not build client control flow on the distinction between
  `FailedPrecondition` and `Internal`.

## 7. QUIC handler — `TPM2Handler`

Category opcode `OpTPM2Category = 0x99`; the **first payload byte is the
sub-opcode** and the remainder is the operation payload. Dispatch is a
`map[byte]TPM2HandlerFunc` built in `NewTPM2Handler` — map-based, not a switch.

```go
const (
        SubOpTPM2Info          byte = 0x01
        SubOpTPM2Provision     byte = 0x02
        SubOpTPM2Clear         byte = 0x03
        SubOpTPM2GetEK         byte = 0x04
        SubOpTPM2CreateEK      byte = 0x05
        SubOpTPM2DeleteEK      byte = 0x06
        SubOpTPM2GetEKCert     byte = 0x07
        SubOpTPM2ImportEKCert  byte = 0x08
        SubOpTPM2GetSRK        byte = 0x09
        SubOpTPM2CreateSRK     byte = 0x0A
        SubOpTPM2DeleteSRK     byte = 0x0B
        SubOpTPM2GetIAK        byte = 0x0C
        SubOpTPM2CreateIAK     byte = 0x0D
        SubOpTPM2DeleteIAK     byte = 0x0E
        SubOpTPM2Quote         byte = 0x0F
        SubOpTPM2VerifyQuote   byte = 0x10
        SubOpTPM2ReadPCRs      byte = 0x11
        SubOpTPM2ExtendPCR     byte = 0x12
        SubOpTPM2EventLog      byte = 0x13
        SubOpTPM2Random        byte = 0x14
        SubOpTPM2Seal          byte = 0x15
        SubOpTPM2Unseal        byte = 0x16
        SubOpTPM2Capabilities  byte = 0x17
        SubOpTPM2NVRead        byte = 0x18
        SubOpTPM2NVWrite       byte = 0x19
        SubOpTPM2NVDelete      byte = 0x1A
        SubOpTPM2NVList        byte = 0x1B
        SubOpTPM2IDevIDCSR     byte = 0x1C
        SubOpTPM2LDevIDCSR     byte = 0x1D
        SubOpTPM2PlatformAttrs byte = 0x1E
        SubOpTPM2GetIDevID     byte = 0x1F
        SubOpTPM2MakeCred      byte = 0x20
        SubOpTPM2ActivateCred  byte = 0x21
)
```

Fail-closed ordering in `HandleMessage`: nil request → `StatusInvalidRequest`;
**nil TPM → `StatusUnavailable`**; empty payload → `StatusInvalidRequest`;
unknown sub-opcode → `StatusNotImplemented`.

`SubOpTPM2LDevIDCSR` is **intercepted before the handler map** by
`QUICServiceHandler.handleTPM2Category` and routed to the IDevID service,
because LDevID issuance is CA-backed. That keeps QUIC semantics equal to
gRPC/Unix/embedded.

Sentinel errors: `ErrTPM2ServiceNotAvailable`, `ErrTPM2MissingSubOpcode`,
`ErrTPM2MissingData`, `ErrTPM2MissingCN`, `ErrTPM2MissingCertificate`,
`ErrTPM2MissingCredentialBlob`, `ErrTPM2MissingEncryptedSecret`,
`ErrTPM2InvalidNumBytes` (maximum 1024), `ErrTPM2InvalidPCRIndex` (0–23).
Typed errors: `ErrTPM2EncodingFailed`, `ErrTPM2DecodingFailed`,
`ErrTPM2OperationFailed`, `ErrTPM2UnknownSubOpcode`.

Secret-bearing QUIC request fields are tagged `secret:"true"` in the codec
struct tags — for example `TPM2ProvisionRequest.OwnerPassword` and
`TPM2ClearRequest.OwnerPassword`. Preserve that tag on any new field carrying a
password.

## 8. SDK — `sdk/go/services/tpm`

```go
type Client struct{ /* grpc platformv1.TPMServiceClient */ }
func NewClient(conn transport.Adapter) (*Client, error)   // common.ErrNilConnection when nil
func NewClientFromGRPC(grpcClient platformv1.TPMServiceClient) *Client
```

Two parallel method families:

- **Proto family** — `Info`, `Provision`, `Clear`, `CreateEK`, `GetEK`,
  `GetEKCertificate`, `ImportEKCertificate`, `DeleteEK`, `CreateSRK`, `GetSRK`,
  `DeleteSRK`, `CreateAK`, `GetAK`, `DeleteAK`, `Seal`, `Unseal`, `Quote`,
  `VerifyQuote`, `GetEventLog`, `GetPCRs`, `DefineNVRAM`, `WriteNVRAM`,
  `ReadNVRAM`, `UndefineNVRAM`, `GetRandom`. Takes and returns `platformv1.*`.
- **Domain family (`*Domain`)** — `InfoDomain`, `ProvisionDomain`,
  `ClearDomain`, `CreateEKDomain`, `GetEKDomain`, `GetEKCertificateDomain`,
  `DeleteEKDomain`, `CreateSRKDomain`, `GetSRKDomain`, `DeleteSRKDomain`,
  `SealDomain`, `UnsealDomain`, `GetEventLogDomain`, `GetPCRsDomain`,
  `DefineNVRAMDomain`, `WriteNVRAMDomain`, `ReadNVRAMDomain`,
  `UndefineNVRAMDomain`, `GetRandomDomain`. Takes and returns SDK-local types.

**The domain family is incomplete.** There is no `QuoteDomain`,
`VerifyQuoteDomain`, `CreateAKDomain`, `GetAKDomain`, `DeleteAKDomain` or
`ImportEKCertificateDomain`. A caller needing those drops to the proto family.
This is a gap, not a design.

Domain types: `KeyAlgorithm` (`UNSPECIFIED`, `RSA-2048`, `RSA-3072`, `RSA-4096`,
`ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`), `PCRBank` (`sha1`, `sha256`,
`sha384`, `sha512`, `sm3_256`), `TPMVersion`, `DeviceKeyAlgorithm`, `Status`,
`KeyAttributes`, `Manufacturer`, `Capability`, `NVIndex`, `InfoResponse`,
`ProvisionRequest/Response`, `ClearResponse`, `CreateKeyResponse`,
`KeyInfoResponse`, `DeleteKeyResponse`, `EKCertificateResponse`,
`SealRequest/Response`, `UnsealRequest/Response`, `EventLogResponse`,
`PCRValue`, `NVRAMDefineResponse`, `NVRAMWriteResponse`, `NVRAMReadResponse`,
`NVRAMUndefineResponse`, `QuoteResponse`, `VerifyQuoteResponse`,
`DeviceKeyInfo`, `DeviceKeyCertificateInfo`, `DeviceIdentityCertificate`,
`CSRTemplate`, `DeviceAttributes`.

Converters: `ParseKeyAlgorithm` (returns `(KeyAlgorithm, bool)`), `ParsePCRBank`,
`ParseDeviceKeyAlgorithm`, `KeyAlgorithmToProto`, `KeyAlgorithmFromProto`,
`PCRBankToProto`, `PCRBankFromProto`.

SDK errors — all carry a `Cause`, all in `sdk/go/services/tpm/errors.go`:
`ErrInfoFailed`, `ErrProvisionFailed`, `ErrClearFailed`, `ErrCreateEKFailed`,
`ErrGetEKFailed`, `ErrGetEKCertFailed`, `ErrImportEKCertFailed`,
`ErrDeleteEKFailed`, `ErrCreateSRKFailed`, `ErrGetSRKFailed`,
`ErrDeleteSRKFailed`, `ErrCreateAKFailed`, `ErrGetAKFailed`, `ErrDeleteAKFailed`,
`ErrSealFailed`, `ErrUnsealFailed`, `ErrQuoteFailed`, `ErrVerifyQuoteFailed`,
`ErrGetEventLogFailed`, `ErrGetPCRsFailed`, `ErrDefineNVRAMFailed`,
`ErrWriteNVRAMFailed`, `ErrReadNVRAMFailed`, `ErrUndefineNVRAMFailed`,
`ErrGetRandomFailed`. The four NVRAM errors also carry `Index`.

## 9. CLI errors — `pkg/cli/commands/tpm/errors.go`

Device identity: `ErrInvalidAlgorithm`, `ErrIDevIDNotFound`, `ErrIAKNotFound`,
`ErrIDevIDAlreadyExists`, `ErrIAKAlreadyExists`, `ErrGenerateIDevIDFailed`,
`ErrGenerateIAKFailed`, `ErrDeleteIDevIDFailed`, `ErrDeleteIAKFailed`,
`ErrGetIDevIDInfoFailed`, `ErrGetIAKInfoFailed`, `ErrCreateIDevIDCSRFailed`,
`ErrCreateIAKCSRFailed`, `ErrInstallIDevIDCertificateFailed`,
`ErrInstallIAKCertificateFailed`, `ErrGetIDevIDCertificateFailed`,
`ErrGetIAKCertificateFailed`, `ErrIDevIDCertificateNotFound`,
`ErrIAKCertificateNotFound`.
LDevID (`ldevid_errors.go`): `ErrCreateLDevIDFailed`, `ErrInvalidTPMHandle`.
Device: `ErrFlushFailed`, `ErrGetDeviceAttributesFailed`.
Service: `ErrTPMInfoFailed`, `ErrTPMProvisionFailed`, `ErrTPMClearFailed`,
`ErrDaemonConnectionRequired`.
Keys: `ErrEKCreateFailed`, `ErrEKNotFound`, `ErrEKCertificateNotFound`,
`ErrEKDeleteFailed`, `ErrInvalidKeyAlgorithm`, `ErrSRKCreateFailed`,
`ErrSRKNotFound`, `ErrSRKDeleteFailed`.
Data: `ErrSealFailed`, `ErrUnsealFailed`, `ErrEventLogFailed`,
`ErrNVRAMDefineFailed`, `ErrNVRAMWriteFailed`, `ErrNVRAMReadFailed`,
`ErrNVRAMDeleteFailed` (the four NVRAM errors carry `Index`).

**`ErrDaemonConnectionRequired{Operation: …}` is the marker for an unimplemented
verb.** Its message is `daemon connection required: operation '<op>' not yet
supported`, and it is returned unconditionally — before any connection is
attempted — by `tpm install`, `tpm destroy`, `tpm policy`, `tpm extend`,
`tpm enroll` and `tpm xkms`. See [cli.md](cli.md) §6.

## 10. Configuration

The type is `xkms.TPMConfig`, bound to the top-level YAML key `tpm:`
(`App.TPMConfig`, tag `yaml:"tpm"`). Defaults come from
`xkms.DefaultTPMConfig`; this repo overrides only what the config file sets.
Precedence follows the platform rule: **flag > environment > config file >
built-in default**.

Keys as shipped in `configs/platform/templates/single-node/default.yaml`:

| Key | Value in the template | Meaning |
|---|---|---|
| `tpm.device` | `/dev/tpmrm0` | Device path, `auto`, or a `*.sock` swtpm socket |
| `tpm.simulator` | `false` | In-process simulator; wins over `device` |
| `tpm.encrypt-sessions` | `false` | Parameter encryption on the CPU↔TPM bus |
| `tpm.entropy` | `false` | Use the TPM as `App.Random` |
| `tpm.hash` | `SHA-256` | Default hash algorithm |
| `tpm.ek.handle` | `0x81010001` | EK persistent handle |
| `tpm.ek.rsa.size` | `2048` | EK RSA size |
| `tpm.ssrk.handle` | `0x81000001` | **Shared SRK** persistent handle |
| `tpm.ssrk.platform-policy` | `false` | Bind the SSRK to the platform policy |
| `tpm.ssrk.hierarchy-auth` | (empty; filled from the SO PIN) | Storage hierarchy auth |
| `tpm.iak.handle` | `0x81010002` | IAK persistent handle |
| `tpm.iak.signature-algorithm` | `SHA256-RSA` | IAK signing algorithm |
| `tpm.idevid.handle` | `0x81020000` | IDevID persistent handle |
| `tpm.idevid.cert-handle` | `0x01C90000` | NV index for the IDevID certificate. **Currently IGNORED** — cleared at bring-up so the certificate store is used instead (interim, item 9 / go-xkms#138). `tpm.iak.cert-handle` is cleared the same way |
| `tpm.idevid.model`, `.serial` | per node | TCG device identity fields |
| `tpm.platform-pcr` | `23` | The PCR the platform extends with its golden measurement |
| `tpm.platform-pcr-bank` | `sha256` | Bank for that PCR |
| `tpm.golden-pcrs` | `[7, 9]` | PCRs composed into the golden measurement |
| `tpm.platform-srk.srk-handle` | `0x81000002` | **PlatformSRK** — a different key from the SSRK |
| `tpm.platform-srk.srk-auth` | `kms://…?ensure=true&len=32&enc=raw` | Secret reference, resolved before the TPM opens |
| `tpm.platform-srk.platform-policy` | `true` | PlatformSRK is bound to the platform PCR policy |

Corresponding Go field names on `xkms.TPMConfig` as used here: `Device`,
`UseSimulator`, `UseEntropy`, `EK`, `SSRK`, `IAK`, `IDevID`, `PlatformSRK`,
`PlatformPCR`, `PlatformPCRBank`, `GoldenPCRs`.

**`golden-pcrs` must not contain PCR 10.** The shipped config says so in place:
PCR 10 is IMA and changes on every boot, so including it makes every post-reboot
unseal fail.

## 11. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/cli/commands/tpm/*_test.go` | Every verb through the `TPMBaseCommandInterface` / `BaseCommandInterface` seams with a fake client |
| Unit | `pkg/api/tpmnv/nv_test.go` | NV command construction and attribute parsing |
| Unit | `pkg/api/quic/tpm_handlers_test.go`, `tpm_credential_test.go` | Sub-opcode dispatch, MakeCredential/ActivateCredential |
| Unit | `pkg/webservice/v1/rest/tpm/router_test.go` | Route registration |
| Unit | `sdk/go/services/tpm/converters_info_test.go` | Proto ⇄ domain conversion, with `fakeTPMClient` |
| Integration | `test/integration/tpm/` | **The six-transport parity suite** |

**The parity mechanism here is `TPMCommands`, not `CommandDefinition`.**
`test/integration/tpm/commands.go` (build tag `integration`) declares a
`TPMCommands` interface — `Name`, `Setup`, `Teardown`, `Info`, `Provision`,
`Clear`, `EKCreate`, `EKInfo`, `EKCertificate`, `EKDelete`, `SRKCreate`,
`SRKInfo`, `SRKDelete`, `Seal`, `Unseal`, `EventLog` — implemented six times:
`NewCLIAdapter`, `NewRESTAdapter`, `NewGRPCAdapter`, `NewQUICAdapter`,
`NewMCPAdapter`, `NewUnixAdapter`. `TestTPMMultiProtocol` runs one suite against
all six. Run it with `make integration-test-tpm`.

`conventions/feature-docs.md` §4 asks for a `CommandDefinition` per verb. **No
`CommandDefinition` type exists in this repository** (grepped 2026-08-18); the
TPM feature satisfies the *intent* through `TPMCommands`, and the naming
mismatch is raised for the owner rather than papered over.

**Seams for fault injection:** `SetTPM2Service(nil)` on the gRPC service or the
QUIC handler exercises every unavailable path; `TPMBaseCommandInterface` and
`BaseCommandInterface` in `pkg/cli/commands/tpm` substitute the SDK client;
`ResolveTPMTarget` takes a config value, so every target error is reachable from
a temp directory with a regular file at the configured path.

## 12. Observability

- `App.OpenTPM` logs `"TPM target resolved"` with `target` and `device`. **This
  is the first line to read when attestation looks wrong** — it says whether the
  node is hardware-rooted.
- `App.InitTPM` logs the platform PCR configuration (`golden_pcrs`,
  `platform_pcr`, `platform_pcr_bank`), PCR values before and after
  `CreatePlatformPolicy`, the SRK auth policy read back from the TPM, the
  platform policy digest and the PCR digest hash. That trail is what makes a
  seal/unseal mismatch diagnosable.
- Destructive recovery is logged at Info/Warn with an explicit statement of
  which escalation step ran (`FactoryResetWithClear`, PPI `ForceClear`, reboot).
- **Never log sealed data, unsealed data, PINs or hierarchy auth values.**
  `App.DebugSecretsFlag` gates the go-xkms debug path and must stay off outside
  development.
- There is no TPM-specific metric or audit record emitted by this repository
  (grepped 2026-08-18). Operations are visible only through logs and through
  `platformctl tpm status`.

## 13. Known defects

Recorded here so they are debts with a location, not discoveries:

1. **`platformctl tpm seal --policy` is silently dropped.** The flag is parsed
   into `sealOptions.UsePolicy` and never read. Neither `tpm.SealRequest` (SDK)
   nor `SealRequest` (proto) has a field for it. The default is `true`, so a
   user who leaves it alone gets whatever the server does anyway; a user who
   passes `--policy=false` gets no change in behaviour.
2. **`platformctl tpm enroll` advertises flags it does not register.** Its help
   text shows `--acme-server`, `--cn`, `--ip` and `--force`; none are bound.
   The verb returns `ErrDaemonConnectionRequired` regardless.
3. **`platformctl tpm destroy`, `install`, `policy`, `extend`, `xkms`** all
   document flags in their long help (`--so-pin`, `--lockout-password`,
   `--confirm`, `--parent`, `--password`, `--ca`, `--tls`, `--hmac`, …) that are
   not registered, and all return `ErrDaemonConnectionRequired`.
4. **The physical-TPM QUIC surface is not scope-checked.**
   `QUICServiceHandler.handleTPM2Category` calls `AuthorizeRequest` nowhere;
   `pkg/api/daemon/quic_pxe.go` is the only QUIC handler that does. A validated
   token reaches `SubOpTPM2Clear` and `SubOpTPM2Unseal`.
5. **`TPMService` and `IDevIDService` are absent from the gRPC scope catalog**
   (`pkg/api/grpc/method_permissions.go`), which is default-allow. Likewise all
   31 `platform_tpm_*` and all 17 `idevid_*` / `iak_*` MCP tools are absent from
   `pkg/api/mcp/authz.go`, which is also default-allow.
6. **AK and IAK are the same key under two names.** gRPC and REST call it `ak`
   (`CreateAK`, `/api/v1/tpm/ak`); QUIC and MCP call it IAK (`SubOpTPM2CreateIAK`,
   `platform_tpm_iak_create`). A client author reading one transport will not
   find the other.
7. **`pkg/api/rest/tpm_handlers.go` is unreachable production code** (§1).

## 14. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC framing, the
  authorization picture
- [`docs/vtpm/engineering.md`](../vtpm/engineering.md) — the other consumer of
  `ResolveTPMTarget`
- [`docs/attestation/engineering.md`](../attestation/engineering.md)
