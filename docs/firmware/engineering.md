# Firmware Trust — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/uefi/`, `pkg/uefi/firmware/`, `pkg/secureboot/`, `pkg/uki/`, `pkg/authenticode/`, `pkg/modulesign/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was grepped in this repository on 2026-08-18. Nothing
> here is aspirational; PLANNED surface is labelled as such.

---

## 1. Package layout

### `pkg/uefi` — UEFI data structures and both enrollment paths

| File | Holds |
|---|---|
| `types.go` | `EFITime`, `FirmwareVolumeHeader`, `VariableStoreHeader`, `Variable`, `SignatureList`, `SignatureData`; the `Attr*` / `Fvb*` / `VarState*` constants; `SecureBootAttributes` |
| `guid.go` | `GUID`, `NewGUID`, `ParseGUID`, `MustParseGUID`, `GUIDFromBytes`, `GUIDSize`, and the well-known GUID table |
| `esl.go` | `EFI_SIGNATURE_LIST` encode/decode |
| `nvram.go` | Firmware-volume and variable-store parsing over an `OVMF_VARS.fd` file |
| `enrollment.go` | `SecureBootEnroller` — the **NVRAM-file** enrollment path, plus `EnrollmentStatus` and the `TRUSTED_PLATFORM` record |
| `efivars_enroll.go` | The **live-firmware** enrollment path, `EfivarsPath`, the Setup-Mode guards, `UKIVerifier` and `VerifySignedUKI` |
| `efivars_status.go` | `SecureBootStatus`, `SignatureDatabase`, and the efivarfs read side |
| `errors.go` | `MessageError`, `SentinelCauseError`, `WrappedError` |

### `pkg/uefi/firmware` — raw runtime variable access

A **separate package** (`package firmware`) that talks to efivarfs at the
individual-variable level. `pkg/uefi` does the Secure Boot semantics;
`pkg/uefi/firmware` does "read me this variable".

### `pkg/secureboot` — key material

| File | Holds |
|---|---|
| `keychain.go` | `XKMSManager`, `XKMSConfig`, `BackendType`, key generation and export |
| `kms_signer.go` | `NewKMSSigner`, `FetchKMSCertificate`, `KMSKeyID` — KMS hash-signing over the platform client |
| `modulekey.go` | `GenerateModuleSigningKey`, `LoadModuleSigningKey`, `ModuleSigningKey` |
| `types.go` | `KeyType`, `KeyPaths`, `ResignMode*`, the sentinel error set |
| `errors.go` | `MessageError`, `SentinelCauseError`, `WrappedError` |

### `pkg/uki` — boot payload construction

`uki.go` (types and interfaces), `builder.go` (native Go PE patcher),
`builder_objcopy.go` (objcopy path), `parser.go`, `pe.go` (PE patcher and its
typed errors), `errors.go`.

### `pkg/authenticode` — PE/COFF signing

`authenticode.go` (the `Authenticode` interface and `Signer`), `pe.go` (PE
parsing, digest computation, PKCS#7 encode/decode, signature embedding),
`errors.go`.

### `pkg/modulesign` — kernel module signing

`modulesign.go` (`SignModule`, `BuildModuleSignature`, `EnumerateModules`),
`cms.go` (detached CMS envelope), `compress.go` (gzip/zstd codecs),
`errors.go`.

---

## 2. Exported surface

### 2.1 `pkg/uefi` — GUIDs, ESLs, NVRAM

```go
type GUID struct { Data1 uint32; Data2, Data3 uint16; Data4 [8]byte }

const GUIDSize = 16

func NewGUID() GUID
func ParseGUID(s string) (GUID, error)
func MustParseGUID(s string) GUID
func GUIDFromBytes(b []byte) (GUID, error)
func (g GUID) String() string
func (g GUID) Bytes() []byte
func (g GUID) Equal(other GUID) bool
func (g GUID) IsZero() bool
```

Well-known GUIDs (package vars): `EFIGlobalVariable`, `EFIImageSecurityDatabase`,
`EFIX509Cert`, `EFIX509SHA256`, `EFISHA256`, `EFISHA384`, `EFISHA512`,
`EFIRSA2048`, `EFIPKCS7Cert`, `FFS2GUID`, `FFS3GUID`, `NVRAMVariableStoreGUID`,
`AuthenticatedVariableGUID`, `TrustedPlatformGUID`.

```go
func NewSignatureListFromCert(certDER []byte, ownerGUID GUID) *SignatureList
func NewSignatureListFromHash(hash []byte, hashType, ownerGUID GUID) *SignatureList
func ParseSignatureList(data []byte) (*SignatureList, int, error)
func ParseSignatureLists(data []byte) ([]*SignatureList, error)
func ConcatSignatureLists(lists ...*SignatureList) []byte

func (sl *SignatureList) AddSignature(data SignatureData) error
func (sl *SignatureList) Bytes() []byte
func (sl *SignatureList) SignatureCount() int
func (sl *SignatureList) IsX509() bool
func (sl *SignatureList) IsSHA256() bool
```

```go
func OpenNVRAM(path string) (*NVRAM, error)
func ParseNVRAM(data []byte, path string) (*NVRAM, error)

func (n *NVRAM) GetVariable(name string, guid GUID) (*Variable, error)
func (n *NVRAM) ListVariables() []*Variable
func (n *NVRAM) SetVariable(name string, guid GUID, attrs uint32, data []byte) error
func (n *NVRAM) DeleteVariable(name string, guid GUID) error
func (n *NVRAM) Save() error
func (n *NVRAM) SaveTo(path string) error
func (n *NVRAM) Bytes() ([]byte, error)
func (n *NVRAM) WriteTo(w io.Writer) (int64, error)
func (n *NVRAM) IsAuthenticatedStore() bool
func (n *NVRAM) Path() string
func (n *NVRAM) Size() int
```

### 2.2 `pkg/uefi` — NVRAM-file enrollment (OVMF / virtual)

```go
type SecureBootEnrollerConfig struct {
    NVRAMPath    string  // required
    KeysDir      string  // required; holds PK.crt, KEK.crt, DB.crt
    TemplatePath string  // optional; source for a missing NVRAM file
    OwnerGUID    *GUID   // optional; defaults to a fresh NewGUID()
}

func NewSecureBootEnroller(config *SecureBootEnrollerConfig, logger *logging.Logger) (*SecureBootEnroller, error)

func (e *SecureBootEnroller) EnrollKeys(ctx context.Context) error
func (e *SecureBootEnroller) GetEnrollmentStatus() (*EnrollmentStatus, error)
func (e *SecureBootEnroller) SetPlatformInfo(ctx context.Context, info *PlatformInfo) error
func (e *SecureBootEnroller) GetPlatformInfo() (*PlatformInfo, error)
func (e *SecureBootEnroller) EnrollKeysWithPlatformInfo(ctx context.Context, info *PlatformInfo) error

type EnrollmentStatus struct {
    SecureBootEnabled, SetupMode, HasPK, HasKEK, HasDB, HasDBX, KeysEnrolled bool
}
func (s *EnrollmentStatus) String() string

type PlatformInfo struct { Version, BuildDate, GitCommit string }
```

`pkg/qemu` has its **own** `SecureBootEnroller` for guest VMs
(`pkg/qemu/secureboot.go`) that delegates to this one's primitives and returns
`*uefi.EnrollmentStatus`. Same name, different package, different lifecycle —
do not confuse them.

### 2.3 `pkg/uefi` — live-firmware enrollment (bare metal)

```go
var EfivarsPath = "/sys/firmware/efi/efivars"   // package var, overridable in tests

func EfivarsAvailable() bool
func IsSetupMode() (bool, error)
func SecureBootEnabled() (bool, error)

func NewEFITime(t time.Time) EFITime
func (t EFITime) Bytes() []byte

func EnrollKeysToEfivars(ctx context.Context, pkCert, kekCert, dbCert *x509.Certificate, ts EFITime) error
func EnrollKeysToEfivarsDir(ctx context.Context, dir string, pkCert, kekCert, dbCert *x509.Certificate, ts EFITime) error

type UKIVerifier interface {
    VerifyFile(path string) error
    ExtractCertificateFile(path string) (*x509.Certificate, error)
}

func VerifySignedUKI(verifier UKIVerifier, ukiPath string, dbCert *x509.Certificate, logger *logging.Logger) error

func ReadSecureBootStatus() (*SecureBootStatus, error)
func ReadSecureBootStatusFromDir(dir string) (*SecureBootStatus, error)

type SecureBootStatus struct {
    EfivarsAvailable, SetupMode, SecureBoot, UserMode bool
    PK, KEK, DB, DBX SignatureDatabase
}

type SignatureDatabase struct {
    Name         string
    Present      bool
    Certificates int
    Hashes       int
    Other        int
    Subjects     []string
}
```

`UKIVerifier` is deliberately a two-method interface: it is satisfied by
`*authenticode.Signer`, and accepting it keeps `pkg/uefi` free of any keystore or
SDK dependency.

### 2.4 `pkg/uefi/firmware` — raw runtime variables

```go
const EfiVarsPath = "/sys/firmware/efi/efivars"

func IsAvailable() bool
func ReadVariable(name string, guid uefi.GUID) ([]byte, uint32, error)
func WriteVariable(name string, guid uefi.GUID, attrs uint32, data []byte) error
func DeleteVariable(name string, guid uefi.GUID) error
func ListVariables() ([]VariableInfo, error)
func GetVariable(name string, guid uefi.GUID) (*uefi.Variable, error)
func SetVariable(v *uefi.Variable) error

type VariableInfo struct {
    Name       string
    GUID       uefi.GUID
    Attributes uint32
    Size       int
}

const TrustedPlatformVariableName = "TRUSTED_PLATFORM"
const TrustedPlatformAttributes = uefi.AttrNonVolatile | uefi.AttrBootserviceAccess | uefi.AttrRuntimeAccess
var  TrustedPlatformGUID uefi.GUID

func SetTrustedPlatform() error
func ClearTrustedPlatform() error
func GetTrustedPlatform() (bool, error)
func IsTrustedPlatform() bool
```

`ListVariables` takes the last 36 characters of each `{name}-{guid}` file as
the GUID, so short names such as `Boot0000` are listed; directories and
names without a valid GUID are skipped.

> **Defect: two different `TRUSTED_PLATFORM` variables.**
> `uefi.TrustedPlatformGUID` is `F47E4B3D-8C21-4A9F-B6E5-1D2C3E4F5A6B`;
> `firmware.TrustedPlatformGUID` is `F47DE8A7-8E5B-4F4A-A73C-6D8F2E1B9C54`.
> `SecureBootEnroller.SetPlatformInfo` writes a pipe-delimited
> `VERSION|BUILD_DATE|GIT_COMMIT` record under the first;
> `firmware.SetTrustedPlatform` writes the literal `true` under the second.
> A reader of one will not find the other. Raised as an owner question; not
> resolved by picking one here.

`uefi.TrustedPlatformGUID` is also the owner GUID stamped into every enrolled
Secure Boot `EFI_SIGNATURE_LIST` (`secureBootKeyOwnerGUID`). The owner GUID is
informational — firmware acceptance depends on the certificate, not on it.

### 2.5 `pkg/secureboot`

```go
type KeyType string
const ( KeyTypePK KeyType = "PK"; KeyTypeKEK KeyType = "KEK"; KeyTypeDB KeyType = "DB" )

const ( ResignModeRemote = "remote"; ResignModeLocal = "local" )

type BackendType string
const (
    BackendFile     BackendType = "file"      // default
    BackendSoftware BackendType = "software"
    BackendPKCS11   BackendType = "pkcs11"
    BackendTPM2     BackendType = "tpm2"
    BackendAWSKMS   BackendType = "awskms"
    BackendAzureKV  BackendType = "azurekv"
    BackendGCPKMS   BackendType = "gcpkms"
    BackendVault    BackendType = "vault"
)
func (b BackendType) String() string
func (b BackendType) IsValid() bool

type XKMSConfig struct {
    KeysDir      string        // required
    Backend      BackendType   // default BackendFile
    CommonName   string
    Country      string
    Organization string
    KeySize      int           // default 2048; minimum 2048
    ValidYears   int           // default 10
    ExportKeys   bool          // forced false when ResignMode == ResignModeRemote
    ResignMode   string
}

func NewXKMSManager(config *XKMSConfig, logger *logging.Logger) (*XKMSManager, error)
func (km *XKMSManager) GenerateAll(ctx context.Context) error
func (km *XKMSManager) GeneratePlatformKey(ctx context.Context) error
func (km *XKMSManager) GenerateKeyExchangeKey(ctx context.Context) error
func (km *XKMSManager) GenerateDatabaseKey(ctx context.Context) error
func (km *XKMSManager) KeysExist() bool
func (km *XKMSManager) GetKeyPaths() KeyPaths
func (km *XKMSManager) GetSigner(ctx context.Context, keyType KeyType) (crypto.Signer, error)
func (km *XKMSManager) Close() error

type KeyPaths struct { PKCert, KEKCert, DBCert, PKKey, KEKKey, DBKey string }
```

```go
type KMSSignClient interface { Sign(ctx, *platformv1.SignRequest, ...grpc.CallOption) (*platformv1.SignResponse, error) }
type CertificateGetter interface { GetCertificate(ctx, *platformv1.GetCertificateRequest, ...grpc.CallOption) (*platformv1.GetCertificateResponse, error) }

func NewKMSSigner(ctx context.Context, kms KMSSignClient, ca CertificateGetter, keyURI, certURI string) (crypto.Signer, *x509.Certificate, error)
func FetchKMSCertificate(ctx context.Context, ca CertificateGetter, ref string) (*x509.Certificate, error)
func KMSKeyID(ref string) string
```

`platform.Client.KMS()` and `.CA()` satisfy the two interfaces, so the node
(IDevID mTLS) and an operator's build (its own client) use the same signer. The
certificate is fetched by `cert-uri`, or by the key id when `cert-uri` is empty;
`Sign` sends the Authenticode digest with `PreHashed` set.

```go
const (
    DefaultModuleKeyBits       = 4096
    MinModuleKeyBits           = 2048
    DefaultModuleKeyValidYears = 10
    DefaultModuleKeyCN         = "Trusted Platform Module Signing Key"
)

type ModuleSigningKeyConfig struct {
    Path         string // required
    KeyBits      int    // default DefaultModuleKeyBits; < MinModuleKeyBits rejected
    CommonName   string // default DefaultModuleKeyCN
    Organization string
    Country      string
    ValidYears   int    // default DefaultModuleKeyValidYears
    Force        bool   // default false
}

type ModuleSigningKey struct {
    Path        string
    Signer      crypto.Signer
    Certificate *x509.Certificate
}

func GenerateModuleSigningKey(ctx context.Context, cfg *ModuleSigningKeyConfig) (*ModuleSigningKey, error)
func LoadModuleSigningKey(path string) (*ModuleSigningKey, error)
```

### 2.6 `pkg/uki`

```go
type UKI struct {
    Kernel     io.Reader   // required
    Initramfs  io.Reader   // required
    Cmdline    string      // required
    OSRelease  string
    Stub       io.Reader   // nil -> DefaultStubPath
    Microcode  io.Reader
    Splash     io.Reader
    DeviceTree io.Reader
    SBAT       string
}
func (u *UKI) Validate() error
func (u *UKI) Close() error
func FromFiles(kernelPath, initramfsPath, cmdline string) (*UKI, error)

type Section struct { Name string; Data []byte }

type UKIBuilder interface {
    Build(uki *UKI, output io.Writer) error
    BuildFile(uki *UKI, outputPath string) error
    AddSection(name string, data []byte) error
    SetArchitecture(arch string) error
}

type UKIParser interface {
    Parse(reader io.Reader) (*UKI, error)
    ParseFile(path string) (*UKI, error)
    ExtractSection(reader io.Reader, sectionName string) ([]byte, error)
    ListSections(reader io.Reader) ([]string, error)
}

func NewBuilder(logger *logging.Logger) UKIBuilder
func NewObjcopyBuilder(logger *logging.Logger) UKIBuilder
func NewParser(logger *logging.Logger) UKIParser

const DefaultStubPath = "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"

type Architecture string
const ( ArchX86_64 = "x86_64"; ArchAArch64 = "aarch64"; ArchARM = "arm"; ArchRISCV64 = "riscv64" )
```

### 2.7 `pkg/authenticode`

```go
type Authenticode interface {
    Sign(input io.Reader, output io.Writer) error
    SignFile(inputPath, outputPath string) error
    Verify(input io.Reader) error
    VerifyFile(path string) error
    ExtractCertificate(input io.Reader) (*x509.Certificate, error)
    ExtractCertificateFile(path string) (*x509.Certificate, error)
}

type SignerOptions struct {
    KeyStore      xkmssdk.KeyProvider   // required
    KeyAttributes *xkmssdk.KeyAttributes // required
    Certificate   *x509.Certificate      // required
    CertChain     []*x509.Certificate
    TimestampURL  string                 // accepted; PLANNED (see §5)
    Logger        *logging.Logger        // required
}

func NewSigner(ctx context.Context, opts *SignerOptions) (Authenticode, error)
func (s *Signer) Public() crypto.PublicKey
func SigningTime(input io.Reader) (time.Time, error)
```

**The constructor takes a context first.** `NewSigner` also does an eager
`opts.KeyStore.Signer(ctx, opts.KeyAttributes)` to prove the key is reachable
before any file is touched.

Every caller that holds a key rather than a key store goes through one of two
constructors on top of `NewSigner` — there is no other key-store shim:

```go
func NewCryptoSigner(ctx context.Context, signer crypto.Signer, cert *x509.Certificate, logger *logging.Logger) (Authenticode, error)
func NewFileSigner(ctx context.Context, keyPath, certPath string, logger *logging.Logger) (Authenticode, error)
func LoadSigningPair(keyPath, certPath string) (crypto.Signer, *x509.Certificate, error)
func LoadPrivateKeyPEM(path string) (crypto.PrivateKey, error)  // PKCS#1 or PKCS#8
func LoadCertificate(path string) (*x509.Certificate, error)    // PEM or DER
```

`NewCryptoSigner` takes any `crypto.Signer` — a file key, the installer's
resolved DB key, or a KMS-held key that only sees digests
(`secureboot.NewKMSSigner`) — and refuses a certificate that does not certify
it (`KeyCertMismatchError`). `NewFileSigner` is `LoadSigningPair` +
`NewCryptoSigner`. The installer, the ISO build's staging gate and bootloader
signing, the PXE harness and the secureboot integration suite all use these.

### 2.8 `pkg/modulesign`

```go
func SignModule(koPath string, signer crypto.Signer, cert *x509.Certificate) error
func BuildModuleSignature(moduleContent []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error)
func EnumerateModules(rootfs, kver string) ([]string, error)
```

Signed layout: `original_module_bytes || cms_der || module_signature(12B) || magic(28B)`,
where `magic` is `"~Module signature appended~\n"` and the trailer carries
`id_type = PKEY_ID_PKCS7 (2)` and a big-endian `sig_len`. The CMS is **detached**
and carries **no embedded certificates** — the kernel matches the signer by
issuer + serial against its keyring.

---

## 3. Invariants

1. **`db` → `KEK` → `PK`, PK last, in both enrollment paths.** `enrollKeysToDir`
   writes in that order; `runEnroll` reports `EnrollOrder: ["db","KEK","PK"]`.
   Writing PK is the step that arms enforcement, so any earlier failure leaves a
   bootable node.
2. **Live enrollment requires Setup Mode.** `EnrollKeysToEfivarsDir` stats the
   directory (`ErrEfivarsUnavailable`) and reads `SetupMode`
   (`ErrNotSetupMode`) before writing anything. A stray call is a no-op, never a
   partial enrollment.
3. **`SetupMode` and `SecureBoot` are never written by enrollment.** They are
   firmware-derived. `GetEnrollmentStatus` mirrors the firmware rule — PK present
   means User Mode with Secure Boot active — and prefers a stored value only when
   one is actually present.
4. **`VerifySignedUKI` compares raw certificate bytes.** Not subject, not public
   key: `bytes.Equal(embedded.Raw, dbCert.Raw)`. Anything else and the firmware's
   `db` would not match what signed the image.
5. **`ResignModeRemote` forces `ExportKeys = false`.** Applied in
   `NewXKMSManager` before validation, so the export path cannot be re-enabled by
   ordering the config fields differently.
6. **`GenerateAll` is idempotent.** It returns early when `KeysExist()` — which
   checks that all three of `PK.crt`, `KEK.crt`, `DB.crt` are present in
   `KeysDir`. Note the consequence: with `ExportKeys: false` no certificate files
   are written, so `KeysExist()` is always false and `GenerateAll` regenerates
   every call. Per-key `generateKey` deletes any existing key of the same CN
   first, so this is a *replace*, not a duplicate.
7. **`GetSigner` never returns an exported key.** It always resolves through
   `xkmssdk.ServiceKey`, so in remote mode `Sign` round-trips only the digest.
8. **The module-signing key is never silently regenerated.**
   `GenerateModuleSigningKey` stats `cfg.Path` and returns `ErrModuleKeyExists`
   unless `Force` is set. A new key orphans every module signed with the old one.
9. **A UKI needs kernel, initramfs and cmdline.** `UKI.Validate` rejects any of
   the three missing. Everything else is optional.
10. **Section names are at most 8 characters** (PE/COFF limit), enforced by both
    builders' `AddSection`.
11. **UKI section order is fixed:** `.osrel`, `.cmdline`, `.ucode`, `.splash`,
    `.linux`, `.initrd`, `.dtb`, `.sbat`; custom sections follow. Data sections
    carry characteristics `0x40000040`
    (`IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`) — deliberately **not**
    `IMAGE_SCN_ALIGN_1BYTES`, which is object-file-only and makes some UEFI PE
    loaders reject the image.
12. **`BuildFile` fsyncs.** FAT32 on real SATA SSDs loses data without it. It
    also chmods `0755` and removes the output on any build failure.
13. **Module signing is atomic.** `atomicWrite` writes a temp file in the same
    directory, chmods to the original mode, and renames over the target; the temp
    file is removed on any failure.
14. **Compressed modules are signed over their decompressed bytes.** The kernel
    decompresses before verifying. `.ko.gz` and `.ko.zst` round-trip through the
    matching codec; `.ko.xz` is refused.
15. **The kernel-update rebuild never generates a DB key.** `resolveRebuildSigner`
    returns a typed error when neither the `file://` nor the remote branch
    resolves, and the caller aborts the swap.
16. **Concurrency:** none of these types are documented or built as
    concurrency-safe. `XKMSManager.initializeService` calls
    `xkmssdk.ServiceReset()` on a **process-global** XKMS service — constructing
    two managers in one process resets the first. Treat one manager per process,
    and do not enroll from two goroutines.

---

## 4. Error semantics

### `pkg/uefi`

| Error | Returned when |
|---|---|
| `ErrInvalidFormat` | Malformed ESL header or entry, a firmware-volume/variable-store header shorter than its fixed size, or a boolean efivar payload under 5 bytes |
| `ErrInvalidSignature` | Firmware-volume header signature is not `_FVH` |
| `ErrVariableNotFound` | `(*NVRAM).GetVariable` / `DeleteVariable` on a missing variable |
| `ErrInsufficientSpace` | Serialising the variable store overflows the firmware volume |
| `ErrNotSetupMode` | **Fail-closed.** Enrollment attempted while the firmware has an active PK |
| `ErrEfivarsUnavailable` | **Fail-closed.** efivarfs not mounted |
| `ErrEfivarRead{Var, Cause}` | An efivar could not be read or parsed; `Var` names it |
| `ErrEnrollWrite{Var, Cause}` | A Secure Boot variable write failed; `Var` is `db`, `KEK` or `PK` |
| `ErrUKIVerify{Cause}` | **Fail-closed.** The signed UKI failed Authenticode verification, or its embedded certificate is not the `db` certificate |
| `ErrInvalidGUID`, `ErrInvalidChecksum`, `ErrReadOnly` | **Declared and never returned** by any non-test code in `pkg/uefi`. Do not write a caller that branches on them |

`pkg/uefi/firmware` has its own sentinel set: `ErrNotAvailable` (efivarfs
absent), `ErrVariableNotFound`, `ErrPermissionDenied`, `ErrInvalidData`,
`ErrImmutable`, plus `ErrNotTrustedPlatform`. They are distinct values from
`pkg/uefi`'s despite two sharing a name — `errors.Is(err, uefi.ErrVariableNotFound)`
will not match `firmware.ErrVariableNotFound`.

`ErrEfivarRead`, `ErrEnrollWrite` and `ErrUKIVerify` all implement `Unwrap`.
`SentinelCauseError.Unwrap` returns `[]error{Sentinel, Cause}` so `errors.Is`
matches both.

**Missing signature-database files are not errors.** `readSignatureDatabaseFile`
returns a non-`Present` summary for `os.IsNotExist`; only malformed content
errors. That is how `secure-boot status` reports `dbx: absent` instead of failing.

### `pkg/secureboot`

Returned: `ErrConfigNil` (nil config), `ErrInvalidConfig` (empty `KeysDir`,
`KeyBits`/`KeySize` below the floor, unknown backend, empty module-key `Path`),
`ErrKeyGenFailed`, `ErrWriteFailed` (module-key bundle write).

Declared and **never returned** by non-test code: `ErrKeysNotFound`,
`ErrInvalidKeyType`. Note that `pkg/qemu` declares its own, distinct
`ErrKeysNotFound`, which *is* returned — do not cross-match them.

Typed: `ErrModuleKeyExists{Path}`, `ErrModuleKeyNotFound{Path, Err}`,
`ErrModuleKeyMalformed{Path, Reason}`, and for the KMS signer
`KMSKeyRefError{KeyURI}`, `KMSCertificateError{Ref, Err}`,
`KMSSignError{KeyID, Err}`, `UnsupportedHashError{Hash}`.

**`NewKMSSigner` fails closed**: a key URI that names no KMS key, a certificate
the CA cannot return or parse, an empty signature and a hash the KMS cannot carry
are each a typed error — never a fall-back to a local key.

### `pkg/modulesign`

`ErrNilSigner`, `ErrNilCertificate`, `ErrUnsupportedCompressionCodec{Path, Codec, Dependency}`,
`ErrUnsupportedKeyType{KeyType}`, `ErrModuleRead{Path, Err}`,
`ErrModuleWrite{Path, Err}`, `ErrDecompress{Path, Codec, Err}`,
`ErrCompress{Path, Codec, Err}`, `ErrSign{Err}`, `ErrASN1Marshal{Stage, Err}`,
`ErrEnumerate{Path, Err}`. All the wrapping ones implement `Unwrap`.

### `pkg/uki`

`ErrInvalidPE`, `ErrNoHeaderSpace`, `ErrSectionNameTooLong`, plus
`MessageError`, `WrappedError`, and `CommandOutputError` (an external-command
failure with captured output or a remediation hint — for example
"install systemd-efistub package" when the stub is missing).

### `pkg/authenticode`

`ErrRFC3161NotImplemented{URL}` — the only typed error; everything else is
`MessageError` / `WrappedError`. Verification failures surface as
`"Authenticode digest mismatch"`, `"PE file is not signed"`, or a wrapped
`"cryptographic signature verification failed"`.

### CLI errors

`pkg/cli/commands/secureboot`: `ErrCertificateLoad{Role, Path, Cause}`,
`ErrUKINotFound{Path}`, `ErrVerifierBuild{Cause}`, `ErrEnforceIncomplete{Reason}`,
`ErrVerifyOnlyBackend{Operation}`, `ErrNotPEMCertificate{Path}`.

`pkg/cli/commands/authenticode`: `ErrDaemonConnectionRequired`,
`ErrReadKeyFailed`, `ErrDecodeKeyFailed`, `ErrParseKeyFailed`,
`ErrReadCertificateFailed`, `ErrDecodeCertificateFailed`,
`ErrParseCertificateFailed`, `ErrCreateSignerFailed`, `ErrSignFileFailed`,
`ErrVerifyFileFailed`, `ErrKeyNotSigner`, `ErrNotImplemented{Operation}`.

`pkg/provisioning/configdelivery` (the remote-signing path):
`ErrInvalidRequest{Reason}`, `ErrNonceRequired`, `ErrMissingProfileService`,
`ErrRemoteSignNotConfigured{Reason}`, `ErrSignerUnavailable`,
`ErrSignFailed{Cause}`, `ErrCertUnavailable{Cause}`.

### Paths that fail closed

- Live enrollment without efivarfs or without Setup Mode.
- Enforcement when the signed UKI does not verify against the `db` certificate.
- `enforce --commit` that completes without leaving a PK in firmware →
  `ErrEnforceIncomplete`.
- Kernel-update UKI rebuild with an unresolvable DB signer.
- `NewKMSSigner` with an empty key URI, an unavailable or malformed certificate,
  a failing or empty KMS signature, or an unsupported hash.
- `remoteDBKeyRefs` on the control plane: Secure Boot disabled, resign-mode not
  `remote`, empty DB key URI, or a key selector other than `db`.
- `GenerateModuleSigningKey` over an existing key without `--force`.

### Paths that warn and continue

Install-time only, and deliberate: an unsigned UKI still boots a machine that
is not enforcing, so a signing-material failure must not strand an otherwise
good install. `signUKI` and `enforceSecureBoot` warn-and-skip on unresolvable DB
material, missing efivarfs, firmware not in Setup Mode, and a failed verify gate.
Only an unexpected failure *after every guard* returns an error, and even that
is logged without aborting the install.

---

## 5. Configuration

### Installer config — `secure-boot:`

`installer.SecureBootConfig`, validated by `(*SecureBootConfig).Validate()`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `secure-boot.enabled` | bool | `false` | Gates both UKI signing and enrollment |
| `secure-boot.enforce` | bool | `false` | Attempt the enforcement transition at install |
| `secure-boot.resign-mode` | string | `remote` | `remote` or `local`; empty defaults to `remote` |
| `secure-boot.pk` | key ref | — | Required when `enforce` is set |
| `secure-boot.kek` | key ref | — | Required when `enforce` is set |
| `secure-boot.db` | key ref | — | `db.key-uri` is **always required** when enabled |

Each key ref (`installer.SecureBootKeyRef`) inlines `common.KeyConfig` — which
supplies `cn` and `store` — plus:

| Field | Meaning |
|---|---|
| `key-uri` | `kms://<path>` or `file://<path>`. Any other scheme is rejected |
| `cert-uri` | Companion certificate reference, same scheme rule |

Validation rules, in order: `resign-mode` must be `remote` or `local`;
`db.key-uri` must be non-empty; when `enforce` is set, `pk.key-uri` and
`kek.key-uri` must also be non-empty; every non-empty URI must start with
`kms://` or `file://` (case-insensitive). Failures are
`ErrSecureBootConfig{Field, Reason}` naming the exact key.

**Backend selection is `store`, not the URI scheme.** The scheme only says
*where the reference resolves*; `store` (`tpm2`, `software`, …) is what the KMS
routes on.

### `XKMSConfig` defaults

`Backend` → `BackendFile`; `KeySize` → 2048 (minimum 2048, else
`ErrInvalidConfig`); `ValidYears` → 10; backend name `"secureboot"`; key CN
`"secureboot-<PK|KEK|DB>"`; certificate subject
`"<CommonName> - <Platform Key|Key Exchange Key|Database Key>"`. Only
`BackendFile` and `BackendSoftware` are constructible from config today — the
hardware and cloud backends return
`"backend <name> requires a pre-configured KeyStore instance"`.

### Environment variables

**None.** No `pkg/uefi`, `pkg/secureboot`, `pkg/uki`, `pkg/authenticode` or
`pkg/modulesign` behaviour is driven by an environment variable. The only env
vars in this area belong to the hardware integration tier (§7):
`TP_HW_TPM`, `TP_HW_TPM_DEVICE`, `TP_HW_EFIVARS`, and the FIPS-kernel fixture
variables `FIPS_KERNEL_IMAGE`, `FIPS_MODULES_TAR`, `FIPS_MODULE_SIGNING_KEY`.

### Filesystem defaults

| Constant | Value |
|---|---|
| `securebootcmd.DefaultKeysDir` | `/etc/trusted-platform/secure-boot` |
| `securebootcmd.DefaultUKIPath` | `/boot/efi/EFI/BOOT/BOOTX64.EFI` |
| `installer.DefaultESPUKIPath` | `/boot/efi/EFI/BOOT/BOOTX64.EFI` |
| `installer.DefaultModulesDir` | `/lib/modules` |
| `installer.DefaultBootDir` | `/boot` |
| `installer.DefaultKernelCmdlinePath` | `/etc/kernel/cmdline` |
| `uki.DefaultStubPath` | `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` |
| `uefi.EfivarsPath` / `firmware.EfiVarsPath` | `/sys/firmware/efi/efivars` |
| `iso.SecureBootKeysISODirName` | `secure-boot-keys` |
| `iso.SecureBootKeysMediaDir` | `/media/cdrom/secure-boot-keys` |
| module-signing key default | `$HOME/.trusted-platform/secure-boot/module-signing-key.pem` |

Install-media probe order for pre-baked keys: `/media/cdrom`, `/media/usb`,
`/mnt/cdrom`. OVMF template probe order:
`/usr/share/OVMF/OVMF_VARS_4M.fd`, `/usr/share/OVMF/OVMF_VARS.fd`,
`/usr/share/edk2/ovmf/OVMF_VARS.fd`, `/usr/share/qemu/OVMF_VARS.fd`.

### File modes

`DB.key` / `PK.key` / `KEK.key` → `0600`. Certificates → `0644`. Module-signing
PEM bundle → `0600`, its parent directory `0700`. Built UKI → `0755`.

---

## 6. Persistence and compatibility

- **The OVMF variable store format is a property of the store, not of a
  variable.** `OVMF_VARS*.fd` uses the authenticated store
  (`gEfiAuthenticatedVariableGuid`), in which *every* variable carries the
  60-byte authenticated header — including variables with no
  `TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute. `NVRAM.IsAuthenticatedStore`
  decides, and `serializeVariable` follows it. Emitting a 32-byte header into an
  authenticated store produces a file the EDK2 variable driver faults on.
- **efivarfs payload shape.** A variable file is
  `<uint32 attributes LE> || <data>`; efivarfs strips the attribute word and
  forwards the rest to `SetVariable`. For a time-based authenticated write the
  data is `EFI_VARIABLE_AUTHENTICATION_2 || EFI_SIGNATURE_LIST`, and in Setup
  Mode the descriptor's PKCS#7 `CertData` is **empty** — the firmware does not
  require the write to chain to an existing PK.
- **`ReadSecureBootStatusFromDir` tolerates both shapes.** A real efivarfs read
  returns bare ESL data; a fixture directory written by
  `EnrollKeysToEfivarsDir` still carries the auth descriptor.
  `skipAuthDescriptor` detects it structurally (EFI_TIME + WIN_CERTIFICATE with
  revision `0x0200`, type `0x0EF1`, and the PKCS#7 GUID) and skips it.
- **Existing efivarfs variables are immutable.** `writeAuthenticatedVarFile`
  clears `FS_IMMUTABLE_FL` via `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS` and retries
  the write exactly once.
- **Unparseable certificates are reported, not dropped.**
  `readSignatureDatabaseFile` records `<unparseable X.509 certificate>` in
  `Subjects` — the firmware will honour an entry Go cannot parse, so hiding it
  would misreport the trust state.
- **The module-signing PEM bundle** is a PKCS#8 private key block followed by a
  certificate block, matching the kernel's own `certs/signing_key.pem`.
  `LoadModuleSigningKey` additionally accepts a PKCS#1 `RSA PRIVATE KEY` block
  for compatibility.
- **UKI rollback.** The kernel-update rebuild keeps the previous image as
  `<uki>.prev` and swaps by a single same-filesystem rename.

---

## 7. Test strategy

| Layer | Location | In `make test`? | Covers |
|---|---|---|---|
| Unit | `pkg/uefi/*_test.go` | **yes** | GUID round-trip, ESL encode/parse, NVRAM parse/serialise, enrollment ordering, efivars enroll payload bytes, status parsing |
| Unit | `pkg/secureboot/*_test.go` | **yes** | Key generation, key paths, re-sign mode, KMS signer (fake KMS and CA clients), module-key generate/load/malformed |
| Unit | `pkg/authenticode/authenticode_test.go` | **yes** | Sign/verify round-trip, certificate extraction, constructor validation |
| Unit | `pkg/modulesign/*_test.go` | **yes** | CMS envelope, trailer, compression codecs, guards, error paths |
| Unit | `pkg/uefi/firmware/*_test.go` | **no** — excluded | Raw variable read/write/delete/list and the `TRUSTED_PLATFORM` marker against a temp-dir efivarfs root with a fake `chattr`; never `/sys` or the host `chattr` |
| Unit | `pkg/uki/*_test.go` | **no** — excluded | PE patching, section ordering, parser, helpers |
| Unit | `pkg/cli/commands/secureboot/secureboot_test.go` | **no** — excluded | Verb wiring, flags, the guard pipeline with an injected `uefi.UKIVerifier` |
| Integration | `test/integration/secureboot/` | separate target | The whole chain against real external verifiers and real firmware |
| Integration (hardware) | `test/integration/secureboot/hardware/` | separate target | Opt-in, run **on the target node** |

**Three of this feature's packages are excluded from the default sweep.**
`TEST_EXCLUDE` in the `Makefile` names `pkg/uefi/firmware$`, `pkg/uki$` and
`pkg/cli/commands` (the whole tree). Their tests exist and pass when run
directly — `go test ./pkg/uki/...` — but a green `make test` says nothing about
them. Note that `pkg/uefi` itself is **not** excluded; only its `firmware`
subpackage is.

Integration entry points: `make integration-test-secureboot` and
`make integration-test-secureboot-hw`.

What the integration tier proves:

| Test | Proves |
|---|---|
| `TestOVMFSecureBootEnforcement` | Platform-generated PK/KEK/DB enrolled into a real OVMF store; a DB-signed EFI payload **boots**; unsigned and wrongly-signed payloads are refused by the firmware with `Access Denied` |
| `TestModuleSignOpenSSLInterop` | The detached CMS is valid to OpenSSL — an independent implementation — over the exact module bytes, with the correct trailer and magic |
| `TestModuleSignCorruptedSignatureFailsVerify` / `TestModuleSignTamperedContentFailsVerify` | Signature and content binding |
| `TestUnsignedModuleLacksTrailer` | The precise condition `CONFIG_MODULE_SIG_FORCE` rejects |
| `TestFIPSKernelModuleSignatureEnforcement` | A real FIPS kernel rejects an unsigned module at `insmod` with `ENOKEY`, loads the build-signed module, and loads the same module re-signed by `pkg/modulesign` |

**Seams for fault injection.** `uefi.EfivarsPath` is a package var;
`EnrollKeysToEfivarsDir` and `ReadSecureBootStatusFromDir` take an explicit
directory; `runEnroll`/`runEnforce` accept an injected `uefi.UKIVerifier`;
`secureboot.KMSSignClient` / `CertificateGetter` and
`installer.RemoteSignerResolver` are small interfaces; `installer.WithUKIBuilder`, `WithESPUKIPath`, `WithModulesDir`,
`WithBootDir` retarget the rebuild at a temp tree.

**Gating is skip-free.** With a hardware tier variable set but the precondition
missing, the test **fails** with a typed error rather than `t.Skip()`. The
hardware tier never writes an EFI variable — committing PK from CI could strand
the node; the write path is validated by an operator through the CLI dry-run and
commit workflow.

**The FIPS-kernel test consumes prebuilt artefacts** (the kernel takes hours to
build) and fails with a typed setup error when they are absent, which is why the
`secureboot` target is excluded from the `all` integration sweep.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, not only here.

---

## 8. Observability

Log prefixes are the fastest way to find the relevant lines:

| Prefix | Emitted by |
|---|---|
| `[SECUREBOOT]` | `pkg/uefi/efivars_enroll.go`, `pkg/installer` signing and enforcement |
| `[AUTHENTICODE]` | `pkg/authenticode` sign/verify/extract |
| `[UKI]` | `pkg/uki` builders |
| `[BUILD-UKI]` | `platformctl install uki` |
| `[ALPINE]` | Installer OS provisioning, including IMA setup |

Key events worth alerting on: `"Secure Boot keys enrolled"` with
`secure_boot_enabled` and `setup_mode`; `"signed UKI verified against db
certificate"`; and every `[SECUREBOOT]` warning, because each one means
enforcement was silently skipped.

`configdelivery` emits `"configdelivery: remote uki digest signed"` with
`profile_id`, `ek_serial`, `mac_address` and `key_uri` on success, and
`"configdelivery: sign ek binding verification failed"` on a rejected EK binding.

**Never log:** private key bytes, the contents of `DB.key` or the module-signing
bundle, or the raw digest/signature pair in a context that could be replayed.
The code logs sizes and subjects, not material — keep it that way.

No metric names are defined for this feature.

---

## 9. Related

- [architecture.md](architecture.md) — boundaries, trust model, rejected alternatives
- [api.md](api.md) — the transport matrix, including everything that is `MISSING`
- [cli.md](cli.md) · [user.md](user.md)
- [`docs/ima/engineering.md`](../ima/engineering.md) — the PCR 10 half
- [`docs/attestation/`](../attestation/) · [`docs/installer/`](../installer/) ·
  [`docs/provisioning/`](../provisioning/) · [`docs/vtpm/`](../vtpm/)
