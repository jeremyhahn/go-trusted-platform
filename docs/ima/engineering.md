# Linux IMA — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/ima/`, plus `installer.IMAConfig` and the IMA provisioning path · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was grepped in this repository on 2026-08-18. Where a
> declared field is never populated, this document says so — that is the whole
> point of the file.

---

## 1. Package layout

`pkg/ima` imports only the Go standard library. It has no dependency on any
other package in this repository, and no package in this repository imports it.

| File | Holds |
|---|---|
| `types.go` | Package doc, sentinel errors, path constants, and every exported struct: `Event`, `EventLog`, `Status`, `PolicyRule`, `Policy`, `VerificationResult`, `Statistics` |
| `reader.go` | `Reader`, its options, event-log and policy parsing, statistics, violations, lookups |
| `verifier.go` | `Verifier`, its options, allowlists, event/file/signature verification, PCR 10 replay, hashing, analysis helpers |
| `tpm_integration.go` | PCR bank constants, PCR 10 read from TPM sysfs, TPM/bank availability |
| `errors.go` | `MessageError`, `SentinelCauseError`, `WrappedError` |

Test files: `reader_test.go`, `verifier_test.go`, `tpm_integration_test.go`.

---

## 2. Exported surface

### 2.1 Constants and paths

```go
const DefaultSecurityFSPath = "/sys/kernel/security"
const IMAPath               = "/sys/kernel/security/ima"
const DefaultTPMSysPath     = "/sys/class/tpm/tpm0"

const (
    PCRBankSHA1   = "sha1"
    PCRBankSHA256 = "sha256"
    PCRBankSHA384 = "sha384"
    PCRBankSHA512 = "sha512"
    PCR10         = 10
)

var EventPaths = struct{ ASCIIRuntime, BinaryRuntime, Policy, Violations string }{
    ASCIIRuntime:  "/sys/kernel/security/ima/ascii_runtime_measurements",
    BinaryRuntime: "/sys/kernel/security/ima/binary_runtime_measurements",
    Policy:        "/sys/kernel/security/ima/policy",
    Violations:    "/sys/kernel/security/ima/violations",
}

var TPMPaths = struct{ TPM0, PCRS string }{
    TPM0: "/sys/class/tpm/tpm0",
    PCRS: "pcr-%s",
}
```

`EventPaths` and `TPMPaths` are **hard-coded absolute paths, not derived from
the `Reader`'s configured securityfs path.** `EventPaths.BinaryRuntime` is
declared and never read — the binary log is PLANNED
([architecture.md](architecture.md) §8).

### 2.2 `Reader`

```go
type Reader struct{ /* securityFSPath */ }

type ReaderOption func(*Reader)
func WithSecurityFSPath(path string) ReaderOption
func NewReader(opts ...ReaderOption) *Reader

func (r *Reader) IsAvailable() bool
func (r *Reader) IsSecurityFSMounted() bool
func (r *Reader) GetStatus() (*Status, error)

func (r *Reader) ReadEventLog() (*EventLog, error)
func (r *Reader) ReadEventLogFromFile(path string) (*EventLog, error)
func (r *Reader) ParseEventLog(reader io.Reader) (*EventLog, error)
func (r *Reader) ParseEvent(line string) (*Event, error)

func (r *Reader) ReadPolicy() (*Policy, error)
func (r *Reader) ReadPolicyFromFile(path string) (*Policy, error)
func (r *Reader) ParsePolicy(reader io.Reader) (*Policy, error)
func (r *Reader) ParsePolicyRule(line string) (*PolicyRule, error)

func (r *Reader) GetStatistics(log *EventLog) *Statistics
func (r *Reader) ReadViolations() (int, error)
func (r *Reader) FindEventByPath(log *EventLog, path string) []*Event
func (r *Reader) FindEventByHash(log *EventLog, hash []byte) []*Event
```

`WithSecurityFSPath` is the **only** `ReaderOption`. The zero-configuration
constructor uses `DefaultSecurityFSPath`.

### 2.3 `Verifier`

```go
type Verifier struct{ /* reader, allowlist, allowlistByAlg */ }

type VerifierOption func(*Verifier)
func WithAllowlist(allowlist map[string][]byte) VerifierOption
func WithReader(reader *Reader) VerifierOption
func NewVerifier(opts ...VerifierOption) *Verifier

func (v *Verifier) VerifyEventLog(log *EventLog) *VerificationResult
func (v *Verifier) VerifyFile(event *Event) error
func (v *Verifier) VerifySignature(event *Event, pubKey crypto.PublicKey) error

func (v *Verifier) ComputePCR10(log *EventLog, hashAlg string) ([]byte, error)
func (v *Verifier) VerifyPCR10(log *EventLog, expectedPCR []byte, hashAlg string) error

func (v *Verifier) AddToAllowlist(path string, hash []byte)
func (v *Verifier) AddToAllowlistWithAlg(alg, path string, hash []byte)
func (v *Verifier) RemoveFromAllowlist(path string)
func (v *Verifier) ClearAllowlist()
func (v *Verifier) GetAllowlist() map[string][]byte
func (v *Verifier) BuildAllowlistFromLog(log *EventLog) error

func (v *Verifier) HashFile(path, alg string) ([]byte, error)
func (v *Verifier) HashFileToHex(path, alg string) (string, error)

func (v *Verifier) DetectMeasurementGaps(log *EventLog, maxGap time.Duration) []string
func (v *Verifier) FindDuplicateMeasurements(log *EventLog) map[string]int
func (v *Verifier) FindModifiedFiles(log *EventLog) []string
```

**`WithTPMSysPath` does not exist.** Custom TPM paths are per-call, §2.4.

**`AddToAllowlistWithAlg` writes to `allowlistByAlg`, which nothing reads.** It
has no effect on any verification path today.

### 2.4 TPM integration (methods on `*Verifier`)

```go
func (v *Verifier) ReadPCR10FromTPM(bank string) ([]byte, error)
func (v *Verifier) ReadPCR10FromTPMWithPath(tpmPath, bank string) ([]byte, error)

func (v *Verifier) VerifyPCR10AgainstTPM(log *EventLog, bank string) error
func (v *Verifier) VerifyPCR10AgainstTPMWithPath(log *EventLog, tpmPath, bank string) error

func (v *Verifier) IsPCR10Available(bank string) bool
func (v *Verifier) IsPCR10AvailableWithPath(tpmPath, bank string) bool
func (v *Verifier) IsTPMAvailable() bool
func (v *Verifier) IsTPMAvailableWithPath(tpmPath string) bool
func (v *Verifier) GetAvailablePCRBanks() []string
func (v *Verifier) GetAvailablePCRBanksWithPath(tpmPath string) []string
```

The `…WithPath` variants exist so the parse and comparison logic can be
exercised against a fixture directory with no TPM present. They are the
fault-injection seam for this package.

### 2.5 Data types — and which fields are actually populated

```go
type Event struct {
    PCR           int       // set
    TemplateHash  []byte    // set
    TemplateName  string    // set
    FileHash      []byte    // set
    HashAlgorithm string    // set ("sha1" when the log has no algorithm prefix)
    FilePath      string    // set when field 5 is present
    Signature     []byte    // set only for template "ima-sig" with field 6 present
    UID           int       // NEVER SET
    EventType     string    // NEVER SET
    Timestamp     time.Time // NEVER SET
    RawLine       string    // set
}

type EventLog struct {
    Events         []*Event  // set
    TotalCount     int       // set
    UniqueFiles    int       // set
    ViolationCount int       // NEVER SET — always 0
    ParseErrors    int       // set
    ParsedAt       time.Time // set
}

type Status struct {
    Available         bool     // set
    Enabled           bool     // set
    PolicyLoaded      bool     // set
    HashAlgorithm     string   // set from the FIRST event, if any
    PolicyType        string   // NEVER SET
    AppraiseMode      string   // NEVER SET
    EVMEnabled        bool     // NEVER SET
    SigningKeyLoaded  bool     // NEVER SET
    MeasurementCount  int      // set
    ViolationCount    int      // copied from EventLog.ViolationCount — always 0
    PCR10Value        []byte   // NEVER SET
    TPMAvailable      bool     // NEVER SET
    AvailablePCRBanks []string // NEVER SET
}

type PolicyRule struct {
    Action, Condition, Func, Mask, Template, RawRule string
    PCR int
}

type Policy struct {
    Rules     []*PolicyRule
    RuleCount int
    LoadedAt  time.Time
}

type VerificationResult struct {
    Passed              bool     // set
    TotalMeasurements   int      // set from EventLog.TotalCount
    ValidMeasurements   int      // set
    InvalidMeasurements int      // set
    MissingFiles        []string // set — allowlist entries with no matching event
    UnexpectedFiles     []string // NEVER APPENDED TO — always empty
    ViolationFiles      []string // set — file paths whose event failed verification
    Errors              []error  // set
    Duration            time.Duration // set
    VerifiedAt          time.Time     // set
    PCR10Verified       bool     // NEVER SET by VerifyEventLog
    PCR10Bank           string   // NEVER SET by VerifyEventLog
}

type Statistics struct {
    TotalEvents     int              // set
    UniqueFiles     int              // set
    FilesByHashAlg  map[string]int   // set
    FilesByTemplate map[string]int   // set
    FilesByAction   map[string]int   // ALWAYS EMPTY (keyed on Event.EventType)
    TopPaths        []string         // set — top 10 by measurement count
    ViolationCount  int              // copied from EventLog.ViolationCount — always 0
    CollectedAt     time.Time        // set
}
```

The "NEVER SET" annotations are not editorial. An implementing agent that
returns `Status.TPMAvailable` to a caller is returning `false` on a machine with
a TPM. Use `Verifier.IsTPMAvailable()` and `Verifier.GetAvailablePCRBanks()`
directly, and `Reader.ReadViolations()` for violations.

---

## 3. Wire formats parsed

### IMA ASCII event line

```
PCR TEMPLATE_HASH TEMPLATE_NAME FILEDATA_HASH FILENAME_HINT [SIGNATURE]

10 a1b2… ima-ng sha256:def4… /usr/bin/bash
10 a1b2… ima-sig sha256:def4… /usr/bin/bash 0302…
```

Parsing rules, exactly as implemented:

- Whitespace-split; fewer than **4** fields → `ErrInvalidEventFormat`.
- Field 1 → `PCR` via `strconv.Atoi`; failure wraps `ErrInvalidEventFormat`.
- Field 2 → `TemplateHash` via `hex.DecodeString`.
- Field 3 → `TemplateName`, verbatim.
- Field 4 → if it contains `:`, split once into `HashAlgorithm` and a hex
  `FileHash`; otherwise the whole field is a hex hash and `HashAlgorithm` is set
  to the literal `"sha1"` (legacy `ima` template).
- Field 5, when present → `FilePath`.
- Field 6, when present **and** `TemplateName == "ima-sig"` → `Signature`, hex.
  A decode failure here is silently ignored and leaves `Signature` nil.

**A path containing a space breaks parsing.** The parser splits on whitespace and
takes field 5 as the whole path. This is inherited from the ASCII format, which
does not escape or quote; the binary log is the correct answer and is PLANNED.

### IMA policy rule

```
action [condition …] [func=X] [mask=X] [pcr=N] [template=X] …
measure func=FILE_CHECK mask=MAY_READ pcr=10 template=ima-ng
```

- Blank lines and `#` comments are skipped by `ParsePolicy`.
- Field 1 → `Action`.
- `func=`, `mask=`, `pcr=`, `template=` populate their fields; `pcr=` that fails
  `Atoi` is silently left at 0.
- **Every other token, with or without `=`, is appended to `Condition`,
  space-separated.** So `fowner=0`, `fsmagic=0x9fa0` and `appraise_type=imasig`
  all land in `Condition` as raw text, not as structured fields.
- `RawRule` always carries the original line.
- A rule that fails to parse is **skipped silently** by `ParsePolicy` — unlike
  the event log, there is no `ParseErrors` counter for policy.

### TPM sysfs PCR

`<tpmPath>/pcr-<bank>/<10>` — a hex string, possibly with trailing whitespace.
Trimmed, hex-decoded, and length-checked against the bank: sha1 → 20, sha256 →
32, sha384 → 48, sha512 → 64 bytes.

---

## 4. Invariants

1. **Nothing in `pkg/ima` writes.** No policy write, no PCR extend, no file
   modification. Every operation is a read plus computation.
2. **A missing measurement log is `ErrNotAvailable`, not a wrapped OS error.**
   `ReadEventLogFromFile` and `ReadPolicyFromFile` map `os.IsNotExist` to
   `ErrNotAvailable`; every other open failure is wrapped.
3. **A missing violations file is zero, not an error.** `ReadViolations` returns
   `(0, nil)` on `os.IsNotExist`, because a kernel with no appraisal never
   creates the file.
4. **Malformed event lines are counted, not fatal.** `ParseEventLog` increments
   `ParseErrors` and continues. Only a `bufio.Scanner` error aborts.
5. **PCR replay skips events whose `PCR != 10`.** `ComputePCR10` starts from a
   zero buffer of `h.Size()` bytes and extends `pcr = H(pcr || TemplateHash)`
   for each PCR-10 event in log order.
6. **`ComputePCR10` does not recompute a per-bank template hash.** It extends
   the template digest exactly as parsed. See [architecture.md](architecture.md)
   §7 for what that means for a multi-bank TPM — this is the single most
   important thing to understand before trusting a `VerifyPCR10AgainstTPM`
   result.
7. **`VerifyPCR10AgainstTPMWithPath` compares in constant time** — it walks the
   full length and accumulates a boolean rather than returning on first
   difference. `VerifyPCR10` and `verifyAgainstAllowlist` use `bytes.Equal`,
   which is not constant time; that is acceptable because both compare public
   values.
8. **Verification is fail-open on unknown files, fail-closed on known ones.**
   A path absent from the allowlist passes; a path present with a different hash
   fails with `ErrHashMismatch` and is appended to `ViolationFiles`. The
   consequence — `UnexpectedFiles` is never populated — is stated in §2.5 and is
   a gap, not a subtlety.
9. **`verifyTemplateHash` validates length only.** It accepts 20, 32, 48 or 64
   bytes and rejects anything else with `ErrHashMismatch`. It does **not** verify
   that the template hash matches the event contents.
10. **`VerifySignature` is a presence check.** Nil event →
    `ErrInvalidEventFormat`; empty signature or nil public key →
    `ErrKeyNotLoaded`; signature shorter than 9 bytes → `ErrAppraisalFailure`;
    otherwise **nil**. It performs no cryptography. Do not call it and report
    "signature verified".
11. **`GetStatus` on an unmounted securityfs is an error, not a status.** It
    returns `ErrSecurityFSNotMounted`. With securityfs mounted but no `ima`
    directory it returns `&Status{Available: false, Enabled: false}, nil`.
12. **`GetStatus` swallows event-log errors.** It calls `ReadEventLog` and, on
    error, leaves the counts at zero without surfacing why.
13. **No concurrency guarantees.** `Verifier`'s allowlist maps are plain maps
    with no lock. Concurrent `AddToAllowlist` and `VerifyEventLog` is a data
    race. One verifier per goroutine, or serialise externally.
14. **`Reader` is effectively immutable after construction** and safe to share;
    all its methods are pure reads.
15. **`GetStatistics(nil)` returns nil**, and every `Verifier` analysis helper
    returns nil for a nil log rather than panicking.
16. **`getTopPaths` is a selection sort** over unique paths — O(n²) in unique
    paths, not in events. Fine for the "top 10" it exists to compute; do not
    reach for it on a synthetic log with a hundred thousand unique paths.

---

## 5. Error semantics

| Error | Returned when |
|---|---|
| `ErrNotAvailable` | The measurement log or policy file does not exist; a nil `*EventLog` was passed to a verifier method |
| `ErrSecurityFSNotMounted` | `GetStatus` and securityfs is not mounted |
| `ErrInvalidEventFormat` | Fewer than 4 fields, unparseable PCR index, unparseable hex, empty template hash, nil event |
| `ErrHashMismatch` | Allowlist hash mismatch, `VerifyFile` hash mismatch, `VerifyPCR10` mismatch, unexpected template-hash length |
| `ErrPolicyViolation` | **Declared and never returned.** No code path produces it |
| `ErrAppraisalFailure` | `VerifySignature` with a signature shorter than 9 bytes |
| `ErrKeyNotLoaded` | `VerifySignature` with an empty signature or a nil public key |
| `ErrTPMNotAvailable` | The PCR file does not exist at the constructed path |
| `ErrPCRReadFailed` | The PCR file exists but read, hex-decode or length check failed |
| `ErrPCRMismatch` | `VerifyPCR10AgainstTPM` — computed and actual differ, in value or in length |
| `ErrInvalidPCRBank` | A bank other than `sha1`/`sha256`/`sha384`/`sha512` |

Wrapping types: `MessageError` (message, no cause), `WrappedError` (message +
cause, `Unwrap() error`), `SentinelCauseError` (sentinel + cause,
`Unwrap() []error` so `errors.Is` matches both). Sentinel-carrying failures use
`SentinelCauseError`, so `errors.Is(err, ima.ErrPCRMismatch)` works while the
message still names the values.

### Paths that fail closed

- `ReadPCR10FromTPMWithPath` on an invalid bank, a missing PCR file, unparseable
  hex, or a length that does not match the bank.
- `VerifyPCR10AgainstTPMWithPath` on any length or value difference.
- `VerifyEventLog` sets `Passed = false` on the first failed event and never
  un-sets it.
- `getHasher` on an unrecognised algorithm — no default, no silent fallback to
  SHA-256.

### Paths that fail open, deliberately

- Files absent from the allowlist pass (§4.8).
- Malformed event lines are counted and skipped (§4.4).
- Malformed policy rules are skipped silently.
- A missing violations file counts as zero violations.

### Paths that fail open, and should not

- `VerifySignature` returning nil for any signature ≥ 9 bytes. Treat it as
  unimplemented ([architecture.md](architecture.md) §8), not as a check.

---

## 6. Configuration

IMA is configured under the installer config's `os:` block —
`installer.OSConfig.IMA`, type `*installer.IMAConfig`. **Not** a top-level
`ima:` key ([architecture.md](architecture.md) §9).

```yaml
os:
  ima:
    enabled: true
    policy: tcb
    hash-algorithm: sha256
    evm: false
    appraise-mode: "off"
    audit-enabled: true
    signing-key-path: ""
    public-key-path: ""
    monitor-paths: []
```

| Key | Go field | Type | Default | Meaning |
|---|---|---|---|---|
| `os.ima.enabled` | `Enabled` | bool | `false` | Gates everything below |
| `os.ima.policy` | `Policy` | string | `tcb` when empty at cmdline time | `tcb`, `appraise_tcb`, `secure_boot`, `critical_data`; any other value falls through to the TCB rules in the generator |
| `os.ima.hash-algorithm` | `HashAlgorithm` | string | `sha256` when empty at cmdline time | `sha256`, `sha1`, `sha512` |
| `os.ima.evm` | `EVM` | bool | `false` | Adds `evm=fix` to the kernel command line |
| `os.ima.appraise-mode` | `AppraiseMode` | string | `""` | `off`, `log`, `enforce`, `fix`. Empty or `off` adds no `ima_appraise=` parameter |
| `os.ima.audit-enabled` | `AuditEnabled` | bool | `false` | Adds `ima_audit=1`, installs `audit`/`audit-openrc`, enables `auditd` |
| `os.ima.signing-key-path` | `SigningKeyPath` | string | `""` | Recorded only; the installer does not consume it |
| `os.ima.public-key-path` | `PublicKeyPath` | string | `""` | Recorded only; the boot script loads a **hard-coded** `/etc/ima/ima-public-key.pem` regardless of this value |
| `os.ima.monitor-paths` | `MonitorPaths` | []string | `[]` | Extra paths appended to the generated policy — but see the `obj_type=` defect in [architecture.md](architecture.md) §9 |

`installer.DefaultIMAMonitorPaths()` returns a 40-entry list of common
system-binary, library, cron, init and network-config paths. **It is never
called by any non-test code.** If you want those paths measured you must put
them in `monitor-paths` yourself.

ISO builds carry two derived booleans, `iso.Config.IMAEnabled` and
`iso.Config.IMAAuditEnabled`, which only add packages to the image.

### Kernel command line, as emitted

| Parameter | Emitted when |
|---|---|
| `ima=on` | always, when `os.ima.enabled` |
| `ima_policy=<policy>` | always; `tcb` when `policy` is empty |
| `ima_hash=<alg>` | always; `sha256` when `hash-algorithm` is empty |
| `ima_audit=1` | `audit-enabled: true` |
| `ima_appraise=<mode>` | `appraise-mode` set and not `off` |
| `evm=fix` | `evm: true` |

These are appended to the UKI command line and are therefore covered by the
Authenticode signature on the boot image.

### Environment variables

**None.** No behaviour in `pkg/ima` or in the IMA provisioning path is driven by
an environment variable.

### Files written at install time

| Path | Mode | Content |
|---|---|---|
| `/etc/ima/ima-policy` | `0644` | The generated policy |
| `/etc/ima/ima.conf` | `0644` | `IMA_ENABLED`, `IMA_POLICY`, `IMA_HASH`, `IMA_AUDIT`, `IMA_APPRAISE`, `IMA_EVM` — a record for humans, read by nothing |
| `/etc/local.d/ima.start` | `0755` | Loads the policy and the `.ima` public key at boot |

Directory `/etc/ima` is created `0755`. The OpenRC `local` service, which runs
`local.d` scripts, is added to the default runlevel by the installer.

### Generated policy, by policy type

| `policy` | Rules emitted |
|---|---|
| `tcb` | `measure` on `BPRM_CHECK`/`MMAP_CHECK` with `mask=MAY_EXEC`, plus `MODULE_CHECK`, `FIRMWARE_CHECK`, `KEXEC_KERNEL_CHECK`, `KEXEC_INITRAMFS_CHECK`, all `pcr=10 template=ima-ng` |
| `appraise_tcb` | The same measurements with `template=ima-sig`, plus `appraise … appraise_type=imasig` on `BPRM_CHECK`, `MMAP_CHECK` (both `fowner=0`) and `MODULE_CHECK` |
| `secure_boot` | `measure` on `KEXEC_KERNEL_CHECK`, `KEXEC_INITRAMFS_CHECK`, `MODULE_CHECK` only |
| `critical_data` | `measure func=CRITICAL_DATA pcr=10 template=ima-buf` |
| anything else | Falls through to a three-rule TCB subset (`BPRM_CHECK`, `MMAP_CHECK`, `MODULE_CHECK`) |

Every generated policy ends with noise-reduction rules:

```
dont_measure fsmagic=0x9fa0        # procfs
dont_measure fsmagic=0x62656572    # sysfs
dont_measure fsmagic=0x64626720    # debugfs
dont_measure fsmagic=0x01021994    # tmpfs
dont_measure fsmagic=0x858458f6    # ramfs
dont_measure fsmagic=0x73636673    # securityfs
```

---

## 7. Persistence

**None.** `pkg/ima` owns no store, no schema and no on-disk format of its own.
Every value is derived on demand from kernel-published files. There is nothing
to migrate and no compatibility window to maintain.

The only durable artefacts are the three install-time files above, and they are
plain text regenerated by a reinstall.

---

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/ima/reader_test.go` | Event and policy parsing (well-formed, malformed, legacy no-prefix hashes, `ima-sig`), statistics, violations, lookups, availability against a temp securityfs tree |
| Unit | `pkg/ima/verifier_test.go` | Allowlist lifecycle, event and file verification, `ComputePCR10` / `VerifyPCR10`, hashing, duplicate and modified-file detection |
| Unit | `pkg/ima/tpm_integration_test.go` | PCR read against a fixture TPM sysfs tree, bank validation, length checks, availability probes |
| Integration | — | **None.** There is no `test/integration/ima` target |

`pkg/ima` is **not** in the `Makefile`'s `TEST_EXCLUDE` list, so it runs in the
ordinary `make test` sweep. It needs no TPM, no root and no special environment,
because every path that touches the system is parameterised by a directory.
(Contrast `pkg/uki`, `pkg/uefi/firmware` and `pkg/cli/commands`, which the
firmware feature notes are excluded —
[`docs/firmware/engineering.md`](../firmware/engineering.md) §7.)

**Fixture strategy.** `WithSecurityFSPath` for the reader; the `…WithPath`
variants for the TPM. A test builds `t.TempDir()/ima/ascii_runtime_measurements`
or `t.TempDir()/pcr-sha256/10` and points the code at it. There is no mocking
layer and none is needed.

**What is not covered, because it is not implemented:** IMA signature
verification, template-hash recomputation, binary-log parsing, per-bank PCR
replay ([architecture.md](architecture.md) §8).

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. It does not bind this
feature in practice, which has no CLI verbs at all.

---

## 9. Observability

`pkg/ima` emits **no logs and no metrics**. It uses `log/slog` in exactly one
place: `IsPCR10AvailableWithPath` logs a `Debug` line if closing the probed PCR
file fails. There is no injected logger and no structured event vocabulary.

The provisioning half logs under the `[ALPINE]` prefix:
`"Configuring Linux Integrity Measurement Architecture (IMA)"`,
`"Created IMA policy"`, `"Created IMA local.d start script"`,
`"Enabled auditd service for IMA audit logging"`, and
`"IMA configuration complete"` with `policy`, `hash` and `audit`. The UKI build
logs `"[UKI] IMA enabled"` with `policy` and `hash`.

**IMA configuration failure at install time is a warning, not an error**:
`"Failed to configure IMA, continuing without it"`. A node can therefore install
successfully with IMA silently absent — check the install log, and check
`platformctl`-independent runtime state (`/sys/kernel/security/ima/`) before
assuming a node is measuring.

Operational signals worth watching, none of which this package surfaces for you
today:

- `/sys/kernel/security/ima/violations` — a rising count means ToMToU or
  open-writer violations, i.e. files changing while being measured.
- `EventLog.ParseErrors` — nonzero means the log format is ahead of the parser.
- `ErrPCRMismatch` — inconclusive until bank and algorithm are checked (§4.6).

**Do not log measurement logs wholesale.** A full `ascii_runtime_measurements`
is an inventory of every binary a machine has executed; it is not secret, but it
is a reconnaissance gift and it is large.

---

## 10. Related

- [architecture.md](architecture.md) — trust boundaries, the PCR replay caveat,
  rejected alternatives, and the full legacy-contradiction list
- [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/firmware/engineering.md`](../firmware/engineering.md) — the boot-time
  half of measured boot
- [`docs/attestation/`](../attestation/) · [`docs/installer/`](../installer/)
