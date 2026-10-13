# IMA API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). There is no `WithTPMSysPath` option; `GetStatus` leaves most `Status` fields zero, and `UnexpectedFiles` is never populated ([architecture.md §9](architecture.md)).

Go package API for reading and verifying IMA measurements.

**Package:** `github.com/jeremyhahn/go-trusted-platform/pkg/ima`

## Reader

The Reader interface provides methods for reading IMA data from the system.

### Constructor

```go
func NewReader(opts ...ReaderOption) *Reader
```

**Options:**
- `WithSecurityFSPath(path string)` - Custom securityfs path (default: `/sys/kernel/security`)

**Example:**
```go
reader := ima.NewReader()
// or with custom path
reader := ima.NewReader(ima.WithSecurityFSPath("/custom/path"))
```

### System Status Methods

#### IsAvailable

Check if IMA is available on the system.

```go
func (r *Reader) IsAvailable() bool
```

#### IsSecurityFSMounted

Check if securityfs is mounted.

```go
func (r *Reader) IsSecurityFSMounted() bool
```

#### GetStatus

Get comprehensive IMA status.

```go
func (r *Reader) GetStatus() (*Status, error)
```

**Returns:** `*Status` struct containing:
- `Available` - IMA available on system
- `Enabled` - IMA enabled
- `PolicyLoaded` - Policy is loaded
- `HashAlgorithm` - Configured hash algorithm
- `PolicyType` - Policy type (tcb, appraise_tcb, etc.)
- `AppraiseMode` - Appraise mode (off, log, enforce, fix)
- `EVMEnabled` - EVM enabled
- `SigningKeyLoaded` - Signing key loaded
- `MeasurementCount` - Number of measurements
- `ViolationCount` - Number of violations
- `PCR10Value` - Current PCR 10 value
- `TPMAvailable` - TPM available
- `AvailablePCRBanks` - Available PCR banks

### Event Log Methods

#### ReadEventLog

Read and parse the IMA event log from default location.

```go
func (r *Reader) ReadEventLog() (*EventLog, error)
```

#### ReadEventLogFromFile

Read and parse the IMA event log from a specific file.

```go
func (r *Reader) ReadEventLogFromFile(path string) (*EventLog, error)
```

#### ParseEventLog

Parse an IMA event log from an io.Reader.

```go
func (r *Reader) ParseEventLog(reader io.Reader) (*EventLog, error)
```

#### ParseEvent

Parse a single IMA event line.

```go
func (r *Reader) ParseEvent(line string) (*Event, error)
```

### Policy Methods

#### ReadPolicy

Read the current IMA policy.

```go
func (r *Reader) ReadPolicy() (*Policy, error)
```

#### ReadPolicyFromFile

Read IMA policy from a specific file.

```go
func (r *Reader) ReadPolicyFromFile(path string) (*Policy, error)
```

#### ParsePolicy

Parse IMA policy from an io.Reader.

```go
func (r *Reader) ParsePolicy(reader io.Reader) (*Policy, error)
```

#### ParsePolicyRule

Parse a single policy rule.

```go
func (r *Reader) ParsePolicyRule(line string) (*PolicyRule, error)
```

### Analysis Methods

#### GetStatistics

Get statistics from an event log.

```go
func (r *Reader) GetStatistics(log *EventLog) *Statistics
```

#### ReadViolations

Read the violation count.

```go
func (r *Reader) ReadViolations() (int, error)
```

#### FindEventByPath

Find events for a specific file path.

```go
func (r *Reader) FindEventByPath(log *EventLog, path string) []*Event
```

#### FindEventByHash

Find events by file hash.

```go
func (r *Reader) FindEventByHash(log *EventLog, hash []byte) []*Event
```

## Verifier

The Verifier interface provides methods for verifying IMA measurements.

### Constructor

```go
func NewVerifier(opts ...VerifierOption) *Verifier
```

**Options:**
- `WithAllowlist(allowlist map[string][]byte)` - Set file hash allowlist
- `WithTPMSysPath(path string)` - Custom TPM sysfs path

**Example:**
```go
verifier := ima.NewVerifier()
// or with allowlist
verifier := ima.NewVerifier(ima.WithAllowlist(myAllowlist))
```

### Verification Methods

#### VerifyEventLog

Verify all events in a log against allowlist.

```go
func (v *Verifier) VerifyEventLog(log *EventLog) *VerificationResult
```

**Returns:** `*VerificationResult` struct containing:
- `Passed` - Verification passed
- `TotalMeasurements` - Total measurements checked
- `ValidMeasurements` - Valid measurements
- `InvalidMeasurements` - Invalid measurements
- `MissingFiles` - Files that should be measured but weren't
- `UnexpectedFiles` - Files measured but not in allowlist
- `ViolationFiles` - Files that caused violations
- `Errors` - Verification errors
- `Duration` - Verification duration
- `PCR10Verified` - PCR 10 was verified
- `PCR10Bank` - PCR bank used

#### VerifyFile

Verify a single file measurement against actual file.

```go
func (v *Verifier) VerifyFile(event *Event) error
```

#### VerifySignature

Verify file signature (for ima-sig template).

```go
func (v *Verifier) VerifySignature(event *Event, pubKey crypto.PublicKey) error
```

### PCR Methods

#### ComputePCR10

Compute expected PCR 10 from event log.

```go
func (v *Verifier) ComputePCR10(log *EventLog, hashAlg string) ([]byte, error)
```

#### VerifyPCR10

Verify computed PCR 10 against expected value.

```go
func (v *Verifier) VerifyPCR10(log *EventLog, expectedPCR []byte, hashAlg string) error
```

#### ReadPCR10FromTPM

Read PCR 10 value from TPM via sysfs.

```go
func (v *Verifier) ReadPCR10FromTPM(bank string) ([]byte, error)
```

#### VerifyPCR10AgainstTPM

Verify event log PCR 10 against actual TPM value.

```go
func (v *Verifier) VerifyPCR10AgainstTPM(log *EventLog, bank string) error
```

### TPM Status Methods

#### IsTPMAvailable

Check if TPM is available.

```go
func (v *Verifier) IsTPMAvailable() bool
```

#### IsPCR10Available

Check if PCR 10 is available for a specific bank.

```go
func (v *Verifier) IsPCR10Available(bank string) bool
```

#### GetAvailablePCRBanks

Get list of available PCR banks.

```go
func (v *Verifier) GetAvailablePCRBanks() []string
```

### Allowlist Methods

#### AddToAllowlist

Add file to allowlist.

```go
func (v *Verifier) AddToAllowlist(path string, hash []byte)
```

#### AddToAllowlistWithAlg

Add file to allowlist with specific algorithm.

```go
func (v *Verifier) AddToAllowlistWithAlg(alg, path string, hash []byte)
```

#### RemoveFromAllowlist

Remove file from allowlist.

```go
func (v *Verifier) RemoveFromAllowlist(path string)
```

#### ClearAllowlist

Clear all allowlist entries.

```go
func (v *Verifier) ClearAllowlist()
```

#### GetAllowlist

Get current allowlist.

```go
func (v *Verifier) GetAllowlist() map[string][]byte
```

#### BuildAllowlistFromLog

Build allowlist from event log.

```go
func (v *Verifier) BuildAllowlistFromLog(log *EventLog) error
```

### Hash Methods

#### HashFile

Compute hash of a file.

```go
func (v *Verifier) HashFile(path string, alg string) ([]byte, error)
```

#### HashFileToHex

Compute hash of a file as hex string.

```go
func (v *Verifier) HashFileToHex(path string, alg string) (string, error)
```

### Analysis Methods

#### DetectMeasurementGaps

Detect gaps in measurements (potential tampering).

```go
func (v *Verifier) DetectMeasurementGaps(log *EventLog, maxGap time.Duration) []string
```

#### FindDuplicateMeasurements

Find files measured multiple times.

```go
func (v *Verifier) FindDuplicateMeasurements(log *EventLog) map[string]int
```

#### FindModifiedFiles

Find files with different hashes across measurements.

```go
func (v *Verifier) FindModifiedFiles(log *EventLog) []string
```

## Data Types

### Event

```go
type Event struct {
    PCR           int       // PCR index (usually 10)
    TemplateHash  []byte    // Hash of template data
    TemplateName  string    // Template name (ima-ng, ima-sig)
    FileHash      []byte    // Hash of measured file
    HashAlgorithm string    // Hash algorithm (sha256, sha1)
    FilePath      string    // Path to measured file
    Signature     []byte    // File signature (ima-sig only)
    UID           int       // Process UID
    EventType     string    // Event type
    Timestamp     time.Time // Event timestamp
    RawLine       string    // Original event line
}
```

### EventLog

```go
type EventLog struct {
    Events         []*Event  // List of events
    TotalCount     int       // Total event count
    UniqueFiles    int       // Unique file paths
    ViolationCount int       // Policy violations
    ParseErrors    int       // Parse errors
    ParsedAt       time.Time // When parsed
}
```

### Policy

```go
type Policy struct {
    Rules     []*PolicyRule // Policy rules
    RuleCount int           // Rule count
    LoadedAt  time.Time     // When loaded
}
```

### PolicyRule

```go
type PolicyRule struct {
    Action    string // measure, appraise, audit, etc.
    Condition string // Rule condition
    Func      string // Function type (BPRM_CHECK, etc.)
    Mask      string // Access mask (MAY_EXEC, etc.)
    PCR       int    // PCR to extend
    Template  string // Template (ima-ng, ima-sig)
    RawRule   string // Original rule string
}
```

### Status

```go
type Status struct {
    Available         bool
    Enabled           bool
    PolicyLoaded      bool
    HashAlgorithm     string
    PolicyType        string
    AppraiseMode      string
    EVMEnabled        bool
    SigningKeyLoaded  bool
    MeasurementCount  int
    ViolationCount    int
    PCR10Value        []byte
    TPMAvailable      bool
    AvailablePCRBanks []string
}
```

### VerificationResult

```go
type VerificationResult struct {
    Passed              bool
    TotalMeasurements   int
    ValidMeasurements   int
    InvalidMeasurements int
    MissingFiles        []string
    UnexpectedFiles     []string
    ViolationFiles      []string
    Errors              []error
    Duration            time.Duration
    VerifiedAt          time.Time
    PCR10Verified       bool
    PCR10Bank           string
}
```

### Statistics

```go
type Statistics struct {
    TotalEvents     int
    UniqueFiles     int
    FilesByHashAlg  map[string]int
    FilesByTemplate map[string]int
    FilesByAction   map[string]int
    TopPaths        []string
    ViolationCount  int
    CollectedAt     time.Time
}
```

## Error Types

```go
var (
    ErrNotAvailable         = errors.New("IMA is not available on this system")
    ErrSecurityFSNotMounted = errors.New("securityfs is not mounted")
    ErrInvalidEventFormat   = errors.New("invalid IMA event format")
    ErrHashMismatch         = errors.New("measurement hash mismatch")
    ErrPolicyViolation      = errors.New("IMA policy violation detected")
    ErrAppraisalFailure     = errors.New("IMA appraisal failure")
    ErrKeyNotLoaded         = errors.New("IMA signing key not loaded")
    ErrTPMNotAvailable      = errors.New("TPM device not available")
    ErrPCRReadFailed        = errors.New("failed to read PCR value")
    ErrPCRMismatch          = errors.New("PCR value mismatch")
    ErrInvalidPCRBank       = errors.New("invalid PCR bank")
)
```

## Constants

```go
const DefaultSecurityFSPath = "/sys/kernel/security"
const IMAPath = "/sys/kernel/security/ima"
const DefaultTPMSysPath = "/sys/class/tpm/tpm0"
```

## Usage Examples

### Basic Status Check

```go
reader := ima.NewReader()

status, err := reader.GetStatus()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("IMA Available: %v\n", status.Available)
fmt.Printf("IMA Enabled: %v\n", status.Enabled)
fmt.Printf("Policy Type: %s\n", status.PolicyType)
fmt.Printf("Measurements: %d\n", status.MeasurementCount)
```

### Verify Measurements

```go
reader := ima.NewReader()
verifier := ima.NewVerifier()

// Read event log
log, err := reader.ReadEventLog()
if err != nil {
    return err
}

// Verify against TPM
err = verifier.VerifyPCR10AgainstTPM(log, "sha256")
if err != nil {
    log.Fatal("Verification failed:", err)
}
fmt.Println("PCR 10 verified successfully")
```

### Build and Verify Allowlist

```go
reader := ima.NewReader()
verifier := ima.NewVerifier()

// Read initial log and build allowlist
log, _ := reader.ReadEventLog()
verifier.BuildAllowlistFromLog(log)

// Later, verify new log against allowlist
newLog, _ := reader.ReadEventLog()
result := verifier.VerifyEventLog(newLog)

if !result.Passed {
    fmt.Printf("Invalid measurements: %d\n", result.InvalidMeasurements)
    for _, file := range result.UnexpectedFiles {
        fmt.Printf("Unexpected: %s\n", file)
    }
}
```

### Remote Attestation Integration

```go
// On attester side
reader := ima.NewReader()
log, _ := reader.ReadEventLog()

// Serialize and send log with attestation quote
logJSON, _ := json.Marshal(log)

// On verifier side
verifier := ima.NewVerifier(ima.WithAllowlist(goldenAllowlist))

var receivedLog ima.EventLog
json.Unmarshal(logJSON, &receivedLog)

// Verify against known-good PCR 10 from quote
err := verifier.VerifyPCR10(&receivedLog, expectedPCR10, "sha256")
if err != nil {
    log.Fatal("PCR mismatch - possible tampering")
}

// Verify against allowlist
result := verifier.VerifyEventLog(&receivedLog)
if !result.Passed {
    log.Fatal("Unexpected files measured")
}
```

## Related Documentation

- [Configuration](configuration.md) - IMA configuration
- [Policies](policies.md) - Policy syntax
- [TPM Integration](tpm-integration.md) - PCR 10 verification
