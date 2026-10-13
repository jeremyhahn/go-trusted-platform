# Attestation API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md).

## Overview

The Attestation API provides comprehensive functionality for hardware-based attestation operations using TPM 2.0 and related trusted computing technologies. This API enables generation and verification of attestation quotes, management of host manifests, policy evaluation, and multi-tenant attestation across hosts, virtual machines, and containers.

## Go API

### Package Import

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation"
```

### Attestation Manager Interface

```go
type AttestationManager interface {
    // Quote Operations
    GenerateQuote(ctx context.Context, nonce []byte, pcrs []int) (*Quote, error)
    VerifyQuote(ctx context.Context, quote *Quote, expected *ExpectedPCRs) (*VerificationResult, error)

    // Manifest Operations
    GenerateManifest(ctx context.Context, opts *ManifestOptions) (*HostManifest, error)
    GetManifest(ctx context.Context, hostID string) (*HostManifest, error)
    PushManifest(ctx context.Context, manifest *HostManifest, verifierURL string) error

    // Policy Operations
    EvaluatePolicy(ctx context.Context, attestation *Attestation, policy string) (*PolicyResult, error)

    // PCR Operations
    GetPCRValues(ctx context.Context, pcrs []int) (map[int][]byte, error)
    GetEventLog(ctx context.Context) (*EventLog, error)

    // Host Operations
    ListHosts(ctx context.Context, opts *ListHostsOptions) ([]*HostInfo, error)
    GetHost(ctx context.Context, hostID string) (*HostInfo, error)

    // Streaming
    StreamAttestations(ctx context.Context, opts *StreamOptions) (<-chan *AttestationEvent, error)
}
```

### Key Types

#### Quote

```go
type Quote struct {
    Data      []byte            // TPM quote data structure
    Signature []byte            // TPM signature over quote
    PCRs      map[int][]byte    // PCR values included in quote
    Nonce     []byte            // Challenge nonce
    Timestamp time.Time         // Quote generation timestamp
    AIKPublic []byte            // Attestation Identity Key public portion
    PCRBank   string            // Hash algorithm bank (SHA256, SHA384)
}
```

#### Host Manifest

```go
type HostManifest struct {
    Host       HostAttestation        // Host-level attestation
    VMs        []VMAttestation        // Virtual machine attestations
    Containers []ContainerAttestation // Container attestations
    Aggregate  AggregateStatus        // Combined status
    Signature  []byte                 // Manifest signature
    Timestamp  time.Time              // Generation timestamp
    Version    int                    // Manifest version
}

type HostAttestation struct {
    HostID      string             // Unique host identifier
    Quote       *Quote             // TPM quote
    PCRs        map[int][]byte     // Current PCR values
    EventLog    *EventLog          // Measured boot event log
    Platform    PlatformInfo       // Platform identification
    Status      AttestationStatus  // Attestation status
    LastUpdated time.Time          // Last attestation time
}

type VMAttestation struct {
    VMID        string            // Virtual machine ID
    HostID      string            // Parent host ID
    Quote       *Quote            // VM-specific quote (if available)
    LaunchDigest []byte           // Expected launch measurement
    Status      AttestationStatus // Attestation status
    Runtime     RuntimeInfo       // Runtime environment info
}

type ContainerAttestation struct {
    ContainerID   string            // Container ID
    ImageDigest   string            // Container image digest
    HostID        string            // Parent host ID
    VMID          string            // Parent VM ID (if applicable)
    PolicyDigest  []byte            // Applied policy digest
    Status        AttestationStatus // Attestation status
    Namespace     string            // Kubernetes namespace
}

type AggregateStatus struct {
    Overall    AttestationStatus // Overall status
    HostStatus AttestationStatus // Host attestation status
    VMStatus   AttestationStatus // Aggregate VM status
    ContainerStatus AttestationStatus // Aggregate container status
    FailureCount int              // Number of failed attestations
    TotalCount   int              // Total attestation count
}
```

#### Verification Result

```go
type VerificationResult struct {
    Valid         bool              // Overall verification result
    Errors        []string          // Verification error messages
    PCRMatches    map[int]bool      // Per-PCR match results
    PolicyResult  *PolicyResult     // Policy evaluation result
    SignatureValid bool             // Quote signature validity
    NonceValid    bool              // Nonce freshness check
    Timestamp     time.Time         // Verification timestamp
}

type PolicyResult struct {
    Passed     bool              // Policy evaluation passed
    PolicyID   string            // Evaluated policy identifier
    Violations []PolicyViolation // Policy violations found
    Timestamp  time.Time         // Evaluation timestamp
}

type PolicyViolation struct {
    Rule        string // Violated rule name
    Expected    string // Expected value
    Actual      string // Actual value
    Severity    string // Violation severity
    Description string // Human-readable description
}
```

#### Supporting Types

```go
type AttestationStatus string

const (
    StatusTrusted    AttestationStatus = "Trusted"
    StatusUntrusted  AttestationStatus = "Untrusted"
    StatusPending    AttestationStatus = "Pending"
    StatusExpired    AttestationStatus = "Expired"
    StatusUnknown    AttestationStatus = "Unknown"
)

type ExpectedPCRs struct {
    Values    map[int][]byte // Expected PCR values
    Bank      string         // Hash algorithm bank
    Tolerance int            // Number of allowed mismatches
}

type ManifestOptions struct {
    IncludeVMs        bool     // Include VM attestations
    IncludeContainers bool     // Include container attestations
    PCRSelection      []int    // PCRs to include
    PolicyID          string   // Policy to evaluate against
    SignManifest      bool     // Sign the manifest
}

type EventLog struct {
    Entries   []EventLogEntry // Log entries
    Algorithm string          // Hash algorithm
    PCRIndex  int             // Associated PCR
}

type EventLogEntry struct {
    PCRIndex  int       // PCR this event extends
    EventType uint32    // Event type code
    Digest    []byte    // Event digest
    Data      []byte    // Event data
    Timestamp time.Time // Event timestamp
}

type PlatformInfo struct {
    Manufacturer string // Platform manufacturer
    Model        string // Platform model
    Firmware     string // Firmware version
    TPMVersion   string // TPM version
    BIOS         string // BIOS version
}

type HostInfo struct {
    HostID       string            // Unique host identifier
    Hostname     string            // Host DNS name
    Platform     PlatformInfo      // Platform information
    LastSeen     time.Time         // Last attestation time
    Status       AttestationStatus // Current status
    VMCount      int               // Number of VMs
    ContainerCount int             // Number of containers
}

type ListHostsOptions struct {
    Status  AttestationStatus // Filter by status
    Limit   int               // Max results
    Offset  int               // Pagination offset
}

type StreamOptions struct {
    HostIDs    []string          // Filter by host IDs
    Statuses   []AttestationStatus // Filter by status
    BufferSize int               // Event buffer size
}

type AttestationEvent struct {
    EventType string            // Event type
    HostID    string            // Affected host
    Timestamp time.Time         // Event timestamp
    Status    AttestationStatus // New status
    Details   map[string]string // Additional details
}

type RuntimeInfo struct {
    Hypervisor string // Hypervisor type
    Version    string // Runtime version
    Features   []string // Enabled features
}
```

### Error Types

```go
var (
    ErrQuoteVerificationFailed = errors.New("quote verification failed")
    ErrPCRMismatch            = errors.New("PCR values do not match expected")
    ErrNonceExpired           = errors.New("nonce has expired")
    ErrPolicyViolation        = errors.New("policy evaluation failed")
    ErrInvalidQuote           = errors.New("invalid quote format")
    ErrInvalidSignature       = errors.New("quote signature verification failed")
    ErrHostNotFound           = errors.New("host not found")
    ErrManifestExpired        = errors.New("manifest has expired")
    ErrTPMUnavailable         = errors.New("TPM device unavailable")
    ErrEventLogInvalid        = errors.New("event log validation failed")
    ErrPolicyNotFound         = errors.New("policy not found")
    ErrStreamClosed           = errors.New("attestation stream closed")
)
```

### Creating an Attestation Manager

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/attestation"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

cfg := &attestation.Config{
    TPMConfig: &xkmssdk.TPMConfig{
    NonceExpiration:   5 * time.Minute,
    ManifestTTL:       24 * time.Hour,
    DefaultPCRs:       []int{0, 1, 2, 3, 4, 5, 6, 7},
    EventLogPath:      "/sys/kernel/security/tpm0/binary_bios_measurements",
    VerifierEndpoint:  "https://verifier.example.com",
    Logger:            os.Stderr,
}

mgr, err := attestation.NewManager(cfg)
if err != nil {
    log.Fatal(err)
}
defer mgr.Close()
```

### Quote Operations

#### Generate Quote

```go
// Generate a fresh attestation quote
nonce := make([]byte, 32)
if _, err := rand.Read(nonce); err != nil {
    log.Fatal(err)
}

pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7}
quote, err := mgr.GenerateQuote(ctx, nonce, pcrs)
if err != nil {
    log.Fatal(err)
}

log.Printf("Generated quote at %s with %d PCRs",
    quote.Timestamp, len(quote.PCRs))
```

#### Verify Quote

```go
expected := &attestation.ExpectedPCRs{
    Values: map[int][]byte{
        0: goldenPCR0,
        1: goldenPCR1,
        // ... additional expected PCR values
    },
    Bank:      "SHA256",
    Tolerance: 0, // No mismatches allowed
}

result, err := mgr.VerifyQuote(ctx, quote, expected)
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    log.Println("Quote verification successful")
} else {
    for _, errMsg := range result.Errors {
        log.Printf("Verification error: %s", errMsg)
    }
    for pcr, matched := range result.PCRMatches {
        if !matched {
            log.Printf("PCR %d mismatch", pcr)
        }
    }
}
```

### Manifest Operations

#### Generate Manifest

```go
opts := &attestation.ManifestOptions{
    IncludeVMs:        true,
    IncludeContainers: true,
    PCRSelection:      []int{0, 1, 2, 3, 4, 5, 6, 7},
    PolicyID:          "default-policy",
    SignManifest:      true,
}

manifest, err := mgr.GenerateManifest(ctx, opts)
if err != nil {
    log.Fatal(err)
}

log.Printf("Generated manifest for host %s with %d VMs and %d containers",
    manifest.Host.HostID, len(manifest.VMs), len(manifest.Containers))
log.Printf("Aggregate status: %s", manifest.Aggregate.Overall)
```

#### Push Manifest to Verifier

```go
verifierURL := "https://verifier.example.com/api/v1/attestation/manifest"
err := mgr.PushManifest(ctx, manifest, verifierURL)
if err != nil {
    log.Fatal(err)
}
```

### Policy Operations

#### Evaluate Policy

```go
attestationData := &attestation.Attestation{
    Quote:    quote,
    Manifest: manifest,
    HostID:   "host-001",
}

result, err := mgr.EvaluatePolicy(ctx, attestationData, "strict-policy")
if err != nil {
    log.Fatal(err)
}

if result.Passed {
    log.Println("Policy evaluation passed")
} else {
    for _, violation := range result.Violations {
        log.Printf("Policy violation: %s - %s (severity: %s)",
            violation.Rule, violation.Description, violation.Severity)
    }
}
```

### PCR Operations

#### Get Current PCR Values

```go
pcrs := []int{0, 1, 2, 3, 4, 5, 6, 7}
values, err := mgr.GetPCRValues(ctx, pcrs)
if err != nil {
    log.Fatal(err)
}

for pcr, value := range values {
    log.Printf("PCR %d: %x", pcr, value)
}
```

#### Get Event Log

```go
eventLog, err := mgr.GetEventLog(ctx)
if err != nil {
    log.Fatal(err)
}

log.Printf("Event log contains %d entries", len(eventLog.Entries))
for _, entry := range eventLog.Entries {
    log.Printf("PCR %d, Type %d: %x",
        entry.PCRIndex, entry.EventType, entry.Digest)
}
```

### Host Operations

#### List Hosts

```go
opts := &attestation.ListHostsOptions{
    Status: attestation.StatusTrusted,
    Limit:  100,
    Offset: 0,
}

hosts, err := mgr.ListHosts(ctx, opts)
if err != nil {
    log.Fatal(err)
}

for _, host := range hosts {
    log.Printf("Host %s (%s): %s, %d VMs, %d containers",
        host.HostID, host.Hostname, host.Status,
        host.VMCount, host.ContainerCount)
}
```

#### Get Host Details

```go
host, err := mgr.GetHost(ctx, "host-001")
if err != nil {
    var notFound attestation.ErrHostNotFound
    if errors.As(err, &notFound) {
        log.Printf("Host not found: %s", notFound.HostID)
    }
}

log.Printf("Host: %s, Platform: %s %s, TPM: %s",
    host.Hostname, host.Platform.Manufacturer,
    host.Platform.Model, host.Platform.TPMVersion)
```

### Streaming Operations

#### Stream Attestation Events

```go
opts := &attestation.StreamOptions{
    HostIDs:    []string{"host-001", "host-002"},
    Statuses:   []attestation.AttestationStatus{attestation.StatusUntrusted},
    BufferSize: 100,
}

events, err := mgr.StreamAttestations(ctx, opts)
if err != nil {
    log.Fatal(err)
}

for event := range events {
    log.Printf("Event: %s on host %s at %s - Status: %s",
        event.EventType, event.HostID, event.Timestamp, event.Status)
}
```

## REST API

Base path: `/api/v1/attestation`

### Attestation Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/attestation/quote | Generate fresh attestation quote |
| POST | /api/v1/attestation/verify | Verify attestation quote |
| GET | /api/v1/attestation/manifest | Get host manifest |
| POST | /api/v1/attestation/manifest/push | Push manifest to verifier |
| GET | /api/v1/attestation/hosts | List all hosts |
| GET | /api/v1/attestation/hosts/{id} | Get specific host manifest |
| GET | /api/v1/attestation/pcrs | Get current PCR values |
| GET | /api/v1/attestation/eventlog | Get event log |
| POST | /api/v1/attestation/policy/evaluate | Evaluate attestation policy |
| GET | /api/v1/attestation/status | Get attestation service status |

### Generate Quote

```http
GET /api/v1/attestation/quote?pcrs=0,1,2,3,4,5,6,7
Authorization: Bearer {token}
X-Attestation-Nonce: {base64-encoded-nonce}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pcrs` | string | Comma-separated list of PCR indices |
| `bank` | string | Hash algorithm bank (SHA256, SHA384) |

**Response:**

```json
{
  "data": "base64-encoded-quote-data",
  "signature": "base64-encoded-signature",
  "pcrs": {
    "0": "base64-encoded-pcr-0",
    "1": "base64-encoded-pcr-1",
    "2": "base64-encoded-pcr-2",
    "3": "base64-encoded-pcr-3",
    "4": "base64-encoded-pcr-4",
    "5": "base64-encoded-pcr-5",
    "6": "base64-encoded-pcr-6",
    "7": "base64-encoded-pcr-7"
  },
  "nonce": "base64-encoded-nonce",
  "timestamp": "2025-01-15T10:30:00Z",
  "aik_public": "base64-encoded-aik-public",
  "pcr_bank": "SHA256"
}
```

### Verify Quote

```http
POST /api/v1/attestation/verify
Content-Type: application/json
Authorization: Bearer {token}

{
  "quote": {
    "data": "base64-encoded-quote-data",
    "signature": "base64-encoded-signature",
    "pcrs": {
      "0": "base64-encoded-pcr-0",
      "1": "base64-encoded-pcr-1"
    },
    "nonce": "base64-encoded-nonce",
    "timestamp": "2025-01-15T10:30:00Z",
    "aik_public": "base64-encoded-aik-public"
  },
  "expected_pcrs": {
    "values": {
      "0": "base64-encoded-expected-pcr-0",
      "1": "base64-encoded-expected-pcr-1"
    },
    "bank": "SHA256",
    "tolerance": 0
  },
  "policy_id": "default-policy"
}
```

**Response:**

```json
{
  "valid": true,
  "errors": [],
  "pcr_matches": {
    "0": true,
    "1": true
  },
  "signature_valid": true,
  "nonce_valid": true,
  "policy_result": {
    "passed": true,
    "policy_id": "default-policy",
    "violations": [],
    "timestamp": "2025-01-15T10:30:05Z"
  },
  "timestamp": "2025-01-15T10:30:05Z"
}
```

### Get Manifest

```http
GET /api/v1/attestation/manifest?include_vms=true&include_containers=true
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `include_vms` | bool | Include VM attestations |
| `include_containers` | bool | Include container attestations |
| `pcrs` | string | Comma-separated PCR indices |
| `sign` | bool | Sign the manifest |

**Response:**

```json
{
  "host": {
    "host_id": "host-001",
    "quote": {
      "data": "base64-encoded-quote-data",
      "signature": "base64-encoded-signature",
      "pcrs": {"0": "base64...", "1": "base64..."},
      "nonce": "base64-encoded-nonce",
      "timestamp": "2025-01-15T10:30:00Z"
    },
    "pcrs": {"0": "base64...", "1": "base64..."},
    "platform": {
      "manufacturer": "Dell Inc.",
      "model": "PowerEdge R750",
      "firmware": "2.10.2",
      "tpm_version": "2.0",
      "bios": "1.5.0"
    },
    "status": "Trusted",
    "last_updated": "2025-01-15T10:30:00Z"
  },
  "vms": [
    {
      "vm_id": "vm-001",
      "host_id": "host-001",
      "launch_digest": "base64-encoded-digest",
      "status": "Trusted",
      "runtime": {
        "hypervisor": "KVM",
        "version": "6.1.0",
        "features": ["SEV-SNP", "AMD-V"]
      }
    }
  ],
  "containers": [
    {
      "container_id": "container-001",
      "image_digest": "sha256:abc123...",
      "host_id": "host-001",
      "vm_id": "vm-001",
      "policy_digest": "base64-encoded-digest",
      "status": "Trusted",
      "namespace": "production"
    }
  ],
  "aggregate": {
    "overall": "Trusted",
    "host_status": "Trusted",
    "vm_status": "Trusted",
    "container_status": "Trusted",
    "failure_count": 0,
    "total_count": 3
  },
  "signature": "base64-encoded-signature",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": 1
}
```

### Push Manifest to Verifier

```http
POST /api/v1/attestation/manifest/push
Content-Type: application/json
Authorization: Bearer {token}

{
  "verifier_url": "https://verifier.example.com/api/v1/attestation/manifest",
  "manifest": {
    "host": {...},
    "vms": [...],
    "containers": [...],
    "aggregate": {...},
    "signature": "base64-encoded-signature",
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

**Response:**

```json
{
  "accepted": true,
  "verifier_response": {
    "status": "Verified",
    "timestamp": "2025-01-15T10:30:05Z"
  }
}
```

### List Hosts

```http
GET /api/v1/attestation/hosts?status=Trusted&limit=50&offset=0
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by attestation status |
| `limit` | int | Maximum number of results |
| `offset` | int | Pagination offset |

**Response:**

```json
{
  "hosts": [
    {
      "host_id": "host-001",
      "hostname": "server1.example.com",
      "platform": {
        "manufacturer": "Dell Inc.",
        "model": "PowerEdge R750",
        "tpm_version": "2.0"
      },
      "last_seen": "2025-01-15T10:30:00Z",
      "status": "Trusted",
      "vm_count": 5,
      "container_count": 12
    },
    {
      "host_id": "host-002",
      "hostname": "server2.example.com",
      "platform": {
        "manufacturer": "HPE",
        "model": "ProLiant DL380",
        "tpm_version": "2.0"
      },
      "last_seen": "2025-01-15T10:29:00Z",
      "status": "Trusted",
      "vm_count": 3,
      "container_count": 8
    }
  ],
  "total": 2
}
```

### Get Host

```http
GET /api/v1/attestation/hosts/{id}
Authorization: Bearer {token}
```

**Response:**

```json
{
  "host_id": "host-001",
  "hostname": "server1.example.com",
  "platform": {
    "manufacturer": "Dell Inc.",
    "model": "PowerEdge R750",
    "firmware": "2.10.2",
    "tpm_version": "2.0",
    "bios": "1.5.0"
  },
  "last_seen": "2025-01-15T10:30:00Z",
  "status": "Trusted",
  "vm_count": 5,
  "container_count": 12,
  "manifest": {
    "host": {...},
    "vms": [...],
    "containers": [...],
    "aggregate": {...}
  }
}
```

### Get PCR Values

```http
GET /api/v1/attestation/pcrs?pcrs=0,1,2,3,4,5,6,7&bank=SHA256
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `pcrs` | string | Comma-separated list of PCR indices |
| `bank` | string | Hash algorithm bank (SHA256, SHA384) |

**Response:**

```json
{
  "pcrs": {
    "0": "base64-encoded-pcr-0",
    "1": "base64-encoded-pcr-1",
    "2": "base64-encoded-pcr-2",
    "3": "base64-encoded-pcr-3",
    "4": "base64-encoded-pcr-4",
    "5": "base64-encoded-pcr-5",
    "6": "base64-encoded-pcr-6",
    "7": "base64-encoded-pcr-7"
  },
  "bank": "SHA256",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### Get Event Log

```http
GET /api/v1/attestation/eventlog?limit=100&pcr=0
Authorization: Bearer {token}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Maximum number of entries |
| `offset` | int | Pagination offset |
| `pcr` | int | Filter by PCR index |

**Response:**

```json
{
  "entries": [
    {
      "pcr_index": 0,
      "event_type": 7,
      "digest": "base64-encoded-digest",
      "data": "base64-encoded-data",
      "timestamp": "2025-01-15T08:00:00Z"
    },
    {
      "pcr_index": 0,
      "event_type": 1,
      "digest": "base64-encoded-digest",
      "data": "base64-encoded-data",
      "timestamp": "2025-01-15T08:00:01Z"
    }
  ],
  "algorithm": "SHA256",
  "total": 2
}
```

### Evaluate Policy

```http
POST /api/v1/attestation/policy/evaluate
Content-Type: application/json
Authorization: Bearer {token}

{
  "attestation": {
    "quote": {...},
    "manifest": {...},
    "host_id": "host-001"
  },
  "policy_id": "strict-policy"
}
```

**Response:**

```json
{
  "passed": false,
  "policy_id": "strict-policy",
  "violations": [
    {
      "rule": "pcr7_secure_boot",
      "expected": "base64-expected-value",
      "actual": "base64-actual-value",
      "severity": "critical",
      "description": "Secure Boot PCR value does not match expected golden value"
    }
  ],
  "timestamp": "2025-01-15T10:30:05Z"
}
```

### Get Service Status

```http
GET /api/v1/attestation/status
Authorization: Bearer {token}
```

**Response:**

```json
{
  "available": true,
  "tpm": {
    "available": true,
    "device": "/dev/tpmrm0",
    "version": "2.0",
    "manufacturer": "STMicroelectronics"
  },
  "hosts_monitored": 25,
  "trusted_hosts": 24,
  "untrusted_hosts": 1,
  "pending_hosts": 0,
  "last_attestation": "2025-01-15T10:30:00Z"
}
```

## gRPC API

Service: `trustedplatform.attestation.v1.AttestationService`

### Service Definition

```protobuf
syntax = "proto3";

package trustedplatform.attestation.v1;

service AttestationService {
    // Quote Operations
    rpc GenerateQuote(QuoteRequest) returns (QuoteResponse);
    rpc VerifyQuote(VerifyRequest) returns (VerifyResponse);

    // Manifest Operations
    rpc GetManifest(ManifestRequest) returns (ManifestResponse);
    rpc PushManifest(PushRequest) returns (PushResponse);

    // Host Operations
    rpc ListHosts(ListHostsRequest) returns (ListHostsResponse);
    rpc GetHost(GetHostRequest) returns (GetHostResponse);

    // PCR Operations
    rpc GetPCRValues(GetPCRValuesRequest) returns (GetPCRValuesResponse);
    rpc GetEventLog(GetEventLogRequest) returns (GetEventLogResponse);

    // Policy Operations
    rpc EvaluatePolicy(EvaluatePolicyRequest) returns (EvaluatePolicyResponse);

    // Streaming
    rpc StreamAttestations(StreamRequest) returns (stream AttestationEvent);

    // Status
    rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
}
```

### Message Definitions

#### Quote Messages

```protobuf
message QuoteRequest {
    bytes nonce = 1;                    // Challenge nonce (32 bytes)
    repeated int32 pcrs = 2;            // PCR indices to include
    string bank = 3;                    // Hash algorithm bank (SHA256, SHA384)
}

message QuoteResponse {
    bytes data = 1;                     // TPM quote data structure
    bytes signature = 2;                // TPM signature over quote
    map<int32, bytes> pcrs = 3;         // PCR values included in quote
    bytes nonce = 4;                    // Challenge nonce
    google.protobuf.Timestamp timestamp = 5; // Quote generation timestamp
    bytes aik_public = 6;               // Attestation Identity Key public portion
    string pcr_bank = 7;                // Hash algorithm bank
}

message VerifyRequest {
    QuoteResponse quote = 1;            // Quote to verify
    ExpectedPCRs expected_pcrs = 2;     // Expected PCR values
    string policy_id = 3;               // Optional policy to evaluate
}

message VerifyResponse {
    bool valid = 1;                     // Overall verification result
    repeated string errors = 2;         // Verification error messages
    map<int32, bool> pcr_matches = 3;   // Per-PCR match results
    bool signature_valid = 4;           // Quote signature validity
    bool nonce_valid = 5;               // Nonce freshness check
    PolicyResult policy_result = 6;     // Policy evaluation result
    google.protobuf.Timestamp timestamp = 7; // Verification timestamp
}

message ExpectedPCRs {
    map<int32, bytes> values = 1;       // Expected PCR values
    string bank = 2;                    // Hash algorithm bank
    int32 tolerance = 3;                // Number of allowed mismatches
}
```

#### Manifest Messages

```protobuf
message ManifestRequest {
    bool include_vms = 1;               // Include VM attestations
    bool include_containers = 2;        // Include container attestations
    repeated int32 pcrs = 3;            // PCRs to include
    string policy_id = 4;               // Policy to evaluate against
    bool sign_manifest = 5;             // Sign the manifest
}

message ManifestResponse {
    HostAttestation host = 1;           // Host-level attestation
    repeated VMAttestation vms = 2;     // Virtual machine attestations
    repeated ContainerAttestation containers = 3; // Container attestations
    AggregateStatus aggregate = 4;      // Combined status
    bytes signature = 5;                // Manifest signature
    google.protobuf.Timestamp timestamp = 6; // Generation timestamp
    int32 version = 7;                  // Manifest version
}

message PushRequest {
    string verifier_url = 1;            // Verifier endpoint URL
    ManifestResponse manifest = 2;      // Manifest to push
}

message PushResponse {
    bool accepted = 1;                  // Verifier accepted the manifest
    string verifier_status = 2;         // Verifier response status
    google.protobuf.Timestamp timestamp = 3; // Response timestamp
}

message HostAttestation {
    string host_id = 1;                 // Unique host identifier
    QuoteResponse quote = 2;            // TPM quote
    map<int32, bytes> pcrs = 3;         // Current PCR values
    EventLog event_log = 4;             // Measured boot event log
    PlatformInfo platform = 5;          // Platform identification
    AttestationStatus status = 6;       // Attestation status
    google.protobuf.Timestamp last_updated = 7; // Last attestation time
}

message VMAttestation {
    string vm_id = 1;                   // Virtual machine ID
    string host_id = 2;                 // Parent host ID
    QuoteResponse quote = 3;            // VM-specific quote (if available)
    bytes launch_digest = 4;            // Expected launch measurement
    AttestationStatus status = 5;       // Attestation status
    RuntimeInfo runtime = 6;            // Runtime environment info
}

message ContainerAttestation {
    string container_id = 1;            // Container ID
    string image_digest = 2;            // Container image digest
    string host_id = 3;                 // Parent host ID
    string vm_id = 4;                   // Parent VM ID (if applicable)
    bytes policy_digest = 5;            // Applied policy digest
    AttestationStatus status = 6;       // Attestation status
    string namespace = 7;               // Kubernetes namespace
}

message AggregateStatus {
    AttestationStatus overall = 1;      // Overall status
    AttestationStatus host_status = 2;  // Host attestation status
    AttestationStatus vm_status = 3;    // Aggregate VM status
    AttestationStatus container_status = 4; // Aggregate container status
    int32 failure_count = 5;            // Number of failed attestations
    int32 total_count = 6;              // Total attestation count
}
```

#### Host Messages

```protobuf
message ListHostsRequest {
    AttestationStatus status = 1;       // Filter by status
    int32 limit = 2;                    // Max results
    int32 offset = 3;                   // Pagination offset
}

message ListHostsResponse {
    repeated HostInfo hosts = 1;        // List of hosts
    int32 total = 2;                    // Total count
}

message GetHostRequest {
    string host_id = 1;                 // Host identifier
}

message GetHostResponse {
    HostInfo host = 1;                  // Host information
    ManifestResponse manifest = 2;      // Latest manifest
}

message HostInfo {
    string host_id = 1;                 // Unique host identifier
    string hostname = 2;                // Host DNS name
    PlatformInfo platform = 3;          // Platform information
    google.protobuf.Timestamp last_seen = 4; // Last attestation time
    AttestationStatus status = 5;       // Current status
    int32 vm_count = 6;                 // Number of VMs
    int32 container_count = 7;          // Number of containers
}

message PlatformInfo {
    string manufacturer = 1;            // Platform manufacturer
    string model = 2;                   // Platform model
    string firmware = 3;                // Firmware version
    string tpm_version = 4;             // TPM version
    string bios = 5;                    // BIOS version
}

message RuntimeInfo {
    string hypervisor = 1;              // Hypervisor type
    string version = 2;                 // Runtime version
    repeated string features = 3;       // Enabled features
}
```

#### PCR and Event Log Messages

```protobuf
message GetPCRValuesRequest {
    repeated int32 pcrs = 1;            // PCR indices to retrieve
    string bank = 2;                    // Hash algorithm bank
}

message GetPCRValuesResponse {
    map<int32, bytes> pcrs = 1;         // PCR values
    string bank = 2;                    // Hash algorithm bank
    google.protobuf.Timestamp timestamp = 3; // Read timestamp
}

message GetEventLogRequest {
    int32 limit = 1;                    // Maximum number of entries
    int32 offset = 2;                   // Pagination offset
    int32 pcr_filter = 3;               // Filter by PCR index (-1 for all)
}

message GetEventLogResponse {
    repeated EventLogEntry entries = 1; // Log entries
    string algorithm = 2;               // Hash algorithm
    int32 total = 3;                    // Total entry count
}

message EventLog {
    repeated EventLogEntry entries = 1; // Log entries
    string algorithm = 2;               // Hash algorithm
    int32 pcr_index = 3;                // Associated PCR
}

message EventLogEntry {
    int32 pcr_index = 1;                // PCR this event extends
    uint32 event_type = 2;              // Event type code
    bytes digest = 3;                   // Event digest
    bytes data = 4;                     // Event data
    google.protobuf.Timestamp timestamp = 5; // Event timestamp
}
```

#### Policy Messages

```protobuf
message EvaluatePolicyRequest {
    Attestation attestation = 1;        // Attestation data
    string policy_id = 2;               // Policy to evaluate
}

message EvaluatePolicyResponse {
    bool passed = 1;                    // Policy evaluation passed
    string policy_id = 2;               // Evaluated policy identifier
    repeated PolicyViolation violations = 3; // Policy violations found
    google.protobuf.Timestamp timestamp = 4; // Evaluation timestamp
}

message PolicyResult {
    bool passed = 1;                    // Policy evaluation passed
    string policy_id = 2;               // Evaluated policy identifier
    repeated PolicyViolation violations = 3; // Policy violations found
    google.protobuf.Timestamp timestamp = 4; // Evaluation timestamp
}

message PolicyViolation {
    string rule = 1;                    // Violated rule name
    string expected = 2;                // Expected value
    string actual = 3;                  // Actual value
    string severity = 4;                // Violation severity
    string description = 5;             // Human-readable description
}

message Attestation {
    QuoteResponse quote = 1;            // TPM quote
    ManifestResponse manifest = 2;      // Host manifest
    string host_id = 3;                 // Host identifier
}
```

#### Streaming Messages

```protobuf
message StreamRequest {
    repeated string host_ids = 1;       // Filter by host IDs
    repeated AttestationStatus statuses = 2; // Filter by status
    int32 buffer_size = 3;              // Event buffer size
}

message AttestationEvent {
    string event_type = 1;              // Event type
    string host_id = 2;                 // Affected host
    google.protobuf.Timestamp timestamp = 3; // Event timestamp
    AttestationStatus status = 4;       // New status
    map<string, string> details = 5;    // Additional details
}
```

#### Status Messages

```protobuf
message GetStatusRequest {}

message GetStatusResponse {
    bool available = 1;                 // Service availability
    TPMStatus tpm = 2;                  // TPM status
    int32 hosts_monitored = 3;          // Total hosts monitored
    int32 trusted_hosts = 4;            // Trusted host count
    int32 untrusted_hosts = 5;          // Untrusted host count
    int32 pending_hosts = 6;            // Pending host count
    google.protobuf.Timestamp last_attestation = 7; // Last attestation time
}

message TPMStatus {
    bool available = 1;                 // TPM availability
    string device = 2;                  // TPM device path
    string version = 3;                 // TPM version
    string manufacturer = 4;            // TPM manufacturer
}
```

#### Enums

```protobuf
enum AttestationStatus {
    ATTESTATION_STATUS_UNSPECIFIED = 0;
    ATTESTATION_STATUS_TRUSTED = 1;
    ATTESTATION_STATUS_UNTRUSTED = 2;
    ATTESTATION_STATUS_PENDING = 3;
    ATTESTATION_STATUS_EXPIRED = 4;
    ATTESTATION_STATUS_UNKNOWN = 5;
}
```

## Error Codes

| Error Type | HTTP Code | gRPC Code | Description |
|------------|-----------|-----------|-------------|
| `ErrQuoteVerificationFailed` | 400 | INVALID_ARGUMENT | Quote verification failed |
| `ErrPCRMismatch` | 400 | INVALID_ARGUMENT | PCR values do not match expected |
| `ErrNonceExpired` | 400 | DEADLINE_EXCEEDED | Nonce has expired |
| `ErrPolicyViolation` | 403 | PERMISSION_DENIED | Policy evaluation failed |
| `ErrInvalidQuote` | 400 | INVALID_ARGUMENT | Invalid quote format |
| `ErrInvalidSignature` | 400 | INVALID_ARGUMENT | Quote signature verification failed |
| `ErrHostNotFound` | 404 | NOT_FOUND | Host not found |
| `ErrManifestExpired` | 410 | FAILED_PRECONDITION | Manifest has expired |
| `ErrTPMUnavailable` | 503 | UNAVAILABLE | TPM device unavailable |
| `ErrEventLogInvalid` | 400 | INVALID_ARGUMENT | Event log validation failed |
| `ErrPolicyNotFound` | 404 | NOT_FOUND | Policy not found |
| `ErrStreamClosed` | 500 | CANCELLED | Attestation stream closed |
| `ErrUnauthorized` | 401 | UNAUTHENTICATED | Authentication required |
| `ErrForbidden` | 403 | PERMISSION_DENIED | Insufficient permissions |
| `ErrInternal` | 500 | INTERNAL | Internal server error |

## Authentication

### mTLS Authentication

All API requests require mutual TLS authentication using client certificates issued by the platform CA.

```http
# Certificate-based authentication
curl --cert client.crt --key client.key --cacert ca.crt \
  https://attestation.example.com/api/v1/attestation/quote
```

### API Key Authentication

For programmatic access, API keys can be used in conjunction with TLS:

```http
GET /api/v1/attestation/quote
Authorization: Bearer {api-key}
X-API-Key: {api-key}
```

### JWT Token Authentication

OAuth 2.0 / OpenID Connect tokens are supported for service-to-service communication:

```http
GET /api/v1/attestation/quote
Authorization: Bearer {jwt-token}
```

### gRPC Authentication

For gRPC, authentication is handled via call credentials:

```go
import "google.golang.org/grpc/credentials"

// mTLS credentials
creds, err := credentials.NewClientTLSFromFile("ca.crt", "attestation.example.com")
if err != nil {
    log.Fatal(err)
}

conn, err := grpc.Dial("attestation.example.com:443",
    grpc.WithTransportCredentials(creds),
    grpc.WithPerRPCCredentials(apiKeyCredentials{key: "api-key"}))
```

## Rate Limits

API rate limits are enforced per client certificate or API key:

| Endpoint Category | Rate Limit | Burst Limit |
|-------------------|------------|-------------|
| Quote Generation | 10/minute | 20 |
| Quote Verification | 100/minute | 200 |
| Manifest Operations | 30/minute | 60 |
| Host Queries | 100/minute | 200 |
| PCR/Event Log Reads | 60/minute | 120 |
| Policy Evaluation | 50/minute | 100 |
| Streaming | 5 concurrent streams | - |

### Rate Limit Headers

Rate limit information is included in response headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312800
```

### Rate Limit Exceeded Response

When rate limits are exceeded, the API returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Please retry after 60 seconds.",
  "retry_after": 60
}
```

### gRPC Rate Limiting

For gRPC, rate limit exceeded returns `RESOURCE_EXHAUSTED` status:

```
status: RESOURCE_EXHAUSTED
message: "Rate limit exceeded. Retry after 60 seconds."
```

## Related Documentation

- [Workload Attestation](workload-attestation.md) - PCR 14 workload chain for containers and VMs
- [VM Attestation](vm-attestation.md) - vTPM EK certification and VM quotes
- [Manifest](manifest.md) - Host manifest structure, signing, and verification
- [Push](push.md) - Push infrastructure, triggers, and transports
