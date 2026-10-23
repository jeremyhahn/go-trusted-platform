# Push Infrastructure

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `pkg/attestation/push` client and scheduler API; [architecture.md](architecture.md) is normative.

The push subsystem distributes signed host manifests to remote verification services. It supports multiple transports, authentication methods, and trigger modes with built-in retry logic.

## Overview

The push infrastructure enables hosts to proactively send attestation manifests to verification services rather than waiting for queries. This supports continuous attestation models where trust state is constantly monitored.

Package: `pkg/attestation/push/`

## Key Types

### TransportType

Represents the transport protocol for pushing attestations.

```go
type TransportType string

const (
    TransportHTTP TransportType = "http"
    TransportGRPC TransportType = "grpc"
)
```

### TriggerType

Represents when a push operation should be triggered.

```go
type TriggerType string

const (
    TriggerPeriodic TriggerType = "periodic"  // Push at regular intervals
    TriggerOnChange TriggerType = "on-change" // Push when manifest changes
    TriggerManual   TriggerType = "manual"    // Push on explicit request
)
```

### PushStatus

Represents the status of a push operation.

```go
type PushStatus string

const (
    PushStatusPending   PushStatus = "pending"
    PushStatusInFlight  PushStatus = "in-flight"
    PushStatusSuccess   PushStatus = "success"
    PushStatusFailed    PushStatus = "failed"
    PushStatusRetrying  PushStatus = "retrying"
    PushStatusCanceled  PushStatus = "canceled"
    PushStatusSkipped   PushStatus = "skipped"
)
```

### PushTarget

Represents a destination endpoint for attestation pushes.

```go
type PushTarget struct {
    ID        string            // Unique identifier
    Name      string            // Human-readable name
    Endpoint  string            // URL of target service
    Transport TransportType     // Transport protocol
    Auth      *AuthConfig       // Authentication configuration
    Enabled   bool              // Whether target is active
    Headers   map[string]string // Additional HTTP headers
    Timeout   time.Duration     // Request timeout
    Metadata  map[string]string // Target-specific metadata
}
```

### AuthConfig

Contains authentication configuration for a push target.

```go
type AuthConfig struct {
    Type       string      // Auth type: bearer, mtls, basic
    Token      string      // Bearer token
    Username   string      // Basic auth username
    Password   string      // Basic auth password
    ClientCert string      // Path to client certificate (mTLS)
    ClientKey  string      // Path to client private key (mTLS)
    CACert     string      // Path to CA certificate
    TLSConfig  *tls.Config // Pre-configured TLS
}
```

### RetryConfig

Contains configuration for retry logic.

```go
type RetryConfig struct {
    MaxAttempts          int           // Maximum retry attempts
    InitialBackoff       time.Duration // Initial backoff duration
    MaxBackoff           time.Duration // Maximum backoff duration
    BackoffMultiplier    float64       // Backoff multiplier
    RetryableStatusCodes []int         // HTTP codes to retry
}
```

### PushResult

Represents the outcome of a push operation to a single target.

```go
type PushResult struct {
    TargetID    string            // Target ID
    Endpoint    string            // Target endpoint
    Status      PushStatus        // Push status
    StatusCode  int               // HTTP status code
    Attempts    int               // Number of attempts
    StartedAt   time.Time         // When started
    CompletedAt time.Time         // When completed
    Duration    time.Duration     // Total time taken
    BytesSent   int64             // Bytes sent
    Error       error             // Any error
    Response    []byte            // Response body
    Metadata    map[string]string // Result metadata
}
```

### PushBatchResult

Represents results of pushing to multiple targets.

```go
type PushBatchResult struct {
    ManifestID   string        // Manifest ID pushed
    Results      []*PushResult // Per-target results
    StartedAt    time.Time     // Batch start time
    CompletedAt  time.Time     // Batch completion time
    Duration     time.Duration // Total duration
    TotalTargets int           // Number of targets
    SuccessCount int           // Successful pushes
    FailureCount int           // Failed pushes
    SkippedCount int           // Skipped pushes
}
```

## Client API

### Client

Handles pushing attestation manifests to remote targets.

```go
// Create client
client, err := push.NewClient(config,
    push.WithTLSConfig(tlsConfig),
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Push to single target
result, err := client.Push(ctx, target, request)
if err != nil {
    log.Fatal(err)
}

// Push to multiple targets
batchResult, err := client.PushBatch(ctx, targets, request)
if err != nil {
    log.Fatal(err)
}
```

### Client Configuration

```go
type ClientConfig struct {
    DefaultTimeout      time.Duration // Default request timeout
    TLSConfig           *tls.Config   // Default TLS configuration
    UserAgent           string        // User-Agent header
    Retry               *RetryConfig  // Retry configuration
    MaxIdleConns        int           // Max idle connections
    MaxIdleConnsPerHost int           // Max idle per host
    IdleConnTimeout     time.Duration // Idle connection timeout
}
```

### Default Client Configuration

```go
cfg := push.DefaultClientConfig()
// Returns:
// - DefaultTimeout: 30s
// - UserAgent: "go-trusted-platform/1.0"
// - MaxIdleConns: 100
// - MaxIdleConnsPerHost: 10
// - IdleConnTimeout: 90s
// - Retry: DefaultRetryConfig()
```

## Scheduler API

### Scheduler

Manages scheduled and triggered push operations.

```go
type Scheduler struct {
    // ... internal fields
}
```

Methods:

```go
// Start the scheduler
func (s *Scheduler) Start(ctx context.Context) error

// Stop the scheduler
func (s *Scheduler) Stop() error

// Trigger an immediate push
func (s *Scheduler) TriggerPush() error

// Notify that the manifest has changed (for on-change triggers)
func (s *Scheduler) NotifyChange()

// Check if scheduler is running
func (s *Scheduler) IsRunning() bool

// Get scheduler statistics
func (s *Scheduler) Stats() SchedulerStats

// Set push result handler
func (s *Scheduler) SetHandler(h PushHandler)

// Update targets
func (s *Scheduler) SetTargets(targets []*PushTarget)
```

### ManifestProvider

Interface for providing manifest data to the scheduler.

```go
type ManifestProvider interface {
    // GetCurrentManifest returns the current manifest payload.
    GetCurrentManifest(ctx context.Context) (*PushRequest, error)

    // HasChanged returns true if manifest changed since last push.
    HasChanged() bool

    // MarkPushed marks the manifest as pushed.
    MarkPushed()
}
```

### SchedulerStats

Contains scheduler statistics.

```go
type SchedulerStats struct {
    PushCount    uint64    // Total push operations
    SuccessCount uint64    // Successful pushes
    FailureCount uint64    // Failed pushes
    LastPushTime time.Time // Time of last push
    IsRunning    bool      // Scheduler running status
}
```

## Usage

### Basic Push

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/push"

// Create client
config := push.DefaultClientConfig()
client, err := push.NewClient(config)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Define target
target := &push.PushTarget{
    ID:        "verifier-1",
    Name:      "Primary Verifier",
    Endpoint:  "https://verifier.example.com/attestation",
    Transport: push.TransportHTTP,
    Enabled:   true,
    Auth: &push.AuthConfig{
        Type:  "bearer",
        Token: "secret-token",
    },
}

// Create push request
request := &push.PushRequest{
    ManifestID:  manifest.ID,
    Payload:     manifestBytes,
    ContentType: "application/json",
    Metadata:    map[string]string{"version": "1.0"},
}

// Push
result, err := client.Push(ctx, target, request)
if err != nil {
    log.Fatal(err)
}

if result.Success() {
    fmt.Printf("Push succeeded in %v\n", result.Duration)
} else {
    fmt.Printf("Push failed: %v\n", result.Error)
}
```

### Batch Push

```go
targets := []*push.PushTarget{
    {ID: "verifier-1", Endpoint: "https://v1.example.com", Transport: push.TransportHTTP, Enabled: true},
    {ID: "verifier-2", Endpoint: "https://v2.example.com", Transport: push.TransportHTTP, Enabled: true},
    {ID: "verifier-3", Endpoint: "https://v3.example.com", Transport: push.TransportHTTP, Enabled: false},
}

result, err := client.PushBatch(ctx, targets, request)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Pushed to %d targets: %d success, %d failed, %d skipped\n",
    result.TotalTargets, result.SuccessCount, result.FailureCount, result.SkippedCount)

if result.AllSuccess() {
    fmt.Println("All targets updated successfully")
}
```

### Using the Scheduler

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/push"

// Create scheduler configuration
schedulerCfg := &push.SchedulerConfig{
    TriggerType:         push.TriggerPeriodic,
    PushInterval:        5 * time.Minute,
    MaxConcurrentPushes: 10,
    OnChangeDebounce:    time.Second,
}

// Create client and targets
client, _ := push.NewClient(push.DefaultClientConfig())
targets := []*push.PushTarget{
    {ID: "v1", Endpoint: "https://v1.example.com", Transport: push.TransportHTTP, Enabled: true},
}

// Create manifest provider
provider := push.NewSimpleManifestProvider("application/json")

// Create scheduler
scheduler, err := push.NewScheduler(schedulerCfg, client, targets,
    push.WithManifestProvider(provider),
    push.WithHandler(func(result *push.PushBatchResult) {
        fmt.Printf("Push completed: %d success, %d failed\n",
            result.SuccessCount, result.FailureCount)
    }),
)
if err != nil {
    log.Fatal(err)
}

// Start scheduler
if err := scheduler.Start(ctx); err != nil {
    log.Fatal(err)
}

// Update manifest when it changes
provider.SetManifest("manifest-001", manifestBytes)

// For on-change triggers, notify the scheduler
scheduler.NotifyChange()

// Trigger immediate push
scheduler.TriggerPush()

// Get stats
stats := scheduler.Stats()
fmt.Printf("Total pushes: %d, Success: %d, Failures: %d\n",
    stats.PushCount, stats.SuccessCount, stats.FailureCount)

// Stop scheduler
scheduler.Stop()
```

### mTLS Authentication

```go
target := &push.PushTarget{
    ID:        "secure-verifier",
    Endpoint:  "https://secure.example.com/attestation",
    Transport: push.TransportHTTP,
    Enabled:   true,
    Auth: &push.AuthConfig{
        Type:       "mtls",
        ClientCert: "/path/to/client.crt",
        ClientKey:  "/path/to/client.key",
        CACert:     "/path/to/ca.crt",
    },
}
```

### gRPC Transport

The gRPC dial always uses TLS (#32 — attestation evidence never travels
plaintext). Credential precedence: target-level TLS material — a pre-built
`Auth.TLSConfig`, `Auth.CACert`, or an mTLS `Auth.ClientCert`/`Auth.ClientKey`
pair (the client certificate is loaded even when server verification uses
system roots) — then the client-level TLS configuration (the `WithTLSConfig`
option or `ClientConfig.TLSConfig`), and finally a standard TLS configuration
verifying against system roots. There is no insecure fallback.

```go
target := &push.PushTarget{
    ID:        "grpc-verifier",
    Endpoint:  "grpc.example.com:9443",
    Transport: push.TransportGRPC,
    Enabled:   true,
    Auth: &push.AuthConfig{
        Type:  "bearer",
        Token: "grpc-token",
    },
}
```

## Retry Configuration

### Default Retry Config

```go
cfg := push.DefaultRetryConfig()
// Returns:
// - MaxAttempts: 3
// - InitialBackoff: 100ms
// - MaxBackoff: 10s
// - BackoffMultiplier: 2.0
// - RetryableStatusCodes: [408, 429, 500, 502, 503, 504]
```

### Exponential Backoff

The retry system uses exponential backoff:

| Attempt | Backoff (2.0x multiplier) |
|---------|---------------------------|
| 1       | 100ms                     |
| 2       | 200ms                     |
| 3       | 400ms                     |
| 4       | 800ms                     |
| 5       | 1.6s                      |
| ...     | up to MaxBackoff          |

### Retryable Conditions

Retryable:
- Network errors (target unreachable)
- HTTP 408 (Request Timeout)
- HTTP 429 (Too Many Requests)
- HTTP 500-504 (Server errors)

Not retryable:
- HTTP 401/403 (Authentication failures)
- HTTP 400-level client errors
- Invalid target configuration

## Configuration

### PushConfig

Complete push configuration for the platform.

```go
type PushConfig struct {
    Targets             []*PushTarget // Push targets
    Retry               *RetryConfig  // Retry configuration
    DefaultTimeout      time.Duration // Default timeout
    DefaultTransport    TransportType // Default transport
    TriggerType         TriggerType   // When to push
    PushInterval        time.Duration // Interval for periodic
    MaxConcurrentPushes int           // Max concurrent pushes
    FailFast            bool          // Stop on first failure
}
```

### SchedulerConfig

```go
type SchedulerConfig struct {
    TriggerType         TriggerType   // Trigger mode
    PushInterval        time.Duration // Periodic interval
    MaxConcurrentPushes int           // Concurrency limit
    FailFast            bool          // Stop on first failure
    OnChangeDebounce    time.Duration // Debounce for on-change
}
```

### Default Configurations

```go
// Push config defaults
pushCfg := push.DefaultPushConfig()
// - DefaultTimeout: 30s
// - DefaultTransport: http
// - TriggerType: periodic
// - PushInterval: 5m
// - MaxConcurrentPushes: 10
// - FailFast: false

// Scheduler config defaults
schedCfg := push.DefaultSchedulerConfig()
// - TriggerType: periodic
// - PushInterval: 5m
// - MaxConcurrentPushes: 10
// - OnChangeDebounce: 1s
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrPushFailed` | Push operation failed |
| `ErrTargetUnreachable` | Cannot reach target |
| `ErrAuthFailed` | Authentication failed |
| `ErrRetryExhausted` | All retry attempts failed |
| `ErrInvalidTarget` | Invalid target configuration |
| `ErrInvalidConfig` | Invalid configuration |
| `ErrClientNotInitialized` | Client not initialized |
| `ErrClientClosed` | Client has been closed |
| `ErrSchedulerNotInitialized` | Scheduler not initialized |
| `ErrSchedulerStopped` | Scheduler has been stopped |
| `ErrSchedulerAlreadyRunning` | Scheduler already running |
| `ErrNoTargetsConfigured` | No targets configured |
| `ErrTargetNotFound` | Target not found |
| `ErrSerializationFailed` | Manifest serialization failed |
| `ErrTransportNotSupported` | Transport type not supported |
| `ErrTLSConfigFailed` | TLS configuration failed |
| `ErrInvalidResponse` | Invalid server response |
| `ErrContextCanceled` | Operation canceled |

## Related Documentation

- [Manifest](manifest.md) - Building manifests to push
- [Workload Attestation](workload-attestation.md) - Container attestation
- [VM Attestation](vm-attestation.md) - VM attestation
- [API Reference](api.md) - REST/gRPC APIs
