# Go SDK Guide

The Go SDK provides a native Go client for the Trusted Platform daemon with support for all five protocols: Unix Socket, gRPC, REST, QUIC, and MCP.

## Installation

```bash
go get github.com/jeremyhahn/go-trusted-platform/sdk/go/platform
```

Import the package:

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"

    // Import transport packages to register protocol adapters
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Create client with automatic protocol selection
    // Load platform CA certificate for TLS verification
    caPool := loadCACertPool("/path/to/ca.crt")

    client, err := platform.NewClient(ctx,
        platform.WithGRPCAddr("localhost:10443"),
        platform.WithTLSConfig(&tls.Config{
            MinVersion: tls.VersionTLS13,
            RootCAs:    caPool,
        }),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.Close()

    // Check connectivity
    if err := client.Ping(ctx); err != nil {
        log.Fatalf("Ping failed: %v", err)
    }

    // Get platform version
    version, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }

    log.Printf("Platform version: %s", version.Version)
}
```

## Multi-Protocol Configuration

### Unix Socket (Fastest, Local Only)

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"

client, err := platform.NewClient(ctx,
    platform.WithUnixSocket("/run/platformd.sock"),
    platform.WithOnlyProtocol(platform.ProtocolUnix),
)
```

**Requirements:** Must run as root.

### gRPC over TCP

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"

client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithTLSConfig(&tls.Config{
        RootCAs:    certPool,
        MinVersion: tls.VersionTLS13,
    }),
)
```

### REST over HTTPS

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"

client, err := platform.NewClient(ctx,
    platform.WithRESTAddr("https://platform.example.com:8443"),
    platform.WithOnlyProtocol(platform.ProtocolREST),
)
```

### QUIC over UDP

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"

client, err := platform.NewClient(ctx,
    platform.WithQUICAddr("platform.example.com:9444"),
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
)
```

### MCP (AI/LLM Integration)

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"

client, err := platform.NewClient(ctx,
    platform.WithMCPAddr("https://platform.example.com:9445"),
    platform.WithOnlyProtocol(platform.ProtocolMCP),
)
```

### Protocol Fallback

```go
// Try gRPC first, fall back to REST
client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithRESTAddr("platform.example.com:8443"),
    platform.WithPreferredProtocol(platform.ProtocolGRPC),
)

// Check which protocol was used
log.Printf("Connected via: %s", client.Protocol())
```

## Service Client Usage

### Certificate Authority

```go
// Get CA information
info, err := client.CA().GetInfo(ctx, &platformv1.GetCAInfoRequest{})
if err != nil {
    log.Fatalf("Failed to get CA info: %v", err)
}
log.Printf("CA: %s, Valid until: %s", info.Subject, info.NotAfter)

// Issue a certificate
cert, err := client.CA().Issue(ctx, &platformv1.IssueCertificateRequest{
    CommonName:   "server.example.com",
    Organization: []string{"Example Corp"},
    DnsNames:     []string{"server.example.com", "localhost"},
    ValidDays:    365,
})
if err != nil {
    log.Fatalf("Failed to issue certificate: %v", err)
}
log.Printf("Issued certificate: %s", cert.Serial)

// Revoke a certificate
_, err = client.CA().Revoke(ctx, &platformv1.RevokeCertificateRequest{
    Serial: cert.Serial,
    Reason: platformv1.RevocationReason_KEY_COMPROMISE,
})
```

### TPM Operations

```go
// Get TPM information
info, err := client.TPM().GetInfo(ctx, &platformv1.GetTPMInfoRequest{})
if err != nil {
    log.Fatalf("Failed to get TPM info: %v", err)
}
log.Printf("TPM Manufacturer: %s, Version: %s", info.Manufacturer, info.FirmwareVersion)

// Seal data to TPM
sealed, err := client.TPM().Seal(ctx, &platformv1.SealRequest{
    Data:       []byte("secret-data"),
    PcrIndices: []int32{0, 1, 7},
})
if err != nil {
    log.Fatalf("Failed to seal: %v", err)
}

// Unseal data
unsealed, err := client.TPM().Unseal(ctx, &platformv1.UnsealRequest{
    SealedData: sealed.SealedData,
})
```

### Virtual TPM Management

```go
// Create a vTPM instance
vtpm, err := client.VTPM().Create(ctx, &platformv1.CreateVTPMRequest{
    Name:        "vm-001-vtpm",
    EkAlgorithm: platformv1.Algorithm_RSA2048,
})
if err != nil {
    log.Fatalf("Failed to create vTPM: %v", err)
}
log.Printf("Created vTPM: %s", vtpm.Id)

// Start the vTPM
_, err = client.VTPM().Start(ctx, &platformv1.StartVTPMRequest{
    Id: vtpm.Id,
})

// List all vTPMs
list, err := client.VTPM().List(ctx, &platformv1.ListVTPMRequest{})
for _, v := range list.Vtpms {
    log.Printf("vTPM: %s, State: %s", v.Name, v.State)
}
```

### IAM Operations

```go
// Authenticate user
auth, err := client.IAM().Authenticate(ctx, &platformv1.AuthenticateRequest{
    Username: "admin",
    Password: "secure-password",
})
if err != nil {
    log.Fatalf("Authentication failed: %v", err)
}
log.Printf("Token: %s", auth.Token)

// Create a user
user, err := client.IAM().CreateUser(ctx, &platformv1.CreateUserRequest{
    Email:    "user@example.com",
    Name:     "New User",
    Roles:    []string{"operator"},
    TenantId: "default",
})

// Check permission
allowed, err := client.IAM().CheckPermission(ctx, &platformv1.CheckPermissionRequest{
    UserId:   user.Id,
    Action:   "read",
    Resource: "certificates",
})
```

## Authentication Setup

### Token-Based Authentication

```go
// First, authenticate to get a token
auth, err := client.IAM().Authenticate(ctx, &platformv1.AuthenticateRequest{
    Username: "admin",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}

// Use token in subsequent connections
// For gRPC, add to context metadata
import "google.golang.org/grpc/metadata"

ctx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+auth.Token)
```

### mTLS Authentication

```go
// Load client certificate and key
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
    log.Fatal(err)
}

// Load CA certificate pool
caCert, err := os.ReadFile("ca.crt")
if err != nil {
    log.Fatal(err)
}
certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(caCert)

// Configure TLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
    MinVersion:   tls.VersionTLS13,
}

// Create client with mTLS
client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithTLSConfig(tlsConfig),
)
```

## Error Handling

### Typed Error Handling

```go
import "errors"

client, err := platform.Connect(ctx, opts)
if err != nil {
    // Check for specific error types
    var connFailed platform.ErrConnectionFailed
    if errors.As(err, &connFailed) {
        log.Printf("Connection to %s via %s failed: %v",
            connFailed.Target, connFailed.Protocol, connFailed.Err)
    }

    var unavailable platform.ErrDaemonUnavailable
    if errors.As(err, &unavailable) {
        log.Printf("Daemon unavailable, tried: %v", unavailable.Attempted)
    }

    var invalidOpts platform.ErrInvalidOptions
    if errors.As(err, &invalidOpts) {
        log.Printf("Invalid option %s: %s", invalidOpts.Field, invalidOpts.Reason)
    }

    return
}
```

### Service Error Handling

```go
cert, err := client.CA().Issue(ctx, request)
if err != nil {
    // Check gRPC status codes
    st, ok := status.FromError(err)
    if ok {
        switch st.Code() {
        case codes.InvalidArgument:
            log.Printf("Invalid request: %s", st.Message())
        case codes.PermissionDenied:
            log.Printf("Permission denied: %s", st.Message())
        case codes.NotFound:
            log.Printf("Resource not found: %s", st.Message())
        default:
            log.Printf("Error: %s", st.Message())
        }
    }
    return
}
```

## Connection Options

### All Available Options

```go
opts := platform.NewOptions(
    // Socket/address configuration
    platform.WithUnixSocket("/run/platformd.sock"),
    platform.WithGRPCAddr("localhost:10443"),
    platform.WithRESTAddr("localhost:8443"),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithMCPAddr("localhost:9445"),

    // Protocol selection
    platform.WithPreferredProtocol(platform.ProtocolGRPC),
    platform.WithOnlyProtocol(platform.ProtocolUnix), // Use only one protocol

    // TLS configuration
    platform.WithTLSConfig(tlsConfig),
    platform.WithTLSConfig(tlsConfig), // Always use TLS 1.3 with CA certs

    // Timeouts and limits
    platform.WithTimeout(10*time.Second),
    platform.WithMaxMessageSize(8*1024*1024), // 8MB
)

client, err := platform.Connect(ctx, opts)
```

### Default Values

| Option | Default Value |
|--------|---------------|
| Unix Socket | `/run/platformd.sock` |
| gRPC Port | `10443` |
| REST Port | `8443` |
| QUIC Port | `9444` |
| MCP Port | `9445` |
| Timeout | `5s` |
| Max Message Size | `4MB` |

## Retry and Reconnection

```go
func connectWithRetry(ctx context.Context, opts *platform.Options, maxRetries int) (platform.Client, error) {
    var client platform.Client
    var err error

    for attempt := 0; attempt <= maxRetries; attempt++ {
        client, err = platform.Connect(ctx, opts)
        if err == nil {
            return client, nil
        }

        // Exponential backoff
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-time.After(time.Duration(attempt*attempt) * time.Second):
            continue
        }
    }

    return nil, err
}
```

## Data Platform Services

The platform SDK provides access to data, AI/ML, security, and infrastructure services through a unified interface. These services are accessed via the platform daemon's gRPC API.

### Service Categories

| Category | Services | Description |
|----------|----------|-------------|
| Data | KV, Batch, Transaction, Query, TimeSeries, Backup | Core data operations |
| AI/ML | Vector, Embedding, Ollama | Vector search and embeddings |
| Security | Auth, KMS, Secrets, Crypto, RBAC, DynamicSecrets | Security operations |
| Infrastructure | Cluster, Health, Cache, Scheduler, ObjectStorage | Infrastructure management |

### KV Operations

Data platform services are accessed through the platform daemon's gRPC services:

```go
// Access KV service through platform gRPC
kvClient := platformv1.NewKVServiceClient(client.Connection())

// Put a value
_, err := kvClient.Put(ctx, &platformv1.PutRequest{
    Key:   "users/user-123",
    Value: []byte(`{"name":"John","email":"john@example.com"}`),
})

// Get a value
resp, err := kvClient.Get(ctx, &platformv1.GetRequest{Key: "users/user-123"})
log.Printf("Value: %s", string(resp.Value))
```

### Vector Search

```go
// Access Vector service through platform gRPC
vectorClient := platformv1.NewVectorServiceClient(client.Connection())

// Store vectors
_, err := vectorClient.Upsert(ctx, &platformv1.UpsertVectorRequest{
    Namespace: "documents",
    Vectors: []*platformv1.Vector{
        {Id: "doc-1", Values: embedding1, Metadata: map[string]string{"title": "Doc 1"}},
        {Id: "doc-2", Values: embedding2, Metadata: map[string]string{"title": "Doc 2"}},
    },
})

// Search similar vectors
results, err := vectorClient.SearchSimilar(ctx, &platformv1.SearchVectorRequest{
    Namespace: "documents",
    Vector:    queryEmbedding,
    TopK:      10,
})
for _, match := range results.Matches {
    log.Printf("Match: %s (score: %.4f)", match.Id, match.Score)
}
```

### Embedding Generation

```go
// Access Embedding service through platform gRPC
embeddingClient := platformv1.NewEmbeddingServiceClient(client.Connection())

// Generate embeddings
resp, err := embeddingClient.Generate(ctx, &platformv1.GenerateEmbeddingRequest{
    Input:    "Hello, world!",
    Provider: "voyage",      // or "openai", "ollama"
    Model:    "voyage-3",
})
log.Printf("Embedding dimension: %d", len(resp.Embedding))

// Batch embedding
batchResp, err := embeddingClient.BatchGenerate(ctx, &platformv1.BatchGenerateEmbeddingRequest{
    Inputs:   []string{"text 1", "text 2", "text 3"},
    Provider: "voyage",
})
```

### Secrets Management

```go
// Access Secrets service through platform gRPC
secretsClient := platformv1.NewSecretsServiceClient(client.Connection())

// Store a secret
_, err := secretsClient.Put(ctx, &platformv1.PutSecretRequest{
    Path:  "apps/myapp/database",
    Data:  map[string]string{"password": "secret123", "host": "db.example.com"},
})

// Get a secret
resp, err := secretsClient.Get(ctx, &platformv1.GetSecretRequest{Path: "apps/myapp/database"})
log.Printf("DB password: %s", resp.Data["password"])

// List secret versions
versions, err := secretsClient.ListVersions(ctx, &platformv1.ListSecretVersionsRequest{
    Path: "apps/myapp/database",
})
```

### Data Key Management

```go
// Access Data KMS service through platform gRPC
dataKmsClient := platformv1.NewDataKMSServiceClient(client.Connection())

// Generate a key
key, err := dataKmsClient.GenerateKey(ctx, &platformv1.GenerateDataKeyRequest{
    KeyID:     "my-encryption-key",
    Algorithm: "AES-256-GCM",
})

// Encrypt data
encrypted, err := dataKmsClient.Encrypt(ctx, &platformv1.DataEncryptRequest{
    KeyID:     "my-encryption-key",
    Plaintext: []byte("sensitive data"),
})

// Decrypt data
decrypted, err := dataKmsClient.Decrypt(ctx, &platformv1.DataDecryptRequest{
    KeyID:      "my-encryption-key",
    Ciphertext: encrypted.Ciphertext,
})
```

### Time Series Data

```go
// Access TimeSeries service through platform gRPC
timeseriesClient := platformv1.NewTimeSeriesServiceClient(client.Connection())

// Write time series data
_, err := timeseriesClient.Write(ctx, &platformv1.WriteTimeSeriesRequest{
    Metric: "cpu_usage",
    Tags:   map[string]string{"host": "server-1"},
    Points: []*platformv1.TimeSeriesPoint{
        {Timestamp: time.Now().UnixNano(), Value: 45.5},
    },
})

// Query time series
results, err := timeseriesClient.Query(ctx, &platformv1.QueryTimeSeriesRequest{
    Metric:    "cpu_usage",
    StartTime: time.Now().Add(-1 * time.Hour).UnixNano(),
    EndTime:   time.Now().UnixNano(),
    Aggregation: &platformv1.Aggregation{
        Function: "avg",
        Interval: "5m",
    },
})
```

### Scheduled Jobs

```go
// Access Scheduler service through platform gRPC
schedulerClient := platformv1.NewSchedulerServiceClient(client.Connection())

// Schedule a job
job, err := schedulerClient.Create(ctx, &platformv1.CreateJobRequest{
    Name:     "daily-backup",
    Schedule: "0 2 * * *",  // 2 AM daily
    Payload:  []byte(`{"type":"backup","target":"all"}`),
})

// List scheduled jobs
jobs, err := schedulerClient.List(ctx, &platformv1.ListJobsRequest{})
```

## SDK Import Paths

The Go SDK uses reexports from dependency packages via the `sdk/go` paths. Never import directly from `pkg/` directories.

### Correct Import Paths

```go
// Correct: Use SDK reexports
import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
    trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// Incorrect: Never use pkg/ paths
// import "github.com/jeremyhahn/go-quicbaas/pkg/quicbaas"     // Wrong
// import "github.com/jeremyhahn/go-xkms/pkg/types"             // Wrong
// import "github.com/jeremyhahn/go-trusted-ca/pkg/ca"          // Wrong
```

### SDK Package Organization

| Package | Purpose | Import Path |
|---------|---------|-------------|
| QuicBaaS SDK | Service layer: KMS, IAM, Secrets, Storage | `github.com/jeremyhahn/go-quicbaas/sdk/go` |
| XKMS SDK | Key management backends | `github.com/jeremyhahn/go-xkms/sdk/go` |
| Trusted CA SDK | Certificate authority operations | `github.com/jeremyhahn/go-trusted-ca/sdk/go` |
| Platform SDK | Public platform client API | `github.com/jeremyhahn/go-trusted-platform/sdk/go` |

## Complete Example

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    "time"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Create client with fallback
    client, err := platform.NewClient(ctx,
        platform.WithGRPCAddr("platform.example.com:10443"),
        platform.WithRESTAddr("platform.example.com:8443"),
        platform.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13}),
        platform.WithTimeout(10*time.Second),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.Close()

    log.Printf("Connected via %s protocol", client.Protocol())

    // Get platform health
    version, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    log.Printf("Platform: %s", version.Version)

    // Issue a certificate
    cert, err := client.CA().Issue(ctx, &platformv1.IssueCertificateRequest{
        CommonName: "app.example.com",
        DnsNames:   []string{"app.example.com"},
        ValidDays:  90,
    })
    if err != nil {
        log.Fatalf("Failed to issue certificate: %v", err)
    }
    log.Printf("Issued certificate: serial=%s", cert.Serial)

    // Create vTPM for a VM
    vtpm, err := client.VTPM().Create(ctx, &platformv1.CreateVTPMRequest{
        Name:        "app-vm-vtpm",
        EkAlgorithm: platformv1.Algorithm_RSA2048,
    })
    if err != nil {
        log.Fatalf("Failed to create vTPM: %v", err)
    }
    log.Printf("Created vTPM: %s", vtpm.Id)

    // Use data platform services
    kvClient := platformv1.NewKVServiceClient(client.Connection())
    embeddingClient := platformv1.NewEmbeddingServiceClient(client.Connection())
    vectorClient := platformv1.NewVectorServiceClient(client.Connection())

    // Store application config
    _, err = kvClient.Put(ctx, &platformv1.PutRequest{
        Key:   "apps/myapp/config",
        Value: []byte(`{"debug":true,"logLevel":"info"}`),
    })
    if err != nil {
        log.Fatalf("Failed to store config: %v", err)
    }

    // Generate and store embeddings for semantic search
    embResp, _ := embeddingClient.Generate(ctx, &platformv1.GenerateEmbeddingRequest{
        Input:    "Application configuration documentation",
        Provider: "voyage",
    })

    _, err = vectorClient.Upsert(ctx, &platformv1.UpsertVectorRequest{
        Namespace: "docs",
        Vectors: []*platformv1.Vector{
            {Id: "config-doc", Values: embResp.Embedding},
        },
    })

    log.Println("Setup complete")
}
```
