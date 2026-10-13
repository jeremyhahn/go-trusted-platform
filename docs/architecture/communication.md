# Inter-Service Communication

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [../daemon/api.md](../daemon/api.md).

This document describes the communication protocols and patterns used between go-trusted-platform components.

## Communication Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                        External Clients                            │
│                                                                    │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────────┐            │
│  │ Web Browser │    │  curl/API   │    │ ACME Client  │            │
│  └──────┬──────┘    └──────┬──────┘    └──────┬───────┘            │
│         │                  │                  │                    │
└─────────┼──────────────────┼──────────────────┼────────────────────┘
          │                  │                  │
          │ HTTPS            │ HTTPS            │ HTTPS
          │ (mTLS)           │ (mTLS)           │ (TLS)
          │                  │                  │
┌─────────┼──────────────────┼──────────────────┼────────────────────┐
│         ▼                  ▼                  ▼                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                         platformd                            │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │              Master Process (root)                     │  │  │
│  │  │                                                        │  │  │
│  │  │  • TPM operations      • OVS/OpenFlow management       │  │  │
│  │  │  • QEMU/KVM lifecycle  • TAP device creation           │  │  │
│  │  │  • LUKS operations     • Network namespaces            │  │  │
│  │  └─────────────────────────────┬──────────────────────────┘  │  │
│  │                                │                             │  │
│  │                       IPC      │                             │  │
│  │                                ▼                             │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │           Worker Processes (platform user)             │  │  │
│  │  │                                                        │  │  │
│  │  │  • REST/gRPC/QUIC APIs  • ACME server                  │  │  │
│  │  │  • DNS server           • Web UI                       │  │  │
│  │  │  • Certificate mgmt     • Device enrollment            │  │  │
│  │  │  • QuicBaaS (embedded)                                 │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                                                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│                            Service Layer                           │
└────────────────────────────────────────────────────────────────────┘
             │
┌────────────┼───────────────────────────────────────────────────────┐
│            │                                                       │
│   ┌────────▼─────────┐                                             │
│   │                  │                                             │
│   │    QuicBaaS      │     Provides: KMS, IAM, Secrets, KV Store   │
│   │                  │     Backend: PebbleDB (standalone) or Raft  │
│   └──────────────────┘                                             │
│                                                                    │
│                        Infrastructure Layer                        │
└────────────────────────────────────────────────────────────────────┘
             │
┌────────────┼───────────────────────────────────────────────────────┐
│            │                                                       │
│   ┌────────┴────────┬─────────┬─────────┐                          │
│   │        │        │         │         │                          │
│   ▼        ▼        ▼         ▼         ▼                          │
│ ┌────┐  ┌─────┐  ┌─────┐  ┌──────┐  ┌──────┐                       │
│ │OVS │  │QEMU │  │ TPM │  │PKCS11│  │Cloud │                       │
│ └────┘  └─────┘  └─────┘  └──────┘  │ KMS  │                       │
│                                     └──────┘                       │
│                       Hardware/External Layer                      │
└────────────────────────────────────────────────────────────────────┘
```

## Protocol Details

### Internal IPC (Master ↔ Workers)

Communication between master and worker processes uses an internal IPC mechanism.

**IPC Message Format**:
```
┌─────────────────────────────────────────────────────────────────┐
│                      IPC Message Format                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┬──────────┬──────────────────────────────────────┐ │
│  │  Length  │   Type   │              Payload                 │ │
│  │ (4 bytes)│ (4 bytes)│           (variable)                 │ │
│  └──────────┴──────────┴──────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| CREATE_VM | Worker → Master | Create virtual machine |
| DELETE_VM | Worker → Master | Delete virtual machine |
| CREATE_TAP | Worker → Master | Create TAP device |
| DELETE_TAP | Worker → Master | Delete TAP device |
| OVS_ADD_PORT | Worker → Master | Add port to OVS bridge |
| OVS_DEL_PORT | Worker → Master | Remove port from OVS bridge |
| TPM_SIGN | Worker → Master | Sign with TPM key |
| TPM_UNSEAL | Worker → Master | Unseal TPM data |
| RESPONSE | Master → Worker | Operation result |
| ERROR | Master → Worker | Operation error |

**Flow Diagram**:
```
Worker Process                         Master Process
      │                                      │
      │  1. Request privileged operation     │
      │      (e.g., CreateVM)                │
      │─────────────────────────────────────▶│
      │                                      │
      │                                      │ 2. Execute privileged op
      │                                      │    • Create TAP device
      │                                      │    • Add to OVS bridge
      │                                      │    • Start QEMU process
      │                                      │
      │  3. Response with result             │
      │◀─────────────────────────────────────│
```

### Unix Socket API (platformctl → platformd)

The CLI client `platformctl` communicates with `platformd` workers via Unix socket.

**Socket Configuration**:
```yaml
daemon:
  socket: /var/run/platform/daemon.sock
  socket_permissions: 0660
  socket_group: platform
```

**Socket Security**:
```
/var/run/platform/daemon.sock
    │
    ├── Owner: root
    ├── Group: platform
    ├── Mode: 0660 (rw-rw----)
    │
    └── Only members of 'platform' group can connect
```

**Connection Example**:
```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

conn, err := grpc.Dial(
    "unix:///var/run/platform/daemon.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
```

**Flow Diagram**:
```
platformctl                            platformd (Worker)
     │                                      │
     │  1. Connect to Unix socket           │
     │─────────────────────────────────────▶│
     │                                      │
     │  2. gRPC Request (protobuf)          │
     │─────────────────────────────────────▶│
     │                                      │
     │                                      │ 3. Process request
     │                                      │    (delegate to master
     │                                      │     if privileged)
     │                                      │
     │  4. gRPC Response (protobuf)         │
     │◀─────────────────────────────────────│
```

### REST/HTTPS API

External clients communicate with `platformd` workers over HTTPS.

**TLS Configuration**:
```yaml
api:
  tls:
    enabled: true
    min_version: "1.3"
    cert: /etc/platform/certs/server.crt
    key: /etc/platform/certs/server.key
    client_ca: /etc/platform/certs/ca.crt
    client_auth: require  # mTLS
```

**Authentication Methods**:

| Method | Use Case | Configuration |
|--------|----------|---------------|
| mTLS | Machine-to-machine | Client certificate required |
| JWT | User sessions | Bearer token in Authorization header |

**Request Flow**:
```
Client                                  platformd (Worker)
   │                                         │
   │  1. TLS Handshake (client cert)         │
   │────────────────────────────────────────▶│
   │                                         │
   │  2. Client cert validated               │
   │                                         │
   │  3. HTTP Request                        │
   │  Authorization: Bearer <token>          │
   │────────────────────────────────────────▶│
   │                                         │
   │  4. Extract identity from cert/token    │
   │  5. Authorize against ABAC policy       │
   │  6. Execute request                     │
   │     (delegate to master if privileged)  │
   │                                         │
   │  7. HTTP Response                       │
   │◀────────────────────────────────────────│
```

### mTLS Authentication Flow

```
Client                           platformd (Worker)                 CA
   │                                      │                          │
   │ 1. TLS ClientHello                   │                          │
   │─────────────────────────────────────▶│                          │
   │                                      │                          │
   │ 2. TLS ServerHello + CertRequest     │                          │
   │◀─────────────────────────────────────│                          │
   │                                      │                          │
   │ 3. Client Certificate                │                          │
   │─────────────────────────────────────▶│                          │
   │                                      │                          │
   │                                      │ 4. Verify cert chain     │
   │                                      │─────────────────────────▶│
   │                                      │◀─────────────────────────│
   │                                      │                          │
   │                                      │ 5. Check revocation      │
   │                                      │─────────────────────────▶│
   │                                      │◀─────────────────────────│
   │                                      │                          │
   │ 6. TLS Finished                      │                          │
   │◀────────────────────────────────────▶│                          │
   │                                      │                          │
   │ 7. Authenticated session             │                          │
```

### ACME Protocol Flow

Device enrollment uses ACME with custom challenges.

```
Device                       platformd (Worker)               Master Process
   │                                 │                             │
   │ 1. GET /acme/directory          │                             │
   │────────────────────────────────▶│                             │
   │◀────────────────────────────────│                             │
   │                                 │                             │
   │ 2. POST /acme/new-account       │                             │
   │────────────────────────────────▶│                             │
   │◀────────────────────────────────│                             │
   │                                 │                             │
   │ 3. POST /acme/new-order         │                             │
   │    identifier: device MAC       │                             │
   │────────────────────────────────▶│                             │
   │◀────────────────────────────────│                             │
   │    challenges: [enroll-01]      │                             │
   │                                 │                             │
   │ 4. Prepare enroll-01 response   │                             │
   │    (EK cert, attestation)       │                             │
   │                                 │                             │
   │ 5. POST /acme/challenge/{token} │                             │
   │────────────────────────────────▶│                             │
   │                                 │                             │
   │                                 │ 6. Verify attestation (IPC) │
   │                                 │◀───────────────────────────▶│
   │                                 │                             │
   │◀────────────────────────────────│                             │
   │    status: valid                │                             │
   │                                 │                             │
   │ 7. POST /acme/finalize          │                             │
   │    CSR with TPM public key      │                             │
   │────────────────────────────────▶│                             │
   │                                 │ 8. Issue IDevID cert (IPC)  │
   │                                 │◀───────────────────────────▶│
   │                                 │                             │
   │ 9. GET /acme/cert/{id}          │                             │
   │────────────────────────────────▶│                             │
   │◀────────────────────────────────│                             │
   │    IDevID certificate           │                             │
```

## QuicBaaS Communication

`platformd` workers communicate with QuicBaaS (embedded) for KMS, IAM, and storage operations.

### Service Connections

```go
import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// Initialize QuicBaaS server
server, err := quicbaassdk.NewServer(quicbaassdk.Config{
    DataDir:     "/var/lib/platform/quicbaas",
    RaftEnabled: true,
    RaftBind:    "10.0.0.1:7000",
    RaftPeers:   []string{"10.0.0.2:7000", "10.0.0.3:7000"},
})

// Get service interfaces
kms := server.KMS()
iam := server.IAM()
secrets := server.Secrets()
kv := server.KV()
```

### KMS Operations

```
platformd (Worker)                 QuicBaaS
    │                                  │
    │ 1. GenerateKey(attrs)            │
    │─────────────────────────────────▶│
    │                                  │
    │                                  │ 2. Select backend
    │                                  │ 3. Generate key material
    │                                  │ 4. Store metadata (Raft)
    │                                  │
    │◀─────────────────────────────────│
    │    Key{path, version, attrs}     │
```

### IAM Authorization

```
platformd (Worker)                 QuicBaaS
    │                                  │
    │ 1. Evaluate(principal, action,   │
    │    resource)                     │
    │─────────────────────────────────▶│
    │                                  │
    │                                  │ 2. Load policies
    │                                  │ 3. Evaluate ABAC rules
    │                                  │ 4. Return decision
    │                                  │
    │◀─────────────────────────────────│
    │    Decision{allow/deny, reason}  │
```

## OVS/OVSDB Communication

The `platformd` master process communicates with Open vSwitch using OVSDB JSON-RPC.

```
platformd (Master)                 ovsdb-server
    │                                  │
    │ 1. Connect (Unix socket)         │
    │─────────────────────────────────▶│
    │                                  │
    │ 2. list_dbs                      │
    │─────────────────────────────────▶│
    │◀─────────────────────────────────│
    │    ["Open_vSwitch"]              │
    │                                  │
    │ 3. transact [insert Bridge]      │
    │─────────────────────────────────▶│
    │◀─────────────────────────────────│
    │    [{uuid: "..."}]               │
```

## OpenFlow Communication

The `platformd` master process manages flow rules via OpenFlow 1.3.

```
platformd (Master)                 ovs-vswitchd
    │                                  │
    │ 1. Connect (br0.mgmt socket)     │
    │─────────────────────────────────▶│
    │                                  │
    │ 2. Hello (version 0x04)          │
    │◀────────────────────────────────▶│
    │                                  │
    │ 3. FeaturesRequest               │
    │─────────────────────────────────▶│
    │◀─────────────────────────────────│
    │    FeaturesReply                 │
    │                                  │
    │ 4. FlowMod (add)                 │
    │─────────────────────────────────▶│
    │                                  │
    │ 5. BarrierRequest                │
    │─────────────────────────────────▶│
    │◀─────────────────────────────────│
    │    BarrierReply                  │
```

## End-to-End Request Flow

This diagram shows how a privileged operation flows through all layers:

```
platformctl                platformd                              External
    │                         │                                   Services
    │              ┌──────────┴──────────┐                           │
    │              │                     │                           │
    │           Worker               Master                          │
    │          (platform)            (root)                          │
    │              │                     │                           │
    │ 1. vm create │                     │                           │
    │─────────────▶│                     │                           │
    │              │                     │                           │
    │              │ 2. Validate request │                           │
    │              │    Check ABAC       │                           │
    │              │                     │                           │
    │              │ 3. CreateVM IPC     │                           │
    │              │────────────────────▶│                           │
    │              │                     │                           │
    │              │                     │ 4. Create TAP             │
    │              │                     │──────────────────────────▶│
    │              │                     │◀──────────────────────────│
    │              │                     │                           │
    │              │                     │ 5. Add to OVS             │
    │              │                     │──────────────────────────▶│
    │              │                     │◀──────────────────────────│
    │              │                     │                           │
    │              │                     │ 6. Start QEMU             │
    │              │                     │──────────────────────────▶│
    │              │                     │◀──────────────────────────│
    │              │                     │                           │
    │              │ 7. VM created       │                           │
    │              │◀────────────────────│                           │
    │              │                     │                           │
    │ 8. Success   │                     │                           │
    │◀─────────────│                     │                           │
```

## Error Handling

### gRPC Errors

```go
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

// Server returns structured errors
func (s *server) CreateVM(ctx context.Context, req *CreateVMRequest) (*VM, error) {
    if req.Name == "" {
        return nil, status.Error(codes.InvalidArgument, "name is required")
    }

    if exists, _ := s.vmExists(req.Name); exists {
        return nil, status.Error(codes.AlreadyExists, "VM already exists")
    }

    // ...
}
```

### REST API Errors

```json
{
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "name is required",
    "details": [
      {
        "field": "name",
        "description": "VM name cannot be empty"
      }
    ]
  }
}
```

## Timeouts and Retries

### Configuration

```yaml
# platformd configuration
daemon:
  timeout: 30s
  retry_attempts: 3
  retry_backoff: 1s

# Client configuration
api:
  timeout: 60s
  keepalive_time: 30s
  keepalive_timeout: 10s
```

### Retry Logic

```go
// Exponential backoff with jitter
func withRetry(ctx context.Context, fn func() error, maxAttempts int) error {
    var err error
    for i := 0; i < maxAttempts; i++ {
        if err = fn(); err == nil {
            return nil
        }

        // Check if error is retryable
        if !isRetryable(err) {
            return err
        }

        // Exponential backoff with jitter
        backoff := time.Duration(1<<uint(i)) * time.Second
        jitter := time.Duration(rand.Int63n(int64(backoff / 2)))

        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(backoff + jitter):
        }
    }
    return err
}
```

## Security Summary

| Component | Privilege Level | Network Exposure | Data Access |
|-----------|----------------|------------------|-------------|
| Master Process | root | None (IPC only) | Devices, hardware |
| Worker Process | platform user | mTLS protected | QuicBaaS, configs |
| platformctl | user | Via worker APIs | Client-side only |
