# SDK Architecture Overview

The go-trusted-platform provides official SDKs for Go and JavaScript/TypeScript that enable developers to integrate with the Trusted Platform daemon across multiple protocols. Both SDKs share a common architecture pattern centered around protocol adapters and service clients.

**go-trusted-platform is the single entry point for all platform services.** Implementation details like the underlying data stores are abstracted away, providing a unified, consistent API.

The SDKs provide access to:
- **Core Platform services** for TPM, CA, IAM, compute, networking, and more
- **Data Platform services** for key-value storage, batch operations, and queries
- **AI/ML Platform services** for vector search, embeddings, and LLM integration
- **Security Platform services** for secrets, encryption, and access control
- **Infrastructure Platform services** for cluster management, health, and scheduling

## Architecture Diagram

```
                                    Trusted Platform SDKs
    +----------------------------------------------------------------------------------+
    |                                                                                  |
    |  +---------------------------+        +---------------------------+              |
    |  |        Go SDK             |        |    JavaScript SDK         |              |
    |  |                           |        |                           |              |
    |  |  +---------------------+  |        |  +---------------------+  |              |
    |  |  |  Platform Client    |  |        |  |  Platform Client    |  |              |
    |  |  +---------------------+  |        |  +---------------------+  |              |
    |  |           |               |        |           |               |              |
    |  |  +---------------------+  |        |  +---------------------+  |              |
    |  |  | Protocol Adapters   |  |        |  |    API Client       |  |              |
    |  |  |  - Unix Socket      |  |        |  |  (REST over HTTPS)  |  |              |
    |  |  |  - gRPC             |  |        |  +---------------------+  |              |
    |  |  |  - REST             |  |        |           |               |              |
    |  |  |  - QUIC             |  |        |  +---------------------+  |              |
    |  |  |  - MCP              |  |        |  |  Service Clients    |  |              |
    |  |  +---------------------+  |        |  +---------------------+  |              |
    |  |           |               |        |           |               |              |
    |  |  +---------------------+  |        |  +---------------------+  |              |
    |  |  | Service Clients     |  |        |  |   React Bindings    |  |              |
    |  |  +---------------------+  |        |  |  - Hooks            |  |              |
    |  |                           |        |  |  - Context          |  |              |
    |  |                           |        |  +---------------------+  |              |
    |  +---------------------------+        +---------------------------+              |
    +----------------------------------------------------------------------------------+
                                             |
                                             v
    +----------------------------------------------------------------------------------+
    |                          Platform Daemon (platformd)                             |
    |                                                                                  |
    |   Unix Socket        gRPC          REST          QUIC           MCP              |
    |   /run/platformd     :10443        :8443         :9444          :9445            |
    |      .sock                                                                       |
    +----------------------------------------------------------------------------------+
                                             |
                                             v
    +----------------------------------------------------------------------------------+
    |                         Platform Service Registry                                |
    |                    (Internal abstraction layer)                                  |
    +----------------------------------------------------------------------------------+
```

## Protocol Adapter Pattern

The Go SDK implements a protocol adapter pattern that provides a unified interface across all supported protocols. Each adapter implements the `transport.Adapter` interface:

```go
type Adapter interface {
    // Connection returns the underlying gRPC client connection.
    // For non-gRPC protocols, this returns a wrapped connection.
    Connection() grpc.ClientConnInterface

    // Close closes the transport connection
    Close() error

    // IsConnected returns true if connected
    IsConnected() bool

    // Target returns the connection target
    Target() string
}
```

This design allows:
- Seamless protocol switching without code changes
- Automatic protocol fallback when connections fail
- Consistent error handling across all protocols
- Unified service client initialization

## Service Client Organization

All services are exposed as **platform services**. Implementation details like underlying data stores are abstracted away, providing a unified, consistent API across both SDKs.

### Core Platform Services

| Go SDK | JavaScript SDK | Description |
|--------|----------------|-------------|
| `Daemon()` | `platform` | Platform daemon status, health, and version |
| `TPM()` | `tpm` | Hardware TPM operations (EK, SRK, AK, quotes) |
| `VTPM()` | `vtpm` | Virtual TPM bundle lifecycle management |
| `CA()` | `ca` | Certificate Authority (issue, revoke, renew) |
| `IAM()` | `iam` | Identity and access management (users, roles, policies) |
| `KMS()` | `kms` | Key management (generate, encrypt, decrypt, sign) |
| `Device()` | `device` | Device registration and profile management |
| `Attestation()` | `attestation` | Quote generation and manifest verification |
| `IDevID()` | `idevid` | Initial Device Identity certificates |
| `Tenant()` | `tenant` | Multi-tenant management with VLAN isolation |
| `SDN()` | `sdn` | Software-defined networking (OVS, flows, ports) |
| `DNS()` | `dns` | DNS zone and record management with DNSSEC |
| `PXE()` | `pxe` | Network boot provisioning |
| `Compute()` | `compute` | Container and VM lifecycle management |
| `Gateway()` | `gateway` | BGP routing and IPAM operations |
| `Overlay()` | `overlay` | VXLAN overlay and multi-host networking |
| `Invitation()` | `invitation` | Tenant invitation management |
| `EAB()` | `eab` | ACME External Account Binding |

### Data Platform Services

| JavaScript SDK | Description |
|----------------|-------------|
| `kv` | Key-value CRUD with Watch support |
| `batch` | Atomic batch operations |
| `transaction` | Compare-and-swap transactions |
| `query` | Secondary index queries |
| `timeseries` | Time-series data with aggregations |
| `backup` | Backup and restore operations |

### AI/ML Platform Services

| JavaScript SDK | Description |
|----------------|-------------|
| `vector` | Vector similarity search (k-NN) |
| `embedding` | Multi-provider embedding generation |
| `ollama` | Local LLM/embedding via Ollama |

### Security Platform Services

| JavaScript SDK | Description |
|----------------|-------------|
| `auth` | Authentication (login, tokens) |
| `dataKms` | Data-layer key management |
| `secrets` | Secret storage with versioning |
| `crypto` | Encryption/decryption, signatures |
| `dynamicSecrets` | Dynamic credential generation |
| `certificate` | X.509 certificate management |
| `seal` | Seal/unseal operations |
| `rbac` | Role-based access control |
| `clusterDek` | Cluster data encryption keys |

### Infrastructure Platform Services

| JavaScript SDK | Description |
|----------------|-------------|
| `cluster` | Cluster status and management |
| `health` | Health checks (ping, liveness) |
| `operations` | Migration, upgrade, rebalance |
| `cache` | Cache management and stats |
| `parameterStore` | Hierarchical parameters |
| `scheduler` | Job scheduling |
| `objectStorage` | Distributed object storage |
| `objectStorageAdmin` | Object storage admin ops |
| `objectTransfer` | Peer-to-peer data transfer |
| `dataIam` | Data-layer identity management |

## Error Handling Patterns

### Go SDK Typed Errors

The Go SDK uses typed errors for precise error handling:

```go
// Connection errors
type ErrConnectionFailed struct {
    Protocol Protocol
    Target   string
    Err      error
}

// Daemon unavailable (all protocols failed)
type ErrDaemonUnavailable struct {
    Attempted []Protocol
    LastErr   error
}

// Protocol errors
type ErrProtocolNotSupported struct { Protocol Protocol }
type ErrProtocolNotImplemented struct { Protocol Protocol }

// Configuration errors
type ErrInvalidOptions struct {
    Field  string
    Reason string
}
```

Usage:

```go
client, err := platform.Connect(ctx, opts)
if err != nil {
    var unavailable platform.ErrDaemonUnavailable
    if errors.As(err, &unavailable) {
        log.Printf("Tried protocols: %v", unavailable.Attempted)
    }
}
```

### JavaScript SDK Error Handling

The JavaScript SDK provides a consistent `ApiResponse<T>` wrapper:

```typescript
interface ApiResponse<T> {
    data?: T;
    error?: ApiError;
    success: boolean;
}

interface ApiError {
    code: string;
    message: string;
    status?: number;
    details?: Record<string, unknown>;
}
```

Usage:

```typescript
const response = await client.ca.issueCertificate(request);
if (response.error) {
    console.error(`Error ${response.error.code}: ${response.error.message}`);
} else {
    console.log('Certificate:', response.data);
}
```

## Authentication Flows

Both SDKs support two primary authentication methods:

### Token-Based Authentication

1. Obtain JWT token via IAM service
2. Attach token to requests via interceptor/metadata
3. Token automatically refreshed before expiry

### mTLS Authentication

1. Configure TLS with client certificate
2. Certificate validated by server
3. Identity extracted from certificate subject

```
+--------+                                              +----------+
| Client |                                              |  Server  |
+--------+                                              +----------+
    |                                                         |
    |  1. Request token (username/password or API key)        |
    |-------------------------------------------------------->|
    |                                                         |
    |  2. Return JWT token                                    |
    |<--------------------------------------------------------|
    |                                                         |
    |  3. API request with Authorization: Bearer <token>      |
    |-------------------------------------------------------->|
    |                                                         |
    |  4. Validate token, process request                     |
    |<--------------------------------------------------------|
    |                                                         |
    |  5. If token expired, refresh                           |
    |-------------------------------------------------------->|
    |                                                         |
```

## When to Use Which SDK

### Use the Go SDK when:

- Building CLI tools or system utilities
- Running on servers with direct access to Unix sockets
- Needing high-performance gRPC or QUIC protocols
- Integrating with existing Go applications
- Requiring access to all 5 protocols

### Use the JavaScript SDK when:

- Building web applications or dashboards
- Creating React-based management interfaces
- Integrating with Node.js backend services
- Need React hooks for state management
- Building browser-based administrative tools

## Connection Priority

The Go SDK attempts connections in this priority order:

1. **Unix Socket** - Fastest, local only, requires root
2. **gRPC** - High performance, supports streaming
3. **REST** - Universal compatibility
4. **QUIC** - Low latency, mobile-friendly
5. **MCP** - AI/LLM integration

Override with `WithPreferredProtocol()` or `WithOnlyProtocol()` options.
