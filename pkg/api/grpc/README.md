# Platform Daemon gRPC API

This package contains the gRPC service definitions for the `platformd` daemon's internal API.

## Overview

The platformd daemon exposes a comprehensive gRPC API over a Unix socket for root-level operations. This is an **INTERNAL API** not intended for direct external access. Clients include:

- `platformctl` - Local CLI tool for platform operations

`platformd` is the only process that serves gRPC. REST, QUIC, MCP and the Unix socket are served by the same daemon; see `docs/daemon/api.md` for the transport model.

## Architecture

```
┌──────────────┐         ┌──────────────┐
│ platformctl  │────────▶│  platformd   │
└──────────────┘         │   (daemon)   │
                         │ Unix Socket  │
                         └──────────────┘
```

## Service Definitions

### 1. PlatformDaemon (`daemon.proto`)

Main orchestration service that provides:
- System status and health checks
- Platform provisioning
- Service lifecycle management
- Configuration management
- Event, log, and metrics streaming

### 2. TPMService (`tpm.proto`)

Trusted Platform Module operations:
- TPM information and capabilities
- Provisioning (EK, SRK, AK creation)
- Seal/unseal operations
- Attestation (quote generation and verification)
- NVRAM operations
- Random number generation
- Event log access

### 3. SDNService (`sdn.proto`)

Software-Defined Networking operations:
- Bridge management (OVS, Linux bridge)
- Port operations (add, delete, statistics)
- OpenFlow rule management
- VLAN configuration
- x509-based port authentication
- Flow log streaming

### 4. ComputeService (`compute.proto`)

Virtual machine and container lifecycle:
- VM creation, start, stop, delete
- Container operations
- Console attachment and streaming
- Disk operations (attach, detach, resize)
- Snapshot management
- Live migration
- VM attestation (vTPM)
- Resource metrics

### 5. Common Types (`common.proto`)

Shared types and enums:
- Error codes and status
- Key algorithms and attributes
- Hash algorithms
- Resource limits
- Pagination
- Health status

## Protocol Buffer Files

```
pkg/api/grpc/
├── proto/
│   ├── common.proto      # Shared types and enums
│   ├── tpm.proto         # TPM service definitions
│   ├── sdn.proto         # SDN service definitions
│   ├── compute.proto     # Compute service definitions
│   └── daemon.proto      # Main daemon service
├── gen/                  # Generated Go code (gitignored)
├── generate.go           # go:generate directive
└── README.md             # This file
```

## Code Generation

### Prerequisites

Install the required tools:

```bash
# Install protoc compiler
# Ubuntu/Debian
sudo apt-get install -y protobuf-compiler

# macOS
brew install protobuf

# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Ensure $GOPATH/bin is in your PATH
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Generate Go Code

```bash
# From repository root
cd pkg/api/grpc
go generate

# Or use make
make proto-gen
```

This will generate:
- `gen/platform/v1/*.pb.go` - Protocol buffer message types
- `gen/platform/v1/*_grpc.pb.go` - gRPC service interfaces

### Clean Generated Code

```bash
rm -rf sdk/go/gen
```

## Usage Examples

### Server Implementation

```go
package main

import (
    "context"
    "net"
    "google.golang.org/grpc"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type daemonServer struct {
    platformv1.UnimplementedPlatformDaemonServer
    // ... dependencies
}

func (s *daemonServer) GetStatus(ctx context.Context, req *platformv1.GetStatusRequest) (*platformv1.GetStatusResponse, error) {
    return &platformv1.GetStatusResponse{
        Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
        Info: &platformv1.PlatformInfo{
            Hostname: "platform-01",
            Version: "1.4.0",
            // ...
        },
    }, nil
}

func main() {
    lis, err := net.Listen("unix", "/var/run/platformd.sock")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    grpcServer := grpc.NewServer()
    platformv1.RegisterPlatformDaemonServer(grpcServer, &daemonServer{})

    if err := grpcServer.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

### Client Implementation

```go
package main

import (
    "context"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func main() {
    conn, err := grpc.Dial(
        "unix:///var/run/platformd.sock",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        log.Fatalf("failed to connect: %v", err)
    }
    defer conn.Close()

    client := platformv1.NewPlatformDaemonClient(conn)

    resp, err := client.GetStatus(context.Background(), &platformv1.GetStatusRequest{})
    if err != nil {
        log.Fatalf("failed to get status: %v", err)
    }

    log.Printf("Platform Status: %v", resp.Status)
}
```

### Streaming Events

```go
stream, err := client.StreamEvents(context.Background(), &platformv1.StreamEventsRequest{
    Types: []platformv1.EventType{
        platformv1.EventType_EVENT_TYPE_VM_CREATED,
        platformv1.EventType_EVENT_TYPE_VM_STARTED,
    },
})
if err != nil {
    log.Fatalf("failed to stream events: %v", err)
}

for {
    event, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatalf("error receiving event: %v", err)
    }
    log.Printf("Event: %v - %s", event.Type, event.Message)
}
```

## Design Principles

### 1. Internal API Design
- Unix socket transport for local IPC
- Root-level operations only
- No authentication required (socket permissions provide access control)
- High performance, low overhead

### 2. Error Handling
- Consistent error codes across all services
- Structured error details with metadata
- Status messages in responses
- Proper gRPC status codes

### 3. Streaming Support
- Console output (VM/container)
- Log streaming with follow mode
- Real-time event notifications
- Metrics collection

### 4. Resource Management
- Pagination for large result sets
- Label selectors for filtering
- Resource limits and quotas
- Proper resource cleanup

### 5. Observability
- Comprehensive metrics
- Structured logging
- Event tracking
- Health checks

## API Versioning

The API uses semantic versioning with the package version `platform.v1`. Breaking changes will result in a new package version (e.g., `platform.v2`).

### Backward Compatibility

When making changes:
- Add new fields instead of modifying existing ones
- Mark deprecated fields with comments
- Maintain support for deprecated fields for at least 2 major versions
- Use reserved field numbers for removed fields

Example:
```protobuf
message VMConfig {
  string name = 1;

  // Deprecated: use cpu.cores instead
  uint32 vcpus = 2 [deprecated = true];

  CPUConfig cpu = 3;

  reserved 4; // Previously used for memory_mb
}
```

## Testing

### Unit Tests

Test message serialization and deserialization:

```go
func TestVMConfigSerialization(t *testing.T) {
    config := &platformv1.VMConfig{
        Name: "test-vm",
        Cpu: &platformv1.CPUConfig{
            Cores: 4,
        },
    }

    data, err := proto.Marshal(config)
    if err != nil {
        t.Fatalf("failed to marshal: %v", err)
    }

    decoded := &platformv1.VMConfig{}
    if err := proto.Unmarshal(data, decoded); err != nil {
        t.Fatalf("failed to unmarshal: %v", err)
    }

    if decoded.Name != "test-vm" {
        t.Errorf("expected name 'test-vm', got '%s'", decoded.Name)
    }
}
```

### Integration Tests

Test actual gRPC communication:

```go
func TestPlatformDaemonService(t *testing.T) {
    // Start test server
    lis := bufconn.Listen(bufSize)
    s := grpc.NewServer()
    platformv1.RegisterPlatformDaemonServer(s, &testDaemonServer{})
    go s.Serve(lis)
    defer s.Stop()

    // Create client
    conn, _ := grpc.DialContext(ctx, "bufnet",
        grpc.WithContextDialer(bufDialer(lis)),
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    defer conn.Close()

    client := platformv1.NewPlatformDaemonClient(conn)

    // Test RPC
    resp, err := client.GetStatus(ctx, &platformv1.GetStatusRequest{})
    if err != nil {
        t.Fatalf("GetStatus failed: %v", err)
    }

    if resp.Status != platformv1.SystemStatus_SYSTEM_STATUS_READY {
        t.Errorf("expected READY status, got %v", resp.Status)
    }
}
```

## Security Considerations

### Unix Socket Permissions

The daemon socket should have restricted permissions:

```bash
# Socket owned by root, group platformd
chown root:platformd /var/run/platformd.sock
chmod 0660 /var/run/platformd.sock
```

### TLS (Future)

For remote access to the platformd gRPC listener:
- Mutual TLS authentication
- Certificate-based authorization
- Client certificate validation
- Encrypted transport

### Input Validation

All service implementations must:
- Validate all input parameters
- Sanitize file paths
- Check resource limits
- Verify permissions

## Performance Considerations

### Message Size Limits

Default gRPC message size: 4MB
- Large files: Use streaming RPCs
- Console output: Stream in chunks
- Event logs: Paginate or stream

### Connection Pooling

Clients should reuse connections:
```go
var (
    conn   *grpc.ClientConn
    connMu sync.Mutex
)

func getConnection() (*grpc.ClientConn, error) {
    connMu.Lock()
    defer connMu.Unlock()

    if conn != nil {
        return conn, nil
    }

    var err error
    conn, err = grpc.Dial("unix:///var/run/platformd.sock", ...)
    return conn, err
}
```

### Timeouts

Always use context timeouts:
```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

resp, err := client.GetStatus(ctx, req)
```

## Future Enhancements

1. gRPC-Web support for browser clients
3. Policy-based authorization
4. Audit logging for all operations
5. Rate limiting per client
6. Request/response compression
7. OpenTelemetry tracing integration

## References

- [gRPC Documentation](https://grpc.io/docs/)
- [Protocol Buffers v3](https://protobuf.dev/)
- [gRPC-Go](https://github.com/grpc/grpc-go)
- [go-trusted-platform Documentation](../../docs/)

## Contributing

When adding new RPC methods:

1. Add the method to the appropriate service in the proto file
2. Define request/response messages
3. Update this README with usage examples
4. Regenerate code with `go generate`
5. Implement the server-side handler
6. Add unit and integration tests
7. Update API documentation

## License

See repository root LICENSE file.
