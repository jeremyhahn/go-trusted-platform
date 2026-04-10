# Platform Daemon API

The `daemon` package provides the complete implementation of the platformd gRPC daemon service that runs over Unix sockets.

## Overview

The platformd daemon is the core service management layer for the go-trusted-platform project. It provides:

- **Service Lifecycle Management**: Start, stop, restart platform services (TPM, SDN, Compute, DNS, ACME, WebService, Attestation)
- **System Monitoring**: Real-time status, health checks, and version information
- **Event Streaming**: Live events, logs, and metrics via gRPC streams
- **Configuration Management**: Runtime configuration access and updates
- **Graceful Shutdown**: Coordinated shutdown of all managed services

## Architecture

### Components

1. **Daemon** (`daemon.go`) - Main daemon lifecycle manager
   - Creates and manages the Unix socket server
   - Coordinates service registration and auto-start
   - Handles daemon-level start/stop operations

2. **Service** (`service.go`) - gRPC service implementation
   - Implements `platformv1.PlatformDaemonServer` interface
   - Manages registered services and their state
   - Provides pub/sub for events, logs, and metrics
   - Enforces atomic state transitions

3. **Config** (`config.go`) - Configuration structures
   - Default and custom daemon configuration
   - Per-service configuration options
   - Configuration validation

4. **Errors** (`errors.go`) - Typed error definitions
   - Service lifecycle errors
   - Configuration errors
   - Daemon state errors

### Design Patterns

- **Atomic Operations**: Uses `sync/atomic` for lock-free state management
- **Clean Separation**: Service layer abstracts business logic from gRPC interface
- **Interface-Based**: `ManagedService` interface allows flexible service integration
- **Event-Driven**: Pub/sub pattern for events, logs, and metrics
- **Context Propagation**: Proper context usage for cancellation and timeouts

## Usage

### Creating and Starting the Daemon

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
)

func main() {
    // Create daemon with default config
    d, err := daemon.New(nil)
    if err != nil {
        log.Fatal(err)
    }

    // Start the daemon
    ctx := context.Background()
    if err := d.Start(ctx); err != nil {
        log.Fatal(err)
    }

    log.Printf("Daemon listening on: %s", d.SocketPath())

    // Wait for signal or shutdown request
    // ...

    // Graceful shutdown
    if err := d.Stop(ctx); err != nil {
        log.Printf("Shutdown error: %v", err)
    }
}
```

### Custom Configuration

```go
config := &daemon.Config{
    SocketPath:      "/var/run/platformd.sock",
    SocketGroup:     "trusted-platform",
    SocketMode:      0660,
    ShutdownTimeout: 30 * time.Second,
    EnableMetrics:   true,
    EnableEvents:    true,
    Services: map[string]daemon.ServiceConfig{
        "tpm": {
            Enabled:    true,
            AutoStart:  true,
            Timeout:    10 * time.Second,
            MaxRetries: 3,
        },
    },
}

d, err := daemon.New(config)
```

### Registering Managed Services

Services must implement the `ManagedService` interface:

```go
type ManagedService interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    IsRunning() bool
    Name() string
}
```

Example:

```go
type TPMService struct {
    running atomic.Bool
}

func (s *TPMService) Name() string {
    return "tpm"
}

func (s *TPMService) Start(ctx context.Context) error {
    // Initialize TPM resources
    s.running.Store(true)
    return nil
}

func (s *TPMService) Stop(ctx context.Context) error {
    // Cleanup TPM resources
    s.running.Store(false)
    return nil
}

func (s *TPMService) IsRunning() bool {
    return s.running.Load()
}

// Register with daemon
tpmSvc := &TPMService{}
if err := d.RegisterService(tpmSvc); err != nil {
    log.Fatal(err)
}
```

### Publishing Events, Logs, and Metrics

The daemon service provides methods to publish to all subscribers:

```go
// Get the service instance
svc := d.Service()

// Publish an event
svc.PublishEvent(&platformv1.Event{
    Type:      "service.started",
    Timestamp: timestamppb.New(time.Now()),
    Data:      map[string]string{"service": "tpm"},
})

// Publish a log entry
svc.PublishLog(&platformv1.LogEntry{
    Level:     "INFO",
    Message:   "Service started successfully",
    Timestamp: timestamppb.New(time.Now()),
})

// Publish a metric
svc.PublishMetric(&platformv1.MetricData{
    Name:      "service.uptime",
    Value:     123.45,
    Timestamp: timestamppb.New(time.Now()),
})
```

## gRPC API

### System Operations

- **GetStatus** - Returns daemon status, platform info, and service list
- **GetHealth** - Returns health status of all components
- **GetVersion** - Returns version, build time, and git commit
- **Provision** - Delegates to platform provision logic (integration pending)
- **Shutdown** - Performs graceful shutdown

### Configuration Operations

- **GetConfig** - Returns current configuration
- **UpdateConfig** - Updates daemon configuration (not yet implemented)
- **ReloadConfig** - Reloads configuration from disk (not yet implemented)

### Service Management

- **StartService** - Starts a managed service
- **StopService** - Stops a managed service
- **RestartService** - Restarts a managed service
- **GetServiceStatus** - Returns status of a specific service
- **ListServices** - Returns list of all managed services

### Event Streaming

- **StreamEvents** - Streams daemon events to clients
- **StreamLogs** - Streams daemon logs to clients
- **StreamMetrics** - Streams daemon metrics to clients

## State Management

### System States

- `SYSTEM_STATUS_INITIALIZING` - Daemon is starting up
- `SYSTEM_STATUS_READY` - Daemon is fully operational
- `SYSTEM_STATUS_DEGRADED` - Some services are unhealthy
- `SYSTEM_STATUS_UNAVAILABLE` - Daemon is not operational
- `SYSTEM_STATUS_SHUTTING_DOWN` - Daemon is shutting down

### Service States

- `SERVICE_STATUS_STOPPED` - Service is not running
- `SERVICE_STATUS_STARTING` - Service is starting
- `SERVICE_STATUS_RUNNING` - Service is operational
- `SERVICE_STATUS_STOPPING` - Service is stopping
- `SERVICE_STATUS_ERROR` - Service encountered an error

State transitions are atomic and thread-safe using `sync/atomic`.

## Error Handling

All errors are typed for precise error handling:

```go
if err := d.RegisterService(svc); err != nil {
    switch e := err.(type) {
    case daemon.ErrServiceAlreadyRunning:
        log.Printf("Service %s already registered", e.ServiceName)
    default:
        log.Fatal(err)
    }
}
```

Available error types:
- `ErrDaemonNotRunning`
- `ErrDaemonAlreadyRunning`
- `ErrServiceNotFound`
- `ErrServiceAlreadyRunning`
- `ErrServiceNotRunning`
- `ErrConfigNotFound`
- `ErrInvalidConfig`
- `ErrProvisionFailed`
- `ErrShutdownFailed`
- `ErrInvalidServiceType`

## Thread Safety

The daemon implementation is fully thread-safe:

- Atomic operations for state management (lock-free where possible)
- RWMutex for service registry and configuration
- Channel-based pub/sub for event distribution
- Context-aware operations for cancellation

## Performance Considerations

- **Lock-Free State**: Service status uses atomic operations
- **Buffered Channels**: Event/log/metric channels are buffered (100 items)
- **Non-Blocking Publish**: Drops messages if subscriber channels are full
- **Efficient Lookups**: Service registry uses map for O(1) lookups
- **Minimal Allocations**: Pre-allocated slices where possible

## Integration Points

### Unix Socket Server

The daemon uses the `pkg/api/unix` server infrastructure:
- Root-only access by default (socket permissions: 0660)
- Optional group-based access control
- Automatic socket cleanup on start/stop
- gRPC credentials for peer authentication

### Platform Services

Integrate existing platform services by implementing `ManagedService`:
1. TPM service
2. SDN service
3. Compute orchestration service
4. DNS service
5. ACME certificate service
6. Web service
7. Attestation service

### Client Access

Clients connect via Unix socket using the generated gRPC client:

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Note: Unix domain sockets use OS-level SO_PEERCRED for authentication.
// The insecure.NewCredentials() transport is appropriate here because TLS
// is not needed over local Unix sockets. For remote gRPC connections,
// always use TLS 1.3 with proper CA certificates.

conn, err := grpc.Dial(
    "unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

client := platformv1.NewPlatformDaemonClient(conn)

// Make RPC calls
status, err := client.GetStatus(ctx, &platformv1.GetStatusRequest{})
```

## Testing

Unit tests should cover:
- Service registration and lifecycle
- State transitions
- Error conditions
- Event/log/metric publishing
- Concurrent operations

Integration tests should verify:
- End-to-end gRPC communication
- Unix socket server integration
- Multi-service coordination
- Graceful shutdown behavior

## Future Enhancements

- **Provision Integration**: Connect to existing platform provisioning logic
- **Config Updates**: Implement runtime configuration updates
- **Config Reload**: Implement configuration file reloading
- **Health Checks**: Add configurable health check probes
- **Service Dependencies**: Support service startup ordering
- **Rate Limiting**: Add rate limiting for API calls
- **Metrics Aggregation**: Built-in metrics collection and aggregation
- **Distributed Tracing**: OpenTelemetry integration

## See Also

- `pkg/api/unix` - Unix socket server infrastructure
- `pkg/api/grpc/gen` - Generated gRPC code
- Proto definitions in `pkg/api/grpc/proto/daemon.proto`
