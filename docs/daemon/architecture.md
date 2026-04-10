# Daemon Architecture

## System Overview

```
+-----------------------------------------------------------------------------------+
|                              Trusted Platform Daemon                               |
|                               (pkg/api/daemon/)                                    |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                          Protocol Layer                                     |  |
|  |                                                                             |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |  |   REST    |  |   gRPC   |  |  QUIC   |  |   MCP   |  |  Unix Socket  |   |  |
|  |  | HTTP/TLS  |  |   TCP    |  |   UDP   |  |  HTTP/  |  | /run/platformd|   |  |
|  |  | Port 8443 |  | Port 9443|  |Port 9444|  |  stdio  |  |    .sock      |   |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |       |              |             |            |              |            |  |
|  +-------|--------------|-------------|------------|--------------|------------+  |
|          |              |             |            |              |               |
|          v              v             v            v              v               |
|  +-----------------------------------------------------------------------------+  |
|  |                         Service Layer                                       |  |
|  |                                                                             |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |  |    CA     |  |   vTPM   |  | Device  |  |   SDN   |  |      KMS      |   |  |
|  |  |  Service  |  | Service  |  | Service |  | Service |  |    Service    |   |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |                                                                             |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |  |    DNS    |  | Attestat |  | Compute |  |   IAM   |  |    Tenant     |   |  |
|  |  |  Service  |  | Service  |  | Service |  | Service |  |    Service    |   |  |
|  |  +-----------+  +----------+  +---------+  +---------+  +---------------+   |  |
|  |                                                                             |  |
|  +-----------------------------------------------------------------------------+  |
|                                      |                                            |
|                                      v                                            |
|  +-----------------------------------------------------------------------------+  |
|  |                        Health Registry                                      |  |
|  |                   (Component Health Monitoring)                             |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

## Components

### Daemon Core

The `Daemon` struct (`daemon.go`) manages the complete lifecycle:

| Component | Description |
|-----------|-------------|
| `config` | Daemon configuration |
| `server` | Unix socket gRPC server |
| `grpcServer` | TCP gRPC server |
| `quicServer` | QUIC protocol server |
| `restServer` | REST HTTP server |
| `mcpServer` | MCP protocol server |
| `service` | Core daemon service implementation |
| `healthRegistry` | Unified health checking |

### Protocol Servers

#### REST Server

The REST server (`rest_service.go`) provides HTTP/HTTPS access:

```
REST Server
    |
    +-- /api/v1/health      GET  - Health check
    +-- /api/v1/status      GET  - Daemon status
    +-- /api/v1/version     GET  - Version info
    +-- /api/v1/services    GET  - List services
    +-- /api/v1/services/{service}        GET  - Get service
    +-- /api/v1/services/{service}/start  POST - Start service
    +-- /api/v1/services/{service}/stop   POST - Stop service
    +-- /api/v1/services/{service}/restart POST - Restart service
    +-- /api/v1/protocols   GET  - Protocol status
```

**Middleware Stack:**
- Request ID generation
- Request logging
- CORS handling (optional)
- Gzip compression (optional)

#### gRPC Server

Two gRPC servers are available:

| Server | Transport | Purpose |
|--------|-----------|---------|
| Unix Socket | /run/platformd.sock | Local CLI communication |
| TCP | Port 9443 | Remote service-to-service |

Both expose the `PlatformDaemon` service with registered subsystem services (CA, vTPM, Device, etc.).

#### QUIC Server

The QUIC server (`quic_service.go`) provides low-latency UDP transport:

| Opcode Range | Service |
|--------------|---------|
| 0x00-0x02 | Health operations |
| 0x10-0x1F | vTPM operations |
| 0x20-0x2F | DNS operations |
| 0x30-0x3F | Device operations |
| 0x80-0x8F | Certificate operations |
| 0xA0-0xAF | CA operations |

#### MCP Server

The MCP server (`mcp_service.go`) enables AI/LLM integration via the Model Context Protocol:

**Supported Tool Categories:**
- vTPM operations (create, delete, list, start, stop)
- CA operations (issue, revoke, renew, verify)
- Device operations (register, get, list, delete)
- SDN operations (bridges, ports, VLANs, flows)
- DNS operations (zones, records)
- Health operations (health, liveness, readiness)

## Startup Sequence

```
1. Create()
   |
   +-- Validate configuration
   +-- Create daemon service
   +-- Create Unix socket server
   +-- Register platform daemon service
   |
   +-- If gRPC TCP enabled:
   |   +-- Create gRPC server
   |   +-- Register services
   |
   +-- If QUIC enabled:
   |   +-- Create QUIC handler
   |   +-- Create QUIC server
   |
   +-- If REST enabled:
   |   +-- Create REST server
   |
   +-- If MCP enabled:
   |   +-- Create MCP service provider
   |   +-- Create MCP server
   |
   +-- Create health registry
   +-- Register health checkers
   +-- Wire health registry to service

2. Start()
   |
   +-- Connect SDN service (if available)
   +-- Start KMS service (if available)
   +-- Start IAM service (if available)
   +-- Start Tenant service (if available)
   +-- Start REST server (if enabled)
   +-- Start MCP server (if enabled)
   +-- Start Unix socket server
   +-- Start gRPC TCP server (if enabled)
   +-- Start QUIC server (if enabled)
   +-- Auto-start configured services
   +-- Mark daemon ready
```

## Shutdown Sequence

```
Stop()
   |
   +-- Close health registry
   +-- Stop QUIC server
   +-- Stop REST server
   +-- Stop MCP server
   +-- Stop Tenant service
   +-- Stop IAM service
   +-- Stop KMS service
   +-- Disconnect SDN service
   +-- GracefulStop gRPC server
   +-- Close gRPC listener
   +-- Shutdown via service
```

## Health Checking

The daemon maintains a centralized health registry with checkers for all enabled components:

```
Health Registry
    |
    +-- CA Service Health Checker
    +-- SDN Service Health Checker
    +-- KMS Service Health Checker
    +-- IAM Service Health Checker
    +-- Tenant Service Health Checker
    +-- QUIC Server Health Checker
    +-- REST Service Health Checker
    +-- MCP Service Health Checker
```

### Health Check Flow

```
Client          REST/gRPC/QUIC          Health Registry         Checkers
   |                  |                        |                    |
   | GET /health      |                        |                    |
   |----------------->|                        |                    |
   |                  | Check()                |                    |
   |                  |----------------------->|                    |
   |                  |                        | Check(ctx)         |
   |                  |                        |------------------->|
   |                  |                        |                    |
   |                  |                        | ComponentHealth    |
   |                  |                        |<-------------------|
   |                  | SystemHealth           |                    |
   |                  |<-----------------------|                    |
   | Response         |                        |                    |
   |<-----------------|                        |                    |
```

## Service Management

### Service State Machine

```
     +----------+
     | Stopped  |
     | (0)      |
     +----+-----+
          |
          | Start()
          v
     +----------+
     | Starting |
     | (1)      |
     +----+-----+
          |
          | Success
          v
     +----------+       Stop()       +----------+
     | Running  |-------------------->| Stopping |
     | (2)      |                     | (3)      |
     +----+-----+                     +----+-----+
          |                                |
          | Error                          | Success
          v                                v
     +----------+                    +----------+
     | Error    |                    | Stopped  |
     | (4)      |                    | (0)      |
     +----------+                    +----------+
```

### ManagedService Interface

All managed services implement:

```go
type ManagedService interface {
    Name() string
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    IsRunning() bool
    Health(ctx context.Context) (health.ComponentHealth, error)
}
```

## Protocol Feature Matrix

| Feature | REST | gRPC | QUIC | MCP | Unix |
|---------|------|------|------|-----|------|
| Health Check | Yes | Yes | Yes | Yes | Yes |
| Service Management | Yes | Yes | No | Yes | Yes |
| CA Operations | Partial | Yes | Yes | Yes | Yes |
| vTPM Operations | No | Yes | Yes | Yes | Yes |
| Device Operations | No | Yes | Yes | Yes | Yes |
| SDN Operations | No | Yes | No | Yes | Yes |
| TLS Support | Yes | Yes | Required | No | N/A |
| Streaming | No | Yes | No | No | Yes |
| Binary Protocol | No | Yes | Yes | No | Yes |

## Configuration Files

| File | Description |
|------|-------------|
| `config.go` | Configuration structs and defaults |
| `daemon.go` | Core daemon lifecycle |
| `rest_service.go` | REST HTTP server and handlers |
| `quic_service.go` | QUIC protocol handler |
| `mcp_service.go` | MCP service provider bridge |

## Thread Safety

The daemon uses several synchronization mechanisms:

| Component | Mechanism |
|-----------|-----------|
| Daemon state | `sync.RWMutex` + `atomic.Bool` |
| Service states | Per-service `sync.RWMutex` |
| REST running state | `atomic.Bool` |
| Health registry | Internal synchronization |
| gRPC server | Built-in thread safety |

## Error Handling

All daemon errors are defined as typed errors:

| Error | Description |
|-------|-------------|
| `ErrDaemonAlreadyRunning` | Daemon start when already running |
| `ErrDaemonNotRunning` | Daemon stop when not running |
| `ErrInvalidConfig` | Configuration validation failed |
| `ErrServiceNotFound` | Unknown service name |
| `ErrServiceAlreadyRunning` | Service start when running |
| `ErrServiceNotRunning` | Service stop when not running |
| `ErrRESTServerStartFailed` | REST server startup failure |
| `ErrQUICServerStartFailed` | QUIC server startup failure |
| `ErrHealthRegistryNotConfigured` | Health check without registry |
