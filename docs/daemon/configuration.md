# Daemon Configuration

Complete configuration reference for the Trusted Platform daemon.

## Configuration Structure

```yaml
daemon:
  # Core daemon settings
  socket_path: /run/platformd.sock
  socket_group: trusted-platform
  socket_mode: 0660
  shutdown_timeout: 30s
  enable_metrics: true
  enable_events: true

  # Protocol configurations
  rest: { ... }
  grpc: { ... }
  quic: { ... }
  mcp: { ... }

  # Service configurations
  services: { ... }
```

## Core Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `socket_path` | string | `/run/platformd.sock` | Unix socket file path |
| `socket_group` | string | `trusted-platform` | Unix socket group ownership |
| `socket_mode` | octal | `0660` | Unix socket file permissions |
| `shutdown_timeout` | duration | `30s` | Graceful shutdown timeout |
| `enable_metrics` | bool | `true` | Enable metrics collection |
| `enable_events` | bool | `true` | Enable event emission |

## REST Configuration

```yaml
rest:
  enabled: true
  listen_addr: "0.0.0.0:8443"
  tls_cert_file: ""
  tls_key_file: ""

  # Server timeouts
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  max_header_bytes: 1048576  # 1 MB

  # Features
  enable_cors: false
  enable_compression: true

  # CORS settings (when enabled)
  allowed_origins:
    - "*"
  allowed_methods:
    - GET
    - POST
    - PUT
    - DELETE
    - OPTIONS
  allowed_headers:
    - Accept
    - Authorization
    - Content-Type
    - X-Request-ID

  # Rate limiting (0 = disabled)
  rate_limit_requests: 0
  rate_limit_burst: 100
```

### REST Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable REST server |
| `listen_addr` | string | `0.0.0.0:8443` | HTTP listen address |
| `tls_cert_file` | string | `""` | TLS certificate file path |
| `tls_key_file` | string | `""` | TLS private key file path |
| `read_timeout` | duration | `30s` | Maximum request read time |
| `write_timeout` | duration | `30s` | Maximum response write time |
| `idle_timeout` | duration | `120s` | Keep-alive idle timeout |
| `max_header_bytes` | int | `1048576` | Maximum header size |
| `enable_cors` | bool | `false` | Enable CORS headers |
| `enable_compression` | bool | `true` | Enable gzip compression |
| `rate_limit_requests` | int | `0` | Requests per second (0=off) |
| `rate_limit_burst` | int | `100` | Rate limit burst size |

### TLS Configuration

When TLS files are provided, the REST server uses HTTPS with TLS 1.2 minimum:

```yaml
rest:
  enabled: true
  listen_addr: "0.0.0.0:8443"
  tls_cert_file: /etc/trusted-platform/certs/server.crt
  tls_key_file: /etc/trusted-platform/certs/server.key
```

TLS material is mandatory: with no in-memory certificate (provisioned at
startup from the platform CA) and no cert/key file pair, the REST server
refuses to start with `ErrRESTServerStartFailed` instead of serving plain
HTTP. The same fail-closed rule applies to gRPC TCP (`ErrTLSConfigFailed`)
and QUIC (`ErrQUICServerStartFailed`). The Unix-domain-socket transport is
the single sanctioned non-TLS carve-out — it is filesystem-permission-scoped,
not network-exposed.

## gRPC Configuration

```yaml
grpc:
  enabled: true
  listen_addr: "0.0.0.0:9443"
  tls_cert_file: ""
  tls_key_file: ""
```

### gRPC Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable gRPC TCP server |
| `listen_addr` | string | `0.0.0.0:9443` | TCP listen address |
| `tls_cert_file` | string | `""` | TLS certificate file path |
| `tls_key_file` | string | `""` | TLS private key file path |

The gRPC server always listens on the Unix socket regardless of TCP settings.

## QUIC Configuration

```yaml
quic:
  enabled: false
  listen_addr: "0.0.0.0:9444"
  # Additional QUIC settings from pkg/api/quic/config.go
```

### QUIC Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Enable QUIC server |
| `listen_addr` | string | `0.0.0.0:9444` | UDP listen address |

QUIC requires TLS and uses certificates from the platform CA or provided configuration.

## MCP Configuration

```yaml
mcp:
  enabled: false
  server_name: "Trusted Platform MCP Server"
  server_version: "1.0.0"
  transport: http
  http_addr: "127.0.0.1:9445"
  request_timeout: 30s
  max_concurrent_requests: 100
```

### MCP Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Enable MCP server |
| `server_name` | string | `Trusted Platform MCP Server` | Server name for clients |
| `server_version` | string | `1.0.0` | Platform version string |
| `transport` | string | `http` | Transport type: `stdio` or `http` |
| `http_addr` | string | `127.0.0.1:9445` | HTTP listen address |
| `request_timeout` | duration | `30s` | Default operation timeout |
| `max_concurrent_requests` | int | `100` | Concurrent request limit |

### Transport Modes

**HTTP Transport:**
```yaml
mcp:
  transport: http
  http_addr: "127.0.0.1:9445"
```

**stdio Transport:**
```yaml
mcp:
  transport: stdio
```

The `stdio` transport is used for direct CLI integration.

## Service Configuration

Each managed service can be individually configured:

```yaml
services:
  tpm:
    enabled: true
    auto_start: true
    timeout: 10s
    max_retries: 3

  vtpm:
    enabled: true
    auto_start: true
    timeout: 10s
    max_retries: 3

  ca:
    enabled: true
    auto_start: true
    timeout: 10s
    max_retries: 3

  kms:
    enabled: true
    auto_start: true
    timeout: 10s
    max_retries: 3

  sdn:
    enabled: true
    auto_start: false
    timeout: 15s
    max_retries: 3

  dns:
    enabled: true
    auto_start: false
    timeout: 10s
    max_retries: 3

  attestation:
    enabled: true
    auto_start: false
    timeout: 10s
    max_retries: 3

  compute:
    enabled: true
    auto_start: false
    timeout: 20s
    max_retries: 3

  acme:
    enabled: true
    auto_start: false
    timeout: 10s
    max_retries: 3

  webservice:
    enabled: true
    auto_start: false
    timeout: 15s
    max_retries: 3

  mcp:
    enabled: true
    auto_start: true
    timeout: 10s
    max_retries: 3
```

### Service Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | varies | Enable the service |
| `auto_start` | bool | varies | Start automatically with daemon |
| `timeout` | duration | varies | Operation timeout |
| `max_retries` | int | `3` | Maximum retry attempts |

### Default Service Configuration

| Service | Enabled | Auto-Start | Timeout |
|---------|---------|------------|---------|
| `tpm` | Yes | Yes | 10s |
| `vtpm` | Yes | Yes | 10s |
| `ca` | Yes | Yes | 10s |
| `kms` | Yes | Yes | 10s |
| `mcp` | Yes | Yes | 10s |
| `sdn` | Yes | No | 15s |
| `dns` | Yes | No | 10s |
| `attestation` | Yes | No | 10s |
| `compute` | Yes | No | 20s |
| `acme` | Yes | No | 10s |
| `webservice` | Yes | No | 15s |

## Environment Variables

Configuration can be overridden via environment variables:

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `PLATFORMD_SOCKET_PATH` | `socket_path` | Unix socket path |
| `PLATFORMD_REST_ADDR` | `rest.listen_addr` | REST listen address |
| `PLATFORMD_GRPC_ADDR` | `grpc.listen_addr` | gRPC listen address |
| `PLATFORMD_QUIC_ADDR` | `quic.listen_addr` | QUIC listen address |
| `PLATFORMD_MCP_ADDR` | `mcp.http_addr` | MCP HTTP address |

## Configuration Validation

The daemon validates configuration at startup:

| Validation | Error |
|------------|-------|
| Empty socket path | `socket path cannot be empty` |
| Non-positive shutdown timeout | `shutdown timeout must be positive` |
| Empty QUIC address when enabled | `QUIC listen address cannot be empty` |
| Empty REST address when enabled | `REST listen address cannot be empty` |
| Invalid MCP transport | `MCP transport must be 'stdio' or 'http'` |
| Empty MCP HTTP address | `MCP HTTP address cannot be empty` |
| Invalid REST timeouts | Various timeout validation errors |
| Invalid service timeout | `service X timeout must be positive` |
| Negative max retries | `service X max retries cannot be negative` |

## Example Configurations

### Development

```yaml
daemon:
  socket_path: /tmp/platformd.sock
  shutdown_timeout: 5s

  rest:
    enabled: true
    listen_addr: "127.0.0.1:8443"
    enable_cors: true
    allowed_origins:
      - "http://localhost:3000"

  grpc:
    enabled: true
    listen_addr: "127.0.0.1:9443"

  quic:
    enabled: false

  mcp:
    enabled: true
    transport: http
    http_addr: "127.0.0.1:9445"
```

### Production

```yaml
daemon:
  socket_path: /run/platformd.sock
  socket_group: trusted-platform
  socket_mode: 0660
  shutdown_timeout: 60s
  enable_metrics: true
  enable_events: true

  rest:
    enabled: true
    listen_addr: "0.0.0.0:8443"
    tls_cert_file: /etc/trusted-platform/certs/server.crt
    tls_key_file: /etc/trusted-platform/certs/server.key
    read_timeout: 30s
    write_timeout: 30s
    enable_cors: false
    enable_compression: true
    rate_limit_requests: 100
    rate_limit_burst: 200

  grpc:
    enabled: true
    listen_addr: "0.0.0.0:9443"
    tls_cert_file: /etc/trusted-platform/certs/server.crt
    tls_key_file: /etc/trusted-platform/certs/server.key

  quic:
    enabled: true
    listen_addr: "0.0.0.0:9444"

  mcp:
    enabled: false
```

### Minimal (Unix Socket Only)

```yaml
daemon:
  socket_path: /run/platformd.sock

  rest:
    enabled: false

  grpc:
    enabled: false

  quic:
    enabled: false

  mcp:
    enabled: false
```

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [README](README.md)
