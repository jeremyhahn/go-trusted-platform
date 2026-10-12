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

## Listen addresses — bind hosts and ports (#552, #93)

Where each transport binds is configuration, never a literal in code
(handbook `conventions/configuration.md` §3, owner ruling 2026-08-26). The
one defaults layer is **loopback on the canonical ports**; a transport reaches
an interface only because an operator named one. The keys below are the
**live** keys — `platformd serve` resolves exactly these through viper and
the listeners consume the resolved value.

```yaml
daemon:
  rest: {bind-host: 127.0.0.1, port: 8443}
  grpc: {bind-host: 127.0.0.1, port: 10443}
  quic: {bind-host: 127.0.0.1, port: 9444}
  mcp:  {bind-host: 127.0.0.1, port: 9445}
```

| Layer | Form | Example |
|---|---|---|
| Flag (wins) | `--<transport>-bind-host`, `--<transport>-port` on `platformd serve` | `--grpc-bind-host 0.0.0.0 --grpc-port 10443` |
| Environment | `PLATFORMD_DAEMON_<TRANSPORT>_BIND_HOST`, `PLATFORMD_DAEMON_<TRANSPORT>_PORT` | `PLATFORMD_DAEMON_QUIC_BIND_HOST=::` |
| File | `daemon.<transport>.bind-host`, `daemon.<transport>.port` | above |
| Defaults | `127.0.0.1` and 8443 / 10443 / 9444 / 9445 | — |

Precedence is flag > environment > file > defaults, per field: a file that
sets only a port keeps the default host, a flag that names one transport
changes nothing else, and a flag left alone never shadows the environment or
the file. `bind-host` is a host only — empty means every interface, an IP
literal also picks the address family (`tcp4`/`tcp6`), a hostname is resolved
by the listener. A value outside `1..65535`, or a host carrying a port, stops
startup with `ErrServeStartup{Phase: "daemon listener configuration"}` naming
the field.

The Unix socket (`--socket-path`) is unaffected. The webservice listeners
(`webservices[].bind-host`) are documented in [`docs/web/engineering.md`](../web/engineering.md).

> The `rest.listen_addr`, `grpc.listen_addr`, `quic.listen_addr` and
> `mcp.http_addr` keys shown in the sections below describe the in-process
> `daemon.Config` fields; they are not read from the platform YAML. Use the
> `daemon.<transport>` keys above.

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
  listen_addr: "127.0.0.1:8443"
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
| `listen_addr` | string | `127.0.0.1:8443` | HTTP listen address — set via `daemon.rest` (see Listen addresses) |
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
  listen_addr: "127.0.0.1:8443"
  tls_cert_file: /etc/trusted-platform/certs/server.crt
  tls_key_file: /etc/trusted-platform/certs/server.key
```

TLS material is mandatory: with no in-memory certificate (provisioned at
startup from the platform CA) and no cert/key file pair, the REST server
refuses to start with `ErrRESTServerStartFailed` instead of serving plain
HTTP. The same fail-closed rule applies to gRPC TCP (`ErrTLSConfigFailed`)
and QUIC (`ErrQUICServerStartFailed`, or `ErrTransportConstructionFailed`
from `New` when the QUIC config carries no TLS at all, #444). The
Unix-domain-socket transport is
the single sanctioned non-TLS carve-out — it is filesystem-permission-scoped,
not network-exposed.

## gRPC Configuration

```yaml
grpc:
  enabled: true
  listen_addr: "127.0.0.1:10443"
  tls_cert_file: ""
  tls_key_file: ""
```

### gRPC Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable gRPC TCP server |
| `listen_addr` | string | `127.0.0.1:10443` | TCP listen address — set via `daemon.grpc` (see Listen addresses) |
| `tls_cert_file` | string | `""` | TLS certificate file path |
| `tls_key_file` | string | `""` | TLS private key file path |

The gRPC server always listens on the Unix socket regardless of TCP settings.

## QUIC Configuration

```yaml
quic:
  enabled: false
  listen_addr: "127.0.0.1:9444"
  # Transport tuning (stream limits, idle timeout, keep-alive) is not
  # YAML-configurable: it comes from DefaultServerConfig in
  # pkg/api/quic/config.go, with listen_addr applied on top.
```

### QUIC Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `false` | Enable QUIC server |
| `listen_addr` | string | `127.0.0.1:9444` | UDP listen address — set via `daemon.quic` (see Listen addresses) |

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
| `transport` | string | `http` | Transport type: `stdio` or `http` (`http` serves HTTPS, TLS 1.3 only) |
| `http_addr` | string | `127.0.0.1:9445` | HTTPS listen address — set via `daemon.mcp` (see Listen addresses) |
| `request_timeout` | duration | `30s` | Default operation timeout |
| `max_concurrent_requests` | int | `100` | Concurrent request limit |

### Transport Modes

**HTTP Transport (HTTPS, TLS 1.3 only):**
```yaml
mcp:
  transport: http
  http_addr: "127.0.0.1:9445"
```

The listener presents the daemon TLS identity that REST and gRPC present, under
the same `EnableMTLS` client-certificate policy. It has no TLS setting of its
own and no plaintext mode; without a usable daemon certificate the daemon
refuses to start (`ErrTLSConfigFailed`). See [`api.md`](api.md) §5.

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

The environment layer is `PLATFORMD_` + the config key with every `.` and
`-` as `_` (`tpconfig.BindDaemonListenerEnv`, installed by the root command).
Only keys viper already knows — defaults, flags or the file — are read from
the environment.

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `PLATFORMD_DAEMON_REST_BIND_HOST` / `_PORT` | `daemon.rest.bind-host` / `.port` | REST bind host / port |
| `PLATFORMD_DAEMON_GRPC_BIND_HOST` / `_PORT` | `daemon.grpc.bind-host` / `.port` | gRPC bind host / port |
| `PLATFORMD_DAEMON_QUIC_BIND_HOST` / `_PORT` | `daemon.quic.bind-host` / `.port` | QUIC bind host / port |
| `PLATFORMD_DAEMON_MCP_BIND_HOST` / `_PORT` | `daemon.mcp.bind-host` / `.port` | MCP bind host / port |

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

### Required keys at load

`platformd` checks the keys it cannot start without when it loads the config
file, before it constructs the QuicBaaS factory. A failure is a
`config.ErrInvalidConfigKey` that names the file and the dotted key:

```
config file "/etc/trusted-platform/config.yaml": key quicbaas.spiffe-trust-domain: invalid configuration: SPIFFETrustDomain: spiffe-trust-domain is required for the embedded server: ...
```

| Key | Required when | Why |
|-----|---------------|-----|
| `quicbaas.spiffe-trust-domain` | the embedded server is selected: `quicbaas.transport` is `embedded` or unset, **or the `quicbaas:` section is absent** | qrdb first boot seeds IAM (system tenant, roles, admin certificate) under this trust domain. It must be a lowercase name with no scheme, port or path. |
| `quicbaas.transport` | set | It must be `embedded`, `unix`, `grpc`, `rest` or `quic`. |

The remote transports (`unix`, `grpc`, `rest`, `quic`) run no first boot, so
they do not need a trust domain. No default applies: a config that leaves the
key out is rejected, even if a code-level `App` literal carries a placeholder.
The bootstrap seeder fills the key from `platform.internal_domain` (see
[bootstrap engineering](../bootstrap/engineering.md)).

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
    listen_addr: "127.0.0.1:8443"
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
    listen_addr: "127.0.0.1:10443"
    tls_cert_file: /etc/trusted-platform/certs/server.crt
    tls_key_file: /etc/trusted-platform/certs/server.key

  quic:
    enabled: true
    listen_addr: "127.0.0.1:9444"

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
