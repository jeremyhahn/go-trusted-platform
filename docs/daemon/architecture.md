# Daemon Architecture

> **Status: NORMATIVE** · Scope: `pkg/api/daemon/`, `pkg/api/{grpc,rest,quic,mcp,noise,tpmnv}/`, `cmd/*` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> [api.md](api.md) carries the **canonical QUIC category-opcode table** and the
> platform-wide authorization picture. Other feature folders link there.
>
> **Verification scope.** Binary set, package layout, RPC lists, route
> registration, transport constants and both authorization catalogs were checked
> against code on 2026-08-18. The diagrams below predate the migration.

## The problem

The platform has to be usable by a human at a shell, a Go program in the same
process, a desktop GUI, a service over the network, a machine that has not
finished booting, and an AI agent — and every one of them has to get the *same*
answer from the *same* logic.

## The shape chosen

**One daemon, six transports, shared services underneath.**

`pkg/api/daemon/` is the composition point. Each transport is an adapter that
decodes, delegates to a shared service, and encodes. The QUIC layer states the
rule for its own area: handlers *"decode the platform.v1 pb request and delegate
to the shared `*ComputeGRPCService`… the same business path the gRPC transport
uses."*

Roles are **configuration**: `platformd` is control-plane or worker by config,
`gatewayd` is the edge. Six binaries, three roles.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **A binary per node role** | Three binaries to build, sign, attest and keep in step, differing only in configuration. Roles are config; the binary set does not grow with the role set. |
| **A transport per daemon** | Six daemons sharing state, or six copies of the logic. Either way the answers drift and there is no single place to fix one. |
| **Business logic in the handlers** | Logic in a REST handler exists on REST only. Every transport is an adapter over a shared service, which is what makes six-transport parity even checkable. |
| **404 for a disabled capability** | Indistinguishable from "does not exist". An unwired service answers **503** with a structured envelope, so an operator can tell configuration from a bug. The `*_service_stub.go` files are the mechanism. |
| **Letting a panicking handler drop the connection** | The client sees a bare EOF and cannot tell a crash from a network fault. Both QUIC and gRPC recover a panic into an internal-error response and log the stack. |
| **A separate GUI binary** | The GUI would drift from the CLI by construction. One binary, one bindings layer, GUI compiled out by default — so a service change that skips `bindings_*.go` is a visible omission rather than a separate product. |
| **A flat QUIC opcode space** | 319 opcodes do not fit in one byte. Category opcodes multiplex a sub-opcode from the payload, which is why values legitimately repeat across namespaces ([api.md](api.md) §4). |

## Component boundaries

| Piece | Location |
|---|---|
| Composition, shared services, transport wiring | `pkg/api/daemon/` (~130 non-test files) |
| gRPC server, interceptors, scope catalog | `pkg/api/grpc/` |
| REST servers | `pkg/api/rest/`, `pkg/webservice/v1/` |
| QUIC server and protocol | `pkg/api/quic/` |
| MCP server and tools | `pkg/api/mcp/` |
| Noise protocol surface | `pkg/api/noise/` |
| TPM NV access surface | `pkg/api/tpmnv/` |
| SDK transports | `sdk/go/transport/{embedded,unix,grpc,rest,quic,mcp}/` |
| Binaries | `cmd/{platformd,gatewayd,platformctl,pxeboot,platform-initrd,deployer-pin}/` |
| **Architecture guards** | `pkg/arch/layerguard_test.go`, `pkg/arch/gatewayguard_test.go` |

The §R capability row is *"Platform cluster, node state, daemon operations"*,
Tier 1, reached through `services/cluster` and `services/daemon`.

**Two guard tests are normative.** `layerguard_test.go` forbids direct imports of
the four lower-layer modules, `_test.go` files included;
`gatewayguard_test.go` bounds `gatewayd`'s import closure so the binary
terminating untrusted traffic does not acquire the whole platform's dependency
tree. A guard failure is an architecture violation, not a flaky test.

**Two run paths, one wiring.** `platformd serve` composes `daemon.Config` on
one of two paths: `runWithWebservices` when a `webservices:` section exists,
`runDaemonOnly` otherwise (`pkg/daemon/commands/serve.go`). Both serve gRPC,
Unix and MCP, so every service those transports register is built by a helper
**both** paths call — never inline in one of them. A service the daemon-only
path skips is registered as its stub and answers every RPC with an error on a
node that is otherwise configured for it (#544: attestation and the OCI
registry). Only REST-only consumers belong to `runWithWebservices` alone.

## Trust boundaries

1. **Client → daemon.** Crossed by mTLS (`mtls_interceptor.go`), a broker token
   (`platform_token_validator.go`), OIDC (`oidc_interceptor.go`), or Unix socket
   peer credentials (`pkg/util/peercred`) depending on transport.
2. **Token → authorization.** The platform **validates** tokens; it does not run
   a token-authorization engine. RBAC decisions belong to the stack.
3. **Scope enforcement.** Per operation on gRPC, QUIC and MCP — and **both
   catalogs default to allow** ([api.md](api.md) §5).
4. **Embedded mode has no transport boundary at all.** In-process callers are
   inside the trust boundary by construction; that is what makes embedded mode
   fast and what makes it unsuitable for anything untrusted.
5. **`gatewayd`.** Its import closure is guarded because it sits at the edge.

## What this feature deliberately does not do

- **It does not add a binary per role.**
- **It does not put business logic in transport handlers.**
- **It does not decide token authorization.**
- **It does not return 404 for a disabled capability.**
- **It does not ship the GUI as a separate product.**

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
0. platformd serve: applyDaemonTLSIdentity()
   |
   +-- Load or issue the server identity in the CA keystore
   +-- Write the admin bootstrap bundle and CA bundle to <platform-dir>/tls

1. Create()
   |
   +-- Validate configuration
   +-- Create daemon service
   +-- If sdn.overlay.ipsec enabled:
   |   +-- Build ipsec.Service, install the fail-closed floor
   |   +-- Refuse to start if either fails (ConfigError / FloorError)
   +-- If sdn.overlay enabled:
   |   +-- Start the overlay controller (registers the VTEP; a failure is logged)
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
   +-- Run overlay IPsec: charon runner, fabric watch, CRL feed (if enabled)
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
   +-- Stop overlay IPsec (the fail-closed floor stays installed)
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
| TLS Support | Required | Required | Required | No (loopback) | N/A (UDS carve-out) |
| Streaming | No | Yes | No | No | Yes |
| Binary Protocol | No | Yes | Yes | No | Yes |

**An enabled transport that cannot be constructed or started stops the
daemon (#444).** There is no degraded mode: `New` returns
`ErrTransportConstructionFailed` (naming the transport and wrapping the
cause) when the QUIC, REST or MCP server cannot be built, `Start` returns the
transport's typed start error (`ErrQUICServerStartFailed`,
`ErrRESTServerStartFailed`, `MCPServerStartError`, `ErrTLSConfigFailed`), and
`platformd` exits non-zero through `ErrServeStartup`. gRPC TCP and Unix obey
the same rule through their own errors. A transport that is not enabled is
never constructed and never fails the daemon; a `With*Server` replacement
stands in for the built-in server it replaces.

Network transports fail closed (#32): absent TLS material, REST, gRPC TCP
and QUIC refuse to start with a typed error and bind no listener; QUIC
without TLS material cannot even be constructed, and MCP over HTTP without
the daemon's certificate is refused by `New` (#844). The
Unix-domain-socket transport is the single sanctioned non-TLS carve-out
(filesystem-permission-scoped); MCP binds loopback only. With no
TLS-terminating transport enabled (UDS-only mode), startup proceeds without provisioning a TLS identity.

Network transports also fail closed on **authentication** (#550, #312). With
`SkipIAMValidation` off, gRPC TCP and QUIC refuse to be constructed — `New`
returns `ErrTransportAuthRequired` naming the transport — whenever no
authentication backend exists: neither the shared platform-token validator,
nor the QuicBaaS service, nor a platform JWT verifier (the state a node is in
when its IAM wiring failed). When a backend exists the token interceptor is
installed with `WithRequireAuth(true)` unconditionally. mTLS is enforced the
same way: `EnableMTLS` with no CA service (gRPC) or no resolvable client CA
pool (gRPC, QUIC, REST) is a typed error, never a listener that merely does
not ask for a client certificate. The daemon REST server has no token
middleware — mTLS at the TLS layer is its only authentication — so
`EnableREST` without `EnableMTLS` is refused by both `New` and
`RESTServer.Start`; in daemon-only mode `platformd serve --enable-rest`
therefore requires `--enable-mtls`. `SkipIAMValidation` (testing only) is the
single explicit opt-out, mirroring MCP (#440); before #550 the interceptors
were installed with `WithRequireAuth(tokenValidator != nil)` and the whole
daemon API was served anonymously in that state. The Unix-domain-socket
transport is unaffected: peer-credential authentication is unconditional.

### Daemon TLS identity and key custody (#33)

`platformd serve` provisions the daemon identity in `applyDaemonTLSIdentity`
(`pkg/daemon/commands/serve.go`), before `Create()`. The work is done by
`provisionDaemonIdentity` (`pkg/daemon/commands/provision_identity.go`).

| Material | Where it lives | Notes |
|----------|----------------|-------|
| Server key (`platformd.localhost`, ECDSA P-256) | Platform CA keystore | Never written to disk. The listeners get a `tls.Certificate` whose `PrivateKey` is the keystore's `crypto.Signer`, from `CA.TLSCertificate` via the `sdk/go/xkms/ca` re-export. |
| Server certificate | Platform CA certificate store | Issued by `CA.IssueCertificate` with `KeyAttributes`, so the CA generates the key in its keystore. |
| Admin bootstrap bundle | `<platform-dir>/tls/client-bundle.pem`, mode 0600 | The one key on disk. See below. |
| CA bundle | `<platform-dir>/tls/ca-bundle.crt`, mode 0644 | Public. Rewritten from `CA.CABundle()` on every boot. |

On each boot the server identity is loaded from the keystore. It is reused
when it chains to the CA, covers the required DNS SANs and is outside the
30-day renewal window. Otherwise it is superseded: the stored certificate is
looked up on its own (`CA.Certificate`, which does not need the key),
`RevokeCert` with `DeleteKeys` revokes it and destroys any old key, and a fresh
key and certificate are issued. The certificate lookup is what lets an
installation upgrade from the pre-#33 PEM-backed identity, whose certificate is
in the CA store but whose key never was in the keystore
([engineering.md](engineering.md) §7).

**Why the admin bundle stays on disk.** It is the client credential an
operator (or the integration harness) hands to `platformctl` for the first mTLS
connection, before any other identity exists. It therefore has to be a file a
separate process can read. It is client-auth only, signed by the platform CA,
and lives in the 0700 `<platform-dir>/tls` directory rather than `/tmp`.

**Fail closed.** The server identity is resolved before any file is written:

- A keystore that cannot issue, load or supersede the key returns
  `ErrTLSIdentityKeystore{Op}`. `Op` is `issue`, `load` or `supersede`.
- With no platform directory, `ErrTLSIdentityRequiresPlatformDir` is returned.

In both cases no TLS material is installed in the daemon config, so no TLS
listener starts.

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
