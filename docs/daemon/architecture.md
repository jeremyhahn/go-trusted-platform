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
   catalogs default to deny**: an unclassified gRPC method or MCP tool is
   refused ([api.md](api.md) §5).
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
    +-- /api/v1/tpm/...     TPM routes (restapi.TPMHandlers, SetTPMHandlers)
```

Each TPM route needs a platform bearer token granting `tpm:read`, `tpm:write`
or `tpm:delete`, checked by the shared platform-token validator, and quote and
verify run on the daemon's `TPMService` ([`docs/tpm/api.md`](../tpm/api.md)
§1, §9).

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
| 0x30-0x3D | Device operations (0x3C retired) |
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
   +-- Write the public CA bundle to <platform-dir>/tls

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

`ForceStop()` follows the same order without waiting for in-flight work.

### Lifecycle guarantees

- `Start`, `Stop` and `ForceStop` each take effect once, even when called
  concurrently. Exactly one `Start` succeeds and the others return
  `ErrDaemonAlreadyRunning`. Exactly one `Stop` or `ForceStop` succeeds and
  the others return `ErrDaemonNotRunning`.
- The service's shutdown handler stops only the gRPC servers. The QUIC server
  is stopped by `Stop` or `ForceStop` alone, so a successful stop never returns
  a QUIC "server is not running" error.
- QUIC `Server.Stop` claims the stop atomically: one caller tears the server
  down and the rest get `ErrServerNotRunning`.
- The auto-start pass runs in a goroutine launched by `Start`. If `Stop` wins
  the lock first, the pass starts nothing, so no service is left running on a
  stopped daemon.

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

The services configured under `services:` are owned by the process, not by
this state machine: they are registered as `subsystemService`, whose `Start`
and `Stop` refuse with `ErrServiceNotControllable` (`FailedPrecondition`) and
whose `IsRunning` reads the subsystem itself. A refused verb leaves the
recorded state untouched ([api.md](api.md) §2).

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

The server key and certificate live in the platform CA keystore; the only
TLS file on disk is `ca-bundle.crt`, the public CA trust bundle (`0644`), in
`<platform-dir>/tls/` (mode `0700`). `provisionDaemonIdentity`
(`pkg/daemon/commands/provision_identity.go`) reuses the keystore identity
across restarts while the server certificate verifies, covers the required
SANs and is more than 30 days from expiry, and otherwise issues a new one
(§Daemon TLS identity and key custody). A running daemon renews the same
identity in the platform renewal sweep (§Daemon TLS identity renewal while
running). A daemon with no platform directory
refuses to start (`ErrTLSIdentityRequiresPlatformDir`). Provisioning issues
**no** admin client certificate: the one-shot `/init` bundle is the platform's
only admin credential ([`../bootstrap/cli.md`](../bootstrap/cli.md) §1a).

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
middleware — mTLS at the TLS layer is its only listener-wide authentication;
the CA sign-csr and `/api/v1/tpm` routes check a platform token per route — so
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
| Server key (slot `platformd.localhost` or `platformd-alt.localhost`, ECDSA P-256) | Platform CA keystore | Never written to disk. The listeners get a `tls.Certificate` whose `PrivateKey` is the keystore's `crypto.Signer`, from `CA.TLSCertificate` via the `sdk/go/xkms/ca` re-export. |
| Server certificate | Platform CA certificate store | Issued by `CA.IssueCertificate` with `KeyAttributes`, so the CA generates the key in its keystore. |
| Admin client credential | Not on disk | The one-shot `/init` reply. See below. |
| CA bundle | `<platform-dir>/tls/ca-bundle.crt`, mode 0644 | Public. Rewritten from `CA.CABundle()` on every boot. |

The identity occupies one of two keystore slots, `platformd.localhost` and
`platformd-alt.localhost`, with the same DNS SANs. On each boot both slots are
loaded from the keystore and the latest one is the held identity. It is reused
when it chains to the CA, covers the required DNS SANs and is outside the
30-day renewal window. Otherwise a fresh key and certificate are issued into
the other slot, under their own key ID. Only after that identity is loaded is
the old slot retired: its certificate is looked up on its own (`CA.Certificate`,
which does not need the key), revoked, and its key and certificate deleted. The
certificate lookup is what lets an installation upgrade from the pre-#33
PEM-backed identity, whose certificate is in the CA store but whose key never
was in the keystore ([engineering.md](engineering.md) §7).

**No admin key on disk.** The daemon mints no admin client certificate. The
operator's first credential is the one-shot `/init` reply
([`../bootstrap/cli.md`](../bootstrap/cli.md) §1a). Only a binary built with the
`integration` tag writes a test `client-bundle.pem` into `<platform-dir>/tls`
for the devcontainer harness (`harnessAdminBundle`).

**Fail closed.** The server identity is resolved before any file is written:

- A keystore that cannot clear the slot being issued into, issue or load the
  key returns `ErrTLSIdentityKeystore{Op}`. `Op` is `retire`, `issue` or `load`.
- With no platform directory, `ErrTLSIdentityRequiresPlatformDir` is returned.

In both cases no TLS material is installed in the daemon config, so no TLS
listener starts.

### Daemon TLS identity renewal while running (#36)

The boot-time check above renews an identity only when the daemon restarts.
A long-running daemon renews it in the platform certificate-renewal sweep
([`../operations/cert-lifecycle.md`](../operations/cert-lifecycle.md)). The
daemon does not run a sweep of its own.

**When it renews.** `applyDaemonTLSIdentity` registers a cert target named
`daemon.platformd`, of kind `daemon` (`daemonIdentityCertTarget`,
`pkg/daemon/commands/daemon_identity_renewal.go`). The node's
`platform.cert-renewal.<nodeID>` job runs daily at 02:00. It reissues the
target once the served certificate is within 30 days of `NotAfter`.
Reissue takes the same keystore path as boot (`issueDaemonServerIdentity`):

1. Clear any leftover in the slot that is not serving.
2. `CA.IssueCertificate` into that slot, under its own key ID.
3. `CA.TLSCertificate`.
4. Swap the served identity (`ServingCertificate.Store`).
5. Retire the old slot: revoke its certificate, then delete its key and
   certificate.

The key stays in the CA keystore, and nothing is written to disk.

**How the listeners pick it up.** The served identity is a
`daemon.ServingCertificate` (`pkg/api/daemon/serving_certificate.go`): an
`atomic.Pointer[tls.Certificate]` set through `Config.TLSIdentity`.

- gRPC TCP, REST, MCP over HTTP and QUIC build their `tls.Config` with
  `Certificates` empty and `GetCertificate` reading that pointer.
- A successful reissue swaps the pointer, so the next handshake presents the
  new certificate. No listener restarts, and the handshake path takes no lock.
- Connections already open keep the certificate they negotiated.
- The Unix socket carries no TLS and is unaffected.
- `Certificates` must stay empty. A handshake without SNI (a dial by IP
  address) takes `Certificates[0]` ahead of `GetCertificate`.

**Client role.** The daemon identity is a single certificate carrying both
the ServerAuth and ClientAuth EKUs (`daemonServerCertRequest`). Renewing it
renews the client role too, so the client role has no separate target.

**Failure.**

- A reissue that fails before the swap returns `ErrTLSIdentityKeystore{Op}` to
  the sweep. The old certificate and key keep serving, untouched. The sweep
  records the target `failed` and logs it, then retries at its next run.
- `ServingCertificate.Store` refuses an unusable certificate
  (`ErrUnusableServingCertificate`). The current certificate keeps serving, and
  the next sweep's `Current` retires the slot that was not swapped in.
- A failure to retire the old slot after the swap is logged as a warning. The
  new identity serves, and every sweep's `Current` retries the retirement of
  the slot that is not serving.
- If the target cannot be registered, boot does not fail. The identity
  serves and renews at the next restart.

The renewal never deletes a key that is serving. `IssueCertificate` refuses an
existing common name and no CA call replaces a certificate atomically, so the
new identity is issued under the other slot's common name and key ID, and the
old one is deleted only after the swap ([engineering.md](engineering.md) §7).

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
