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

**With a `webservices:` section there is one REST listener.** The daemon runs
no REST listener of its own (`EnableREST` false) but still builds its route
table (`Config.RESTRoutesOnly`). `runWithWebservices` hands the daemon to the
webservice registry (`RegistryParams.DaemonRESTRoutes`), and the webservice
router mounts every daemon route group under `/api/v1`: health, version,
services, protocols, BMC, ceremony, PIV, LUKS, FIDO2, cluster, IDevID/IAK,
config delivery, and the `pkg/api/rest` groups (proxy, SDN, gateway, overlay,
NTP, VPN, app services, devices, tenants, KMS, compute, CA, auth factors, TPM,
vTPM) (`RESTServer.MountOwnedRoutes`, `pkg/webservice/v1/daemon_routes.go`).
The webservice mounts them after its own routes, so a path it serves itself
keeps the webservice handler and the daemon group fills only the rest. Those
routes keep the contract they have on the daemon's own listener: a request
whose TLS handshake verified no client certificate is refused with 401
(`ErrDaemonRouteClientCertRequired`), and a verified certificate that does not
chain to the daemon's own client roots is refused with 403
(`ErrDaemonRouteClientCertUntrusted`). The webservice handshake verifies against
a wider pool than the daemon does: its `ClientCAs` also hold the attestation
caller-admission anchors (`trustCallerAnchors`), so that reporting servers reach
the caller policy. A chain to one of those anchors is not a daemon client. The
gate re-verifies the leaf for client authentication against
`DaemonRESTRoutes.ClientCAs()`, the pool the daemon's own listeners use: the
admin trust pool `applyDaemonTLSIdentity` provisions from the platform anchor
(`Config.MTLSClientCAPool`). A daemon with no such pool has no client it could
admit, and `MountDaemonRESTRoutes` refuses to mount its routes
(`ErrDaemonRouteNoClientRoots`).
A certificate that chains to those roots is not, by itself, authority to change
the CA or the node: the platform anchor also issues user certificates. The
privileged daemon CA routes therefore also take the authorization of their
webservice twin, and every other state-changing or inventory route of a group
whose handlers check nothing themselves takes the admin role and the scope its
MCP and gRPC operation takes, through the
webservice's own admin gate and scope check (`privilegedDaemonRoutes`,
`privilegedDaemonMethodRoutes`, `Router.daemonRouteAuthorizer`). A caller without a session is refused with 401,
and a caller without the admin role or the scope is refused with 403, before the
daemon handler runs:

| Replayed daemon route | Requires |
|-----------------------|----------|
| `POST`/`GET /ca/certificates`, `GET /ca/certificates/{serial}` | admin |
| `POST /ca/certificates/{serial}/revoke` | admin + `certs:revoke` |
| `POST /ca/certificates/{serial}/renew` | admin + `certs:generate` |
| `POST /ca/certificates/verify` | admin + `certs:read` |
| `POST /ca/sign-csr` | admin + `ca:sign-csr` (and the daemon's own token check) |
| `GET /ca/info`, `/ca/crl`, `/ca/bundle` | client certificate only (public twins) |
| `PUT /tenants/{id}/security/mfa-policy` | admin (no scope names it) |
| `GET /tenants/{id}/security/mfa-policy` | client certificate only (the login flow reads it) |
| `POST /users/{id}/factors/mtls/issue-cert` | client certificate and a webservice session, then the handler: the session is the user or holds the admin role, and the CSR is bound to the user (below) |
| `GET /health`, `/version`, `/protocols`, `/services`, `/services/{service}` | admin + `platform:read` |
| `POST /services/{service}/start`, `/stop`, `/restart` | admin + `platform:write` |
| `GET /bmc/{profileID}/power`, `/boot-device`, `/virtual-media`, `/sensors`, `/system-info`, `/provision`, `/cert`, `/users` | admin + `bmc:read` |
| `POST /bmc/{profileID}/power` | admin + `bmc:power` |
| `POST /bmc/{profileID}/boot-device` | admin + `bmc:write` |
| `POST`/`DELETE /bmc/{profileID}/virtual-media` | admin + `bmc:media` |
| `POST /bmc/{profileID}/provision`, `/enroll`, `/cert/restore`, `/users`; `PUT /bmc/{profileID}/cert`; `DELETE /bmc/{profileID}/users/{slot}`; `PUT .../users/{slot}/password`, `/privilege` | admin + `bmc:admin` |
| `GET /cluster/status`, `/cluster/nodes` | admin + `cluster:read` |
| `POST /cluster/bootstrap`, `/join`, `/leave` | admin + `cluster:write` |
| `POST /ceremony/init`, `/claim-cert/begin`, `/claim-cert/complete`, `/claim-share/begin`, `/claim-share/complete`, `/sign-csr` | admin + `ceremony:write` |
| `GET /ceremony/status` | client certificate only (custodians follow the ceremony; gRPC serves it pre-auth) |
| `GET /piv/devices`, `/piv/devices/{device}/slots`, `/piv/slots/{slot}`; `POST /piv/slots/{slot}/attest` | admin + `piv:read` |
| `POST /piv/slots/{slot}/generate`, `/import`, `/sign`; `POST /piv/devices/{device}/reset` | admin + `piv:write` |
| `GET /luks/status`, `/info`, `/slots`; `POST /luks/keys/test-unlock` | admin + `luks:read` |
| `POST /luks/enroll/passphrase`, `/fido2`, `/tpm`, `/recovery`; `POST /luks/passphrase/change` | admin + `luks:write` |
| `POST /luks/keys/remove` | admin + `luks:delete` |
| `GET /fido2/devices`, `/fido2/devices/wait`, `/fido2/devices/{device}` | admin + `fido2:read` |
| `POST /fido2/register`, `/authenticate` | admin + `fido2:write` |
| `GET /tpm/device/attributes`, `/tpm/iak`, `/tpm/iak/exists`, `/tpm/iak/cert`, `/tpm/idevid`, `/tpm/idevid/exists`, `/tpm/idevid/cert` | admin + `idevid:read` |
| `POST /tpm/iak/generate`, `/csr`, `/install`; `POST /tpm/idevid/generate`, `/csr`, `/install`; `POST /idevid/ldevid` | admin + `idevid:write` |
| `DELETE /tpm/iak`, `/tpm/iak/cert`, `/tpm/idevid`, `/tpm/idevid/cert` | admin + `idevid:delete` |
| `GET /provisioning/sessions`, `/provisioning/sessions/{sessionID}` | admin + `provisioning:read` |
| `POST /provisioning/sessions/{sessionID}/fulfill` | admin + `provisioning:write` |
| `POST /provisioning/config`, `/provisioning/sign`; `GET /provisioning/config/nonce`, `/provisioning/sessions/{sessionID}/poll` | client certificate only (the machine authenticates in the request: nonce, EAB HMAC, EK binding) |
| `GET /devices`, `/devices/{id}`, `/devices/{id}/state`, `/devices/serial/{serial}`, `/devices/profiles`, `/devices/profiles/{id}` | admin + `device:read` |
| `POST /devices`, `/devices/profiles`, `/devices/{id}/activate`, `/devices/{id}/attest`; `PUT /devices/{id}`, `/devices/profiles/{id}` | admin + `device:write` |
| `DELETE /devices/{id}`, `/devices/profiles/{id}` | admin + `device:delete` |
| `GET /kms/keys`, `/kms/keys/{id}`, `/kms/keys/{id}/export`, `/kms/keys/{id}/versions`, `/kms/status`; `POST /kms/decrypt`, `/batch-decrypt`, `/verify`, `/hash`, `/random` | admin + `kms:read` |
| `POST /kms/keys`, `/kms/keys/import`, `/kms/keys/{id}/rotate`, `/kms/encrypt`, `/batch-encrypt`, `/rewrap`, `/sign`, `/hmac` | admin + `kms:write` |
| `DELETE /kms/keys/{id}` | admin + `kms:delete` |
| `GET /sdn/overlay/status`, `/vteps`, `/vteps/{node_id}`, `/vnis`, `/tunnels`, `/macs` | admin + `sdn:read` |
| `POST /sdn/overlay/vnis`; `DELETE /sdn/overlay/macs/{mac}` | admin + `sdn:write` |
| `DELETE /sdn/overlay/vnis/{vni}` | admin + `sdn:delete` |
| `DELETE /sdn/gateway/bgp/prefixes/{prefix}`, `/sdn/gateway/ipam/allocations/{ip}` | admin + `sdn:write` (as MCP `gateway_bgp_withdraw`, `gateway_ipam_release`) |
| every other `/proxy/...` route | admin + `proxy:read` (`GET`, `HEAD`), `proxy:write` (`POST`, `PUT`, `PATCH`) or `proxy:delete` (`DELETE`) |
| every other `/sdn/...` route, `/sdn/gateway/...` included | admin + `sdn:read`, `sdn:write` or `sdn:delete`, by method as above |
| every `/vtpm/...` route | admin + `vtpm:read`, `vtpm:write` or `vtpm:delete`, by method as above |
| every `/ntp`, `/vpn`, `/cache`, `/scheduler`, `/messaging`, `/object-storage`, `/compute`, `/tpm` and `/tenants` route not named above | a webservice session, any role (the daemon handler checks the tenant and scope itself) |
| any other method or route | refused: 403 `ErrDaemonRouteUnclassified` |

`guardPrivilegedDaemonRoutes` classifies each method of each replayed route
(`classifyDaemonRoute`), in this order: the template table
(`privilegedDaemonRoutes`), the method table (`privilegedDaemonMethodRoutes`),
issue-cert (`callerCheckedDaemonMethodRoutes`), the client-certificate-only
routes (`certificateOnlyDaemonMethodRoutes`), the admin groups `proxy`, `sdn`
and `vtpm` (`adminDaemonGroups`, scope by method), and the daemon-scoped groups
(`daemonScopedGroups`). A method or route none of them names is denied: the
webservice answers 403 `ErrDaemonRouteUnclassified` and the daemon handler never
runs, so a group the daemon gains is closed until it is classified.

The scope of each non-CA route is the scope its MCP and gRPC operation takes
(`pkg/api/mcp/authz.go`). The admin-group and table daemon handlers check no
authorization themselves, so the replay gate is the only check on the
webservice. The daemon-scoped groups take a session only, as their handlers
check the tenant and scope themselves (`ntp_handlers.go`, `vpn_handlers.go`,
`app_service_handlers.go`, `compute_handlers.go`, `tpm_handlers.go`,
`tenant_handlers.go`), and an admin gate there would lock tenant users out.
With the webservice CA configured, its own handlers shadow every CA route
except `POST .../{serial}/revoke`, which only the daemon serves.
`TestPrivilegedDaemonRoutes_CoverTheDaemonCATable` fails if the daemon gains a CA
route that is in neither set. Every other gated route is gated per method
(`privilegedDaemonMethodRoutes`, keyed `METHOD template`).
`TestPrivilegedDaemonMethodRoutes_NameDaemonRoutes` fails if an entry stops
naming a replayed daemon route or an auth-factor route, and
`TestRegisterRoutes_DaemonMethodEntriesTakeAdminAndScope` sends each entry a
request without a session (401), from a non-admin holding the scope (403), from
an admin without the scope (403) and from an admin holding it (served).

Issue-cert is not in the admin gate, as a user issues for themselves. It takes
the webservice login check instead (`callerCheckedDaemonMethodRoutes`,
`Router.daemonCallerAuthenticator`): a caller without a session is refused with
401 `ErrDaemonRouteNoSession`, and the session's user ID, username, tenant and
roles reach the daemon handler as its caller (`restapi.WithCaller`). The handler
decides admin from that caller's `admin` role, never from the certificate: a
certificate whose CN or OU says `admin` is no admin. On the daemon's own
listener the caller is the platform token or client certificate its scope guard
verifies, and a client certificate carries no role, so it issues only for its
own CN. Without a scope guard the handler refuses every request with 503
`ErrCallerGuardNotConfigured`. A caller that is neither the path user (subject
or username) nor an admin is refused with 403 `ErrForbiddenUserID`. The CA
signs an issue-cert CSR's subject and SANs as given, so the handler refuses,
with 403 `ErrCSRNotBoundToUser`, a CSR whose CN is not the path user, which
carries an OU the caller's own certificate does not (or `admin`), or which
carries any SAN.
The body is `{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}`; the web
console's add-factor wizard builds that CSR in the browser
(`web/src/lib/csr.ts`: a WebCrypto P-256 key, subject `CN=<user id>`, no
attributes) and keeps the private key there.
`TestRegisterRoutes_DaemonIssueCertTakesTheSessionCaller`
replays the real handler behind the login check. Without an authorizer or a
caller authenticator, `MountDaemonRESTRoutes` refuses to mount
(`ErrDaemonRouteNoAuthorizer`, `ErrDaemonRouteNoCallerAuthenticator`).
`pkg/webservice/v1/testdata/daemon_routes.golden` lists every route the
webservice mounts for these groups, and `daemon_routes_golden_test.go` sends each
endpoint a request without a client certificate and expects that 401.
`TestMountDaemonRESTRoutes_EveryDaemonEndpointIsGatedOrPublic` sends each
endpoint a verified client certificate and fails unless the endpoint reaches the
gate `classifyDaemonRoute` names for it (the admin gate with its scope, the
session check, or none for the client-certificate-only routes above); an
unclassified endpoint fails it. `TestMountDaemonRESTRoutes_UnclassifiedRouteIsDenied`
replays an unknown route and expects the 403. The golden regenerates with
`-update` (see the test's comment). The daemon's `/api/v1/status` stays off
that set because the webservice serves its own. Only groups registered inside
`daemon.New` are mounted: the webservice is built after it, and a group
registered later would not be replayed.

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
A daemon whose REST routes are served by the webservice listener
(`RESTRoutesOnly`) is not UDS-only: that listener terminates TLS for the
routes and they verify clients against the daemon's roots, so the identity
is provisioned even with every daemon transport off.

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
the CA sign-csr and `/api/v1/tpm` routes check a platform token per route, and
the scope-guarded VPN, NTP, application service, compute and tenant routes
take a `Bearer` token or the client certificate
([`api.md`](api.md) §5), over a connection that has already passed mTLS — so
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
