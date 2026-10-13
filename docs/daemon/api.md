# Platform Daemon — API

> **Status: NORMATIVE** · Scope: daemon routes on every transport; the platform's transport model · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.
>
> **This file carries the canonical QUIC category-opcode table (§4).** Other
> feature folders link here rather than repeating it.

---

## 1. The six transports

`sdk/go/protocol.go` declares exactly six protocol constants:

| Transport | Constant | Mechanism |
|---|---|---|
| Embedded | `ProtocolEmbedded` | In-process; gRPC method strings dispatched straight to service implementations via an O(1) map (`sdk/go/transport/embedded/`) |
| Unix | `ProtocolUnix` | **gRPC over a Unix domain socket** (`sdk/go/transport/unix/adapter.go`) |
| gRPC | `ProtocolGRPC` | gRPC over TCP |
| REST | `ProtocolREST` | HTTPS under `/api/v1` (no plaintext listener) |
| QUIC | `ProtocolQUIC` | Binary opcode protocol over QUIC, MessagePack payloads |
| MCP | `ProtocolMCP` | JSON-RPC tools over stdio or HTTPS (TLS 1.3 only; no plaintext listener) |

**Unix is not a separate service surface** — it is the same gRPC service set over
a socket. Any gRPC RPC is available on Unix under the same name.

**The SDK never sends a credential in plaintext** (#837). Each adapter either
honours `WithBearerToken`, `WithTLSConfig` and `WithTLSServerName` or refuses
them with a typed error; none drops them silently:

| Transport | Credentials |
|---|---|
| REST | TLS 1.3 only; an `http://` address is refused with `ErrInsecureTransport`. Token sent as `Authorization: Bearer`. |
| gRPC | TLS 1.3; token sent as per-RPC metadata. |
| QUIC | TLS 1.3 (always); token framed into every request. |
| MCP | The server serves TLS 1.3 only (#844); `https://` is the default when no scheme is given and honours all three options. A bare `http://` address gets no answer from the server, and with any of the three options set the SDK refuses it with `ErrInsecureTransport` before dialing. |
| Unix | Refuses all three with `ErrUnsupportedOption`; the daemon authenticates by `SO_PEERCRED`. |
| Embedded | Refuses all three with `ErrUnsupportedOption`; calls never leave the process. |

Connecting also proves the endpoint answers: REST probes `GET /health` and MCP
runs `initialize`. A failure returns `ErrConnectionFailed`, so auto-detection
moves on to the next protocol instead of handing back a dead client.

**The embedded transport's reach is bounded by `ServiceRegistry`**
(`sdk/go/transport/embedded/adapter.go:32`), which has **22 fields**: Daemon, CA,
TPM, VTPM, Device, IAM, KMS, SDN, Compute, IDevID, Attestation, Tenant, PXE,
DNS, Gateway, Proxy, Overlay, Registry, Cluster, EAB, Invitation and
ConfigDelivery. Anything not in that list has **no embedded route** —
`SwitchService` is the notable absentee ([`docs/sdn/api.md`](../sdn/api.md) §7).

**An enabled transport that cannot be constructed or started stops the
daemon (#444).** `New` returns `ErrTransportConstructionFailed` (transport name
plus the wrapped cause) when the QUIC, REST or MCP server cannot be built;
`Start` returns the transport's typed start error; `platformd` exits non-zero.
There is no degraded mode, so a running daemon serves every transport its
configuration enables. A disabled transport is never constructed and never
fails startup. The rule and its errors are specified in
[`architecture.md` § Protocol Feature Matrix](architecture.md#protocol-feature-matrix).

`/api/v1/platform/protocols` reports which transports are actually serving.

### Error classes on MCP (#505)

The platform's error classes are the gRPC codes. gRPC and Unix carry them
directly, REST and QUIC through the status tables in each feature's `api.md`.
MCP carries them as JSON-RPC error codes, from one table
(`sdk/go/wire/mcpwire/errorcodes.go`). The server encodes with `CodeForClass`,
and the SDK MCP adapter decodes with `ClassForCode`, so an SDK caller gets the
same `status.Code` over MCP as over gRPC:

| Class | JSON-RPC code |
|---|---|
| `InvalidArgument` | `-32602` (Invalid params) |
| `Unauthenticated` | `-32001` (`-32002` for an invalid token) |
| `PermissionDenied` | `-32003` |
| `Unavailable` | `-32004` |
| `NotFound` | `-32005` |
| `AlreadyExists` | `-32006` |
| `FailedPrecondition` | `-32007` |
| anything else | `-32603` (Internal error) |

A failed `tools/call` or `resources/read` is classified in
`pkg/api/mcp/error_class.go` (`toolErrorCode`):

- An error with a gRPC status anywhere in its chain (`GRPCStatus()`) uses that
  status's class. Every tool error type implements it.
- The `Code`-carrying tool error types (`DeviceError`, `KMSError`, ...) take
  their class from their `Code`: `*_NOT_FOUND`, `*_REQUIRED` / `*INVALID*` /
  `*_DECODE*`, `*_SERVICE_UNAVAILABLE` / `*_NOT_CONFIGURED`, `*_NOT_RUNNING` /
  `*_NOT_INITIALIZED`.
- A malformed argument (bad base64, a missing field checked inline), an unknown
  tool, and a malformed resource URI are `ErrInvalidArgument`, so `-32602`.
- The package's sentinel errors are classified in one table
  (`sentinelClasses`): `datastore.ErrRecordNotFound` is `NotFound`, as the gRPC
  services map it; each `Err<Service>NotConfigured` is `Unavailable`; each
  `Err...Required` is `InvalidArgument`.

`TestEveryToolErrorIsClassified` (`error_class_test.go`) parses the package
and fails on an error type without `GRPCStatus()`, a sentinel missing from
`sentinelClasses`, or a `Code` no rule classifies, unless the test's exemption
list names it with a reason. Only a failure none of these covers is `-32603`. An unclassified tool
(`AuthErrorToolNotClassified`, §5) is also `-32603`, because it is a gap in the
platform's own configuration, not a caller error. Before #505 the server
answered every tool failure with `-32603`.

---

## 2. Daemon capabilities

gRPC: `PlatformDaemon`, 17 RPCs (`pkg/api/grpc/proto/daemon.proto`).
REST: `/api/v1/platform` (`pkg/webservice/v1/rest/platform/router.go`).
MCP: eleven tools.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Status | `GET /api/v1/platform/status` | `GetStatus` | `MISSING — docs/13 G7` | `platform_daemon_status` | ✅ |
| Health | `GET /api/v1/platform/health` | `GetHealth` | `OpHealth` (`0x00`) | `platform_health` | ✅ |
| Liveness | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpLiveness` (`0x01`) | `platform_liveness` | — |
| Readiness | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpReadiness` (`0x02`) | `platform_readiness` | — |
| Version | `GET /api/v1/platform/version` | `GetVersion` | `MISSING — docs/13 G7` | `platform_daemon_version` | ✅ |
| System info | `GET /api/v1/platform/system` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| **Shutdown** | `MISSING — docs/13 G7` | `Shutdown` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Get config | `GET /api/v1/platform/config` | `GetConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Update config | `MISSING — docs/13 G7` | `UpdateConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Reload config | `POST /api/v1/platform/config/reload` | `ReloadConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| **Validate config** | `POST /api/v1/platform/config/validate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| List services | `GET /api/v1/platform/services` | `ListServices` | `MISSING — docs/13 G7` | `platform_daemon_list_services` | ✅ |
| Get service | `GET /api/v1/platform/services/{service}` | `GetServiceStatus` | `MISSING — docs/13 G7` | `platform_daemon_get_service` | ✅ |
| Start service | `POST /api/v1/platform/services/{service}/start` | `StartService` | `MISSING — docs/13 G7` | `platform_daemon_start_service` | ✅ |
| Stop service | `POST /api/v1/platform/services/{service}/stop` | `StopService` | `MISSING — docs/13 G7` | `platform_daemon_stop_service` | ✅ |
| Restart service | `POST /api/v1/platform/services/{service}/restart` | `RestartService` | `MISSING — docs/13 G7` | `platform_daemon_restart_service` | ✅ |
| List protocols | `GET /api/v1/platform/protocols` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `platform_daemon_list_protocols` | — |
| Metrics | `GET /api/v1/platform/metrics` | `StreamMetrics` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Query logs | `GET /api/v1/platform/logs` | `StreamLogs` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| List log services | `GET /api/v1/platform/logs/services` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Stream logs | `GET /api/v1/platform/logs/stream` | `StreamLogs` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Stream events | `MISSING — docs/13 G7` | `StreamEvents` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| List entity types | `MISSING — docs/13 G7` | `ListEntityTypes` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Dump entity type | `MISSING — docs/13 G7` | `DumpEntityType` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |

**QUIC carries only three daemon opcodes** — health, liveness and readiness at
`0x00`–`0x02`. Everything else about running the daemon is REST, gRPC, MCP or
embedded.

---

## 3. Configuration snapshots — REST only

| Method | Path |
|---|---|
| GET | `/api/v1/platform/config/snapshots` |
| POST | `/api/v1/platform/config/snapshots` |
| GET | `/api/v1/platform/config/snapshots/{id}` |
| DELETE | `/api/v1/platform/config/snapshots/{id}` |
| POST | `/api/v1/platform/config/snapshots/{id}/rollback` |

Plus `POST /api/v1/platform/config/validate`.

**This is the platform's configuration undo, and it exists on REST alone.** On a
system that programs a datapath and enforces attestation policy, a bad
configuration change is the most likely way to lose access — snapshot before
changing, validate before applying, roll back if wrong.

---

## 4. The QUIC protocol — canonical reference

### Frame constants (`sdk/go/wire/quicwire/protocol.go`)

| Constant | Value |
|---|---|
| `ProtocolVersion` | `0x01` |
| `MaxPayloadSize` | 16 MiB |
| `MaxTokenSize` | 8 KiB |

### Status bytes — the platform's canonical status vocabulary

| Byte | Name | REST |
|---|---|---|
| `0x00` | `StatusOK` | 200 |
| `0x01` | `StatusInvalidRequest` | 400 |
| `0x02` | `StatusNotFound` | 404 |
| `0x03` | `StatusUnauthorized` | 401 |
| `0x04` | `StatusInternalError` | 500 |
| `0x05` | `StatusTimeout` | 504 |
| `0x06` | `StatusAlreadyExists` | 409 |
| `0x07` | `StatusPermissionDenied` | 403 |
| `0x08` | `StatusResourceExhausted` | 429 |
| `0x09` | `StatusInvalidArgument` | 400 |
| `0x0A` | `StatusUnavailable` | 503 |
| `0x0B` | `StatusNotImplemented` | 501 |

### Category opcodes — read this before writing any QUIC client

The opcode is a **single byte** with a **two-level extension**: certain values
are *category* opcodes whose sub-opcode is carried in the payload, and the daemon
routes them to a dedicated handler (`pkg/api/daemon/quic_service.go`). Seventeen
distinct values, eighteen names:

| Opcode | Category | Notes |
|---|---|---|
| `0x2E` | `OpOverlayCategory` | VXLAN/EVPN overlay |
| `0x2F` | `OpGatewayCategory` | Edge gateway. **Sub-opcodes `0x20`–`0x2D` route to the proxy handler**; zone ops at `0x10`–`0x14`; telemetry snapshots at `0x15`–`0x16`; perf at `0x36`–`0x38` |
| `0x2F` | `OpProxyCategory` | **An alias of `OpGatewayCategory`**, not a separate value |
| `0x3F` | `OpIPAMCategory` | IPAM |
| `0x50` | `OpNTPCategory` | Time synchronisation |
| `0x51` | `OpIAMCategory` | IAM tenant records; sub-opcodes `IAMSub*` `0x01`–`0x05`. Not the platform tenancy opcodes `0xDB`–`0xEB` |
| `0x69` | `OpVMExtendedCategory` | VM operational sub-opcodes (`0xCC`–`0xD0`) |
| `0x99` | `OpTPM2Category` | Physical TPM |
| `0x9A` | `OpCeremonyCategory` | Phase 3.5 |
| `0x9B` | `OpPIVCategory` | Phase 3.5 |
| `0x9C` | `OpLUKSCategory` | Phase 3.5 |
| `0x9D` | `OpFIDO2Category` | Phase 3.5 |
| `0x9E` | `OpTenantBarrierCategory` | Per-tenant barrier |
| `0x9F` | `OpBMCCategory` | BMC enrollment |
| `0xCC` | `OpSwitchCategory` | Physical switch; sub-opcodes `SwitchSub*` `0x01`–`0x05` |
| `0xCD` | `OpKMSExtendedCategory` | KMS key-lifecycle verbs; `KMSSubSignCSR` (`0x07`) is CA Sign CSR, which requires `ca:sign-csr` (`docs/ca/api.md` §4) |
| `0xCE` | `OpSecretsCategory` | Secrets |
| `0xCF` | `OpProvisioningCategory` | Provisioning / config delivery |

**This is why opcode values repeat.** `OpOverlayStatus`, `OpGatewayStatus` and
`OpLiveness` are all `0x01`: the first two are sub-opcodes inside their category,
the third is a top-level opcode. A client sending `0x01` at top level gets a
liveness check. Likewise `OpVMMetrics` (`0xCC` under `0x69`) and
`OpSwitchCategory` (`0xCC` at top level) are unrelated.

`sdk/go/wire/quicwire/vm_ops_opcodes.go` documents the rule for its own range: values
*"live in the 0x69 sub-opcode namespace and only need to be unique among the
sub-opcodes routed under that category"*.

### Two dead opcode names

`OpAttestGetReport` (`0x76`) and `OpAttestGetPCRs` (`0x77`) are shadowed by
`OpAttestGetManifest` and `OpAttestGetReportByID` at the same values, and the
handler dispatches on the latter pair. **Both dead names are still in the
`OpcodeNames` table**, so logs mislabel those two operations. See
[`docs/attestation/api.md`](../attestation/api.md) §4.

`sdk/go/wire/quicwire/opcode_uniqueness_test.go` enforces the rule this section
describes — and the one `protocol.go` states, that new operations *"must
multiplex as sub-opcodes under an existing category opcode"*. It asserts opcode
values are unique **within a dispatch namespace**, so the by-design repeats
above stay legal while a genuine same-namespace clash fails the build. The Go
compiler already rejects two constants of one value in a single `switch`; what
it cannot see is two switches sharing the top-level byte, which is what all
seven known collisions are. Those seven are carried as an explicit ratchet
against #386, and an entry that stops colliding fails too, so the list can only
shrink.

### Authorization runs before dispatch

Every frame is authenticated and authorized against the operation catalog
(`pkg/api/quic/opcode_permissions.go`) before the dispatcher routes it; for a
category opcode the catalog key is the sub-opcode in `payload[0]`. An
unallocated opcode or sub-opcode is therefore answered by the guard —
`StatusPermissionDenied` with an `ErrOperationNotClassified` payload — not by
the dispatcher's `StatusNotImplemented`, and a category frame with an empty
payload is `StatusInvalidRequest`. A new opcode or sub-opcode needs a catalog
entry in the same change, or the contract tests fail. The steps and the
pre-auth list are in §5.

### Panics do not drop connections

`pkg/api/quic/server.go` recovers a panicking handler into
`StatusInternalError` and logs the stack, *"so the client never sees a bare EOF
from a panicking handler."* gRPC has the equivalent in
`pkg/api/daemon/recovery_interceptor.go`.

---

## 5. Authorization — the platform-wide picture

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form, minted by the broker from the subject's resolved
permissions. Enforcement is per operation: gRPC `RequireScope`, QUIC
`AuthMiddleware.GuardRequest`, MCP `AuthorizeTool`.

Three catalogs with **different defaults** — gRPC allows an unlisted entry, MCP
(since #300) and QUIC (since #767) deny one:

| Catalog | Coverage | Default for an unlisted entry |
|---|---|---|
| gRPC (`pkg/api/grpc/method_permissions.go`) | **185 of 461 RPCs**, across 11 of 31 services | *"carries no required scope: the interceptor allows it once the token is validated"* |
| MCP (`pkg/api/mcp/authz.go`) | **124 of 434 registered tools** (5 of them explicitly open with `""`) | **denied**: `AuthorizeTool` refuses a tool with no map entry (`AuthErrorToolNotClassified`, reported on the wire as `-32603`); the 310 unmapped tools are enumerated in `knownUnclassified` (`authz_completeness_test.go`), a list that may only shrink (#304) |
| QUIC (`pkg/api/quic/opcode_permissions.go`) | **every routable opcode and sub-opcode** — pinned by `pkg/api/daemon/quic_authz_contract_test.go` | **denied**: `StatusPermissionDenied`, payload `QUIC operation not classified for authorization: …` (`ErrOperationNotClassified`) |

**gRPC TCP, QUIC and REST fail closed without an authentication backend
(#550, #312).** With `SkipIAMValidation` off, a daemon configuration under
which no token validator can be built (no platform-token validator, no
QuicBaaS service, no platform JWT verifier) refuses to construct the gRPC TCP
and QUIC servers with `ErrTransportAuthRequired`; when a validator exists the
interceptor requires a credential unconditionally, and an anonymous call is
`Unauthenticated`. `EnableMTLS` without a CA service or a resolvable client CA
pool is refused the same way. The daemon REST server authenticates by mTLS
only, so `EnableREST` requires `EnableMTLS`. Before #550 the interceptors were
installed with `WithRequireAuth(tokenValidator != nil)`, so the misconfigured
state served the whole daemon API anonymously.

**QUIC authorizes every request before dispatch (#767).** Before #767 the QUIC
dispatcher authenticated a token when a middleware was installed and then
dispatched with no authorization at all: any valid token reached every
operation, whatever its `scp`. `HandleRequest` now runs
`AuthMiddleware.GuardRequest` on every request, in this order:

1. **Pre-auth list.** `OpHealth`, `OpLiveness`, `OpReadiness` (probes run
   before a caller holds a token) and `OpIAMAuthenticate` (the token
   exchange itself) pass with no credential, as do the diskless boot
   sub-operations `DeviceSubBootCertificate` and `DeviceSubBootDelivery`
   under `OpProvisioningCategory` (the node holds no token; the boot service
   authenticates it against its own TLS channel). Each entry in
   `preAuthOpcodes` and `preAuthSubOpcodes` carries its reason; nothing else
   is exempt.
2. **Authentication** of the token (`StatusUnauthorized` when missing or
   invalid).
3. **Classification** by `LookupOperationPermission`: the opcode, or for a
   category opcode the sub-opcode in `payload[0]`, resolves to one
   resource/action pair in a map lookup. A category frame without a
   sub-opcode is `StatusInvalidRequest`; an unclassified opcode or
   sub-opcode is `StatusPermissionDenied`.
4. **Authorization** of the pair: on the platform-token path the scope
   `"<resource>:<action>"` is enforced by `RequireScope` (wildcards apply);
   otherwise a configured `AuthorizationChecker` decides. A scope-less
   credential with no checker (a peer certificate, the legacy bool-only
   token validator) authorizes every *classified* operation, as on gRPC.

The pairs mirror the gRPC catalog and the MCP map for the same capability;
`TestQUICAuthzContract_ScopesMatchGRPC` pins one mutating and one reading
operation per family, and the contract tests fail when an opcode or
sub-opcode is added without a catalog entry. A `QUICServiceHandler` cannot be
built without a middleware (`NewQUICServiceHandler` returns
`ErrQUICAuthMiddlewareRequired`), and a handler built as a bare literal
answers `StatusUnavailable` to everything. Under mTLS the verified client
certificate authenticates a tokenless request (`WithQUICPeerAuthenticated`) —
as on gRPC, where the certificate alone authenticates — while a presented
token is still validated and scope-checked. `SkipIAMValidation` skips
authentication only; unclassified operations are refused there too.

**MCP fails closed without an authorization backend (#440).** With neither the
platform-token validator nor the QuicBaaS auth adapter configured,
`AuthorizeTool` refuses every tool that requires a permission (`-32001`, the
message names the missing backend); only the five tools explicitly mapped to
`""` answer. The daemon refuses to create the MCP server in that state
(`New` fails with `ErrTransportConstructionFailed` wrapping
`ErrMCPAuthorizationBackendRequired`, #444) unless `SkipIAMValidation`, the testing-only opt-out, is set. Before #440 that
state was a `Warn` and every registered tool was served to any caller.

**MCP over HTTP serves TLS 1.3 only (#844).** The listener presents the
daemon's TLS identity (`Config.TLSCertificate`, the certificate REST and gRPC
serve) under the same mTLS policy: with `EnableMTLS` it requires and verifies
a client certificate against the pool REST and gRPC use
(`newServerTLSConfig`, `pkg/api/daemon/transport_auth.go`). The version is
pinned to TLS 1.3 by the MCP server itself (`pkg/api/mcp/server.go`
`serverTLSConfig`), per-client configs included. There is no plaintext
listener and no option that brings one back: a plain `http://` request gets
`400` from the TLS listener and never reaches tool dispatch. A daemon
configured for MCP over HTTP without a usable certificate is refused by `New`
(`ErrTransportConstructionFailed` wrapping `ErrTLSConfigFailed`, #444) and
binds nothing, and an MCP start failure (for
example a bind error) fails `Daemon.Start` with `MCPServerStartError` and
rolls back what had started. `platformd serve` provisions the daemon identity
when MCP over HTTP is the only network transport. The stdio transport binds no
listener and needs no certificate. Before #844 the listener served plaintext
HTTP and bearer tokens crossed the network in the clear.

Services **in** the gRPC catalog: `CAService` (12), `DeviceService` (21),
`DNSService` (13), `GatewayService` (11 of 26), `KeyManagementService` (23),
`NTPService` (3), `PlatformIAMService` (41), `ProxyService` (14),
`SDNService` (25), `VTPMService` (23), and one daemon method.

Services **not** in it include `PlatformDaemon` (16 of 17 RPCs, among them
`Shutdown`, `UpdateConfig` and `StopService`), `ComputeService`,
`AttestationService`, `RegistryService`, `TenantService`, `ClusterService`,
`PXEService`, `ConfigDeliveryService`, `BMCService`, `OverlayService`,
`SwitchService`, `TPMService`, `IDevIDService`, `EABService` and
`InvitationService`.

MCP's 94 mapped tools are the vtpm, dns, device, profile, gateway-lb,
gateway-perf, sdn, proxy, ntp, bmc and invitation families. The 334 unmapped
tools are **refused, not served** — measured from the built registry on
2026-09-05 (#412): `platform_tpm` 31, `vtpm` 26, `iam` 25, `vm` 23, `kms` 20,
`gateway` 20, `tenant` 17, `attestation` 15, `dns` 12, `sdn` 11, `platform_eab`
11, `container` 10, `platform_luks` 10, and smaller families. Until #304
classifies a tool it cannot be called by any caller, which is why `platform_tpm_*`
and `attestation_*` answer `-32603 tool '<name>' has no permission mapping` on
the fleet. Where a capability has two tool names, frequently only the older one
is mapped ([`docs/dns/api.md`](../dns/api.md) §3,
[`docs/vtpm/api.md`](../vtpm/api.md) §5).

**MCP discovery is not gated.** Over HTTPS, `initialize` and `tools/list` read no
token (`pkg/api/mcp/server.go` `handleInitialize`, `handleToolsList`), so an
anonymous client receives `serverInfo` and every registered tool's schema;
only `tools/call` runs `AuthorizeTool`. A missing token is reported as a JSON-RPC
error inside an HTTP 200, never as HTTP 401 + `WWW-Authenticate`, although the
server publishes the RFC 9728 protected-resource metadata that header would
point at. Whether discovery should require the same principal as REST's
listings is raised for the owner on #412 and is not decided here.

**Whether the gRPC catalog should default to deny is still open** and raised
for the owner in the migration report; the MCP half of that question was
answered by #300.

### Certificate-bound routes

A few REST routes authorize on the **mTLS client certificate** rather than on a
token scope, because their caller is a machine whose identity *is* its
certificate. The webservice listener therefore requests a client certificate
optionally — `tls.VerifyClientCertIfGiven`, set in
`pkg/webservice/webserver_v1.go` — so a presented certificate is chained to the
configured `ClientCAs` by the TLS stack before any handler runs, while clients
that present none (the WebUI, token-authenticated API callers) are unaffected.
Handlers on these routes read identity from the connection's `VerifiedChains`,
never from `PeerCertificates`.

| Route | Bound to | Refusal |
|---|---|---|
| `POST /api/v1/gateway/telemetry` | body `gateway_id` == client certificate CN | 401 unverified · 403 mismatch |
| `GET /api/v1/gateway/desired-config/{id}` | `{id}` == client certificate CN | 401 unverified · 403 mismatch |
| device enrollment routes (`pkg/webservice/v1/router/device.go`) | `MTLSMiddleware` chain verification | 401 |

The Subject Common Name is the platform's machine-principal field throughout —
the trusted reverse proxy keys attestation manifests by the IDevID CN, and the
daemon's gRPC mTLS interceptor reads the same field. See
[`docs/gateway/api.md`](../gateway/api.md) §8.

---

## 6. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. The OCI distribution `/v2` routes
([`docs/registry/api.md`](../registry/api.md) §3) are the distribution
specification's version, not the platform's.
