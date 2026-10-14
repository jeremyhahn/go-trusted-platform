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
(`sdk/go/transport/embedded/adapter.go:32`), which has **25 service fields**: Daemon, CA,
TPM, VTPM, Device, IAM, KMS, SDN, Compute, IDevID, Attestation, Tenant, PXE,
DNS, Gateway, Proxy, Overlay, Registry, Cluster, EAB, Invitation,
ConfigDelivery, Ceremony, PIV and FIDO2, plus the `CallerContext` hook that
attaches the caller's identity. platformctl's embedded hosts (the desktop
standalone daemon and a CLI context whose transport is embedded) both start
through `daemon.StartEmbeddedHost`, which fills each field from the daemon
accessor of the same service (`pkg/api/daemon/embedded_host.go`); a service the
daemon did not build stays nil and registers no methods. Both pass
`appbackends.WireEmbeddedHost` as `WireBackends`, which wires the same ceremony
backend `platformd serve` does (`appbackends.WireSDKBackends`), so the ceremony
answers on the embedded transport too, and without an SDK client the embedded
host refuses to start (`ErrEmbeddedHostFailed{Op: "backends"}`). Anything not in that list has **no embedded route** —
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

### Before and after unseal

None of the six transports exists until the barrier is unsealed. Until then
platformd serves only the **pre-unseal mux**: plain HTTP with `GET /healthz`,
`POST /init` and `POST /unseal` ([`docs/bootstrap/api.md`](../bootstrap/api.md) §3).

| Daemon phase | Listening | Client |
|---|---|---|
| Uninitialized or sealed | Pre-unseal mux on the Unix socket and `127.0.0.1:9446` only | `sdk/go/services/gate` (`platformctl init`) |
| Unsealed | The six transports above; the pre-unseal mux is torn down | `sdk/go` (`platformd.Connect`), every other `platformctl` command |

The pre-unseal mux carries PINs and returns the one-shot admin bundle in clear,
so it is never bound off-host, and the gate client refuses any endpoint that is
not `unix://<path>` or a loopback `host:port`. `platformctl init` uses the Unix
socket unless `--loopback-http` is passed: only there can a lost `/init`
response be replayed ([`docs/bootstrap/cli.md`](../bootstrap/cli.md) §1a).
`CeremonyService/Init` on the six transports reaches the same ceremony backend,
but it is only reachable after unseal and carries the `ceremony` scope on every
token-gated listener, so it cannot bootstrap a fresh platform — `platformctl
init` does not use it.

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
routes them to a dedicated handler (`pkg/api/daemon/quic_service.go`). Twenty-one
distinct values, twenty-two names:

| Opcode | Category | Notes |
|---|---|---|
| `0x2E` | `OpOverlayCategory` | VXLAN/EVPN overlay |
| `0x2F` | `OpGatewayCategory` | Edge gateway. **Sub-opcodes `0x20`–`0x2D` route to the proxy handler**; zone ops at `0x10`–`0x14`; telemetry snapshots at `0x15`–`0x16`; perf at `0x36`–`0x38` |
| `0x2F` | `OpProxyCategory` | **An alias of `OpGatewayCategory`**, not a separate value |
| `0x3F` | `OpIPAMCategory` | IPAM |
| `0x50` | `OpNTPCategory` | Time synchronisation |
| `0x51` | `OpIAMCategory` | IAM tenant records; sub-opcodes `IAMSub*` `0x01`–`0x05`. Not the platform tenancy opcodes `0xDB`–`0xEB` |
| `0x52` | `OpVPNCategory` | VPN control plane; sub-opcodes `VPNSub*` `0x01`–`0x08`, scopes `vpn:read`/`vpn:write`/`vpn:admin` ([docs/vpn/api.md](../vpn/api.md)) |
| `0x53` | `OpCacheCategory` | Cache through the composed go-quicbaas SDK; sub-opcodes `CacheSub*` `0x01`–`0x04`, scopes `cache:read`/`cache:write`/`cache:delete` ([docs/sdk/api.md](../sdk/api.md) §3.5) |
| `0x54` | `OpSchedulerCategory` | Scheduler through the composed go-quicbaas SDK; sub-opcodes `SchedulerSub*` `0x01`–`0x0B`, scopes `scheduler:read`/`scheduler:write`/`scheduler:delete` ([docs/sdk/api.md](../sdk/api.md) §3.5) |
| `0x55` | `OpMessagingCategory` | Messaging through the composed go-quicbaas SDK; sub-opcodes `MessagingSub*` `0x01`–`0x08`, scopes `messaging:read`/`messaging:write`/`messaging:delete` ([docs/sdk/api.md](../sdk/api.md) §3.5) |
| `0x69` | `OpVMExtendedCategory` | VM operational sub-opcodes (`0xCC`–`0xD0`) |
| `0x99` | `OpTPM2Category` | Physical TPM |
| `0x9A` | `OpCeremonyCategory` | Bootstrap ceremony; per-sub-opcode scopes in [`docs/cli/ceremony.md`](../cli/ceremony.md) |
| `0x9B` | `OpPIVCategory` | PIV smartcards; scopes in [`docs/cli/piv.md`](../cli/piv.md) |
| `0x9C` | `OpLUKSCategory` | LUKS volumes |
| `0x9D` | `OpFIDO2Category` | FIDO2 tokens; scopes in [`docs/cli/fido2.md`](../cli/fido2.md) |
| `0x9E` | `OpTenantBarrierCategory` | Per-tenant barrier |
| `0x9F` | `OpBMCCategory` | BMC enrollment |
| `0xCC` | `OpSwitchCategory` | Physical switch; sub-opcodes `SwitchSub*` `0x01`–`0x05` |
| `0xCD` | `OpKMSExtendedCategory` | KMS key-lifecycle verbs; `KMSSubSignCSR` (`0x07`) is CA Sign CSR, which requires `ca:sign-csr` (`docs/ca/api.md` §4) |
| `0xCE` | `OpSecretsCategory` | Secrets |
| `0xCF` | `OpProvisioningCategory` | Provisioning / config delivery. Device sub-opcodes `0x20`–`0x29` (profile assign/unassign, attestation certificate, diskless boot certificate and delivery, disable/enable, template create, profile from template, find matching profile) are routed first — [`docs/device/api.md`](../device/api.md) §3.7 |

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
`AuthMiddleware.GuardRequest`, MCP `AuthorizeTool`. On QUIC the ceremony, PIV
and FIDO2 categories also run `AuthorizeSubOpcode`, which requires a principal
(#720, below).

All three catalogs **deny an unlisted entry** — MCP since #300, QUIC since
#767, gRPC since #768:

| Catalog | Coverage | Default for an unlisted entry |
|---|---|---|
| gRPC (`pkg/api/grpc/method_permissions.go`) | **every registered RPC**, unary and streaming, across every `platform.v1` service, the four quicbaas KMS services and `grpc.health.v1.Health`; a contract test keeps it that way | **denied**: the OIDC interceptor answers `PermissionDenied` (`ErrMethodNotClassified`) before it reads a token, unless the method is on the documented pre-auth list |
| MCP (`pkg/api/mcp/authz.go`) | **184 of 445 registered tools** (7 of them explicitly open with `""`) | **denied**: `AuthorizeTool` refuses a tool with no map entry (`AuthErrorToolNotClassified`, reported on the wire as `-32603`); the 261 unmapped tools are enumerated in `knownUnclassified` (`authz_completeness_test.go`), a list that may only shrink (#304) |
| QUIC (`pkg/api/quic/opcode_permissions.go`) | **every routable opcode and sub-opcode** — pinned by `pkg/api/daemon/quic_authz_contract_test.go` | **denied**: `StatusPermissionDenied`, payload `QUIC operation not classified for authorization: …` (`ErrOperationNotClassified`) |

Per-service scopes are listed in each feature folder. A new RPC must carry the
permission its twins on the other transports require: the `DeviceService`
operator writes `DisableDevice`, `EnableDevice` and `CreateTemplate` (#873)
take `device:write`, as QUIC sub-opcodes `0x25`–`0x27`, MCP `device_disable`,
`device_enable` and `device_template_create`, and the webservice REST routes do
([`docs/device/api.md`](../device/api.md) §7).

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

**The daemon REST VPN, NTP and application service routes check the RPC's
scope (#584, #704).** mTLS at the handshake is not authorization: each
`/api/v1/vpn/*`, `/api/v1/ntp/*`, `/api/v1/cache/*`, `/api/v1/scheduler/*` and
`/api/v1/messaging/*` route on the daemon listener runs through
`restapi.ScopeGuard` (`pkg/api/rest/route_scope.go`) and requires the scope the
gRPC catalog gives its RPC (`vpn:read|write|admin`, `ntp:read` for status and
sources, `ntp:write` for step, and `cache`, `scheduler` and `messaging` as in
[docs/sdk/api.md](../sdk/api.md) §3.5). The guard takes the credentials QUIC takes, in the same order:

- a `Bearer` platform token (with its `DPoP` proof), validated by the shared
  platform-token validator; its `scp` is the scope set;
- otherwise the verified client certificate (`VerifiedChains` only),
  authenticated against the mTLS client CA pool and admitted as the operator
  holding `*:*`.

No credential, or one with no verifier configured, is 401; a caller without the
scope is 403. A handler set built without a guard answers 403 on every route
(default-deny). The guard is built by `newRESTScopeGuard`; it does not change
the routes of the other REST handler sets.

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
   credential with no checker (a peer certificate admitted without a
   principal, the legacy bool-only token validator) authorizes every *classified* operation —
   except the ceremony, PIV and FIDO2 categories, which need a principal
   (below).

The pairs mirror the gRPC catalog and the MCP map for the same capability;
`TestQUICAuthzContract_ScopesMatchGRPC` pins one mutating and one reading
operation per family, and the contract tests fail when an opcode or
sub-opcode is added without a catalog entry. A `QUICServiceHandler` cannot be
built without a middleware (`NewQUICServiceHandler` returns
`ErrQUICAuthMiddlewareRequired`), and a handler built as a bare literal
answers `StatusUnavailable` to everything. Under mTLS the verified client
certificate authenticates a tokenless request — as on gRPC, where the
certificate alone authenticates — while a presented token is still validated
and scope-checked. The daemon installs `WithQUICPeerAuthenticator`, which
attaches the certificate's principal; `WithQUICPeerAuthenticated` marks a
transport-verified peer authenticated without one. `SkipIAMValidation` skips
authentication only; unclassified operations are refused there too.

**QUIC category operations need a principal (#720).** The ceremony (`0x9A`),
PIV (`0x9B`) and FIDO2 (`0x9D`) categories check the caller's scope per
sub-opcode (`pkg/api/quic/phase35_auth.go`) and refuse a request that carries
no `AuthorizedContext` with `PermissionDenied`. The QUIC auth middleware
attaches one in two cases:

- a platform token: the `scp` claim is the scope set;
- under `EnableMTLS`: the connection's verified client certificate,
  authenticated against the client CA pool. The certificate is admitted as the
  operator principal holding `*:*`, the standing gRPC and REST give an mTLS
  caller. Only `VerifiedChains` is read, never `PeerCertificates`.

A legacy bool-only token validator (QuicBaaS `ValidateToken`, the platform JWT
verifier) and `SkipIAMValidation` attach none, so on those daemons the three
categories are refused over QUIC. The Unix socket and the embedded transport
dispatch through gRPC and never reach this check.

**gRPC TCP never serves a bool-only token on its validity alone (#720, #768).**
Without the platform-token validator the gRPC TCP interceptor falls back to
the legacy bool-only validator, which proves a token valid but yields no
scopes. That path used to call the handler once the token validated, so any
valid token reached `CeremonyService/Init`, `PIVService/Sign` and
`FIDO2Service/Register` whatever its scope. The interceptor now asks the
`AuthorizationChecker` (the IAM PEP, `iamTokenAuthorizer`) for the method's
catalog permission on that path, for every method, these three services
included. Without a checker the call is `PermissionDenied`
(`ErrAuthorizationCheckerRequired`). Under `EnableMTLS` the verified client
certificate is the operator principal and the interceptor is not involved.

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

**The gRPC catalog maps every method.** `buildGRPCMethodPermissions` gives each
RPC a `"<resource>:<action>"` scope using the same resource names as the QUIC
opcode table and MCP `authz.go`. For the platform's own resources the actions
are `read`, `write` and `delete`; `bmc` adds `power`, `media` and `admin`, and
`platform` adds `admin` for `Shutdown` and `DumpEntityType`. These resources
are:

- `vtpm`, `dns`, `ntp`, `proxy`, `device`, `sdn`, `kms` and `iam`
- `vpn`, whose actions are `read`, `write` and `admin` (posture policies)
- `cache`, `scheduler` and `messaging`, the services platformd serves over
  the composed go-quicbaas SDK ([docs/sdk/api.md](../sdk/api.md) §3.5)
- `platform` (`PlatformDaemon`, including `StreamEvents`, `StreamLogs` and
  `StreamMetrics`)
- `attestation`, `bmc`, `cluster`, `container`, `vm`, `provisioning`, `eab`,
  `fido2`, `idevid`, `invitation`, `luks`, `pxe`, `registry`, `switch`, `tpm`
  and `tenant`

**Resource families go-qrdb owns use go-qrdb's registered actions (#768).**
The broker can mint only a permission go-qrdb registers, so any other action in
these families could never be held. They are `ca`, `certs`, `ceremony`, `piv`,
`seal`, `secrets` and `trust`:

| Service | Mapping |
|---|---|
| `CAService` | `InitCA` `ca:create`; `SignCSR` `ca:sign-csr`; CA info, bundle and CRL `ca:read`; issue and renew `certs:generate`; revoke `certs:revoke`; get and verify `certs:read`; list `certs:list`; install and uninstall CA certificates `trust:write` |
| `BarrierService` | `seal:status`, `seal:bootstrap` (`Init`, single-key and Shamir), `seal:unseal`, `seal:seal`, `seal:rekey` |
| `CeremonyService` | claim-cert begin and complete `ceremony:claim_cert`; `ceremony:claim_share_begin`, `ceremony:claim_share_complete`, `ceremony:sign_csr` |
| `PIVService` | `Sign` is `piv:use`; the rest use `piv:read`, `piv:write` or `piv:delete` |
| `SecretsManagement` | listing is `secrets:list`; the rest use `secrets:read`, `secrets:write` or `secrets:delete` |

`TestGRPCMethodPermissions_WellFormed` pins go-qrdb's vocabulary for these
families and fails on any action outside it.

**The platform's own families cannot be granted action by action yet.** Neither
go-qrdb nor go-quicbaas registers `vtpm`, `dns`, `bmc`, `platform` or any other
family in the list above, and no built-in role holds them. A custom role may
name only a registered permission or a whole-segment wildcard (go-qrdb
`role.validatePermissions`). The token check `AuthorizedContext.HasScope`
matches `<resource>:*` and `*:*`. On the platform-token path, these RPCs are
therefore reachable only through a role that grants the whole family, such as
`bmc:*`. A role holding `bmc:read` but not `bmc:power` cannot be created.
Least-privilege grants need an SDK surface that registers the platform's
permission vocabulary (go-qrdb `permission.Register` and `RegisterRoleGrant`,
reached through go-quicbaas). The SDK does not expose one today. This is a
missing capability, not a hole: an unregistered scope is never held, so it can
deny but never allow.

`OverlayService` and all of `GatewayService` (status, mode, VIP, snapshot,
admitted VTEP, perf, IPAM and BGP) map to `sdn`. The
quicbaas `KeyManagement`, `Crypto` and `DEKManagement` services map to `kms`, and
`SecretsManagement` maps to `secrets`. `ProvisioningGateway` is generated but not
registered by platformd; it is mapped anyway so that registering it cannot open
a hole.

`method_permissions_test.go` builds the list of registered methods from the
service descriptors: `protoregistry` for `platform.v1`, plus the quicbaas and
health `ServiceDesc`s. Three tests guard the catalog:

- `TestGRPCMethodCatalog_CoversEveryRegisteredMethod` fails when a method has
  neither a scope nor a pre-auth entry.
- `TestGRPCMethodCatalog_NoStaleEntries` fails when an entry names a method
  that does not exist.
- `TestGRPCMethodCatalog_PreAuthIsNotScoped` fails when a method is on both
  lists.

So a new RPC cannot ship without a decision.

**The gRPC pre-auth list** (`preAuthMethods`) is the only set of methods the
OIDC interceptor serves without a token. Each entry is commented in source with
its reason:

| Methods | Why they are pre-auth |
|---|---|
| `grpc.health.v1.Health/Check` | The liveness and readiness probe: it answers one aggregate SERVING status, and orchestrators call it without credentials |
| `CeremonyService/{Init,Status}` | First-boot ceremony: `Init` enrolls the first custodians, so no principal exists yet to hold a token; `Status` lets them follow it |
| `InvitationService/{GetInvitationByToken,AcceptInvitation}` | The invitation token in the request is the credential; the invitee has no platform session yet (matches the ungated REST invitee routes and MCP tools) |
| `ConfigDeliveryService/{GetNonce,FetchConfig,SignDigest,PollSession}` | Pre-enrollment config delivery: the machine authenticates inside the request (single-use nonce, EAB HMAC, EK-certificate binding) and the session ID is the poll capability (matches the ungated REST `/provisioning` routes); the operator half — `ListSessions`, `GetSession`, `FulfillSession` — is scoped `provisioning` |
| `DeviceService/{BootCertificate,BootDelivery}` | Diskless boot: the node holds no platform token and, for `BootCertificate`, no certificate yet; the boot service verifies the node's proof, or its chain and quote, bound to the connection. They are on the TCP skip list too, so the mTLS interceptor passes them as well |

The rest of the health surface is scoped `platform:read` (#768).
`PlatformDaemon/GetHealth` names every component with its failure message, the
same reconnaissance the REST `/api/v1/platform/health` route gates.
`Health/List` enumerates the registered services, and `Health/Watch` holds a
stream open for as long as the caller likes.

`PlatformIAMService` has no login method, so IAM contributes no pre-auth entry. The
daemon's own skip list, `grpcTCPSkipMethods` in `transport_auth.go`, is handed
to both the mTLS and the OIDC interceptor. It holds only `Health/Check`, so it
widens neither path. Under mTLS, the gRPC TCP transport authenticates the client
certificate and does not apply the per-method scope catalog. The UDS server
authorizes by peer credentials.

MCP's 94 mapped tools are the vtpm, dns, device, profile, gateway-lb,
gateway-perf, sdn, proxy, ntp, bmc and invitation families. The eight `vpn_*`
tools (#584) are mapped as well, and so are the 23 `cache_*`, `scheduler_*` and
`messaging_*` tools (#704), each with its RPC's scope
([docs/sdk/api.md](../sdk/api.md) §3.5). The 334 unmapped
tools are **refused, not served** — measured from the built registry on
2026-09-05 (#412): `platform_tpm` 31, `vtpm` 26, `iam` 25, `vm` 23, `kms` 20,
`gateway` 20, `tenant` 17, `attestation` 15, `dns` 12, `sdn` 11, `platform_eab`
11, `container` 10, `platform_luks` 10, and smaller families. Until #304
classifies a tool it cannot be called by any caller, which is why `platform_tpm_*`
and `attestation_*` answer `-32603 tool '<name>' has no permission mapping` on
the fleet. Where a capability has two tool names, frequently only the older one
is mapped ([`docs/dns/api.md`](../dns/api.md) §3,
[`docs/vtpm/api.md`](../vtpm/api.md) §5). Since that measurement #65 mapped
`gateway_status` (`sdn:read`) and `gateway_mode_set` (`sdn:write`), so the
`gateway` family has two fewer refused tools than the count above; its
`gateway_bgp_*` tools remain unmapped
([`docs/gateway/api.md`](../gateway/api.md) §3).

**MCP discovery is not gated.** Over HTTPS, `initialize` and `tools/list` read no
token (`pkg/api/mcp/server.go` `handleInitialize`, `handleToolsList`), so an
anonymous client receives `serverInfo` and every registered tool's schema;
only `tools/call` runs `AuthorizeTool`. A missing token is reported as a JSON-RPC
error inside an HTTP 200, never as HTTP 401 + `WWW-Authenticate`, although the
server publishes the RFC 9728 protected-resource metadata that header would
point at. Whether discovery should require the same principal as REST's
listings is raised for the owner on #412 and is not decided here.

**The gRPC catalog defaults to deny (#768).** Before #768, about 345 RPCs had no
entry and were served to any caller with a valid token whatever its scopes. That
included `PlatformDaemon/Shutdown`, `UpdateConfig` and `StopService`, and every
BMC power and media method. The MCP half of that gap was closed by #300.

**A token without scope claims is authorized by the IAM PEP (#768).** The
catalog is enforced against the token's `scp` claim only on the platform-token
path (`PlatformToken.Enabled`). With platform tokens off — the default — the
daemon's local validator (`grpcTokenValidator`) reports only that a token is
valid, so `selectGRPCTCPAuth` pairs it with `iamTokenAuthorizer`
(`WithAuthorizationChecker`): the token's verified subject, tenant and roles go
to the IAM PEP, which decides the method's `"<resource>:<action>"`, exactly as
on QUIC (#767). A token naming no tenant is denied. Without a PEP the gRPC TCP
transport is refused with `ErrTransportAuthRequired`, and the OIDC interceptor
answers `PermissionDenied` (`ErrAuthorizationCheckerRequired`) for any token
from a claim-less validator that has no checker; a PEP error is `Unavailable`
(`ErrAuthorizationCheckFailed`). Before this, the default configuration let
any valid token call every classified method, `Shutdown` and the BMC power RPCs
included.

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
| `PUT /api/v1/gateway/vpn-leases/{id}`, `DELETE /api/v1/gateway/vpn-leases/{id}/{tenant}/{lease}` | `{id}` == client certificate CN; a lease another gateway issued is refused | 401 unverified · 403 mismatch or another gateway's lease |
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
