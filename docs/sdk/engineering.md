# Go SDK — Engineering

> **Status: NORMATIVE** · Scope: building, extending and testing `sdk/go` · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

---

## 1. Module

`sdk/go/go.mod` declares `github.com/jeremyhahn/go-trusted-platform/sdk/go`.
It requires `github.com/jeremyhahn/go-quicbaas/sdk/go` and nothing from the root
module `github.com/jeremyhahn/go-trusted-platform`, and it has no `replace`
directives. A tag of `sdk/go` therefore builds on its own (#840).

The dependency runs one way. The root module requires `sdk/go` through
`replace ./sdk/go` and imports the wire contract from it:

| Package | Wire contract | Root importers |
|---|---|---|
| `wire/quicwire` | QUIC frame and message types, opcodes, codecs, status codes, `ClientConfig`, the client | `pkg/api/quic`, `pkg/api/daemon` |
| `wire/mcpwire` | JSON-RPC request, response and error types, the MCP client | `pkg/api/mcp` |
| `wire/restwire` | `WebServiceResponse`, the `/api/v1` response envelope; the device role and auth-method strings and `NormalizeProfileJSON` | `pkg/webservice/v1/response` and the REST handlers |
| `wire/switchwire` | `PortMode`, `PortStatus` | `pkg/switch` and the switch REST handlers |

Server behaviour stays in root: the QUIC server and `ServerConfig`, the MCP tool
argument structs and handlers, the response writer, the proxy protobuf
converters (`pkg/proxy/proto.go`). A type both sides put on the wire belongs in
`wire/`; never copy it into root or alias it there.

`make sdk-consumer-check` (`scripts/sdk-consumer-check.sh`, run by CI) copies
`sdk/go` alone into a temporary directory, builds every SDK package from a
throwaway consumer module with `GOWORK=off`, and fails if any root-module
package is in the dependency graph. Run it after changing an SDK import.

`sdk/go` is tagged in lockstep with the root (release-versioning.md §6).
`make release-alpha VERSION=vX.Y.Z-alpha`, run on `main`, writes `VERSION`,
re-pins the root's `sdk/go` requirement to the new version, commits, and tags
`vX.Y.Z-alpha` and `sdk/go/vX.Y.Z-alpha` on that commit: annotated, signed
through `agent-git.sh`, and pushed with the commit in one atomic push that
carries no other tag. The version is never inferred; `CHANGELOG.md` must hold a
`## [X.Y.Z-alpha]` section first. The recipe is the handbook template, copied
verbatim into `build/make/`.

The module has its own build. Run Go commands from `sdk/go/` and take the tags
from the root Makefile; never type the tag list:

```bash
cd sdk/go
go vet -tags "$(make -C ../.. -s print-build-tags)" ./...
go test -tags "$(make -C ../.. -s print-build-tags)" ./transport/rest/ -run TestName -v
```

## 2. Layout

| Path | Contents |
|---|---|
| `client.go` | `Client` interface, `ServiceClients`, `NewClient`, `Connect`, `ConnectUnix`, `ConnectGRPC`, `RegisterProtocol`, protocol order, QuicBaaS side-client |
| `options.go` | `Options`, the `With*` options, `Default*` constants, `Validate` |
| `protocol.go` | `Protocol`: `ProtocolUnix`, `ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`, `ProtocolEmbedded`; `ParseProtocol`, `DefaultPort` |
| `errors.go` | typed connection errors (§5) |
| `wire/<protocol>wire/` | the wire contract shared with the daemon (§1) |
| `transport/adapter.go` | `transport.Adapter` |
| `transport/<protocol>/` | one adapter per protocol; each registers from `init()` |
| `gen/` | generated protobuf and gRPC code, package `platformv1`, 31 services |
| `services/<name>/` | domain wrappers over the generated clients, plus `common` (pagination, shared errors) |
| `services/quicbaas/`, `services/auth/` | typed frontage over the go-quicbaas SDK |
| `services/orchestration/` | container-trust aliases over `go-quicbaas/sdk/go/orchestration` |
| `services/{orchestrator,project,account,sdlc}/` | request, response and record aliases over the matching `go-quicbaas/sdk/go/client/*` package |
| `services/{cache,vector,timeseries,objectstorage,scheduler,messaging}/` | request, response and value aliases over the matching `go-quicbaas/sdk/go/client/*` package |
| `auth/` | `Provider`, `MTLSProvider`, `TokenProvider`, `NoneProvider` |

### Service wrapper constructors

Most wrappers have two constructors:

- `NewClient(conn transport.Adapter) (*Client, error)`, which returns
  `common.ErrNilConnection` for a nil adapter or connection;
- `NewClientFromGRPC(platformv1.<Service>Client) *Client`, which wraps an
  accessor from `platform.Client` (e.g. `ca.NewClientFromGRPC(c.CA())`).

`fido2`, `piv`, `luks` and `ceremony` are different. They expose
`NewGRPCClient(*grpc.ClientConn)` and
`NewGRPCClientFromClient(platformv1.<Service>Client)`, which wraps the
matching accessor (e.g. `luks.NewGRPCClientFromClient(c.LUKS())`).

`switch` (package `switchsdk`) is HTTP-only: `NewClient(baseURL, *http.Client)`.
`invitation` and `tenant` (user client) have both REST and gRPC constructors.

### Re-exporting a go-quicbaas capability

A go-quicbaas client is re-exported by a one-line accessor on
`services/quicbaas.Client` that returns the upstream client (`c.sdk.Orchestrator()`),
plus a row flipped to ✅ in [api.md §3](api.md#3-go-quicbaas-re-export-surface).
Its tests prove the accessor returns the SDK's own client and returns nil when the
SDK serves none.

A QRDB-backed upstream accessor (`Security().Barrier()`, `Discovery()`, ...) also
returns an error, because go-quicbaas opens its QRDB transport lazily on the first
call. The wrapper returns `(client, error)` too and wraps the upstream error in
`ErrServiceUnavailable{Service, Cause}` from `services/quicbaas/errors.go`, which
unwraps to the cause. Its tests also prove that failure path.

Upstream types are re-exported as aliases (`type TrustLevel = quicbaasorch.TrustLevel`),
never as copies, so `errors.As` and type assertions hold across the boundary;
`services/orchestration` and `services/orchestrator` test that through a wrap
chain. Each alias package also has a table test that compares every alias's
`reflect.Type` with the upstream type, so a defined type that slips in fails the
test. Upstream functions are
wrapped in a function, not bound to an exported `var`, so no linked package can
replace them.

## 3. Adding a service or method

A method is done when it reaches the caller over all six transports, in one
change set:

1. **Proto and server.** Define the RPC and implement the server on every daemon
   transport (see [../daemon/api.md](../daemon/api.md)), then regenerate
   `sdk/go/gen`.
2. **Client surface.** For a new service, add the accessor to the `Client`
   interface, a field to `ServiceClients` and the constructor call in
   `initServiceClients`. Add a domain wrapper under `services/<name>/` when
   callers need more than raw protobuf.
3. **REST.** Add the method to `grpcMethodToRESTMap`. Use `templatedRouteTable`
   when the route has path parameters, or query parameters — a handler that
   reads `r.URL.Query()` never sees a field sent in the body, and BGP withdraw
   and overlay MAC forget once failed every REST call that way
   ([../bgp/api.md](../bgp/api.md#1-the-six-transports) §1,
   [../sdn/api.md](../sdn/api.md) §6). When the handler's request type is not
   the gRPC message, register a `restRequestEncoders` entry that builds the
   body it decodes; when its reply is not the gRPC reply, a
   `restResponseDecoders` entry. Prove both against the real handler, not a
   fixture — the device profile routes once sent `{"profile": {...}}` to a
   handler that decodes a flat `ProfileRequest`
   ([../device/api.md](../device/api.md) §1b). A path parameter may name a nested field with a dotted
   path (`device.id`) when the request carries the id inside the resource;
   the field is cleared from the body, and a zero value is
   `codes.InvalidArgument` before anything is sent. An unmapped method falls back to a guessed
   `POST /api/v1/<service>/<method>`. Do not rely on the fallback: map the
   method explicitly.
4. **QUIC.** Add the method to `grpcMethodToOpcodeMap`. For a method in a
   category opcode, also add it to `categorySubOpcodeMap`. A missing
   sub-opcode panics at `init` with `ErrCategorySubOpcodeMissing`, so the
   omission cannot ship.
5. **MCP.** Add the method to `grpcMethodToMCPToolMap`. Add `mcpArgBuilders` /
   `mcpReplyDecoders` entries when `structToMap` / `mapToStruct` cannot
   round-trip the message. An unmapped method returns `codes.Unimplemented`
   (`ErrMethodNotMapped`).
6. **Embedded.** Add the server field to `ServiceRegistry` and a
   `register<Service>Handlers` function in `transport/embedded/dispatch.go`. An
   unregistered method returns `codes.Unimplemented`.
7. **Docs.** Update the row in [api.md](api.md) and the feature folder's own
   `api.md`.

Streaming RPCs work only on unix and grpc. REST, QUIC, MCP and embedded return
`codes.Unimplemented` from `NewStream`. A capability that needs a streaming RPC
also needs a unary form, or it is `MISSING` on four transports.

## 4. Transport contracts

| Adapter | Requires | Applies | Refuses | Failure on connect |
|---|---|---|---|---|
| unix | `UnixSocket` (default `/run/platformd.sock`) exists (`os.Stat`) | `MaxMessageSize` | `BearerToken`, `TLSConfig`, `TLSServerName` (`ErrUnsupportedOption`) | `ErrConnectionFailed` if the socket is missing; the connection itself is lazy |
| grpc | `GRPCAddr` (`ErrEmptyAddress`) | `ClientTLSConfig()`, `BearerToken` per RPC, `MaxMessageSize` | — | `ErrConnectionFailed` only for an unusable target; the connection is lazy, so a dead endpoint fails on the first RPC |
| rest | `RESTAddr`; `https://` is added when no scheme is given | `ClientTLSConfig()`, `Timeout`, `BearerToken` | any `http://` address (`ErrInsecureTransport`) | `ErrConnectionFailed` when `GET /health` fails or is not 2xx; wrapping `ErrTimeout` when it runs out of time |
| quic | `QUICAddr` | `ClientTLSConfig()`, ALPN `platform-quic`, idle timeout `2 × Timeout`, `BearerToken` in every request | — | `ErrConnectionFailed` when the dial or handshake fails; wrapping `ErrTimeout` when it runs out of time |
| mcp | `MCPAddr`; `https://` is added when no scheme is given | over `https://`: `ClientTLSConfig()`, `BearerToken`; always `Timeout` | `BearerToken`, `TLSConfig`, `TLSServerName` over `http://` (`ErrInsecureTransport`) | `ErrConnectionFailed` when `initialize` fails; wrapping `ErrTimeout` when it runs out of time |
| embedded | `EmbeddedServices` holding `*embedded.ServiceRegistry` (`ErrNilRegistry`) | none | `BearerToken`, `TLSConfig`, `TLSServerName` (`ErrUnsupportedOption`) | `ErrNilRegistry` |

`Options.ClientTLSConfig()` clones `TLSConfig` (or starts from the system
roots), raises it to TLS 1.3 and applies `TLSServerName`; the caller's config
is never modified. `Options.CredentialOptions()` lists which of `BearerToken`,
`TLSConfig` and `TLSServerName` are set; Unix, embedded and plaintext MCP refuse
the connection when it is non-empty. `ErrUnsupportedOption.Option` names the
first one set, in that order.

platformd serves MCP over TLS 1.3 only and has no plaintext MCP listener
(#844), so against the daemon the mcp adapter always dials `https://` and
verifies the server against `ClientTLSConfig()`. The `http://` pass-through
exists only for third-party MCP servers, and only without credentials.

The mcp adapter's wire client (`mcpwire.DefaultClientConfig`: 3 retries, 1 s
apart, `Timeout` per attempt) retries only what `mcpwire.IsRetryable` accepts:
a dial failure, an HTTP 429, 502, 503 or 504, and a timeout on a method that
only reads (`initialize`, `ping`, `tools/list`, `resources/list`,
`resources/read`). A `Retry-After` on a 429, 502, 503 or 504 replaces the
delay before the next try. Everything else returns at once: a JSON-RPC error,
a tool error result, any other HTTP status, a timeout on `tools/call`, and a
cancelled or expired context. An answer the server gave on purpose is the same
on every try, and a state-changing call sent twice can apply twice.

HTTP → gRPC status mapping (REST, and a non-2xx answer on MCP):

| HTTP | gRPC code |
|---|---|
| 400 | `InvalidArgument` |
| 401 | `Unauthenticated` |
| 403 | `PermissionDenied` |
| 404 | `NotFound` |
| 409 | `AlreadyExists` |
| 429 | `ResourceExhausted` |
| 500 | `Internal` |
| 501 | `Unimplemented` |
| 502, 503 | `Unavailable` |
| 504 | `DeadlineExceeded` |
| other | `Unknown` |

## 5. Errors

Connection errors live in `sdk/go/errors.go`. They are value types, so match
them with a value target:

| Error | Meaning |
|---|---|
| `ErrNilOptions`, `ErrEmptyAddress`, `ErrNotConnected` | sentinels |
| `ErrInvalidOptions{Field, Reason}` | `Validate` rejected an option |
| `ErrConnectionFailed{Protocol, Target, Err}` | one adapter failed (unwraps) |
| `ErrDaemonUnavailable{Attempted, LastErr}` | every candidate protocol failed (unwraps) |
| `ErrTimeout{Operation, Elapsed, Err}` | inside `ErrConnectionFailed`: the REST health probe, QUIC handshake or MCP `initialize` ran out of time (context deadline or network timeout); unwraps, so `errors.Is(err, context.DeadlineExceeded)` still holds |
| `ErrProtocolNotImplemented{Protocol}` | no adapter registered for the protocol |
| `ErrProtocolNotSupported{Transport}` | inside `ErrQuicBaaSInitFailed`: `QuicBaaSTransport` is not `unix`, `grpc`, `rest`, `quic`, `mcp` or empty |
| `ErrInsecureTransport{Protocol, Target, Reason}` | the adapter refused a plaintext address: any `http://` for REST, `http://` with a credential option for MCP |
| `ErrUnsupportedOption{Protocol, Option, Reason}` | the transport cannot carry a credential option it was given (Unix, embedded) |
| `ErrServiceUnavailable{Service}` | the service client was not initialised |
| `ErrCloseFailed{Protocol, Err}` | closing the adapter or side-client failed |
| `ErrQuicBaaSNotConfigured{}` | `QuicBaaS()` called with no address configured |
| `ErrQuicBaaSInitFailed{Addr, Transport, Err}` | the side-client failed to open |

The embedded transport has its own types (`transport/embedded/errors.go`):
`ErrNilRegistry`, `ErrNotConnected`, `ErrMethodNotFound`, `ErrTypeMismatch`,
`ErrMarshalFailed`, `ErrUnmarshalFailed`, `ErrServiceNotRegistered`. The auth
providers have theirs in `auth/errors.go`. After a call reaches a service,
errors are gRPC status errors on every transport.

## 6. Tests

- Unit tests live beside each package and run in-process.
- `test/integration/<feature>/` drives each feature through `platformctl` and
  through per-protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) against a
  real daemon in the devcontainer. Run them with `make integration-test-<feature>`.
