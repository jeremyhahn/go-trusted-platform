# Go SDK — User Guide

> **Status: NORMATIVE** · Scope: connecting to `platformd` from Go · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

---

## 1. Install

```bash
go get github.com/jeremyhahn/go-trusted-platform/sdk/go
```

| Import | Package name | Use |
|---|---|---|
| `github.com/jeremyhahn/go-trusted-platform/sdk/go` | `platform` | client, options, errors |
| `github.com/jeremyhahn/go-trusted-platform/sdk/go/gen` | `platformv1` | request and response messages |
| `github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/<protocol>` | — | blank-import every transport you use |
| `github.com/jeremyhahn/go-trusted-platform/sdk/go/services/<name>` | `<name>` | domain wrappers |
| `github.com/jeremyhahn/go-trusted-platform/sdk/go/auth` | `auth` | mTLS and token credentials |

A transport you did not import fails with `ErrProtocolNotImplemented`.

## 2. Connect

```go
import (
    "context"
    "fmt"

    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

func version(ctx context.Context, token string) error {
    client, err := platform.NewClient(ctx,
        platform.WithGRPCAddr("platform.example.com:10443"),
        platform.WithTLSServerName("platform.example.com"),
        platform.WithBearerToken(token),
    )
    if err != nil {
        return err
    }
    defer client.Close()

    resp, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        return err
    }
    fmt.Println(resp.GetVersion(), client.Protocol())
    return nil
}
```

With several addresses set, the SDK tries them in a fixed order and keeps the
first one that connects:

1. `WithPreferredProtocol`;
2. Unix, when running as root;
3. gRPC, REST, QUIC, MCP;
4. embedded.

`WithOnlyProtocol` disables fallback. `client.Protocol()` reports the transport
in use, and `client.Ping(ctx)` checks the daemon.

### Options

| Option | Default |
|---|---|
| `WithUnixSocket(path)` | `/run/platformd.sock` |
| `WithGRPCAddr(addr)` | unset (port `10443`) |
| `WithRESTAddr(addr)` | unset (port `8443`) |
| `WithQUICAddr(addr)` | unset (port `9444`) |
| `WithMCPAddr(addr)` | unset (port `9445`) |
| `WithTLSConfig(*tls.Config)` | system roots, TLS 1.3 (see [§3](#3-credentials)) |
| `WithTLSServerName(name)` | from the address (see [§3](#3-credentials)) |
| `WithBearerToken(token)` | none (see [§3](#3-credentials)) |
| `WithTimeout(time.Duration)` | `5s` |
| `WithMaxMessageSize(bytes)` | 4 MiB |
| `WithPreferredProtocol(platform.Protocol)` | none |
| `WithOnlyProtocol(platform.Protocol)` | none |
| `WithEmbeddedServices(*embedded.ServiceRegistry)` | none |
| `WithQuicBaaSAddr(addr)`, `WithQuicBaaSTransport(name)` | none; transport auto-detected |
| `WithQuicBaaSTLSConfig(*tls.Config)` | none; required with `WithQuicBaaSAddr` (see [§5](#5-go-quicbaas-services)) |

`platform.ConnectUnix(ctx, opts)` and `platform.ConnectGRPC(ctx, opts)` connect
with one protocol and no fallback.

## 3. Credentials

`WithTLSConfig`, `WithTLSServerName` and `WithBearerToken` are the credential
options. Where each one can go:

| Transport | Credential options |
|---|---|
| gRPC, QUIC | honoured; always TLS 1.3 |
| REST | honoured; an `http://` address fails with `ErrInsecureTransport` |
| MCP | honoured over `https://`, the default when the address has no scheme; always TLS 1.3. Over `http://` they fail with `ErrInsecureTransport`; a bare `http://` works only without them, and never against platformd, which serves MCP over TLS 1.3 only (#844) |
| Unix | refused with `ErrUnsupportedOption`; the daemon authenticates the local user from the socket |
| Embedded | refused with `ErrUnsupportedOption`; calls never leave the process |

A refused option is a connect error like any other, so with fallback enabled
`Connect` skips that transport and tries the next one. Leave the credential
options unset when you mean to use Unix or embedded. The server side of these
rules is in [../daemon/api.md §1](../daemon/api.md#1-the-six-transports).

Over the network, use mTLS, a bearer token, or both:

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/auth"

provider, err := auth.NewMTLSProvider(
    auth.WithCAFile("<install-dir>/certs/ca.pem"),
    auth.WithCertFile("<install-dir>/certs/client.pem"),
    auth.WithKeyFile("<install-dir>/certs/client.key"),
)
if err != nil {
    return err
}
client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithTLSConfig(provider.GetTLSConfig()),
)
```

`auth.NewTokenProvider(auth.WithToken(jwt), auth.WithRefreshCallback(fn))`
holds a JWT, reads its `exp` claim and refreshes it through the callback. Pass
`provider.GetToken(ctx)` to `platform.WithBearerToken`.

## 4. Call services

Each accessor on `Client` (`Daemon()`, `TPM()`, `CA()`, `KMS()` and the rest,
listed in [api.md §2](api.md#2-platform-services-by-transport)) returns the
generated `platformv1` gRPC client. The `services/<name>` wrappers add typed
results and pagination on top:

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"

info, err := ca.NewClientFromGRPC(client.CA()).GetCAInfo(ctx)
```

A wrapper can also be built without a `platform.Client`, on an adapter from a
transport package's `Connect`; every wrapper's `NewClient` takes a
`transport.Adapter`:

```go
import (
    grpctransport "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/eab"
)

adapter, err := grpctransport.Connect(ctx, opts) // opts *platform.Options
if err != nil {
    return err
}
defer adapter.Close()
eabClient, err := eab.NewClient(adapter)
```

## 5. go-quicbaas services

Set the go-quicbaas address to open the second client:

```go
client, err := platform.NewClient(ctx,
    platform.WithUnixSocket("/run/platformd.sock"),
    platform.WithQuicBaaSAddr("baas.example.com:10443"),
    platform.WithQuicBaaSTransport("grpc"),
    platform.WithQuicBaaSTLSConfig(baasTLS), // *tls.Config for quicbaasd
)
qb, err := client.QuicBaaS()
if err != nil {
    return err // ErrQuicBaaSNotConfigured or ErrQuicBaaSInitFailed
}
keys := qb.Security().KMS()
```

The go-quicbaas SDK refuses every connection without TLS, so an address
without `WithQuicBaaSTLSConfig` makes `QuicBaaS()` return
`ErrQuicBaaSInitFailed` wrapping `ErrQuicBaaSTLSNotConfigured`.
`WithQuicBaaSTransport` takes `unix`, `grpc`, `rest`, `quic` or `mcp`; an empty
value auto-detects. Any other name makes `QuicBaaS()` return
`ErrQuicBaaSInitFailed` wrapping `ErrProtocolNotSupported`; platformd services
are unaffected. For typed accessors, wrap the client with
`quicbaas.NewClientFromSDK(qb)` from `sdk/go/services/quicbaas`.

### Agentic orchestration

The typed wrapper routes the agentic clients: `Orchestrator()` (agents,
sessions, tasks, jobs, workflows), `Project()`, `Account()` (the pooled
provider accounts a session is spawned against) and `SDLC()` (forge bindings,
onboarding, conformance and deliveries). The container-trust types come
from `sdk/go/services/orchestration`:

```go
import (
    sdkquicbaas "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/quicbaas"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestration"
)

baas, err := sdkquicbaas.NewClientFromSDK(qb)
if err != nil {
    return err
}
agents := baas.Orchestrator()

level, err := orchestration.ResolveTrustLevel(
    orchestration.TrustLevelDefault,
    orchestration.TrustPolicyAttested,
    nil, // no tenant override
    orchestration.TrustCapabilities{DigestPinning: true, HostTPM: true},
)
var violation *orchestration.TrustLevelViolationError
if errors.As(err, &violation) {
    return err // the host cannot prove the tier the policy requires
}
```

The request and response types of each client come from its sibling package,
`sdk/go/services/{orchestrator,project,account,sdlc}`
([api.md §3.2](api.md#32-agentic-client-types)):

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/project"

_, err = baas.Project().GrantAgentRole(ctx, &project.GrantAgentRoleRequest{
    TenantID:  tenantID,
    ProjectID: projectID,
    AgentID:   agentID,
    Role:      project.ProjectRoleWorker,
})
```

### Application and search services

The same wrapper routes `Cache()`, `Vector()`, `TimeSeries()`,
`ObjectStorage()`, `Scheduler()`, `Messaging()`, `Backup()`,
`ParameterStore()`, `Operations()`, `ObjectStorageAdmin()`,
`ObjectTransfer()`, `Embedding()`, `Ollama()` and `RAG()`. Their types come
from
`sdk/go/services/{cache,vector,timeseries,objectstorage,scheduler,messaging,backup,parameterstore,operations,objectstorageadmin,objecttransfer,embedding,ollama,rag}`
([api.md §3.4](api.md#34-application-and-search-client-types)):

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/vector"

resp, err := baas.Vector().SearchSimilar(ctx, &vector.SearchSimilarRequest{
    Namespace:   "embeddings",
    QueryVector: embedding,
    K:           10,
})
```

An accessor returns nil when quicbaasd does not serve that service. Every
accessor other than Cache, Scheduler, Messaging and ObjectStorage is reached
only through the side-client.
platformd serves those four itself: `platform.Client`'s `Cache()`,
`Scheduler()`, `Messaging()` and `ObjectStorage()` reach them on the platform
transport, and `platformctl cache`, `scheduler`, `messaging` and
`objectstorage` drive them ([cli.md](cli.md)).

## 6. In-process (embedded)

A Go program that links the platform services can call them without a socket:

```go
import "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"

client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolEmbedded),
    platform.WithEmbeddedServices(&embedded.ServiceRegistry{
        Daemon: daemonServer,
        CA:     caServer,
    }),
)
```

Calls run on the caller's goroutine and replies are copied, so the result never
aliases server state. A method whose service is not in the registry returns
`codes.Unimplemented`. Streaming RPCs need gRPC or Unix.

## 7. Errors

Connection failures are typed values in package `platform`:

```go
var unavailable platform.ErrDaemonUnavailable
if errors.As(err, &unavailable) {
    log.Printf("tried %v: %v", unavailable.Attempted, unavailable.LastErr)
}
```

A daemon that does not answer within `WithTimeout` (REST health probe, QUIC
handshake, MCP `initialize`) fails with `ErrConnectionFailed` wrapping
`ErrTimeout`:

```go
var timeout platform.ErrTimeout
if errors.As(err, &timeout) {
    log.Printf("%s gave up after %s", timeout.Operation, timeout.Elapsed)
}
```

Unix and gRPC connect lazily, so they time out on the first call instead, as a
gRPC `DeadlineExceeded` status.

A REST call bound to its TLS channel (the diskless `BootCertificate` and
`BootDelivery`) dials a connection of its own. `WithTimeout` bounds that dial
and its TLS handshake even when the call's context has no deadline, and an
earlier context deadline still wins. A daemon that accepts the connection and
never answers TLS fails the call with `transport.ErrChannelBindingUnavailable`
wrapping `ErrTimeout` (operation `REST bound dial`).

`ErrInsecureTransport` and `ErrUnsupportedOption` mean the options and the
address do not fit the transport ([§3](#3-credentials)); fix the configuration
rather than retrying.

After a call reaches a service, errors are gRPC status errors on every
transport; read them with `status.Code(err)`. REST maps HTTP statuses onto the
same codes ([engineering.md §4](engineering.md#4-transport-contracts)).

The MCP transport retries a call only when it never reached the daemon or the
daemon asked for a retry: a dial failure, an HTTP 429, 502, 503 or 504
(honouring `Retry-After`), or a timeout on a read-only method. A refusal, any
other error and a cancelled context come back at once
([engineering.md §4](engineering.md#4-transport-contracts)).
