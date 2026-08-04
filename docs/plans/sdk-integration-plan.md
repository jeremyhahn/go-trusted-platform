# SDK Integration Plan: Unified QuicBaaS Storage Architecture

> **STATUS: SUPERSEDED (CA model).** This plan was written when
> `go-trusted-ca` was a standalone repository whose `CertificateAuthority`
> was injected into go-quicbaas via `WithCA`. **go-trusted-ca has since
> been decommissioned**: its CA and ACME engines were absorbed into
> **go-xkms** (`pkg/ca` + `pkg/acme`), and go-trusted-platform now consumes
> CA/ACME exclusively through the **go-quicbaas SDK** (which composes
> go-xkms) -- there is no separate `go-trusted-ca` import and no platform
> `WithCA` injection step. The storage-unification objectives below remain
> valid; read every `go-trusted-ca/...` path and `WithCA`-injection step as
> the go-xkms-via-quicbaas surface.

## Overview

This document describes the plan to unify the storage architecture across the go-trusted-platform
ecosystem. The goal is to eliminate direct go-objstore usage from go-trusted-platform, establish
a clean single-CA model where the CA (go-xkms `pkg/ca`, formerly go-trusted-ca) is reached through go-quicbaas, and route all
platform storage through the QuicBaaS ObjectStorage SDK with proper multi-tenant DEK isolation.

---

## Current State

### Problems

**Problem 1: Direct go-objstore imports (technical debt)**

`pkg/storage/objstore/` (adapter.go + config.go) bridges `common.Storage` (go-objstore) to
`xkmssdk.StorageBackend` (go-xkms). This package exists only because go-trusted-platform was
initializing xkms backends using go-objstore as a storage driver, even though go-xkms has its
own native `xkmssdk.NewFileStorageBackend(path)` constructor. 12 files import this package.

**Problem 2: xkms pre-initialization hack**

`pkg/app/app.go initStores()` (lines 1100–1150) pre-initializes xkms with filesystem-backed
storage before QuicBaaS starts. This is required because `xkmssdk.ServiceInitialize()` uses
`sync.Once` — whoever calls it first wins. QuicBaaS's embedded server `startKMS()` would
otherwise initialize xkms with in-memory storage, losing key persistence across reboots. The
hack races the initialization and is fragile.

**Problem 3: Two separate CA instances**

go-quicbaas always creates its own internal TrustedCA for TLS bootstrap via `initializeCA()` in
`pkg/server/lifecycle.go`. go-trusted-platform independently creates a go-trusted-ca CA.
These are distinct instances with no relationship. go-quicbaas cannot use the platform CA for
its TLS needs, and the platform CA cannot benefit from go-quicbaas's lifecycle management.

**Problem 4: go-objstore-backed ACME storage**

`pkg/app/app.go InitACMEClient()` (line 1434) creates `quicbaassdk.NewObjectStorageLocal()` then
passes it to `trustedca.NewACMEStorageFactory()`. Despite using the QuicBaaS SDK type name, this
is the local filesystem backend (go-objstore under the hood, not the multi-tenant QuicBaaS
ObjectStorage service). The `acmestorage.Factory` interface is sound; the backing implementation
needs to be replaced with the real QuicBaaS ObjectStorage client.

**Problem 5: ObjectStore wraps go-objstore**

`pkg/store/object/store.go ObjectStore` wraps `common.Storage` (go-objstore interface) and is
used by `CAStoreFactory.CreateCertStore()` in `pkg/app/ca_factory.go`. This creates a
dependency chain: CA cert storage → ObjectStore → go-objstore → filesystem. The same isolation
can be achieved through QuicBaaS ObjectStorage with proper namespace prefixing.

### Current Dependency Graph

```
go-trusted-platform
├── pkg/storage/objstore/     → go-objstore (direct, 12 files)
├── pkg/store/object/         → go-objstore (via common.Storage)
├── pkg/app/app.go            → go-objstore (initStores xkms hack, newKeyBackend)
├── pkg/app/ca_factory.go     → object.ObjectStore → go-objstore
├── pkg/daemon/commands/      → go-objstore (indirect via app)
├── pkg/api/daemon/           → go-objstore (test files)
└── pkg/api/grpc/ca/          → go-objstore (test files)
```

### Target Dependency Graph

```
go-trusted-platform
├── xkms: native NewFileStorageBackend(path) for CA key/cert storage
├── go-trusted-ca: CA init with xkms native backends
├── go-quicbaas: WithCA(trustedCA) — single CA, no internal TrustedCA
│   └── QuicBaaS ObjectStorage, KMS, KV, IAM available
└── All platform storage through QuicBaaS SDK
    ├── ObjectStorage (TenantID + TenantDEK) → certs, ACME state, objects
    ├── KMS → application keys (already in place)
    └── go-objstore: ZERO direct imports (transitive only)
```

---

## Target Bootstrap Order

The new startup sequence eliminates the race condition and establishes deterministic ordering:

```
1. xkmssdk.NewFileStorageBackend(caRoot/keys)  — pure filesystem, no network
2. xkmssdk.NewFileStorageBackend(caRoot/certs) — pure filesystem, no network
3. xkmssdk.NewPKCS8Backend(keyStorage)         — or TPM2Backend if hardware
4. trustedca.New(keyStore, certStore, config)   — platform CA, fully initialized
5. quicbaas.NewServer(cfg, WithCA(trustedCA))   — single CA injection
   └── QuicBaaS skips internal initializeCA(),
       uses platform CA for TLS cert issuance
6. quicbaasSDK.ObjectStorage()                 — now available
7. NewQuicBaaSACMEFactory(objectStorage)        — QuicBaaS-backed ACME storage
8. platform services, API servers, etc.
```

---

## Phases

---

### Phase 1: go-quicbaas — WithCA Server Option

**Repository:** `/home/jhahn/sources/go-quicbaas`

**Goal:** Add an external CA injection point to go-quicbaas so the platform CA can be provided
at construction time, bypassing the internal `initializeCA()` entirely. The server must remain
fully standalone-capable when no external CA is provided.

**Type Compatibility**

`go-xkms/pkg/ca/interface.go` defines `type TrustedCA = TrustedCA` (a type alias, not a new type).
`go-trusted-ca`'s `CertificateAuthority` embeds `xkmsca.TrustedCA`. Both sides use the same
interface. The `WithCA` option field type is `xkmsca.TrustedCA` (or equivalently `xkmsca.TrustedCA`).

#### 1.1 Files to Modify

**`pkg/server/server.go`**

Add an `options` field to the `Server` struct to hold server options supplied at construction:

```go
type serverOptions struct {
    externalCA      xkmsca.TrustedCA
    tlsCertificate  *tls.Certificate
}
```

Add `opts serverOptions` field to `Server`.

Update `NewServer` signature and body to accept variadic options and apply them:

```go
type ServerOption func(*serverOptions)

func WithCA(ca xkmsca.TrustedCA) ServerOption {
    return func(o *serverOptions) { o.externalCA = ca }
}

func WithTLSCertificate(cert *tls.Certificate) ServerOption {
    return func(o *serverOptions) { o.tlsCertificate = cert }
}

func NewServer(cfg *config.Config, opts ...ServerOption) (*Server, error) {
    // apply options
    var options serverOptions
    for _, opt := range opts {
        opt(&options)
    }
    s := &Server{..., opts: options}
    ...
}
```

Also export the existing `CA()` accessor so callers can retrieve it:

```go
func (s *Server) CA() xkmsca.TrustedCA { return s.xkmsCA }
```

**`pkg/server/lifecycle.go`**

Update `initializeCA()` to short-circuit when an external CA is already provided:

```go
func (s *Server) initializeCA() error {
    if !s.config.Security.TLSEnabled {
        return nil
    }

    // When the caller provides an external CA, skip internal CA bootstrap.
    // The external CA is responsible for having completed Load() or Init()
    // before being passed here.
    if s.opts.externalCA != nil {
        s.xkmsCA = s.opts.externalCA
        s.logger.Info("Using external certificate authority — skipping internal CA bootstrap")
        return s.issueTLSCertFromExternalCA()
    }

    // ... existing internal CA initialization code unchanged ...
}
```

Add `issueTLSCertFromExternalCA()` as a private method on `Server`. It issues a server TLS cert
using the injected CA, writes cert/key to the paths in `s.config.Security.*`, and sets
`s.tlsConfig`. If `s.opts.tlsCertificate` is already set (pre-issued cert), skip issuance and
use it directly.

**`sdk/go/server.go`**

Export the new `WithCA` and `WithTLSCertificate` option types so downstream consumers (including
go-trusted-platform) can use them through the SDK:

```go
// ExternalCAOption injects an external Certificate Authority into the server.
// When set, the server skips its internal CA bootstrap and uses this CA for TLS.
type ServerOption = server.ServerOption

var (
    WithCA             = server.WithCA
    WithTLSCertificate = server.WithTLSCertificate
)
```

Update the `NewServer` var alias in `sdk/go/server.go` to pass through options:

```go
var NewServer = server.NewServer
```

This already works because `server.NewServer` now accepts `...ServerOption`.

#### 1.2 Files to Create

None required. All changes are modifications to existing files.

#### 1.3 Testing Requirements

- Unit test `server_test.go`: `TestNewServer_WithExternalCA` — verify `s.CA()` returns the
  provided CA after construction.
- Unit test `lifecycle_test.go`: `TestInitializeCA_ExternalCA` — verify `initializeCA()` skips
  internal bootstrap when external CA is set, and `s.xkmsCA` equals the provided instance.
- Unit test `lifecycle_test.go`: `TestInitializeCA_ExternalCA_TLSDisabled` — verify early return
  when `TLSEnabled == false` regardless of external CA.
- Unit test: `TestWithTLSCertificate` — verify pre-issued cert bypasses CA cert issuance.
- Existing tests must continue to pass unchanged (no behavior change when options are absent).

#### 1.4 Dependencies

None. This phase is self-contained in go-quicbaas.

---

### Phase 2: go-trusted-platform — New Bootstrap Order

**Repository:** `/home/jhahn/sources/go-trusted-platform`

**Goal:** Replace the xkms pre-initialization hack with a deterministic, ordered initialization
sequence. xkms gets native file storage backends. go-trusted-ca CA is initialized before
QuicBaaS starts. QuicBaaS receives the platform CA via the new `WithCA` option from Phase 1.

#### 2.1 Files to Modify

**`pkg/app/app.go`**

Remove `newKeyBackend()` function (lines 147–156). This function uses `objstore.DefaultLocalConfig`
and `objstore.NewBackendFromConfig` — its purpose disappears when xkms gets native backends.

Remove the import of `"github.com/jeremyhahn/go-trusted-platform/pkg/storage/objstore"` from
`app.go` (will become unused after all call sites are removed).

Rewrite `initXKMSService()` to use `xkmssdk.NewFileStorageBackend(path)` directly:

```go
func (app *App) initXKMSService(caRoot string, soPIN, userPIN xkmssdk.Password) (xkmssdk.ServiceBackend, error) {
    var keyStorageBackend, certStorageBackend xkmssdk.StorageBackend

    if app.Environment == EnvTest {
        keyStorageBackend = xkmssdk.NewStorageMemory()
        certStorageBackend = xkmssdk.NewStorageMemory()
    } else {
        var err error
        keyStorageBackend, err = xkmssdk.NewFileStorageBackend(caRoot)
        if err != nil {
            return nil, ErrXKMSStorageInit{Path: caRoot, Cause: err}
        }
        certStorageBackend, err = xkmssdk.NewFileStorageBackend(caRoot)
        if err != nil {
            return nil, ErrXKMSStorageInit{Path: caRoot, Cause: err}
        }
    }
    // ... rest of backend construction unchanged ...
}
```

Rewrite `initStores()` to remove the xkms pre-initialization block (lines 1100–1150). The new
ordering is: xkms init first (called explicitly before QuicBaaS), then QuicBaaS with `WithCA`:

```go
func (app *App) initStores() error {
    // Initialize platform CA using xkms native file storage.
    // This must happen BEFORE QuicBaaS starts.
    if app.CAConfig != nil && len(app.CAConfig.Identity) > 0 {
        if err := app.initPlatformCA(); err != nil {
            return err
        }
    }

    // Start QuicBaaS with the platform CA injected.
    if app.daoFactory == nil && app.QuicBaaSConfig != nil {
        if err := app.QuicBaaSConfig.ParseTransportFromConfig(); err != nil {
            return ErrQuicBaaSConfig{Cause: err}
        }
        factory, err := quicbaas.NewFactory(app.Logger, app.QuicBaaSConfig, app.CA)
        if err != nil {
            return err
        }
        app.daoFactory = factory
    }

    // ObjectStore and CertStore are now backed by QuicBaaS ObjectStorage.
    // app.Storage is set by the QuicBaaS factory after it starts.
    app.Storage = app.daoFactory.(*quicbaas.Factory).ObjectStorage()

    objectStore, err := object.NewObjectStore(app.Logger, app.Storage, app.PlatformDir, nil)
    if err != nil {
        return err
    }
    app.ObjectStore = objectStore

    cs, err := app.NewCertificateStore(objectStore)
    if err != nil {
        return err
    }
    app.PlatformCertStore = cs

    return nil
}
```

Add `initPlatformCA()` as a private method that:
1. Resolves the CA root path (`platformDir/ca/<cn>`).
2. Calls `xkmssdk.NewFileStorageBackend(caRoot)` for key and cert storage.
3. Calls `initXKMSService(caRoot, soPIN, userPIN)`.
4. Constructs the go-trusted-ca CA via `trustedca.New(...)` or `trustedca.NewFromMultiIdentity(...)`.
5. Assigns result to `app.CA`.

**`pkg/storage/quicbaas/embedded_server.go`**

Update `NewEmbeddedServer` and the `Start()` method to accept and forward the external CA option.
The `EmbeddedServer` currently constructs `quicbaassdk.Server` internally. It needs a field:

```go
type EmbeddedServer struct {
    config     *Config
    logger     *logging.Logger
    server     *quicbaassdk.Server
    externalCA xkmssdk.TrustedCA  // optional; forwarded to server as WithCA option
    ...
}

func NewEmbeddedServerWithCA(config *Config, logger *logging.Logger, ca xkmssdk.TrustedCA) (*EmbeddedServer, error) {
    srv, err := NewEmbeddedServer(config, logger)
    if err != nil {
        return nil, err
    }
    srv.externalCA = ca
    return srv, nil
}
```

In `Start()`, when creating `quicbaassdk.NewServer(cfg)`, forward the CA:

```go
var serverOpts []quicbaassdk.ServerOption
if s.externalCA != nil {
    serverOpts = append(serverOpts, quicbaassdk.WithCA(s.externalCA))
}
s.server, err = quicbaassdk.NewServer(cfg, serverOpts...)
```

**`pkg/storage/quicbaas/factory.go`**

Update `NewFactory` to accept an optional CA parameter and forward it to `EmbeddedServer`:

```go
func NewFactory(logger *logging.Logger, config *Config, ca xkmssdk.TrustedCA) (*Factory, error) {
    ...
    if config.Transport == TransportEmbedded {
        srv, err := NewEmbeddedServerWithCA(config, logger, ca)
        ...
    }
    ...
}
```

The existing `NewFactory(logger, config)` two-argument signature must be updated everywhere it
is called. A convenience overload that accepts `nil` for the CA maintains backward compatibility.

**`pkg/daemon/commands/serve.go`**

Update the call to `app.initStores()` to align with the new ordering. No structural change
needed here — the ordering is encapsulated inside `initStores()`. However, ensure that any
explicit QuicBaaS factory construction in `serve.go` (if present) passes `app.CA`.

**`pkg/boot/commands/manager.go`**

Audit for any direct calls to `objstore.NewBackendFromConfig` or `newKeyBackend`. Replace with
`xkmssdk.NewFileStorageBackend(path)`.

#### 2.2 Files to Create

**`pkg/app/errors.go`** (if not present, else add to existing errors file)

Typed errors to replace ad-hoc `fmt.Errorf` strings:

```go
// ErrXKMSStorageInit is returned when a filesystem storage backend cannot be created.
type ErrXKMSStorageInit struct {
    Path  string
    Cause error
}

func (e ErrXKMSStorageInit) Error() string { ... }
func (e ErrXKMSStorageInit) Unwrap() error { return e.Cause }

// ErrQuicBaaSConfig is returned when QuicBaaS configuration is invalid.
type ErrQuicBaaSConfig struct {
    Cause error
}

func (e ErrQuicBaaSConfig) Error() string { ... }
func (e ErrQuicBaaSConfig) Unwrap() error { return e.Cause }
```

#### 2.3 Testing Requirements

- `pkg/app/app_test.go`: `TestInitStores_NewOrder` — verify that when `CAConfig` is set,
  `app.CA` is non-nil after `initStores()` and `app.daoFactory` is non-nil.
- `pkg/app/app_test.go`: `TestInitStores_NilCA` — verify graceful handling when `CAConfig`
  is nil (client mode, no CA).
- `pkg/storage/quicbaas/embedded_server_test.go`: `TestNewEmbeddedServerWithCA` — verify CA
  is stored and forwarded to `NewServer`.
- Existing unit tests must compile and pass without modification.

#### 2.4 Dependencies

Phase 1 must be complete before Phase 2 can use `quicbaassdk.WithCA`.

---

### Phase 3: QuicBaaS ObjectStorage for Platform Storage

**Repository:** `/home/jhahn/sources/go-trusted-platform`

**Goal:** Replace all platform storage that currently uses go-objstore's `common.Storage` with
QuicBaaS ObjectStorage SDK calls. The `pkg/store/object/store.go` ObjectStore today wraps
`common.Storage`. It should instead wrap `quicbaassdk.ObjectStorageClient`.

#### 3.1 Current Object Storage Call Sites

All 12 files that import go-objstore, grouped by function:

| File | Current Usage | Replacement |
|------|--------------|-------------|
| `pkg/storage/objstore/adapter.go` | Core adapter | Delete entire file |
| `pkg/storage/objstore/config.go` | Backend config/factory | Delete entire file |
| `pkg/app/app.go` | `newKeyBackend`, xkms pre-init | Phase 2 removes these |
| `pkg/app/ca_factory.go` | `object.NewObjectStore` for cert storage | Phase 3 |
| `pkg/store/object/store.go` | `ObjectStorer` wraps `common.Storage` | Rewrite |
| `pkg/store/certstore/adapter.go` | `ObjectStorer` for cert I/O | Update |
| `pkg/api/daemon/*_test.go` | Test helpers | Update |
| `pkg/api/grpc/ca/*_test.go` | Test helpers | Update |

#### 3.2 Files to Modify

**`pkg/store/object/store.go`**

Replace the `common.Storage` dependency with `quicbaassdk.ObjectStorageClient`. The
`ObjectStorer` interface surface stays identical — callers are not affected. Internally,
`Get(key)` maps to `objectStorage.GetObject(ctx, &quicbaassdk.ObjectGetRequest{Key: key})` and
`Save(key, data)` maps to `objectStorage.PutObject(...)`.

The `rootDir` and `partition` fields continue to be used as key namespace prefixes:

```
key = filepath.Join(rootDir, partition, string(userKey))
```

Updated struct:

```go
type ObjectStore struct {
    logger    *logging.Logger
    storage   quicbaassdk.ObjectStorageClient
    tenantID  string  // empty = platform-scoped
    rootDir   string
    partition string
}
```

The `Storage() common.Storage` method on `ObjectStorer` must be replaced with
`ObjectStorage() quicbaassdk.ObjectStorageClient` to avoid exposing the go-objstore interface.

**`pkg/app/ca_factory.go`**

`CAStoreFactory` already holds `storage quicbaassdk.ObjectStorage`. The `CreateCertStore` method
calls `object.NewObjectStore(app.Logger, f.storage, caRoot, &f.certPartition)`. After the
ObjectStore rewrite, this call becomes:

```go
certBackend, err := object.NewObjectStore(
    f.app.Logger, f.storage.Storage(), caRoot, &f.certPartition)
```

The factory already has the QuicBaaS ObjectStorage client available; no structural change.

**`pkg/store/certstore/adapter.go`**

`ObjectStorageAdapter` wraps `object.ObjectStorer`. Once `ObjectStorer.Storage()` returns
`quicbaassdk.ObjectStorageClient`, the `ObjectStorageAdapter` must be updated accordingly.
The `SaveCert`, `GetCert`, `DeleteCert`, `CertChain` methods call into `ObjectStorer` — no
change required to those method bodies if the interface is preserved.

#### 3.3 Files to Delete

- `pkg/storage/objstore/adapter.go`
- `pkg/storage/objstore/adapter_test.go`
- `pkg/storage/objstore/config.go`
- `pkg/storage/objstore/config_test.go`

The directory `pkg/storage/objstore/` is removed entirely.

#### 3.4 Testing Requirements

- `pkg/store/object/store_test.go`: All existing tests must be updated to use
  `quicbaassdk.NewObjectStorageMemory()` instead of a go-objstore memory backend.
- `pkg/store/certstore/adapter_test.go`: Update mock to use `quicbaassdk.ObjectStorageClient`
  instead of `common.Storage`.
- `pkg/app/ca_factory_test.go`: Verify `CreateCertStore` works with in-memory QuicBaaS storage.

#### 3.5 Dependencies

Phase 2 must be complete (QuicBaaS starts with platform CA, ObjectStorage client is available
before platform services start).

---

### Phase 4: QuicBaaS-Backed ACME Storage Factory

**Repository:** `/home/jhahn/sources/go-trusted-platform`

**Goal:** Replace `quicbaassdk.NewObjectStorageLocal()` in `InitACMEClient` with a proper
QuicBaaS-backed ACME storage factory. The platform's QuicBaaS ObjectStorage service provides
multi-tenant isolation, DEK encryption, and cluster replication for all ACME state.

go-trusted-ca defines the `acmestorage.Factory` interface (at
`/home/jhahn/sources/go-trusted-ca/pkg/acme/storage/types.go`) and provides an objstore
implementation at `pkg/acme/storage/objstore/`. We need a QuicBaaS implementation in
go-trusted-platform that satisfies the same interface.

#### 4.1 Files to Create

**`pkg/acme/storage/quicbaas/factory.go`**

```go
// Package quicbaas provides an ACME storage factory backed by QuicBaaS ObjectStorage.
// It implements go-trusted-ca's acmestorage.Factory interface.
package quicbaas

import (
    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
    qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
    acmestorage "github.com/jeremyhahn/go-trusted-ca/pkg/acme/storage"
    "github.com/jeremyhahn/go-trusted-ca/pkg/acme/entities"
)

// compile-time interface check
var _ acmestorage.Factory = (*Factory)(nil)

// Factory implements acmestorage.Factory using QuicBaaS ObjectStorage.
type Factory struct {
    storage  quicbaassdk.ObjectStorageClient
    codec    acmestorage.Codec
    tenantID string  // empty = platform namespace
}

// NewFactory creates a new ACME storage factory backed by QuicBaaS ObjectStorage.
func NewFactory(storage quicbaassdk.ObjectStorageClient) (*Factory, error)

// AccountDAO returns a GenericDAO for ACME accounts.
func (f *Factory) AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error)

// OrderDAO returns a GenericDAO for ACME orders scoped to an account.
func (f *Factory) OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error)

// AuthorizationDAO, ChallengeDAO, CertificateDAO, NonceDAO,
// ExternalAccountBindingDAO follow the same pattern.
```

Each DAO is backed by a `quicbaasGenericDAO[E]` that maps the `qrdbsdk.GenericDAO[E]` interface
methods (`Get`, `Put`, `Delete`, `List`, `Query`) onto `ObjectStorage.GetObject`,
`ObjectStorage.PutObject`, `ObjectStorage.DeleteObject`, `ObjectStorage.ListObjects`.

Key encoding: `"acme/{collection}/{id}"` — consistent with the go-trusted-ca objstore factory's
key scheme (`"acme/accounts"`, `"acme/orders/{accountID}"`, etc.).

**`pkg/acme/storage/quicbaas/generic_dao.go`**

Implements `qrdbsdk.GenericDAO[E]` using QuicBaaS ObjectStorage. Objects are serialized with
the ACME codec (JSON by default). The key for each entity is:
`"{namespace}/{entityID}"` where namespace is the collection prefix.

**`pkg/acme/storage/quicbaas/factory_test.go`**

Unit tests using `quicbaassdk.NewObjectStorageMemory()`:
- `TestFactory_AccountDAO_RoundTrip`
- `TestFactory_OrderDAO_RoundTrip`
- `TestFactory_AccountDAO_NotFound`
- `TestFactory_AccountDAO_NilStorage`

#### 4.2 Files to Modify

**`pkg/app/app.go InitACMEClient()`**

Replace the existing `NewObjectStorageLocal` + `trustedca.NewACMEStorageFactory` block:

```go
// Before (lines 1433–1440):
localStorage := quicbaassdk.NewObjectStorageLocal()
storageFactory, err := trustedca.NewACMEStorageFactory(localStorage)

// After:
objStorage := app.daoFactory.(*quicbaas.Factory).ObjectStorage()
storageFactory, err := acmequicbaas.NewFactory(objStorage)
```

Add import: `acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"`

Remove the `"github.com/jeremyhahn/go-quicbaas/sdk/go"` import alias if it was only used for
`NewObjectStorageLocal` (check for other usages first).

#### 4.3 Testing Requirements

- `pkg/acme/storage/quicbaas/factory_test.go`: Full DAO round-trip tests for all 7 DAO types.
- `pkg/app/app_test.go`: `TestInitACMEClient_QuicBaaSStorage` — verify `storageFactory` is the
  QuicBaaS implementation, not the objstore one.

#### 4.4 Dependencies

Phase 3 must be complete (ObjectStorage is available via the QuicBaaS factory). Phase 2 ensures
QuicBaaS is started before `InitACMEClient` is called.

---

### Phase 5: Multi-Tenant Storage Integration

**Repository:** `/home/jhahn/sources/go-trusted-platform`

**Goal:** Wire the multi-tenancy layer into the storage architecture. When a tenant is created,
provision a TenantDEK and an ObjectStorage partition. When a tenant is deleted, clean up both.
Implement `acmestorage.TenantAwareFactory` so ACME state is isolated per tenant.

#### 5.1 DEK Hierarchy

```
Master Key (TPM/seal)
  └── ClusterDEK (Raft-distributed, initialized via quicbaassdk.ClusterDEK())
        └── TenantDEK (per-tenant, key ID: "dek:tenant:{tenantID}")
              └── TenantDEK-encrypted objects in ObjectStorage
```

QuicBaaS SDK accessor chain for DEK operations:

```go
clusterDEK := sdkClient.Security().ClusterDEK()
clusterDEK.EnsureTenantDEK(ctx, tenantID, algorithm)
clusterDEK.DeleteTenantDEK(ctx, tenantID)
```

ObjectStorage tenant scoping:

```go
sdkClient.Storage().ObjectStorage().PutObject(ctx, &quicbaassdk.ObjectPutRequest{
    TenantID: tenantID,
    Key:      key,
    Data:     data,
})
```

#### 5.2 Files to Modify

**`pkg/api/daemon/tenant_service.go`**

The existing `TenantService` delegates to QuicBaaS IAM `TenantManager` for CRUD. Extend
`createTenant` and `deleteTenant` to also manage DEKs:

```go
func (s *TenantService) provisionTenantStorage(ctx context.Context, tenantID string) error {
    clusterDEK := s.sdkClient.Security().ClusterDEK()
    _, err := clusterDEK.EnsureTenantDEK(ctx, &quicbaassdk.EnsureTenantDEKRequest{
        TenantID:  tenantID,
        Algorithm: "AES-256-GCM",
    })
    return err
}

func (s *TenantService) deprovisionTenantStorage(ctx context.Context, tenantID string) error {
    clusterDEK := s.sdkClient.Security().ClusterDEK()
    _, err := clusterDEK.DeleteTenantDEK(ctx, &quicbaassdk.DeleteTenantDEKRequest{
        TenantID: tenantID,
    })
    return err
}
```

Call `provisionTenantStorage` after successful IAM tenant creation.
Call `deprovisionTenantStorage` before IAM tenant deletion.

**`pkg/acme/storage/quicbaas/factory.go`** (extend from Phase 4)

Add `TenantAwareFactory` implementation:

```go
// compile-time interface check
var _ acmestorage.TenantAwareFactory = (*TenantAwareFactory)(nil)

// TenantAwareFactory wraps Factory and adds tenant-scoped DAO creation.
type TenantAwareFactory struct {
    Factory
}

// NewTenantAwareFactory creates a tenant-aware ACME storage factory.
func NewTenantAwareFactory(storage quicbaassdk.ObjectStorageClient) (*TenantAwareFactory, error)

// TenantDAO returns a GenericDAO for managing tenants (super-admin only).
func (f *TenantAwareFactory) TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error)

// ForTenant returns a Factory scoped to the specified tenant.
// All DAOs from the returned factory use TenantID in every ObjectStorage request.
func (f *TenantAwareFactory) ForTenant(tenantID string) (acmestorage.Factory, error) {
    if tenantID == "" {
        return nil, ErrInvalidTenantID
    }
    return &Factory{
        storage:  f.storage,
        codec:    f.codec,
        tenantID: tenantID,
    }, nil
}

// GetTenantID returns the current tenant ID, empty if platform-scoped.
func (f *TenantAwareFactory) GetTenantID() string { return f.tenantID }
```

**`pkg/app/app.go InitACMEClient()`**

Use `TenantAwareFactory` instead of `Factory` so the ACME server supports multi-tenant mode:

```go
storageFactory, err := acmequicbaas.NewTenantAwareFactory(objStorage)
```

#### 5.3 Files to Create

**`pkg/acme/storage/quicbaas/tenant_aware_factory.go`**

Separate file for `TenantAwareFactory` following the same pattern as go-trusted-ca's
`pkg/acme/storage/objstore/tenant_aware_factory.go`.

**`pkg/acme/storage/quicbaas/tenant_aware_factory_test.go`**

Unit tests:
- `TestTenantAwareFactory_ForTenant_Isolation` — verify DAOs from different tenant scopes
  produce different keys.
- `TestTenantAwareFactory_ForTenant_EmptyID` — verify error on empty tenant ID.
- `TestTenantAwareFactory_TenantDAO_RoundTrip`

**`pkg/api/daemon/errors.go`** (if not present)

Add typed errors for tenant storage operations:

```go
// ErrTenantDEKProvision is returned when DEK provisioning fails during tenant creation.
type ErrTenantDEKProvision struct {
    TenantID string
    Cause    error
}

// ErrTenantDEKDeprovision is returned when DEK cleanup fails during tenant deletion.
type ErrTenantDEKDeprovision struct {
    TenantID string
    Cause    error
}
```

#### 5.4 Testing Requirements

- `pkg/api/daemon/tenant_service_test.go`: `TestCreateTenant_ProvisionsDEK` and
  `TestDeleteTenant_DeprovisionsDEK` using a mock QuicBaaS client.
- `pkg/acme/storage/quicbaas/tenant_aware_factory_test.go`: full coverage of
  `TenantAwareFactory` and `tenantScopedFactory`.

#### 5.5 Dependencies

Phase 4 must be complete (`Factory` exists). QuicBaaS `ClusterDEK()` requires the server to be
started, so this phase's runtime behavior depends on Phase 2 ordering.

---

### Phase 6: Cleanup and go.mod

**Repository:** `/home/jhahn/sources/go-trusted-platform`

**Goal:** Remove all direct go-objstore imports, delete the `pkg/storage/objstore/` package,
and demote go-objstore to an indirect dependency in go.mod.

#### 6.1 Verification Checklist

Run before and after:

```sh
grep -r "go-objstore" pkg --include="*.go" -l
grep -r "common.Storage" pkg --include="*.go" -l
grep -r "\"github.com/jeremyhahn/go-objstore" go.mod
```

All three should produce zero output after cleanup.

#### 6.2 Files to Delete

```
pkg/storage/objstore/adapter.go
pkg/storage/objstore/adapter_test.go
pkg/storage/objstore/config.go
pkg/storage/objstore/config_test.go
```

Directory `pkg/storage/objstore/` is removed. Do not delete `pkg/storage/` — the `luks/`,
`drive/`, and `quicbaas/` subdirectories are unrelated and remain.

#### 6.3 Files to Modify

**`go.mod`**

Remove the direct `github.com/jeremyhahn/go-objstore` entry from the `require` block. If
go-objstore is still a transitive dependency (via go-trusted-ca's objstore ACME factory), it
will remain as an indirect entry — `go mod tidy` handles this automatically.

```
# Remove from direct requires:
github.com/jeremyhahn/go-objstore v0.1.4-alpha

# After tidy, it should appear only as indirect:
github.com/jeremyhahn/go-objstore v0.1.4-alpha // indirect
```

**All test files that imported `pkg/storage/objstore/`**

Files to audit and update:
- `pkg/api/daemon/ca_grpc_service_test.go`
- `pkg/api/daemon/quic_ca_test.go`
- `pkg/api/grpc/ca_service_test.go`
- `pkg/api/quic/ca_handlers_test.go`

In each, replace constructs like:

```go
storageCfg := objstore.DefaultLocalConfig(tmpDir)
backend, _ := objstore.NewBackendFromConfig(storageCfg)
```

With:

```go
backend, err := xkmssdk.NewFileStorageBackend(tmpDir)
```

Or in tests that need in-memory storage:

```go
backend := xkmssdk.NewStorageMemory()
```

#### 6.4 go.mod / go-qrdb

`go-qrdb/sdk/go` is imported directly by go-trusted-platform for its `GenericDAO` types
(used by `acmestorage.Factory` interface method signatures). This import stays as a direct
dependency because the types appear in interface signatures. Do not move it to indirect.

#### 6.5 Testing Requirements

Run the full unit test suite and verify compilation succeeds:

```sh
make test
go build ./...
```

Specific coverage targets:
- `pkg/store/object/`: maintain existing coverage (≥ 90%).
- `pkg/acme/storage/quicbaas/`: ≥ 90% from new tests.
- `pkg/storage/quicbaas/`: ensure no regressions.

---

## Cross-Cutting Concerns

### Error Handling

All new error types must be declared as named types (not `fmt.Errorf`). Follow the existing
pattern in the codebase:

```go
type ErrXKMSStorageInit struct { Path string; Cause error }
func (e ErrXKMSStorageInit) Error() string { return "xkms: storage init failed at " + e.Path + ": " + e.Cause.Error() }
func (e ErrXKMSStorageInit) Unwrap() error { return e.Cause }
```

QuicBaaS ObjectStorage not-found errors must be mapped to existing domain not-found errors.
Check existing `isNotFoundString()` pattern in `pkg/storage/quicbaas/sdk_storage.go` and
reuse it for the new ACME DAO implementation.

### Concurrency

`initPlatformCA()` and QuicBaaS startup are sequential within `initStores()`. No locking is
needed beyond what the embedded server already manages via its `sync.Once` and `atomic.Bool`.
`EmbeddedServer.externalCA` is set at construction and never mutated — safe to read without locks.

### Testing Strategy

**Unit tests** (make test):
- Use `quicbaassdk.NewObjectStorageMemory()` as the backing store.
- Use `xkmssdk.NewStorageMemory()` for xkms backends.
- Do not start a real embedded server.

**Integration tests** (make integration-test, devcontainer):
- Use the existing `test/integration/ca/` suite.
- Add `test/integration/acme/` to verify ACME state persistence across server restarts.
- Verify tenant creation provisions DEK via `test/integration/daemon/` tenant test suite.

### Configuration Migration

Users upgrading from a release that used go-objstore-backed ACME storage will need to migrate
their ACME state. Document this in `docs/operations/acme-storage-migration.md` (create when
Phase 4 is complete). The migration path is:

1. Export ACME accounts/orders/certs from filesystem using a one-time migration tool.
2. Import into QuicBaaS ObjectStorage using the same key namespace scheme.

No CA cert migration is required — xkms native file storage uses the same directory layout
as the previous go-objstore-backed storage (both write to `caRoot/`).

### Backward Compatibility for go-quicbaas

The `WithCA` and `WithTLSCertificate` options are additive. Existing go-quicbaas deployments
that do not use these options behave identically to the current release. `NewServer` accepts
zero options by default. The `initializeCA()` function runs its full existing logic when
`s.opts.externalCA == nil`.

---

## Dependency Graph After All Phases

```
go-trusted-platform
└── go-quicbaas/sdk/go       — the ONLY stack entry point; composes
    go-xkms (CA + ACME via pkg/ca + pkg/acme, formerly go-trusted-ca)
    and go-qrdb (KV / seal / ceremony / credentials).
    ├── Security().ACME() / Security().Certificate()  — CA + ACME
    ├── ObjectStorage() / KMS() / IAM()               — storage / keys / identity
    └── go-objstore is transitive only (inside the SDK), never a direct import
```

---

## Phase Execution Order

| Phase | Description | Upstream Repo | Depends On |
|-------|-------------|---------------|------------|
| 1 | go-quicbaas WithCA option | go-quicbaas | none |
| 2 | New bootstrap order | go-trusted-platform | Phase 1 |
| 3 | QuicBaaS ObjectStorage for platform storage | go-trusted-platform | Phase 2 |
| 4 | QuicBaaS-backed ACME storage factory | go-trusted-platform | Phase 3 |
| 5 | Multi-tenant DEK + TenantAwareFactory | go-trusted-platform | Phase 4 |
| 6 | Cleanup and go.mod | go-trusted-platform | Phase 5 |

Phases 2–6 are all in go-trusted-platform and can be developed on a feature branch. Phase 1
requires a go-quicbaas commit first (or a local replace directive in go.mod during development).

---

## File Change Summary

### go-quicbaas (Phase 1)

| File | Change |
|------|--------|
| `pkg/server/server.go` | Add `serverOptions` struct, `ServerOption` type, `WithCA()`, `WithTLSCertificate()`, apply options in `NewServer` |
| `pkg/server/lifecycle.go` | Add external CA short-circuit in `initializeCA()`, add `issueTLSCertFromExternalCA()` |
| `sdk/go/server.go` | Export `ServerOption`, `WithCA`, `WithTLSCertificate` |

### go-trusted-platform (Phases 2–6)

| File | Change |
|------|--------|
| `pkg/app/app.go` | Remove `newKeyBackend()`, rewrite `initXKMSService()` to use native xkms file storage, rewrite `initStores()` to new ordered sequence, add `initPlatformCA()`, update `InitACMEClient()` |
| `pkg/app/ca_factory.go` | Minor update for changed `object.NewObjectStore` signature |
| `pkg/app/errors.go` | Add `ErrXKMSStorageInit`, `ErrQuicBaaSConfig` typed errors |
| `pkg/storage/quicbaas/embedded_server.go` | Add `externalCA` field, `NewEmbeddedServerWithCA()`, forward CA in `Start()` |
| `pkg/storage/quicbaas/factory.go` | Update `NewFactory` to accept CA parameter |
| `pkg/store/object/store.go` | Replace `common.Storage` with `quicbaassdk.ObjectStorageClient` |
| `pkg/store/certstore/adapter.go` | Update `ObjectStorageAdapter` for new `ObjectStorer.Storage()` return type |
| `pkg/daemon/commands/serve.go` | Audit for explicit QuicBaaS factory calls, pass CA |
| `pkg/boot/commands/manager.go` | Replace `objstore.*` calls with `xkmssdk.NewFileStorageBackend` |
| `pkg/api/daemon/tenant_service.go` | Add `provisionTenantStorage`, `deprovisionTenantStorage` |
| `go.mod` | Remove direct go-objstore dependency |

| File | Action |
|------|--------|
| `pkg/storage/objstore/adapter.go` | Delete |
| `pkg/storage/objstore/adapter_test.go` | Delete |
| `pkg/storage/objstore/config.go` | Delete |
| `pkg/storage/objstore/config_test.go` | Delete |
| `pkg/acme/storage/quicbaas/factory.go` | Create |
| `pkg/acme/storage/quicbaas/generic_dao.go` | Create |
| `pkg/acme/storage/quicbaas/factory_test.go` | Create |
| `pkg/acme/storage/quicbaas/tenant_aware_factory.go` | Create |
| `pkg/acme/storage/quicbaas/tenant_aware_factory_test.go` | Create |
| `pkg/api/daemon/errors.go` | Create (or extend) |
