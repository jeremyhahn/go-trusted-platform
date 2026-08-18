# ACME External Account Binding — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/eab/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Package layout

`pkg/eab/` — five non-test files:

| File | Holds |
|---|---|
| `types.go` | `Status`, `Credential`, `GenerateParams`, the `Service` interface, the length/expiry constants |
| `service.go` | `DefaultService`, the canonical implementation |
| `entity.go` | `EABCredential`, the storage entity |
| `dao.go` | The `DAO` interface and `QuicBaaSDAO` |
| `delivery.go` | `Delivery`, `ExportedCredential`, QR / file / URL rendering |
| `errors.go` | Eleven typed errors |

## 2. Exported surface

### Types and constants (`types.go`)

```go
type Status uint8

const (
    StatusActive Status = iota
    StatusRevoked
    StatusExpired
    StatusUsed
)

func (s Status) String() string       // "active" | "revoked" | "expired" | "used" | "unknown"
func ParseStatus(s string) Status     // unknown input falls back to StatusActive
```

**`ParseStatus` has no error return and defaults to `StatusActive`.** A
misspelled filter string therefore reads as "active", not as "invalid". Callers
that need strictness must check the input themselves.

```go
type Credential struct {
    ID        uint64
    KeyID     string
    HMACKey   []byte
    ProfileID uint64
    TenantID  string
    ExpiresAt time.Time
    Status    Status
    CreatedAt time.Time
    UsedAt    time.Time
}

func (c *Credential) IsExpired() bool  // false when ExpiresAt is the zero time
func (c *Credential) IsValid() bool    // StatusActive && !IsExpired()
```

```go
type GenerateParams struct {
    ProfileID  uint64
    TenantID   string
    ExpiresIn  time.Duration
    HMACKeyLen int // bytes; 0 means DefaultHMACKeyLength
}

func (p GenerateParams) Validate() error
```

```go
const MinHMACKeyLength     = 32
const DefaultHMACKeyLength = 32
const DefaultCredentialExpiry = 24 * time.Hour
```

**`DefaultCredentialExpiry` is declared and is not applied by
`DefaultService.Generate`.** `Generate` only sets an expiry when
`params.ExpiresIn > 0`; a zero `ExpiresIn` produces a credential with a zero
`ExpiresAt`, which `IsExpired` reports as *never expiring*. The constant is
available for callers to pass in; nothing defaults to it. Verified 2026-08-18.

### The `Service` interface (`types.go`)

```go
type Service interface {
    Generate(ctx context.Context, params GenerateParams) (*Credential, error)
    Get(ctx context.Context, id uint64) (*Credential, error)
    GetByKeyID(ctx context.Context, keyID string) (*Credential, error)
    Revoke(ctx context.Context, id uint64) error
    MarkUsed(ctx context.Context, id uint64) error
    Validate(ctx context.Context, keyID string, hmacKey []byte) (*Credential, error)
    ListByProfile(ctx context.Context, profileID uint64) ([]*Credential, error)
    ListByTenant(ctx context.Context, tenantID string) ([]*Credential, error)
    CleanupExpired(ctx context.Context) (int, error)
    Delete(ctx context.Context, id uint64) error
    Count(ctx context.Context) (int, error)
    Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*Credential], error)
}
```

`pkg/api/daemon.EABServicer` is a type alias of this interface.

### Implementation

```go
type DefaultService struct { /* dao DAO; logger *logging.Logger */ }
func NewService(dao DAO, logger *logging.Logger) *DefaultService
var _ Service = (*DefaultService)(nil)
```

### Storage (`entity.go`, `dao.go`)

```go
type EABCredential struct {
    ID        uint64
    KeyID     string
    HMACKey   []byte
    ProfileID uint64
    TenantID  string
    ExpiresAt int64   // Unix seconds; 0 = no expiry
    Status    uint8
    CreatedAt int64
    UsedAt    int64
    entities.KeyValueEntity
}

func (e *EABCredential) EntityID() uint64
func (e *EABCredential) SetEntityID(id uint64)
```

```go
type DAO interface {
    datastore.GenericDAO[*EABCredential]
    FindByKeyID(ctx context.Context, keyID string) (*EABCredential, error)
    FindByProfileID(ctx context.Context, profileID uint64) ([]*EABCredential, error)
    FindByTenantID(ctx context.Context, tenantID string) ([]*EABCredential, error)
    FindExpired(ctx context.Context, before time.Time) ([]*EABCredential, error)
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

type QuicBaaSDAO struct { *quicbaas.GenericDAO[*EABCredential]; /* ... */ }
func NewQuicBaaSDAO(storage quicbaas.Storage, logger *logging.Logger, opts ...quicbaas.DAOOption) *QuicBaaSDAO
```

The entity type name registered with the store is the unexported constant
`entityTypeEABCredential = "EABCredential"`.

### Delivery (`delivery.go`)

```go
type DeliveryConfig struct {
    BaseURL    string
    QRCodeSize int // default 256
}
func DefaultDeliveryConfig() DeliveryConfig      // QRCodeSize: 256, BaseURL: ""
func NewDelivery(config DeliveryConfig) *Delivery

type ExportedCredential struct {
    KeyID     string `json:"kid"`
    HMACKey   string `json:"hmac_key"`   // base64url, no padding
    ProfileID uint64 `json:"profile_id"`
    TenantID  string `json:"tenant_id"`
    ExpiresAt string `json:"expires_at,omitempty"` // RFC 3339
}

func (d *Delivery) ToQRCode(cred *Credential) ([]byte, error)
func (d *Delivery) ToQRCodeSized(cred *Credential, size int) ([]byte, error)
func (d *Delivery) ToQRCodeFile(cred *Credential, path string) error
func (d *Delivery) ToFile(cred *Credential, path string) error
func (d *Delivery) ToJSON(cred *Credential) ([]byte, error)
func (d *Delivery) ToURL(cred *Credential) (string, error)
func (d *Delivery) ToURLWithPath(cred *Credential, path string) (string, error)

func ParseExportedCredential(data []byte) (*ExportedCredential, error)
func (e *ExportedCredential) DecodeHMACKey() ([]byte, error)
```

`ToQRCodeSized(cred, 0)` falls back to the configured size, so a wire-level
optional size field can be passed straight through.

## 3. Invariants

1. **The HMAC key is returned on exactly one path.**
   `eabCredentialToPb(cred, includeHMACKey bool)` in
   `pkg/api/daemon/eab_grpc_service.go` is called with `true` only from
   `CreateCredential`. Every other RPC passes `false`.
2. **`Generate` never reuses a KeyID.** 16 bytes of `crypto/rand`, `base64url`
   without padding. Uniqueness is probabilistic, not enforced by a store
   constraint.
3. **HMAC comparison is constant time.** `subtle.ConstantTimeCompare` in
   `Validate`. Do not replace it.
4. **Terminal statuses are terminal.** `Revoke`, `MarkUsed` and the expiry
   write-back move a credential out of `StatusActive`; nothing moves it back.
5. **`Validate` checks the HMAC key before the status.** A wrong key on a
   revoked credential reports `ErrInvalidCredential`, not `ErrCredentialRevoked`
   — status is only disclosed to a caller that already proved possession.
6. **Zero `ExpiresAt` means no expiry.** See §2 on `DefaultCredentialExpiry`.
7. **Zero IDs are rejected before any store access.** `Get`, `Revoke`,
   `MarkUsed`, `Delete` all return `ErrInvalidCredential{Reason: "id cannot be
   zero"}` for `id == 0`.
8. **Concurrency:** `DefaultService` holds no mutable state; safety is whatever
   the underlying DAO provides. Two concurrent `Validate` calls for the same
   single-use credential can both succeed — **`Validate` does not consume**. If
   single use matters, `MarkUsed` is the consuming operation and it is
   last-write-wins, not compare-and-swap.

## 4. Error semantics

All errors are typed structs in `pkg/eab/errors.go`. Match with `errors.As`.

| Error | Fields | Returned when |
|---|---|---|
| `ErrCredentialNotFound` | `ID`, `KeyID` | Lookup by ID or KeyID found nothing |
| `ErrCredentialExpired` | `ID`, `KeyID` | Status is `StatusExpired`, or `IsExpired()` at validation |
| `ErrCredentialRevoked` | `ID`, `KeyID` | Status is `StatusRevoked` |
| `ErrCredentialAlreadyUsed` | `ID`, `KeyID` | Status is `StatusUsed` |
| `ErrInvalidCredential` | `Reason` | Empty KeyID / empty HMAC key / zero id / HMAC mismatch / unconfigured delivery base URL |
| `ErrInvalidProfileID` | `ProfileID` | `ProfileID == 0` on generate or list-by-profile |
| `ErrInvalidTenantID` | `TenantID` | Empty tenant on generate or list-by-tenant |
| `ErrInvalidExpiresAt` | `Reason` | Negative `ExpiresIn` |
| `ErrKeyGenerationFailed` | `Cause` (unwraps) | `crypto/rand` read failed |
| `ErrQRCodeGenerationFailed` | `Cause` (unwraps) | QR encode / scale / PNG encode failed |
| `ErrFileExportFailed` | `Path`, `Cause` (unwraps) | `MkdirAll` or `WriteFile` failed |

Transport-level errors raised by the service wrapper
(`pkg/api/daemon/eab_grpc_service.go`):

| Error | Meaning |
|---|---|
| `ErrEABNotConfigured` | No backing `eab.Service` — every RPC returns `codes.Unavailable` |
| `ErrEABDeliveryNotConfigured` | No `eab.Delivery` — QR / URL RPCs return `codes.Unavailable` |

MCP argument errors (`pkg/api/mcp/eab_tools.go`), all plain `errors.New`
sentinels: `ErrEABNotConfigured`, `ErrEABCredentialIDRequired`,
`ErrEABKeyIDRequired`, `ErrEABHMACKeyRequired`, `ErrEABProfileIDRequired`,
`ErrEABTenantIDRequired`.

### gRPC status mapping

`eabErrorMatchers` (ordered; first match wins, unmatched → `codes.Internal`):

| Typed error | gRPC code | REST |
|---|---|---|
| `ErrCredentialNotFound` | `NotFound` | 404 |
| `ErrInvalidProfileID` | `InvalidArgument` | 400 |
| `ErrInvalidTenantID` | `InvalidArgument` | 400 |
| `ErrInvalidExpiresAt` | `InvalidArgument` | 400 |
| `ErrInvalidCredential` | `InvalidArgument` | 400 |
| `ErrCredentialExpired` | `FailedPrecondition` | 400 |
| `ErrCredentialRevoked` | `FailedPrecondition` | 400 |
| `ErrCredentialAlreadyUsed` | `FailedPrecondition` | 400 |
| `ErrKeyGenerationFailed` | `Internal` | 500 |
| `ErrQRCodeGenerationFailed` | `Internal` | 500 |
| service nil | `Unavailable` | 503 |

`ErrFileExportFailed` has **no matcher** and therefore maps to `Internal`. It is
raised only by the file-writing delivery helpers, which no RPC calls.

### Fail-closed paths

- **`Validate` fails closed.** Not-found, HMAC mismatch, and every terminal
  status produce an error and a nil credential. A store error propagates rather
  than being swallowed.
- **The RPC surface fails closed when unconfigured**: `requireService` /
  `requireDelivery` return `codes.Unavailable`, never `Unimplemented`, never a
  panic.
- **The pre-enrollment consumer does NOT fail closed when EAB is unconfigured.**
  `pkg/provisioning/configdelivery/service.go`:

  ```go
  func (s *Service) verifyNonceAndEAB(ctx context.Context, nonce, eabKeyID, eabHMAC string) error {
      if !s.nonceStore.Validate(nonce) {
          return ErrNonceExpired{}
      }
      if s.eabService != nil {
          // ... base64 decode, then s.eabService.Validate
      }
      return nil
  }
  ```

  With `s.eabService == nil` the EAB pair is required to be *present*
  (`validateIdentityFields` rejects empty `eab_key_id` / `eab_hmac`) but is
  never checked. Deployments that rely on EAB to gate pre-enrollment must
  confirm the service is wired.

## 5. Configuration

There is **no `eab:` configuration section**. The feature is configured
indirectly:

| Input | Source | Effect |
|---|---|---|
| Backing service | `App.ServiceRegistry().EABService()` — non-nil only when the DAO factory is QuicBaaS-backed | nil ⇒ all RPCs `Unavailable` |
| Delivery base URL | `configdelivery.ProvisionBaseURL(app.FQDN(), <REST port>)` → `https://<fqdn>:<port>` | empty ⇒ `ToURL` returns `ErrInvalidCredential{Reason: "base URL not configured"}` |
| QR size | `DeliveryConfig.QRCodeSize`, or the per-request `size` argument | ≤ 0 ⇒ 256 |
| Expiry | per-credential `expires_in_seconds` | 0 ⇒ no expiry |
| HMAC key length | per-credential `hmac_key_length` | 0 ⇒ 32; 1–31 ⇒ `ErrInvalidCredential` |

No environment variables read this feature. Verified 2026-08-18.

## 6. Persistence

Entity type `EABCredential`, stored through
`quicbaas.GenericDAO[*EABCredential]`.

- `ExpiresAt`, `CreatedAt`, `UsedAt` are **Unix seconds (`int64`)** at rest and
  `time.Time` in the domain type. `entityToCredential` converts; zero stays zero.
- `Status` is a `uint8` at rest and an `eab.Status` in the domain type.
- `FindByKeyID` prefers a secondary-index query on the `KeyID` field and **falls
  back to a full paged scan** (`findByKeyIDScan`, page size 1000) when the index
  is absent or returns nothing. That fallback is O(n) in credential count on
  every pre-enrollment request; it is correct but it is not free.
- `FindByProfileID`, `FindByTenantID` and `FindExpired` are **always** full paged
  scans with an in-memory filter. There is no index on `ProfileID`, `TenantID`
  or `ExpiresAt`.
- `DeleteExpired` deletes one at a time and logs-and-continues on individual
  failures, returning the count actually deleted.

Compatibility: adding fields to `EABCredential` is backward compatible under the
JSON codec. Changing the meaning of `Status` values would not be — the enum is
persisted numerically.

## 7. uint64 across JSON

`ID` and `ProfileID` are `uint64` and exceed the 2^53 precision limit of a JSON
number. The MCP surface accepts `profile_id` as `{"type": ["integer","string"]}`
so large IDs can be sent as decimal strings. Follow that pattern for any new
JSON surface.

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/eab/{types,entity,errors,service,dao,delivery}_test.go` | Status round-trip, param validation, lifecycle transitions, constant-time compare, DAO scan fallbacks, QR/URL/file rendering |
| Service wrapper | `pkg/api/daemon/eab_grpc_service_test.go` | Error→status mapping, nil-service and nil-delivery guards, HMAC-key suppression |
| MCP | `pkg/api/daemon/mcp_eab_test.go`, `pkg/api/mcp/eab_dispatch_test.go` | Tool dispatch, argument validation, provider-absent behaviour |
| QUIC | `pkg/api/daemon/quic_eab_test.go` | Sub-opcode dispatch under `0xCF` |
| REST | `pkg/webservice/v1/rest/eab/router_test.go` | Route registration and ordering |
| SDK | `sdk/go/transport/{rest,quic,mcp}/eab_test.go`, `sdk/go/transport/embedded/dispatch_test.go` | Per-transport client parity |
| Integration | `test/integration/provision/multiprotocol_test.go`, `seeding.go` | End-to-end pre-enrollment with a seeded credential |

Fault-injection seams: the `DAO` interface (substitute a failing store), the
`EABServicer` / `EABDeliveryServicer` interfaces (substitute nil to exercise the
`Unavailable` guards).

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide. It is moot here — this
feature has no CLI verbs ([cli.md](cli.md)).

## 9. Observability

- `DefaultService` logs exactly once: a `Warn` when the expiry write-back fails
  during `Validate` (`"Failed to update expired credential status"`, with `id`
  and `error`).
- `QuicBaaSDAO.DeleteExpired` logs a `Warn` per failed delete.
- The daemon logs `"EAB gRPC service registered"` with
  `service=platform.v1.EABService` at startup.
- There are **no metrics** for issuance, validation success or validation
  failure. A brute-force attempt against KeyIDs is not currently visible.
- **Never log `Credential.HMACKey`, `ExportedCredential.HMACKey`, the `hmac`
  query parameter, or QR-code bytes.** They are the credential.

## 10. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/ca/`](../ca/) — the ACME surface
- [`docs/daemon/api.md`](../daemon/api.md) — transports and authorization
