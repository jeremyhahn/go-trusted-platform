# Barrier Engineering

> **Status: NORMATIVE** · Scope: `pkg/barrier/`, `pkg/app/barrier.go`, `pkg/daemon/commands/serve_barrier_gate.go`, `pkg/api/daemon/initonly.go`, `pkg/api/rest/init_handlers.go`, `pkg/api/daemon/barrier_grpc_service.go`, `pkg/cli/commands/barrier/` · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · engineering (this file) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

## 1. Package map

| Path | Holds |
|---|---|
| `pkg/barrier/manager.go` | `Manager`: the SDK wrapper and its local state |
| `pkg/barrier/config.go` | `Config`, the seal-strategy constants, the ceremony types |
| `pkg/barrier/errors.go` | Sentinels, `ManagerError`, `ConfigError` |
| `pkg/app/barrier.go` | `App.Barrier()`, `initBarrier` |
| `pkg/daemon/commands/serve_barrier_gate.go` | The gate: `invokeBarrierGate`, `runInitOnlyMode`, `waitForUnseal`, the gate's state, init and unseal services |
| `pkg/api/daemon/initonly.go` | `InitOnlyServer`: the pre-unseal listeners |
| `pkg/api/rest/init_handlers.go` | `InitHandlers`: `/healthz`, `/init`, `/unseal`, and their request and response types |
| `pkg/api/daemon/barrier_grpc_service.go` | `BarrierGRPCService`, which implements `platform.v1.BarrierService` |
| `pkg/api/grpc/proto/barrier.proto` | The `BarrierService` contract |
| `sdk/go/services/barrier/client.go` | Platform SDK client for `BarrierService` |
| `pkg/cli/commands/barrier/` | `platformctl barrier` |
| `pkg/tenant/` | The per-tenant barrier methods on `tenant.Manager` — see [`docs/tenant/engineering.md`](../tenant/engineering.md) |

## 2. `barrier.Manager`

```go
func NewManager(sdk quicbaassdk.Client, config *Config, logger *slog.Logger) (*Manager, error)
func (m *Manager) SyncStatus(ctx context.Context) error
func (m *Manager) Initialize(ctx context.Context, secret string) error
func (m *Manager) InitializeShamir(ctx context.Context, secret string, threshold, shares int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error)
func (m *Manager) Unseal(ctx context.Context, secret string) error
func (m *Manager) UnsealWithShare(ctx context.Context, share string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error)
func (m *Manager) Seal(ctx context.Context) error
func (m *Manager) Rekey(ctx context.Context, threshold, total int) (*quicbaassdk.QRDBBarrierRekeyResponse, error)
func (m *Manager) Status(ctx context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error)
func (m *Manager) CeremonyInitialize(ctx context.Context, config *CeremonyConfig) (*CeremonyInitResult, error)
func (m *Manager) CeremonyStatus(ctx context.Context) (*CeremonyStatusInfo, error)
func (m *Manager) BeginClaimCert(ctx context.Context, username string) (*CeremonyChallenge, error)
func (m *Manager) CompleteClaimCert(ctx context.Context, username, nonceHex string, signature []byte) (*CeremonyClaimCertResult, error)
func (m *Manager) BeginClaimShare(ctx context.Context, username string) (*CeremonyChallenge, error)
func (m *Manager) CompleteClaimShare(ctx context.Context, username, nonceHex string, signature []byte) ([]byte, error)
func (m *Manager) WaitReady(ctx context.Context) error
func (m *Manager) IsSealed() bool
func (m *Manager) IsUnsealing() bool
func (m *Manager) IsInitialized() bool
func (m *Manager) Config() *Config
```

Every method calls the quicbaas SDK's `Security().Barrier()` or
`Security().Ceremony()`. Nothing in the package encrypts, splits or checks a PIN.

### Local state

The manager keeps three `atomic.Bool` flags, `initialized`, `sealed` and
`unsealing`, plus the current ready generation. It starts **sealed and
uninitialized**.

- `SyncStatus` reads the upstream status. `initialized` becomes
  `InitializedAt != ""`, `sealed` becomes the upstream `Sealed`, and an unsealed
  answer opens the ready generation. A fresh barrier reports sealed with an
  empty `InitializedAt`, which is how the gate tells "uninitialized" from
  "sealed".
- `Initialize`, `InitializeShamir`, `Unseal` and a completing `UnsealWithShare`
  mark the barrier unsealed and open the ready generation. `Seal` marks it
  sealed and starts a new generation, so `WaitReady` blocks again.
- `UnsealWithShare` that does not meet the threshold sets `unsealing` when the
  upstream reports at least one submitted share. `Seal`, a completing share and
  an unsealed `SyncStatus` clear it. `IsUnsealing` is true only while the
  barrier is also sealed. The upstream status carries no share progress, so a
  progress reset made elsewhere is not seen here.
- **The flags are a cache.** A change made through quicbaasd directly — which is
  what `platformctl barrier` does — is visible here only after the next
  `SyncStatus`.

### Pre-checks against the cache

Some methods refuse on the cached flags without calling upstream:

| Method | Refuses with | When |
|---|---|---|
| `Initialize` | `ErrAlreadyInitialized` | `initialized` is set |
| `Unseal` | `ErrNotSealed` | `sealed` is clear |
| `Seal` | `ErrSealed` | `sealed` is set |

A stale cache therefore produces a wrong refusal rather than a wrong action.

### Ceremony

`CeremonyInitialize` returns `ErrCeremonyNotSupported` unless
`Config.RequiresCeremony()` is true. `CompleteClaimShare` returns the share
bytes; the share is destroyed upstream once retrieved.

### Secret handling

`Initialize` and `Unseal` copy the secret into a byte slice for the request and
wipe it with `secure.Wipe` on return.

## 3. Configuration

The daemon configuration key is `barrier` (`App.BarrierConfig`, `pkg/app/app.go`).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `barrier.seal_strategy` | string | `software` | One of `none`, `passphrase`, `software`, `shamir`, `tpm2`, `pkcs11`; empty is accepted |
| `barrier.shamir_threshold` | int | `0` | M of M-of-N; `0` means a single key |
| `barrier.shamir_shares` | int | `0` | N of M-of-N |

The strategy constants in `pkg/barrier/config.go` are `SealStrategyNone`,
`SealStrategyPassphrase`, `SealStrategySoftware` (alias of passphrase),
`SealStrategyShamir`, `SealStrategyTPM2` and `SealStrategyPKCS11`, with
`DefaultSealStrategy = SealStrategySoftware`.

`Config.Validate` (called by `NewManager`) returns `*ConfigError{Field, Message}`
when:

- the strategy is not in the set (the message lists all six);
- either Shamir value is negative;
- only one of threshold and shares is set; or
- a set threshold breaks the Shamir split rule.

The split rule is `ValidateShamirSplit(threshold, shares)`:
`MinShamirThreshold` (2) ≤ threshold ≤ shares, else `ErrInvalidThreshold`.
It is the only copy of the rule. `Config.Validate`, `Manager.InitializeShamir`,
`Manager.Rekey`, the `barrier` CLI flags (`init-shamir`, `recovery generate`,
`rekey`) and `platformctl init --barrier-strategy=shamir` all call it. The gRPC
`Initialize` RPC uses `MinShamirThreshold` to choose between Shamir and
single-key mode.

`IsShamir()` is true when both Shamir values are positive. `RequiresCeremony()`
is true for `shamir`. It is also true for `passphrase`, `software` and the empty
strategy when the threshold is at least `MinShamirThreshold`. These are the
strategies that resolve to a passphrase seal.

### Start-up

`App` builds the manager only when `barrier:` is present. `initBarrier`:

1. returns `ErrBarrierRequiresQuicBaaS` when the daemon has no quicbaas SDK
   client;
2. wraps a `NewManager` failure, including a validation failure, in
   `ErrBarrierInit`. Both are fatal to start-up;
3. calls `SyncStatus`. A failure is logged and start-up continues with the manager
   sealed and uninitialized;
4. logs whether the barrier is sealed or unsealed.

There is no automatic unseal. A sealed barrier stays sealed until an operator
unseals it.

## 4. The barrier gate

`invokeBarrierGate(ctx, app, logger)` is called from both daemon entry points in
`pkg/daemon/commands/serve.go` before `daemon.New`. It runs `initOnlyGate`, a
package variable that points at `runInitOnlyMode` and that tests replace.

`runInitOnlyMode`:

1. Returns `ErrBarrierGateRequiresApp` for a nil app.
2. Builds the state provider, which reports `uninitialized`, `sealed`,
   `unsealing` or `unsealed` from the manager's `IsInitialized`, `IsUnsealing`
   and `IsSealed`. The services hold the manager through `gateBarrier`, the
   narrow interface they drive. An app with no manager yields a nil
   `gateBarrier`, never a nil `*Manager` inside a non-nil interface.
3. Wires the init service only when the app has a quicbaas SDK client, and the
   unseal service only when the app has a manager. An unwired service answers
   `503`.
4. Starts an `InitOnlyServer` on the `--socket-path` Unix socket and
   `127.0.0.1:9446`.
5. Calls `waitForUnseal`, then stops the server whatever the outcome.

`waitForUnseal` returns at once when the app has no manager, or when the barrier
is already initialized and unsealed. Otherwise it selects over context
cancellation, the manager's `WaitReady` and a one-second ticker that calls
`SyncStatus`. A `SyncStatus` error is logged at debug level and retried.

### `InitOnlyServer`

`InitOnlyConfig` fields and defaults:

| Field | Default |
|---|---|
| `SocketPath` | `/run/platformd.sock` |
| `SocketMode` | `0660` |
| `HTTPListenAddr` | `DefaultInitOnlyHTTPAddr`, `127.0.0.1:9446`. No production transport uses that port. |
| `State` | required — `ErrInitOnlyMissingState` |
| `Init`, `Unseal` | optional; nil answers `503` |
| `ShutdownTimeout` | 10 s |
| `UnixHandler` | the same three-route mux as the HTTP listener |

`Start` binds HTTP first, then removes any stale socket and binds the Unix
socket. Either bind failure is `ErrInitOnlyListenerFailed{Address, Cause}`. A
failed `chmod` on the socket is logged and does not stop the gate. A second
`Start` returns `ErrInitOnlyAlreadyRunning`, and `Stop` on a stopped server
returns `ErrInitOnlyNotRunning`. Both listeners use a 5-second
`ReadHeaderTimeout`.

### The gate's `/init`

The handler rate limits every attempt first (per key: the socket peer uid from
`SO_PEERCRED`, or one shared key for loopback HTTP; `InitOnlyConfig.InitAttemptBurst` 5, `InitAttemptInterval` 12 s), answering
`429` with `ErrInitRateLimited`. A state other than `uninitialized` goes to the
init service's `Replay`, which answers the retained response or `409`.

The gate's init service:

1. Plans the barrier step from `barrier.seal_strategy` (`planBarrierInit`):
   a strategy outside `barrierInitStrategies` is
   `ErrBarrierStrategyUnsupported` (`500`); an empty `user_pin` is
   `ErrInitInvalidRequest{ErrBarrierInitMissingSecret}`, and a `shamir` quorum
   outside `2 <= threshold <= shares` is
   `ErrInitInvalidRequest{ErrBarrierShamirQuorum}` (both `400`).
2. For `shamir`, reads `Manager.Status` (`requireQuorumBarrier`). A registered
   strategy other than `shamir`, or no manager, is
   `ErrInitBarrierConflict{ErrBarrierShamirUnenforceable}` (`409`); a failed
   read is `ErrBarrierStatusUnavailable` (`500`).
3. Under its mutex, digests the request (SHA-256). When a response is already
   retained, an identical request from the issuing socket uid re-runs steps 5–6
   and gets the retained response; anything else is `ErrInitAlreadyIssued`
   (`409`).
4. Calls the quicbaas ceremony backend (`CeremonyBackend.Initialize`) with
   `so_pin`, `user_pin`, a `"M-of-N"` threshold built from `threshold` and
   `shares` (empty unless both are positive), `hostname`, `sans` and
   `credential_seal_strategy`. The backend mints the admin bundle from the
   platform CA before the ceremony. The response is retained
   (`newIssuedInit`: digest, caller uid, the admin key in a `pkg/memguard`
   enclave) **before** the barrier step.
5. Unless the manager already reports initialized, calls `Manager.Initialize(ctx,
   user_pin)`, or `Manager.InitializeShamir(ctx, user_pin, threshold, shares)`
   for `shamir`, **using the user PIN as the barrier secret**. An error fails
   the request with `ErrBarrierInitFailed{Cause}`, which unwraps to the
   manager's error; the retained response lets an identical retry re-attempt it.
6. Calls `SyncStatus`. An error is logged as a warning. The response then
   reports the flags `Initialize` cached, which are already correct.
7. Returns `ceremony_id`, `initialized_at`, `spki_pin`, `admin_cert_pem`,
   `admin_key_pem` and the current `state`, and destroys the retained key once
   the state is `unsealed`. The backend copies `spki_pin` from the upstream
   `CeremonyInitializeResponse.SPKIPin`. It also uses that value as
   `ceremony_id`, because upstream returns no ceremony ID.

The ceremony and the barrier initialize are two upstream calls, not one
transaction. If the ceremony succeeds and the barrier initialize fails, the
ceremony stays initialized; only an identical Unix-socket retry from the
issuing uid can finish the barrier step.

The handlers decode with `DisallowUnknownFields`, so a body that carries a field
the request does not define, such as the removed `barrier_strategy`, is a `400`.
`serviceErrorStatus` maps a service error that wraps `ErrMissingRequiredField`,
`ErrInvalidRequestBody` or `ErrInitInvalidRequest` to `400`, and
`ErrInitAlreadyIssued` or `ErrInitBarrierConflict` to `409`. Any other service
error takes its status from `barrier.Code`, else `500`.
[api.md §2](api.md#2-the-barrier-gate) shows
the wire behaviour.

### The gate's `/unseal`

A non-empty `secret` goes to `Manager.Unseal`, and a non-empty `share` to
`Manager.UnsealWithShare`. If both are present, `secret` wins. If neither is,
the gate returns `ErrMissingRequiredField{Field: "secret or share"}`, a `400`.

## 5. `BarrierGRPCService`

| RPC | Behaviour |
|---|---|
| `Init` | `threshold >= 2` → `InitializeShamir(secret, threshold, shares)`, response `SHAMIR` with `threshold`, `shares_total`, `share_count`. Otherwise `Initialize(secret)`, response `SINGLE_KEY`. Neither path has a root token to return; `root_token` (4) is reserved. |
| `GetStatus` | One `Manager.Status` call fills every field, never the cached flags: `sealed`; `initialized` = `InitializedAt != ""`, as `SyncStatus` decides it; `threshold` and `shares_total` from `ShamirThreshold` and `ShamirTotal`; `initialized_at` parsed as RFC 3339, left unset with a warning log when it does not parse. `strategyToProto` maps the strategy: a non-zero threshold or `shamir` → `SHAMIR`; `passphrase`, `software`, `tpm2`, `pkcs11`, `system-barrier` → `SINGLE_KEY`; anything else `UNSPECIFIED`. `shares_provided` (7) is reserved — upstream status has no share progress. |
| `Unseal` | When `Config.IsShamir()`, `secret` is submitted as a share and the response carries `sealed`, `shares_provided`, `shares_threshold`. Otherwise a direct unseal. |
| `Seal` | `Manager.Seal`. |
| `Rekey` | `Manager.Rekey(threshold, shares)`. `threshold`, `shares_total` and `share_count` come from the SDK rekey response, and the strategy is `strategyToProto("", Threshold)`: `SHAMIR` for the split upstream reports, `UNSPECIFIED` if it reports none. The SDK rekey response has no strategy name; upstream rekey is Shamir-only. |

A nil manager answers `codes.Unavailable`. Every other error goes through
`barrierErrorToGRPC`, which takes its code from `barrier.Code`
(`pkg/barrier/error_codes.go`) and keeps the error's own message. The REST
gate's `serviceErrorStatus` uses the same function and turns the code into an
HTTP status with `grpcCodeToHTTPStatus`, so the two transports cannot disagree.

`barrier.Code` looks through the whole chain with `errors.Is` and `errors.As`,
in this order, each by a lookup table:

| Error in the chain | Code |
|---|---|
| `ErrAlreadyInitialized` | `AlreadyExists` |
| `ErrNotInitialized`, `ErrSealed`, `ErrNotSealed`, `ErrCeremonyNotSupported` | `FailedPrecondition` |
| `ErrEmptySecret`, `ErrEmptyShare`, `ErrInvalidThreshold`, `ErrNilContext`, `ErrEmptyUsername`, `ErrEmptyNonce`, `ErrEmptySignature` | `InvalidArgument` |
| `ErrNilSDKClient`, `ErrNilConfig` | `Internal` |
| `context.Canceled`, `context.DeadlineExceeded` | `Canceled`, `DeadlineExceeded` |
| A gRPC status (upstream gRPC transport) | Its code; `OK` and `Unknown` fall through |
| `*sdkerrors.QBError` | `quicbaasCodes` by `QBError.Code` |
| Anything else | `Internal` |

The manager returns its pre-check sentinels bare and wraps every upstream
failure in `ManagerError`, so a chain carries at most one sentinel and the
table order cannot change the answer. Over the embedded transport the upstream
seal errors (a wrong secret, for example) carry no code the platform can read —
the quicbaas SDK does not re-export the qrdb seal sentinels — and come out as
`Internal`.

## 6. Errors

`pkg/barrier` sentinels: `ErrNotInitialized`, `ErrAlreadyInitialized`,
`ErrSealed`, `ErrNotSealed`, `ErrNilSDKClient`, `ErrNilConfig`, `ErrNilContext`,
`ErrEmptySecret`, `ErrEmptyShare`, `ErrInvalidThreshold`,
`ErrCeremonyNotSupported`, `ErrEmptyUsername`, `ErrEmptyNonce`,
`ErrEmptySignature`. Upstream failures are wrapped in `*ManagerError{Op, Err}`,
which unwraps. `barrier.Code` classifies all of them for every transport
([§5](#5-barriergrpcservice)).

The gate's REST handlers use `ErrInitNotPermitted{Current}`,
`ErrUnsealNotPermitted{Current}`, `ErrBarrierInitServiceUnavailable{}`,
`ErrBarrierUnsealServiceUnavailable{}`, `ErrInitRateLimited`,
`ErrInitAlreadyIssued`, `ErrInitInvalidRequest{Err}` and
`ErrInitBarrierConflict{Err}`. The gate itself adds
`ErrBarrierGateRequiresApp`, `ErrBarrierGateRequiresSDK`,
`ErrBarrierInitFailed{Cause}`, `ErrBarrierStrategyUnsupported`,
`ErrBarrierInitMissingSecret`, `ErrBarrierShamirQuorum`,
`ErrBarrierShamirUnenforceable` and `ErrBarrierStatusUnavailable`. Request
validation reuses the REST package's `ErrMissingRequiredField`.

The CLI's typed errors are listed in [cli.md §4](cli.md#4-validation).

## 7. Invariants

1. **No production transport binds while the configured barrier is sealed.** The
   gate returns before `daemon.New` runs only once the barrier is unsealed or the
   context ends.
2. **Wrong state is a conflict, never a silent success.** `/init` outside
   `uninitialized` and `/unseal` outside `sealed`/`unsealing` answer `409`.
3. **Share material is not returned by init, rekey or recovery generation** on
   any platform surface.
4. **No barrier crypto in this repository.** Every operation is an SDK call.

## 8. Concurrency

The cached flags are `atomic.Bool`. The ready signal is an
`atomic.Pointer[readyGate]`: each generation holds a channel and an
`atomic.Bool`, and `signalReady` closes the current generation's channel only
when its `CompareAndSwap(false, true)` wins. Any number of unseal paths — init,
unseal, a completing share, `SyncStatus` — can signal together; the channel
closes once. `Seal` stores a new generation atomically, so `WaitReady` always
waits on a whole generation, old or new, never a torn one.

`Seal` stores `sealed` before it swaps the generation. An unseal that lands
between the two leaves the manager reporting unsealed with an unopened
generation: a waiter blocks until the next signal (the gate's one-second
`SyncStatus` supplies it) rather than passing while the manager reports sealed.

`TestManager_ConcurrentSealWaitReadySignal` and
`TestManager_ConcurrentUnsealSignalsDoNotPanic` hold this under `-race`.

## 9. Tests

| Kind | Where |
|---|---|
| Unit | `pkg/barrier/{manager,config,errors,error_codes}_test.go`, `pkg/app/barrier_cov2_test.go`, `pkg/daemon/commands/serve_barrier_gate_test.go`, `pkg/api/rest/init_handlers_test.go`, `pkg/app/backends/ceremony_test.go`, `pkg/api/daemon/initonly_test.go`, `pkg/api/daemon/barrier_grpc_service_test.go`, `pkg/cli/commands/barrier/barrier_test.go`, `pkg/tenant/barrier_test.go` |
| Integration | `test/integration/barrier_gate/` — the gate against a running daemon |

Run one package with `make test-pkg PKG=./pkg/barrier/`.

## 10. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/bootstrap/engineering.md`](../bootstrap/engineering.md) — first boot and the ceremony
- [`docs/tenant/engineering.md`](../tenant/engineering.md) — the per-tenant barrier
