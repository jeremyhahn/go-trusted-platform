# Barrier API

> **Status: NORMATIVE** · Scope: the barrier gate routes, `platform.v1.BarrierService`, and the per-tenant barrier rows · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · api (this file) · [user.md](user.md).

One row per capability. A transport that does not carry a capability reads
`MISSING — docs/13 G7`. It is never left out.

## 1. Transports

The six-transport model, the QUIC opcode table and authorization are in
[`docs/daemon/api.md`](../daemon/api.md#1-the-six-transports) and
[its authorization section](../daemon/api.md#5-authorization--the-platform-wide-picture).
This file adds only the barrier rows.

The platform barrier has **two daemon surfaces that never run at the same
time**:

| Surface | When it answers | Listeners |
|---|---|---|
| The barrier gate (§2) | From `platformd serve` until the barrier is unsealed | The Unix socket (`--socket-path`, default `/run/platformd.sock`) and `127.0.0.1:9446`, both plain HTTP |
| `platform.v1.BarrierService` (§3) | After the gate releases | The TCP gRPC server and the gRPC-over-Unix server |

`platformctl barrier` uses neither. It calls quicbaasd directly; see
[cli.md §2](cli.md#2-where-the-verbs-go).

## 2. The barrier gate

Handlers: `pkg/api/rest/init_handlers.go`. Services: `pkg/daemon/commands/serve_barrier_gate.go`.
Request bodies are JSON, capped at 64 KiB. Every error body is `{"error": "<message>"}`.
**No route authenticates**; see [architecture.md](architecture.md#trust-assumptions).

| Route | Method | Purpose |
|---|---|---|
| `/healthz` | `GET`, `HEAD` | Report the state |
| `/init` | `POST` | Run the bootstrap ceremony and initialize the barrier |
| `/unseal` | `POST` | Submit a secret or a Shamir share |

### State

`state` is one of `uninitialized`, `sealed`, `unsealing` or `unsealed`. The
platform's state provider derives it from the manager's cached flags. It reports
`unsealing` once a Shamir share has been accepted and the barrier is still
sealed. With no `barrier:` configuration it reports
`uninitialized`, but the gate has already released.

### `GET /healthz`

```json
{"state": "sealed", "ready": false}
```

`ready` is true only when `state` is `unsealed`.

### `POST /init`

Accepted only in `uninitialized`.

| Request field | Type | Used |
|---|---|---|
| `so_pin` | string | Passed to the ceremony |
| `user_pin` | string | Passed to the ceremony, **and used as the barrier secret** |
| `shares`, `threshold` | int | Passed to the ceremony as `"<threshold>-of-<shares>"` when both are positive, otherwise empty |
| `hostname` | string | Passed to the ceremony |
| `sans` | string array | Passed to the ceremony |
| `credential_seal_strategy` | string | Passed to the ceremony |

The barrier's seal strategy comes from `barrier.seal_strategy` in the
configuration, not from the request. A body with any other field is refused
with 400.

With a barrier configured, an empty `user_pin` is refused with 400 before the
ceremony runs. The gate then runs the upstream ceremony initialize. If that
fails, the gate returns 500. If it succeeds, the gate initializes the barrier
with `user_pin` as the secret. If that fails, the gate returns 500
(`ErrBarrierInitFailed`). Last, it refreshes the state from upstream. A failed
refresh is logged, and the response reports the state cached by the barrier
initialize.

| Response field | Set |
|---|---|
| `ceremony_id` | Yes. Upstream returns no ID, so this is the SPKI pin. |
| `initialized_at` | Yes |
| `state` | Yes, after the barrier initialize |
| `spki_pin` | Yes, from the upstream ceremony initialize |

The response carries no admin certificate or key: the upstream ceremony
initialize returns none.

### `POST /unseal`

Accepted only in `sealed` or `unsealing`.

| Request field | Meaning |
|---|---|
| `secret` | Single-secret unseal. Takes priority when both fields are set. |
| `share` | One Shamir share toward the threshold |

| Response field | Meaning |
|---|---|
| `state` | State after the call |
| `sealed` | Whether the barrier is still sealed |
| `shares_provided`, `required` | Share progress (share path only) |

### Status codes

| Code | `/init` | `/unseal` |
|---|---|---|
| 200 | Ceremony initialized | Secret or share accepted |
| 400 | Body not valid JSON, over 64 KiB, or with an unknown field; an empty `user_pin` with a barrier configured (`ErrMissingRequiredField`) | Body not valid JSON, over 64 KiB, or with an unknown field; neither `secret` nor `share` (`ErrMissingRequiredField`) |
| 405 | Not `POST` | Not `POST` |
| 409 | State not `uninitialized` (`ErrInitNotPermitted`) | State not `sealed`/`unsealing` (`ErrUnsealNotPermitted`) |
| 500 | An unclassified ceremony or barrier failure | An unclassified service error |
| 503 | No quicbaas SDK client (`ErrBarrierInitServiceUnavailable`) | No barrier manager (`ErrBarrierUnsealServiceUnavailable`) |

Any other service error takes its code from `barrier.Code`, which the gRPC
service uses too ([gRPC codes](#grpc-codes)). `ErrBarrierInitFailed` unwraps
to the barrier error, so a failed barrier initialize is classified the same way.

| `barrier.Code` | HTTP |
|---|---|
| `InvalidArgument` | 400 |
| `Unauthenticated` | 401 |
| `PermissionDenied` | 403 |
| `NotFound` | 404 |
| `AlreadyExists`, `FailedPrecondition` | 409 |
| `Unavailable` | 503 |
| Anything else | 500 |

`FailedPrecondition` answers 409, like the gate's own state checks, because it
means the barrier is in the wrong state for the call.

`/healthz` answers 405 to anything but `GET` or `HEAD`.

## 3. Platform barrier capabilities

`platform.v1.BarrierService` is in `pkg/api/grpc/proto/barrier.proto`. The
platform Go SDK reaches it through `Client.Barrier()` and the wrapper in
`sdk/go/services/barrier/`. Embedded callers hold `*barrier.Manager` (from
`App.Barrier()`).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Initialize | MISSING — docs/13 G7 (gate `/init` only before unseal) | `BarrierService.Init` | MISSING — docs/13 G7 | MISSING — docs/13 G7 | `Manager.Initialize`, `Manager.InitializeShamir` |
| Status | MISSING — docs/13 G7 (gate `/healthz` only before unseal) | `BarrierService.GetStatus` | MISSING — docs/13 G7 | MISSING — docs/13 G7 | `Manager.Status` |
| Unseal | MISSING — docs/13 G7 (gate `/unseal` only before unseal) | `BarrierService.Unseal` | MISSING — docs/13 G7 | MISSING — docs/13 G7 | `Manager.Unseal`, `Manager.UnsealWithShare` |
| Seal | MISSING — docs/13 G7 | `BarrierService.Seal` | MISSING — docs/13 G7 | MISSING — docs/13 G7 | `Manager.Seal` |
| Rekey | MISSING — docs/13 G7 | `BarrierService.Rekey` | MISSING — docs/13 G7 | MISSING — docs/13 G7 | `Manager.Rekey` |
| Recovery keys (generate, recover) | MISSING — docs/13 G7 | MISSING — docs/13 G7 | MISSING — docs/13 G7 | MISSING — docs/13 G7 | MISSING — docs/13 G7 |

Recovery is reachable only through the quicbaas SDK, which is what
`platformctl barrier recovery` uses.

### Messages

| Message | Fields |
|---|---|
| `BarrierInitRequest` | `secret`, `threshold`, `shares` |
| `BarrierInitResponse` | `status`, `strategy`, `initialized_at`, `threshold`, `shares_total`, `share_count`. Fields 3 (`unseal_keys`) and 4 (`root_token`) are reserved: shares are never returned, and the SDK barrier initialize returns no root token. |
| `BarrierStatusRequest` | — |
| `BarrierStatusResponse` | `status`, `sealed`, `initialized`, `strategy`, `threshold`, `shares_total`, `initialized_at`. Field 7 (`shares_provided`) is reserved: the SDK status carries no share progress, which `BarrierUnsealResponse` reports after each share. |
| `BarrierUnsealRequest` | `secret` |
| `BarrierUnsealResponse` | `status`, `sealed`, `shares_provided`, `shares_threshold` |
| `BarrierSealRequest` | — |
| `BarrierSealResponse` | `status`, `sealed` |
| `BarrierRekeyRequest` | `threshold`, `shares` |
| `BarrierRekeyResponse` | `status`, `strategy`, `threshold`, `shares_total`, `share_count`. Field 3 is reserved. |

`BarrierStrategy` is `UNSPECIFIED`, `SINGLE_KEY` or `SHAMIR`.

### Behaviour that callers see

- `Init` with `threshold >= 2` initializes Shamir. Anything lower initializes a single key.
- `Unseal` treats `secret` as a share when the configured strategy is Shamir.
- `GetStatus` takes every field from one upstream status reading. `initialized`
  is true once upstream reports an initialization time; `threshold` and
  `shares_total` are the Shamir split, zero for a single key.
- `strategy` is `SHAMIR` when upstream reports a Shamir threshold or the
  `shamir` strategy; `SINGLE_KEY` for `passphrase`, `software`, `tpm2`,
  `pkcs11` and `system-barrier`; `UNSPECIFIED` for `none` or anything else.
- `Rekey` reports the split upstream says it made: `SHAMIR` with its
  `threshold`, `shares_total` and `share_count`. Upstream rekey is Shamir-only,
  so a successful rekey is always `SHAMIR`; a response without a threshold
  reports `UNSPECIFIED` rather than claiming one.

The RPC-by-RPC mapping is in [engineering.md §5](engineering.md#5-barriergrpcservice).

### gRPC codes

Every barrier RPC error is classified by `barrier.Code`
(`pkg/barrier/error_codes.go`). It looks through the whole error chain, so a
wrapped error keeps its code.

| Condition | Code |
|---|---|
| No barrier configured | `Unavailable` |
| Already initialized (`ErrAlreadyInitialized`) | `AlreadyExists` |
| Not initialized; sealed when it must be unsealed; not sealed when it must be sealed; no ceremony for this strategy | `FailedPrecondition` |
| Empty secret, share, username, nonce or signature; invalid threshold; nil context | `InvalidArgument` |
| Context cancelled; deadline exceeded | `Canceled`; `DeadlineExceeded` |
| A gRPC status from the upstream gRPC transport | The upstream code (`Unknown` becomes `Internal`) |
| A quicbaas SDK error (`sdkerrors.QBError`) | By its code: invalid input `InvalidArgument`; not found `NotFound`; already exists or conflict `AlreadyExists`; unauthorized `Unauthenticated`; forbidden `PermissionDenied`; precondition failed, sealed or not initialized `FailedPrecondition`; rate limited or resource exhausted `ResourceExhausted`; unavailable, connection or transport `Unavailable`; timeout `DeadlineExceeded`; cancelled `Canceled`; unimplemented `Unimplemented` |
| Anything else, including a nil SDK client or config | `Internal` |

Over the embedded transport the upstream barrier errors (a wrong secret, for
example) carry no code the platform can read: the quicbaas SDK does not
re-export the qrdb seal sentinels. They are reported as `Internal`.

## 4. Per-tenant barrier

The per-tenant barrier is a separate capability with its own routes on every
transport. They are listed once, in
[`docs/tenant/api.md` §5](../tenant/api.md#5-per-tenant-barrier).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Init, unseal, seal, status | `/api/v1/tenants/{id}/barrier/{init,unseal,seal}`; status is `GET .../barrier` (daemon REST server: `.../barrier/status`) | `TenantService.*TenantBarrier*` | Category `0x9E`, sub-opcodes `0x01`–`0x04` | `platform_tenant_barrier_*` | `tenant.Manager` |

None of these touch the platform barrier.

## 5. Authorization

The gate routes carry no authentication; access is limited to the loopback
address and the socket's file mode. `BarrierService` follows the platform-wide
rules in
[`docs/daemon/api.md` §5](../daemon/api.md#5-authorization--the-platform-wide-picture).
