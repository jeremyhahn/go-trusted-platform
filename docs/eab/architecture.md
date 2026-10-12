# ACME External Account Binding — Architecture

> **Status: NORMATIVE** · Scope: `pkg/eab/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

A machine being installed has no identity yet. It has an EK serial and a MAC
address, both of which an attacker on the same wire can read and replay. Before
the platform will hand that machine its configuration — and before it will sign
a Secure Boot DB digest on its behalf — something has to prove the machine was
*expected*.

ACME solves the same problem for account creation with **External Account
Binding** (RFC 8555 §7.3.4): the CA operator issues a `(key identifier, HMAC
key)` pair out of band, and the client proves possession of the HMAC key when it
creates its account.

This feature is that pair, issued and tracked by the platform, and consumed by
the **pre-enrollment provisioning flow** rather than only by ACME account
creation.

## 2. The shape chosen

**One credential = one `(KeyID, HMACKey)` pair, bound to a device profile and a
tenant, with an expiry and a four-state lifecycle.**

- `KeyID` is 16 random bytes, `base64url` without padding.
- `HMACKey` is 32 random bytes by default (`DefaultHMACKeyLength`), never fewer
  than `MinHMACKeyLength` (32).
- The pair is bound to `ProfileID` (a device profile) and `TenantID`.
- The lifecycle is `StatusActive → StatusRevoked | StatusExpired | StatusUsed`.
  Three of those four are terminal.

**The HMAC key leaves the platform exactly once**, in the `CreateCredential`
response. Every later read path — `GetCredential`, `GetCredentialByKeyID`,
`ListCredentials`, `ValidateCredential` — omits it.

Delivery to the device is a separate concern (`pkg/eab/delivery.go`): the same
credential can be rendered as a JSON document, a PNG QR code, or an enrollment
URL with the pair in query parameters.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Trust EK serial + MAC alone for pre-enrollment** | Both are readable off the wire and off the chassis. `configdelivery.validateIdentityFields` requires at least one of them *and* an EAB pair — the EK/MAC says *which* machine, the EAB pair says *that it was expected*. |
| **A long-lived shared enrollment secret for the fleet** | One leaked value enrolls every machine forever. Credentials are per-profile, per-tenant, and default to `DefaultCredentialExpiry` (24 hours). |
| **Make the HMAC key readable after creation** | A secret that can be re-read is a secret that ends up pasted into a runbook. `eabCredentialToPb(cred, includeHMACKey)` is called with `true` on exactly one path. Losing the key means issuing a new credential, which is the correct blast radius. |
| **Delete on use** | An audit trail of *which* credential enrolled *which* machine is worth more than the storage. `MarkUsed` sets `StatusUsed` and stamps `UsedAt`; `Delete` and `CleanupExpired` are separate, explicit operations. |
| **Compare the HMAC key with `bytes.Equal`** | Byte-by-byte comparison leaks the shared prefix length through timing. `Validate` uses `crypto/subtle.ConstantTimeCompare`. |
| **Report validation failure as a transport error** | An enrollment client needs to distinguish "your credential is revoked" from "the network is broken". `ValidateCredential` returns `valid=false` plus `error_message` in a 200/`StatusOK` response; only infrastructure failures become transport errors. |
| **A `platformctl eab` command group** | Not rejected — **not written**. Credentials are created through the API and consumed by `platformctl provision` / `platformctl install` flags. This is a gap, recorded in [cli.md](cli.md) §4, not a decision. |
| **Its own QUIC top-level opcode** | The single-byte QUIC opcode space is fully allocated. EAB multiplexes as sub-opcodes `0x10`–`0x1A` under `OpProvisioningCategory` (`0xCF`), which is also semantically right: EAB exists to authenticate provisioning. |

## 3. Component boundaries

| Piece | Location | Owner |
|---|---|---|
| Credential domain model, lifecycle, validation | `pkg/eab/types.go`, `service.go` | this repo |
| Storage entity and DAO | `pkg/eab/entity.go`, `dao.go` | this repo |
| Delivery rendering (JSON, QR, URL) | `pkg/eab/delivery.go` | this repo |
| gRPC/REST/QUIC/MCP service implementation | `pkg/api/daemon/eab_grpc_service.go` | this repo |
| REST router | `pkg/webservice/v1/rest/eab/` | this repo |
| QUIC sub-opcode dispatch | `pkg/api/daemon/quic_eab.go`, `sdk/go/wire/quicwire/eab_opcodes.go` | this repo |
| MCP tools | `pkg/api/mcp/eab_tools.go`, `pkg/api/daemon/mcp_eab.go` | this repo |
| Go SDK client | `sdk/go/services/eab/client.go` | this repo |
| **Underlying key-value storage, secondary indexes, pagination** | go-qrdb via `go-quicbaas/sdk/go`, reached through `pkg/storage/quicbaas` | **not this repo** |
| **The ACME server that consumes an EAB binding** | go-xkms `TrustedCA` + ACME, re-exported — [`docs/ca/`](../ca/) | **not this repo** |
| **Device profiles a credential is bound to** | `pkg/device/` — [`docs/device/`](../device/) | this repo, separate feature |
| **The pre-enrollment flow that validates a credential** | `pkg/provisioning/configdelivery/` — [`docs/provisioning/`](../provisioning/) | this repo, separate feature |
| **Transport, opcode and authorization model** | [`docs/daemon/api.md`](../daemon/api.md) | this repo, cross-cutting |

The §R capability row this feature serves is *"Zero-touch provisioning
(BMC/iPXE/installer)"* — EAB is the credential that gates it — with the ACME
half owned by go-xkms and re-exported per docs/00 L5.

## 4. Data flow

### Issuing

1. An operator (or an automation) calls `CreateCredential` with a `profile_id`,
   a `tenant_id`, and optionally `expires_in_seconds` and `hmac_key_length`.
2. `DefaultService.Generate` reads 32 bytes of `crypto/rand` for the HMAC key and
   16 for the KeyID, and persists an `EABCredential` through the DAO into
   QuicBaaS-backed storage.
3. The response carries the HMAC key `base64url`-encoded. **This is the only
   response that ever does.**
4. Optionally the operator renders the credential for the device:
   `GetCredentialQRCode` (PNG bytes) or `GetEnrollmentURL` (a URL with `kid`,
   `hmac` and `profile` query parameters).

### Consuming — pre-enrollment

1. The installer fetches a single-use nonce:
   `GET /api/v1/provisioning/config/nonce`.
2. It posts `POST /api/v1/provisioning/config` with EK serial, MAC, nonce, and
   the EAB pair (`eab_key_id`, `eab_hmac`).
3. `configdelivery.Service.verifyNonceAndEAB` consumes the nonce, then calls
   `eab.Service.Validate(ctx, keyID, hmacKey)`.
4. `Validate` looks the credential up by KeyID, constant-time compares the HMAC
   key, and rejects revoked/expired/used credentials.
5. The platform resolves the device's profile and requires the credential to be
   bound to it — `ProfileID` equal, and `TenantID` equal when the profile names
   a tenant (`configdelivery.verifyEABBinding`, `ErrEABProfileMismatch`). Only
   then does it return the configuration; the same path guards
   `POST /api/v1/provisioning/sign` (remote Secure Boot DB digest signing), so
   a credential can neither fetch nor sign on another profile's behalf.
6. After a successful enrollment the credential is retired with
   `MarkCredentialUsed`.

**Nothing in `pkg/eab` calls `MarkUsed` automatically.** Retirement is an
explicit call by whoever declares the enrollment complete.

### What crosses a boundary

| Crossing | What crosses |
|---|---|
| Operator → platform | The HMAC key, once, in a create response |
| Platform → device | The HMAC key, in a QR code, JSON file, or URL |
| Device → platform | The HMAC key, on every pre-enrollment request |
| Platform → storage | The HMAC key at rest, as a `[]byte` field of `EABCredential` |

## 5. Trust boundaries

This feature is almost entirely trust boundary. Precisely:

1. **The HMAC key is a bearer credential.** Anyone holding `(KeyID, HMACKey)`
   can pass pre-enrollment for the bound profile until the credential expires,
   is revoked, or is marked used. A QR code photographed off a screen is a
   compromise. Treat exported files (`ToFile`, `ToQRCodeFile` — both written
   `0600`, in directories created `0750`) as key material.

2. **`ValidateCredential` is fail-closed.** A credential that cannot be found, whose
   HMAC key does not match, or whose status is revoked / expired / used yields a
   typed error and no credential. There is no "allow if the store is
   unreachable" path: a storage error propagates.

3. **The service being absent is fail-closed *at the EAB surface* and
   fail-OPEN at the provisioning surface.** When the platform is not
   QuicBaaS-backed, `Registry.EABService()` returns nil and every EAB RPC
   returns `codes.Unavailable` (`ErrEABNotConfigured`). But
   `configdelivery.Service.verifyNonceAndEAB` guards its check with
   `if s.eabService != nil` — **with no EAB service wired, pre-enrollment
   validates the nonce and the presence of the EAB fields and accepts any
   values.** This is a fail-open path on the *provisioning* side and is called
   out again in [engineering.md](engineering.md) §6. It is recorded here as
   observed behaviour, not endorsed.

4. **Tenancy is a filter, not an enforced boundary, on some paths.**
   `ListByProfile` filters by `ProfileID` only; `ListByTenant` filters by
   `TenantID` only. The gRPC `ListCredentials` takes both and the service
   applies whichever is set. There is no server-side check that the caller's
   token tenant matches the requested `tenant_id` inside `pkg/eab` — that is
   the transport authorization layer's job, and **`EABService` is absent from
   the gRPC scope catalog** ([`docs/daemon/api.md`](../daemon/api.md) §5), so
   today no scope is required. See [api.md](api.md) §5.

5. **Timing.** HMAC comparison is constant time
   (`subtle.ConstantTimeCompare`). The lookup that precedes it is not, so the
   existence of a KeyID is distinguishable from a wrong HMAC key by response
   *type* (`ErrCredentialNotFound` vs `ErrInvalidCredential`) — deliberately, so
   operators can debug enrollment, and acceptable because a KeyID is not itself
   a secret.

6. **Expiry is evaluated at validation time and written back.** A credential
   found expired during `Validate` has its stored status flipped to
   `StatusExpired` before the error is returned. If that write fails the
   validation still fails — the write-back is best-effort, the rejection is not.

7. **The enrollment URL puts the HMAC key in a query string.** `ToURL` /
   `ToURLWithPath` set `hmac=` as a query parameter. Query strings land in proxy
   logs, browser history and `Referer` headers. Prefer the QR code or the JSON
   file where you control the channel.

## 6. What this feature deliberately does not do

- **It does not run ACME.** It issues and tracks the binding material; the ACME
  server that verifies an `externalAccountBinding` JWS lives in go-xkms and is
  re-exported through [`docs/ca/`](../ca/).
- **It does not compute or verify the ACME EAB JWS.** `Validate` compares raw
  HMAC key bytes for the pre-enrollment flow. It is not an RFC 8555 §7.3.4
  signature check.
- **It does not authenticate the pre-enrollment request by itself.** It answers
  "is this pair valid"; `pkg/provisioning/configdelivery` decides what that
  permits.
- **It does not retire credentials automatically after use.** `MarkUsed` is an
  explicit call.
- **It does not expire credentials on a timer.** There is no background sweeper;
  `CleanupExpired` runs when something calls it.
- **It does not encrypt the HMAC key at rest beyond whatever the storage layer
  provides.** `EABCredential.HMACKey` is a `[]byte` field persisted through the
  DAO.
- **It has no CLI command group.** See [cli.md](cli.md).

## 7. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/ca/`](../ca/) — the ACME surface an EAB credential ultimately binds to
- [`docs/device/`](../device/) — device profiles
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC categories, authorization
