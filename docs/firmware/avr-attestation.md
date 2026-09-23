# AVR Attestation Provider

Status: Implemented (provider only)
Owner: `pkg/firmware/avr/attestation`

The platform-side attestation provider for arduino-generic AVR devices. It
collects device-signed evidence, parses it, and appraises it against a policy,
using the same vendor-neutral contract the BMC attestation subsystem defines
(`pkg/bmc/attestation`).

## Goals

- Implement `bmcattestation.AttestationProvider` for an AVR device reached
  over a serial link, so a microcontroller and a server BMC appraise through
  one set of types.
- Relay device-signed evidence **verbatim**, so a compromised gateway cannot
  lie about what a device measured.
- Carry tenancy from the first record.
- Land arduino-generic's reproducible `FWHash` in `Policy.Reference`, the
  golden-build comparison.

## Non-goals

- **Not** DICE verification. Decoding the UCCS claims set, verifying a DICE
  chain and checking the `eat_nonce` claim belong to go-xkms
  (`pkg/attestation/dice`), reached through the go-quicbaas SDK re-export.
  This package does not reimplement them and does not pretend to have run
  them.
- **Not** enrolment, the device registry, gateway wiring, or CLI surface.
  Those are separate work; see [Following work](#following-work).

## The two flows

The device answers two different questions and they take different challenges.
The widths are different on purpose and merging them is a wire break, so each
command refuses the other's width **before a frame is built** — a device handed
a truncated challenge cannot tell it was truncated.

| Method | Challenge | Wire | Evidence | Question |
|---|---|---|---|---|
| `Dump` | `aggeneric.AttestNonceLen` (16) | `ATTEST` | 164-byte signed frame | Is this device reporting *now*? |
| `AttestCert` | `aggeneric.AliasNonceLen` (32) | `ATTEST_CERT` | DICE alias certificate (DER) | Is this key on *this* device? |

`AttestCert` is not on the shared provider interface. It lives on
`CertAttester`, a one-method interface this package declares, because a BMC has
no enrolment ceremony and widening the shared contract for one backend would
leave every other backend with a method it must refuse.

## The evidence frame

`include/ag/protocol.h` in arduino-generic defines it:

```
[Version:1][Nonce:16][DeviceID:16][FWHash:32][BootCount:4]
[UptimeMs:4][AlgID:1][Signature:64][Reserved:26]
```

`UptimeMs` is **not a timestamp**. No part in this family has an RTC. It is
recorded as the attribute `uptime_millis`, named so it cannot be read as a
time, and nothing compares it against a clock.

## Synthetic PCR mapping

DICE has no PCRs and this device performs no extend operation, so
`Measurement.PCRBank` carries **raw measurements at synthetic indices in this
package's namespace**. They are not TPM PCRs and must never be compared with
one.

| Index | Constant | Contents |
|---|---|---|
| 0 | `PCRBootloader` | ag-boot's measurement of its own boot section. **Reserved and absent.** |
| 1 | `PCRApplication` | `FWHash` — SHA-256 over the application flash, taken by ag-boot before it jumps. The reproducible golden-build value. |

Index 0 is reserved rather than populated because **the wire does not carry a
measurement of the bootloader**. ag-boot measures the *application*; it is
itself anchored out of band, by the public-key hash pinned in reserved EEPROM
(`docs/security/bootloader.md` in arduino-generic), and the device does not
report that hash in signed evidence. Reserving the index means that the day
ag-boot does report its own measurement, nothing below has to renumber.

An absent index is **absent from the map**, never zero-filled. A verifier must
be able to tell "the device did not report this" from "the device reported
thirty-two zero bytes" — and an all-zero `FWHash` is exactly what an
unprovisioned device sends, deliberately, so that it can be seen for what it
is.

## Contract mapping

| Contract member | AVR meaning |
|---|---|
| `Vendor` | `"arduino-generic"`. Not registered with the BMC dispatcher: an AVR part has no manufacturer string to sniff, so routing is the caller's decision from the transport. |
| `Dump` | `ATTEST`, 16-byte nonce. |
| `List` / `Download` / `Delete` | `ErrAttestationUnsupported`, terminal. The device regenerates evidence per nonce and caches none — which is also why both attestation commands page. |
| `GetInfo` | **The single parse point.** Nothing else in the package reads `Evidence.Raw`; `Compare` and `Verify` both come through here. |
| `Compare` | Golden-build comparison over frame version, device id, algorithm id and `PCRApplication`. |
| `Policy.Reference` | The golden build's evidence frame. |
| `Policy.MaxAgeSeconds` | **Required and positive.** See below. |
| `Verifier` | `NewVerifier(provider)`. |

### Freshness and the relay stamp

`Evidence.CreatedAt` is stamped by **this gateway** when it relays, from
`Config.Clock`. `Measurement.CreatedAt` stays zero, because the contract
documents it as the vendor-side generation time and the device generated none.

`Policy.MaxAgeSeconds` ages the gateway stamp and nothing else. The contract
treats zero as "disable the age check"; **this backend refuses zero**, with
`ErrPolicyMaxAgeUnset`. A stale posture reading as a good one is the failure
this subsystem exists to prevent, and a caller who wants a loose bound must
state one an auditor can see rather than leave a field at its zero value.
Unstamped evidence fails the `relay_stamp` rule; a future stamp fails it too.

### Where verification stops

`RequireNonceEcho` **fails** on alias-certificate evidence. The challenge is
inside `tcg-dice-UCCS-evidence`, this package does not decode CWT claims, and
reporting a check it had not performed would be worse than refusing. The
failure reason names go-xkms as the component that does perform it.

`TrustedIssuers` is a **name** check on the leaf's issuer. Building and
verifying a DICE chain is `dice.Verify`'s job; a name match narrows which
certificates are worth forwarding and claims nothing more.

### Verbatim relay

`Evidence.Raw` is exactly the bytes the device sent. Every parsed view copies
out of it rather than aliasing it, so a caller cannot reach back through a
`Measurement` and change what a device is recorded as having said. A
compromised gateway may lie about *which* devices exist; it must not be able to
lie about what a given device measured.

### Tenancy

A provider is bound to one tenant at construction, validated with
`tenant.TenantPath`, so this package and the tenant key space agree on what a
legal identifier is. Every record carries it in
`Evidence.Metadata["tenant_id"]` (`TenantOf` reads it). Evidence from another
tenant — or with no tenant — is **refused** by `GetInfo`, `Compare` and
`Verify` with `ErrTenantMismatch`. A refusal, not a failed appraisal score:
cross-tenant evidence is never scored.

## What did not fit

Reuse of `pkg/bmc/attestation` exposed five misfits. They are recorded rather
than worked around.

1. **The contract lives under `pkg/bmc`.** Nothing in `Evidence`,
   `Measurement`, `Policy`, `CompareResult`, `Verifier` or the error set is
   BMC-specific, but a microcontroller provider now imports a BMC package to
   reach them. The contract wants lifting to `pkg/attestation`, with
   `pkg/bmc/attestation` keeping the dispatcher, the BMC `Vendor` constants
   and the vendor backends.
2. **`Vendor` and `DetectVendor` are closed to BMC manufacturers.** `Vendor`
   is an open string type, so `"arduino-generic"` is legal, but
   `DetectVendor` can never return it and `NewProvider` routes from a Redfish
   manufacturer string. This backend is therefore not registered.
3. **`Target` describes a network BMC** — address, port, username, password.
   An AVR device is an `io.ReadWriter` with no credentials, so this package
   declares its own `Config`.
4. **The `Action` set has no enrolment verb**, because a BMC has no enrolment
   ceremony. `ActionAttestCert` extends it.
5. **`Evidence` has no typed tenant field**, so the binding rides in
   `Metadata`. When the device registry lands, a typed `TenantID` on the
   contract's `Evidence` would be better than a map key.

One thing arduino-generic's Go SDK does not yet provide: **a parser for the
evidence frame.** `Device.Attest` returns 164 opaque bytes, so every consumer
must know the offsets. They are duplicated in `evidence.go`, marked as such,
and should be deleted when the SDK grows a `ParseEvidence`. The lengths and
both nonce widths already come from the SDK, so the constants a consumer must
not guess at are not guessed at.

## Testing without hardware

There is no device and CI has none. The SDK speaks over an `io.ReadWriter`, so
the seam is a **fake link driving the real codec**: every byte a test sends is
framed by the SDK's own `EncodeResponse` and every byte the provider sends is
parsed by the SDK's own `Decode`. Mocking the SDK's methods would replace the
one thing worth exercising — a reply's layout, a status code's meaning, the
width a command needs — with this package's own opinion of it, and the tests
would pass for a device that does not exist. The shape follows
arduino-generic's `cannedLink` and go-xkms's `pkg/backend/avr` harness.

```
make test-avr-attestation
make coverage-avr-attestation
make bench-avr-attestation
```

## Following work

- Enrolment: driving `AttestCert` into an ACME `device-attest-01` flow, with
  `dice.Verify` reached through the go-quicbaas SDK re-export of go-xkms.
- The device registry: persisting tenant-scoped device identity and the
  golden `FWHash` per build.
- gatewayd wiring: scheduling collection rounds and relaying evidence.
- `platformctl` surface for collection and appraisal.
- `docs/firmware/architecture.md`'s NORMATIVE scope line should gain
  `pkg/firmware/avr/attestation/` — its scope names packages that exist, and
  this one now does.
