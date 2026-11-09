# AVR Attestation Provider

> **Status: REFERENCE** · Last verified: 2026-10-26
> The AVR attestation provider in `pkg/firmware/avr/attestation`.

The platform-side attestation provider for trusted-firmware AVR devices. It
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
- Land trusted-firmware's reproducible `FWHash` in `Policy.Reference`, the
  golden-build comparison.

## Non-goals

- **Not** DICE verification. Decoding the UCCS claims set, verifying a DICE
  chain and checking the `eat_nonce` claim belong to go-xkms
  (`pkg/attestation/dice`), reached through the go-quicbaas SDK re-export
  `xkms.DICEVerify` (`sdk/go/xkms`, go-quicbaas v0.14.0-alpha and later; the
  pinned v0.12.0-alpha does not carry it). This package does not reimplement them and does not pretend to have run
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
| `Dump` | `tfw.AttestNonceLen` (16) | `ATTEST` | 164-byte signed frame | Is this device reporting *now*? |
| `AttestCert` | `tfw.AliasNonceLen` (32) | `ATTEST_CERT` | DICE alias certificate (DER) | Is this key on *this* device? |

`AttestCert` is not on the shared provider interface. It lives on
`CertAttester`, a one-method interface this package declares, because a BMC has
no enrolment ceremony and widening the shared contract for one backend would
leave every other backend with a method it must refuse.

## The evidence frame

`include/tfw/protocol.h` in trusted-firmware defines it:

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
| 0 | `PCRBootloader` | tfw-boot's measurement of its own boot section. **Reserved and absent.** |
| 1 | `PCRApplication` | `FWHash` — SHA-256 over the application flash, taken by tfw-boot before it jumps. The reproducible golden-build value. |

Index 0 is reserved rather than populated because **the wire does not carry a
measurement of the bootloader**. tfw-boot measures the *application*; it is
itself anchored out of band, by the public-key hash pinned in reserved EEPROM
(`docs/secure-boot/architecture.md` in trusted-firmware), and the device does
not report that hash in signed evidence. Reserving the index means that the day
tfw-boot does report its own measurement, nothing below has to renumber.

An absent index is **absent from the map**, never zero-filled. A verifier must
be able to tell "the device did not report this" from "the device reported
thirty-two zero bytes" — and an all-zero `FWHash` is exactly what an
unprovisioned device sends, deliberately, so that it can be seen for what it
is.

## Contract mapping

| Contract member | AVR meaning |
|---|---|
| `Vendor` | `"trusted-firmware"`. Not registered with the BMC dispatcher: an AVR part has no manufacturer string to sniff, so routing is the caller's decision from the transport. |
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
verifying a DICE chain is go-xkms `dice.Verify`'s job; a name match narrows which
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
   is an open string type, so `"trusted-firmware"` is legal, but
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

One thing trusted-firmware's Go SDK does not yet provide: **a parser for the
evidence frame.** `Device.Attest` returns 164 opaque bytes, so every consumer
must know the offsets. They are duplicated in `evidence.go`, marked as such,
and should be deleted when the SDK grows a `ParseEvidence`. The lengths and
both nonce widths already come from the SDK, so the constants a consumer must
not guess at are not guessed at.

## Constructing the device

`New` takes an already-built `*tfw.Device` from
`github.com/jeremyhahn/trusted-firmware/sdk/go` (package `tfw`, pinned at
`sdk/go/v0.3.0-alpha`); the caller owns the link. `tfw.New` waits up to
`tfw.DefaultBootWait` (2 s) for the firmware's BOOT event before it
returns, so the first frame lands on a running application and not in the
bootloader's window after a DTR auto-reset. An adapter that never resets the
board simply pays that bound.

- A device running `tfw-boot` built with `BOOT_MEASURE=atecc608a` measures the
  application through the secure element and can outrun the default. Pass
  `tfw.WithBootWait` sized to the flashed image.
- `tfw.WithBootWait(0)` disables the wait for a link known never to
  reset the board, such as the in-memory link used by this package's tests.
- The SDK speaks wire protocol 2.x and refuses a device reporting 1.x in
  `CAPS`, so `New` fails with `ErrAttestationFailed` (`CAPS`) against a board
  still running firmware from before the trusted-firmware rename. Reflash it;
  the evidence frame itself is unchanged (version 1, 164 bytes).

## Testing without hardware

There is no device and CI has none. The SDK speaks over an `io.ReadWriter`, so
the seam is a **fake link driving the real codec**: every byte a test sends is
framed by the SDK's own `EncodeResponse` and every byte the provider sends is
parsed by the SDK's own `Decode`. Mocking the SDK's methods would replace the
one thing worth exercising — a reply's layout, a status code's meaning, the
width a command needs — with this package's own opinion of it, and the tests
would pass for a device that does not exist. The shape follows
trusted-firmware's `cannedLink` and go-xkms's `pkg/backend/avr` harness.

```
make test-avr-attestation
make coverage-avr-attestation
make bench-avr-attestation
```

## Physical-board enrollment run (trusted-firmware#7)

trusted-firmware#7 runs a real board through ACME `device-attest-01` (#1093
asks where). **No bench lane can run it yet. No documented command exists.**
This section records what main has and what is missing. Line numbers are
against the commit that added this section.

### Where the ACME server and control plane run

The only ACME server is platformd's REST route group,
`pkg/webservice/v1/router/acme.go` ([../ca/api.md §3](../ca/api.md)). No test
binary, make target or fixture hosts one for a board. `make
integration-test-acme` runs platformd in the devcontainer and drives
`platformctl acme`, but it has no serial port and no `device-attest-01`.

A deployed platformd does not serve `device-attest-01` either:

- `buildChallengeMap` (`pkg/daemon/commands/serve.go:249-276`) maps
  `http-01`, `dns-01`, `enroll-01` and `endorse-01` only. Listing
  `device-attest-01` under `webservices[].acme.challenges`, as
  [../ca/acme.md](../ca/acme.md) shows, adds no verifier for it.
- The pinned SDK, go-quicbaas `sdk/go` v0.12.0-alpha (`go.mod:54-55`, held for
  #906/#937), exports the constant `ACMEChallengeTypeDeviceAttest01` but no
  `device-attest-01` verifier, and has no `xkms.DICEVerify`. That arrives in
  v0.14.0-alpha ([Non-goals](#non-goals)). The verifier is go-xkms's to
  implement ([../ca/api.md §3](../ca/api.md)).
- `platformctl acme renew --challenge device-attest-01`
  (`pkg/cli/commands/acme/renew.go:142`) is a client that holds a TPM. It does
  not hold a board.

**How the server reaches the board.** Nothing on main reaches it. Only this
package's own tests import `pkg/firmware/avr/attestation`. `New`
(`pkg/firmware/avr/attestation/provider.go:84`) takes a `*tfw.Device` over
an `io.ReadWriter`, so today it can only run in process on the host that holds
the serial port. There is no gateway relay yet (#696). The SPEC `firmware` row
(#771) requires the platform to reach the device through the go-quicbaas SDK,
with trusted-firmware's `xkms` adapter composed into go-xkms. The pinned SDK
does not carry that adapter.

### Which issue owns it

- **#772** owns the run itself. It is the SPEC `device-enrollment` row's "a
  DICE AVR enrolled end to end", and its finalize uses the CSR the device
  builds.
- **#696** owns what the run needs first: the enrolment driver (`AttestCert`
  into `device-attest-01`), the device registry and the gateway relay.
- **Upstream** owns the `device-attest-01` verifier and DICE chain
  verification (go-xkms, re-exported through go-quicbaas), and with them the
  SDK bump.

### The calls, in order, and what each is missing

| # | Call | On main | Missing |
|---|------|---------|---------|
| 1 | Device profile | `platformctl device profile create` ([../device/cli.md §3.2](../device/cli.md)) | The profile is keyed by EK serial, MAC and EK certificate. It has no field for a DICE device id or the golden `FWHash`. That is #696's registry. |
| 2 | EAB, if required | `webservices[].acme.external-account-required` (`pkg/webservice/v1/config.go:105`, passed through at `pkg/webservice/v1/registry.go:1900`). Create a credential with `POST /api/v1/eab/credentials` (`pkg/webservice/v1/rest/eab/router.go:59`). | Nothing. A bench may leave EAB off. |
| 3 | `newAccount`, then `newOrder` for a `permanent-identifier` | The ACME routes ([../ca/api.md §3](../ca/api.md)) | Nothing on the order. |
| 4 | Respond to the `device-attest-01` challenge | `AttestCert` (`provider.go:189`) signs the 32-byte SHA-256 of the key authorization | A server-side verifier (`buildChallengeMap`) and a client that carries the alias certificate to the challenge (#696). |
| 5 | `finalizeOrder` with the CSR the device built | The `finalizeOrder` route | The device-built CSR path (#772). |
| 6 | Download the issued certificate | The `certificate` route | Nothing once step 5 succeeds. |

**The verifier policy knob.** No setting admits a `notSecure` soft-rooted
device: the term does not appear in `pkg/` or `docs/` outside
`docs/reference/`, and `Policy` here has no security-level field. The knob
belongs to the `device-attest-01` verifier, which does not exist yet, so it
lands with that verifier upstream, and the platform's ACME configuration
exposes it.

## Following work

- Enrolment: driving `AttestCert` into an ACME `device-attest-01` flow, with
  `dice.Verify` reached through `xkms.DICEVerify`, the go-quicbaas SDK
  re-export of go-xkms.
- The device registry: persisting tenant-scoped device identity and the
  golden `FWHash` per build.
- gatewayd wiring: scheduling collection rounds and relaying evidence.
- `platformctl` surface for collection and appraisal.
- `docs/firmware/architecture.md`'s NORMATIVE scope line should gain
  `pkg/firmware/avr/attestation/` — its scope names packages that exist, and
  this one now does.
