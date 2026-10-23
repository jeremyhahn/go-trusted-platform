# Zero-Touch Provisioning — Architecture

> **Status: NORMATIVE** · Scope: `pkg/provisioning/`, `pkg/ipxe/`, `pkg/installer/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Scope note.** BMC (`pkg/bmc/`) and bootstrap (`pkg/bootstrap/`) belong to the
> same capability row and are **not documented in this pass** — see
> [engineering.md](engineering.md) §1. `docs/bmc/` and `docs/bootstrap/` remain
> unconverted.

---

## The problem

A bare machine is racked and powered on. It must end up as a trusted platform
node without anyone logging into it. The obstacle is at the very first step:

**the machine has no identity, and the platform must not trust anything the
machine says about itself.**

Everything downstream — attestation, port authentication, workload admission —
assumes an identity already exists. Provisioning is the one place that assumption
does not hold.

## The shape chosen

Identify the machine by **what it cannot choose**, and require **out-of-band
authorisation** before it receives anything.

1. The machine presents its **TPM endorsement key serial** and its **MAC
   address** — neither of which it selects — plus an **EAB credential** issued to
   it out of band.
2. That opens a **provisioning session**, which is **pending**.
3. An operator or an authorised automation **fulfils** the session by linking a
   **device profile** to it.
4. Only then is configuration delivered.
5. The installer runs, with **Secure Boot digests signed remotely** so the
   signing key never reaches the machine.
6. The machine reports completion; the platform decides what that means, and
   attestation establishes trust afterwards.

Throughout, the machine sits in a **provisioning-role network zone** whose flows
permit enrollment traffic and nothing else, and a failed check moves it to a
**quarantine** zone rather than leaving it ambiguous.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Let a machine provision itself once it presents valid credentials** | Then the credential *is* the identity, and a copied credential is a machine on your platform. `FulfillSession` makes a human or an authorised automation the gate, and there is no self-service path. |
| **Identify the machine by a hostname, serial file or DMI string it reports** | All of those are things the machine chooses or that a compromised firmware can change. The EK serial is burned into the TPM. |
| **Put a Secure Boot signing key on the machine so it can sign its own boot chain** | A machine you have not yet decided to trust would hold a key that signs boot chains. `SignDigest` keeps the key on the platform; the machine sends a digest and receives a signature. |
| **Give a booting machine ordinary network access** | It would be on the network before anything established what it was. A provisioning-role zone permits enrollment and nothing else. |
| **Mark a failed machine "failed" and leave it connected** | An ambiguous state is one somebody eventually authorises past. Quarantine is a distinct state on an isolated VLAN, with `Retry` as the only way back. |
| **Enrol disk-unlock factors after installation** | A disk encrypted at install time with no enrolled factor is a disk nobody can unlock. FIDO2 enrolment happens during installation. |
| **Trust the install-complete webhook** | It is the machine reporting on itself, which is exactly what the design refuses to trust. It is an input to the state machine; attestation is what establishes trust. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Provisioning client and types | `pkg/provisioning/` | this repo |
| **Pre-enrollment config delivery, nonces, remote signing, sessions** | `pkg/provisioning/configdelivery/` | this repo |
| Bare-metal provisioning service | `pkg/provisioning/baremetal/` | this repo |
| iPXE / network boot | `pkg/ipxe/` | this repo |
| OS installer, UKI, FIDO2 enrolment | `pkg/installer/` | this repo |
| ISO build and test | `pkg/iso/` | this repo |
| **BMC (Redfish/IPMI/SOL, vendor quirks)** | `pkg/bmc/` — **not documented in this pass** | this repo |
| **Bootstrap** | `pkg/bootstrap/` — **not documented in this pass** | this repo |
| **Device records, profiles, IDevID** | `pkg/device/` — [`docs/device/`](../device/) | this repo, separate feature |
| **EAB credentials** | `pkg/eab/` — [`docs/eab/`](../eab/) | this repo, separate feature |
| **The provisioning and quarantine zones** | `pkg/sdn/` — [`docs/sdn/`](../sdn/) | this repo, separate feature |
| **Certificate issuance** | the stack's CA — [`docs/ca/`](../ca/) | **not this repo** |
| **Signing keys** | the stack's KMS — [`docs/kms/`](../kms/) | **not this repo** |

The §R capability row is *"Zero-touch provisioning — BMC (Redfish/IPMI),
iPXE/network boot, installer"*, Tier 1, reached through `services/bmc`,
`services/pxe` and `services/provision`.

## Trust boundaries

1. **Unidentified machine → platform.** The primary boundary, and the reason
   this feature exists. It is crossed by an EAB credential plus a nonce, and it
   is **rate-limited** (`RateLimitConfig`) because anything can reach it.
2. **Pending session → fulfilled session.** The authorisation boundary. Nothing
   the machine does crosses it.
3. **Secure Boot signing.** The key stays on the platform.
   `pkg/provisioning/configdelivery/sign.go` and
   `pkg/installer/remote_sign_client.go` are the two ends.
4. **Provisioning zone → production zone.** Crossed when the port authenticates
   with the IDevID the machine obtained during provisioning
   ([`docs/sdn/`](../sdn/)).
5. **Install-complete report.** Untrusted. Attestation is what follows.
6. **Booting machine → its profile's config (`GET /api/v1/devices/config`).**
   Unauthenticated by design, because the caller has no credential yet. It is
   reachable only from the isolated provisioning VLAN (#177). Only a
   `surface: provisioning` listener bound inside the provisioning zone serves
   it, and every other listener answers `404`. The zone's flows keep everyone
   else off that address. An EK-bound challenge is planned
   ([engineering.md](engineering.md) §3, *Planned*).

## Data flow — a machine joining

```
machine boots (provisioning zone: enrollment traffic only)
   │
   ├─ GetNonce                      → nonce
   ├─ FetchConfig (EK serial + MAC + EAB credential + nonce)
   │      └─ session PENDING ───────────────────────────────┐
   │                                                        │
   │   operator: FulfillSession(session, profile-id) ───────┘
   │
   ├─ PollSession → config delivered
   ├─ install (SignDigest for Secure Boot; FIDO2 unlock enrolled)
   ├─ WebhookComplete
   │
   └─ IDevID enrolment → port authenticates → production zone
                                            → attestation
```

Two states have no forward path without an external decision: **pending**
(needs fulfilment) and **quarantined** (needs an operator).

## What this feature deliberately does not do

- **It does not decide whether a machine belongs.** Fulfilment does, and
  fulfilment is an operator action.
- **It does not issue certificates or hold signing keys.** Both come from the
  stack.
- **It does not establish trust.** It gets a machine to the point where
  attestation can.
- **It does not put a Secure Boot signing key on the machine.**
- **It does not offer PXE device lifecycle management from the CLI** — no
  `platformctl pxe` group exists ([cli.md](cli.md) §5), which is a gap rather
  than a decision.
