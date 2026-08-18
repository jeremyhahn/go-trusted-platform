# Zero-Touch Provisioning — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/provisioning/`, `pkg/ipxe/`, `pkg/installer/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).
>
> **Scope note.** BMC (`pkg/bmc/`) and bootstrap (`pkg/bootstrap/`) are part of
> the same §R capability row but are **deliberately not documented in depth
> here** — see §1.

---

## 1. What this document does and does not cover

The §R capability row is *"Zero-touch provisioning — BMC (Redfish/IPMI),
iPXE/network boot, installer"*. This folder covers **`pkg/provisioning/`,
`pkg/ipxe/` and `pkg/installer/`**, plus the PXE and provisioning-gateway
transport surfaces.

**BMC and bootstrap are excluded from this pass.** At the time of writing there
is substantial uncommitted work in the owner's tree touching `pkg/bootstrap` and
`pkg/bmc`, and documenting their internals from `main` alone would produce a
contract that is wrong the moment that work lands. Those two need their own pass
once it does. `docs/bmc/` and `docs/bootstrap/` remain unconverted.

The BMC surface as seen from *outside* — the gRPC service and the QUIC BMC
category opcode — is recorded in [api.md](api.md) because it is transport shape
rather than internals.

## 2. Package layout

| Package | Holds |
|---|---|
| `pkg/provisioning/` | `client.go`, `types.go`, `errors.go` — the provisioning client and its types |
| `pkg/provisioning/configdelivery/` | `service.go`, `handler.go`, `nonce.go`, `sign.go`, `types.go`, `errors.go` — **pre-enrollment config delivery** |
| `pkg/provisioning/baremetal/` | `service.go`, `config.go`, `types.go`, `doc.go`, `errors.go` |
| `pkg/ipxe/` | `config.go`, `dhcp_rawconn_linux.go`, `dhcp_rawconn_stub.go` |
| `pkg/installer/` | The OS installer — see §4 |

`pkg/ipxe/dhcp_rawconn_stub.go` is the non-Linux stub for the raw DHCP
connection; the real implementation is Linux-only. Provisioning boots machines,
and that needs raw sockets.

## 3. Config delivery — the pre-enrollment problem, solved

`pkg/provisioning/configdelivery/` is the interesting part, because it answers
the hardest question in zero-touch provisioning: **how does a machine that has
no identity yet get a configuration it can trust, without the server trusting
anything the machine says?**

`ConfigDeliveryService` (`pkg/api/grpc/proto/configdelivery.proto`) has seven
RPCs:

| RPC | Role |
|---|---|
| `GetNonce` | Issues a nonce — the anti-replay anchor for the exchange |
| `FetchConfig` | Delivers the device's configuration |
| `SignDigest` | **Remote Secure Boot digest signing** |
| `PollSession` | The device polls its provisioning session |
| `FulfillSession` | An operator links a device profile to a pending session |
| `ListSessions` | Lists pending sessions |
| `GetSession` | One session |

The shape this implies:

1. A device with no identity contacts the server and gets a **nonce**.
2. It presents evidence it *does* have — an **EK serial**, a **MAC**, and an
   **EAB credential** (`--eab-kid` / `--eab-hmac`).
3. That opens a **session**, which is *pending* until a human or an automation
   **fulfils** it by linking a device profile.
4. The device **polls** until fulfilment, then fetches its config.

**Fulfilment is the authorisation step.** A device cannot provision itself: the
session sits pending until something with authority attaches a profile. That is
why `FulfillSession` takes a `--profile-id` and why `interactive` QR
provisioning exists — a human scanning a code is the out-of-band authorisation.

**`SignDigest` is the other notable RPC.** It signs a Secure Boot digest
remotely, so the signing key stays on the platform rather than being placed on
the machine being provisioned. `pkg/provisioning/configdelivery/sign.go` and
`pkg/installer/remote_sign_client.go` are the two ends.

## 4. The installer

`pkg/installer/` is a full OS installer, not a script wrapper:

| Concern | Files |
|---|---|
| Orchestration | `installer.go`, `os.go`, `postinstall.go`, `hardreset.go` |
| Configuration | `config.go`, `config_generator.go`, `config_loader.go`, `types.go` |
| Profiles | `profiles.go`, `profiles/` |
| Disk | `disk.go` |
| Distribution support | `alpine.go`, `alpine/` |
| Initramfs | `dracut_builder.go`, `kernel_hook.go` |
| **Unified Kernel Image** | `uki.go`, `uki_rebuild.go`, `uki_rebuild_errors.go` |
| **FIDO2 disk unlock** | `fido2_enroll.go`, `fido2_unlock.go` |
| Remote signing | `remote_sign_client.go` |
| Hardware offload | `hwoffload.go` |

Three things worth knowing:

1. **UKI rebuild has its own error file** (`uki_rebuild_errors.go`). Rebuilding a
   Unified Kernel Image changes what the machine measures at boot, which
   invalidates anything sealed to those PCRs. It is not a routine operation.
2. **FIDO2 enrolment and unlock are part of installation**, not a later step. A
   disk encrypted at install time needs its unlock factor enrolled at install
   time.
3. **`remote_sign_client.go` pairs with `SignDigest`.** The installer does not
   hold a Secure Boot signing key.

## 5. Invariants

1. **A provisioning session is pending until fulfilled.** No self-service path.
2. **The nonce bounds the exchange.** A replayed config-delivery request without
   a fresh nonce is refused.
3. **The device is identified by what it cannot choose** — EK serial and MAC —
   plus an EAB credential that was issued to it out of band
   ([`docs/eab/`](../eab/)).
4. **Secure Boot signing happens on the platform**, never on the machine being
   provisioned.
5. **A PXE device has a lifecycle with a quarantine state.** `Authorize`,
   `Quarantine`, `Retry` and `SetDeviceEnrolled` are separate RPCs; a device that
   fails a check is quarantined rather than left in an ambiguous state.
6. **`WebhookComplete` is the machine's report that installation finished.** It
   is an input to the state machine, not a trusted assertion of success.

## 6. Configuration

`pkg/ipxe/config.go` configures network boot; `pkg/installer/config.go`,
`config_generator.go` and `config_loader.go` configure installation, with
`profiles/` holding the reusable shapes.

`pkg/provisioning/types.go` carries `ClientConfig`, `NetworkConfig`, `ACLConfig`
and `RateLimitConfig` — note **`RateLimitConfig`**: the provisioning endpoint is
reachable by unidentified machines and is rate-limited for that reason.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/provisioning/**/*_test.go`, `pkg/installer/*_test.go` | Session state, nonce handling, config generation, UKI rebuild |
| Integration | `test/integration/provision/`, `test/integration/pxe/`, `test/integration/ipxe/`, `test/integration/iso/` | Real boot flows |

**Two known holes in the integration suite** (measured 2026-08-18):

- `test/integration/pxe/grpc_adapter.go` contains **15 occurrences** of
  *"TODO: Implement when proto definitions are available"* — the adapter is
  hollow, so the PXE integration tests that use it exercise nothing.
- `test/integration/authenticode/multiprotocol_test.go:68-72` has **all five
  protocol adapters commented out** — a multi-protocol conformance test that
  exercises no protocol.

Both are recorded here rather than left to be rediscovered. A green run of
either suite currently means less than it appears to.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`GetEvents` / `pxe_get_device_events` gives a device's provisioning event
history — the first thing to read when a machine did not come up.
`GetStatus` / `pxe_service_status` reports whether the PXE service is running at
all.

**EAB HMACs are credentials.** `provision fetch-config --eab-hmac` takes one on
the command line; it must not be logged and will land in shell history.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/device/`](../device/) — device records, profiles and IDevID
- [`docs/eab/`](../eab/) — the EAB credentials a device provisions with
- [`docs/sdn/`](../sdn/) — the provisioning-role network zone a booting device sits in
- [`docs/attestation/`](../attestation/) — what a provisioned node does next
- **Not converted in this pass:** [`docs/bmc/`](../bmc/),
  [`docs/bootstrap/`](../bootstrap/) — see §1
- Deep dives carried over and not re-verified:
  [`docs/installer/`](../installer/), [`docs/ipxe/`](../ipxe/), and the other
  files in this folder
