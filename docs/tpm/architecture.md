# Physical TPM 2.0 — Architecture

> **Status: NORMATIVE** · Scope: `pkg/app/` (TPM lifecycle), `pkg/vtpm/target.go`, `pkg/api/daemon/tpm_grpc_service.go`, `pkg/api/quic/tpm_handlers.go`, `pkg/api/tpmnv/`, `pkg/webservice/v1/rest/tpm/`, `pkg/api/mcp/tpm_tools*.go`, `pkg/cli/commands/tpm/`, `sdk/go/services/tpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

The platform's whole security argument rests on a device that it does not, and
must not, implement. Node identity, sealed secrets, measured boot and every
attestation quote come out of a TPM 2.0. Someone has to own the TPM 2.0 command
layer — the marshalling, the sessions, the hierarchy authorization, the key
templates — and it is not this repository.

So the question this feature answers is narrow and it is the only question it
answers: **how does the platform drive a TPM it does not own, consistently,
across six transports, without ever letting a caller silently get a weaker root
of trust than the one it asked for.**

## 2. The shape chosen

**This repo is a driver and an exposer, not an implementation.**

- **One handle.** `App.TPM` is a single `TrustedPlatformModule` opened once at
  boot by `App.OpenTPM` and injected into every transport handler by a
  `SetTPM2Service` call. No transport opens its own connection to the device.
- **One decision point.** `vtpm.ResolveTPMTarget` decides hardware character
  device versus swtpm socket versus in-process simulator, and it decides it
  once. Its doc comment says so: *"the ONE decision point for hardware vs swtpm
  vs simulator selection"*.
- **Fail closed on the root of trust.** A configuration that names a hardware
  device never silently degrades to software, and a configuration that names a
  swtpm socket never silently opens a hardware device.
- **One NV implementation.** The upstream `TrustedPlatformModule` interface
  does not expose NV operations, so `pkg/api/tpmnv` constructs the NV commands
  once, over the module's raw transport, for every protocol to share.
- **The platform PCR is the platform's own.** The platform extends a dedicated
  PCR (`tpm.platform-pcr`, `23` in the shipped single-node template) with a
  golden measurement composed from `tpm.golden-pcrs`, and re-extends it on every
  boot because PCRs are volatile. Platform-owned keys are sealed to *that* PCR,
  not to firmware PCRs directly.

There is **no `pkg/tpm/` package in this repository** (grepped 2026-08-18). The
feature is a lifecycle, a resolver, six transport adapters, an SDK client and a
CLI — nothing more.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Implement TPM 2.0 commands, key templates and session handling here** | All hardware crypto is owned by go-xkms and consumed through the quicbaas SDK. A second implementation means two key-template dialects and two sets of session bugs against the same device. |
| **Import go-xkms directly instead of `go-quicbaas/sdk/go/xkms`** | The platform imports `go-quicbaas/sdk/go` only. `pkg/api/daemon/tpm_grpc_service.go` records the second reason in a comment: the `xkms` sub-package exists so that xkms's TPM types *"don't collide with QuicBaaS's own type aliases of the same name (UnsealRequest, KeyInfo, PIVSignRequest, …)"*. |
| **Let each transport open its own TPM** | The TPM is a single-tenant device with a resource manager in front of it and hierarchy auth established once at provisioning. Four independent openers means four independent auth states and `TPM_RC_OBJECT_MEMORY` under load. One handle, injected. |
| **Fall back from a missing hardware TPM to swtpm** | The fallback is invisible in every downstream artefact: the quote still verifies, the seal still unseals, and the deployment now has software-rooted attestation while believing it has hardware-rooted attestation. `ErrHardwareTPMUnavailable` and `ErrSwtpmSocketUnavailable` make the mismatch a startup failure instead. |
| **Open the configured path and let the `open(2)` error explain it** | Pointing a hardware path at a socket (or the reverse) is the most common misconfiguration and produces an unreadable error. `ErrNotCharDevice` / `ErrNotUnixSocket` type-check the path *before* opening it. |
| **Re-implement NV define/read/write/undefine per transport** | Four wire implementations of the same four TPM commands, each choosing its own auth hierarchy. `pkg/api/tpmnv` is the single implementation; the auth hierarchy is derived from the index's own public attributes (AUTHREAD / OWNERREAD / PPREAD) in exactly one place. |
| **Seal platform keys directly to firmware PCRs (0, 7, 9…)** | Every firmware or bootloader update would invalidate every sealed object, and the set of PCRs a given key depends on would be scattered across call sites. The platform composes one golden measurement into one platform PCR and seals to that. |
| **Include PCR 10 (IMA) in the golden measurement** | PCR 10 changes on every boot. The shipped config says so in place: *"PCR 10 (IMA) changes on every boot — DO NOT include for LUKS unlock!"* Including it turns every reboot into an unseal failure. |
| **Expose the raw `TrustedPlatformModule` interface through the SDK** | The SDK would then be a second, unversioned copy of go-xkms's surface, and the platform's own SDK would break whenever the upstream interface moved. `sdk/go/services/tpm` exposes the platform's `TPMService` gRPC contract instead. |

## 3. Component boundaries

| Piece | Package / location | Owner |
|---|---|---|
| TPM lifecycle at boot — open, provision, policy restore, recovery | `pkg/app/app.go` (`OpenTPM`, `InitTPM`) | this repo |
| **TPM target resolution** (hardware / swtpm / simulator) | `pkg/vtpm/target.go` (`ResolveTPMTarget`) | this repo |
| Hardware TPM auto-detection | `pkg/initrd` (`NewTPMDetector`, `DetectTPMType`) | this repo |
| gRPC `TPMService` implementation | `pkg/api/daemon/tpm_grpc_service.go` | this repo |
| QUIC TPM2 category handler (`0x99`) | `pkg/api/quic/tpm_handlers.go` | this repo |
| REST routes under `/api/v1/tpm` | `pkg/webservice/v1/rest/tpm/` | this repo |
| MCP `platform_tpm_*` tools | `pkg/api/mcp/tpm_tools.go`, `tpm_tools_exec.go` | this repo |
| NV command construction (shared by gRPC and QUIC) | `pkg/api/tpmnv/` | this repo |
| Device identity — IDevID / IAK / LDevID | `pkg/api/daemon/idevid_grpc_service.go`, `idevid_ldevid.go`, `pkg/webservice/v1/rest/idevid/`, `pkg/api/mcp/idevid_tools.go` | this repo |
| SDK client | `sdk/go/services/tpm/`, `sdk/go/services/idevid/` | this repo |
| CLI | `pkg/cli/commands/tpm/` | this repo |
| **TPM 2.0 command layer, key hierarchy, EK/SRK/IAK/IDevID creation, seal, unseal, quote, policy sessions, platform policy digest, factory reset, PPI ForceClear** | `go-quicbaas/sdk/go/xkms`, re-exporting **go-xkms** | **not this repo** |
| **EK / IDevID / IAK certificate issuance** | the CA, through the quicbaas SDK — [`docs/ca/`](../ca/) | **not this repo** |
| **PKCS#11, cloud KMS, WebAuthn/FIDO2/PIV** | go-xkms | **not this repo** |
| Virtual TPM bundles for VMs | `pkg/vtpm/`, `pkg/swtpm/` — [`docs/vtpm/`](../vtpm/) | this repo, separate feature |
| Quote verification against policy, manifests, IMA | `pkg/attestation/`, `pkg/ima/` — [`docs/attestation/`](../attestation/) | this repo, separate feature |

The §R capability row is the attestation row — *"TPM attestation of nodes and
workloads"*, Tier 1 — reached through `services/tpm` alongside
`services/attestation` and `services/vtpm`. The **hardware-crypto** row is
go-xkms's, and this feature is a consumer of it, never a second owner.

### The SDK edge, precisely

Every TPM operation in this repository crosses exactly one import:

```go
quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
```

The types that cross it and are used here: `TrustedPlatformModule`, `TPMConfig`,
`DefaultTPMConfig`, `TPMParams`, `NewTPM2`, `TPMKeyBackend`,
`TPMCertificateStorer`, `EKConfig`, `SRKConfig`, `Password`,
`ErrTPMNotInitialized`, `NewTPM2BackendWithTPM`, `TPM2BackendExternalConfig`.
Nothing in `pkg/` constructs a TPM command directly except `pkg/api/tpmnv`,
which does so over the transport handed out by `TrustedPlatformModule`.

## 4. Data flow

### 4a. Boot — how the platform gets a usable TPM

1. **Config load.** `app.TPMConfig` (`xkms.TPMConfig`, YAML key `tpm:`) is
   populated; `DefaultTPMConfig` supplies the base.
2. **PIN resolution first.** The Security Officer PIN is resolved *before* the
   TPM is touched, and `assertNoUnresolvedKMSURI` refuses to proceed with an
   unresolved `kms://` reference in `TPMConfig.SSRK.HierarchyAuth` or
   `TPMConfig.EK.HierarchyAuth`. An unresolved URI would be submitted verbatim
   as a hierarchy auth value and rejected by the TPM as an oversized buffer.
3. **Target resolution.** `vtpm.ResolveTPMTarget` returns
   `TPMTargetHardware`, `TPMTargetSwtpm` or `TPMTargetSimulator` plus a concrete
   device path. An `auto` sentinel is rewritten to the detected path so
   downstream consumers see something real.
4. **Open.** `xkms.NewTPM2` is given a key backend, a blob store, a certificate
   store, the config, the platform FQDN and a logger. The result is `App.TPM`.
   When `tpm.entropy` is set, `App.Random` becomes the TPM.
5. **Platform policy restore.** `IsPlatformPCRExtended` is checked on every
   boot; if the platform PCR is clear, `CreatePlatformPolicy` re-extends it with
   the golden measurement. **PCR values are volatile — this must happen every
   boot or every TPM-sealed platform secret is unreachable.**
6. **Provision if needed.** `InitTPM` is idempotent. If the TPM is unprovisioned
   it runs the destructive recovery path (§4c) — on a disk node. A diskless
   node (`platform_boot_model=diskless` on the signed kernel command line)
   decides from the TPM alone (§4d).
7. **Injection.** The single handle is passed to the gRPC service, the QUIC
   TPM2 handler, the MCP tool service and the REST handler set.

Steps 2 and 3 happen before any key material moves. That ordering is the
security property: the platform decides *which* TPM it is talking to and
*whether it is the one that was asked for* before it authorizes anything to it.

### 4b. A request — any transport

```
platformctl / SDK / REST / gRPC / QUIC / MCP client
        │
        ▼
transport handler (pkg/api/daemon, pkg/api/quic, pkg/webservice/v1/rest/tpm, pkg/api/mcp)
        │  all four hold the SAME *TrustedPlatformModule
        ▼
go-quicbaas/sdk/go/xkms  ──►  go-xkms TPM2 implementation
        │
        ▼
resolved target: /dev/tpmrm0 | swtpm .sock | in-process simulator
```

Nothing is persisted by this feature. Sealed objects, NV contents and key
handles live in the TPM; the EK certificate falls back to the platform
certificate store when NVRAM cannot hold it (`App.TPMCertStore`). The IAK and
IDevID certificates currently go to that same store unconditionally — their
configured NV handles are ignored while the #80 interim stands (see
[engineering.md](engineering.md) item 9).

### 4c. Recovery — the one destructive path

`InitTPM` will, when the TPM is present but unprovisioned or carrying an unknown
hierarchy auth from a prior install:

1. attempt `FactoryResetWithClear` (TPM2_Clear via the LOCKOUT hierarchy, then
   an EK-preserving evict);
2. on a lockout or bad-auth failure, schedule a UEFI **Physical Presence
   Interface** `ForceClear` and warm-reset the machine so firmware services it;
3. guard against a reboot loop — a second pass proceeds to `ProvisionPlatform`
   rather than rebooting again.

This is the only place the platform can wipe a TPM without an operator typing a
verb, and it only triggers when the TPM is already unusable **and** the ESP
seal probe PROVES no TPM-sealed LUKS unlock exists. The probe is tri-state:
with seal artifacts present, recovery is the non-clearing, non-evicting
seal-preserving repair instead; with an indeterminate probe (unmounted or
unreadable ESP), startup fails typed (`ErrTPMSealStateUnknown`) rather than
guessing in either direction. A TPM adopted with firstboot-created handles
but missing IAK/IDevID certificates is completed non-destructively by
`CompletePlatformIdentity`. Full detail:
[docs/installer/factory-reset.md](../installer/factory-reset.md) §platformd's
seal-preservation gate.

### 4d. Diskless node — the identity lives in the TPM

A diskless node (#690) boots a verified read-only root under a tmpfs overlay,
so none of §4c's evidence outlives a boot: no ESP to probe, no PPI-clear
sentinel, no identity certificates. `InitTPM` reads the boot model from
`/proc/cmdline` (`bootsDiskless`; an unreadable or ambiguous command line is
`ErrBootModelUnreadable`, never a guess) and on a diskless node decides from
the TPM alone (`pkg/app/tpm_diskless.go`):

1. **Provisioned means resident.** Each configured handle — EK, SSRK, Platform
   SRK, IAK, IDevID — must hold a `fixedTPM`/`fixedParent` object of its role
   (the EK and both SRKs restricted decryption keys, the IAK a restricted
   signing key, the IDevID an unrestricted signing key) whose reported Name is
   the Name of its public area. All five resident: the TPM is adopted
   untouched — no reset, no `Provision`, no clear — on every boot.
2. **First provisioning only on an empty TPM, once.** All five handles empty
   runs `FactoryResetWithClear` (empty lockout auth) and `ProvisionPlatform`,
   which leaves the five handles resident, so the next boot takes step 1.
   Anything between — some handles empty, or a handle holding an object of
   another role or under a Name that is not its public area's — is
   `ErrTPMIdentityPartial`, naming the empty and the mismatched handles. The
   node fails closed and clears nothing: TPM2_Clear would destroy whatever the
   TPM still holds, an enrolled identity included, so recovering such a TPM is
   an operator decision, never an automatic repair. A TPM whose manufacturer
   persisted the EK at the configured EK handle is therefore refused too; the
   operator clears it (firmware TPM clear) before the node's first boot.

   *Recovering a partial TPM.* Read the handles `ErrTPMIdentityPartial` names.
   If the TPM holds no identity worth keeping (an interrupted first
   provisioning, a vendor-persisted EK), clear it from the firmware and boot:
   the node provisions all five handles on the empty TPM. The IDevID and IAK
   are new keys after a clear, so the control plane's recorded enrollment for
   the device no longer matches the node's leaf; re-enroll the device before
   its first diskless boot delivery, or `BootCertificate` and `BootDelivery`
   refuse it. If the TPM does hold an enrolled identity, do not clear it:
   restore the missing or mismatched objects from the enrollment, or accept
   the loss and re-enroll as above. A
   refused reset is logged and provisioning proceeds; there is no seal probe
   (no LUKS seal exists) and no PPI `ForceClear` escalation (its loop guard is
   a file, which would not outlive the reset).
3. **A read failure is not an empty TPM.** Any `ReadHandle` failure other than
   an empty handle is `ErrTPMHandleUnreadable`, and a configuration missing a
   handle is `ErrTPMHandleUnset` — provisioning begins with TPM2_Clear.
4. **Certificates come back from the control plane, never re-minted.** A
   resident identity whose IAK/IDevID certificates are not on this boot's
   tmpfs does not run `CompletePlatformIdentity` — re-enrollment recreates the
   IDevID under the endorsement hierarchy auth, which a stateless node does not
   hold across boots, and each refused attempt counts toward dictionary-attack
   lockout. It recovers them instead (`recoverDisklessIdentity`,
   `pkg/app/tpm_diskless_boot.go`), after `InitCA` brings up the key store
   that signs with the IDevID and the certificate store the chain lands in:
   1. The control plane is the ACME directory's origin
      (`acme.client.directory-url`), the identity is the node's EK-derived
      name (step 5 below) — the name the IDevID was enrolled under. The node trusts the OS store plus the image's
      `ca-bundle.pem` (the well-known bundle paths `InitACMEClient` reads).
   2. `POST /api/v1/device/boot/certificate` returns the IDevID chain
      recorded at enrollment, which the node needs before it can present it.
      Having no certificate yet, the node proves itself in the request
      instead. It reads the IDevID public key from its persistent handle and
      signs the identity and the connection's channel value (step 3) with the
      TPM-resident key. The control plane checks that signature against the
      recorded leaf. Every request without that proof gets one identical
      `403`, so the route does not reveal which names are enrolled.
   3. The node presents that chain over TLS 1.3 mTLS, signing with the
      TPM-resident IDevID, and `POST /api/v1/device/boot` answers a 32-byte
      challenge the server takes from the connection itself (the TLS exporter,
      label `EXPORTER-go-trusted-platform-diskless-boot`) with an IAK quote
      over the default PCR selection. A quote is valid on the connection that
      produced it and nowhere else; there is no nonce round-trip to replay.
   4. The control plane refuses unless the presented leaf is the recorded
      IDevID, it chains to the platform CA with the client-auth usage, the
      quote's nonce is the connection's, and the device quote verifier — the
      one `POST /api/v1/device/attest` runs — returns a verified verdict for
      that device. Revoked and suspended devices are refused; a quarantined one
      may boot (quarantine is enforced on its port). It then returns that
      device's IDevID chain, IAK certificate, the platform CA bundle and its
      provisioning profile ([docs/device/api.md](../device/api.md) §Diskless
      boot delivery).
   5. The node stores nothing it has not checked against its TPM: the IAK
      certificate must certify the resident IAK. The issuers go to the CA
      certificate store, the leaves to it and to the TPM certificate store,
      which completes the platform identity for the rest of `InitTPM`.

   Any failure — no control plane configured, CP unreachable or untrusted, a
   refusal, material that does not certify the resident keys — stops startup
   with `ErrDisklessIdentityUnavailable`, which names the step that refused
   and carries its cause. There is no fallback to re-enrollment and no
   partially-identified start.
5. **The node is named after its EK, never after the image.** Every node
   built from one media set boots the same squashfs, so the platform config's
   TCG product serial and identity Common Names and `/etc/hostname` are the
   same on all of them. A diskless node therefore derives its identity from
   its TPM (`applyDisklessNodeIdentity`): `ek-` and the first 128 bits, in hex,
   of the SHA-256 of the EK's DER SubjectPublicKeyInfo
   (`entities.EKNodeIdentity`). It does so on every boot — on first
   provisioning right after `TPM.Provision` leaves the EK resident and before
   anything is enrolled — and that name replaces the image's
   `tpm.idevid.serial` (the TCG product serial, the device registry's key),
   the IDevID and IAK Common Names (`<identity>-idevid`, `<identity>-iak`) and
   the ACME enrollment Common Name. The hostname stays the image's and is
   cosmetic. On the control plane the registration refuses an `ek-` serial or
   Common Name that is not the identity of the EK certificate the enrollment's
   credential activation proved (`ErrRegistrationEKIdentityUnbound`,
   `pkg/device/registration.go`), so the record a node recovers from is the
   one bound to its TPM's EK. An EK the node cannot read is
   `ErrDisklessIdentityUnavailable`.

**Open:** the verdict reports `pcr_baseline_source`. Until a signed baseline is
published for a device, the first delivery captures a trust-on-first-use
baseline, so that boot's quote proves freshness and IAK possession, not that
the boot state is the expected one; the node logs which applied. Where a
stateless node's PIN material lives across boots is an open owner decision
(the SO PIN is never stored — #681).

## 5. Trust boundaries

1. **Configuration → root of trust.** `tpm.device` and `tpm.simulator` decide
   whether attestation is hardware-rooted. A deployment whose TPM resolves to
   swtpm or to the simulator has **software-rooted attestation** and is not
   equivalent to hardware, regardless of what its quotes verify against.
2. **Platform PCR → sealed data.** Anything sealed under the platform policy is
   reachable only while the platform PCR holds the golden measurement.
   `InitTPM` detects **SRK policy drift** — a stored `AuthPolicy` that no longer
   matches the current `PlatformPolicyDigest` — and re-provisions rather than
   letting every subsequent seal fail obscurely.
3. **Hierarchy auth.** The SO PIN is the Storage (owner) hierarchy
   authorization, set by firstboot on an installed node and by platformd on a
   TPM it finds unowned; the Endorsement and lockout auth stay empty
   ([engineering.md](engineering.md) §4 item 5). It is resolved through the
   secret-reference resolver, mirrored into `TPMConfig`, and never logged.
4. **Transport → device.** Every transport reaches the *same* TPM with the
   *same* authority. There is no per-caller TPM identity, so transport
   authorization is the only thing standing between a token holder and
   `Clear`. See §6 and [api.md](api.md) §6 — today that check is weaker than it
   should be, and it is recorded as a defect rather than described as a design.
5. **Identity certificate storage.** When the EK certificate exceeds what
   NVRAM will hold, it is stored in the platform certificate store instead. A
   verifier trusting an EK certificate must know which of the two it read.
   The IAK and IDevID certificates are in the store unconditionally today —
   the #80 interim ignores their NV handles because go-xkms defines the NV
   index as a counter (go-xkms#138), so a verifier must not assume an
   identity certificate is in NVRAM merely because a handle is configured.

## 6. What this feature deliberately does not do

- **It does not implement TPM 2.0.** Every command is executed by go-xkms
  through the quicbaas SDK. A missing capability is fixed upstream, never
  reimplemented here.
- **It does not issue certificates.** It creates keys and CSRs and installs
  certificates handed to it. Issuance is the CA's — [`docs/ca/`](../ca/).
- **It does not verify quotes against policy.** It produces quotes and can check
  a signature; deciding whether the measurements are acceptable is
  [`docs/attestation/`](../attestation/).
- **It does not manage virtual TPMs.** Bundles, templates and swtpm lifecycle
  are [`docs/vtpm/`](../vtpm/). The two features share only
  `vtpm.ResolveTPMTarget`.
- **It does not own PKCS#11, cloud KMS, WebAuthn, FIDO2 or PIV.** Those are
  go-xkms surfaces and are not exposed by this feature at all.
- **It does not authorize.** The platform is a broker-token validator: it
  enforces `scp` claims offline where a catalog entry exists. There is no
  TPM-specific policy engine.
- **It does not expose a `platformctl tpm quote` or `pcr read` verb.** No CLI
  verb quotes the physical TPM at all — the only attest verb in `platformctl` is
  `container attest` ([`docs/attestation/cli.md`](../attestation/cli.md) §1).
  Quoting and physical PCR access are API-only. See [cli.md](cli.md) §8.

## 7. Corrections against the pre-migration documents

The legacy files in this folder are retained for mining and are **not
authoritative**. Where they disagree with the code, the code won:

| Legacy claim | Reality in code |
|---|---|
| `architecture.md` (old): "Shared SRK (SSRK) Handle: 0x81000002" | The shipped template sets `tpm.ssrk.handle: 0x81000001`. `0x81000002` is `tpm.platform-srk.srk-handle`, a **different key**. The old document conflated SSRK and PlatformSRK. |
| `architecture.md` (old): a `tpm.pcr_policy:` config block with `indices`/`bank`/`description` entries | No such key exists. The real keys are `tpm.platform-pcr`, `tpm.platform-pcr-bank` and `tpm.golden-pcrs`. |
| `architecture.md` (old): "Performance Considerations" latency table | Not measured in this repository and not derivable from it. Treat as folklore. |
| `architecture.md` (old): NV index table listing `0x01C00012` "Platform Certificate" | The platform does not define or read that index anywhere in `pkg/`. The EK, IAK and IDevID each have their own `cert-handle` field; `tpm.idevid.cert-handle` is the IDevID's, not the EK's. Both `tpm.iak.cert-handle` and `tpm.idevid.cert-handle` are ignored today (interim, [engineering.md](engineering.md) item 9). |
| Several legacy files: "go-xkms" imported directly | The import is `go-quicbaas/sdk/go/xkms`. |
| Various: a `pkg/tpm/` package | Does not exist. |

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/vtpm/`](../vtpm/) — virtual TPMs for VMs
- [`docs/attestation/`](../attestation/) — what consumes a quote
- [`docs/ca/`](../ca/) — certificate issuance
- [`docs/daemon/api.md`](../daemon/api.md) — the six transports, the QUIC
  category-opcode table, and the platform-wide authorization picture
