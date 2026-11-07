# Firmware Trust — Architecture

> **Status: NORMATIVE** · Scope: `pkg/uefi/`, `pkg/uefi/firmware/`, `pkg/secureboot/`, `pkg/uki/`, `pkg/authenticode/`, `pkg/modulesign/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, exported surface, error sets, CLI flags,
> config keys and the transport matrix were read out of the code on 2026-08-18.
> Where the legacy files in this folder disagree with the code, the code wins and
> the correction is recorded in §9.

---

## 1. The problem

A node that boots an image nobody signed has no root of trust to attest *from*.
Every measurement the platform later collects — PCR quotes, IMA logs, workload
admission — is only as meaningful as the first link: did the firmware refuse to
run anything the platform did not authorise?

Making firmware enforce that is easy. Making it enforce that **without bricking
the machine** is the hard part, and it is what this feature is shaped around. A
Platform Key written into firmware is irreversible from software: once PK is
enrolled, the firmware runs only what chains to the enrolled `db`, and if the
image on disk is not one of those, the node is a paperweight until somebody
walks up to it.

## 2. The shape chosen

Four independent pieces, deliberately kept separable, plus one gate that binds
them:

| Piece | What it produces |
|---|---|
| **Key material** (`pkg/secureboot`) | PK, KEK and DB keypairs, and the stable kernel module-signing key |
| **Boot payload** (`pkg/uki`) | One PE/COFF executable holding kernel + initramfs + cmdline |
| **Signature** (`pkg/authenticode`) | An Authenticode/PKCS#7 signature embedded in that PE |
| **Firmware state** (`pkg/uefi`, `pkg/uefi/firmware`) | The PK/KEK/db/dbx variables, in an OVMF NVRAM file or in live efivarfs |
| **The gate** (`uefi.VerifySignedUKI`) | Proof that the signature on the payload was made by exactly the certificate about to be enrolled |

The gate is the design. Nothing writes a Platform Key until the image the
firmware will be asked to boot has been shown to verify against the `db`
certificate that write depends on — and PK is written **last**, so every failure
mode before it leaves a node that still boots unsigned.

A fifth piece, `pkg/modulesign`, hangs off the same trust idea one layer down:
the kernel's own keyring, which is a **separate trust root** from UEFI Secure
Boot and is enforced at module load time rather than at boot.

### 2.1 Two enrollment targets, one key set

The same PK/KEK/DB certificates are enrolled two different ways depending on
what the firmware is:

- **Virtual (OVMF)** — the variable store is a *file* (`OVMF_VARS.fd`). The
  platform parses the firmware volume and rewrites variables directly
  (`pkg/uefi/nvram.go`, `pkg/uefi/enrollment.go`).
- **Bare metal** — the variable store is the running firmware, reached through
  the `efivarfs` pseudo-filesystem. Writes are time-based authenticated
  variables (`pkg/uefi/efivars_enroll.go`).

They share the ESL encoder (`pkg/uefi/esl.go`), the GUID table
(`pkg/uefi/guid.go`) and the `db → KEK → PK` ordering. They do **not** share a
code path, because the failure modes are not the same: a corrupt NVRAM file is
recoverable by deleting a file, a corrupt live variable store is a service call.

## 3. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Shell out to `sbsign`, `sbverify`, `efitools`, `virt-fw-vars`** | The signer has to run inside an installer initramfs and inside a container-built ISO, where none of those tools are guaranteed present. Worse, an external binary takes a *file* private key — it cannot drive a hardware- or KMS-resident signer. `pkg/authenticode` signs through a `crypto.Signer` so the key can stay in a TPM or in the control-plane KMS. |
| **Write `SetupMode` and `SecureBoot` into the OVMF variable store** | They are firmware-**derived**, not persisted policy: EDK2 recomputes both from PK presence at every boot. Persisting them was worse than redundant — they carry no `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`, so they serialised with a 32-byte header inside an authenticated store and faulted the EDK2 variable driver with `#UD` on the next boot. `EnrollKeys` writes `db`, `KEK`, `PK` and nothing else. |
| **Enroll PK first** (it is the root, so enroll the root first) | Writing PK is precisely what takes the firmware out of Setup Mode and arms enforcement. Enrolling it first means a later `db` failure produces a node that enforces Secure Boot against an empty signature database. The order is `db → KEK → PK`, PK last, in both enrollment paths. |
| **Enforce first, verify the image afterwards** | That is the brick. `uefi.VerifySignedUKI` runs *before* any variable is written and requires two things: the UKI's Authenticode signature is valid, **and** its embedded certificate is byte-identical to the `db` certificate about to be enrolled. Passing that gate is what makes enrollment provably non-stranding. |
| **Ship the DB private key to each node** | A private key that traverses the network is a private key you no longer control. `resign-mode: remote` keeps it in the control-plane KMS and round-trips only the digest (`secureboot.NewKMSSigner`, `installer.RemoteSignerResolver`); `XKMSConfig.ResignMode == ResignModeRemote` forces `ExportKeys = false` so the export path cannot be re-enabled by accident. |
| **Generate a fresh DB key when the kernel is updated** | The new key would not be in the firmware's `db`, so the freshly signed UKI would be refused and the node would not boot. `installer.resolveRebuildSigner` returns a typed error and the rebuild aborts, leaving the working UKI in place, rather than falling back to generation. |
| **Use the kernel's own EFI stub as the UKI base PE** | `CONFIG_EFI_STUB` reads `LoadOptions` from `EFI_LOADED_IMAGE_PROTOCOL`; it does **not** read PE sections. A UKI built on it boots with no command line and no initrd and hangs silently. The base PE is systemd-stub (`uki.DefaultStubPath`), which is what reads `.linux`, `.initrd` and `.cmdline`. |
| **Reuse the Secure Boot DB key as the kernel module-signing key** | Different trust root, different enforcement point. Module signatures are checked against the kernel's `.builtin_trusted_keys` at `insmod` time, not by firmware at boot. They are also produced in bulk (`CONFIG_MODULE_SIG_ALL` signs thousands of in-tree modules) inside a standalone build container with no KMS reachable, so the module key is a stable operator-provisioned PEM file, not a KMS-resident key. |
| **Sign compressed modules in place, without decompressing** | The kernel decompresses a `.ko.gz`/`.ko.zst` *before* checking the appended signature, so a signature over the compressed bytes verifies against nothing. `pkg/modulesign` decompresses, signs the decompressed image, and recompresses with the same codec. `.ko.xz` returns `ErrUnsupportedCompressionCodec` rather than silently producing an unloadable module — there is no pure-Go xz codec in the module graph and an installer signer cannot shell out. |
| **Implement key storage in this repository** | go-xkms owns all hardware and cloud crypto. Every key operation here goes through `go-quicbaas/sdk/go/xkms` — `KeyProvider`, `KeyAttributes`, `ServiceKey`, `ServiceSaveCertificate`. This repo assembles envelopes (Authenticode PKCS#7, kernel CMS) around signatures produced elsewhere. |
| **Expose Secure Boot enrollment as a daemon RPC** | An RPC that writes a Platform Key writes it into *the firmware of the machine running the daemon*. Exposed remotely, that is a one-call brick primitive with no physical-presence requirement. Enrollment stays a local CLI verb with a dry-run default; only the half that is genuinely a service — signing a digest with the control-plane DB key — is on the transports (see [api.md](api.md)). |
| **A single `pkg/firmware` module covering AVR, Raspberry Pi and Android** | Not rejected — **not built**. See §8. |

## 4. Component boundaries

| Piece | Package / path | Owner |
|---|---|---|
| UEFI data structures: GUIDs, `EFI_SIGNATURE_LIST`, firmware volume and variable store parsing | `pkg/uefi/guid.go`, `esl.go`, `nvram.go`, `types.go` | this repo |
| OVMF NVRAM-file enrollment + enrollment status | `pkg/uefi/enrollment.go` | this repo |
| Live-firmware (efivarfs) enrollment, status read, verify-before-enforce gate | `pkg/uefi/efivars_enroll.go`, `efivars_status.go` | this repo |
| Raw runtime EFI variable read/write/delete/list; `TRUSTED_PLATFORM` marker | `pkg/uefi/firmware/efivars.go`, `trusted_platform.go` | this repo |
| PK/KEK/DB generation, key paths, remote DB signer, module-signing key | `pkg/secureboot/keychain.go`, `kms_signer.go`, `modulekey.go` | this repo (**keys live in go-xkms**, see below) |
| UKI construction (Go PE patcher and objcopy) and parsing | `pkg/uki/builder.go`, `builder_objcopy.go`, `parser.go`, `pe.go` | this repo |
| Authenticode PE/COFF signing, verification, certificate extraction | `pkg/authenticode/authenticode.go`, `pe.go` | this repo |
| Kernel module detached-CMS signing and compression handling | `pkg/modulesign/modulesign.go`, `cms.go`, `compress.go` | this repo |
| **Key storage and every private-key operation** | `go-quicbaas/sdk/go/xkms` → **go-xkms** | **not this repo** |
| **Certificate issuance** | the platform CA — [`docs/ca/`](../ca/) | this repo, separate feature |
| Install-time signing, enrollment and the never-brick kernel-update rebuild | `pkg/installer/installer.go`, `pkg/installer/uki_rebuild.go` — [`docs/installer/`](../installer/) | this repo, separate feature |
| Control-plane digest signing for `resign-mode: remote` | `pkg/provisioning/configdelivery/sign.go` — [`docs/provisioning/`](../provisioning/) | this repo, separate feature |
| ISO key staging (`<iso-root>/secure-boot-keys/`) | `pkg/iso/customize.go` | this repo, separate feature |
| OVMF enrollment for guest VMs | `pkg/qemu/secureboot.go` — [`docs/vtpm/`](../vtpm/) | this repo, separate feature |
| Runtime file measurement (PCR 10) | `pkg/ima/` — [`docs/ima/`](../ima/) | this repo, adjacent feature |
| Quote collection and policy evaluation over the resulting PCRs | `pkg/attestation/` — [`docs/attestation/`](../attestation/) | this repo, adjacent feature |

### The key-ownership boundary, stated precisely

**No private key is implemented here.** `secureboot.XKMSManager` constructs an
xkms backend, asks it to generate a key, and gets back a `crypto.Signer`;
`authenticode.Signer` holds an `xkmssdk.KeyProvider` and calls
`keystore.Signer(ctx, attrs).Sign(...)`; `modulesign.SignModule` takes an
injected `crypto.Signer` and never sees key bytes at all. The backend
vocabulary — `StoreSoftware`, `StorePKCS11`, `StoreTPM2`, `StoreAWSKMS`,
`StoreAzureKV`, `StoreGCPKMS`, `StoreVault` — is go-xkms's, reached through the
go-quicbaas SDK. `backendToStoreType` maps an unknown backend type to
`StoreSoftware` without an error; only `createXKMSBackend` refuses an
unsupported type.

One honest exception, marked `DEFERRED` in the code: `XKMSManager` keeps a
`rawBackend *xkmssdk.SoftwareBackend` so it can export an RSA private key to
`<keys-dir>/DB.key` when `ExportKeys` is set. That exists because the installer's
offline/`local` path needs a file key on the media. It is disabled outright in
`ResignModeRemote`. It is a boundary concession, not the model.

## 5. Data flow

### 5.1 Building and signing a boot payload

```
kernel + initramfs + cmdline
        │
        ▼  uki.NewBuilder / NewObjcopyBuilder
   systemd-stub (base PE)
        │  + .osrel .cmdline .ucode .splash .linux .initrd .dtb .sbat
        ▼
   unsigned UKI (PE/COFF)
        │
        ▼  authenticode.Signer.SignFile
   Authenticode digest ──▶ SPC content ──▶ authenticated attributes
                                                │ digest only
                                                ▼
                                    crypto.Signer  (go-xkms backend:
                                    software file, TPM 2.0, PKCS#11,
                                    cloud KMS — or the control-plane
                                    KMS over the network)
                                                │ signature
                                                ▼
   PKCS#7 SignedData embedded in the PE certificate table
        │
        ▼
   signed UKI at /boot/efi/EFI/BOOT/BOOTX64.EFI
```

Only the digest crosses the key boundary. That is what makes the same code path
work for a file key, a TPM key, and a key that lives on another machine.

### 5.2 Remote signing — the only part that crosses a host boundary

For `resign-mode: remote` the node holds no DB private key at all:

1. The node computes the Authenticode digest locally.
2. It sends `{ek_serial, mac_address, eab_key_id, eab_hmac, nonce, ek_cert, digest, key_ref}`
   to the control plane. Pre-enrollment this is
   `POST /api/v1/provisioning/sign`; post-install it goes over the node's
   IDevID-authenticated platform client to the KMS `Sign` RPC.
3. The control plane consumes the single-use nonce, validates the EAB
   credential, matches a device profile, and verifies the presented EK
   certificate against the profile binding — **all before the digest is signed**.
4. It returns the signature plus the PEM DB certificate.
5. The node embeds both in the PE.

Persisted state on that path belongs to config delivery (nonces, provisioning
sessions, device profiles), not to this feature.

### 5.3 Enforcing

```
platformctl secure-boot enroll        (dry run — writes nothing)
        │
        ├─ gate 1: efivarfs mounted?            else ErrEfivarsUnavailable
        ├─ gate 2: firmware in Setup Mode?      else ErrNotSetupMode
        ├─ gate 3: PK.crt / KEK.crt / DB.crt load and parse?
        └─ gate 4: signed UKI Authenticode-verifies AND its embedded
                   certificate == the DB certificate?   else ErrUKIVerify
        │
        ▼  --commit
   write db   (defines what firmware will accept)
   write KEK
   write PK   ◀── this, and only this, arms enforcement
        │
        ▼
   read back SetupMode / SecureBoot / PK present
```

Every gate runs on the dry run too. A dry run that passes is a commit that will
work, minus the writes.

### 5.4 What is persisted where

| Artefact | Location |
|---|---|
| PK/KEK/DB certificates (and DB key in `local` mode) | `<install-dir>/secure-boot/` — default `/etc/trusted-platform/secure-boot/` — or `<iso-root>/secure-boot-keys/` on install media |
| Keys and certificates inside the KMS | go-xkms storage (file, TPM, HSM, cloud) — not this repo |
| Enrolled `PK`/`KEK`/`db`/`dbx` | firmware NVRAM: an `OVMF_VARS.fd` file for VMs, live efivarfs on bare metal |
| Signed UKI | `/boot/efi/EFI/BOOT/BOOTX64.EFI`; previous image kept as `BOOTX64.EFI.prev` across a rebuild |
| Module-signing key | an operator path outside the repository, default `$HOME/.trusted-platform/secure-boot/module-signing-key.pem`, mode `0600` |
| `TRUSTED_PLATFORM` marker variable | firmware NVRAM under a platform-private vendor GUID |

## 6. Trust boundaries

**The Secure Boot key hierarchy is the trust boundary of the boot chain, and PCR
measurement and IMA policy are the trust boundary of everything after it.** Say
it that way round, because they fail differently: a Secure Boot failure means the
node does not run; a measurement failure means the node runs and cannot prove
what it is.

1. **PK → KEK → db.** PK is the firmware's root: it authorises KEK updates, KEK
   authorises db updates, db is the list of certificates whose signatures the
   firmware will honour on a boot image. The platform's PK and KEK are normally
   TPM-resident (`store: tpm2`) so they never leave silicon; DB is normally
   KMS-backed because it is the key that actually signs images, repeatedly, on
   every kernel update.
2. **Setup Mode is the write window.** Raw (unauthenticated) enrollment is only
   permitted while the firmware has no active PK. Both `EnrollKeysToEfivarsDir`
   and the CLI refuse with `ErrNotSetupMode` otherwise. Leaving Setup Mode is a
   one-way transition from software; getting back in requires physical or BMC
   access to the firmware setup menu.
3. **The verify-before-enforce gate is a trust boundary, not a convenience.**
   `uefi.VerifySignedUKI` compares `embedded.Raw` to `dbCert.Raw` byte for byte.
   A signature that is merely *valid* is not enough — it must be valid under the
   certificate that is about to become firmware policy.
4. **The digest boundary.** In `resign-mode: remote` the only thing that leaves
   the control plane is a signature; the only thing that reaches it is a digest
   plus an authenticated identity (EAB credential + single-use nonce + EK
   certificate). A node that has not enrolled cannot obtain a signature, and a
   replayed request fails on the nonce.
5. **PCR measurement.** Firmware measures itself and its configuration into
   PCRs 0–7 (Secure Boot state lands in PCR 7); the kernel command line, which is
   *inside* the UKI and therefore covered by the same signature, lands in PCR 9.
   Those PCRs are what [`docs/attestation/`](../attestation/) quotes and what
   LUKS keys are sealed against. This feature does not read or quote them — it
   determines what gets measured.
6. **IMA policy.** PCR 10 continues the chain into userspace runtime. The IMA
   policy that decides *what* is measured is itself installed by the same
   installer that signs the UKI, and the kernel parameters that turn it on
   (`ima=on`, `ima_policy=`, `ima_appraise=`) are embedded in the signed UKI's
   command line — so tampering with IMA configuration means re-signing the boot
   image. See [`docs/ima/architecture.md`](../ima/architecture.md).
7. **The kernel keyring is a separate root.** Module signatures chain to
   `.builtin_trusted_keys`, embedded at kernel build time from
   `CONFIG_MODULE_SIG_KEY`. UEFI Secure Boot has no say in it, and
   `CONFIG_MODULE_SIG_FORCE` has no runtime override — enforcement is a
   compile-time decision.
8. **Exported key material.** `<keys-dir>/DB.key` (mode `0600`) and the
   module-signing PEM bundle (mode `0600`) are private keys on disk. Anyone
   holding `DB.key` can sign a boot image the firmware will accept; anyone
   holding the module key can sign a kernel module that loads under
   `CONFIG_MODULE_SIG_FORCE`. Treat both as root-equivalent.
9. **Certificate verification in `pkg/authenticode` is signature verification,
   not trust verification.** `Verify` extracts the certificate embedded in the
   PKCS#7 blob and checks the signature under it. It builds no chain and consults
   no trust anchor. The binding to a trust anchor is `uefi.VerifySignedUKI`, or
   the firmware itself. See §9.

## 7. Failure posture

| Situation | Behaviour |
|---|---|
| No usable DB signing material at install | Warn, leave the UKI unsigned, continue. An unsigned UKI still boots a machine that is not enforcing. |
| `enforce: true` but firmware not in Setup Mode | Warn and skip. Never an aborted install. |
| Signed UKI fails the verify gate | Warn and skip enrollment. The node keeps booting. |
| `db` or `KEK` write fails | Abort before PK. Firmware stays in Setup Mode; the node boots unsigned. |
| PK write fails | Firmware stays in Setup Mode. Loud typed error. |
| Kernel update, DB signer unresolvable | **Hard error.** The rebuild aborts and the working UKI is left in place — the old kernel still boots. This is the one place that fails closed rather than degrading, because degrading here means an unbootable node. |
| `.ko.xz` module | `ErrUnsupportedCompressionCodec`; the file is left untouched rather than silently skipped. |

## 8. What this feature deliberately does not do

- **It does not store keys or perform private-key operations.** go-xkms does,
  through `go-quicbaas/sdk/go/xkms`.
- **It does not issue certificates.** The PK/KEK/DB certificates generated by
  `secureboot.XKMSManager` are **self-signed**, one per role, `IsCA: false`. The
  platform CA is a separate feature.
- **It does not validate certificate chains.** See §6.9 and §9.
- **It does not measure or quote.** [`docs/attestation/`](../attestation/) and
  [`docs/ima/`](../ima/) do.
- **It does not decide when to enforce.** `secure-boot.enforce` is operator
  policy; this feature only refuses to act on it when acting would be unsafe.
- **It does not offer a remote enrollment RPC.** By design — see §3.
- **It does not sign modules anywhere in the production path.** `pkg/modulesign`
  is complete and proven against OpenSSL and a real FIPS kernel, but the only
  callers today are the tests; in-tree modules are signed by the
  kernel build itself. Out-of-tree module signing is a library capability with
  no CLI verb. **PLANNED** surface.
- **It does not support embedded or mobile firmware.** No AVR, no Raspberry Pi
  OTP boot, no Android/AVB, no OTA, no ISP flashing, no `platformctl firmware`
  command group. `pkg/ota`, `pkg/avr`, `pkg/rpi` and `pkg/android` **do not
  exist**; `pkg/firmware` holds only `pkg/firmware/avr/attestation`, the AVR
  evidence verifier described in [avr-attestation.md](avr-attestation.md), with
  no sign, flash or OTA path. Everything in this
  folder's `README.md`, `rpi.md`, `android.md` and `configuration.md`
  describing those platforms is **PLANNED**, not shipped — see §9.

## 9. Where the code contradicts the legacy documents

The legacy files in this folder predate the conversion. Where they disagree with
the code, the code is right.

| Legacy claim | Reality in code |
|---|---|
| `architecture.md` (previous revision): "Firmware support is integrated into go-trusted-platform as `pkg/firmware`" with `pkg/firmware/{avr,rpi,android,signing,trust,encryption,testing}` and `pkg/ota/{avr,rpi,android}.go` | **None of those packages exist.** The shipped firmware surface is the six packages in this document's scope line, plus `pkg/firmware/avr/attestation` (AVR attestation evidence only; see [avr-attestation.md](avr-attestation.md)). |
| `README.md`: `platformctl firmware sign\|flash\|attest\|test`, `platformctl firmware android …`, `platformctl firmware ota configure`, `platformctl ota update\|status\|rollback`, `platformctl vtpm install-swtpm\|create-bundle\|deploy-bundle` | **No such verbs.** There is no `firmware` or `ota` command group; the real `platformctl vtpm` verbs are in [`docs/vtpm/cli.md`](../vtpm/cli.md). |
| `README.md`, `configuration.md`: a top-level `firmware:` config section | Does not exist. The legacy files already flag this as PROPOSED in places; treat the whole section as PLANNED. |
| `secure-boot.md`: `uefi.ReadVariable(...)` / `uefi.WriteVariable(...)` | Those functions are in **`pkg/uefi/firmware`**, not `pkg/uefi`, and their signatures differ: `firmware.ReadVariable(name, guid) ([]byte, uint32, error)`, `firmware.WriteVariable(name, guid, attrs, data) error`. |
| `secure-boot.md`, `uki.md`: `authenticode.NewSigner(&authenticode.SignerOptions{...})` | The constructor takes a context first: `authenticode.NewSigner(ctx, opts)`. |
| `secure-boot.md`: `signer.SignFile(ukiPath)` | `SignFile(inputPath, outputPath string)` — two arguments; signing in place is `SignFile(ukiPath, ukiPath)`. The output is written to a temporary file beside it and renamed over it, so a failed signing leaves the existing file untouched. The installer signs to `<uki>.signed` and renames. |
| `uki.md`: "Uses kernel's built-in EFI stub (CONFIG_EFI_STUB)"; "When `Stub` is nil, the builder uses the kernel itself as the base PE" | The opposite for the native builder. `builder.loadStub` reads the host architecture's systemd stub (`uki.StubPath(uki.HostArchitecture())`, i.e. `uki.DefaultStubPath` = `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` on x86_64) when `UKI.Stub` is nil, precisely because the kernel's own EFI stub does not read PE sections. The kernel goes into the `.linux` section. (One log line in `builder.go` still says "Kernel loaded as base PE"; the log string is stale, the behaviour is not.) |
| `uki.md`: per-architecture EFI stub paths for aarch64/arm/riscv64 | `uki.StubPath` knows the x86_64, aarch64, arm and riscv64 stubs, and the native builder picks the **host** architecture's stub when constructed. `SetArchitecture` records the target architecture and nothing else, so a cross-architecture build needs an explicit `UKI.Stub`. The objcopy builder never reads a stub at all: the kernel is its base PE, it always records `x86_64`, and it ignores `UKI.Stub`. |
| `uki.md`: `logging.NewLogger(logging.INFO)` | `logging.NewLogger(level slog.Level, ...)`. |
| `uki.md`: `types.KeyAttributes` | `xkmssdk.KeyAttributes`, from `go-quicbaas/sdk/go/xkms`. |
| Legacy files cite absolute workstation paths and an internal IP | Removed here. This folder is publication-bound; use `<install-dir>`, `$HOME`, `example.com`. |

Two code-level defects recorded here earlier are fixed (2026-09-23): verification
no longer needs a key or a certificate (`authenticode.NewVerifier`), and
`platformctl authenticode verify --cert` now requires the embedded signer to be
exactly that certificate — the same binding `uefi.VerifySignedUKI` enforces.

## 10. Related

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/ima/`](../ima/) — the runtime half of measured boot
- [`docs/attestation/`](../attestation/) — what consumes the resulting PCRs
- [`docs/daemon/api.md`](../daemon/api.md) — the transport model and the
  canonical QUIC opcode table
- [`docs/vtpm/`](../vtpm/) — Secure Boot key enrollment for guest VMs
- Legacy notes retained in this folder: [secure-boot.md](secure-boot.md),
  [uefi.md](uefi.md), [uefi-secure-boot.md](uefi-secure-boot.md),
  [uki.md](uki.md), [authenticode.md](authenticode.md), [bios.md](bios.md),
  and the PLANNED device notes [rpi.md](rpi.md), [android.md](android.md),
  plus [avr-attestation.md](avr-attestation.md) for `pkg/firmware/avr/attestation`.
  The legacy ROADMAP.md and avr.md are deleted.
