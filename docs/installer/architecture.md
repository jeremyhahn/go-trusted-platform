# Installer — Architecture

> **Status: NORMATIVE** · Scope: `pkg/installer/`, `pkg/initrd/`, `pkg/iso/`, `pkg/qemu/`, `cmd/platform-initrd` · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

A node has to arrive at a state where it will only boot software the platform
signed, and will only give up its disk encryption key to a boot chain that
measures the way the platform expects. Nothing about that state can be created
by the node itself: a machine that authors its own trust root has not been
provisioned, it has been asked politely.

Two facts make this hard, and both of them shape every decision below.

1. **The installer runs in a different measured environment than the installed
   system.** The Alpine autoinstall kernel and its initramfs extend different
   PCR values than the production Unified Kernel Image (UKI) will. A key sealed
   during installation cannot be unsealed after the first production boot.
2. **Between "disk formatted" and "key sealed to the TPM" there is a window in
   which the LUKS key must exist somewhere the machine can read without a
   TPM policy.** That window is the whole attack surface of the feature.

## 2. The shape chosen

**Two-phase provisioning with an encrypted, self-destructing carrier.**

- **Phase A — installer** (`pkg/installer`, running from the live ISO).
  Partitions, LUKS2-formats, installs the OS, builds and signs the UKI,
  generates a random 32-byte LUKS key and a recovery passphrase, and puts both
  — plus the platform config — inside a 100 MB LUKS2 container written to the
  EFI System Partition at `/boot/efi/tpm2/installer.luks`. **The TPM is not
  sealed to in this phase.** The only TPM operation the installer performs is a
  `TPM2_Clear` to remove stale hierarchy state from a previous install, and it
  skips that on a `diskless-nbd` node, whose TPM holds the IDevID its export
  attaches with.
- **Phase B — first production boot** (`pkg/firstboot`, running inside
  `platform-initrd` under the production UKI). Opens the carrier, provisions the
  TPM, seals the LUKS key against **live** production PCRs, unlocks the root,
  copies platform state onto the root filesystem, applies the recovery-key
  strategy, and then **securely wipes the carrier** — random overwrite, TRIM,
  unlink.
- **Phase C — platformd first run** (`pkg/app`). Consumes a tmpfs handoff and,
  under `recovery-key-strategy: escrow`, moves the recovery passphrase into the
  tenant secret store.

`pkg/initrd` is the strategy engine that decides *how* the root gets unlocked on
every boot after that; `pkg/iso` builds the media that carries Phase A;
`pkg/qemu` is the harness that exercises all of it under a software TPM before
any of it touches hardware.

For diskless image boots, `platform-initrd` has a second early-boot root path.
A node is diskless because its `boot_model: diskless` says so: the bootstrap
server puts `platform_boot_model=diskless` on that node's installer command
line and on no other. The installer then takes the root — hash, salt, sizes —
from the media set's signed `diskless/manifest.json` and writes it into the
UKI's `.cmdline` as `platform_roothash=`, `platform_rootfs_url=` and the rest
([kernel-cmdline.md](../reference/kernel-cmdline.md#diskless-root-parameters)).
Nothing on the live command line can name the root.

The manifest is verified only against a **pinned anchor**, never against the
key the installer is about to sign with:

- the **platform's DB certificate** where it is enrolled in the node's UEFI
  `db`, read from efivarfs (`uefi.ReadDBCertificates`) and picked by subject
  common name: the configured `secure-boot.db.cn` (default `Trusted Platform
  Secure Boot DB`), alone or followed by ` - <hostname>`. The rest of `db` — the
  vendor's and Microsoft's certificates the firmware also trusts to run boot
  code — is not an anchor; or
- the KMS-held DB certificate, fetched over the SDK when
  `secure-boot.resign-mode: remote`.

Any one anchor verifying the signature suffices. Key pairs staged on the media
(`secure-boot-keys/DB.{key,crt}`), a `file://` `secure-boot.db.key-uri`, and a
locally generated key are **never** anchors on the diskless path, so blanking
`key-uri` cannot swap in a media-staged signer. With no anchor at all — no
efivarfs, an empty `db`, and no reachable KMS — the install fails closed.

**Remaining gap: netboot trust on first use.** A node in Secure Boot setup mode
has nothing of the platform's in `db` yet, so its only anchor is the KMS
certificate. That fetch is authenticated by the CA bundle inside the installer
image, and on a netboot first install that image itself arrived over the
network before any platform key was enrolled — the firmware did not verify it
against a platform anchor. The first install of a fresh node therefore trusts
whatever the network delivered; every boot after `db` enrolment is anchored in
the firmware. Closing the gap needs the platform DB certificate enrolled before
the first netboot (factory provisioning, or HTTPS boot with a pre-enrolled TLS
CA). At boot `platform-initrd`
fetches the squashfs root and dm-verity hash tree into RAM, verifies before
mount under the pinned parameters, then overlays the read-only root with tmpfs
at `/sysroot`. This path does not unlock local LUKS root storage; mutable state
lives in platform services after `switch_root`.

**Diskless over NBD (`boot_model: diskless-nbd`, #689).** A second diskless
model, separate from `diskless` and leaving it unchanged: the node has no local
disk, and its root is a **persistent, per-device block device** that the boot
server exports over NBD on the provisioning segment (VLAN 405, `192.0.2.0/24`,
pure L2 with no gateway — [sdn configuration](../sdn/configuration.md)). The root
is NBD + LUKS + TPM (#685): the node LUKS2-encrypts its export
and seals the key to its own TPM, so the boot server stores ciphertext only.
The root is never NFS. The export is reached only over TLS 1.3 after
`NBD_OPT_STARTTLS`, and the node authenticates with its IDevID certificate,
which chains to the platform anchor. The server picks the export from that
verified identity and from nothing the client names. The server side is built
([bootstrap architecture](../bootstrap/architecture.md#nbd-export-server-diskless-nbd)).
The node side is partly built; the attach is **Planned**:

- **Built:** `bootstrap.yaml` accepts `boot_model: diskless-nbd` on a
  Raspberry Pi, and the bootstrap server puts `platform_boot_model=diskless-nbd`
  on that node's installer command line. The installer accepts that value only
  with exactly one well-formed `platform_nbd_server`; any other unknown model is
  still refused as its first step, before it clears the TPM or touches a disk.
- **Built:** the node's half of the negotiation, `nbd.Attach`: STARTTLS
  first, TLS 1.3 with the IDevID as the client certificate, `NBD_OPT_GO`, and a
  refusal is final ([installer engineering](engineering.md)). Nothing calls it
  yet.
- **Built:** the bootstrap server puts `platform_nbd_server`, the export
  server's address on the provisioning segment, on that node's installer
  command line. The node reads the address only from the signed UKI
  `.cmdline` (`nbd.ServerFromCmdline`), and builds its client configuration
  from it, the platform anchor and its IDevID (`nbd.NewClientConfig`). The
  installer reads the address; nothing calls `nbd.NewClientConfig` yet.
- **Built:** the installer target `nbd`. A `diskless-nbd` install runs Phase A
  against `/dev/nbd0` instead of the configured disk, with the same partition,
  LUKS2 and LVM steps a disk install uses. It refuses, before the TPM clear or
  any format, an `nbd0` that is missing or not attached to an export, and a
  configuration without `disk.encryption`. Partition 1 of the export is the
  **metadata area** that holds the sealed key and the PCR banks
  ([installer engineering](engineering.md#the-nbd-metadata-area)). The UKI it
  builds signs `platform_boot_model=diskless-nbd` and `platform_nbd_server`
  and no local root, LUKS or LVM device. The installer always writes the export
  as GPT, whatever the profile's local-disk table, because the boot server
  reads it. The live environment's `autoinstall.sh` targets `/dev/nbd0` on this
  model and scans no local disk, and the install leaves the TPM alone: a
  TPM2_Clear would evict the IDevID key the export attaches with.
- **Built:** the installer enrols, then attaches (#883 Q2). Every node except
  the first enrols the same way on every architecture and boot model: ACME
  `enroll-01` or `endorse-01` through the go-quicbaas SDK client that
  `platformd` runs on a disk node's first boot. There is no second path. A
  `diskless-nbd` install calls that client through one seam before the TPM
  clear, before it uses the export and before any disk. A failed enrollment is
  its own refusal and changes no disk
  ([installer engineering](engineering.md#enrolling-before-the-attach)).
- **Planned:** the live environment supplying that enrollment client. It runs
  inside `platformd`'s first-boot provisioning, whose TPM PINs and datastore
  belong on the export the node cannot attach until it enrols. Until then a
  `diskless-nbd` install is refused at enrollment.
- **Built:** the boot after the install. Once the export's metadata area holds
  the UKI, the node's device script boots that UKI instead of the installer;
  the bootstrap server reads it from the volume file and serves it
  ([bootstrap engineering](../bootstrap/engineering.md#the-diskless-nbd-runtime-path)).
  The UKI then needs the `platform-initrd` attach below.
- **Planned:** where the node takes the platform anchor from before the export
  is attached; the image's CA bundle lives on the root filesystem, which for
  this model is the export. The IDevID is the one its enrollment put in its
  TPM.
- **Planned:** `platform-initrd` attaches the export before the unlock chain
  runs, then unlocks it like a local LUKS root. The live environment needs the
  same attach before `platformctl install system` runs, from the same code,
  after the node enrols; the installer reads the attachment and never makes
  it. Until then the installer refuses the install, before anything destructive
  ([installer engineering](engineering.md#attaching-before-the-install)).

## 3. Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| **Seal the LUKS key to the TPM during installation** | The installer measures a different boot chain than the installed system. Every sealed blob would fail `TPM2_Unseal` with a policy error on the first production boot. This is the single constraint the two-phase design exists to satisfy. |
| **Write the LUKS key as a plain file on the ESP for one boot** | An earlier revision did exactly this. A FAT32 ESP on an SSD leaves copies in spare blocks that wear-levelling never overwrites, so `rm` does not remove the key — it removes the directory entry. The key now lives only inside a LUKS2 container whose header is destroyed on wipe, so the residue is high-entropy ciphertext with no header to decrypt it. |
| **Give the installer container a secret password** | It could not be one. The machine has to open it unattended, before any TPM policy exists, so any password must be derivable on the node — which makes it not a secret. The container's job is **forensic protection, not access control**, and the password is the exported constant `installer.InstallerPassword` (`"forensic-protection-only"`) precisely so nobody mistakes it for a security control. |
| **Keep the recovery passphrase forever, unconditionally** | A permanently-valid passphrase slot defeats the TPM binding for anyone who can reach the header. |
| **Destroy the recovery passphrase always** | A node whose TPM state becomes unusable — firmware update, board swap, hierarchy auth drift — is then unrecoverable. The default is `escrow`: the slot survives and the passphrase moves into the tenant secret store, where it is subject to an ACL. `destroy` remains available for kiosk and unattended fleets. |
| **`TPM2_Clear` on every first boot, unconditionally** | Destructive operations must be opt-in. `factory-reset-on-firstboot` defaults to `false` in Go and `true` in the reference templates, so the library never silently destroys hierarchy state an operator meant to keep. See [factory-reset.md](factory-reset.md). |
| **Skip the software `TPM2_Clear` and always use UEFI PPI** | PPI requires a reboot and, on some firmware, an operator at the BIOS screen. The software clear is tried first; PPI escalation is opt-in via `force-clear-via-ppi` and loop-guarded by an ESP marker so a firmware that ignores the request cannot produce a reboot loop. |
| **A single "unlock" function with an if/else ladder** | The failure modes are unrelated to each other — a stopped daemon, a stale PCR set, a missing security key, a user at a prompt. Unlock is a **priority-ordered chain of `UnlockStrategy` implementations** (`pkg/initrd/strategy.go`), each of which answers `CanUnlock` before it is asked to `Unlock`, so a strategy that does not apply is skipped rather than failed. |
| **Ship one boot binary** | `platform-initrd` must fit in an initramfs, link statically, and run before networking exists. It carries exactly two verbs — `boot` and `recovery` — and delegates everything post-`switch_root` to `platformctl`. |
| **Mirror initrd stderr onto the serial port in userspace** | Tried and removed. A goroutine copying `os.Stderr` to `/dev/ttyS0` blocked on the device under serial flow control, filled the pipe, and deadlocked every subsequent write — the binary froze with no output and dracut timed out into an emergency shell. The kernel cmdline routes the console to the BMC serial channel already; the userspace tee was pure risk. The history is recorded at the top of `cmd/platform-initrd/main.go` so nobody reintroduces it. |
| **Build the ISO from a shell script** | ISO production has to be reproducible and testable. `pkg/iso` drives download, extract, customise and build in Go with typed errors, and `pkg/qemu` runs the resulting image under swtpm and OVMF in CI. |

## 4. Component boundaries

| Piece | Package / path | Owner |
|---|---|---|
| Install orchestration — partition, LUKS, OS, UKI, Secure Boot, firstboot service | `pkg/installer/installer.go` | this repo |
| Boot firmware seam (`uefi`: NVRAM entry + efivars enrolment; `uboot`: staged firmware tree on the ESP, keys preseeded) and the image-target skip list | `pkg/installer/boot_firmware.go` | this repo |
| Configuration model and validation | `pkg/installer/types.go`, `config.go`, `config_loader.go`, `config_generator.go` | this repo |
| Built-in profiles (`dev`, `production`, `production-hs`, `fips`) | `pkg/installer/profiles.go` + embedded `pkg/installer/profiles/*.yaml` | this repo |
| Disk / LVM / LUKS operations | `pkg/installer/disk.go` | this repo |
| OS-specific install (Alpine, APK, FIPS kernel) | `pkg/installer/os.go`, `alpine.go`, `pkg/installer/alpine/` | this repo |
| UKI build and post-kernel-update rebuild | `pkg/installer/uki.go`, `dracut_builder.go`, `uki_rebuild.go`, `kernel_hook.go` | this repo |
| Remote Secure Boot DB signing client | `pkg/installer/remote_sign_client.go` | this repo |
| FIDO2 enrolment / unlock at install time | `pkg/installer/fido2_enroll.go`, `fido2_unlock.go` | this repo |
| Boot-time unlock strategy engine | `pkg/initrd/` | this repo |
| `platform-initrd` verbs | `cmd/platform-initrd`, `pkg/boot/commands/` | this repo |
| First-boot seal, wipe, recovery-key strategy | `pkg/firstboot/` | this repo, adjacent feature |
| ISO production | `pkg/iso/` | this repo |
| QEMU + swtpm test harness | `pkg/qemu/`, `pkg/swtpm/` | this repo |
| **LUKS2 primitives** (`AddKey`, `KillSlot`, `Lock`, `Wipe`, `GetVolumeInfo`) | `go-luks2` | **not this repo** |
| **TPM operations** (`NewTPM2`, `Clear`, `ForceClear`, seal/unseal) | reached through `go-quicbaas/sdk/go/xkms` | **not this repo** |
| **FIDO2 / CTAP2** | reached through `go-quicbaas/sdk/go/xkms/fido2` | **not this repo** |
| **Vendor quirks** (serial console, earlycon, kernel modules) | `pkg/quirks` | this repo, separate feature |
| **Network boot / PXE** | `pkg/ipxe/` — [`docs/ipxe/`](../ipxe/) | this repo, separate feature |
| **NBD export server for `diskless-nbd` roots** | `pkg/bootstrap/nbd/` — [`docs/bootstrap/`](../bootstrap/) | this repo, separate feature |
| **Provisioning state machine, config delivery, remote digest signing service** | `pkg/compute/pxe/`, config-delivery — [`docs/provisioning/`](../provisioning/) | this repo, separate feature |

**SDK edge.** Every cryptographic operation the installer performs against a
TPM, a KMS, or a FIDO2 authenticator is consumed through the
`go-quicbaas/sdk/go` re-export, never by importing a lower layer directly.
`pkg/initrd` imports `go-quicbaas/sdk/go/xkms` and
`go-quicbaas/sdk/go/xkms/fido2`; `pkg/installer` imports
`go-quicbaas/sdk/go/xkms`. The LUKS2 on-disk format library (`go-luks2`) is an
ordinary Layer 0 library, not a stack SDK edge.

## 5. Data flow

### Phase A — installation

```
platformctl install system  (running from the live ISO)
   │
   ├─ 1. clearTPM()                 TPM2_Clear via LOCKOUT hierarchy.
   │                                 On TPM_RC_LOCKOUT → ForceClear (UEFI PPI)
   │                                 + HardReset() so firmware services it.
   │                                 Failure is non-fatal: a VM has no TPM.
   ├─ 2. setupDisk()                GPT → EFI partition (538 MB default) →
   │                                 root partition → LUKS2 → LVM (vg0/root)
   │                                 or ext4 → mount /mnt and /mnt/boot/efi
   ├─ 3. installOS()                base system, fstab/crypttab, kernel,
   │                                 root password, packages, network,
   │                                 post-install script (FATAL on failure)
   ├─ 4. FIPS kernel                (phase 1 only — OpenSSL config comes later)
   ├─ 5. install platform-initrd    into the dracut module. CRITICAL: without
   │                                 this the installed system cannot unlock.
   ├─ 6. buildUKI()                 dracut → UKI; cmdline carries root=,
   │                                 rd.luks.uuid=, rd.luks.name=, rd.lvm.*,
   │                                 lockdown=, and pkg/quirks console args
   ├─ 7. signUKI()                  Secure Boot DB signature. resign-mode
   │                                 remote → digest only leaves the node
   ├─ 8. configureUEFIBoot()        boot entry (best effort)
   ├─ 9. enforceSecureBoot()        db → KEK → PK, **PK written last**, and
   │                                 only if the signed UKI verifies against
   │                                 the db cert AND firmware is in Setup Mode
   ├─10. kernel-update hook         so a future kernel upgrade re-signs
   ├─11. FIPS OpenSSL config        (phase 2 — after signing, which FIPS breaks)
   ├─12. prepareLUKSKeyForTPM()     32-byte random key → LUKS slot 1
   │                                 recovery passphrase → LUKS slot 2
   │                                 both + config.yaml → installer.luks
   ├─13. firstboot service          fallback only; the primary path is initramfs
   ├─14. FIDO2 enrolment            explicit, or auto if a device is present
   └─15. flush, unmount, close LUKS, verify the LUKS header magic survived
```

**Step 15 fails the install; it does not warn and carry on.** The completion
path is the last place the installer can still tell anyone something went
wrong — after it, the next signal is a machine that does not POST into an
operating system. Three conditions end the install there:

| condition | why it is fatal |
|---|---|
| the UKI (`BOOTX64.EFI`; `BOOTAA64.EFI` on aarch64) absent from, or empty on, the ESP | the file firmware loads is not there; the machine cannot boot |
| `blockdev --flushbufs` **refused** by a device | the device rejected the flush, so writes may not be durable |
| a mount point survives both a regular and a lazy unmount | it is still attached and unflushed at reboot; on FAT32 that is how a written UKI fails to be a readable one |

Two deliberate non-failures, because too strict is its own outage:

- **`blockdev` missing or not executable.** Nothing was attempted, and the
  preceding `unix.Sync()` already blocked until writeback completed. Failing
  here would turn an absent optional tool into a failed install on hardware
  where the install worked.
- **A lazy unmount that succeeds after a regular one fails.** `MNT_DETACH`
  detaches the tree and completes teardown when the last reference goes; that
  is a legitimate outcome, not a degraded one.

The UKI is fsynced as a **file and then its parent directory**, matching
`pkg/installer/uki_rebuild.go`. Fsyncing the mount point alone flushes
directory metadata, not the UKI's contents.

### Phase B — first production boot

```
UEFI → signed UKI → dracut hook → platform-initrd boot --device ... 
   │
   ├─ tryMountInstaller()  opens installer.luks and mounts /mnt/installer,
   │                       because on the first boot the PCR set and the
   │                       platform config only exist inside the container
   ├─ PCR selection        --pcrs flag  >  /boot/efi/tpm2/pcr-banks
   │                                    >  config.yaml inside the container
   └─ StrategyChain.Execute()
          Keyfile (80) reads /mnt/installer/luks-key.bin and unlocks
   ⇒ pkg/firstboot: provision TPM, seal to live PCRs, write
     seal-platform.pub/.priv to the ESP, apply recovery-key-strategy,
     secure-wipe installer.luks (only if sealing succeeded)
   ⇒ switch_root
```

**First provision, the EK and recovery.** This is the
contract, and firstboot implements it (`pkg/firstboot/firstprovision.go`; the
SO PIN bullet is [TPM engineering](../tpm/engineering.md) §4 item 5).

- **First provision.** A fresh TPM with a valid EK and no sealed object on the
  ESP (no `tpm2/seal-platform.pub`) is first provision: firstboot provisions the
  TPM and seals, and only then does the node serve. The installer's
  `tpm2/pcr-banks` is not a seal and never makes a boot look provisioned.
- **EK certificate.** Before it touches the TPM, firstboot reads the EK
  certificate through the SDK (`EKCertificate`: the NV index, the certificate
  store, then the manufacturer's service). A TPM without one is refused with
  `EKCertificateMissingError`, and the boot drops to the seal-retry path
  below, unless the admin relaxed the EK requirement with
  `disk.encryption.tpm.allow-missing-ek-certificate: true`
  ([docs/device-templates.md](../device-templates.md)). The default is
  `false`: the certificate is required. A relaxed TPM is provisioned without an
  IDevID, and firstboot logs a warning that names the setting. A lookup that
  fails for another reason is refused either way. This is separate from
  `RequireEKMatch` in `pkg/provisioning/configdelivery`, which governs only the
  control plane's match against a prestaged EK certificate.
- **Recovery** means a seal that existed and broke. A TPM that never held a
  seal is first provision, never recovery.
- **SO PIN.** firstboot sets the owner hierarchy auth to the SO PIN with
  `TPM2_HierarchyChangeAuth` (TPM 2.0 Part 3 §24.8) and hands the PIN to
  `platformd` over the firstboot tmpfs handoff
  (`/run/platform/firstboot-handoff/`), at the kms path the config names for it
  (`platform.so-pin`, [docs/device-templates.md](../device-templates.md)
  "Platform PINs"). The hierarchy auth is no longer left empty. The keys are
  created under the empty owner auth and ownership is taken last, so no
  device leaves firstboot with an empty owner auth; a TPM a previous install
  owned is re-provisioned only after the configured SO PIN is proven.

A diskless node takes neither path. Its signed command line carries
`platform_boot_model=diskless` and no `root=` or `rd.luks.*`, so the dracut
cmdline hook gives dracut a root that names no device, the unlock hook runs
`platform-initrd boot --diskless` instead of `--device`, and the finished and
mount hooks wait only for the verified overlay at `/sysroot`. After
`switch_root` nothing is sealed: the `tpm-firstboot-seal` service reads the
same selector and exits before its LUKS lookup, and `platformd` adopts a
TPM that holds the node's identity or provisions an empty one once. On every
boot after the first, `platformd` recovers the identity certificates the
tmpfs lost from the control plane, over an mTLS connection authenticated by
the TPM-resident IDevID and an IAK quote bound to that connection
([docs/tpm/architecture.md §4d](../tpm/architecture.md)). The image therefore
carries the control plane's address (`acme.client.directory-url`) and, unless
the OS trust store already anchors it, its CA as `ca-bundle.pem`.

A `diskless-nbd` node takes the disk path once its export is attached; the
attach is **Planned**. Before the unlock chain runs, `platform-initrd` reaches the boot server's NBD listener on the
provisioning segment and negotiates fixed newstyle. Its first option is
`NBD_OPT_STARTTLS`; it completes TLS 1.3 with its TPM-resident IDevID as the
client certificate and verifies the server against the platform anchor. It then
asks for the default export with `NBD_OPT_GO` and attaches the result as a
block device. From there the unlock chain treats the device as the LUKS root:
`/dev/nbd0p2` is the LUKS2 root and `/dev/nbd0p1`, the metadata area, holds
`tpm2/installer.luks` for the first boot and the seal afterwards.

### Steady state

```
UEFI → signed UKI → platform-initrd boot
   └─ StrategyChain.Execute()
        TPM-PCR (1)      unseal under the Platform KeyStore SRK, PCR policy
        TPM-Upgrade (2)  looks for seal-upgrade.* on the ESP; nothing
                         writes them in production, so it declines
        FIDO2 (3)        user touches the key
        Password (100)   operator types the LUKS passphrase
```

**What is persisted, and where.** The installed root filesystem holds the OS
and, after Phase B, the platform state. The **ESP holds every artefact the
machine needs before the root is readable**: the UKI, `tpm2/pcr-banks`,
`tpm2/seal-platform.pub` / `.priv`, and — for one boot only —
`tpm2/installer.luks`. No upgrade seal (`tpm2/seal-upgrade.*`) is
written: its only writer, `pkg/firstboot/executor.go:763-774`, is reached
only from `Executor.Run`, which nothing calls.
A `diskless-nbd` node keeps the same artefacts in the same layout on
partition 1 of its NBD export, the metadata area, which it mounts at
`/boot/efi` by path (`/dev/nbd0p1`), never by the `EFI` label; the boot server
stores that partition and the LUKS2 ciphertext beside it, and holds no key.
Apart from those export blocks, nothing crosses a host boundary during Phase A
or B except the Secure Boot
digest under `resign-mode: remote`, which travels to the control plane and
returns as a signature.

## 6. Trust boundaries

The installer is where a machine decides what it will trust for the rest of its
life. Six boundaries, in the order they are crossed.

1. **Install media → machine.** The ISO carries the platform binary, the
   platform config, the Secure Boot keys or key references, and the autoinstall
   script. **Anyone who can substitute the ISO owns the resulting node.** The
   media is the root of the whole chain; distribute it over a channel you
   trust, and prefer `--pre-fetch` (the default — but see the FIPS caveat in
   [cli.md](cli.md#pre-fetch-is-unavailable-in-a-fips-build)) so the install does not also
   depend on a package mirror reached at install time.
2. **Machine → Secure Boot keys.** `enforceSecureBoot` enrolls db, then KEK,
   then PK, in that order and only when the signed UKI provably verifies
   against the db certificate and the firmware is in Setup Mode. **PK is
   written last on purpose**: writing PK first closes Setup Mode and a failure
   after that point strands the node. Under `resign-mode: remote` the DB
   private key never reaches the node at all — only a digest leaves and only a
   signature returns.
3. **The installer container.** For one boot, `installer.luks` holds the LUKS
   key, the recovery passphrase, and the platform config, behind a password
   that is a compiled-in constant. **Treat the ESP of a machine between
   installation and first boot as holding the disk encryption key.** The window
   closes when Phase B wipes the container — and the wipe only runs *if sealing
   succeeded*, so a machine whose first boot half-failed is still inside the
   window.
4. **PCR policy.** After Phase B the LUKS key is sealed under a PCR policy. Any
   change to firmware, Secure Boot state, kernel command line, or IMA
   measurements invalidates the seal — that is the control working, and it is
   also why a firmware update looks like a break-in. Nothing carries a kernel
   change across today. `TPM-Upgrade` reads a non-PCR upgrade seal, but no
   production path writes one (§5, *Steady state*), so it declines
   (`pkg/initrd/strategy_tpm_upgrade.go:117-118`). The kernel-update hook
   rebuilds and re-signs the UKI (`pkg/installer/uki_rebuild.go:269-273`)
   and does not re-seal. A change that moves the bound PCRs
   therefore ends at the `Password` prompt, and after it platformd refuses to
   start with `ErrTPMSealPolicyDrift` (`pkg/app/tpm_seal_guard.go:214`); see
   [engineering.md §5](engineering.md#5-unlock-strategy-table--as-the-code-registers-it).
   *Planned, not implemented (go-xkms #1443):* `TPM-Upgrade` stays; upgraded
   images are built and signed centrally and staged, and the on-device dracut
   rebuild is not the upgrade path; the bound PCR set becomes configurable per
   board, default 7 and 11; the upgrade seal gets a named policy approved for
   the predicted PCR values.
5. **The recovery passphrase.** `escrow` moves it into the tenant secret store
   at `tenants/{tenant}/nodes/{node}/secrets/luks/recovery`, where an ACL
   governs it; `destroy` removes the keyslot and makes the TPM seal the only
   unlock path. Choosing `destroy` is choosing to have no break-glass.
6. **The NBD root (`diskless-nbd`).** The root's ciphertext lives on the boot
   server and crosses the provisioning segment on every read and write. TLS
   protects it on the wire. The IDevID decides which export a node can open:
   with no certificate, an untrusted one, or a request for another device's
   export, the server refuses before any data is served. LUKS, with its key
   sealed to the node's TPM, protects it at rest from the boot server itself.
   Whoever holds the boot server holds every node's ciphertext and can deny
   service, but cannot read a root.

## 7. What this feature deliberately does not do

- **It does not seal anything to the TPM during installation.** Sealing is
  Phase B's job and cannot be moved earlier. §1.
- **It does not decide which machine gets installed.** Device identity,
  authorisation and quarantine belong to provisioning
  ([`docs/provisioning/`](../provisioning/)).
- **It does not serve the network boot.** DHCP, TFTP and the iPXE chain are
  [`docs/ipxe/`](../ipxe/).
- **It does not issue certificates.** The CA does ([`docs/ca/`](../ca/)); the
  installer consumes an EAB credential and a control-plane URL.
- **It does not own the LUKS2 format.** `go-luks2` does.
- **It does not have a platform API.** There is no `/api/v1/install`, no
  `/api/v1/iso`, no installer gRPC service, no QUIC opcode and no MCP tool —
  verified by grep, 2026-08-18. Installation is CLI and embedded-Go only, by
  design: it runs on media, before the node has an identity to authenticate
  with. See [api.md](api.md), which records this as a decision rather than a
  gap, and records the four `platformctl iso` verbs that *are* stubs.
- **It does not manage the running system.** Everything after `switch_root` is
  `platformctl`, not `platform-initrd`.

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [factory-reset.md](factory-reset.md) — the `TPM2_Clear` and recovery-key
  decision, with the full wire path. Verified accurate against code.
- [autoinstall.md](autoinstall.md), [iso-building.md](iso-building.md),
  [provisioning-client.md](provisioning-client.md), [qemu-testing.md](qemu-testing.md)
  — pre-convention documents kept for their detail.
  **Where they disagree with the five files, the five files win**; the specific
  corrections are listed in [engineering.md](engineering.md) §10.
- SECURITY_MODEL.md, UNLOCK_STRATEGIES.md, initrd-overview.md,
  initrd-architecture.md and README.md are deleted. These five files hold their
  content.
- [`docs/ipxe/`](../ipxe/) · [`docs/provisioning/`](../provisioning/) ·
  [`docs/daemon/api.md`](../daemon/api.md)
