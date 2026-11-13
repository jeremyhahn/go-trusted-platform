# Factory Image — Architecture

> **Status: NORMATIVE** · Scope: `pkg/diskimage/` (`rpi`, `qemuvirt`, `uboot`, `runner`, `virtkernel`, `netboot`, `artifacts`, `fatimage`, `diskimagetest`), `pkg/disklessroot/`, `pkg/cli/commands/diskimage/`, `build/docker/uboot-builder/`, `build/docker/diskimage-builder/` · Last verified: 2026-09-16
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

The installer ([`docs/installer/`](../installer/architecture.md)) runs on the
machine it installs: boot the ISO, and Phase A partitions the disk and lays the
platform down on the hardware that will run it. A Raspberry Pi cannot be
provisioned that way. It has no UEFI firmware to boot an ISO, no BMC, and no
disk other than the SD card the operator writes before the first power-on.
What such a device needs is a **factory image**: a complete, encrypted,
signed-boot platform install on a card, produced somewhere else, that turns
into a provisioned node the first time it boots.

Three facts shape the design:

1. **The build host is not the node.** Its TPM, its security keys and its
   kernel command line have nothing to do with the device the image is for.
   Everything the installer normally learns from the machine it runs on must
   instead come from the image's configuration.
2. **The Pi has no UEFI and no Secure Boot of its own.** The boot chain,
   measured boot and Secure Boot verification the platform depends on have to
   be brought along on the card.
3. **An image is copied.** Whatever secret the installer leaves on the media
   for the first boot is in every copy of the image, so the image has to be
   built so that one image is good for exactly one device.

## 2. The shape chosen

**Run the unchanged installer Phase A on the build host, inside a container of
the target architecture, against a loop-mounted image file; leave Phase B to
the device.**

- **Phase A — on the build host** (`pkg/diskimage`). `Create` stages the
  install media exactly as `platformctl iso create` does (`pkg/iso`'s
  `StageInstallMedia`: pre-fetched apk repository for the target architecture,
  platform binaries, the baked platform config, Secure Boot keys, CA bundle),
  adds the target's boot firmware, then starts an Alpine container
  (`build/docker/diskimage-builder`) **at the host platform** (`linux/<host
  GOARCH>`, not the target's) with `--privileged` but its own private
  `/dev`, the media copied in at `/media/cdrom` and the image copied out of
  `/work` (`runner.Container`: create, copy in, start, copy out; no bind
  mounts, because the docker daemon may not share the build's filesystem).
  Under qemu-user there are no keyring syscalls, so go-luks2 cannot open the
  LUKS volume in a foreign-architecture container (#802): partitioning, LUKS
  and mkfs therefore run natively, and only the target-chroot steps (apk,
  dracut, depmod) run under binfmt. For a foreign target the installer is the
  host-architecture `platformctl-static` (`BuildConfig.HostInstallerBinary`,
  copied in at `/installer`; the media's target-architecture one is what the
  image carries); for a native target it is the media's. Inside it, `platformctl-static diskimage
  assemble --platform-config /media/cdrom/configs/installer.yaml` creates a
  sparse image, takes a free loop device from `/dev/loop-control` (creating
  its node when the private `/dev` lacks it), attaches the image with
  `losetup --partscan`, points
  `pkg/installer` at the loop device with the install target set to `image`,
  and the installer does what it always does: partition table, LUKS2 root with
  LVM inside, Alpine root, dracut and the UKI, the boot firmware onto the EFI
  partition, and `tpm2/installer.luks` for the first boot. The baked platform
  config is converted through the app layer (`app.App.GetInstallerConfig`)
  the same way the live ISO installer converts it.
- **Phase B — on the device** is unchanged from
  [`docs/installer/architecture.md` §5](../installer/architecture.md#5-data-flow):
  `platform-initrd` opens `installer.luks`, `pkg/firstboot` provisions the
  TPM, seals the LUKS key to the live PCRs, wipes the container, and
  `platformd` enrols. Nothing in this feature runs on the device.

A `Target` supplies only what differs per device: architecture, kernel
package, extra packages, installer overrides, the U-Boot board and the files
that go onto the EFI partition. Two targets exist: `rpi` (the SD-card image)
and `qemu-virt` (the same pipeline on the QEMU `virt` machine, so it can be
exercised under a software TPM before it touches a Pi).

### The boot chain on the Raspberry Pi

```
VideoCore firmware (start4.elf / fixup4.dat; bootcode.bin on older boards;
                    the Pi 5 bootloader EEPROM loads kernel8.img directly)
  └─ config.txt: kernel=kernel8.img, dtoverlay=tpm-soft-spi, dtoverlay=disable-bt
       └─ U-Boot (kernel8.img) — EFI_TCG2_PROTOCOL measured boot, EFI Secure Boot
            └─ EFI boot manager finds EFI/BOOT/BOOTAA64.EFI on the first FAT partition
                 └─ the signed UKI (systemd-stub) → LoadImage of the signed kernel inside it
                      └─ platform-initrd → firstboot → platformd
```

Two images are authenticated, not one. systemd-stub does not jump into the
kernel it carries; it hands the `.linux` section to the firmware's
`LoadImage`, and U-Boot verifies that image against `db` exactly as it
verified the UKI. EDK2 firmware would let the stub install a Security-Arch
override that trusts the already-verified stub's payload; U-Boot has no such
protocol. The installer therefore signs the kernel with the DB key before
the PE builder wraps it (`bootFirmware.VerifiesEmbeddedKernel`,
[installer engineering.md](../installer/engineering.md) invariant 17); the
x86 UKI is unchanged.

U-Boot is built by `build/docker/uboot-builder` from a pinned upstream release
with the platform's PK/KEK/db **preseeded into the binary**: with
`EFI_SECURE_BOOT` on, U-Boot refuses to restore authenticated variables from
`ubootefi.var` on the ESP, because a file on an unauthenticated FAT partition
cannot be the root of trust for its own verification. A Secure Boot key set
therefore implies a U-Boot build, cached by the digests of its inputs.

The certificates U-Boot preseeds come from `iso.ResolveSecureBootMaterial`,
which reads the platform config's `secure-boot` references: a `kms://`
reference is fetched from the control plane's CA through the operator's
platform client (the private key stays in the KMS), a media `file://`
reference or none is read from `--keys-dir`. The resolved `PK.crt`, `KEK.crt`
and `DB.crt` land in `<work-dir>/secure-boot-certs` and are what the U-Boot
build mounts — so a fleet whose DB key lives in the KMS gets a U-Boot whose db
is that key's certificate.

The TPM is an Infineon SLB9670 on SPI0 CE1. Mainline U-Boot has no BCM2835
SPI driver, so the bus is bit-banged over GPIO (`SOFT_SPI` + `TPM2_TIS_SPI`)
as described by the platform's `tpm-soft-spi` overlay; Linux binds the same
node with `spi-gpio` + `tpm_tis_spi`, so one overlay serves both stages. The
kernel's `tpm-slb9670` overlay (hardware SPI0) is **not** applied.

What is measured: PCR 0 receives only U-Boot's version string
(`EV_S_CRTM_VERSION`) — the VideoCore firmware measures nothing; PCRs 1
(boot variables), 2 (drivers), 4 (the UKI), 5 (ExitBootServices) and 7 (the
Secure Boot variables and the db entry that verified the image) by U-Boot;
PCR 9 (the initrd) by the Linux EFI stub. DTB measurement is off: U-Boot
rewrites `/chosen/kaslr-seed` every boot, so a policy over it would never
unseal.

### The image

An MBR partition table, because that is what the Pi firmware reads:

| Partition | Content |
|---|---|
| `p1` FAT32, the EFI system partition | U-Boot as `kernel8.img`, `config.txt`, the firmware blobs (`start*.elf`, `fixup*.dat`, `bootcode.bin`) from the `raspberrypi-bootloader` packages, every supported board DTB from `linux-rpi`, `overlays/tpm-soft-spi.dtbo` and `overlays/disable-bt.dtbo`, `EFI/BOOT/BOOTAA64.EFI` (the UKI), `tpm2/installer.luks`, `EFI/TRUSTED_PLATFORM/PROVISIONED`; `ubootefi.var` is written by U-Boot at runtime |
| `p2` LUKS2 | the root, with LVM inside, exactly as the ISO lays it out |

All board device trees are staged, so one image boots any supported model;
`--model` selects the description baked into the config and the DTB whose
presence the build verifies. The kernel is `linux-rpi` for `rpi` and
`linux-virt` for `qemu-virt` (the Pi kernel carries no virtio) — a kernel the
platform builds, next section.

### The stand-in's kernel

The QEMU virt image boots a kernel the platform builds
(`build/docker/virt-kernel-builder`, `pkg/diskimage/virtkernel`), not an
Alpine package. QEMU's only TPM front-end for the virt machine is the
memory-mapped `tpm-tis-device`, and no Alpine aarch64 kernel carries the
memory-mapped TIS driver (`CONFIG_TCG_TIS` is unset in `linux-lts` and
`linux-rpi`; `linux-virt` has no TPM support), so a stock kernel would boot
to platform-initrd and find no `/dev/tpm0`. The built
kernel is Alpine's `linux-lts` version with the TIS and CRB drivers built
in, signed modules and the lockdown LSM; it is installed from the media
(`os.kernel-artifacts-dir`, verified against its `SHA256SUMS`) under the
`linux-virt` flavour name, so `vmlinuz-virt` and `/lib/modules/<release>`
look like a packaged kernel to everything downstream. The Raspberry Pi
image keeps Alpine's `linux-rpi`, whose SPI transport is what the SLB9670
needs. The stand-in uses a platform-built kernel, not an out-of-tree module
(which would need lockdown off) and not hardware-only firstboot testing.

### The diskless root image

A diskless node boots the same operating system a disk install writes, so
the diskless root is that install: `diskimage netboot --diskless` runs the
installer onto a scratch image inside the builder container
(`pkg/diskimage/runner.Container`, the staged media copied in, the artifacts
copied out, no bind mounts), and packs the installed root partition into
`rootfs.squashfs` plus its dm-verity hash tree `rootfs.verity`. Both are
served over HTTP beside the set's kernel; neither is trusted for what it is.

The root is public — every node that boots the set fetches it, and so can
anyone who can reach the boot server — so it must hold no private key and no
reusable credential. The build locks every shadow entry (the installer writes a
root password) and refuses a root with a usable hash; `--debug` is rejected for
a diskless build because it would enable SSH root login in the shared root.
The installer also copies the platform config to
`/etc/trusted-platform/config.yaml`, and the build refuses the root, naming
each field, if any field the config schema tags `secret:"true"` (root
password, BMC password and IPMI key, PKCS#11 SO and user PINs, switch and disk
encryption passwords, …) holds a literal instead of a secret reference
(`kms://`, `env://`, `file://`, …). It refuses rather than strips: a stripped
config would ship a node that fails later, far from the cause, while the
reference is already the supported way to write the field.
Per-node credentials come after attestation, from the TPM-resident identity,
never from the image. The
in-container install runs with Secure Boot off: it signs nothing the root
carries (the UKI is on the ESP, which is not packed), and with Secure Boot on
the installer would generate a DB key onto the very root it publishes. Before
`mksquashfs` the build walks the installed tree and refuses, naming the path,
any `*.key` file, any PEM block of a `PRIVATE KEY` type anywhere in a file,
and any small file that parses as a DER PKCS#8, PKCS#1 or SEC 1 key. A node's
own keys live in its TPM and in the tmpfs overlay, never in the image.

The root's identity — root hash, salt and the two sizes — is a manifest
(`cdrom/diskless/manifest.json`) signed with the Secure Boot DB key, carried
to the installer in the install media. The installer verifies it against a
pinned anchor — the platform's DB certificate enrolled in the node's UEFI `db` (not any other `db` entry) or the KMS-held
DB certificate, never a key pair staged on the media (see
[installer architecture](../installer/architecture.md) for the first-netboot
trust gap) — and writes the root parameters into the UKI command line it
signs; nothing on the network-supplied command line or iPXE script can name
a root. `platform-initrd` fetches both artifacts into bounded RAM, opens
dm-verity with the pinned parameters before any mount, mounts the verified
squashfs read-only under a tmpfs overlay, and fails before mounting root on
any mismatch.

The build is reproducible: `mksquashfs -reproducible` with every timestamp
set to `SOURCE_DATE_EPOCH`, and the verity salt derived from
`SOURCE_DATE_EPOCH` and the platform version, so the same inputs give the
same root hash.

## 3. Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| **A separate image-building installer** | It would duplicate partitioning, LUKS, the OS install and the UKI, and drift. The installer gained two seams instead — a boot-firmware dispatch (`uefi` / `uboot`) and an install target (`disk` / `image`) that skips the host-only steps — and the image builder runs the same code the ISO runs. |
| **Cross-install from the x86-64 host without a container** | apk, dracut and the UKI build have to run in the target chroot; that needs the target architecture's userspace, which binfmt gives a chroot inside a container. The container also confines `--privileged` and the loop-device work to one process. |
| **Load U-Boot's Secure Boot keys from the ESP** | U-Boot will not: authenticated variables restored from a plain file would let anyone with the card replace the root of trust. Preseeding the keys into the binary is the only path U-Boot accepts, at the cost of one U-Boot build per key set. |
| **Use the kernel's `tpm-slb9670` overlay** | It enables the hardware SPI0 controller U-Boot cannot drive, so U-Boot would boot without a TPM and measure nothing. The bit-banged overlay costs bus speed and buys a TPM that is present from the first instruction U-Boot executes. |
| **One LUKS passphrase for every image built** | Every copy of an image would open with it. The keyslot-0 passphrase is 32 random bytes per build and exists only until firstboot replaces it with the TPM-sealed key. |
| **Seal to the TPM during the build** | The build host's TPM is not the node's; same constraint as the ISO, and the reason Phase B is unchanged. |

## 4. Component boundaries

| Piece | Package | Owns |
|---|---|---|
| Build orchestration, preflight, inspection | `pkg/diskimage` (+ `runner`, the one seam through which docker, losetup and mtools run) | `Create`, `Assemble`, `Inspect`, the `Target` interface and its registry |
| Raspberry Pi target | `pkg/diskimage/rpi` | the model table, `config.txt`, staging the boot firmware from the prefetched apks and the U-Boot output |
| QEMU virt target | `pkg/diskimage/qemuvirt` | the emulated stand-in (U-Boot supplied to QEMU as `-bios`, empty boot-firmware directory) |
| U-Boot | `pkg/diskimage/uboot` + `build/docker/uboot-builder` | cache key, container invocation, checksum verification of what comes back |
| Installer seams | `pkg/installer/boot_firmware.go` | `InstallTarget`, `BootFirmwareType`, `imageTargetSkips` — documented in [installer engineering.md](../installer/engineering.md) invariant 3 |
| Media staging and overrides | `pkg/iso` | `StageInstallMedia` (which drives the `Customizer`'s `StageMedia`), `InstallerOverrides`, `NewPlatformISOConfig`, `EnsureSecureBootKeys`, `ResolveSecureBootMaterial` |

Everything here is platform-owned (docs/00 §R: secure boot, measured boot,
UKI, installer/ISO/initrd). Secure Boot key generation reaches go-xkms through
the quicbaas `sdk/go/xkms` re-exports, as `iso create` does; nothing else
below the platform is touched. There is no daemon surface ([api.md](api.md)).

## 5. Data flow

```
platformctl diskimage create --target rpi --model rpi4
  ├─ Preflight            docker usable; qemu-aarch64 binfmt with the F flag; loop + dm_crypt loaded
  ├─ iso.StageInstallMedia
  │    ├─ EnsureSecureBootKeys       generate or reuse PK/KEK/db (or "remote" when the config signs remotely)
  │    ├─ ResolveSecureBootMaterial  the DB signer and certificates the build signs with
  │    └─ Customizer.StageMedia      <work>/media: apks-prefetch/aarch64, platformd-bin/, configs/installer.yaml, keys, ...
  ├─ uboot.Build          reuse output/ when manifest.json carries the cache key, else build
  ├─ virtkernel           the platform-built kernel (qemu-virt only)
  ├─ StageBootFirmware    <work>/media/boot-firmware: kernel8.img, config.txt, DTBs, overlays, blobs
  ├─ StageKernel          the platform-built kernel onto the media (qemu-virt only)
  └─ runner.Container --privileged: create, cp media → /media/cdrom, start, cp /work → out  (linux/<host arch>, private /dev; host-arch installer at /installer when the target is foreign)
       platformctl-static diskimage assemble --platform-config /media/cdrom/configs/installer.yaml
         ├─ sparse image → LOOP_CTL_GET_FREE, mknod /dev/loopN if missing, losetup --partscan
         ├─ installer.Install with Target=image, Boot.Firmware=uboot, Disk.Device=/dev/loopN
         │    copies /media/cdrom/boot-firmware onto the ESP root, writes the PROVISIONED sentinel
         └─ sync, losetup --detach
  ⇒ Result{Image, SHA256, SizeBytes, MediaDir, UBoot, Kernel}
```

What crosses the container boundary: the media (copied in) and the image
(copied out), nothing else. The host's `/dev` is never bind-mounted: the
installer's `mdev -s`, which creates the partition nodes, resets the mode of
every device node it walks, and on a shared `/dev` that takes `/dev/null` away
from every unprivileged process on the build host.
The container's private `/dev` starts with the host's loop nodes; a loop device
allocated later gets its node from `assemble` itself. The Secure Boot DB key
travels on the media
exactly as it does on the ISO; the container image itself carries no platform
binaries and no keys.

What persists: the image, the staged media directory, the U-Boot output
(`manifest.json`, `SHA256SUMS`) and the Secure Boot keys directory.

## 6. Trust boundaries

1. **The root of trust is an unauthenticated U-Boot on a FAT partition.**
   Anyone who can write the card can replace `kernel8.img` with a U-Boot that
   carries different keys. Raspberry Pi OTP signed boot, which would anchor
   U-Boot in the SoC, is out of scope. What the chain does guarantee is that
   *this* U-Boot boots only a UKI signed by the platform's db key and records
   what it booted in the TPM — a swapped U-Boot changes PCR 0 and PCR 7, and
   the sealed LUKS key does not unseal.
2. **PCR 0 is weak.** It holds only U-Boot's version string; the firmware
   before U-Boot is unmeasured. Sealing policy should lean on 4, 7 and 9.
3. **One image = one device.** The keyslot-0 passphrase is random per build,
   and `tpm2/installer.luks` on the ESP holds the volume key until the first
   boot. **An image that has not booted once is as sensitive as the disk
   encryption key**: store it accordingly, and never flash the same image to
   two devices that will both be trusted.
4. **The build host sees everything** — keys, media, finished image. It is
   the install media of the ISO flow ([installer §6](../installer/architecture.md#6-trust-boundaries), boundary 1).
5. **`ubootefi.var` is not protected**: only non-authenticated variables
   (boot order and the like) live there, and anyone with the card can edit it.
   On the shipped image U-Boot does not write it at all: it treats only an
   MBR partition of type `0xEF` as the EFI system partition, and the boot
   partition is `0x0c` because the Raspberry Pi firmware reads nothing
   else, so every boot logs "Cannot persist EFI variables without system
   partition". The chain depends on no persisted variable — PK/KEK/db are
   compiled in and the UKI is found by path.

## 7. What this feature deliberately does not do

- **It does not run on the device.** First boot, sealing, enrolment and
  attestation are the installer's Phase B and provisioning, unchanged.
- **It does not sign U-Boot or anchor it in hardware.** No OTP signed boot.
- **It does not provide IMA on the Pi.** Alpine's `linux-rpi` kernel is built
  without `CONFIG_IMA`, so the IMA / PCR 10 measurement feature
  ([`docs/ima/`](../ima/)) is unavailable on that kernel.
- **It does not flash cards from the CLI.** Writing a device is a Makefile
  target with explicit guards ([user.md](user.md)), the only `sudo` step.
- **It does not build every role on every Pi.** `rpi4` ships the
  single-node template (the default) and, through `--role compute`, the
  dedicated-profile compute node; `rpi5` ships the same compute node as an
  experimental template (next item); `--role control-plane` builds the
  standalone control plane on `cm4` and `rpi4`. A Pi gateway has no
  template ([`dedicated/raspberrypi/README.md`](../../configs/platform/templates/dedicated/raspberrypi/README.md)
  says why), and other models fall back to the x86 single-node template with
  the target's overrides; `--overrides` adjusts anything else, including
  `seal-pcrs`.
- **It does not validate the Pi 5.** `--model rpi5` builds an image with no
  VideoCore firmware on the boot partition (the bootloader EEPROM loads
  `kernel8.img`), but no Pi 5 has booted it. The 40-pin header's GPIO and SPI
  belong to the RP1 I/O chip behind PCIe, and the U-Boot build bit-bangs the
  SLB9670 over BCM2835 GPIO, so whether U-Boot reaches the TPM — and so
  whether PCRs 0, 4, 7 and 9 are measured — is unknown; the console and the
  RP1 Ethernet are unvalidated too. The detail is in
  [`dedicated/raspberrypi/README.md`](../../configs/platform/templates/dedicated/raspberrypi/README.md).

## 8. Measurement manifest

> **Designed, not built.** Nothing below exists in the code yet. It is the
> design that slices 3-6 of [docs/plans/669.md](../plans/669.md) build, and
> it needs approval before slice 3 starts. Today a node's quote is checked
> against its device profile's `PCRBaseline` table.

The SPEC row says every image, an upgrade included, is built and signed
centrally. It also says every image carries a **measurement manifest**: a
signed CoRIM ([draft-ietf-rats-corim-11](../reference/rats/draft-ietf-rats-corim-11.txt))
of the PCR values the image determines, registered in the go-quicbaas
reference-values store. The verifier then knows what a node booted from
that image must quote, before the node first boots. It does not have to
learn the values from the node.

**What the image determines.** A PCR goes in the manifest only when the
image fixes every event extended into it. The build has every input that
the boot chain in §2 measures:

| PCR | Events | Build input |
|---|---|---|
| 0 | `EV_S_CRTM_VERSION`, U-Boot's version string | the U-Boot build (`uboot.Build`'s `manifest.json`) |
| 4 | the Authenticode digests of the UKI and of the db-signed kernel the stub hands to `LoadImage`, and their separators and actions | the signed UKI and kernel |
| 7 | `SecureBoot`, `PK`, `KEK`, `db`, `dbx` as U-Boot preseeds them, and the `db` entry that verified each image | `<work-dir>/secure-boot-certs` |
| 9 | the initrd, measured by the Linux EFI stub | the UKI's `.initrd` section |
| 11 | the UKI's sections, measured by systemd-stub | the UKI |

PCRs 1, 2 and 5 hold events that U-Boot's own code fixes: boot variables,
drivers, and `ExitBootServices`. They go in the manifest only if slice 5's
event-log replay shows that two boots of one image give the same value.
PCR 11 is in the table on the same condition: the replay must show that
systemd-stub measures under U-Boot's TCG2 protocol. The manifest never
carries a PCR that is extended at runtime: 10 (IMA, absent on `linux-rpi`),
12-15, or 16-23. PCR 0 is in the manifest, but §6 boundary 2 still holds: it
proves the U-Boot version, not the firmware before it.

**How the values are computed.** The values are predicted, not measured.
The build replays the event sequence that the boot chain extends, from the
same bytes it writes to the card, for each configured bank (`sha256` by
default). The bank list is a build input. A missing input fails the build;
the build never writes a partial manifest. Slice 5 proves the prediction:
`make integration-test-diskimage` boots the image on the QEMU `virt` stand-in
and checks that the live TCG event log, replayed, gives the manifest's
values. The x86 ISO path gets the same check.

**The CoRIM.** One `signed-corim` (`#6.18`, COSE_Sign1, content type
`application/rim+cbor`) per build, written as `measurements.corim` beside the
image. It holds one CoMID (`#6.506`):

- `tag-identity`: a UUID derived from the image's SHA-256. An upgrade is a
  new build, so it gets a new tag.
- one `reference-triple-record`. Its environment is a `class-map` with
  vendor `go-trusted-platform` and model `<target>/<model>`, for example
  `rpi/rpi4` or `qemu-virt/virt`.
- one `measurement-map` per PCR. `mkey` is the PCR index (`uint`), and
  `mval.digests` holds one digest per bank.

The COSE protected header carries `corim-meta` (signer name and validity)
and the signing certificate's `x5chain`.

**Signed centrally.** The build host never holds the manifest's signing key.
The key is a KMS key, given as a `kms://` reference, as the DB key in
`resign-mode: remote` and the HTTP boot fleet key already are. Its
certificate chains to the platform CA. A media-staged `file://` key is
refused for the manifest, as `refusePrivateKeys` refuses one for a network
set. Every build that produces a UKI writes a manifest: the SD-card image,
a netboot media set, and an upgrade.

**Registered.** `platformctl diskimage` registers the manifest with
`Security().Attestation().PutReferenceValues`, keyed by the CoMID's
`tag-identity`, after the build succeeds. A registration failure fails the
command, and the image is still left on disk. The verb ships in go-quicbaas
v0.14.0-alpha, and the platform pins v0.12.0-alpha (#720), so registration
is the last code slice.

**Open questions for approval:**

1. A node mid-upgrade may quote either its old image or its new one. The
   current proposal is that both manifests stay registered until the new
   image is confirmed, and the old one is then deleted
   (`DeleteReferenceValues`). That matches the `.prev` refusal in the luks
   row.
2. Signing algorithm: ES384 on a P-384 KMS key is proposed, rather than
   reusing the EEPROM's RSA-2048 fleet key. The EEPROM key's format is fixed
   by the Pi firmware; the manifest's is not.
3. The banks: `sha256` alone, or `sha256` and `sha384` where the TPM enables
   both. The SLB9670 has no `sha384` bank.
