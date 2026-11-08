# Factory Image — CLI

> **Status: NORMATIVE** · Scope: `platformctl diskimage` · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and flag below was read out of `pkg/cli/commands/diskimage/` on 2026-10-09.

---

## 1. Command group

```
platformctl diskimage            Factory disk images (Raspberry Pi SD card, QEMU virt)
platformctl diskimage create     Build a factory disk image
platformctl diskimage netboot    Build the netboot media the bootstrap container serves
platformctl diskimage rpi-eeprom-hsm Sign an EEPROM digest through the fleet KMS key
platformctl diskimage inspect    Report an image's partitions, EFI partition contents and UKI
platformctl diskimage assemble   (hidden) Run the installer against a loop-mounted image
platformctl diskimage netboot-initfs (hidden) Netboot initramfs + modloop for a platform-built kernel
platformctl diskimage diskless-root (hidden) Squashfs root + dm-verity tree for diskless media
platformctl diskimage test       Boot a factory image under emulation
platformctl diskimage test boot  Boot an image (interactive console, or wait for a serial milestone)
```

All verbs except `rpi-eeprom-hsm` run on a build host without a running daemon;
the root `--transport` / `--server` flags are accepted and ignored there.
`rpi-eeprom-hsm` uses the root context to reach platformd's KMS and CA clients.
Exit status is `0` on success and non-zero on any error, with the typed error
message on stderr ([engineering.md §4](engineering.md#4-error-semantics)).
Output is plain text; `--output` on the root command does not apply.

The Makefile wraps the common invocations ([user.md](user.md)): `make
image-rpi`, `make image-rpi-qemu`, `make image-rpi-xz`, `make rpi-sdcard`,
`make uboot-build`, `make virt-kernel-build` / `virt-kernel-verify` /
`virt-kernel-clean` (the stand-in's kernel), and the suites `make
integration-test-diskimage` (layout, U-Boot console, emulated first boot)
and `make integration-test-diskimage-userspace` (the aarch64 daemon in an
arm64 container against a host swtpm).

## 2. `platformctl diskimage create`

Builds an image end to end: preflight, Secure Boot keys, U-Boot (built or
located), media staging, boot firmware, and the assemble step inside the
assemble container, which runs at the build host's platform (for a foreign
target it runs the host-architecture installer at
`/installer/platformctl-static`). Prints the image path, SHA-256, size, the U-Boot binary used
and the staged media directory.

### Build flags

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--target` | string | `rpi` | `rpi` or `qemu-virt` |
| `--model` | string | `rpi4` for `rpi` | `rpi4`, `rpi400`, `cm4`, `rpi3b+`, `rpi5` (experimental) | <!-- lab-string-ok: Raspberry Pi model name, not a lab host -->
| `--role` | string | | dedicated-profile role for `--target rpi`: builds `configs/platform/templates/dedicated/raspberrypi/<model>/<role>.yaml` (today `compute` on `rpi4`, and on `rpi5` as an experimental template; `control-plane` on `cm4` and `rpi4`). Empty builds the single-node image. Refused with `ErrRoleTemplate` beside `--platform-config`, on `qemu-virt`, for a model the builder does not know, or when that file does not exist; there is no fallback |
| `--size` | int | `4096` | image size in MB; minimum `2048` |
| `--output` | string | `<work-dir>/trusted-platform-<target>.img` | output image path |
| `--binaries-dir` | string | `aarch64/` next to the running binary | directory holding the target-architecture `platformd`, `platformctl`, `platform-initrd`, `gatewayd`; its `platformctl-static` (or, when it has none, its static `platformctl`) is the media's `platformctl-static` |
| `--builder-image` | string | `trusted-platform-diskimage-builder` | assemble container image repository, without a tag or digest (a registry port such as `registry:5000/foo` is fine; `foo:latest` and `foo@sha256:…` are rejected); tagged `:<arch>` (host arch for assemble, target arch for netboot-initfs and diskless-root) so each platform has its own image |
| `--builder-dir` | string | `build/docker/diskimage-builder` | assemble container build context |
| `--container-runtime` | string | `docker` | container runtime binary |
| `--uboot-dir` | string | | prebuilt U-Boot artifacts; skips the U-Boot build |
| `--uboot-builder-dir` | string | `build/docker/uboot-builder` | U-Boot builder build context |
| `--uboot-output-dir` | string | `<uboot-builder-dir>/output` | U-Boot builder output directory |
| `--virt-kernel-dir` | string | | prebuilt virt kernel artifacts for `qemu-virt` (skips the kernel build) |
| `--virt-kernel-builder-dir` | string | `build/docker/virt-kernel-builder` | virt kernel builder context |
| `--virt-kernel-output-dir` | string | `<builder-dir>/output` | where the built kernel lives (`make virt-kernel-build`) |
| `--virt-kernel-cache-volume` | string | `trusted-platform-virt-kernel-src` | docker volume caching the kernel tarball |
| `--uboot-cache-volume` | string | `trusted-platform-uboot-src` | docker volume caching the U-Boot tarball |
| `--skip-preflight` | bool | `false` | skip the build-host checks (binfmt, container runtime, kernel modules) |

### Media flags (shared with `iso create`)

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--platform-version` | string | the `VERSION` file, else `dev` | platform version baked into the image |
| `--alpine-version` | string | `3.22.2` | Alpine Linux version |
| `--mirror` | string | `http://mirror.cs.odu.edu/alpine` | Alpine mirror used for the build-time pre-fetch |
| `--apk-mirror` | string | | install-time apk mirror baked into the kernel cmdline |
| `--platform-config` | string | auto-detected | platform config template baked into the image (the `--role` template when one is given; otherwise `configs/platform/templates/single-node/raspberrypi/<model>/default.yaml` when present, else `configs/platform/templates/single-node/default.yaml`) |
| `--overrides` | string | | override YAML deep-merged onto `--platform-config` (requires it) |
| `--platform-apk-dir` | string | | strongSwan builder output (`make strongswan-build`) whose apks the media carries and installs for the overlay's IPsec transport; refused without `--pre-fetch` |
| `--platform-type` | string | `server` | `server` or `client` |
| `--secure-boot` | bool | `true` | enable Secure Boot; the keys are preseeded into U-Boot |
| `--tpm-unseal` | bool | `true` | enable TPM auto-unseal |
| `--luks` | bool | `true` | enable LUKS encryption |
| `--fido2` | bool | `false` | enable FIDO2 security key support |
| `--keys-dir` | string | `<work-dir>/secure-boot-keys` | Secure Boot keys directory (`PK`, `KEK`, `DB`) for references that are not `kms://`. `kms://` references in the platform config are resolved through the platform context (`--context`); the command connects only when one is present |
| `--generate-keys` | bool | `true` | generate Secure Boot keys if they do not exist |
| `--key-backend` | string | `file` | `file`, `software`, `pkcs11`, `tpm2`, `awskms`, `azurekv`, `gcpkms`, `vault` |
| `--ca-bundle` | string | | CA bundle PEM to embed for the client trust store |
| `--ca-key-algorithm` | string | | CA key algorithm filter: `rsa`, `ecdsa`, `ed25519`; empty means all |
| `--webui` | string | | web UI directory or tarball |
| `--work-dir` | string | `work` | working directory |
| `--pre-fetch` | bool | `true` | pre-download every package into the media; required, the container installs offline |
| `--debug` | bool | `false` | debug output (also passed to the assemble step) |
| `--verbose` | bool | `false` | verbose output |

No flag is required. `--binaries-dir` must contain `platformd`
(`ErrBinariesNotFound` otherwise — run `make rpi-binaries`). `--overrides`
without a `--platform-config` (explicit or auto-detected) is an error.

### Examples

```sh
# Raspberry Pi 4 image with the defaults
platformctl diskimage create --target rpi --model rpi4 --output bin/trusted-platform-rpi.img

# A Raspberry Pi 4 compute node of the dedicated profile, joining an x86 control plane
platformctl diskimage create --target rpi --model rpi4 --role compute --overrides node.yaml \
  --ca-bundle cp-ca.pem --output bin/trusted-platform-rpi4-compute.img

# A Compute Module 4 image, larger card, prebuilt U-Boot, keys from a fixed directory
platformctl diskimage create --target rpi --model cm4 --size 8192 \
  --uboot-dir build/docker/uboot-builder/output --keys-dir "$HOME/.trusted-platform/secure-boot" \
  --output bin/trusted-platform-cm4.img

# The QEMU virt stand-in the integration suite boots
platformctl diskimage create --target qemu-virt --output bin/trusted-platform-qemu-virt.img

# Custom platform config with per-node overrides (for example seal-pcrs: [0, 4, 7, 9])
platformctl diskimage create --platform-config configs/platform/templates/single-node/default.yaml \
  --overrides node.yaml --output bin/node-01.img
```

## 2a. `platformctl diskimage netboot`

Builds a netboot media build (`container.NetbootMedia`, layout in
[engineering.md §6](engineering.md)): one media set per architecture and board
— `x86_64`, `aarch64-rpi`, `aarch64-virt` — plus the Raspberry Pi TFTP tree,
the db-signed arm64 iPXE, and — with `--diskless` — the diskless root of every
set that installs a target image.
`bootstrap.yaml`'s `deployer.netboot_media_dir`
points at the output. It takes every **Build** and **Media** flag of `create`
(one `--platform-config` bakes into every set; the node's own config fetched
per MAC replaces it at install), and:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--output` | string | `<work-dir>/netboot-media` | output directory; replaced |
| `--cache-dir` | string | `<output>.cache/alpine` | pinned Alpine netboot releases |
| `--x86-binaries-dir` | string | next to this binary | x86_64 `platformd`, `platformctl`, `platformctl-static`, `platform-initrd`, `gatewayd` |
| `--arm64-binaries-dir` | string | `aarch64/` next to this binary | the arm64 set |
| `--ipxe` | string | `build/docker/ipxe-builder/output/bin-arm64-efi/snponly.efi` | the arm64 iPXE to sign (`make ipxe-build`; checked against its `SHA256SUMS`) |
| `--model` | string | `rpi4` | board the TFTP tree's `config.txt` is written for |
| `--sets` | strings | all | sets to build; an unknown name is `ErrUnknownMediaSet` |
| `--diskless` | bool | `false` | also build the diskless root: `rootfs.squashfs` and `rootfs.verity` in the set, and `cdrom/diskless/manifest.json` (+ `.sig`) signed by the DB key; needs Secure Boot and a platform version. With no `--sets`, sets that have no diskless image (x86_64) are left out of the defaults with a logged notice; naming one in `--sets` fails with `UnsupportedDisklessSetError` |
| `--fleet-key` | string | `""` | `kms://` reference of the RSA-2048 fleet key that signs the Pi's HTTP `boot.sig`; turns HTTP boot on (needs the `aarch64-rpi` set and a board with an EEPROM, not the 3B+) |
| `--fleet-cert` | string | the `--fleet-key` id | `kms://` reference of the fleet key's certificate, which carries its public key; `kms://<ref>#sha256=<fingerprint>` pins it |
| `--source-date-epoch` | int | `$SOURCE_DATE_EPOCH`; for `boot.sig`, now | the build time as a Unix time: the diskless root's every timestamp and, with the platform version, its verity salt, and `boot.sig`'s `ts`; with `--diskless`, missing or invalid is `ErrSourceDateEpoch` |
| `--target-soc` | string | `""` | optional `boot.sig` `target-soc` (`2711` or `2712`); omitted by default for fleet `boot.img` |

`--fleet-cert` and `--target-soc` without `--fleet-key`, and
`--source-date-epoch` without `--fleet-key` or `--diskless`, are an
`ErrHTTPBootFlags`. A non-`kms://` `--fleet-key` is refused (the fleet
key never exists as a file).

**Pin the fleet certificate.** `--fleet-cert kms://rpi/fleet#sha256=<fingerprint>`
signs only if the certificate the CA returns has that SHA-256 fingerprint of
its DER — the value `platformctl ca sign-csr` and `ca certificate` print as
"SHA-256 Fingerprint", with or without colons, in either case. Any other
certificate under the reference is a `CertPinError` and nothing is signed; a
malformed pin is a `CertPinFormatError`. `rpi-eeprom-hsm` takes the same
form. With `--fleet-key` the build also writes
`http-boot/{boot.img,boot.sig,pubkey.bin}`, verifies them as the bootloader
does, and prints the OTP customer key hash plus the EEPROM's `HTTP_HOST`,
`HTTP_PORT`, and `HTTP_PATH` inputs. The hash is what an operator burns into
OTP - **irreversible**; the runbook is
[user.md](user.md#provision-a-fleet-signed-http-boot).

**Secure Boot keys must be in the KMS.** A set is served over HTTP, so it
never carries a private key: with `--secure-boot` the platform config's
`secure-boot.db` must be a `kms://` reference (`resign-mode: remote`), reached
through the platform context (`--context`); a file DB key is refused. With
Secure Boot off, no key is generated and only public certificates are staged.

```sh
make netboot-media                                   # builds every input, then:
platformctl diskimage netboot --output bin/netboot-media \
  --x86-binaries-dir bin --arm64-binaries-dir bin/aarch64 \
  --uboot-output-dir build/docker/uboot-builder/output \
  --virt-kernel-output-dir build/docker/virt-kernel-builder/output
```

## 2b. `platformctl diskimage rpi-eeprom-hsm FILE`

Signs `FILE` through the same KMS signer used for Raspberry Pi HTTP `boot.sig`
and prints the raw RSA signature as lowercase hex on stdout. It exists for
upstream `rpi-eeprom-digest -H`, which invokes the wrapper as
`<wrapper> -a rsa2048-sha256 <file>`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--fleet-key` | string | required | `kms://` reference of the RSA-2048 fleet signing key |
| `--fleet-cert` | string | the `--fleet-key` id | `kms://` reference of the fleet certificate/public key; `#sha256=<fingerprint>` pins it (§2a) |
| `-a`, `--algorithm` | string | `rsa2048-sha256` | upstream HSM-wrapper algorithm; other values are refused |

```sh
RPI_EEPROM_FLEET_KEY=kms://rpi/fleet \
  scripts/rpi-eeprom-kms-hsm-wrapper.sh -a rsa2048-sha256 bootconf.txt
```

## 3. `platformctl diskimage inspect IMAGE`

Reports an image without mounting it and without privilege: the MBR and the
LUKS2 header are read in Go; the EFI partition is listed with mtools
(`mdir`, `mcopy` must be installed). One positional argument, no flags.

Output: the partition table (`p1 type=0x0c start=... sectors=... (N MB)
boot`), whether p1 is a FAT32 ESP, whether p2 is LUKS2, whether
`tpm2/installer.luks` is still present (the image has not had its first
boot), whether the `EFI/TRUSTED_PLATFORM/PROVISIONED` sentinel exists, the
UKI path with its COFF machine (`0xaa64` for aarch64) and whether it carries
an Authenticode signature, the Raspberry Pi `config.txt`, and every file on
the ESP.

```sh
platformctl diskimage inspect bin/trusted-platform-rpi.img
```

## 4. `platformctl diskimage test boot`

Boots a factory image on the QEMU virt machine with a software TPM: U-Boot
(`qemu_arm64/u-boot.bin`) as `-bios`, the image as a raw virtio disk, a
swtpm behind `tpm-tis-device`, user-mode networking. It is `pkg/diskimage.Boot`
behind the flags; the integration suite and a CI job use the same function.
The image is copied into the work directory before boot unless `--in-place`
is given, because the first boot changes it (firstboot seals the LUKS key
and wipes `installer.luks`). The TPM state under `<work-dir>/tpm` is kept
between boots, so a second boot of the same disk unseals what the first
sealed.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--image` | string | `bin/trusted-platform-qemu-virt.img` | image to boot |
| `--in-place` | bool | `false` | boot the image itself, not a copy |
| `--uboot` | string | `build/docker/uboot-builder/output/qemu_arm64/u-boot.bin` | U-Boot passed as `-bios` |
| `--work-dir` | string | `work/diskimage-test` | TPM state, sockets, the working copy |
| `--memory` | int | `2048` | guest RAM in MB |
| `--cpus` | int | up to 4 | guest CPUs |
| `--serial-log` | string | | write the serial transcript here instead of the terminal |
| `--console-socket` | string | | also expose the console on this unix socket (`harness.Console`) |
| `--expect` | string | | return once this text appears in `--serial-log` (requires it) |
| `--timeout` | duration | `45m` | give up waiting for `--expect` (TCG emulation is slow) |
| `--forward` | `host:guest[/udp]` | | user-mode port forward, repeatable |
| `--debug` | bool | `false` | QEMU and swtpm debug output |

Without `--serial-log` the console is interactive on the terminal (`Ctrl-A X`
quits QEMU). Errors are `BootError{Step}`: a missing image or firmware, a
swtpm that did not start, a VM that did not start, or a milestone that did
not appear before `--timeout` (the error carries the tail of the transcript).
An invalid `--forward` is `ErrInvalidPortForward` before anything starts.

```sh
# interactive first boot of the QEMU stand-in
platformctl diskimage test boot

# unattended: return once platformd is up, keep the transcript
platformctl diskimage test boot --serial-log work/diskimage-test/boot1.log \
  --expect "platformd ready" --forward 18443:8443

# second boot of the same disk and TPM state
platformctl diskimage test boot --image work/diskimage-test/disk.img --in-place \
  --serial-log work/diskimage-test/boot2.log --expect "Successfully unlocked"
```

## 5. `platformctl diskimage assemble` (hidden)

The in-container step `create` runs; it is hidden from `--help` and not
meant for direct use. It creates the sparse image, attaches it as a loop
device, runs the installer with the install target `image` and the boot
firmware `uboot`, and detaches. It needs root, a loop device and the media at
`/media/cdrom`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | | installer configuration YAML (`installer.Config`) |
| `--platform-config` | string | | platform configuration YAML, converted the way the live installer converts it |
| `--output` | string | | image path to create (required) |
| `--size` | int | `4096` | image size in MB; minimum `2048` |
| `--debug` | bool | `false` | debug output |

Exactly one of `--config` and `--platform-config` is required
(`ErrConfigRequired` otherwise). `create` always passes
`--platform-config /media/cdrom/configs/installer.yaml`.

```sh
# what create runs inside the assemble container (host platform; for a foreign
# target the binary is /installer/platformctl-static, the host-architecture one)
platformctl-static diskimage assemble --platform-config /media/cdrom/configs/installer.yaml \
  --output /work/trusted-platform-rpi.img --size 4096
```

## 5a. `platformctl diskimage netboot-initfs` (hidden)

The in-container step of a netboot media build for a set on a platform-built
kernel (`netboot.ARM64VirtSet`, the QEMU virt stand-in's kernel), run in the
arm64 builder image by `StagedMedia.BuildNetbootInitfs`. It installs the
kernel's modules, runs `mkinitfs` with Alpine's netboot features
(`base network squashfs usb virtio`, `diskimage.NetbootInitfsFeatures`) and
squashes the modules into the modloop (`modules/<release>/` at its root — the
layout Alpine's init mounts).

| Flag | Type | Meaning |
|---|---|---|
| `--modules` | string | the kernel's modules tarball (`lib/modules/<release>`) |
| `--release` | string | the kernel release |
| `--flavour` | string | names `initramfs-<flavour>` and `modloop-<flavour>` |
| `--output` | string | directory receiving both |

All four are required.

## 5b. `platformctl diskimage diskless-root` (hidden)

The in-container step of a diskless media build, run in the builder image by
`StagedMedia.BuildDisklessRoot` with the staged media as its input and no
bind mount. It installs the media's platform onto a scratch image (no LUKS,
ext4 root, Secure Boot off so no DB key is generated), packs the installed
root partition with a reproducible `mksquashfs`, refuses a root without
`/sbin/init` or `/usr/bin/platformd` or with any private key material in it
(a `*.key` file, a PEM `PRIVATE KEY` block, a DER key). Before packing it
locks every account in `/etc/shadow` (and `shadow-`) that has a usable password
(`!` in the password field) and refuses any root where one remains: the
installer's root password must not reach the public image. It refuses a root
whose `/etc/trusted-platform/config.yaml` holds a plaintext value in any
`secret:"true"` field of the platform config, naming the fields; a secret
reference (`kms://`, `env://`, `file://`, …) passes. It then formats the
dm-verity tree with pinned parameters (sha256, 4096/4096, no
superblock, the given salt). It writes `rootfs.squashfs`, `rootfs.verity` and
`rootfs.roothash`; the host signs the manifest and drops `rootfs.roothash`.

| Flag | Type | Meaning |
|---|---|---|
| `--config` / `--platform-config` | string | the install configuration, as for `assemble` (exactly one) |
| `--size` | int | scratch image size in MB |
| `--work-dir` | string | scratch image and mount point |
| `--output` | string | directory receiving the three files |
| `--source-date-epoch` | int | every timestamp in the squashfs |
| `--salt` | string | dm-verity salt, 64 hex characters |
| `--debug` | bool | rejected: debug mode (SSH root login, host keys) cannot be baked into the shared public root |

## 6. Parity gap

`conventions/feature-docs.md` §4 requires a `CommandDefinition` per verb in
the integration parity suite. This repository defines no `CommandDefinition`
type (grepped repo-wide, 2026-09-16); see [engineering.md §9](engineering.md#9-parity-gap).
