# Factory Image — CLI

> **Status: NORMATIVE** · Scope: `platformctl diskimage` · Last verified: 2026-09-16
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and flag below was read out of `pkg/cli/commands/diskimage/` on 2026-09-16.

---

## 1. Command group

```
platformctl diskimage            Factory disk images (Raspberry Pi SD card, QEMU virt)
platformctl diskimage create     Build a factory disk image
platformctl diskimage inspect    Report an image's partitions, EFI partition contents and UKI
platformctl diskimage assemble   (hidden) Run the installer against a loop-mounted image
```

**None of these verbs needs a running daemon and none takes a transport.**
They run on a build host; the root `--transport` / `--server` flags are
accepted and ignored. Exit status is `0` on success and non-zero on any
error, with the typed error message on stderr ([engineering.md §4](engineering.md#4-error-semantics)).
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
arm64 container. Prints the image path, SHA-256, size, the U-Boot binary used
and the staged media directory.

### Build flags

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--target` | string | `rpi` | `rpi` or `qemu-virt` |
| `--model` | string | `rpi4` for `rpi` | `rpi4`, `rpi400`, `cm4`, `rpi3b+`, `rpi5` (experimental) |
| `--size` | int | `4096` | image size in MB; minimum `2048` |
| `--output` | string | `<work-dir>/trusted-platform-<target>.img` | output image path |
| `--binaries-dir` | string | `aarch64/` next to the running binary | directory holding the target-architecture `platformd`, `platformctl`, `platformctl-static`, `platform-initrd`, `gatewayd` |
| `--builder-image` | string | `trusted-platform-diskimage-builder:arm64` | assemble container image tag |
| `--builder-dir` | string | `build/docker/diskimage-builder` | assemble container build context |
| `--container-runtime` | string | `docker` | container runtime binary |
| `--uboot-dir` | string | | prebuilt U-Boot artifacts; skips the U-Boot build |
| `--uboot-builder-dir` | string | `build/docker/uboot-builder` | U-Boot builder build context |
| `--uboot-output-dir` | string | `<uboot-builder-dir>/output` | U-Boot builder output directory |
| `--virt-kernel-dir` | string | | prebuilt virt kernel artifacts for `qemu-virt` (skips the kernel build) |
| `--virt-kernel-builder-dir` | string | `build/docker/virt-kernel-builder` | virt kernel builder context |
| `--virt-kernel-output-dir` | string | `<builder-dir>/output` | where the built kernel lives (`make virt-kernel-build`) |
| `--virt-kernel-cache-dir` | string | | kernel tarball cache |
| `--uboot-cache-dir` | string | | U-Boot tarball cache directory |
| `--skip-preflight` | bool | `false` | skip the build-host checks (binfmt, container runtime, kernel modules) |

### Media flags (shared with `iso create`)

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--platform-version` | string | the `VERSION` file, else `dev` | platform version baked into the image |
| `--alpine-version` | string | `3.22.2` | Alpine Linux version |
| `--mirror` | string | `http://mirror.cs.odu.edu/alpine` | Alpine mirror used for the build-time pre-fetch |
| `--apk-mirror` | string | | install-time apk mirror baked into the kernel cmdline |
| `--platform-config` | string | auto-detected | platform config template baked into the image (`configs/platform/templates/single-node/raspberrypi/<model>/default.yaml` when present, else `configs/platform/templates/single-node/default.yaml`) |
| `--overrides` | string | | override YAML deep-merged onto `--platform-config` (requires it) |
| `--platform-type` | string | `server` | `server` or `client` |
| `--secure-boot` | bool | `true` | enable Secure Boot; the keys are preseeded into U-Boot |
| `--tpm-unseal` | bool | `true` | enable TPM auto-unseal |
| `--luks` | bool | `true` | enable LUKS encryption |
| `--fido2` | bool | `false` | enable FIDO2 security key support |
| `--keys-dir` | string | `<work-dir>/secure-boot-keys` | Secure Boot keys directory (`PK`, `KEK`, `DB`) |
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
# what create runs inside the arm64 container
platformctl-static diskimage assemble --platform-config /media/cdrom/configs/installer.yaml \
  --output /work/trusted-platform-rpi.img --size 4096
```

## 6. Parity gap

`conventions/feature-docs.md` §4 requires a `CommandDefinition` per verb in
the integration parity suite. This repository defines no `CommandDefinition`
type (grepped repo-wide, 2026-09-16); see [engineering.md §9](engineering.md#9-parity-gap).
