# Build Docs

> **Status: REFERENCE** · Last verified: 2026-10-13
> Building the go-trusted-platform binaries and the installer ISO from source.

## Binary Architecture

go-trusted-platform builds six binaries, one per directory under `cmd/`:

| Binary | Purpose | Commands |
|--------|---------|----------|
| `platformd` | Daemon server | serve, version |
| `gatewayd` | Edge daemon | serve, service, version |
| `platformctl` | CLI operations | firstboot + all operational commands |
| `platform-initrd` | Initramfs boot | boot, recovery, version |
| `pxeboot` | Network boot server | — |
| `deployer-pin` | Deployer pin management | — |

**Note**: `firstboot` runs via `platformctl` after switch_root (when the real filesystem is mounted), not in platform-initrd. This keeps platform-initrd minimal for initramfs size constraints.

## Bare Metal Builds

### System Requirements

* [Debian](https://www.debian.org/) based distro
* [Make](https://www.gnu.org/software/make/)
* [Golang](https://go.dev/)
* [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/)
* [QEMU / KVM](https://www.qemu.org/)
* [Docker](https://www.docker.com/get-started/)

### Optional

* [SoftHSM](https://www.opendnssec.org/softhsm/)
* [NitroKey](https://www.nitrokey.com/products/nitrokeys)
* [YubiKey](https://www.yubico.com/)
* [YubiHSM](https://www.yubico.com/products/hardware-security-module/)
* Other PKCS #11 HSM

    For FIPS compliance, a FIPS certified token is required.

### Makefile

The `Makefile` provides targets for performing optimized and debug builds that produce dynamically and statically linked binaries.

#### Dynamic Builds

The [trusted-platform-builder](../build/docker/trusted-platform-builder) container provides a [Debian](https://www.debian.org/).

#### Static Builds

The [trusted-platform-builder](../build/docker/trusted-platform-builder) container provides an [Alpine Linux](https://www.alpinelinux.org/) `(Dockerfile-alpine)` build environment based on [musl libc](https://musl.libc.org/) to facilitate static builds.


The following libraries require dynamic linking:

* [pkcs11](https://github.com/miekg/pkcs11)
* [libvirt](https://libvirt.org/golang.html)

To perform a manual static build, use the Makefile `build-static` and `build-debug-static` targets.

To perform a container build, use the Makefile `docker-builder-load` and `release-binaries` targets.

### Build Targets

| Target | Description |
|--------|-------------|
| `make build` | Build platformd, platformctl, gatewayd and deployer-pin |
| `make platform-initrd` | Build platform-initrd (boot/recovery only) |
| `make platform-initrd-static` | Build static platform-initrd |
| `make binaries` | Build the `make build` binaries plus platform-initrd |
| `make build-static` | Build all static binaries |

### Build All Binaries

```bash
# Build all binaries (dynamic)
make binaries

# Build all binaries (static)
make binaries-static

```

## Install

Build a UEFI-bootable `trusted-platform.iso` with the in-CLI builder:

```bash
make build
bin/platformctl iso create --output bin/trusted-platform.iso
```

`platformctl iso create` downloads Alpine, generates Secure Boot keys (or
reuses existing ones), customizes the image with `platformd` and the
selected TPM/LUKS/FIDO2/FIPS options, and emits a hybrid BIOS/UEFI
bootable ISO. Pass `--platform-type client` for a workstation image or
`--platform-type server` (default) for a server image. See
`bin/platformctl iso create --help` for all flags.

The legacy Docker-based `make iso-hwtpm` / `make iso-swtpm` targets and
the `trusted-platform-iso-builder` image have been removed; the in-CLI
builder above is the supported and intended workflow.

