# Build Docs

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

The [trusted-platform-builder](/build/docker/trusted-platform-builder) container provides a [Debian](https://www.debian.org/).

#### Static Builds

The [trusted-platform-builder](/build/docker/trusted-platform-builder) container provides an [Alpine Linux](https://www.alpinelinux.org/) `(Dockerfile-alpine)` build environment based on [musl libc](https://musl.libc.org/) to facilitate static builds.


The following libraries require dynamic linking:

* [pkcs11](https://github.com/miekg/pkcs11)
* [libvirt](https://libvirt.org/golang.html)

To perform a manual static build, use the Makefile `build-static` and `build-debug-static` targets.

To perform a container build, use the Makefile `docker-builder-load` and `release-binaries` targets.


## Install

The [build/docker/trusted-platform-iso-builder](/build/docker/trusted-platform-iso-builder) directory contains a Makefile that makes it easy to build a UEFI bootable `trusted-platform.iso` and `trusted-platform-swtpm.iso`. 

The `swtpm` ISO installs a software TPM and configures the system accordingly.

The standard ISO is intended for hardware based TPM platforms.

