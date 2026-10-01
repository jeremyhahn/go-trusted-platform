# Virt kernel builder

Cross-builds the aarch64 kernel the QEMU virt stand-in of the Raspberry Pi
factory image boots, from the same upstream stable release Alpine 3.22's
`linux-lts` is built from, inside an Alpine container with the bare-metal
aarch64 toolchain the U-Boot builder uses.

```
make build            # output/virt/{vmlinuz-virt,modules-virt.tar.gz,config-virt,System.map-virt,kernel-version.txt,SHA256SUMS}
make verify           # recompute SHA256SUMS
make config-check     # configuration phase only (KERNEL_CONFIG_ONLY=1): proves every fragment line survives Kconfig, builds nothing
```

or, from the repository root, `make virt-kernel-build`. `output/manifest.json`
records the version, the tarball digest, the cache key and the release string
(`6.12.110-0-virt`, Alpine's flavour naming, so `/lib/modules/<release>` and
`vmlinuz-virt` look exactly like a packaged kernel to the installer).
`pkg/diskimage/virtkernel` is the Go consumer: it computes the same cache key
(`make cache-key`), skips the build when `manifest.json` already carries it,
and verifies `SHA256SUMS` before anything is staged onto install media.

## Why the platform builds a kernel for the stand-in

The Raspberry Pi's TPM (Infineon SLB9670) is on SPI, and Alpine's `linux-rpi`
carries that transport (`tpm_tis_spi`). QEMU's virt machine has no SPI or I2C
bus to put a TPM on; its only TPM front-end is `tpm-tis-device`, the
memory-mapped TIS interface, and **no Alpine aarch64 kernel has that driver**:
`CONFIG_TCG_TIS` is unset in `linux-lts` and `linux-rpi`, and `linux-virt`
has no TPM support at all (measured 2026-09-20 from the packages' shipped
configs). So the emulated first boot — TPM provisioning, LUKS sealing to the
PCRs, platformd — could not run on a stock kernel.

This kernel is the arm64 defconfig plus `configs/virt.config`: the TIS and CRB
TPM drivers built in, the virtio devices, dm-crypt and the LUKS ciphers, ext4
and FAT, the EFI stub, the PL011 console, and the same integrity posture as
Alpine's kernels — signed modules (`MODULE_SIG_ALL`, a per-build key like
Alpine's) and the lockdown LSM the platform boots with. On top of that it
merges `build/docker/kernel-config/platform-required.config`, the options
every platform kernel carries (the overlay datapath, IPsec, conntrack/NAT,
VRF, vsock, `MODULE_SIG_FORCE`, IMA appraisal, core scheduling, `CRYPTO_FIPS`),
shared with the fips kernel builder and baked into the image through the
`kernelconfig` named build context (`docker build --build-context
kernelconfig=../kernel-config`). `require-config.sh` from the same directory
fails the build if Kconfig drops or changes any line of either fragment, so
an unmet dependency is a build failure rather than a silent downgrade.

## What the stand-in does and does not share with the Pi

Shared: the Alpine userland, the installer, the UKI with its signed embedded
kernel, U-Boot with the preseeded Secure Boot keys and TCG2 measured boot,
platform-initrd, firstboot sealing, platformd. Different: the kernel binary
(this one, with the drivers built in, versus Alpine's `linux-rpi` with the
SPI transport as modules) and the disk (virtio versus SD card). The
integration suite therefore proves the chain; the Pi's kernel package and
its SPI TPM are validated on hardware ([docs/factory-image/user.md](../../../docs/factory-image/user.md)).
