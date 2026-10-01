# U-Boot builder

Builds the two U-Boot binaries the Raspberry Pi factory image needs from one
pinned upstream release, inside an Alpine container:

| Board | Loaded by | TPM transport | Used for |
|---|---|---|---|
| `rpi_arm64` | the Raspberry Pi firmware, as `kernel8.img` | Infineon SLB9670 on SPI0 CE1, bit-banged over GPIO (`SOFT_SPI` + `TPM2_TIS_SPI`) | the SD-card image |
| `qemu_arm64` | `qemu-system-aarch64 -M virt -bios u-boot.bin` | `tpm-tis-device` (swtpm), memory-mapped (`TPM2_MMIO`) | the emulated end-to-end tests |

Both carry the same EFI configuration: `EFI_TCG2_PROTOCOL` measured boot,
`EFI_SECURE_BOOT` with the platform's PK/KEK/db **preseeded into the binary**
(`EFI_VARIABLES_PRESEED`), a FAT-backed variable store on the ESP
(`EFI_VARIABLE_FILE_STORE`, `ubootefi.var`), and the standard boot flow that
finds `EFI/BOOT/BOOTAA64.EFI` on the first FAT partition.

```
make build KEYS_DIR=~/.trusted-platform/secure-boot   # PK.crt KEK.crt DB.crt
make verify                                           # recompute SHA256SUMS
```

or, from the repository root, `make uboot-build`. Output:

```
output/rpi_arm64/{u-boot.bin,u-boot.config,overlays/tpm-soft-spi.dtbo,SHA256SUMS}
output/qemu_arm64/{u-boot.bin,u-boot.config,SHA256SUMS}
output/manifest.json    # version, tarball sha256, cache key, owner GUID, measured PCRs
```

`pkg/diskimage/uboot` is the Go consumer: it computes the same cache key from
the same inputs (`make cache-key`), skips the build when `manifest.json`
already carries it, and verifies `SHA256SUMS` before anything is staged.

## Network boot

Both boards also carry U-Boot's standard network boot
(`configs/common-efi.config`): after the disks, `bootflow scan` tries
`BOOTDEV_ETH` — DHCP, then TFTP of the offered bootfile, run as an EFI
application under the same Secure Boot verification as a disk-booted UKI
(`BOOTMETH_EFILOADER`). The DHCP request identifies the client as a standard
EFI AArch64 PXE client (`DHCP_PXE_CLIENTARCH=0xb`, RFC 4578 option 93), so
the platform's PXE server — or any other with a per-architecture bootfile
map — hands it the signed arm64 iPXE rather than an x86 binary. The vendor
class stays U-Boot's own `U-Boot.armv8` (a non-visible Kconfig symbol), which
the platform's DHCP server recognises. This needs the legacy network stack
(`NET_LEGACY`): lwIP's DHCP client sends neither option 60 nor option 93.

`build-uboot.sh` fails the build if a fragment option was dropped by
Kconfig, and if a `# CONFIG_X is not set` line (here `NET_LWIP`) came back
enabled.

## Why the keys are compiled in

With `EFI_SECURE_BOOT` on, U-Boot deliberately does not restore
time-authenticated variables (PK, KEK, db, dbx) from `ubootefi.var` on the
ESP: a file on an unauthenticated FAT partition cannot be the root of trust
for its own verification. The preseed image is the one place U-Boot accepts
them from, so a Secure Boot key set implies a U-Boot build, and the build is
cached by the certificates' digests. `SecureBoot=1` is derived from the
presence of PK at boot.

## Why the TPM is bit-banged

Mainline U-Boot has no driver for the BCM2835 SPI controller. Its `SOFT_SPI`
driver bit-bangs the bus over GPIO, and `configs/tpm-soft-spi.dts` describes
SPI0's pins (SCLK 11, MOSI 10, MISO 9, CE1 7, reset 24) as a `spi-gpio` bus
with the SLB9670 as its only device. Linux binds the same node with
`spi-gpio` + `tpm_tis_spi`, so one overlay serves both stages; the kernel's
own `tpm-slb9670` overlay (hardware SPI0) is **not** applied. The overlay is
compiled here with `dtc` and shipped in `output/rpi_arm64/overlays/`.

## What is measured

U-Boot's `EFI_TCG2_PROTOCOL` extends PCR 0 (`EV_S_CRTM_VERSION`, the U-Boot
version string — the Raspberry Pi VC firmware measures nothing), PCR 1 (boot
variables, hand-off tables), PCR 2 (drivers), PCR 4 (the loaded EFI
application, i.e. the UKI), PCR 5 (ExitBootServices), and PCR 7 (the Secure
Boot variables and the db entry that verified the image); the Linux EFI stub
extends PCR 9 with the initrd through the same protocol. `manifest.json`
records `measured_pcrs`. DTB measurement (`EFI_TCG2_PROTOCOL_MEASURE_DTB`) is
left off because U-Boot rewrites `/chosen/kaslr-seed` on every boot.

## Limits, stated

- The root of trust is the U-Boot binary on an unauthenticated FAT
  partition; Raspberry Pi OTP signed boot is out of scope for this builder.
- `ubootefi.var` on the ESP still carries the non-authenticated variables
  (boot order and the like) and can be edited by anyone with the card.
- `rpi_arm64_defconfig` covers Pi 3B+/4B/CM4/400; Pi 5 support in mainline is
  recent and unvalidated here.
