# Factory Image — Using It

> **Status: REFERENCE** · Scope: building, flashing and first-booting a Raspberry Pi factory image · Last verified: 2026-09-16
> Task-oriented, in the order you do things. Internals are in
> [engineering.md](engineering.md); the design is in
> [architecture.md](architecture.md).
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

You build an SD-card image on your workstation, write it to a card, put the
card in a Raspberry Pi with a TPM attached, and power it on. The first boot
provisions the TPM, seals the disk encryption key to it, and brings up a
platform node — the same first boot an ISO install produces, without ever
booting an installer on the Pi.

Three things to know before you start:

1. **One image, one device.** Every image carries its own random disk
   passphrase and, until the first boot, the key that opens the root. Treat
   an image that has not booted like the disk encryption key it contains,
   and do not flash one image to two devices you intend to trust.
2. **The first boot is where the real work happens.** Building and flashing
   are quick; the first boot provisions the TPM and seals the key. Watch the
   serial console: nothing else tells you whether it worked.
3. **Hardware validation is your step.** The pipeline is exercised under
   emulation; booting a real Pi with a real TPM is the verification below.

## Prerequisites

On the build host:

- Docker with `buildx`, and a binfmt handler for arm64 registered with the
  `F` flag so a chroot inside an arm64 container can run. `make init`
  installs the packages and registers the handler
  (`multiarch/qemu-user-static --reset -p yes`).
- The `loop` and `dm_crypt` kernel modules loaded (`modprobe loop dm_crypt`).
- `mtools` (`mdir`, `mcopy`) if you want to inspect images.
- Enough disk for the pre-fetched packages, the media and a 4 GB sparse image.

The build fails early, with the remedy, if any of the first two is missing.

On the device:

- A Raspberry Pi 4 Model B, 400, Compute Module 4 or 3 Model B+. The Pi 5 is
  experimental.
- An Infineon SLB9670 TPM 2.0 on SPI0 chip-select 1 — the LetsTrust or
  Iridium 9670 wiring (SCLK GPIO 11, MOSI 10, MISO 9, CE1 7, optional reset
  24).
- A USB serial adapter on the primary UART (GPIO 14/15), 115200 baud.
  Bluetooth is moved off that UART by the image.
- An SD card of at least 4 GB.

## Build

```sh
make image-rpi                              # Raspberry Pi 4, bin/trusted-platform-rpi.img
make image-rpi DISKIMAGE_MODEL=cm4          # Compute Module 4
make image-rpi DISKIMAGE_SIZE_MB=8192       # bigger card
make image-rpi-xz                           # also produce the .xz for release
```

`make image-rpi` builds the host binaries, cross-compiles the arm64 set
(`make rpi-binaries`) and runs `platformctl diskimage create`, which does the
rest: it generates the Secure Boot keys in `UBOOT_KEYS_DIR` (default
`~/.trusted-platform/secure-boot`) when they do not exist yet, builds U-Boot
with that key set preseeded into `UBOOT_OUTPUT_DIR` (or reuses the build
there when its manifest carries the same key set), builds the assemble
container, and assembles the image. Extra flags go in `DISKIMAGE_FLAGS`, for
example `DISKIMAGE_FLAGS='--overrides node.yaml'` to set
`seal-pcrs: [0, 4, 7, 9]` or a hostname. The full flag list is in [cli.md](cli.md).

**Keep the key directory.** A new key set means a new U-Boot build, and a
card built with one key set does not boot a UKI signed with another. To
build U-Boot on its own for an existing key set, `make uboot-build` still
does exactly that and stops if `PK.crt`, `KEK.crt` or `DB.crt` is missing.

For the emulated stand-in: `make image-rpi-qemu` produces
`bin/trusted-platform-qemu-virt.img`, booted with
`qemu-system-aarch64 -M virt -bios build/docker/uboot-builder/output/qemu_arm64/u-boot.bin`
and a software TPM. That image carries a kernel the platform builds rather
than Alpine's (`make virt-kernel-build`, run for you by `make image-rpi-qemu`
and cached by its inputs; the first build cross-compiles Linux and takes
about twenty minutes): no Alpine aarch64 kernel has the memory-mapped TPM
driver QEMU's `tpm-tis-device` needs, so on a stock kernel the first boot
would find no TPM to seal to. The Pi image itself keeps Alpine's
`linux-rpi`. Details in [architecture.md](architecture.md) §2.

## Verify before flashing

```sh
platformctl diskimage inspect bin/trusted-platform-rpi.img
```

Expect: `p1 type=0x0c ... boot`, `ESP: true`, `LUKS2 root: true`,
`installer.luks: true` (it has not booted), `provisioned sentinel: true`, a
UKI at `EFI/BOOT/BOOTAA64.EFI` with `machine=0xaa64 signed=true`, a
`config.txt` naming `kernel=kernel8.img` and `dtoverlay=tpm-soft-spi`, and
the firmware files (`start4.elf`, `fixup4.dat`, the board `.dtb` files,
`overlays/`) on the ESP.

## Boot it under emulation first

The `qemu-virt` image is the same build for the QEMU virt machine (only the
kernel package differs: `linux-lts`, because the Pi kernel has no virtio).
Booting it proves the whole chain — U-Boot, Secure Boot verification of the
UKI and of the kernel inside it, the initrd, firstboot sealing, platformd —
on your workstation, with a software TPM, before a card is written:

```sh
make image-rpi-qemu                          # bin/trusted-platform-qemu-virt.img
make devcontainer-shell                      # qemu-system-aarch64 lives in the devcontainer
platformctl diskimage test boot              # interactive console; Ctrl-A X quits
```

Unattended, waiting for the first-boot milestone and keeping the transcript:

```sh
platformctl diskimage test boot --serial-log work/diskimage-test/boot1.log \
  --expect "platformd" --forward 18443:8443
```

`make integration-test-diskimage` runs the same boot as a test suite (image
layout, U-Boot with the TPM at its prompt, first boot, second boot unsealing
against the sealed PCRs) and takes 30-60 minutes under TCG emulation. Every
boot logs `Cannot persist EFI variables without system partition` from
U-Boot: expected, see [architecture.md §6](architecture.md#6-trust-boundaries).

## Flash

```sh
lsblk                                        # find the card; it must show RM=1
make rpi-sdcard RPI_SDCARD=/dev/sdX RPI_SDCARD_CONFIRM=yes
```

This is the only step that uses `sudo`. It refuses to run unless the path is
a block device, is removable, is not the disk holding your running root
filesystem, `RPI_SDCARD_CONFIRM=yes` is set, and the image exists. It writes
with `dd ... conv=fsync`; wait for it to return before pulling the card.

## First boot

Connect the serial console, insert the card, power on. In order:

1. The firmware's own log (`uart_2ndstage=1`), then the **U-Boot banner** with
   the pinned version. There is a one-second autoboot delay; interrupting it
   and running `tpm2 info` shows whether U-Boot can talk to the TPM.
2. `Booting /EFI/BOOT/BOOTAA64.EFI` — the boot manager found the UKI on the
   first FAT partition and the Secure Boot check passed.
3. The kernel, then `platform-initrd` opening the installer container and
   unlocking the root.
4. **firstboot**: TPM provisioning, then sealing the disk key to the live
   PCRs, then the secure wipe of the installer container. Expect a minute or
   more; the bit-banged TPM bus is slow.
5. `platformd` starting. The node is now provisioned; enrolment and
   attestation continue as for any node ([`docs/provisioning/`](../provisioning/)).

## Verify on the node

```sh
ls -l /dev/tpm0 /dev/tpmrm0
dmesg | grep tpm_tis_spi                      # the TPM bound over spi-gpio
tpm2_pcrread sha256:0,4,7,9
ls /boot/efi/tpm2/                            # installer.luks must be gone
```

PCR 0 holds only U-Boot's version measurement; 4 and 7 are the UKI and the
Secure Boot state; 9 the initrd. All four are non-zero after a good boot.

IMA (PCR 10) is not available on the Pi: the Alpine `linux-rpi` kernel is
built without it. Do not enable the IMA feature on these nodes.

## Troubleshooting

| Symptom | Meaning | Do |
|---|---|---|
| `no binfmt handler` or `lacks the F flag` at build time | the host cannot run arm64 containers | `make init`, or re-register with `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes` |
| `kernel module loop is not loaded` | | `modprobe loop`; likewise `dm_crypt` |
| `no platformd in ...` | arm64 binaries not built | `make rpi-binaries`, or pass `--binaries-dir` |
| `missing Secure Boot certificate` from the U-Boot build | `UBOOT_KEYS_DIR` lacks `PK.crt`, `KEK.crt`, `DB.crt` | point it at the keys `iso create` or a previous build generated |
| `boot firmware file ... was not produced` | a required file did not come out of the packages or the U-Boot output | check the pre-fetch completed and `make uboot-build` produced `overlays/tpm-soft-spi.dtbo` |
| Nothing on serial after the firmware log | U-Boot did not start | re-inspect the image: `kernel8.img`, `config.txt` and the board `.dtb` must be on the ESP; try the serial adapter on GPIO 14/15 |
| U-Boot starts, no `Booting /EFI/BOOT/BOOTAA64.EFI` | the UKI failed verification or is missing | the U-Boot keys and the UKI signature are from different key sets; rebuild both with one `UBOOT_KEYS_DIR` |
| First boot ends with a **fallback** message and `/boot/efi/tpm2/installer.luks` is still present | sealing failed; the node unlocked with the plain key and kept the container so the boot can be retried | almost always the TPM: check `dmesg | grep -i tpm`, the overlay (`dtoverlay=tpm-soft-spi` in `config.txt`) and the wiring on SPI0 CE1; power-cycle and boot again — the container is preserved for exactly this |
| The node boots but `tpm2_pcrread` shows PCR 4 or 7 as zero | U-Boot booted the UKI without measuring or without Secure Boot | the U-Boot on the card is not the platform build; rebuild the image |

Until the fallback message is gone and `installer.luks` has been wiped, the
card still holds the disk key in the clear-enough container described in
[architecture.md §6](architecture.md#6-trust-boundaries); keep it in hand.
