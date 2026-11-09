# Raspberry Pi Templates

Single-node platform on a Raspberry Pi, shipped as a factory SD-card image
rather than an installer ISO: `platformctl diskimage create --target rpi
--model <model>` picks `raspberrypi/<model>/default.yaml` automatically
(`make image-rpi` builds the `rpi4` one). The feature is documented in
[docs/factory-image/](../../../../../docs/factory-image/); the hardware
runbook is its [user.md](../../../../../docs/factory-image/user.md).
A Pi as a compute node of the dedicated profile is built with `--role
compute`, and a CM4 or Pi 4 as a standalone control plane with `--role
control-plane`, from [`dedicated/raspberrypi/`](../../dedicated/raspberrypi/README.md);
the hardware prerequisites below apply to them too (to the Pi 4 and CM4 — the
experimental Pi 5 compute template lists what differs there).

| Model directory | Board | Device tree | Status |
|---|---|---|---|
| `rpi4/` | Raspberry Pi 4 Model B | `bcm2711-rpi-4-b.dtb` | Image builds and boots on the QEMU virt stand-in; hardware validation per the runbook |

Without `--role`, the other boards the image builder knows (the Pi 400,
`cm4`, `rpi3b+`, `rpi5`) fall back to `single-node/default.yaml` until they
get a directory here; copy `rpi4/default.yaml` and change `hardware-model` and
`os.hostname`. With `--role` nothing falls back: `--model cm4 --role
control-plane` builds the dedicated CM4 control plane, and the Pi 5 has only
the experimental dedicated compute template.

## Hardware prerequisites

- Raspberry Pi 4 Model B, 2 GB RAM or more, booting from the SD card.
- Infineon SLB9670 TPM 2.0 on SPI0 chip-select 1 with reset on GPIO 24
  (Infineon Iridium 9670, LetsTrust TPM and compatibles). U-Boot and Linux
  both drive it as a GPIO bit-banged bus (`dtoverlay=tpm-soft-spi`), so the
  HAT must be on SPI0's pins (SCLK 11, MOSI 10, MISO 9, CE1 7).
- An HDMI display and a serial console on GPIO 14/15 at 115200 8N1 (a
  USB-TTL adapter). Bluetooth is moved off the PL011 so the serial console
  is `ttyAMA0` (`console=ttyAMA0,115200`); it carries the firmware log,
  U-Boot and the kernel log. The kernel command line ends in
  `console=tty1`, so HDMI is `/dev/console`: `platform-initrd`, firstboot
  and `platformd` print to the display, not to the serial line.
- Ethernet on `eth0` (DHCP by default).

## What the template changes against `single-node/default.yaml`

| Key | Value | Why |
|---|---|---|
| `os.architecture` | `aarch64` | Alpine aarch64 packages and binaries |
| `os.kernel-package` | `linux-rpi` | the Alpine Raspberry Pi kernel (EFI stub, `tpm_tis_spi`) |
| `disk.device` | `/dev/mmcblk0` | the SD card on the Pi (the build host uses a loop device) |
| `disk.partition-table` | `mbr` | the Pi firmware reads only an MBR; p1 is FAT32 (type `0x0c`, boot flag) |
| `install-target` | `image` | Phase A runs on the build host; host-only steps are skipped |
| `boot.firmware` | `uboot` | the firmware files go onto the boot partition; Secure Boot keys are preseeded in U-Boot |
| `hardware-manufacturer` / `hardware-model` | `Raspberry Pi` / `Raspberry Pi 4 Model B` | the `pkg/quirks` entry: `console=ttyAMA0,115200 console=tty1 rootwait` |
| `seal-pcrs` | `[0, 4, 7, 9]` | U-Boot's TCG2 measures PCR 0 (U-Boot version), 4 (the UKI), 7 (Secure Boot state); the EFI stub measures 9 |
| `uki.kernel-path` / `initramfs-path` | `/boot/vmlinuz-rpi` / `/boot/initramfs-rpi` | the `linux-rpi` file names |
| `os.hostname` | `rpi4.trusted-platform.local` | per-node; override it |

Everything else is the single-node reference configuration, and the same
`--overrides` file that customises the x86 template customises this one.

## Trust model, stated

The root of trust is the U-Boot binary on the unauthenticated FAT boot
partition (Raspberry Pi OTP signed boot is out of scope). From there the
chain is the x86 chain: U-Boot verifies the signed UKI against the
preseeded db, measures it into the TPM, the initrd unseals the LUKS key
against the PCRs, and platformd enrols and attests. PCR 0 binds the U-Boot
version only. `ubootefi.var` on the boot partition holds the
non-authenticated EFI variables and is writable by anyone with the card;
the authenticated ones (PK, KEK, db) are compiled into U-Boot and cannot be
changed from the card.
