# Factory Image — Using It

> **Status: REFERENCE** · Scope: building, flashing and first-booting a Raspberry Pi factory image · Last verified: 2026-10-09
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

> **Partly built: the measurement manifest.** The SPEC row's
> [acceptance](../SPEC.md#features) says every image carries a signed CoRIM of
> the PCR values it determines, registered in the go-quicbaas
> reference-values store. A Secure Boot image built with
> `--manifest-key kms://<key>` gets `measurements.corim` beside it, signed in
> the KMS (`--manifest-cert` names the key's certificate on the platform CA
> when it is not the key's ID). Without the flag, or with Secure Boot off,
> the build writes none and says why. Nothing is registered yet, so a node's
> quote is still checked against its device profile's `PCRBaseline` table. The registration verbs ship in
> go-quicbaas v0.14.0-alpha; the platform pins v0.12.0-alpha (#720). The
> design is [architecture.md §8](architecture.md#8-measurement-manifest), and
> the plan is [docs/plans/669.md](../plans/669.md).

## Prerequisites

On the build host:

- Docker with `buildx`, and a binfmt handler for arm64 registered with the
  `F` flag so a chroot inside an arm64 container can run. `make init`
  installs the packages and ends in `make binfmt`, which registers the
  pinned `tonistiigi/binfmt` handler with the `F` flag.
- The `loop` and `dm_crypt` kernel modules loaded (`modprobe loop dm_crypt`).
- `mtools` (`mdir`, `mcopy`) if you want to inspect images.
- Enough disk for the pre-fetched packages, the media and a 4 GB sparse image.

The build fails early, with the remedy, if any of the first two is missing.

On the device:

- A Raspberry Pi 4 Model B with 2 GB of RAM or more, 400, Compute Module 4 or
  3 Model B+. The Pi 5 is experimental, and its OTP is never burned
  ([step 6](#6-burn-the-otp-hash--irreversible)).
- The 3 Model B+ has no EEPROM, so signed HTTP boot refuses it; its network
  boot path is not documented.
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
kernel differs: `linux-virt`, the platform-built kernel described above,
because the Pi kernel has no virtio).
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

Connect the serial console and an HDMI display, insert the card, power on.
The serial line carries the firmware, U-Boot and the kernel log; the kernel
command line ends in `console=tty1`, so `platform-initrd`, firstboot and
`platformd` print to HDMI
([kernel-cmdline.md §5](../reference/kernel-cmdline.md#5-hardware-specific-parameters)).
In order:

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

## CM4 SD card

A Compute Module 4 as a standalone control plane, booted from an SD card.
It is built from `dedicated/raspberrypi/cm4/control-plane.yaml` with the
desk overrides beside it: static 192.0.2.10/24 on an untagged eth0, VLAN 405,
no gateway. What the control plane does without a gateway is in the
[templates README](../../configs/platform/templates/dedicated/raspberrypi/README.md#control-plane).

The board:

- A **CM4 Lite** (no eMMC), or a carrier whose SD slot the CM4 boots from. A
  CM4 with eMMC boots its eMMC, not the SD slot; writing the image to eMMC is
  not covered here.
- The **TPM HAT** on SPI0 chip-select 1, wired as in
  [Prerequisites](#prerequisites). Without it the first boot has nothing to
  seal to and ends in the fallback ([Troubleshooting](#troubleshooting)).
- The **serial console** on the primary UART (GPIO 14/15), 115200 baud.
- 8 GB of RAM. The template is sized for it; confirm it at the first login
  (below).

Build, compress and check the image. `image-rpi-xz` keeps the `.img` and
writes the `.xz` beside it:

```sh
make image-rpi-xz DISKIMAGE_MODEL=cm4 \
  DISKIMAGE_FLAGS='--role control-plane --overrides configs/platform/templates/dedicated/raspberrypi/cm4/desk-overrides.yaml' \
  DISKIMAGE_OUTPUT=bin/trusted-platform-cm4-cp.img
sha256sum bin/trusted-platform-cm4-cp.img.xz    # record it; check it again on the host that writes the card
```

Write the card by hand. Unlike `make rpi-sdcard`, `dd` checks nothing, so
find the card with `lsblk` first: it must show `RM=1` and the size of the
card, and must not hold your root filesystem.

```sh
lsblk -o NAME,SIZE,RM,TYPE,MOUNTPOINTS
xzcat bin/trusted-platform-cm4-cp.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
```

(`make rpi-sdcard RPI_SDCARD=/dev/sdX RPI_SDCARD_CONFIRM=yes
DISKIMAGE_OUTPUT=bin/trusted-platform-cm4-cp.img` writes the uncompressed
image with those checks.)

Boot it with the serial console attached and watch the
[first boot](#first-boot). Then, on the node:

```sh
ls -l /dev/tpm0 /dev/tpmrm0                    # the TPM HAT is present
dmesg | grep tpm_tis_spi
ls /boot/efi/tpm2/                             # firstboot done: installer.luks is gone
grep MemTotal /proc/meminfo                    # about 8 GB
platformctl health --detailed
```

`platformctl health` exits 0 on an unhealthy platform; read the overall
status and the component table, not `$?` ([health CLI](../health/cli.md#4-exit-codes)).

## Provision a fleet: signed HTTP boot

A Pi can skip the SD card's first stage and boot from the network instead. Its
bootloader EEPROM fetches `boot.img` (the boot partition as a FAT ramdisk: the
firmware, `config.txt`, U-Boot as `kernel8.img`) and `boot.sig` from the boot
container over HTTP. With `SIGNED_BOOT=1` the EEPROM runs the image only if
`boot.sig` verifies against the **fleet public key whose SHA-256 is burned in
the Pi's OTP**. Whoever controls the network cannot substitute a first stage;
only the holder of the fleet private key can sign one — and that key lives in
the platform KMS, which is sent a digest and never gives the key out.

> [!CAUTION]
> **Burning the key hash into OTP is IRREVERSIBLE.** OTP bits can be set and
> never cleared. The hash cannot be changed, removed or replaced afterwards: a
> board with the wrong hash burned can never verify a `boot.sig` from the
> right key, and a board whose key you have lost can never boot a new first
> stage. Burn one sacrificial board first. Take the hash from
> `platformctl diskimage netboot`'s output (or the SHA-256 of `pubkey.bin`)
> and check it twice. Everything before step 6 is reversible.
>
> **Pi 5 / CM5: do not burn.** Their OTP burn is UNSUPPORTED until Phase 6
> hardware validation (#692); see step 6.

### 1. Make the fleet key

Use one stable key id for the private key and the companion certificate. The
private key is an RSA-2048 signing key in the KMS - the only size the
bootloader verifies - and deletion protection is recommended because this key
is a fleet root of trust.

```sh
sudo platformctl kms key generate rpi/fleet --algorithm rsa-2048 \
  --purpose sign --deletion-protection
sudo platformctl kms key csr rpi/fleet --out fleet.csr
sudo platformctl ca sign-csr fleet.csr --out fleet.pem
```

`ca sign-csr` is a platform-admin operation: run it as root on the platformd
host, or with a platform token granting `ca:sign-csr` (`certs:generate` is
not enough). The certificate it issues is for **code signing only** — extended
key usage `codeSigning`, key usage `digitalSignature`, subject `CN=rpi/fleet`
and nothing else — so it can sign boot artifacts but never act as a TLS
identity. The CA refuses a CSR with any other subject field or a SAN.

The certificate must hold **the KMS key**: the KMS signs the CSR for its own
key, and the CA checks the CSR's key against the KMS key it names before
certifying it, generating nothing. Do not use
`ca issue` here — it always generates a new key, so its certificate would
certify a key the KMS does not hold, and every `boot.sig` would fail against
it. The CA stores the certificate under the key id, and
`secureboot.NewKMSSigner` fetches it by that id when `--fleet-cert` is
omitted; `platformctl ca certificate rpi/fleet --pem` prints it again. `fleet.pem` is the public key/certificate material
for Raspberry Pi's EEPROM tooling; the private key never exists as a file.

**Record the certificate's fingerprint.** `ca sign-csr` prints it as
"SHA-256 Fingerprint" (`openssl x509 -in fleet.pem -noout -fingerprint
-sha256` gives the same value with colons). Keep it with the change record:
every later step pins the fleet certificate to it.

```sh
FLEET_FP=<the SHA-256 Fingerprint ca sign-csr printed>
```

### 2. Build the media with it

```sh
platformctl diskimage netboot --sets aarch64-rpi --fleet-key kms://rpi/fleet \
  --fleet-cert "kms://rpi/fleet#sha256=${FLEET_FP}" \
  --uboot-dir build/docker/uboot-builder/output       # plus the flags in cli.md §2a
```

(`--fleet-key` takes the same `kms://` form as `secure-boot.db`; the build
reaches the KMS through the platform context, `--context`, and fetches the
certificate from `--fleet-cert` or the key id.) The `#sha256=` pin makes the
build refuse any certificate under `rpi/fleet` but the one you recorded, so
a certificate replaced in the CA cannot slip a different public key into
`pubkey.bin` and the OTP hash. Besides the media set and the
TFTP tree this writes `http-boot/{boot.img,boot.sig,pubkey.bin}` and prints:

```
HTTP boot (bin/netboot-media/http-boot):
  OTP customer key hash: 3f9a…c1
  EEPROM: HTTP_HOST=<the container's address> HTTP_PORT=8080 HTTP_PATH=data/http-boot SIGNED_BOOT=1
  boot.img: 524288 bytes
```

Before it returns, the build reads the files back and verifies them the way
the EEPROM does — `pubkey.bin` against the hash, `boot.sig` over `boot.img` —
so a KMS key of the wrong size, or a signature the bootloader would reject,
fails the build and not the Pi. `--source-date-epoch` pins `boot.sig`'s `ts`
for a reproducible build. Pi 3B+ has no EEPROM and is refused.

### 3. Serve it

`deployer.netboot_media_dir` points at the build as for any netboot media; the
deployer stages `http-boot/` into the container's data directory, and the
container serves it at `http://<container>:<bootstrap_http_port>/data/http-boot/`
(`bootstrap_http_port`, default 8080). `HTTP_PATH` is therefore
`data/http-boot`. It is plain HTTP on the boot segment: `boot.sig`
authenticates the image, so the transport adds no integrity (see the HTTPS
note in step 7).

### 4. Prove it before touching a Pi

From any host on the boot segment, speak the bootloader's side of it, with the
key and hash **the Pi will hold**:

```sh
platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 \
  --pubkey bin/netboot-media/http-boot/pubkey.bin --otp-key-hash 3f9a…c1
```

It fetches both files, checks the key against the hash, verifies the
signature and mounts the image, and fails on whatever the EEPROM would refuse
(a tampered image, a signature by another key, an OTP hash of another key). A
green probe means the files are right; it cannot say the EEPROM accepts them
(see *What hardware must still confirm*).

### 5. Configure the EEPROM

On a Pi with a current bootloader (`rpi-eeprom-update`; bootloader
configuration is edited with `rpi-eeprom-config`), in the EEPROM's config:

```ini
BOOT_ORDER=0xf17          # nibbles read right to left: 7 = HTTP, 1 = SD card, f = start over
HTTP_HOST=10.99.99.1      # the container address
HTTP_PORT=8080            # bootstrap_http_port from bootstrap.yaml
HTTP_PATH=data/http-boot
SIGNED_BOOT=1
```

`BOOT_ORDER` is the operator's call: `0x7` alone makes the network the only
way in, and `0xf17` falls back to an SD card when the container is down. A
fallback to the card is a fallback to the card's unauthenticated FAT
partition - leave it out on a fleet that must not run an unsigned first
stage.

With `SIGNED_BOOT=1` the EEPROM config is signed too, and the EEPROM image
embeds the fleet public key. That key is not signed: the bootloader checks its
hash against the one burned into OTP. The upstream digest tool calls an HSM
wrapper as `<wrapper> -a rsa2048-sha256 <file>` and expects the RSA signature as hex on
stdout; this repo ships `scripts/rpi-eeprom-kms-hsm-wrapper.sh`, which forwards
that contract to `platformctl diskimage rpi-eeprom-hsm` and signs through the
same KMS signer as `boot.sig`.

```sh
export RPI_EEPROM_FLEET_KEY=kms://rpi/fleet
export RPI_EEPROM_FLEET_CERT="kms://rpi/fleet#sha256=${FLEET_FP}"
rpi-eeprom-digest -H ./scripts/rpi-eeprom-kms-hsm-wrapper.sh \
  -i bootconf.txt -o bootconf.sig
rpi-eeprom-config --config bootconf.txt --digest bootconf.sig \
  --pubkey fleet.pem --out pieeprom-signed.bin pieeprom.bin
```

`rpi-eeprom-config --pubkey` takes a PEM file (`fleet.pem`), not the
platform's `pubkey.bin` key blob. `pubkey.bin` remains the OTP/probe artifact:
its SHA-256 must equal the customer key hash you burn.

### 6. Burn the OTP hash — IRREVERSIBLE

> [!CAUTION]
> This is the one step that cannot be undone. Re-read the box above.

> [!WARNING]
> **Pi 5 / CM5: the OTP burn is UNSUPPORTED until Phase 6 hardware validation
> (#692).** Their EEPROM also runs a customer-signed first stage
> (`bootcode.bin`) whose signing this runbook does not yet cover (step 7). A
> Pi 5 or CM5 burned now can be left unable to boot anything. Burn Pi 4 / 400 /
> CM4 only.

Use the Raspberry Pi bootloader's own secure-boot provisioning from
`raspberrypi/usbboot`'s `secure-boot-recovery`, whose recovery `config.txt`
carries `program_pubkey=1`, and `revoke_devkey=1` to retire the ROM's
development key. The recovery image programs the SHA-256 of the key in the
EEPROM image into OTP. Confirm the hash it burns equals the one the build
printed. Afterwards the Pi must boot a `boot.sig` made by the fleet key, which
the steps above already proved against the probe.

### 7. Pi 5, CM5 and a private CA

`boot.sig` omits `target-soc` by default. Keep it that way for fleet media
unless a hardware validation run needs the explicit field; then pass
`platformctl diskimage netboot --target-soc 2712` for Pi 5/CM5 or `2711` for
Pi 4/400/CM4.

> [!WARNING]
> **Pi 5 / CM5 secure boot is UNSUPPORTED until Phase 6 hardware validation
> (#692). Do not burn their OTP.** On the 2712 the customer key must also sign
> the EEPROM's first-stage `bootcode.bin`, and that signing is not the
> `rpi-eeprom-digest` flow above. An earlier revision of this page signed
> `bootcode.bin` and `bootsys.bin` that way and embedded them with
> `rpi-eeprom-config -b`/`-s`. Those steps were wrong and have been removed.
> Until #692 validates the 2712 bootcode signing on hardware, the steps on
> this page are for Pi 4 / 400 / CM4. For Pi 5 / CM5 they cover the parts
> short of the burn: `boot.img`/`boot.sig` and the probe.

The platform serves plain HTTP, so no CA is involved by default. If the boot
network requires HTTPS, put the container behind a TLS terminator; the
bootloader then has to trust that certificate from CA certificates held in its
own EEPROM image, not from the platform's trust store. A private platform CA
therefore has to be embedded in the EEPROM image with the `rpi-eeprom` tooling
and re-embedded on every Pi (an EEPROM update) each time that CA rotates.
Whether the Pi 5 and CM5 accept a custom CA on the bootloader release you
flash is **not validated here**; it is on the list below.

### Rotating the fleet key

OTP holds one customer key hash and holds it forever, so **there is no
rotation without new boards**. Treat the fleet private key as a root of trust:
KMS access control, audit and backup apply, and losing it strands every
burned Pi. A compromised key means the fleet's first stage can no longer be
trusted and the boards need replacing.

### What hardware must still confirm

The pipeline above is exercised under emulation (`pkg/rpinetboot`'s HTTP-boot
client is the EEPROM's, byte for byte on the signature, the key blob and the
hash; golden vectors from upstream's `rpi-eeprom-digest` pin the format). A
real Pi must still show — this is Phase 6 of the epic:

- the EEPROM **accepts** the signed `boot.img`/`boot.sig` pair, with
  `target-soc` omitted by default and with an explicit `target-soc: 2711` or
  `target-soc: 2712` when a validation image is built that way;
- the EEPROM accepts the signed-config path from step 5: `bootconf.txt`,
  `bootconf.sig`, and the PEM-derived key embedded by `rpi-eeprom-config`;
- the 2712 bootcode signing for Pi 5/CM5: how the customer key signs the
  EEPROM's first-stage `bootcode.bin` with the fleet KMS key, and that a
  2712 with the OTP burned boots it. Until this is validated, the Pi 5/CM5
  OTP burn is unsupported (step 6);
- `HTTP_HOST`/`HTTP_PORT`/`HTTP_PATH` are read as above, including whether the
  port belongs in `HTTP_HOST`;
- the OTP programming path of step 6, on the bootloader release you flash;
- the largest `boot.img` the EEPROM takes (the emulated client's limit is
  `rpinetboot.MaxImageBytes`, 256 MiB; the EEPROM's is its own), and that the
  container's HTTP server's 30 s read/write timeout is long enough for a large
  image on a slow link;
- the EEPROM FAT reader accepts both VFAT long names and lowercase 8.3 short
  names with NT case flags as written by the platform image;
- the HTTPS and custom-CA behaviour of step 7 on the Pi 5 and CM5.

## Troubleshooting

| Symptom | Meaning | Do |
|---|---|---|
| `probe rpi-http` fails `digest mismatch` | `boot.img` on the server is not the one `boot.sig` signed | rebuild and redeploy the media; the deployer replaces `http-boot/` whole |
| `probe rpi-http` fails with a key hash mismatch | `pubkey.bin` does not hash to `--otp-key-hash` | you gave the probe a different fleet's key or hash; take both from the build's output |
| `probe rpi-http` fails with a 404 | the container does not serve `http-boot/` | the build was made without `--fleet-key`, or `netboot_media_dir` is stale |
| `--fleet-key` is refused: not a `kms://` reference | | generate the key in the KMS and pass its reference |
| `no binfmt handler` or `lacks the F flag` at build time | the host cannot run arm64 containers | `make binfmt` (part of `make init`): it registers the pinned `tonistiigi/binfmt` handler with the `F` flag |
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
