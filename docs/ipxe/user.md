# iPXE Network Boot — Using It

> **Status: REFERENCE** · Scope: booting a bare machine over the network · Last verified: 2026-08-18
> Task-oriented, in the order you do things. Internals are in
> [engineering.md](engineering.md); the design is in
> [architecture.md](architecture.md).
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

A machine with no operating system broadcasts on the network, and this answers.
It hands the firmware an iPXE binary over TFTP, then hands iPXE an HTTP boot
script, then serves the kernel and initrd. From there the installer takes over
([`docs/installer/`](../installer/)).

Two things to internalise before you plug anything in:

1. **There is no authentication anywhere in this path.** A machine is
   identified by a MAC address it claims. Anything on the segment can claim any
   MAC and receive that MAC's hostname and installer config. **Run this on an
   isolated provisioning network.** That is not a suggestion; it is the only
   control.
2. **Whatever this server hands out is what the machine executes.** If you can
   change the boot server, you own every node that boots from it.

---

## Prerequisites

- A network segment you control, ideally a dedicated provisioning VLAN.
- **No other DHCP server on it**, unless you know exactly how the two will
  interact. This one answers PXE clients by default and can be told to answer
  everyone.
- Privilege to bind UDP 67 and UDP 69 — root, or `CAP_NET_BIND_SERVICE` (plus
  `CAP_NET_RAW` if you use the raw-socket DHCP path).
- Outbound HTTPS to `boot.ipxe.org` **the first time**, so the iPXE firmware can
  be downloaded. After that it is cached and the server works offline.
- A netboot media build staged under the data directory (`make netboot-media`
  builds one; `bootstrap run` stages it for you), and a `manifest.yaml`
  describing which MAC boots what.

---

## 1. Run the boot server

```bash
pxeboot \
  --manifest /data/manifest.yaml \
  --media-dir /data/media \
  --interface eth0 \
  --dhcp-server-ip 10.10.0.1 \
  --dhcp-range-start 10.10.0.100 \
  --dhcp-range-end 10.10.0.200 \
  --dhcp-gateway 10.10.0.1 \
  --dhcp-dns 10.10.0.1
```

Five flags are required — `--manifest`, `--media-dir` (it defaults to
`/data/media`), `--dhcp-server-ip`, `--dhcp-range-start`, `--dhcp-range-end`. If any is missing
you get one message naming all of them, then usage, then exit 1.

Two more you will usually want:

```bash
  --apk-mirror http://mirror.example.com:8080 \
  --alpine-version 3.22.2
```

**`--alpine-version` must match the media build's Alpine release.** It
derives the package repository branch the live environment uses. Mismatch it and
the installer boots fine and then cannot resolve a single package.

**`--apk-mirror` matters specifically for PXE.** A PXE-booted node has no
CD-ROM, so it cannot fall back to packages on the media. Point it at a mirror
it can reach, or leave it empty to use the public Alpine mirror — which only
works if the provisioning network has outbound internet.

`Ctrl-C` or `SIGTERM` shuts it down cleanly. Logs are JSON on stdout.

---

## 2. Tell it what each machine should boot

Stage the per-node values before the machine boots:

```bash
curl -X PUT --data-binary "node-01.example.com" \
  http://10.10.0.1:8080/config/mac/aa-bb-cc-dd-ee-ff/hostname

curl -X PUT --data-binary @node-01-installer.yaml \
  http://10.10.0.1:8080/config/mac/aa-bb-cc-dd-ee-ff/installer.yaml
```

Read them back to confirm:

```bash
curl http://10.10.0.1:8080/config/mac/aa-bb-cc-dd-ee-ff/hostname
```

**The MAC must be lowercase and dash-separated here.** `AA:BB:CC:DD:EE:FF` and
`aa:bb:cc:dd:ee:ff` are both rejected with a 400. Confusingly, the
`/boot/device/{mac}.ipxe` route accepts either form and any case — the two
routes normalise differently. When in doubt, use lowercase dashes for `/config`
and copy the exact string from your manifest for boot scripts.

Values are capped at 256 KiB, which comfortably fits a fully merged
`installer.yaml` (typically 10–40 KiB).

**Anyone who can reach port 8080 can read or overwrite these.** They contain a
LUKS passphrase and a root password. Isolate the network.

---

## 3. Boot the machine

Set the machine to PXE boot and power it on. What you should see, in order:

1. The firmware DISCOVERs and gets an offer with a boot filename.
2. It TFTPs `ipxe.efi` (or `ipxe32.efi`, or `undionly.kpxe` on legacy BIOS).
3. iPXE starts, DISCOVERs again, and is handed
   `http://<server>:8080/boot.ipxe`.
4. It chains to `/boot/device/<mac>.ipxe`: a MAC the manifest knows boots its
   media set with its role and hostname; any other MAC gets 404 and falls
   through to its architecture's default media set (`/menu.ipxe` only for
   an architecture with none).
5. It fetches the kernel and initrd from `/data/…` (`/data/media/<set>/…` for
   a set other than the x86_64 installer).
6. The installer runs.

The server's request log is the fastest way to watch this. Every HTTP request is
logged with method, path, status and duration.

---

## 4. Read the install log afterwards

The autoinstall script uploads `/tmp/install.log` on **every** exit path,
success or failure, so you have a post-mortem even though the install
environment has already rebooted.

```
http://10.10.0.1:8080/installs/
http://10.10.0.1:8080/installs/node-01.example.com/
http://10.10.0.1:8080/installs/node-01.example.com/install.log
```

Browse the index in a browser or `curl` the file. On disk it is under
`<InstallsDir>/{hostname}/{filename}`, default `/data/installs`. Uploads are
capped at 16 MiB and written via a `.partial` file plus an atomic rename, so a
log you can see is a log that finished uploading.

---

## 5. Test it without hardware

```bash
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso
```

This builds an isolated bridge (`pxe-br`, `10.99.99.0/24`), starts a PXE server
on it, extracts kernel and initrd from the ISO, and boots a QEMU client. It
**requires root** for bridge and TAP creation and says so up front.

Override the boot source if you are not testing a whole ISO:

```bash
sudo platformctl iso test pxe \
    --kernel ./vmlinuz --initrd ./initramfs --args "console=ttyS0"
```

For a Raspberry Pi, test from U-Boot onward: `--architecture aarch64` boots
the QEMU `virt` machine from the same U-Boot the factory image puts on the
card (`make uboot-build`), so the DHCP exchange, the signed arm64 iPXE, the
architecture-aware script and the signed kernel are all the ones a Pi sees.
What it cannot stand in for is the Pi's own EEPROM netboot client, which
runs before U-Boot; that stage is covered by the Raspberry Pi netboot
emulator and by hardware ([factory image](../factory-image/user.md)).

```bash
sudo platformctl iso test pxe --architecture aarch64 \
    --kernel ./vmlinuz-lts --initrd ./initramfs-lts \
    --args "console=ttyAMA0,115200 ip=dhcp" \
    --serial-log work-pxe/serial.log --expect "Welcome to Alpine"
```

`make integration-test-netboot` runs exactly that in the devcontainer,
after `make uboot-build` and `make ipxe-build` (the platform builds its own
arm64 iPXE: upstream's hangs under U-Boot) and after fetching Alpine's
aarch64 netboot kernel, initramfs and modloop into `bin/`. The guest's
initramfs installs `alpine-base` from the Alpine mirror through the boot
server's HTTPS relay (`/proxy/https/…`), so the host needs internet access
for the suite; `NETBOOT_ALPINE_MIRROR` and `NETBOOT_ALPINE_BRANCH` pick the
mirror.

---

## Raspberry Pi on hardware

Four steps, in this order: each one proves what the next one stands on. The
board is a Raspberry Pi 4 Model B with 2 GB of RAM or more, and an Infineon
SLB9670 TPM on SPI0 chip-select 1. The image seals the disk key to that TPM
and first boot expects it there
([prerequisites](../factory-image/user.md#prerequisites)). The Pi 5 is
experimental and its OTP is never burned. The 3B+ has no EEPROM, so signed
HTTP boot refuses it; its network boot path is not documented and it has no
template.

**The console.** Wire a USB serial adapter to the primary UART, GPIO 14/15,
at 115200 baud. The image moves Bluetooth off that UART
(`dtoverlay=disable-bt`), so it is `ttyAMA0`, and turns on the firmware's own
log there (`uart_2ndstage=1`). The serial line carries the firmware, U-Boot
and the kernel log. The kernel command line ends in `console=tty1`, which
makes HDMI `/dev/console`: OpenRC, first boot and `platformd` print to the
display, not to the serial line
([kernel-cmdline.md §5](../reference/kernel-cmdline.md#5-hardware-specific-parameters)).
Watch both.

The EEPROM settings below are edited with `rpi-eeprom-config`. `BOOT_ORDER`
is read right to left, one nibble per boot mode. The platform's code names
one value, `0xf21` for `boot_model: sd`, where the bootloader tries the card
(`1`) first. The other nibbles are the Raspberry Pi bootloader's: `2` is the
network (DHCP and TFTP), `7` HTTP, and `f` starts over. The platform sets no
`BOOT_ORDER`; every value below is the operator's EEPROM setting.

### Step 1: the SD image

No boot server and no `bootstrap.yaml` node. Build the image, then write the
card by hand on the build host; `rpi-sdcard` is the only `make` target that
uses `sudo`:

```sh
make image-rpi
make rpi-sdcard RPI_SDCARD=/dev/sdX RPI_SDCARD_CONFIRM=yes
```

Then follow the factory image's [Flash](../factory-image/user.md#flash),
[First boot](../factory-image/user.md#first-boot) and
[Verify on the node](../factory-image/user.md#verify-on-the-node). First boot
names five milestones, in order: the firmware log and the U-Boot banner,
`Booting /EFI/BOOT/BOOTAA64.EFI`, the kernel and `platform-initrd`, firstboot,
and `platformd`. The first two and the kernel are on the serial line; the
rest are on HDMI.

### Step 2: netboot onto the SD card (`boot_model: sd`)

The node installs to its card over the network once. Afterwards the
bootloader tries the card first, so an installed node never asks the boot
server again.

EEPROM:

```ini
BOOT_ORDER=0xf21          # nibbles read right to left: 1 = SD card, 2 = network, f = start over
```

A bootable card wins, so start with a blank card.

`bootstrap.yaml` names the Pi as a node
([`bootstrap.yaml` node fields](../bootstrap/engineering.md#bootstrapyaml--the-day-zero-fleet-description)). The
`serial` is the low 32 bits of `/proc/cpuinfo` `Serial`; the MAC is
`cat /sys/class/net/eth0/address` on the Pi:

```yaml
deployer:
  # host, user, ssh_key, known_hosts_path as in ../bootstrap/engineering.md §5
  netboot_media_dir: bin/netboot-media    # relative to this file
  proxy_dhcp: false        # true when the segment already has a DHCP server
nodes:
  - hostname: pi-01
    role: worker
    macs: ["dc:a6:32:01:36:c2"]
    platform: raspberrypi
    model: rpi4
    serial: 9ffefdef
    boot_model: sd
```

Build the media, start the boot server, then prove the bootloader's side of
it from a host on the provisioning segment
([probe rpi](../bootstrap/cli.md#6a-platformctl-bootstrap-probe-rpi)):

```sh
make netboot-media
platformctl bootstrap run --config ./bootstrap.yaml --dry-run
platformctl bootstrap run --config ./bootstrap.yaml
sudo platformctl bootstrap probe rpi --interface eth1 --serial 9ffefdef --mac dc:a6:32:01:36:c2
```

A Pi has no BMC: power it on yourself. In order:

1. Serial: the firmware log of the bootloader's network boot, which fetches
   `start4.elf`, `config.txt`, `fixup4.dat`, `bcm2711-rpi-4-b.dtb`,
   `overlays/*.dtbo` and `kernel8.img` over TFTP, trying `9ffefdef/` before
   the root. These are the files the probe listed.
2. Serial: the U-Boot banner. U-Boot's `bootflow scan` asks DHCP again and
   loads the db-signed arm64 iPXE, `snponly-aarch64.efi`.
3. iPXE fetches `/boot.ipxe`, then `/boot/device/<mac>.ipxe`, then the signed
   kernel and initrd ([§3](#3-boot-the-machine)).
4. The kernel, then the installer writes the card and posts its log
   ([§4](#4-read-the-install-log-afterwards)).
5. From the card: the five first-boot milestones of step 1.

### Step 3: prove signed HTTP boot before any OTP burn

The factory image's
[Provision a fleet: signed HTTP boot](../factory-image/user.md#provision-a-fleet-signed-http-boot)
is the runbook: make the fleet key, build the media with `--fleet-key`, serve
it, prove it, configure the EEPROM. Its step 5 sets:

```ini
BOOT_ORDER=0xf17          # nibbles read right to left: 7 = HTTP, 1 = SD card, f = start over
HTTP_HOST=10.99.99.1      # the container address
HTTP_PORT=8080            # bootstrap_http_port from bootstrap.yaml
HTTP_PATH=data/http-boot
SIGNED_BOOT=1
```

The `bootstrap.yaml` node is the one from step 2; the media in
`netboot_media_dir` now carries `http-boot/`. From any host on the
provisioning segment, with the key and hash from the board's provisioning
record, not from the server
([probe rpi-http](../bootstrap/cli.md#6a-1-platformctl-bootstrap-probe-rpi-http)):

```sh
platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 \
  --pubkey bin/netboot-media/http-boot/pubkey.bin --otp-key-hash 3f9a…c1
```

On the console, in order: the firmware log of the HTTP fetch of `boot.img`
and `boot.sig`, then the U-Boot banner, which `boot.img` carries as
`kernel8.img`.

Do not burn the OTP until the probe is green.
[Step 6](../factory-image/user.md#6-burn-the-otp-hash--irreversible) is
**irreversible**, it is the owner's call alone, and it is never done on a
Pi 5 or CM5.

### Step 4: diskless (`boot_model: diskless`)

The node boots stateless from the media set's squashfs root and its
dm-verity hash tree, held in RAM.

EEPROM:

```ini
BOOT_ORDER=0xf12          # nibbles read right to left: 2 = network, 1 = SD card, f = start over
```

This is the operator's setting for network first, then the SD card; the
platform does not set it.

`bootstrap.yaml`: the step 2 node with `boot_model: diskless`.

The media must carry the diskless root, built with `diskimage netboot
--diskless` ([cli.md §2a](../factory-image/cli.md#2a-platformctl-diskimage-netboot)).
That needs Secure Boot with the DB key in the KMS and a fixed build time:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) make netboot-media NETBOOT_MEDIA_FLAGS=--diskless
platformctl bootstrap run --config ./bootstrap.yaml
```

Without it, the node's device script fails with `ErrDisklessUnavailable`:
`… boots diskless and media set … has no diskless root (rebuild the netboot
media with --diskless)`.

In order:

1. Serial: the bootloader, U-Boot and iPXE as in step 2. The device script
   for this node's MAC adds `platform_boot_model=diskless`.
2. The installer verifies the media set's signed `diskless/manifest.json`
   against a pinned anchor and writes `platform_roothash=`,
   `platform_rootfs_url=` and the rest into the UKI's `.cmdline`
   ([installer architecture](../installer/architecture.md)).
3. `platform-initrd` fetches `rootfs.squashfs` and `rootfs.verity` into RAM,
   verifies them, and mounts the root read-only under a tmpfs overlay at
   `/sysroot`. A failed fetch reads `diskless root: fetch <url>: …`, and a
   root hash mismatch fails closed before any root mount.
4. `platformd` logs `Diskless node: TPM identity not resident, running
   first provisioning` on the first boot, then `Diskless node: TPM-resident
   identity found, skipping provisioning` on every boot after.

A TPM holding part of an identity, or another node's, is refused, not
cleared: `tpm: diskless node's TPM holds a partial or foreign identity;
refusing to clear it` ([tpm architecture](../tpm/architecture.md)).

---

## Troubleshooting

**Nothing happens. The client loops DISCOVER forever, no error.**
Almost always the wrong boot file for the client's architecture. A UEFI binary
handed to a legacy-BIOS ROM fails the TFTP load silently. Check the TFTP log for
which filename was requested; `undionly.kpxe` means legacy BIOS, `ipxe32.efi`
means UEFI IA32, `ipxe.efi` means UEFI x64. If the optional binaries failed to
download at startup you will have a warning in the log and clients on those
architectures cannot boot.

**PXE-E18 "Server response timeout" on UEFI, while legacy BIOS works.**
The firmware is doing Boot Server Discovery instead of downloading the file it
was offered. The server sets DHCP option 43 sub-option 6 specifically to stop
this. If you are seeing it, something is stripping option 43 or option 60 —
check for a relay or a second DHCP server on the segment.

**The client gets an address from something else.**
Two DHCP servers on the same segment. Isolate the provisioning network. If this
server genuinely should be the only one, that is what `DHCPRespondToAll` is for
— but do not enable it on a shared network.

**iPXE loads, chainloads fine, then "Could not boot: Not found".**
The `/data/` endpoint is not registered. It only exists when `DataDir` is
non-empty. Kernel and initrd fetches 404 while everything before them worked,
which is exactly the confusing shape this produces.

**The console's Networking → PXE page says PXE is not available on this node.**
Not a fault. PXE is served by the **gateway** role, so on a control plane the
`/api/v1/pxe/*` endpoints answer 503 with the discriminator
`SERVICE_NOT_CONFIGURED`, and the page renders the reporting gateways' PXE
telemetry — status, listen address, boots served — from
`/api/v1/gateway/state` instead of an error. A 503 *without* that discriminator
means a node that does serve PXE has a stopped or failing service, and the page
raises it as an error.

**"device not found" on `/boot/device/…`.**
The manifest does not know that MAC — expected for a machine that is not in
`bootstrap.yaml`, which then boots its architecture's default. For a node that
should be known, the MAC in the URL does not match the manifest. The route
lowercases and rewrites dashes to colons before the lookup, so the callback
always sees colon form.

**A `/config/mac/…` request returns 400.**
Wrong MAC format. Lowercase, dash-separated, 12–17 characters. Or the key is
not `[a-z0-9][a-z0-9._-]{0,64}`. Or the path contains `..`.

**A `/config/mac/…` request returns 503.**
`InstallsDir` is empty, so there is nowhere to store values. Configure it.

**The TFTP server refuses to start.**
`ipxe.efi` could not be loaded — no cache and no network to `boot.ipxe.org`.
That one binary is required; the other two are optional. Pre-seed the cache
under `$XDG_CACHE_HOME/go-trusted-platform/firmware/` (or
`/var/cache/go-trusted-platform/firmware/` for a root or container process) if
the host is air-gapped.

**Firmware behaves oddly after an upgrade.**
A cached firmware file is served without revalidation. Delete the cache
directory and let it re-download.

**The proxy returns 502.**
The upstream HTTPS fetch failed. TLS verification is mandatory and the floor is
TLS 1.3 — a host with an untrusted certificate or an older TLS version will not
work. Supply the right CA pool, or serve the file from `/files/` or `/data/`
instead.

**Permission denied binding a port.**
UDP 67 and 69 are privileged. Run as root, grant `CAP_NET_BIND_SERVICE`, or
change `--http-port` / `--tftp-port` — but note that PXE firmware only ever asks
for TFTP on 69, so moving that port is not useful in practice.

**IPv6.**
Not supported. The DHCP server is DHCPv4 only and server-IP detection returns
the first non-loopback IPv4 address.

**A Pi gets no DHCP OFFER.**
The bootloader accepts only a reply whose option 43 carries `Raspberry Pi
Boot`, and the server recognises a Pi by its vendor class
`PXEClient:Arch:00000:UNDI:002001` plus option 97 or a Raspberry Pi MAC.
Check that `BOOT_ORDER` has the network nibble `2`, then run
`sudo platformctl bootstrap probe rpi --interface <if> --serial <serial> --mac <mac>`
from a host on the provisioning segment: no offer within the bootloader's
45 s means the container is not on that segment. On a segment that already
has a DHCP server, set `proxy_dhcp: true`. A bootloader with its own
`PXE_OPTION43` needs `--option43` to match it.

**A Pi times out on TFTP.**
The bootloader waits 30 s per file and retries five times. The probe lists
each file and the path that served it, and stops at the first file neither
the device prefix nor the root serves: the same place the Pi stopped. A
`serial` in `bootstrap.yaml` that is not the board's names the wrong
per-device directory, and an EEPROM `TFTP_PREFIX` other than the serial
needs the matching `--prefix`. A media build with no Pi files is refused
before boot: `the build has no Raspberry Pi TFTP tree or arm64 iPXE`.

**A Pi refuses the signature.**
With `SIGNED_BOOT=1` the EEPROM runs `boot.img` only if `boot.sig` verifies
against the key whose hash is in OTP. Run
[`probe rpi-http`](../bootstrap/cli.md#6a-1-platformctl-bootstrap-probe-rpi-http)
with the key and hash from the board's provisioning record:
`DigestMismatchError` is a `boot.img` changed after signing, `SignatureError`
a signature by another key, `KeyHashMismatchError` a `pubkey.bin` that is not
the key whose hash the board holds, `TargetSoCError` a `target-soc` other
than 2711 or 2712. Rebuild the media; never burn another hash to match it.

**A Pi's TPM is not found.**
First boot cannot seal without it. The image binds the SLB9670 through
`dtoverlay=tpm-soft-spi` on SPI0 chip-select 1. On the node:

```sh
ls -l /dev/tpm0 /dev/tpmrm0
dmesg | grep tpm_tis_spi
tpm2_pcrread sha256:0,4,7,9
```

No device nodes and no `tpm_tis_spi` line means the module is not seated on
chip-select 1, or is not wired as the LetsTrust or Iridium 9670 module is
([prerequisites](../factory-image/user.md#prerequisites)). Interrupting
U-Boot's autoboot and running `tpm2 info` shows whether U-Boot can reach it.
After a good boot PCRs 0, 4, 7 and 9 are all non-zero
([Verify on the node](../factory-image/user.md#verify-on-the-node)).

---

## Where to go next

- [cli.md](cli.md) — `pxeboot` and `platformctl iso test pxe`, flag by flag
- [api.md](api.md) — every route, the two MAC formats, and where the PXE control
  plane actually lives
- [architecture.md](architecture.md) — the two-stage chainload and its trust
  boundaries
- [`docs/installer/`](../installer/) — what happens once the kernel boots
- [`docs/provisioning/`](../provisioning/) — authorising a machine, and the API
  for everything the CLI does not cover
