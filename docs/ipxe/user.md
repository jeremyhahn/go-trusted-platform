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

---

## Where to go next

- [cli.md](cli.md) — `pxeboot` and `platformctl iso test pxe`, flag by flag
- [api.md](api.md) — every route, the two MAC formats, and where the PXE control
  plane actually lives
- [architecture.md](architecture.md) — the two-stage chainload and its trust
  boundaries
- [configuration.md](configuration.md) · [testing.md](testing.md) —
  pre-convention worked examples
- [`docs/installer/`](../installer/) — what happens once the kernel boots
- [`docs/provisioning/`](../provisioning/) — authorising a machine, and the API
  for everything the CLI does not cover
