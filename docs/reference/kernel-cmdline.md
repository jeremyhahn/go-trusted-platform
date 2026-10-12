# Kernel Command-Line Parameter Reference

All `platform_*` and `bootstrap_*` kernel command-line parameters
recognized by the Trusted Platform ISO live environment and
`platform-initrd`.

For architectural context see:
- `docs/architecture/bootstrap-flow.md`
- `docs/bootstrap/config-delivery.md`
- `docs/installer/autoinstall.md`
- `docs/installer/initrd-overview.md`

---

## 1. Summary Table

| Parameter | Set by | Read by | Purpose |
|-----------|--------|---------|---------|
| `platform_config` | `iso create --config-server` (GRUB), bootstrap server (PXE) | `autoinstall.sh` | Per-MAC `/config/mac` base URL for the merged `installer.yaml` |
| `platform_bin_url` | Bootstrap server (PXE only) | `autoinstall.sh` | Base URL of the node's media set (`/data/media/<set>`), whose `payload.list` rebuilds `/media/cdrom` on nodes with none |
| `platform_hostname` | `iso create --platform-config` with `os.hostname` set | `autoinstall.sh` | Hostname override (hostname PRIO 0) |
| `platform_debug_sink` | Auto-detected via DHCP server, or operator-set | `autoinstall.sh`, `platform-initrd` | HTTP sink for install-log + `/config/mac` fetches |
| `platform_apk_mirror` | `iso create --apk-mirror` (GRUB), bootstrap server `BOOTSTRAP_APK_MIRROR` (PXE) | `autoinstall.sh` | Install-time APK repository base for nodes with no `/media/cdrom` |
| `alpine_repo` | Bootstrap server (PXE only) | Alpine initramfs `init` | Live-system (diskless root) repository; without it PXE installs 0 packages |
| `modloop` | Bootstrap server (PXE only) | Alpine initramfs `init`, `run-autoinstall.sh` | Kernel-modules squashfs URL; `run-autoinstall.sh` fetches+mounts it over HTTP when no CD is present (dm-crypt/LUKS/ext4/TPM modules) |
| `platform_boot_model` | Bootstrap server (per node, from `boot_model`) | installer, `platform-initrd` | `diskless` selects the diskless root; absent means the disk install. The installer copies it into the signed UKI `.cmdline` |
| `platform_rootfs_url` | Installer, from the signed media-set manifest | `platform-initrd` | HTTP(S) URL of the squashfs root image for stateless boot |
| `platform_verity_url` | Installer, from the signed media-set manifest | `platform-initrd` | HTTP(S) URL of the dm-verity hash tree for `platform_rootfs_url` |
| `platform_roothash` | Signed UKI `.cmdline`, from the signed media-set manifest | `platform-initrd` | dm-verity SHA-256 root hash of the diskless root; Secure Boot and measured boot cover it |
| `platform_verity_salt`, `platform_rootfs_size`, `platform_verity_size` | Signed UKI `.cmdline`, from the signed media-set manifest | `platform-initrd` | Pinned dm-verity salt and the exact byte sizes fetched; nothing is read from a superblock |
| `platform_autoinstall_debug` | Operator (manual) | `autoinstall.sh` | Enable `set -x` for verbose install trace |
| `platform_server` | Operator (post-bootstrap) | Interactive provisioning client | Server URL for interactive QR mode |
| `bootstrap_strategy` | `iso create --bootstrap-strategy` | Post-bootstrap provisioning client | `dane`, `noise`, `spki`, or `auto` |
| `bootstrap_dns` | `iso create --bootstrap-dns` | Post-bootstrap provisioning client | DNS server for DANE TLSA lookups |
| `bootstrap_noise_key` | `iso create --bootstrap-noise-key` | Post-bootstrap provisioning client | Hex-encoded Noise_NK server public key |
| `bootstrap_spki_pin` | `iso create --bootstrap-spki-pin` | Post-bootstrap provisioning client | SHA-256 SPKI certificate pin |
| `eab_kid` | Operator (post-bootstrap) | Post-bootstrap provisioning client | EAB key ID |
| `eab_hmac` | Operator (post-bootstrap) | Post-bootstrap provisioning client | Base64-encoded EAB HMAC key |
| `console=` | `iso create` hardware-aware | Kernel, boot loader | Serial console routing |
| `earlycon=` | `iso create` hardware-aware | Kernel | Pre-console early boot output |
| `tpm_tis.force=` | Operator (X10 Supermicro workaround) | `tpm_tis` driver | Force legacy ACPI binding |

---

## 2. Bootstrap-Time Config Delivery

### `platform_config=<URL>`

**Purpose:** Base URL for the pxeboot HTTP config server.
**Set by:**
- `platformctl iso create --config-server <URL>` bakes this into the GRUB /
  iPXE kernel cmdline via `pkg/iso/customize.go::buildDynamicConfigParams`
  (virtual-media / standalone ISOs).
- The bootstrap server (`pkg/bootstrap/container/server.go`) appends it to
  the PXE iPXE cmdline as `http://<server>:<port>/config/mac`. PXE nodes
  have no `/media/cdrom/configs/installer.yaml`, so this is their primary
  config source. The orchestrator publishes the merged config there via
  `stagePerMACConfig`, before every install boot: BMC-managed PXE,
  virtual media, and unmanaged (observe-only) nodes alike.

**Read by:** `autoinstall.sh` in the Alpine live environment.
**Behavior:** Autoinstall appends `/<mac-dashed>/installer.yaml` and
performs HTTP GET. If it returns 2xx and looks like YAML, the body
becomes the device config. On any failure, falls through to the
`platform_debug_sink` per-MAC fetch, then to
`/media/cdrom/configs/installer.yaml` (baked).

Example:
```
platform_config=http://deployer.lan:8080/config/mac
```

Full URL constructed at install time:
```
http://deployer.lan:8080/config/mac/aa-bb-cc-dd-ee-ff/installer.yaml
```

See `docs/bootstrap/config-delivery.md` §3 for the full dynamic flow.

### `platform_bin_url=<URL>`

**Purpose:** Base URL of the node's **media set** — its installer payload —
on nodes that have **no `/media/cdrom`**, the PXE case.
Virtual-media installs read these off the mounted ISO's
`/media/cdrom/platformd-bin/` and ignore this param.
**Set by:** The bootstrap server (`pkg/bootstrap/container/server.go`)
appends `platform_bin_url=http://<server>:<port>/data/media/<set>` to the PXE
iPXE cmdline. The set's `payload.list` is written by the netboot media build
(`platformctl diskimage netboot`) and staged with the build by the deployer
(`stageNetbootMedia`).
**Read by:** `autoinstall.sh` (`buildAutoinstallScript`,
`fetch_install_payload`), before the `platformctl` binary search.
**Behavior:** When set and no CD is present, autoinstall fetches
`<base>/payload.list`, then every entry into a scratch directory, checks each
against its SHA-256 (`sha256sum -c`), copies files and unpacks tarballs to
their `dest` under `/media/cdrom`, and writes `.payload-complete`. Any
failure — a missing list, a digest mismatch, a path escaping `/media/cdrom`,
no executable `platformd-bin/platformctl` — stops the install. No-op on
virtual-media.

Example:
```
platform_bin_url=http://deployer.lan:8080/data
```

### `platform_hostname=<name>`

**Purpose:** Hostname override (PRIO 0 of the hostname chain).
**Set by:** `platformctl iso create` inspects the merged platform
config's `os.hostname` field and bakes this param if present (see
`customize.go` line ~1417).
**Read by:** `autoinstall.sh::resolve_platform_hostname`.
**Behavior:** If no per-MAC orchestrator hostname is published
(PRIO -1), this value is used as the installed-system hostname.

See `docs/installer/autoinstall.md` §3.

### `platform_debug_sink=<host:port>`

**Purpose:** HTTP sink for install-log uploads AND `/config/mac` fetches.
**Set by:** Operator via bootstrap.yaml deployer config, or
auto-detected from the DHCP server-identifier at install time.
**Read by:** `autoinstall.sh` for install-log upload and per-MAC
hostname/config fetch fallback.

Example:
```
platform_debug_sink=192.0.2.91:8080
```

### `platform_apk_mirror=<URL>` and `alpine_repo=<URL>`

**Purpose:** Make APK packages resolvable on nodes that have **no
`/media/cdrom`** — the PXE case, where only `vmlinuz` + `initramfs` are
fetched over the network. Virtual-media / CD installs are unaffected: the
mounted ISO supplies a local `/media/cdrom/apks` repo and the auto-detect
below uses it (OFFLINE), ignoring both params.

**`alpine_repo=<base>/v<major.minor>/main`** — read by Alpine's own
initramfs `init` (`find_boot_repositories`) when it builds the diskless
live root. PXE nodes have no `.boot_repository` under `/media/*`, so
without this the live-system `apk add alpine-base` installs **0 packages**,
there is no `/sbin/init`, and the kernel drops to the *"init not found in
new root"* emergency shell. Pointing it at a mirror's `main` branch also
flips Alpine's `do_networking` on (it detects a URL repo).

**`platform_apk_mirror=<base>`** — read by `autoinstall.sh` after
`switch_root` to populate `/etc/apk/repositories` for the install-time
package set (parted, lvm2, eudev, ...).

**Set by:**
- `platformctl iso create --apk-mirror <URL>` bakes `platform_apk_mirror`
  into the GRUB cmdline (`pkg/iso/customize.go::ConfigureBootloader`).
- The bootstrap server (`pkg/bootstrap/container/server.go`) appends BOTH
  `alpine_repo` and `platform_apk_mirror` to the PXE iPXE cmdline, sourced
  from `BOOTSTRAP_APK_MIRROR` / `BOOTSTRAP_ALPINE_VERSION`
  (`DeployConfig.BootstrapAPKMirror`). Both default to the public Alpine
  mirror so internet-connected PXE installs work with no extra config.

**Read by:** `autoinstall.sh` repo auto-detect (`buildAutoinstallScript`),
which picks in priority order:
1. `/media/cdrom/apks` present → local CD repos (OFFLINE, `--allow-untrusted`).
2. `platform_apk_mirror` set → `<mirror>/v<major.minor>/{main,community}`.
3. otherwise → `https://dl-cdn.alpinelinux.org/alpine/v<major.minor>/{main,community}`.

The release branch (`v3.22`) is baked from the configured Alpine version;
at runtime it falls back to `v$(cut -d. -f1-2 /etc/alpine-release)`.

Example (PXE cmdline fragment):
```
alpine_repo=http://192.0.2.11:8080/v3.22/main platform_apk_mirror=http://192.0.2.11:8080
```

### `modloop=<URL>`

**Purpose:** Locate the Alpine kernel-modules squashfs. The modules that
are **not** baked into the initramfs — `dm-mod`, `dm-crypt`, `ext4`, `tpm*`,
LVM targets — live only here. Without modloop mounted, the installer's LUKS
step dies on a missing `/dev/mapper/control`.
**Set by:** The bootstrap server appends
`modloop=http://<server>:<port>/data/media/<set>/modloop-<flavour>` to the PXE
iPXE cmdline.
**Read by:** Alpine's initramfs `init`, and — as a fallback —
`run-autoinstall.sh::ensure_modloop`.
**Behavior:** On virtual-media the modloop is mounted from the CD. On PXE
there is no CD, so `ensure_modloop` fetches the squashfs from this URL over
HTTP (after the boot NIC has a lease) and loop-mounts it at `/.modloop`,
symlinking `/lib/modules` so `modprobe` resolves. Idempotent; the call runs
both before and after network bring-up so it works regardless of when the
NIC comes up.

### `platform_autoinstall_debug=1`

**Purpose:** Enable `set -x` tracing in `autoinstall.sh` for
debugging.
**Set by:** Operator appending to kernel cmdline at the GRUB menu
(interactive boot) or via a custom-built ISO.
**Read by:** `autoinstall.sh`.
**Behavior:** Every shell command is echoed to the serial console.
Combines well with `console=ttyS1,115200` for BMC serial-over-LAN
capture.

---

## 3. Post-Bootstrap Config Delivery

These parameters are consumed by the production provisioning client
(`platformctl-static bootstrap trust` + `provision fetch-config`)
AFTER the device has its installed OS up. They are NOT used during
ISO autoinstall. For the flow, see
`docs/provisioning/config-delivery.md`.

### `platform_server=<URL>`

Server URL for interactive QR-based provisioning mode.

### `bootstrap_strategy=<dane|noise|spki|auto>`

Which trust-bootstrap strategy to try first. `auto` tries DANE first,
falls back to Noise_NK, then SPKI.

### `bootstrap_dns=<server>`

DNS server for DANE TLSA record lookups.

### `bootstrap_noise_key=<hex>`

Hex-encoded Noise_NK server long-term public key (32 bytes = 64 hex chars).

### `bootstrap_spki_pin=<sha256>`

SHA-256 hash of the server's Subject Public Key Info, base64-encoded.
Used for SPKI pinning.

### `eab_kid=<string>`

EAB (External Account Binding) key ID used to authenticate the
config fetch request.

### `eab_hmac=<base64>`

EAB HMAC key used to sign the config fetch request.


---

## 3a. Kernel cmdline → `trust:` YAML Mapping

The bootstrap kernel cmdline parameters are set by `platformctl iso create`
and propagate through the install flow to the running platform daemon's
`trust:` configuration block.

```
Kernel cmdline param          Install-time action               trust: YAML key
─────────────────────────────────────────────────────────────────────────────────
bootstrap_strategy=<s>        passed to provisioning client     trust.bootstrap.strategies: [<s>]
bootstrap_dns=<server>        passed to provisioning client     trust.bootstrap.dane.dns-server: <server>
bootstrap_noise_key=<hex>     passed to provisioning client     trust.bootstrap.noise.server-static-key: <hex>
bootstrap_spki_pin=<pin>      autoinstall.sh writes pin to      trust.bootstrap.spki.pin-file:
                              /etc/trusted-platform/                /etc/trusted-platform/bootstrap-spki-pin
                              bootstrap-spki-pin
```

**How the pin-file flow works** (source: `pkg/iso/customize.go` lines 3342-3351):

1. The orchestrator stages the CP's SPKI pin to `/tmp/cp-spki-pin` on the
   installer filesystem.
2. `autoinstall.sh` copies it to `/mnt/etc/trusted-platform/bootstrap-spki-pin`
   on the installed disk.
3. The platform YAML template references it via:

```yaml
trust:
  default:
    strategies: [spki]
    spki:
      pin-file: /etc/trusted-platform/bootstrap-spki-pin
```

4. At boot, `pkg/trust.Config.Validate()` reads `pin-file` and resolves it
   into the in-memory `spki.pin` field (`pkg/trust/config.go`).

**`trust:` YAML class summary** (source: `pkg/trust/config.go`):

| Class | Allowed strategies | Typical use |
|-------|--------------------|-------------|
| `bootstrap` | dane, noise, spki, embedded, tofu | First-boot CA bundle fetch, before the node holds the platform CA |
| `bmc` | dane, spki, ca-file, tofu | BMC Redfish / IPMI-over-TLS client |

Platform-issued peers (attestation, SDN reporter, provisioning, heartbeat) are
not a class: they are verified against the platform anchor, which needs no
configuration — see
[docs/bootstrap/configuration.md](../bootstrap/configuration.md#platform-anchor).

The `trust:` key is read into `pkg/app.AppConfig.TrustConfig` and wired to
`pkg/trust.NewResolver()`. It is NOT the same as the `pkg/bootstrap.ClientConfig`
used for the one-shot CA bundle fetch at first-boot; that path uses
`bootstrap.Fetch()` from the QuicBaaS SDK re-export.
---

## 4. Platform-initrd (LUKS unlock) Parameters

Consumed by `platform-initrd` in the initramfs context before
`switch_root`.

### `console=`

Inherited from kernel. `platform-initrd` writes progress messages
to the configured console. See `docs/installer/initrd-overview.md`.

### `rd.luks.uuid=<uuid>`

Standard dracut-compatible LUKS UUID. `platform-initrd` reads this
to find the LUKS device to unlock.

### `rd.trusted.strategy=<strategy>`

Override the unlock strategy order. Defaults to the order compiled
into the initrd config. See `docs/installer/UNLOCK_STRATEGIES.md`.

### Diskless root parameters

Diskless image boot only. Every one of these comes from the **signed UKI
`.cmdline`**, never from a live command line or an iPXE script. The bootstrap
server marks a node with `platform_boot_model=diskless` (from its
`boot_model`) and nothing more; the installer then reads the media set's
`diskless/manifest.json`, verifies its `.sig` against a pinned anchor — the
platform's DB certificate enrolled in the node's UEFI `db` (not any other `db`
entry), or the KMS-held DB certificate,
never a media-staged key ([installer architecture](../installer/architecture.md))
— and writes the root parameters from that manifest into the UKI. A root hash on the installer's command line is ignored,
so a tampered boot script cannot change the root a node boots. `platform-initrd`
rejects a command line that names any of these keys twice.

| Parameter | Meaning |
|-----------|---------|
| `platform_boot_model=diskless` | Selects the diskless root; any other value is refused |
| `platform_rootfs_url=<url>` | Absolute HTTP(S) URL of the squashfs root, fetched into RAM, attached read-only, and used as the lower root under a tmpfs overlay |
| `platform_verity_url=<url>` | Absolute HTTP(S) URL of the dm-verity hash tree for that image |
| `platform_roothash=<sha256-hex>` | 64-hex dm-verity root hash; a mismatch fails closed before any root mount |
| `platform_verity_salt=<hex>` | dm-verity salt, pinned so the open does not trust on-media parameters |
| `platform_rootfs_size=<bytes>`, `platform_verity_size=<bytes>` | Exact sizes; the fetch stops at them and the RAM spent is bounded |

The names carry the `platform_` prefix because systemd's
`systemd-veritysetup-generator` claims `roothash=` and would try to open a
verity root of its own.

---

## 5. Hardware-Specific Parameters

### Raspberry Pi (all 64-bit models, `pkg/quirks` entry `raspberry pi`)

The factory SD-card image ([docs/factory-image/](../factory-image/)) selects
this entry through the template's `hardware-manufacturer: Raspberry Pi`; the
command line lives in the UKI's `.cmdline` section, not in a `cmdline.txt` on
the boot partition.

```
console=ttyAMA0,115200 console=tty1 rootwait loglevel=7
```

`tty1` last makes the HDMI console `/dev/console`, so an operator at the
display sees OpenRC and the firstboot seal; the serial port carries the
kernel log. The QEMU virt stand-in (`hardware-model: QEMU virt stand-in`,
entry `raspberry pi/qemu virt`) has no display and inverts the order —
`console=tty1 console=ttyAMA0,115200` — so that the serial transcript the
integration suite reads continues past `switch_root`.

The primary UART is the PL011 on GPIO14/15, which is `ttyAMA0` once the
firmware moves Bluetooth off it (`dtoverlay=disable-bt` in `config.txt`); the
QEMU `virt` machine used for emulated boots presents the same device. There is
deliberately no `earlycon=`: the PL011 base address differs between Pi 3, Pi 4
and QEMU, and a wrong one faults before any console exists. `rootwait` covers
the SD card appearing after the initramfs has started. The entry is selected
by the media generator's `hardware_manufacturer: Raspberry Pi` override, not
by Redfish (a Pi has no BMC).

### Supermicro X10 (X10SDV-TP8F / -7TP8F)

```
console=ttyS1,115200 console=ttyS0,115200 earlycon=uart8250,io,0x3f8,115200
```

X10SDV SOL is wired to COM1 (ttyS0, I/O 0x3f8) on IPMI payload instance 1 —
measured on node-02 (`SYS-5018D-FN8T-AS001`, ATEN FW 4.00) 2026-08-29: kernel,
autoinstall, initrd and OpenRC output all on instance 1, instance 2 silent.
Earlier revisions of this page and of the quirk entry said COM2 / 0x2f8; that
was wrong for this board. Both UARTs stay on the cmdline with `ttyS0` last so
it is `/dev/console`. BIOS POST is not redirected to SOL on this board.

### Dell R640 (14G)

```
console=ttyS0,115200
```

Dell iDRAC SoL defaults to COM1.

### TPM workarounds

```
tpm_tis.force=1
```

Forces the `tpm_tis` driver to use legacy ACPI binding on certain
X10 firmware versions where CRB auto-detection fails.

---

## 6. Source of Truth

When adding a new kernel cmdline parameter:

1. Add a row to §1 table in this doc.
2. Add a detail section in the appropriate category (§2–§5).
3. Update the code that sets it (usually
   `pkg/iso/customize.go::buildDynamicConfigParams` or
   `pkg/cli/commands/iso/create.go`).
4. Update the code that reads it (usually `pkg/iso/customize.go`
   embedded shell or `pkg/initrd/`).
5. Update the doc that describes the containing flow
   (`docs/installer/autoinstall.md`, `docs/installer/initrd-overview.md`,
   or `docs/provisioning/config-delivery.md`).

Parameters without doc coverage are considered broken and may be
removed in cleanup passes.
