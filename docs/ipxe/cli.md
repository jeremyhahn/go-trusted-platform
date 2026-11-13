# iPXE Network Boot — CLI

> **Status: NORMATIVE** · Scope: `cmd/pxeboot`, `platformctl iso test pxe` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. `pkg/ipxe` has no CLI of its own

**There is no `platformctl ipxe` command group**; `pkg/ipxe` exports a library
and nothing else. The `platformctl pxe` group belongs to provisioning, not to
this package (below).

Two command-line surfaces reach it, and they are for different audiences:

| Surface | Audience | What it is |
|---|---|---|
| `pxeboot` | An operator or an orchestrator running the bootstrap container | A container entrypoint with flags. Not a subcommand of anything. |
| `platformctl iso test pxe` | An engineer | A test harness that stands up an isolated network, runs a PXE server on it, and boots a QEMU client. |

What an operator does to a PXE device belongs to provisioning:
`platformctl pxe` lists, inspects, authorizes, quarantines and retries devices
and reads their events
([`docs/provisioning/cli.md`](../provisioning/cli.md) §5). Registering or
removing a device and starting or stopping the service stay **API-only**.

---

## 2. `pxeboot`

```
pxeboot --manifest <path> --dhcp-server-ip <ip> \
        --dhcp-range-start <ip> --dhcp-range-end <ip> [flags]
```

A minimal entrypoint (`cmd/pxeboot/main.go`) that builds a
`container.ServerConfig` and delegates to `container.Server`, which wraps
`ipxe.Server` with manifest-based boot-script generation. It uses Go's
`flag` package, so flags take **one leading dash or two** and there are no
short forms and no subcommands.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--manifest` | string | `""` | **yes** | Path to `manifest.yaml` |
| `--dhcp-server-ip` | string | `""` | **yes** | DHCP server IP address |
| `--dhcp-range-start` | string | `""` | **yes** | First allocatable address |
| `--dhcp-range-end` | string | `""` | **yes** | Last allocatable address |
| `--config-dir` | string | `/data/configs` | no | Directory of per-device configs |
| `--interface` | string | `eth0` | no | Network interface to bind |
| `--bind-host` | string | `""` | no | Address the HTTP and TFTP servers bind; empty is every interface. DHCP stays on the unspecified address, scoped to `--interface` ([engineering.md](engineering.md)). The container sets it from `BOOTSTRAP_BIND_HOST` |
| `--http-port` | int | `8080` | no | HTTP server port |
| `--device-script-port` | int | `0` | no | Per-device boot script server port (`/boot/device/{mac}.ipxe`), a second listener. Zero derives `--http-port` + 1 |
| `--tftp-port` | int | `69` | no | TFTP server port |
| `--dhcp-gateway` | string | `""` | no | IPv4 gateway advertised as the router (option 3); empty advertises no router |
| `--dhcp-dns` | string | `""` | no | Comma-separated IPv4 DNS servers, all advertised in option 6 in the order given |
| `--apk-mirror` | string | `""` | no | Install-time APK mirror base; empty uses `container.DefaultAPKMirror` (the public Alpine mirror) |
| `--alpine-version` | string | `""` | no | Alpine version of the staged kernel/initramfs; empty uses `container.DefaultAlpineVersion` (`3.22.2`) |
| `--data-dir` | string | `/data` | no | Directory served at `/data/`; `--media-dir` must be inside it |
| `--media-dir` | string | `/data/media` | **yes** | The media sets served, one per subdirectory with a `media-set.yaml` (`container.MediaSet`): the netboot media build's `media/`, staged by the deployer. It must hold at least one set |
| `--tftp-dir` | string | `""` | no | Raspberry Pi boot tree served over TFTP beside the iPXE firmware |
| `--firmware-dir` | string | `""` | no | Directory the iPXE firmware is loaded from and cached into; empty is the user cache directory, else the system one |
| `--firmware-override` | name=path | — | no | Serve a prebuilt firmware file in place of the upstream download; repeatable (the db-signed arm64 iPXE as `snponly-aarch64.efi`) |
| `--dhcp-proxy` | bool | `false` | no | Proxy DHCP: boot options, no lease — the segment has its own DHCP server |
| `--nbd-listen` | string | `""` | no | NBD-over-TLS export server address; empty is `--dhcp-server-ip`:10809 |
| `--nbd-volume-dir` | string | `""` | no | One NBD root volume per `diskless-nbd` node; empty is `--data-dir`/nbd |
| `--nbd-volume-size` | int64 | `0` | with a `diskless-nbd` node | Bytes of a new NBD root volume, a multiple of 512 |
| `--nbd-ca-file` | string | `""` | with a `diskless-nbd` node | Platform CA bundle that verifies NBD client IDevIDs |
| `--nbd-cert` | string | `""` | with a `diskless-nbd` node | NBD server TLS certificate |
| `--nbd-key` | string | `""` | with a `diskless-nbd` node | NBD server TLS private key |

The `--nbd-*` flags are read only when the manifest has a `boot_model:
diskless-nbd` entry; see [bootstrap engineering](../bootstrap/engineering.md#nbd-export-server-pkgbootstrapnbd).

**Media sets.** Every installer pxeboot serves is a media set from a netboot
media build (`platformctl diskimage netboot`, `make netboot-media`); nothing is
baked into the image. Each directory under `--media-dir` with a
`media-set.yaml` is one: its name, architecture (`x86_64` or `arm64`), kernel,
initrd (the release's initramfs rewritten as the installer's, which runs the
autoinstall), modloop and flavour kernel arguments, and whether it is its
architecture's default. Every set carries a
`payload.list` (`container.PayloadListName`): one line per file or tarball the
installer lays under `/media/cdrom`, as `<sha256> <file|tar> <dest> <src>`.
pxeboot verifies every source's digest when it starts and refuses a set whose
list is missing, malformed, unverifiable or has no `platformd-bin/platformctl`. `/boot.ipxe` boots each architecture's default
(`${buildarch}` dispatch); a node in the manifest boots the set its entry
names — or its architecture's default — through `/boot/device/<mac>.ipxe`
with its role and hostname. A manifest entry naming a set that is not staged,
or an architecture with no default, fails pxeboot at start.

```bash
pxeboot \
  --manifest /data/manifest.yaml \
  --media-dir /data/media \
  --interface eth0 \
  --dhcp-server-ip 10.10.0.1 \
  --dhcp-range-start 10.10.0.100 \
  --dhcp-range-end 10.10.0.200 \
  --dhcp-gateway 10.10.0.1 \
  --dhcp-dns 10.10.0.1 \
  --apk-mirror http://mirror.example.com:8080 \
  --alpine-version 3.22.2
```

**`--dhcp-gateway` and `--dhcp-dns` are checked before anything starts.**
DHCPv4 options 3 and 6 carry IPv4 addresses only, so a value that is not one —
a hostname, an IPv6 address, an empty entry such as `192.0.2.1,,1.1.1.1` or a
trailing comma — is refused with a `FlagError` naming the flag and wrapping
`ipxe.DHCPAddressError`, and pxeboot exits 1. Spaces around a DNS entry are
dropped. With no `--dhcp-gateway` the offers and acks carry no router option,
which is how the bootstrap image's `BOOTSTRAP_NO_ROUTER=true` reaches the
server ([bootstrap README](../../build/docker/bootstrap/README.md)).

**Missing required flags produce one message naming all of them** —
*"required flags not set: --manifest, --media-dir, …"* — then `flag.Usage()` and
exit 1. `validateRequiredFlags` collects them rather than failing on the first.

**`--alpine-version` must match the staged kernel and initramfs.** The value
derives the repository branch (`vMAJOR.MINOR`) used by the live system's
`apk add` and by the autoinstall repos. Getting it wrong gives a live
environment that cannot resolve packages against the version it is actually
running.

**Binding DHCP needs privilege.** UDP 67 and UDP 69 are privileged ports; in a
container, that means running as root or holding `CAP_NET_BIND_SERVICE`, plus
`CAP_NET_RAW` if the deployment uses the raw-socket DHCP path.

**Exit codes.** `0` on clean shutdown; `1` on a missing required flag, a server
construction failure, or a server that exits with an error. `SIGINT` and
`SIGTERM` cancel the context and shut the services down; logging is JSON to
stdout at info level, not configurable by flag.

---

## 3. `platformctl iso test pxe`

Stands up the isolated test network, runs the PXE server on it, and boots a
QEMU client from it. Documented in full in
[`docs/installer/cli.md`](../installer/cli.md) §3.2; repeated here because it is
the only interactive way to exercise this feature.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--iso` | string | `""` | ISO to boot; kernel, initrd, modloop and kernel args are extracted automatically |
| `--kernel` | string | `""` | Path or URL to a kernel, overriding ISO extraction |
| `--initrd` | string | `""` | Path or URL to an initrd, overriding ISO extraction |
| `--args` | string | `""` | Kernel boot arguments; auto-detected from the ISO when empty |
| `--memory` | int | `4096` | Client RAM in MB |
| `--cpus` | int | host CPU count | Client CPU cores |
| `--work-dir` | string | `work-pxe` | VM artefacts and PXE server files |
| `--disk` | string | `<work-dir>/pxe-client.qcow2` | The client's disk, created empty when missing; the target of whatever the network delivers |
| `--disk-size` | string | `10G` | Size of the client disk when it is created |
| `--secure-boot` | bool | `false` | UEFI Secure Boot on the client (x86_64; U-Boot on aarch64 always verifies) |
| `--architecture` | string | `x86_64` | Client architecture: `x86_64` (OVMF) or `aarch64` (QEMU `virt` booted from the platform's U-Boot, the Raspberry Pi stand-in) |
| `--uboot` | string | `build/docker/uboot-builder/output/qemu_arm64/u-boot.bin` | aarch64: the `qemu_arm64` U-Boot from `make uboot-build` |
| `--ipxe` | string | `build/docker/ipxe-builder/output/bin-arm64-efi/snponly.efi` | aarch64: the platform-built arm64 iPXE from `make ipxe-build`, served in place of upstream's (which halts under U-Boot; see `build/docker/ipxe-builder/README.md`) |
| `--keys-dir` | string | `~/.trusted-platform/secure-boot` | aarch64: the Secure Boot key set U-Boot was preseeded with; `DB.key` + `DB.crt` sign the served iPXE and the kernel |
| `--serial-log` | string | `""` | Capture the client console to this file instead of the terminal |
| `--expect` | string | `""` | With `--serial-log`: stop, successfully, when this text appears on the console; fail when the context ends first |
| `--debug` | bool | `false` | Debug output |

```bash
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso
sudo platformctl iso test pxe \
    --kernel ./vmlinuz --initrd ./initramfs --args "console=ttyS0"

# The Raspberry Pi stand-in: U-Boot → DHCP (arch 0x000b) → signed arm64 iPXE
# → per-architecture script → signed kernel + initrd, unattended.
sudo platformctl iso test pxe --architecture aarch64 \
    --kernel ./vmlinuz-lts --initrd ./initramfs-lts \
    --args "console=ttyAMA0,115200 ip=dhcp modloop=http://10.99.99.1:8080/files/modloop-lts" \
    --serial-log work-pxe/serial.log --expect "Welcome to Alpine"
```

On aarch64 the client is the platform's own U-Boot with PK/KEK/db compiled
in, so it verifies every EFI image it loads: the PXE server signs the
`snponly-aarch64.efi` it serves with `DB.key`, and the command decompresses
and signs the kernel the same way before publishing the boot entry. A local
(`file://`) kernel or initrd is copied into `<work-dir>/pxe-files/`, which
is served at `/files/`, and the boot script fetches it from there; anything
else you put in that directory (the Alpine modloop, say) is served the same
way.

**It requires root** and says so before doing anything —
*"pxe boot test requires root privileges for network setup: please run with
sudo"*. Bridge and TAP creation cannot be done unprivileged.

The isolated network it builds is `DefaultTestEnvConfig()`: bridge `pxe-br`,
TAP `tap-pxe-client`, subnet `10.99.99.0/24`, server `10.99.99.1`, DHCP range
`10.99.99.100`–`10.99.99.200`. Those are constants in `pkg/ipxe/testenv.go`, not
flags — if they collide with something on your host, change the constants.

**A PXE server failure and a QEMU failure are reported together.**
`PXEServerQEMUError` carries both causes and implements `Unwrap() []error`, so
`errors.Is` matches either. When the test fails, read both halves: a QEMU error
is usually the consequence, not the cause.

---

## 4. What no CLI covers

| Capability | Reach it with |
|---|---|
| Register / list / get / remove a PXE device | REST `/api/v1/pxe/devices`, gRPC `PXEService`, QUIC, MCP |
| **Authorize / quarantine / retry** a device | REST, gRPC, QUIC, MCP |
| PXE device events, service status, start / stop the service | REST, gRPC, QUIC, MCP |
| Stage a per-MAC hostname or `installer.yaml` | `PUT /config/mac/{mac}/{key}` on the boot server ([api.md](api.md) §3) |
| Read an uploaded install log | `GET /installs/` in a browser, or the file under `<InstallsDir>` |
| Run a boot server outside the container | Embed `ipxe.NewServer` — [api.md](api.md) §2 |

All of the first three rows are documented in
[`docs/provisioning/api.md`](../provisioning/api.md) §2.

---

## 5. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the
requirement is unmet repo-wide. It is additionally unclear whether `pxeboot` —
a container entrypoint using Go's `flag` package rather than cobra — would be in
scope for that suite at all.
