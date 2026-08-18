# iPXE Network Boot — CLI

> **Status: NORMATIVE** · Scope: `cmd/pxeboot`, `platformctl iso test pxe` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. `pkg/ipxe` has no CLI of its own

**There is no `platformctl pxe` and no `platformctl ipxe` command group.**
Neither appears in the `rootCmd.AddCommand` list in
`pkg/cli/commands/root.go` (read 2026-08-18); `pkg/ipxe` exports a library and
nothing else.

Two command-line surfaces reach it, and they are for different audiences:

| Surface | Audience | What it is |
|---|---|---|
| `pxeboot` | An operator or an orchestrator running the bootstrap container | A container entrypoint with flags. Not a subcommand of anything. |
| `platformctl iso test pxe` | An engineer | A test harness that stands up an isolated network, runs a PXE server on it, and boots a QEMU client. |

Everything an operator would want to *do* to a PXE device — register, list,
authorize, quarantine, retry, start or stop the service — is **API-only** and
belongs to provisioning. There is no CLI for it at all; see
[`docs/provisioning/cli.md`](../provisioning/cli.md) §5, which records the same
absence.

---

## 2. `pxeboot`

```
pxeboot --manifest <path> --kernel <path> --initrd <path> \
        --dhcp-server-ip <ip> --dhcp-range-start <ip> --dhcp-range-end <ip> [flags]
```

A minimal entrypoint (`cmd/pxeboot/main.go`) that builds a
`container.ServerConfig` and delegates to `container.Server`, which wraps
`ipxe.Server` with manifest-based boot-script generation. It uses Go's
`flag` package, so flags take **one leading dash or two** and there are no
short forms and no subcommands.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--manifest` | string | `""` | **yes** | Path to `manifest.yaml` |
| `--kernel` | string | `""` | **yes** | Path to `vmlinuz` |
| `--initrd` | string | `""` | **yes** | Path to `initramfs` |
| `--dhcp-server-ip` | string | `""` | **yes** | DHCP server IP address |
| `--dhcp-range-start` | string | `""` | **yes** | First allocatable address |
| `--dhcp-range-end` | string | `""` | **yes** | Last allocatable address |
| `--config-dir` | string | `/data/configs` | no | Directory of per-device configs |
| `--interface` | string | `eth0` | no | Network interface to bind |
| `--http-port` | int | `8080` | no | HTTP server port |
| `--tftp-port` | int | `69` | no | TFTP server port |
| `--dhcp-gateway` | string | `""` | no | Gateway to advertise |
| `--dhcp-dns` | string | `""` | no | Comma-separated DNS servers to advertise |
| `--apk-mirror` | string | `""` | no | Install-time APK mirror base; empty uses `container.DefaultAPKMirror` (the public Alpine mirror) |
| `--alpine-version` | string | `""` | no | Alpine version of the staged kernel/initramfs; empty uses `container.DefaultAlpineVersion` (`3.22.2`) |

```bash
pxeboot \
  --manifest /data/manifest.yaml \
  --kernel /data/vmlinuz --initrd /data/initramfs \
  --interface eth0 \
  --dhcp-server-ip 10.10.0.1 \
  --dhcp-range-start 10.10.0.100 \
  --dhcp-range-end 10.10.0.200 \
  --dhcp-gateway 10.10.0.1 \
  --dhcp-dns 10.10.0.1 \
  --apk-mirror http://mirror.example.com:8080 \
  --alpine-version 3.22.2
```

**Missing required flags produce one message naming all of them** —
*"required flags not set: --manifest, --kernel, …"* — then `flag.Usage()` and
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
| `--secure-boot` | bool | `false` | UEFI Secure Boot on the client |
| `--debug` | bool | `false` | Debug output |

```bash
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso
sudo platformctl iso test pxe \
    --kernel ./vmlinuz --initrd ./initramfs --args "console=ttyS0"
```

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
