# ISO Configuration

> **Status: REFERENCE** · Last verified: 2026-10-15
> How the platform ISO receives its installer config: embedded or server-fetched.

The platform ISO gets its installer config one of two ways: embedded in the ISO
at build time, or fetched from a server at boot.

## Build Modes

### Embedded Config

Build an ISO with the platform config baked in:

```bash
platformctl iso create --platform-config platform-config.yaml
```

The config is embedded at `/media/cdrom/configs/installer.yaml` and must
contain `seal-pcrs:`. Without `--platform-config`, `iso create` looks for a
default under `configs/platform/` relative to the working directory
(`configs/platform/templates/single-node/default.yaml` first, then a
`--platform-type`-specific example). `--config` is a different flag: the ISO
*build* configuration file.

### Server-Fetched Config

Build an ISO that fetches its config from a server at boot time:

```bash
platformctl iso create \
  --config-server https://platform.example.com:8443 \
  --bootstrap-strategy dane \
  --bootstrap-dns 8.8.8.8
```

`--config-server` adds `platform_config=<url>` to the kernel command line,
plus `bootstrap_strategy` (only when not `auto`, the default), `bootstrap_dns`,
`bootstrap_noise_key` and `bootstrap_spki_pin` when set
(`buildDynamicConfigParams`, `pkg/iso/customize.go`). When no platform config
file is given or found, nothing is embedded and the device depends on the
server; without either, the build fails with
`platform config path is required`.

### Hybrid

Embed a config AND point to a server. The device tries the server first and
falls back to the embedded config:

```bash
platformctl iso create \
  --platform-config platform-config.yaml \
  --config-server https://platform.example.com:8443
```

## Config Resolution at Boot

The generated `autoinstall.sh` (`pkg/iso/customize.go`) resolves the installer
config in this order:

| Priority | Source | How |
|----------|--------|-----|
| 1 | Server | Kernel param `platform_config=<base_url>`: for each local NIC, GET `<base>/<mac-dashed>/installer.yaml`, then `<base>?mac=<mac-colons>` |
| 1b | Debug sink | Per-MAC fetch from the `platform_debug_sink` host |
| 2 | Embedded | `/media/cdrom/configs/installer.yaml` |
| 3 | Defaults | Built-in installer defaults |

The server fetch uses the ISO's `/media/cdrom/configs/ca-bundle.pem` when
present (`--ca-bundle`). It is a plain HTTPS GET: `autoinstall.sh` does not run
`platformctl bootstrap trust` or the config delivery API; see
[Config Delivery](config-delivery.md) for those.

## Kernel Parameters

`platform_config` is described in
[`docs/reference/kernel-cmdline.md`](../reference/kernel-cmdline.md) §2. The
`bootstrap_*` parameters `iso create` bakes are listed there in §3; no code
reads them.
