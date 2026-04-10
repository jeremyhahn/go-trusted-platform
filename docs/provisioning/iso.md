# ISO Configuration

The platform ISO supports three modes of configuration delivery: embedded config, server-fetched config, and interactive provisioning.

## Build Modes

### Embedded Config (Traditional)

Build an ISO with the platform config baked in:

```bash
platformctl iso create --config platform-config.yaml
```

The config is embedded at `/media/cdrom/configs/config.yaml` and used as a fallback when server-based delivery is unavailable.

### Server-Fetched Config

Build an ISO that fetches config from a server at boot time:

```bash
platformctl iso create \
  --config-server https://platform.example.com:8443 \
  --bootstrap-strategy dane \
  --bootstrap-dns 8.8.8.8
```

This injects kernel command line parameters so the device bootstraps trust and fetches its config automatically.

### Hybrid (Recommended)

Embed a default config AND point to a server. The device tries the server first and falls back to the embedded config:

```bash
platformctl iso create \
  --config platform-config.yaml \
  --config-server https://platform.example.com:8443 \
  --bootstrap-strategy dane
```

### Minimal (Interactive Only)

Build an ISO with no config — devices must be provisioned interactively via QR code:

```bash
platformctl iso create
```

At boot, the device enters interactive QR mode if `platform_server` is set in the kernel cmdline.

## Config Resolution at Boot

The `autoinstall.sh` script resolves config in this order:

| Priority | Source | How |
|----------|--------|-----|
| 1 | Server | Kernel param `platform_config=<url>` triggers trust bootstrap + HTTPS fetch |
| 2 | USB | Scans removable media for `/platform/config.yaml` |
| 3 | Embedded | `/media/cdrom/configs/config.yaml` or `installer.yaml` (legacy) |
| 4 | Interactive | QR code displayed, operator provisions via web UI |
| 5 | Error | Fatal with diagnostic message listing all sources tried |

## USB Provisioning

Place a config file on a USB drive:

```
/platform/
  config.yaml    # Full app.App platform configuration
```

Insert the USB before booting the ISO. The config is detected automatically.

## Kernel Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `platform_config` | — | Server URL for automatic config fetch |
| `platform_server` | — | Server URL for interactive mode only |
| `bootstrap_strategy` | `auto` | DANE, Noise, SPKI, or auto |
| `bootstrap_dns` | — | DNS server for DANE TLSA lookups |
| `bootstrap_noise_key` | — | Noise_NK server public key (hex) |
| `bootstrap_spki_pin` | — | SPKI certificate pin (SHA-256) |
| `eab_kid` | — | EAB key ID for authentication |
| `eab_hmac` | — | EAB HMAC key (base64) |

## Single Universal ISO

A single ISO image works for any device and any configuration. The config is NOT baked into the ISO — it comes from the server, USB, or interactive provisioning. This enables:

- One ISO for an entire fleet
- Per-device configs managed server-side
- Operator-provisioned systems via QR code
- Air-gapped deployments via USB
