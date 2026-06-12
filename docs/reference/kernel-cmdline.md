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
| `platform_config` | `iso create --config-server` | `autoinstall.sh` | Dynamic config-server base URL |
| `platform_hostname` | `iso create --platform-config` with `os.hostname` set | `autoinstall.sh` | Hostname override (hostname PRIO 0) |
| `platform_debug_sink` | Auto-detected via DHCP server, or operator-set | `autoinstall.sh`, `platform-initrd` | HTTP sink for install-log + `/config/mac` fetches |
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
**Set by:** `platformctl iso create --config-server <URL>` bakes this
into the GRUB / iPXE kernel cmdline via
`pkg/iso/customize.go::buildDynamicConfigParams`.
**Read by:** `autoinstall.sh` in the Alpine live environment.
**Behavior:** Autoinstall appends `/<mac-dashed>/installer.yaml` and
performs HTTP GET. If it returns 2xx and looks like YAML, the body
becomes the device config. On any failure, falls through to
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
platform_debug_sink=198.51.100.91:8080
```

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
bootstrap_strategy=<s>        passed to provisioning client     trust.default.strategies: [<s>]
bootstrap_dns=<server>        passed to provisioning client     trust.default.dane.dns-server: <server>
bootstrap_noise_key=<hex>     passed to provisioning client     trust.default.noise.server-static-key: <hex>
bootstrap_spki_pin=<pin>      autoinstall.sh writes pin to      trust.default.spki.pin-file:
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
| `default` | dane, noise, spki, embedded, tofu | First-boot CA bundle fetch; provisioning client TLS |
| `bmc` | dane, spki, ca-file, tofu | BMC Redfish / IPMI-over-TLS client |
| `internal` | platform-ca | Intra-platform mTLS (attestation push, SDN reporter) |

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

---

## 5. Hardware-Specific Parameters

### Supermicro X10 (X10SDV-TP8F)

```
console=ttyS1,115200 earlycon=uart8250,io,0x2f8,115200
```

X10 SoL is wired to COM2 (ttyS1, I/O 0x2f8), not COM1. See
`feedback_x10_bios_flash_wipes_uefi_nvram.md` memory entry.

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
