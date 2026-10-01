# Autoinstall Script Reference

Reference for `autoinstall.sh` — the shell script that runs inside the
Alpine live environment during ISO-based installs. It resolves the
device config, partitions disks, installs the UKI, seals LUKS to the
TPM, and reboots into the installed platform.

The script is embedded into ISOs at build time by `pkg/iso/customize.go`.
Do not edit `autoinstall.sh` in isolation — edit the heredoc in
`customize.go` so the embedded copy matches.

For the bootstrap-level context in which autoinstall runs, see
`docs/architecture/bootstrap-flow.md` and
`docs/bootstrap/config-delivery.md`.

---

## 1. Responsibilities

In order of execution:

1. Resolve device config (priority chain — §2)
2. Resolve hostname (priority chain — §3)
3. Partition target disk (GPT, EFI + LUKS-wrapped root)
4. Format filesystems (FAT32 EFI, ext4 root inside LUKS)
5. Mount install target, copy UKI + tools
6. Seal LUKS keyslot to TPM PCR policy
7. Install UEFI boot entry (or rely on fallback bootloader path)
8. Upload install.log to deployer
9. Reboot

---

## 2. Config Resolution Priority Chain

```
                ISO boot → autoinstall.sh starts
                          │
                          ▼
     ┌──────────────────────────────────────────────┐
     │ Read /proc/cmdline                           │
     │   platform_config=<URL>                      │
     └─────────┬───────────────────────┬────────────┘
               │ present               │ absent
               ▼                       │
  ┌─────────────────────────────┐      │
  │ PRIO 1 — Dynamic            │      │
  │   Discover local MAC        │      │
  │   Format lowercase dashed   │      │
  │   GET <URL>/<mac>/          │      │
  │       installer.yaml        │      │
  │   HTTP 200 + yaml-looking   │      │
  │     body → use it           │      │
  │   else fall through         │      │
  └─────────┬───────────────────┘      │
            │ fail                     ▼
            ▼                  ┌─────────────────────────────┐
            └─────────────────▶│ PRIO 2 — Baked              │
                               │   /media/cdrom/configs/     │
                               │     installer.yaml          │
                               │   exists → use it           │
                               └─────────┬───────────────────┘
                                         │ absent
                                         ▼
                               ┌─────────────────────────────┐
                               │ PRIO 3 — Fatal              │
                               │   echo diagnostics          │
                               │   exec /bin/sh              │
                               └─────────────────────────────┘
```

Implementation: `pkg/iso/customize.go` lines 2756–2870 (search for
`# Find installer configuration file`).

**The installed system's runtime config.** The installer copies
`/media/cdrom/configs/installer.yaml` onto the target as
`/etc/trusted-platform/config.yaml`. On a CD rebuilt from a netboot media
set's payload (`.payload-complete`) that file is the set's *baked* config, so
`stage_node_config` (`iso.NodeConfigFunction`) replaces it with the config
the install actually runs with — the node's own, fetched per MAC — and the
set's `ca-bundle.pem` with the fetched CA bundle, before the installer runs.
A failed copy ends the install: a node must never come up with the generic
config. A real CD (virtual media) is read-only and left alone.

---

## 3. Hostname Resolution Priority Chain

Hostname resolution is **independent of config resolution**. Even
when PRIO 2 (baked) wins the config race, PRIO -1 can override the
hostname:

```
                autoinstall needs hostname
                          │
                          ▼
  ┌──────────────────────────────────────────┐
  │ PRIO -1 — Orchestrator per-MAC publish   │
  │   For each local NIC MAC:                │
  │     GET http://<sink>/config/mac/<mac>/  │
  │         hostname                         │
  │   First 2xx wins                         │
  └──────────┬───────────────────────────────┘
             │ none
             ▼
  ┌──────────────────────────────────────────┐
  │ PRIO 0 — Kernel cmdline                  │
  │   /proc/cmdline: platform_hostname=X     │
  └──────────┬───────────────────────────────┘
             │ absent
             ▼
  ┌──────────────────────────────────────────┐
  │ PRIO 1 — Config yaml                     │
  │   Scan resolved config for               │
  │     os.hostname                          │
  └──────────┬───────────────────────────────┘
             │ empty
             ▼
  ┌──────────────────────────────────────────┐
  │ PRIO 2 — Alpine live env hostname        │
  │   `hostname` command fallback            │
  └──────────────────────────────────────────┘
```

Implementation: `pkg/iso/customize.go` function
`resolve_platform_hostname()` (embedded shell around line 2150).

---

## 4. Kernel Command-Line Parameters Consumed

Full reference at `docs/reference/kernel-cmdline.md`. Parameters read
by `autoinstall.sh`:

| Parameter | Purpose |
|-----------|---------|
| `platform_config=<URL>` | Dynamic config-server base URL |
| `platform_hostname=<name>` | Hostname override (PRIO 0 of hostname chain) |
| `platform_debug_sink=<host:port>` | Deployer HTTP sink for install-log + /config/mac fetches |
| `bootstrap_strategy=<dane|noise|spki|auto>` | Trust strategy (post-bootstrap only, passed through) |
| `bootstrap_dns=<server>` | DNS for DANE lookups |
| `bootstrap_noise_key=<hex>` | Noise_NK server public key |
| `bootstrap_spki_pin=<sha256>` | SPKI certificate pin |

---

## 5. Install-Log Upload

After install (success or failure), autoinstall POSTs to:

```
POST http://<platform_debug_sink>/install-log/<mac>/<status>
  status ∈ { success, failed }
  body: full install.log contents
```

If `platform_debug_sink` is not set on the cmdline, autoinstall
auto-detects the DHCP server from the leases file and uses
`<dhcp-server>:8080`. This matches the deployer's pxeboot HTTP
server port in the standard bootstrap topology.

---

## 6. Disk Partitioning Layout

Produced layout on target disk:

```
  /dev/sda (GPT)
  ├── /dev/sda1  512 MiB  FAT32  EFI system partition (ESP)
  │     └── /boot/efi (after install)
  └── /dev/sda2  remainder LUKS2 container
        └── crypt-root (mapper)
              └── ext4 root filesystem
                    ├── /boot (UKI lives here; loader picks it up)
                    ├── /etc/trusted-platform/config.yaml (resolved config)
                    └── /var/lib/trusted-platform/
```

LUKS2 keyslot 0 holds a TPM-sealed key (unlocked at boot by
`platform-initrd`). Keyslot 1 holds a passphrase for recovery — the
passphrase is printed to the console during install with a
"WRITE THIS DOWN" banner and appended to the install-log upload.

---

## 7. TPM Sealing at Install Time

- `autoinstall.sh` shells to `platformctl tpm seal --luks --device /dev/sda2`
  after LUKS2 is created.
- Seal binds the random LUKS key to a PCR policy including PCRs that
  span firmware → boot loader → UKI (see `docs/tpm/pcrs.md`).
- Unseal at runtime lives in `platform-initrd` — see
  `docs/installer/initrd-overview.md`.

---

## 8. Failure Paths

| Stage | Failure | Autoinstall behavior |
|-------|---------|----------------------|
| Config resolve | All three priorities fail | Drops to `/bin/sh`; install-log shows diagnostics |
| Partition | Target disk missing or too small | Aborts; uploads log with `failed` status; **stops in the installer** |
| LUKS format | Entropy starvation, keyslot init fail | Aborts; uploads log; **stops in the installer** |
| TPM seal | No TPM, wrong PCR state | Aborts; uploads log; **stops in the installer**. Operator must install a hardware TPM or switch to the swtpm variant |
| UKI install | EFI variable write rejected | Falls back to `EFI/BOOT/BOOTX64.efi` default path (see `docs/installer/initrd-overview.md` §UKI fallback) |
| Completion | UKI absent or empty on the ESP, a device refuses `blockdev --flushbufs`, or a mount survives even a lazy unmount | Aborts; uploads log; **stops in the installer** |
| Upload | `platform_debug_sink` unreachable | Install continues; log saved to `/var/log/trusted-platform/install.log` on disk for post-mortem |

### A failed install does not reboot

The `after-install` action (`reboot` or `poweroff`) applies to the **success**
branch only. On a non-zero installer exit the wrapper dumps `/tmp/install.log`
to the console, uploads the `install-failed` checkpoint and the log with its
exit code, then exits 1 — leaving the machine in the installer where the
failure can be read.

That matters most for the completion row above. Rebooting a host whose EFI
system partition has no bootloader on it produces an unbootable machine whose
install reported success, with the real cause a warning in a log nobody reads.

The chain is: `pkg/installer` returns an error → `platformctl install system`
returns `ErrInstallationFailed` → `cmd/platformctl` exits 1 → the wrapper's
`INSTALL_RESULT` is non-zero → the failure branch runs. Every link is required;
`TestAutoinstallScript_FailedInstallDoesNotReboot` in `pkg/iso` pins the last
two, because a test inside `pkg/installer` alone cannot see this seam.

---

## 9. Debugging

Enable verbose autoinstall by adding kernel cmdline:

```
platform_autoinstall_debug=1
```

This enables `set -x` in the autoinstall shell and streams each command
to the serial console. Combined with `console=ttyS1,115200` on X10
hardware or `console=ttyS0,115200` on generic hardware, the full
install trace is visible to anyone watching the BMC serial-over-LAN.

---

## 10. See Also

- `docs/architecture/bootstrap-flow.md` — overall bootstrap architecture
- `docs/bootstrap/config-delivery.md` — orchestrator side of config delivery
- `docs/installer/initrd-overview.md` — post-reboot boot path
- `docs/installer/iso-building.md` — how the ISO was built
- `docs/reference/kernel-cmdline.md` — all recognized cmdline params
- `docs/tpm/pcrs.md` — PCR policy used by LUKS seal
