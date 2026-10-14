# Autoinstall Script Reference

> **Status: REFERENCE** · Last verified: 2026-10-14
> The embedded `autoinstall.sh`: config and hostname resolution, log upload and failure handling.

Reference for `autoinstall.sh` — the shell script that runs inside the
Alpine live environment during ISO-based installs. It resolves the
device config and hostname, runs `platformctl install system` (which
partitions the disk, installs the UKI and stores the LUKS keys for
first-boot sealing), uploads the install log, and powers off or reboots.

The script is embedded into ISOs at build time by `pkg/iso/customize.go`.
Do not edit `autoinstall.sh` in isolation — edit the heredoc in
`customize.go` so the embedded copy matches.

For the bootstrap-level context in which autoinstall runs, see
`docs/architecture/bootstrap-flow.md` and
`docs/bootstrap/architecture.md` (Phase 3 · Control plane).

---

## 1. Responsibilities

In order of execution:

1. Resolve device config (priority chain — §2)
2. Resolve hostname (priority chain — §3)
3. Pick the target: `/dev/nbd0` on a `diskless-nbd` node
   (`nbd_install_target`; no local disk is scanned), otherwise the first
   non-removable, writable disk of at least 8 GB
4. Run `platformctl install system`, which:
   - partitions the target disk (GPT, EFI + LUKS-wrapped root);
   - formats the filesystems (FAT32 EFI, ext4 root inside LUKS);
   - installs the UKI and tools;
   - adds the LUKS keys and stores them in `installer.luks` for
     first-boot sealing (§7);
   - creates a UEFI boot entry, keeping the fallback bootloader path
     if that fails.
5. Upload install.log to the deployer (§5)
6. Run the `after-install` action — `poweroff` by default, or `reboot`

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

Implementation: `pkg/iso/customize.go` (search for
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
`resolve_platform_hostname()` (embedded shell).

---

## 4. Kernel Command-Line Parameters Consumed

Full reference at `docs/reference/kernel-cmdline.md`. Parameters read
by `autoinstall.sh`:

| Parameter | Purpose |
|-----------|---------|
| `platform_config=<URL>` | Dynamic config-server base URL |
| `platform_hostname=<name>` | Hostname override (PRIO 0 of hostname chain) |
| `platform_debug_sink=<host:port>` | Deployer HTTP sink for install-log + /config/mac fetches |
| `platform_debug=1` | Passes `--password "password"` to the installer (§9) |

`pkg/iso` also bakes `bootstrap_strategy`, `bootstrap_dns`,
`bootstrap_noise_key` and `bootstrap_spki_pin` from the build config when
they are set. The script does not read them, and nothing in this
repository parses them from `/proc/cmdline`.

---

## 5. Install-Log Upload

After install (success or failure), autoinstall appends a postmortem
manifest to `/tmp/install.log` and `PUT`s it to:

```
PUT http://<platform_debug_sink>/installs/mac/<mac>/install.log
PUT http://<platform_debug_sink>/installs/<hostname>/install.log
```

The MAC path (lowercase, dashed) is what the orchestrator polls; without
a MAC the first upload uses the hostname path. Progress checkpoints go to
`/installs/<hostname>/checkpoint-<name>.txt`. The receiving end is the
iPXE HTTP server ([`docs/ipxe/api.md`](../ipxe/api.md)).

If `platform_debug_sink` is not set on the cmdline, autoinstall
auto-detects the DHCP server from the leases file and uses
`<dhcp-server>:8080`. This matches the deployer's pxeboot HTTP
server port in the standard bootstrap topology.

---

## 6. Disk Partitioning Layout

Produced layout on target disk:

```
  /dev/sda (GPT)
  ├── /dev/sda1  538 MiB (default)  FAT32  EFI system partition (ESP)
  │     ├── /boot/efi (after install)
  │     ├── EFI/BOOT/BOOTX64.EFI (the UKI)
  │     └── tpm2/installer.luks (keys for first-boot sealing)
  └── /dev/sda2  remainder LUKS2 container
        └── cryptroot (mapper)
              └── ext4 root filesystem
                    ├── /etc/trusted-platform/config.yaml (resolved config)
                    └── /var/lib/trusted-platform/
```

The ESP size comes from `disk.efi_size` (default 538 MiB). LUKS2
keyslot 0 holds the install passphrase. Keyslot 1 holds a random 32-byte
key that first boot seals to the TPM. Keyslot 2 holds the recovery key,
which is handled per `recovery-key-strategy` ([factory-reset.md](factory-reset.md)).
First boot kills keyslot 0.

---

## 7. TPM Sealing at First Boot

- `autoinstall.sh` does not seal. `platformctl install system`
  (`prepareLUKSKeyForTPM` in `pkg/installer`) adds the keyslot 1 and 2
  keys, then stores them in the encrypted `installer.luks` container on
  the ESP. No plaintext key is written.
- First boot seals the keyslot 1 key to the TPM PCR policy
  (`FirstbootSealStrategy` in `pkg/firstboot/strategy.go`, files
  `seal-platform.pub` / `seal-platform.priv`; PCRs in `docs/tpm/pcrs.md`).
- Unseal at runtime lives in `platform-initrd` — see
  `docs/installer/architecture.md` §5 (Phase B — first production boot).

---

## 8. Failure Paths

| Stage | Failure | Autoinstall behavior |
|-------|---------|----------------------|
| Config resolve | All three priorities fail | Drops to `/bin/sh`; install-log shows diagnostics |
| Target | No local disk qualifies (not a `diskless-nbd` node) | `error`: stops before the installer runs |
| Target | `diskless-nbd` node whose `/dev/nbd0` is not attached to its export | The installer refuses with `ErrorTypeNBDTarget` before the TPM or the export is touched; uploads log; **stops in the installer** ([engineering](engineering.md#attaching-before-the-install)) |
| Partition | Target disk missing or too small | Aborts; uploads log with the exit code; **stops in the installer** |
| LUKS format | Entropy starvation, keyslot init fail | Aborts; uploads log; **stops in the installer** |
| LUKS keys | Keyslot add, missing platform config or `installer.luks` creation fails | Aborts; uploads log; **stops in the installer**. TPM sealing is a first-boot step (§7), not an install failure |
| UEFI boot entry | `efibootmgr --create` fails | Logs a warning and continues; firmware finds the UKI at the fallback path `EFI/BOOT/BOOTX64.EFI` |
| Completion | UKI absent or empty on the ESP, a device refuses `blockdev --flushbufs`, or a mount survives even a lazy unmount | Aborts; uploads log; **stops in the installer** |
| Upload | No sink resolved, or the sink is unreachable | Install continues; the log is not uploaded and is not saved to the target disk |

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

There is no `platform_autoinstall_debug` parameter and no `set -x` mode.
`pkg/iso` bakes `platform_debug=1` onto every ISO's kernel command line
(see [engineering.md](engineering.md) §10). With it, the script passes
`--password "password"` to `platformctl install system`, so keyslot 0
holds a known passphrase until first boot kills it.

The install trace is `/tmp/install.log`. On failure the wrapper dumps it
to the console. It is uploaded per §5 whenever a sink resolves. Use
`console=ttyS1,115200` on X10 hardware or `console=ttyS0,115200` on
generic hardware to watch over BMC serial-over-LAN.

---

## 10. See Also

- `docs/architecture/bootstrap-flow.md` — overall bootstrap architecture
- `docs/bootstrap/architecture.md` (Phase 3 · Control plane) — orchestrator side of config delivery
- `docs/installer/architecture.md` §5 (Phase B) — post-reboot boot path
- `docs/installer/iso-building.md` — how the ISO was built
- `docs/reference/kernel-cmdline.md` — all recognized cmdline params
- `docs/tpm/pcrs.md` — PCR policy used by LUKS seal
