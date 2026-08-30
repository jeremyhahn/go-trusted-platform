# Vendor Quirks Architecture

This document is the authoritative audit of hardware vendor-specific behaviour
in the go-trusted-platform codebase and describes how it is isolated via the
`pkg/quirks` abstraction layer.

## Audit Findings

The following table records every vendor-specific code fragment found during
the Phase 5 audit, where it lived before the refactoring, what it conditioned
on, and when it applied.

| Quirk | Original location | File(s) | Conditioned on | Applies at |
|-------|-------------------|---------|----------------|-----------|
| Aspeed AST2400/2500 vUART — kernel module `8250_aspeed_vuart` + `console=ttyS4` | Comment only; module deliberately excluded for Alpine compatibility | `pkg/installer/alpine.go:685` | Manufacturer "Aspeed", Aspeed BMC chipset | Install time (dracut modules) |
| Supermicro X10 — SOL wired to COM2 (`ttyS1`, 0x2f8) | Inline cmdline literals; misleading comment said "we put ttyS1 last because X10SDV-TP8F" | `pkg/iso/customize.go:1372`, `pkg/installer/installer.go:1048` | Model string "X10SDV" (Supermicro X10SDV-TP8F) | Install time (UKI cmdline), ISO boot (GRUB cmdline) |
| Supermicro X10/X11 BMC — SMB1 (NT1) required for virtual-media mounts | Hardcoded `server min protocol = NT1`, `client min protocol = NT1` | `build/docker/bootstrap/smb.conf:29-30` | Manufacturer "Supermicro", X10/X11 generation BMC firmware | Bootstrap time (Samba server config) |
| Supermicro X10 — SMB encryption disabled (cleartext) | Hardcoded `smb encrypt = disabled` | `build/docker/bootstrap/smb.conf:35` | Manufacturer "Supermicro", BMC stack limitations | Bootstrap time (Samba server config) |
| Supermicro X10 — ACPI S5 reboot bug; SysRq-b required | Comment explaining HardReset strategy, no vendor branch in code | `pkg/installer/hardreset.go:28,64` | Informational comment only | Runtime (reboot sequence) |
| Supermicro UEFI — caches stale partition tables; needs disk wipe | Comment explaining `dd` zeroing strategy, no vendor branch in code | `pkg/installer/disk.go:71` | Informational comment only | Install time (disk prep) |
| Generic dual-UART coverage — `earlycon=uart8250,io,0x3f8` + ttyS0+ttyS1 | Inline hardcoded cmdline strings | `pkg/installer/installer.go:1046-1049`, `pkg/iso/customize.go:1372` | All supported platforms (generic default) | Install time (UKI cmdline), ISO boot |

### Notes

- The `8250_aspeed_vuart` module is documented in comments but **was never
  loaded** in the Alpine install path. The comment explicitly states "We
  deliberately do NOT add 8250_aspeed_vuart here" (Alpine LTS kernel does not
  ship the module). The quirks registry carries the entry for non-Alpine
  distributions that do ship the module.

- The Samba `smb.conf` is a static file in the bootstrap Docker image. Its
  vendor-specific settings (`NT1`, `smb encrypt = disabled`) are documented in
  the `pkg/quirks.Quirk` struct fields `SambaMinProtocol` and `SambaEncryption`
  for reference, but the smb.conf itself is not dynamically generated. Templating
  the smb.conf from quirks data is deferred until a templated bootstrap config
  system is introduced.

- "Informational comment only" rows contain no branching code — the comment
  explains why a particular strategy was chosen, but there is no
  `if manufacturer == "Supermicro"` guard. They are listed for completeness.

## `pkg/quirks` Package

### Purpose

`pkg/quirks` is the single authoritative location for all hardware
vendor-specific configuration. Adding support for a new board is a
**data-only change** in `pkg/quirks/registry.go` — no core installer or
ISO code needs to change.

### API

```go
// ResolveIdentity returns the best-matching Quirk for the hardware identity.
// Always returns a valid Quirk; falls back to Default() when no match.
func ResolveIdentity(id Identity) Quirk

// Resolve is ResolveIdentity with no part number.
func Resolve(manufacturer, model string) Quirk

// Default returns the generic cross-vendor Quirk.
func Default() Quirk
```

### Quirk struct fields

| Field | Type | Meaning | Default |
|-------|------|---------|---------|
| `KernelModules` | `[]string` | Extra dracut `add_drivers` entries | nil |
| `KernelCmdline` | `[]string` | Full ordered console/earlycon params | generic dual-UART |
| `SOLPort` | `string` | Primary SOL tty device name | `"ttyS0"` |
| `EarlyconSpec` | `string` | `earlycon=` value (without the prefix) | COM1 spec |
| `SambaMinProtocol` | `string` | Samba `server min protocol` value | `"SMB2"` |
| `SambaEncryption` | `string` | Samba `smb encrypt` value | `"required"` |
| `Key` | `string` | Informational name of the entry that won (`supermicro/x10sdv`, `default`, …), for logs | `"default"` |
| `SOLPayloadInstance` | `byte` | IPMI 2.0 SOL payload instance the BMC streams the console on | `0x01` |
| `BootMediaType` | `MediaType` | Vendor CD/DVD aliases for `BootSourceOverrideTarget` (`CDDVDAlias`, `UEFICDAlias`) | none (DMTF only) |
| `CertBackendFallback` | `[]string` | Ordered `CertBackend` names for `AutoCertManager` | nil |
| `VmediaRedfishOEMFallback` | `bool` | Treat a 404 on DMTF virtual-media actions as "use the OEM backend" | `false` |
| `BootOverrideContinuous` | `bool` | Always request `BootSourceOverrideEnabled=Continuous` | `false` |
| `BootOverrideStrategy` | `string` | Vendor boot-override backend to try before Redfish PATCH (`smc-oem-ipmi`, `smc-cgi`) | `""` |

The BMC-facing fields are specified in [`docs/bmc/architecture.md`](../bmc/architecture.md) §7.

### Lookup precedence

1. Board-specific entry for the manufacturer — model substring **or**
   part-number prefix (`Identity.PartNumber`, for firmware whose `Model` is a
   placeholder) — first declared wins.
2. Manufacturer-wide default (no model or part-number key).
3. `Default()` — generic cross-vendor safe values.

All matching is case-insensitive. The normative description lives in
[`docs/bmc/architecture.md`](../bmc/architecture.md) §7.

### Registry entries (as of Phase 5)

| Key | SOL port | Earlycon IO | Samba proto | Notes |
|-----|----------|-------------|-------------|-------|
| Supermicro (any model) | ttyS0 | 0x3f8 (COM1) | NT1 | X10/X11 BMC virtual-media limitation |
| Supermicro X10SDV | ttyS0 | 0x3f8 (COM1) | NT1 | COM1 SOL, payload instance 1 — measured on lab-node-2 2026-08-29 (the entry claimed COM2 until #102); exists for the part-number identity match and the boot-override trap |
| Aspeed (any model) | ttyS4 | 0x3f8 (COM1) | SMB2 | vUART module; Alpine LTS does not ship it |
| Dell Inc. (any model) | ttyS0 | 0x3f8 (COM1) | SMB2 | iDRAC SOL on COM1 |
| HPE (any model) | ttyS0 | 0x3f8 (COM1) | SMB2 | iLO SOL on COM1 |
| (default) | ttyS0 | 0x3f8 (COM1) | SMB2 | Safe cross-vendor baseline |

## How Core Code Consumes Quirks

### `pkg/installer/installer.go` — UKI kernel cmdline

The `buildUKI` function calls `quirks.Resolve(config.HardwareManufacturer,
config.HardwareModel)` and appends `quirk.KernelCmdline` to the UKI command
line. No inline vendor strings remain.

`HardwareManufacturer` and `HardwareModel` are new fields on
`installer.Config` (YAML keys `hardware-manufacturer` and
`hardware-model`), populated from Redfish `System.Manufacturer` /
`System.Model` by the bootstrap orchestrator.

### `pkg/iso/customize.go` — GRUB cmdline

The ISO is built generically and must work on all supported hardware. The
GRUB customizer calls `quirks.Default()` and joins `KernelCmdline` into the
GRUB kernel line. No inline console strings remain.

## Adding a New Vendor

1. Open `pkg/quirks/registry.go`.
2. Add a new entry to the slice in `buildRegistry()` with the correct
   `mfr`, `model`, and `quirk` fields.
3. Add a unit test in `pkg/quirks/quirks_test.go` covering the new entry.
4. Run `make test` — no other files need to change.
