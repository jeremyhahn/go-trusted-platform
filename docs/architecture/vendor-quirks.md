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

// MoreSpecific reports whether identity a resolves a strictly more specific
// registry entry than identity b. For callers choosing between two readings
// of the same hardware; ordering follows the lookup precedence below.
func MoreSpecific(a, b Identity) bool
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
| `BootOverrideStrategy` | `string` | Vendor boot-override backend to try before Redfish PATCH (`smc-oem-ipmi` is the only registered name; `""` means PATCH only; an unregistered name fails `SetBootDevice` with `ErrUnknownBootOverrideStrategy`) | `""` |

The BMC-facing fields are specified in [`docs/bmc/architecture.md`](../bmc/architecture.md) §7.

### Lookup precedence

1. Board-specific entry for the manufacturer — model substring **or**
   part-number prefix (`Identity.PartNumber`, for firmware whose `Model` is a
   placeholder). The most specific entry wins: an exact model match beats a
   substring or prefix hit, then the longer matching key; declaration order
   only breaks exact ties, so a narrower entry can be appended after the
   broader one it refines.
2. Manufacturer-wide default (no model or part-number key).
3. `Default()` — generic cross-vendor safe values.

All matching is case-insensitive. The normative description lives in
[`docs/bmc/architecture.md`](../bmc/architecture.md) §7.

### Registry entries (as of Phase 5)

| Key | SOL port | Earlycon IO | Samba proto | Notes |
|-----|----------|-------------|-------------|-------|
| Supermicro (any model) | ttyS0 | 0x3f8 (COM1) | NT1 | X10/X11 BMC virtual-media limitation |
| Supermicro X10SDV | ttyS0 | 0x3f8 (COM1) | NT1 | COM1 SOL, payload instance 1 — measured on node-02 2026-08-29 (the entry claimed COM2 until #102); matched by `Model` ⊇ `x10sdv` or `PartNumber` prefix `SYS-5018D-FN` (FN8T = X10SDV-TP8F, FN4T = X10SDV-TLN4F; `SYS-5018D-MTF`/`-MTLN4F`/`-MF` are X10SLM-F and stay manufacturer-wide); exists for the part-number identity match and the boot-override trap |
| Aspeed (any model) | ttyS4 | 0x3f8 (COM1) | SMB2 | vUART module; Alpine LTS does not ship it |
| Dell Inc. (any model) | ttyS0 | 0x3f8 (COM1) | SMB2 | iDRAC SOL on COM1 |
| HPE (any model) | ttyS0 | 0x3f8 (COM1) | SMB2 | iLO SOL on COM1 |
| (default) | ttyS0 | 0x3f8 (COM1) | SMB2 | Safe cross-vendor baseline |

## How Core Code Consumes Quirks

### `pkg/installer/installer.go` — UKI kernel cmdline

The `buildUKI` function calls
`quirks.ResolveIdentity(config.OS.hardwareIdentity())` and appends
`quirk.KernelCmdline` to the UKI command line; `newAlpineInstaller` resolves
the same identity for the serial-console and Samba settings. No inline vendor
strings remain.

`HardwareManufacturer`, `HardwareModel` and `HardwarePartNumber` are fields on
`installer.Config` (YAML keys `hardware-manufacturer`, `hardware-model` and
`hardware-part-number`), propagated to `OSConfig` by `NewInstaller`. They are
the same three fields the BMC clients match on (Redfish `System.Manufacturer`
/ `Model` / `PartNumber`; FRU Board Product / Product Part Number over IPMI),
so the installed OS and the BMC side resolve the same entry — the part number
is what names the board on firmware that serves a placeholder `Model`.

The bootstrap orchestrator populates them. During discovery it asks each
BMC-managed node's `bmc.Client` for `HardwareIdentity` — the identity that
client resolves its own quirk entry from, not a second lookup rebuilt from
`SystemInfo`, whose fields differ — and `resolveNodeConfig` writes the three
keys into the node's merged installer config. Both sides therefore match on
one identity and land on one registry entry.

Precedence inside the merged config is `template -> platform globals ->
discovered hardware identity -> per-node overrides`, so an operator who pins
the keys by hand for a BMC that misreports itself still wins.

Two BMC outcomes are handled differently on purpose:

| BMC outcome | What is written | What the installed OS resolves | Log |
|---|---|---|---|
| Named all three fields | the three keys | the same entry the BMC side uses | INFO |
| Named only some of them | what it named | the same entry the BMC side uses | **WARN**, naming the missing fields |
| Answered, named nothing | the three keys, empty | `Default()` — the same entry the BMC side uses | WARN |
| Failed partway, having learned something | the partial identity, after retrying | the same entry the BMC side uses | **WARN**, naming the missing fields |
| Failed, having learned nothing | nothing | whatever the config already carried | DEBUG |

**The decision, recorded:** an incomplete identity is *propagated*, not
refused. Declining to populate the keys unless all three fields are present
was considered and rejected — the BMC client resolves its own quirk from that
same incomplete value, so refusing would put the installed OS on `Default()`
while the BMC sat on the vendor entry: the divergence this exists to prevent,
in a new costume. Parity is the rule, not confidence.

The cost is real and is why the WARN exists. An identity missing both `Model`
and `PartNumber` can only ever reach a manufacturer-wide entry, never a
board-specific one, so such a node installs against a different quirk than a
fully-identified one — and nothing downstream reports it, because it is not
an error. The capture-time log names the missing fields and whether a board
entry is reachable at all (`board_entry_reachable` — true only when the BMC
named a manufacturer AND a model or part number, since every registry entry
requires a manufacturer match before any board rule can apply). That line is
what a deploy postmortem needs to explain which entry a node actually used.

**A retryable failure is re-read before it is staged.** An error from
`HardwareIdentity` means the client did not cache the answer, so a later BMC
operation will try again and may resolve a *more specific* entry — the FRU
read that timed out can succeed a second later and name the board. The
installer config is written once, so staging the first partial answer would
freeze the installed OS on the manufacturer-wide entry while the BMC side
went on to use the board entry: parity lost in the one direction nothing
downstream can correct. `readHardwareIdentity` therefore re-reads (bounded,
context-aware) before settling. Retrying does not guarantee agreement — the
BMC can still recover after the config is written — but it removes the case
where a cheap chance to agree was available and not taken. Whatever the last
attempt learned is still staged, so a partial answer remains preferable to
none.

Attempts are not monotonic, so the *best* answer any **failed** attempt
produced is what gets staged — not the last one. Attempt 1 can name the vendor and fail on the
FRU while attempt 3 fails earlier still and names nothing (a dropped session).
Keeping the last answer would let that later zero erase the vendor and report
"learned nothing", reintroducing through the retry the very case the retry was
added to prevent.

"Best" is decided by **quirk specificity first**, with the count of populated
fields only as the tiebreaker (`quirks.MoreSpecific`, then
`identityFieldsMissing`). Counting fields alone gets the staged entry wrong on
this project's own hardware: a Supermicro X10 that answers
`{Manufacturer, Model:"Super Server"}` on one attempt and
`{Manufacturer, PartNumber:"SYS-5018D-FN8T-AS001"}` on the next leaves both
answers one field short, yet only the second reaches `supermicro/x10sdv` — the
placeholder `Model` falls through to the manufacturer-wide `supermicro` entry.
Keeping the first because it arrived first stages the wrong quirk, and the
installer config is written once. Where two answers resolve the same entry the
richer one is staged, because the extra field is what a human reading the
staged config — or a later registry entry — has to go on.

A **successful** read ends the loop and is staged as-is, even when an earlier
failed attempt had learned more. A nil error is the client's definitive answer
and the value it caches and resolves its own quirk from, so staging anything
else — however much richer — is precisely the divergence this path exists to
prevent. The earlier attempt's extra field came from a FRU read that is now
known to be unavailable rather than slow. Parity beats richness.

Note that the second row arrives looking like success: the IPMI path returns
a vendor-only identity with a **nil** error when the FRU is definitively
unavailable ("FRU unavailable, vendor-only identity"). Completeness is
therefore checked on the value, not inferred from the error.

The keys survive the load path because `app.App` declares them too: on-disk
configs reach the installer through `loadUnifiedConfig`, which unmarshals
into `App` and returns `App.GetInstallerConfig()`, so a field `App` does not
carry never reaches `quirks.ResolveIdentity`.

Clearing the keys on an answering-but-unidentified BMC is the point of the
second row: a stale template value left behind would send the installed OS
to a board entry the BMC side does not use.

The third row is the same rule applied to a half-answer. The IPMI path names
the vendor from Get Device ID and can then time out reading the FRU; it
returns that partial identity alongside the error, and the BMC client
resolves its own quirk from it. Staging the partial value keeps the two
sides together on the vendor entry; discarding it would drop the installer
to `Default()` while the BMC stayed on the vendor quirk.

Only the last row is genuinely unknown rather than unidentified, so it is
the only one where a hand-pinned identity is left alone.

`bmc.Client.HardwareIdentity` takes the client's lifecycle pin itself, since
an out-of-process caller has no other way to hold one; the internal callers
go through an unlocked variant because they already hold it and a recursive
read lock would deadlock against a waiting `Close`.

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
