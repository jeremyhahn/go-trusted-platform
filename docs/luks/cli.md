# LUKS Key-Slot Management — CLI

> **Status: NORMATIVE** · Scope: `platformctl luks` · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> Read out of the cobra declarations in `pkg/cli/commands/luks/*.go` on 2026-10-11.

---

## 1. Read this before anything else

**Every `platformctl luks` verb fails today.** Each verb runs its local checks
(root, flags, device detection) and then calls the daemon through
`platform.Client.LUKS()` on the selected transport. The server side is
registered on every transport but is not connected to a backend
([engineering.md](engineering.md) §6), so it refuses each call. This page
documents the verbs as declared, so the contract is fixed before the backend
wiring lands.

---

## 2. Command group

```
platformctl luks
    status             Show LUKS volume status
    list-slots         List active keyslots with backend type
    info               Full LUKS2 header: JSON metadata, keyslots, segments
    enroll-passphrase  Add a passphrase keyslot
    enroll-fido2       Add a FIDO2 keyslot (hmac-secret extension)
    enroll-tpm         Add a TPM2-sealed keyslot
    enroll-recovery    Generate and enroll a recovery key
    remove-key         Remove a keyslot (destructive)
    test-unlock        Check a keyslot
    change-passphrase  Replace the passphrase on a slot
```

### Migration from `platformctl fido2`

The LUKS-specific `fido2` verbs were removed with no compatibility shim:

| Old command | New command |
|---|---|
| `platformctl fido2 enroll` | `platformctl luks enroll-fido2` |
| `platformctl fido2 list` | `platformctl luks list-slots` |
| `platformctl fido2 remove` | `platformctl luks remove-key` |
| `platformctl fido2 test` | `platformctl luks test-unlock` |
| `platformctl fido2 info` (LUKS view) | `platformctl luks info` |

### Global flags

The `platformctl` persistent flags apply: `--config`/`-c`, `--context`,
`--transport`, `--server`, `--server-name`, `--output`/`-o`, `--verbose`/`-v`,
`--no-color`. See [`docs/kms/cli.md`](../kms/cli.md) §2 for their defaults
and environment variables.

**`enroll-recovery` declares its own `--output`** (the recovery-key file),
which shadows the global `--output` for that verb: neither `-o` nor
`--output` can select the output format of `enroll-recovery`.

### Local versus remote

LUKS operations act on a block device on the daemon's host. The CLI, however,
runs two checks **on the CLI's own host**, before any transport is used:

- **root:** every verb exits with `luks: this command must be run as root`
  unless the CLI's effective UID is 0;
- **device auto-detection:** when `--device` is omitted the CLI probes its own
  host's disks (§3).

Against a remote `--server`, pass `--device` explicitly.

---

## 3. Device auto-detection

Every verb takes `--device`. When it is empty, the CLI probes, in order:

```
/dev/vda3  /dev/vda2  /dev/sda3  /dev/sda2  /dev/nvme0n1p3  /dev/nvme0n1p2
```

The first path that exists and carries a LUKS header wins. If none does, the
verb exits with
`luks: could not auto-detect LUKS device; please specify with --device`.

---

## 4. Verbs

All flags are optional to cobra; required values are enforced in the run
function, in the order listed. Every verb checks root first.

### `luks status`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |

Output: `device`, `is_luks`, `version`, `uuid`, `label`, `cipher`,
`active_slots`.

```
platformctl luks status --device /dev/<device>
```

### `luks list-slots`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |

Output: `device`, `slots[]` of `slot`, `type` (`passphrase`, `fido2`, `tpm`,
`recovery`), `key_size`, `priority`.

```
platformctl luks list-slots --device /dev/<device>
```

### `luks info`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |

Output: `device`, `uuid`, `label`, `version`, `cipher`, `key_size`,
`sector_size`, `slots[]`, `metadata_json` (the raw LUKS2 JSON area).

```
platformctl luks info --device /dev/<device> -o json
```

### `luks enroll-passphrase`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--existing-passphrase` | string | | yes |
| `--new-passphrase` | string | | yes |

Output: `slot`, the new keyslot.

```
platformctl luks enroll-passphrase --device /dev/<device> \
    --existing-passphrase '<existing>' --new-passphrase '<new>'
```

### `luks enroll-fido2`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--existing-passphrase` | string | | yes |
| `--credential-id` | string | | yes |
| `--require-pin` | bool | `false` | no |
| `--require-uv` | bool | `false` | no |

Output: `slot`, `token_id`.

```
platformctl luks enroll-fido2 --device /dev/<device> \
    --existing-passphrase '<existing>' --credential-id '<base64url-id>' --require-uv
```

### `luks enroll-tpm`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--existing-passphrase` | string | | yes |
| `--pcrs` | int32 list, comma-separated | none | no |
| `--handle` | string, persistent handle such as `0x81000003` | | no |

Output: `slot`, `token_id`.

```
platformctl luks enroll-tpm --device /dev/<device> \
    --existing-passphrase '<existing>' --pcrs 7,9 --handle 0x81000003
```

### `luks enroll-recovery`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--existing-passphrase` | string | | yes |
| `--output` | string, file path | | yes |

When the response carries a key, the CLI writes it to `--output` with mode
`0600` and then prints the response — **including `recovery_key`** — to
standard output.

Output: `slot`, `recovery_key`.

```
platformctl luks enroll-recovery --device /dev/<device> \
    --existing-passphrase '<existing>' --output ./recovery.key
```

### `luks remove-key`

Destructive: the keyslot is wiped.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--slot` | int32, `0`–`31` | `-1` (unset) | yes |

Output: `removed`.

```
platformctl luks remove-key --device /dev/<device> --slot 3
```

### `luks test-unlock`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--slot` | int32, `0`–`31` | `-1` (unset) | yes |

Output: `unlocked`. The request carries no credential; the backend reports
`true` when the slot exists ([engineering.md](engineering.md) §3).

```
platformctl luks test-unlock --device /dev/<device> --slot 3
```

### `luks change-passphrase`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--device` | string | auto-detect | no |
| `--slot` | int32, `0`–`31` | `-1` (unset) | yes |
| `--old-passphrase` | string | | yes |
| `--new-passphrase` | string | | yes |

Output: `changed`.

```
platformctl luks change-passphrase --device /dev/<device> --slot 0 \
    --old-passphrase '<old>' --new-passphrase '<new>'
```

### Validation errors (`pkg/cli/commands/luks/errors.go`)

| Error | Message |
|---|---|
| `ErrRootRequired` | `luks: this command must be run as root` |
| `ErrDeviceAutoDetectFailed` | `luks: could not auto-detect LUKS device; please specify with --device` |
| `ErrExistingPassphraseRequired` | `--existing-passphrase` missing |
| `ErrNewPassphraseRequired` | `--new-passphrase` missing |
| `ErrOldPassphraseRequired` | `--old-passphrase` missing |
| `ErrCredentialIDRequired` | `--credential-id` missing |
| `ErrOutputPathRequired` | `luks: --output is required for enroll-recovery` |
| `ErrSlotRequired` | `luks: --slot is required` |
| `ErrInvalidSlot` | `luks: invalid --slot <n> (must be 0-31)` |
| `ErrRecoveryKeyWrite` | the recovery-key file could not be written |

---

## 5. Exit codes

`0` on success. `1` on any error, with `Error: <message>` on standard error
(`cmd/platformctl/main.go`). There are no verb-specific exit codes.

---

## 6. Security notes

Passphrases are command-line flags, so they are visible in the CLI host's
process table and shell history. Clear shell history after use, and run these
verbs only on a host you control.
