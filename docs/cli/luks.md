# `platformctl luks`

LUKS2 volume management.

The `luks` command tree owns all LUKS2 block-device operations: header
status, keyslot listing, detailed info dumps, enrollment of passphrase /
FIDO2 / TPM2 / recovery keyslots, slot removal, test-unlock, and passphrase
change.

All subcommands require **root** privileges (LUKS2 header IO needs
`CAP_SYS_ADMIN`). All subcommands connect to `platformd` via the SDK and
therefore honor the global flags `--config`, `--context`, `--transport`,
`--server`, `--output`.

> Phase 3 status: CLI + SDK scaffolding is complete. Server-side handlers
> land in Phase 3.5. The SDK currently returns `ErrNotYetWired` for every
> method.

## Migration from `platformctl fido2`

The `luks` subcommand tree takes over the LUKS-specific commands that used
to live under `platformctl fido2`:

| Old command | New command |
|-------------|-------------|
| `platformctl fido2 enroll` | `platformctl luks enroll-fido2` |
| `platformctl fido2 list`   | `platformctl luks list-slots` |
| `platformctl fido2 remove` | `platformctl luks remove-key` |
| `platformctl fido2 test`   | `platformctl luks test-unlock` |
| `platformctl fido2 info` (LUKS view) | `platformctl luks info` |

The old subcommands have been removed cold-turkey: this is pre-1.0 and
there is no compatibility shim.

## Device auto-detection

All subcommands accept `--device`. When omitted the CLI probes common
partition paths (`/dev/vda3`, `/dev/vda2`, `/dev/sda3`, `/dev/sda2`,
`/dev/nvme0n1p3`, `/dev/nvme0n1p2`) for a LUKS header; the first match
wins. If no LUKS device is found the command exits with
`luks: could not auto-detect LUKS device; please specify with --device`.

## Subcommands

### `luks status`

Header state (version, UUID, cipher, active slots).

```
platformctl luks status
platformctl luks status --device /dev/vda3
```

### `luks list-slots`

Enumerate active keyslots with their backend type.

```
platformctl luks list-slots
```

### `luks info`

Detailed header dump (JSON metadata, keyslots, segments).

```
platformctl luks info
```

### `luks enroll-passphrase`

Add a passphrase keyslot.

```
platformctl luks enroll-passphrase \
    --existing-passphrase <existing> \
    --new-passphrase <new>
```

### `luks enroll-fido2`

Add a FIDO2 keyslot (replaces the legacy `fido2 enroll`).

```
platformctl luks enroll-fido2 \
    --existing-passphrase <existing> \
    --credential-id <base64url credID> \
    --require-uv
```

### `luks enroll-tpm`

Add a TPM2-sealed keyslot bound to the given PCRs and persistent NV handle.

```
platformctl luks enroll-tpm \
    --existing-passphrase <existing> \
    --pcrs 7,9 \
    --handle 0x81000003
```

### `luks enroll-recovery`

Generate a recovery key and enroll it. The key is written to `--output`
(mode 0600) exactly once.

```
platformctl luks enroll-recovery \
    --existing-passphrase <existing> \
    --output ./recovery.key
```

### `luks remove-key`

Remove a keyslot (replaces the legacy `fido2 remove`). Destructive.

```
platformctl luks remove-key --slot 3
```

### `luks test-unlock`

Verify a slot can unlock the master key without mounting (replaces the
legacy `fido2 test`).

```
platformctl luks test-unlock --slot 3
```

### `luks change-passphrase`

Replace an existing passphrase slot.

```
platformctl luks change-passphrase \
    --slot 0 \
    --old-passphrase <old> \
    --new-passphrase <new>
```

## Exit codes

Non-zero on any SDK or validation error. Typed errors live in both
`pkg/cli/commands/luks/errors.go` (validation) and
`sdk/go/services/luks/errors.go` (transport).

## Wire surface

Every CLI subcommand maps 1:1 to a REST endpoint and MCP tool. Task #88
wires these live at platformd startup. LUKS operations are root-gated; the
server rejects non-root callers with `ErrLUKSRootRequired` (HTTP 403).

| Subcommand | REST | MCP tool |
|------------|------|----------|
| `luks status` | `GET /api/v1/luks/status?device=…` | `platform_luks_status` |
| `luks list-slots` | `GET /api/v1/luks/slots?device=…` | `platform_luks_list_slots` |
| `luks info` | `GET /api/v1/luks/info?device=…` | `platform_luks_info` |
| `luks enroll passphrase` | `POST /api/v1/luks/enroll/passphrase` | `platform_luks_enroll_passphrase` |
| `luks enroll fido2` | `POST /api/v1/luks/enroll/fido2` | `platform_luks_enroll_fido2` |
| `luks enroll tpm` | `POST /api/v1/luks/enroll/tpm` | `platform_luks_enroll_tpm` |
| `luks enroll recovery` | `POST /api/v1/luks/enroll/recovery` | `platform_luks_enroll_recovery` |
| `luks remove-key` | `POST /api/v1/luks/keys/remove` | `platform_luks_remove_key` |
| `luks test-unlock` | `POST /api/v1/luks/keys/test-unlock` | `platform_luks_test_unlock` |
| `luks change-passphrase` | `POST /api/v1/luks/passphrase/change` | `platform_luks_change_passphrase` |
