# `platformctl fido2`

FIDO2 authenticator device operations and WebAuthn register / authenticate.

The `fido2` command tree mirrors `xkmsctl fido2` and covers CTAP2 device
enumeration and WebAuthn credential ceremonies.

All subcommands connect to `platformd` via the SDK and therefore honor the
global flags `--config`, `--context`, `--transport`, `--server`, `--output`.

> Phase 3 status: CLI + SDK scaffolding is complete. Server-side handlers
> land in Phase 3.5. The SDK currently returns `ErrNotYetWired` for every
> method.

## Migration from the LUKS-focused command tree

Prior to Phase 3 this command tree hosted LUKS-specific subcommands. Those
use cases have moved:

| Old command | New command |
|-------------|-------------|
| `platformctl fido2 enroll` | `platformctl luks enroll-fido2` |
| `platformctl fido2 list`   | `platformctl luks list-slots` |
| `platformctl fido2 remove` | `platformctl luks remove-key` |
| `platformctl fido2 test`   | `platformctl luks test-unlock` |
| `platformctl fido2 info` (LUKS view) | `platformctl luks info` |

`platformctl fido2 info` is now device-level only (AAGUID, firmware,
capabilities). LUKS volume information lives under `platformctl luks`.

## Subcommands

### `fido2 list-devices`

Enumerate attached FIDO2 authenticators via CTAP2 HID.

```
platformctl fido2 list-devices
```

### `fido2 wait-device`

Block until a FIDO2 device is detected. Useful in scripts.

```
platformctl fido2 wait-device            # wait indefinitely
platformctl fido2 wait-device --timeout 10   # 10 seconds max
```

### `fido2 info`

Show device-level capability profile for a single authenticator.

```
platformctl fido2 info --device <device-id>
```

Fields include AAGUID, firmware version, CTAP2 extensions, and option
booleans (`rk`, `uv`, `clientPin`, ...).

### `fido2 register`

Register a new WebAuthn credential for a user.

```
platformctl fido2 register \
    --username alice \
    --role admin \
    --require-uv \
    --rp-id platform.example.com
```

`--role` is optional; when supplied it binds the new credential to a
ceremony role (`so`, `admin`, `user`) for later use by `ceremony
claim-cert`.

### `fido2 authenticate`

Test an authentication ceremony against a registered credential.

```
platformctl fido2 authenticate --credential-id <base64url credID>
```

## Exit codes

Non-zero on any SDK error. Typed errors live in
`sdk/go/services/fido2/errors.go`.

## Wire surface

Every CLI subcommand maps 1:1 to a REST endpoint and MCP tool. Task #88
wires these live at platformd startup.

| Subcommand | REST | MCP tool |
|------------|------|----------|
| `fido2 list-devices` | `GET /api/v1/fido2/devices` | `platform_fido2_list_devices` |
| `fido2 wait-device` | `GET /api/v1/fido2/devices/wait?timeout_seconds=…` | `platform_fido2_wait_device` |
| `fido2 info` | `GET /api/v1/fido2/devices/{device}` | `platform_fido2_info` |
| `fido2 register` | `POST /api/v1/fido2/register` | `platform_fido2_register` |
| `fido2 authenticate` | `POST /api/v1/fido2/authenticate` | `platform_fido2_authenticate` |
