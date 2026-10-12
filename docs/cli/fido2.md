# `platformctl fido2`

FIDO2 authenticator device operations and WebAuthn register / authenticate.

All subcommands route through the go-quicbaas SDK
(`Security().Auth().FIDO2()` — the single canonical surface for both
device-level verbs and the WebAuthn ceremony). The platform repo does
not implement any FIDO2 CTAP2 or WebAuthn logic locally — the canonical
implementation lives in go-xkms and is re-exported through
`go-quicbaas/sdk/go/xkms/fido2` for the initramfs carve-out.

The subcommands honor the global flags `--config`, `--context`,
`--transport`, `--server`, `--output`.

## Migration from the LUKS-focused command tree

LUKS-specific FIDO2 management has moved under `platformctl luks`
([`docs/luks/cli.md`](../luks/cli.md)):

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

Non-zero on any SDK error. Typed errors propagate from
`go-quicbaas/sdk/go/security/fido2` (device verbs) and
`go-quicbaas/sdk/go/security/webauthn` (ceremony verbs).

## Wire surface

Every CLI subcommand maps 1:1 to a quicbaas SDK call and is reachable
over every quicbaas transport (REST, gRPC, QUIC, MCP, Unix, embedded).

| Subcommand | SDK call | REST endpoint | MCP tool |
|------------|----------|---------------|----------|
| `fido2 list-devices` | `Security().Auth().FIDO2().ListDevices` | `GET /api/v1/fido2/devices` | `platform_fido2_list_devices` |
| `fido2 wait-device` | `Security().Auth().FIDO2().WaitDevice` | `GET /api/v1/fido2/devices/wait?timeout_seconds=…` | `platform_fido2_wait_device` |
| `fido2 info` | `Security().Auth().FIDO2().Info` | `GET /api/v1/fido2/devices/{device}` | `platform_fido2_info` |
| `fido2 register` | `Security().Auth().FIDO2().BeginRegistration` + `FinishRegistration` | `POST /api/v1/fido2/register` | `platform_fido2_register` |
| `fido2 authenticate` | `Security().Auth().FIDO2().BeginAuthentication` + `FinishAuthentication` | `POST /api/v1/fido2/authenticate` | `platform_fido2_authenticate` |
