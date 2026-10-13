# `platformctl fido2`

FIDO2 authenticator device operations and WebAuthn register / authenticate.

All subcommands route through `platform.Client.FIDO2()` and the platform SDK
FIDO2 service adapter. The platform repo does not implement FIDO2 CTAP2 or
WebAuthn logic locally. Runtime WebAuthn/FIDO2 ceremony support belongs behind
`quicbaas.SDK().Security().Auth().FIDO2()` in the composed SDK.

`platformd serve` currently leaves the daemon FIDO2 backend unwired because the
SDK exposes the WebAuthn ceremony surface and client-local device discovery,
but not the daemon backend shape used by these platform transports
(`ListDevices`, `WaitDevice`, `Info`, `Register`, `Authenticate`). Until that
SDK surface exists, every FIDO2 transport returns the typed
`fido2: backend not configured` error rather than installing a local CTAP2/KV
credential implementation.

The `quicbaas/sdk/go/xkms/fido2` re-export remains valid for the initramfs
carve-out and LUKS-specific flows that run before the runtime SDK is available.
It is not used by the long-running daemon FIDO2 service.

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

The command prints the new credential's hex-encoded id. platformd records the
credential (id, relying party, user, AAGUID, public key, sign count) in the
SDK KV store under the `platform_fido2_credentials` entity type, so it
survives a platformd restart. A registration that cannot be recorded fails;
the authenticator still holds the key, but platformd does not report a
credential it cannot authenticate later.

### `fido2 authenticate`

Test an authentication ceremony against a registered credential.

```
platformctl fido2 authenticate --credential-id <hex credID from register>
```

platformd looks the credential up in the SDK KV store and asks the attached
authenticator for an assertion against it. An id that is not hex is rejected;
an id that was never registered is reported as not registered.

## Exit codes

Non-zero on any SDK error. Typed command-surface errors live in
`sdk/go/services/fido2/errors.go`; backend errors propagate through the
selected platform SDK transport.

## Wire surface

Every CLI subcommand maps 1:1 to the FIDO2 service client exposed by
`platform.Client.FIDO2()` and is reachable over every platform transport
(REST, gRPC, QUIC, MCP, Unix, embedded).

| Subcommand | Platform SDK call | REST endpoint | MCP tool |
|------------|-------------------|---------------|----------|
| `fido2 list-devices` | `Client.FIDO2().ListDevices` | `GET /api/v1/fido2/devices` | `platform_fido2_list_devices` |
| `fido2 wait-device` | `Client.FIDO2().WaitDevice` | `GET /api/v1/fido2/devices/wait?timeout_seconds=…` | `platform_fido2_wait_device` |
| `fido2 info` | `Client.FIDO2().Info` | `GET /api/v1/fido2/devices/{device}` | `platform_fido2_info` |
| `fido2 register` | `Client.FIDO2().Register` | `POST /api/v1/fido2/register` | `platform_fido2_register` |
| `fido2 authenticate` | `Client.FIDO2().Authenticate` | `POST /api/v1/fido2/authenticate` | `platform_fido2_authenticate` |

### Transports and scopes

The SDK client for each transport is tested against the daemon's real handlers.
QUIC uses category opcode `0x9D` with the sub-opcode in `payload[0]`.
The embedded transport dispatches every RPC in-process through
`ServiceRegistry.FIDO2`.

| Subcommand | gRPC method (`platform.v1.FIDO2Service`) | QUIC sub-opcode | Scope |
|------------|------------------------------------------|-----------------|-------|
| `fido2 list-devices` | `ListDevices` | `0x01` | `fido2:read` |
| `fido2 wait-device` | `WaitDevice` | `0x02` | `fido2:read` |
| `fido2 info` | `Info` | `0x03` | `fido2:read` |
| `fido2 register` | `Register` | `0x04` | `fido2:write` |
| `fido2 authenticate` | `Authenticate` | `0x05` | `fido2:write` |

gRPC (TCP), QUIC and MCP refuse a token that lacks the scope (`PermissionDenied`
/ `StatusPermissionDenied`). QUIC refuses a caller with no principal the same
way; under mTLS the client certificate is the principal and holds every scope
([`docs/daemon/api.md`](../daemon/api.md) §5). The Unix socket is local and not
token-gated. Scopes are minted by the broker from the subject's IAM
permissions, so a role gains `fido2:read` / `fido2:write` by being granted those permissions; the admin role
needs both.
