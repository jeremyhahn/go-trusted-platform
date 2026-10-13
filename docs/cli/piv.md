# `platformctl piv`

PIV (Personal Identity Verification, NIST SP 800-73-4) smartcard operations.

Routes through `platform.Client.PIV()` and the platform SDK PIV service
adapter. The device implementation remains in the composed security stack;
the platform repo contains no PIV-side implementation and never imports
`go-xkms/pkg/piv` directly.

**Known gap: platformd does not wire a PIV backend yet**, so every
subcommand answers `piv: backend not configured`. The backend needs the
go-xkms PIV manager initialised with a slot certificate store, and the
store constructor and its registration (`NewPIVFileBackend`,
`RegisterPIVStore`) are not re-exported under `go-quicbaas/sdk/go/xkms`
(v0.12, nor v0.14). Building a local store would reimplement an SDK
capability, so the gap closes upstream: once quicbaas re-exports them,
`wireSDKBackends` (`pkg/daemon/commands/serve_sdk_backends.go`) wires PIV
beside the ceremony and FIDO2 backends.

The subcommands honor the global flags `--config`, `--context`,
`--transport`, `--server`, `--output`.

## Slot reference (NIST SP 800-73-4)

| Slot | Purpose |
|------|---------|
| `9a` | PIV Authentication |
| `9c` | Digital Signature |
| `9d` | Key Management |
| `9e` | Card Authentication |
| `F9` | Attestation (vendor-specific) |
| `82`-`95` | Retired Key Management |

## Subcommands

### `piv list-devices`

Enumerate attached PIV devices.

```
platformctl piv list-devices
```

### `piv list-slots`

List the slots on a specific device.

```
platformctl piv list-slots --device <device-id>
```

### `piv info`

Inspect one slot. Returns the public key (PEM) and certificate (PEM) when
present.

```
platformctl piv info --slot 9a
platformctl piv info --slot 82 --device <device-id>
```

### `piv generate`

Generate a fresh key in a slot. Private key never leaves the device.

```
platformctl piv generate --slot 9c --algorithm ecdsa --pin 123456
```

| `--algorithm` | Notes |
|---------------|-------|
| `rsa` | RSA 2048/3072/4096 depending on device |
| `ecdsa` | ECDSA P-256 / P-384 depending on device |
| `ed25519` | Ed25519 (not all devices) |

### `piv import`

**Unsupported — fails closed.** Every `piv import` returns
`ErrPIVKeyImportUnsupported` and writes nothing. The command was previously
filing the private key PEM in the slot's *certificate* object (often listed,
logged or exported as public) while reporting `imported: true`. go-xkms has
`ImportPIVKey` (go-xkms#207), but the go-quicbaas SDK (`sdk/go` v0.12) does not
re-export it; import will be enabled once it does. Use `generate` instead.

Status per transport: REST `501 Not Implemented`, gRPC `Unimplemented`, QUIC
`StatusNotImplemented`, MCP tool error (`platform_piv_import`), Unix as REST.

```
platformctl piv import --slot 82 --key-file ./key.pem --pin 123456   # error
```

### `piv sign`

Sign a payload with the key in the specified slot.

```
platformctl piv sign --slot 9c --input-file ./data.bin --pin 123456
```

### `piv attest`

Produce an attestation certificate for the slot's key.

```
platformctl piv attest --slot 9a
```

### `piv reset`

Factory-reset a device. Destructive: all keys, certs, and slot
configuration are lost. Requires `--yes-i-understand` to confirm.

```
platformctl piv reset --device <device-id> --yes-i-understand
```

## Exit codes

Non-zero on any SDK error. Typed errors live in
`sdk/go/services/piv/errors.go`.

## Wire surface

Every CLI subcommand maps 1:1 to a REST endpoint, gRPC RPC, QUIC opcode,
and MCP tool. The CLI opens the selected platform SDK transport and dispatches
through the PIV service client exposed by `platform.Client.PIV()`.

| Subcommand | REST | MCP tool |
|------------|------|----------|
| `piv list-devices` | `GET /api/v1/piv/devices` | `platform_piv_list_devices` |
| `piv list-slots` | `GET /api/v1/piv/devices/{device}/slots` | `platform_piv_list_slots` |
| `piv slot-info` | `GET /api/v1/piv/slots/{slot}` | `platform_piv_slot_info` |
| `piv generate` | `POST /api/v1/piv/slots/{slot}/generate` | `platform_piv_generate` |
| `piv import` | `POST /api/v1/piv/slots/{slot}/import` | `platform_piv_import` |
| `piv sign` | `POST /api/v1/piv/slots/{slot}/sign` | `platform_piv_sign` |
| `piv attest` | `POST /api/v1/piv/slots/{slot}/attest` | `platform_piv_attest` |
| `piv reset` | `POST /api/v1/piv/devices/{device}/reset` | `platform_piv_reset` |

MCP `platform_piv_sign` takes a base64-encoded payload and returns the
signature base64-encoded.

### Transports and scopes

Every subcommand is served by the daemon over REST, gRPC, QUIC, MCP and the Unix
socket, and the SDK client for each transport is tested against the daemon's real
handlers. QUIC uses category opcode `0x9B` with the sub-opcode in `payload[0]`.
The embedded transport dispatches every RPC in-process through
`ServiceRegistry.PIV`.

| Subcommand | gRPC method (`platform.v1.PIVService`) | QUIC sub-opcode | Scope |
|------------|----------------------------------------|-----------------|-------|
| `piv list-devices` | `ListDevices` | `0x01` | `piv:read` |
| `piv list-slots` | `ListSlots` | `0x02` | `piv:read` |
| `piv slot-info` | `SlotInfo` | `0x03` | `piv:read` |
| `piv generate` | `Generate` | `0x04` | `piv:write` |
| `piv import` | `Import` | `0x05` | `piv:write` |
| `piv sign` | `Sign` | `0x06` | `piv:write` |
| `piv attest` | `Attest` | `0x07` | `piv:read` |
| `piv reset` | `Reset` | `0x08` | `piv:write` |

gRPC (TCP), QUIC and MCP refuse a token that lacks the scope (`PermissionDenied`
/ `StatusPermissionDenied`). QUIC refuses a caller with no principal the same
way; under mTLS the client certificate is the principal and holds every scope
([`docs/daemon/api.md`](../daemon/api.md) §5). The Unix socket is local and not
token-gated. Scopes are minted by the broker from the subject's IAM
permissions, so a role gains `piv:read` / `piv:write` by being granted those permissions; the admin role needs
both.
