# `platformctl piv`

PIV (Personal Identity Verification, NIST SP 800-73-4) smartcard operations.

The `piv` command tree mirrors `xkmsctl piv` and covers device enumeration,
per-slot key management, signing, attestation, and device reset.

All subcommands connect to `platformd` via the SDK and therefore honor the
global flags `--config`, `--context`, `--transport`, `--server`, `--output`.

> Phase 3 status: CLI + SDK scaffolding is complete. Server-side handlers
> land in Phase 3.5. The SDK currently returns `ErrNotYetWired` for every
> method.

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

Import a PEM private key into a slot. Prefer `generate` for hardware
binding.

```
platformctl piv import --slot 82 --key-file ./key.pem --pin 123456
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

Every CLI subcommand maps 1:1 to a REST endpoint and MCP tool. Task #88
wires these live at platformd startup.

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
