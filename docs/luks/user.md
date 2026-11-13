# LUKS Key-Slot Management — User Guide

> **Status: NORMATIVE** · Scope: managing who and what can open a host's LUKS2 volume · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

---

## Before you start

- `platformctl luks` validates its input and reaches platformd over the active
  transport, where the go-luks2 backend runs the verb on the host's volume.
  A *backend not configured* error means platformd started without its SDK
  client, so it wired no LUKS backend ([engineering.md](engineering.md) §6).
  [cli.md](cli.md) §1 has the details.
- Run as root, on the host that holds the volume. The CLI checks root and
  auto-detects the device on the host it runs on.
- Pass `--device /dev/<device>` explicitly unless the volume is on one of the
  partitions listed in [cli.md](cli.md) §3.
- Passphrases are command-line arguments. Clear your shell history afterwards.

How the initramfs uses these keyslots at boot is in
[`docs/installer/engineering.md` §5](../installer/engineering.md).

---

## See what is on the volume

```
platformctl luks status     --device /dev/<device>
platformctl luks list-slots --device /dev/<device>
platformctl luks info       --device /dev/<device> -o json
```

`list-slots` reports each slot's type: `passphrase`, `fido2`, `tpm` or
`recovery`.

---

## Add a second passphrase

```
platformctl luks enroll-passphrase --device /dev/<device> \
    --existing-passphrase '<existing>' --new-passphrase '<new>'
```

The command prints the new slot number.

---

## Bind a FIDO2 security key

Register the authenticator first and note its credential ID, then:

```
platformctl luks enroll-fido2 --device /dev/<device> \
    --existing-passphrase '<existing>' --credential-id '<base64url-id>' --require-uv
```

`--require-pin` is refused, and no keyslot is written, until the SDK ships a
PIN-capable fido2 handler (SDK seam #584): today the slot would be guarded by a
touch alone. Use `--require-uv` for user verification.

---

## Bind the TPM

```
platformctl luks enroll-tpm --device /dev/<device> \
    --existing-passphrase '<existing>' --pcrs 7,9 --handle 0x81000003
```

Choose PCRs that change only when you want unlock to stop working; after a
firmware or boot-chain change that moves them, the TPM slot no longer opens the
volume and another slot must be used.

---

## Create a recovery key

```
platformctl luks enroll-recovery --device /dev/<device> \
    --existing-passphrase '<existing>' --output ./recovery.key
```

The key is written to `./recovery.key` with mode `0600` **and also printed to
the terminal**. Move the file offline and clear the terminal scroll-back. The
platform keeps no copy.

---

## Rotate a passphrase

Find the slot with `list-slots`, then:

```
platformctl luks change-passphrase --device /dev/<device> --slot 0 \
    --old-passphrase '<old>' --new-passphrase '<new>'
```

---

## Retire a slot

```
platformctl luks test-unlock --device /dev/<device> --slot 3
platformctl luks remove-key  --device /dev/<device> --slot 3
```

`remove-key` wipes the slot and cannot be undone. Make sure another slot you
can use still exists first. `test-unlock` confirms only that the slot exists;
it does not prove a credential opens it. Every transport, MCP included, gives
that same answer.

---

## Moving from `platformctl fido2`

The old LUKS verbs under `platformctl fido2` are gone; [cli.md](cli.md) §2 maps
each one to its `platformctl luks` replacement.
