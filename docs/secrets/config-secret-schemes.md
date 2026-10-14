# Configuration Secret Schemes: `kms://`, `idevid://`, `file://`

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `kms://`, `idevid://` and `file://` config secret URI schemes; the resolvers are wired in `pkg/app/secrets.go`, and `kms://` resolution itself is go-quicbaas's.

This document describes the secret-reference URI schemes available for
configuration values. Each keeps plaintext credentials out of config files so
they can be safely version-controlled and shared.

> The former platform-wide AES-256-GCM config-encryption scheme (a single
> wrapping key shared by every node) has been **removed**. A global wrapping
> key has an unacceptable blast radius — compromising it exposes every secret
> on every node. Use `kms://` (preferred) or `idevid://` (per-device) instead.

## Overview

| Scheme | Backing | Key location | Scope | Use case |
|--------|---------|--------------|-------|----------|
| `kms://` | QuicBaaS KMS | Platform KMS | Per tenant/node keyspace | Canonical: generate-on-first-boot, fetch thereafter |
| `idevid://` | RSA-OAEP | Node's TPM/XKMS | Single node | Per-node secrets bound to device identity |
| `file://` | Raw file bytes | Local filesystem | Single node | Airgap / dev / recovery escape hatch (opt-in) |

## `kms://` Scheme (canonical)

The `kms://` scheme identifies a secret by path in the QuicBaaS KMS. With the
`?ensure=true` query parameter it applies Vault-style
generate-on-first-boot / return-on-subsequent-boot semantics via
`SecretsService.EnsureSecret` under a distributed lock.

```yaml
# Ensure a 32-byte base64 secret exists; first boot generates and persists,
# every subsequent boot returns the same stable bytes.
password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"

# TPM authorization values are capped at one digest (32 bytes on a
# SHA-256 TPM), so they use enc=raw — see "TPM authorization values" below.
srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"

# Reference an existing KMS-managed secret (short form; the tenant and node
# identifiers are prepended at resolution time).
ssh-password: "kms://switches/core-01/ssh-password"
```

Query parameters:

- `ensure=true` — opt in to generate-and-persist semantics
- `len=N` — entropy length: bytes for `base64` / `hex` / `raw`, digits for `numeric`
- `enc=base64` / `enc=hex` / `enc=numeric` / `enc=raw` — encoding of the
  returned value. `base64` is `base64url` without padding (`RawURLEncoding`),
  so `len=32` yields a **43-character** value; `hex` yields 64 characters;
  `raw` yields the `len` random bytes verbatim.

### TPM authorization values must use `enc=raw`

A TPM `TPM2B_AUTH` is capped at `sizeof(TPMU_HA)` — the largest digest the TPM
supports, which is **32 bytes** on a SHA-256-max TPM. A `len=32&enc=base64`
value is 43 characters and overflows that cap, and the TPM rejects the
`TPM2_Create` / `TPM2_CreatePrimary` with `TPM_RC_SIZE`.

Every config field whose value becomes a TPM authorization value therefore uses
`?ensure=true&len=32&enc=raw` — exactly 32 random bytes, the full 256 bits of
entropy the cap allows:

| Config field | Why it is a TPM auth value |
|--------------|----------------------------|
| `webservice(s)[*].key.password` | `tpm-policy: platform` seals the password to the TPM as a keyed-hash object whose `UserAuth` is this value |
| `acme.client.account.key.password` | same tpm-policy sealing; also the `TPM2_Create` `UserAuth` when `store: tpm2` |
| `tpm.platform-srk.srk-auth` | Platform SRK authorization value |
| `certificate-authority.identity[*].keystores.tpm2.srk-auth` | CA TPM keystore SRK authorization value |

`tpm-policy: platform` is the trigger, **not** `store:`. A key with
`store: software` and `tpm-policy: platform` still has its configured password
sealed into a TPM keyed-hash object, so the 32-byte cap applies.

Fields that are **not** TPM auth values keep `enc=base64` and its full
43-character value — notably every `certificate-authority.identity[*].keys[*].password`
(PKCS#8 private-key encryption password) and `bmc.password` (an IPMI / Redfish
account credential that must remain printable ASCII).

Raw bytes are safe on this path: the resolved value is written straight into
the in-memory config struct and read back only as `[]byte`. It is never JSON /
msgpack / CBOR encoded, never logged as a serialized struct, never sent over a
wire protocol, and never persisted. (The KMS itself stores and transports
secrets as `[]byte`, which `encoding/json` base64-encodes, so the
generate-and-fetch round trip is byte-clean.)

> **Changing `len` or `enc` on an already-generated secret is a breaking
> change.** `EnsureSecret` records the spec in the stored secret's metadata and
> returns `ErrSecretSpecMismatch` rather than regenerating. Either delete the
> KMS path first or redeploy onto a clean secret store.

Short-form paths (not starting with `tenants/`) are expanded to
`tenants/{tenant}/nodes/{node}/secrets/{path}` at resolution time using
the platform tenant (`App.TenantID`, the top-level `tenant-id` key) and the
node hostname. Config files must not embed
`tenants/…/nodes/…` literals.

When QuicBaaS is unreachable at bootstrap, `kms://` URIs **fail closed** — they
are never passed downstream as raw literal strings.

## `idevid://` Scheme (per-node)

Per-node encryption using RSA-OAEP with SHA-256 to the node's IDevID
certificate. Only the node holding the matching IDevID private key (in its TPM
or XKMS) can decrypt.

```yaml
# Standard URI form
device:
  unlock-key: "idevid://BQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk..."

# Shorthand form
tpm:
  srk-auth: "idevid:BQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk..."
```

Producing an `idevid://` value (encrypt to the node's IDevID public key):

```bash
openssl pkeyutl -encrypt \
  -pubin -inkey <(openssl x509 -in node-idevidcert.pem -pubkey -noout) \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -in secret.txt | base64 -w0
```

Provisioning servers encrypt secrets to each node's enrolled IDevID
certificate before embedding them in the device profile (see the
`idevid://` scheme in [api.md](api.md)).

Characteristics:

- Decryptable only on the node it was encrypted for (IDevID is `FixedTPM`)
- Private key never leaves the TPM
- No key rotation — re-provisioning is required to change the value

## `file://` Scheme (escape hatch)

The `file://` scheme reads a secret's raw bytes verbatim from a path on the
local filesystem. It is a deliberate, **opt-in** escape hatch for Secure Boot
airgap provisioning, offline development, and recovery flows where the
KMS-backed `kms://` resolver is unavailable.

```yaml
secrets:
  enabled: true
  file: true            # opt-in; off by default

bmc:
  password: "file:///run/secrets/bmc-password"
```

- The referenced file is read verbatim — no base64 decoding, no trimming. The
  file's bytes are the secret value, so the operator controls the exact on-disk
  representation.
- An empty file is an error (`ErrFileEmpty`); a missing/unreadable file is an
  error (`ErrFileReadFailed`).

**Never enable `file:` on a node that can reach a KMS** — the secret lives in
plaintext on disk. Use `kms://` there instead.

## Choosing a Scheme

- `kms://` — default for almost everything: shared service credentials,
  generated auths, rotatable values.
- `idevid://` — per-node device credentials that must never be transferable
  (TPM owner auth, per-node unlock keys).
- `file://` — only when no KMS is reachable (airgap install media, recovery
  shell, local dev), and only with `secrets.file: true`.

## Enabling Resolvers

```yaml
secrets:
  enabled: true       # master switch for config secret resolution
  local-kms: true     # kms:// resolver (fail-closed when KMS absent)
  encrypted: true     # idevid:// resolver (requires a provisioned IDevID)
  file: false         # file:// escape hatch (opt-in)
```

## See Also

- [Secrets Framework](./architecture.md) — overview of the secrets system
- [Bootstrap Secrets](./engineering.md) — resolution during bootstrap
- Provisioning Secrets — node provisioning workflow
- [IDevID Design](../tpm/device-identity-design.md) — device identity architecture
