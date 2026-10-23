# Key Management — Using It

> **Status: REFERENCE** · Last verified: 2026-10-11
> Working with keys, secrets and cryptographic operations on the platform.
> Internals are in [engineering.md](engineering.md).

---

## What this is

The platform's key-management surface: generate and rotate keys, encrypt,
decrypt, sign, verify, mint data-encryption keys, and store secrets — all
against whatever backend the deployment uses (hardware TPM, PKCS#11, a cloud
KMS, or software).

**The platform does not implement key management.** It re-exports the stack's,
which is why a missing capability is almost never fixable here.

---

## Two things to know first

### 1. Some of `platformctl kms` refuses

These verbs exist in `--help`, parse their flags and then exit 1 with a typed
error:

- **`kms key import`, `export`, `unwrap` and `backend-test`** are not
  implemented ([cli.md](cli.md) §8).
- **`kms secrets watch`** is an SDK gap ([cli.md](cli.md) §7).
- **`kms dek set-default`, `set-safety` and `clear-safety`** exit 1 over the
  gRPC and Unix SDK transports, the embedded-daemon default; REST, QUIC and
  MCP serve them ([cli.md](cli.md) §7). `kms dek status` works on every
  transport.

The rest of `kms key`, `kms crypto`, `kms dek` and `kms secrets` works;
[cli.md](cli.md) §2 has the full tree.

### 2. Which backend are you on?

```bash
platformctl kms key list
curl -s https://platform.example.com/api/v1/kms/backend/status
```

Backend status tells you whether keys are in hardware, in a cloud KMS, or in
software. Everything else you conclude about key custody depends on that answer.

---

## Working with keys

```bash
platformctl kms key generate tenant-a-kek --algorithm aes-256 --purpose encrypt,decrypt
platformctl kms key metadata get tenant-a-kek --output json
platformctl kms key list
platformctl kms key rotate tenant-a-kek
platformctl kms key delete old-kek --pending-days 30
```

**Rotate on a schedule.** Rotation creates a new key version; it does not
re-encrypt your data, so it is cheap. There is no reason to leave a key
unrotated for years. To move existing ciphertext onto the new version without
exposing plaintext, run `kms crypto rewrap` over it.

---

## Encrypting, signing and the hash/HMAC distinction

```bash
platformctl kms crypto encrypt --key-id tenant-a-kek --input backup.tar --output backup.tar.enc
platformctl kms crypto decrypt --key-id tenant-a-kek --input backup.tar.enc --output backup.tar
platformctl kms crypto sign    --key-id release-signer --input release.tar.gz --output release.sig
platformctl kms crypto verify  --key-id release-signer --input release.tar.gz --signature-file release.sig -o json
platformctl kms crypto hmac generate --key-id webhook-mac --input payload.json --output payload.mac
platformctl kms crypto hmac verify   --key-id webhook-mac --input payload.json --hmac-file payload.mac -o json
platformctl kms crypto hash   --input release.tar.gz --algorithm sha3-256
platformctl kms crypto random --bytes 32
platformctl kms key algorithms
```

**A failed `verify` exits 1** after printing `valid: false`, so a script can
test the exit code.

**`crypto hash` is unkeyed. `crypto hmac` is keyed.** A hash proves a message has not
changed by accident. An HMAC proves it came from someone holding the key. If you
reach for `hash` where you needed `hmac`, you have an authentication check that
authenticates nothing — and it will look like it works.

---

## AEAD safety limits — you cannot check these yet

AES-GCM has a limit on how many times one key may be used before nonce reuse
becomes probable. Crossing it is not a slow degradation — it is a break in the
encryption's guarantees.

**No shipped `platformctl` has AEAD safety commands, and no API exposes them**
([cli.md](cli.md) §10). Until that changes, rotate high-volume keys on a
schedule rather than waiting to see a limit approach. If a crypto operation
starts returning 429, that may be the limit rather than backpressure — rotate
the key.

---

## Secrets — use REST

The CLI subtree is a stub. The API is not:

```bash
curl -s -X POST https://platform.example.com/api/v1/kms/secrets \
     -d '{"name":"api-token","value":"..."}'

curl -s        https://platform.example.com/api/v1/kms/secrets
curl -s        https://platform.example.com/api/v1/kms/secrets/api-token
curl -s -X POST https://platform.example.com/api/v1/kms/secrets/api-token/rotate
curl -s -X PUT  https://platform.example.com/api/v1/kms/secrets/api-token/policy -d '{...}'
curl -s -X DELETE https://platform.example.com/api/v1/kms/secrets/api-token
```

Versions, rollback and rotation policy are all there. Note that secrets have
**no gRPC service** — they are REST, QUIC and partially MCP — so the SDK's typed
gRPC path and embedded mode cannot reach them.

---

## Data encryption keys — also REST

```bash
curl -s -X POST   https://platform.example.com/api/v1/kms/deks
curl -s           https://platform.example.com/api/v1/kms/deks
curl -s           https://platform.example.com/api/v1/kms/deks/<path>/status
curl -s -X POST   https://platform.example.com/api/v1/kms/deks/<path>/rotate
curl -s -X DELETE https://platform.example.com/api/v1/kms/deks/<path>
```

DEKs are what per-tenant and per-image encryption are built on — see
[`docs/tenant/`](../tenant/) and [`docs/registry/`](../registry/).

---

## Troubleshooting

**A verb says "not yet implemented".**
It is one of the stubs. Check [cli.md](cli.md) §8 for the list and whether REST
has it.

**A `kms key` verb dies with `panic: unable to redefine 'v' shorthand`.**
A known defect in `key get`, `key export`, `key policy set` and `key status
enable|disable` ([cli.md](cli.md) §9). Use `kms key metadata get` to read a key.

**Everything returns 503.**
The KMS is not wired into the daemon.

**A crypto operation returns 429.**
Not necessarily backpressure. It can be the key's AEAD safety limit, which
nothing on the platform reports today; rotate the key.

**A decrypt fails after a rotation.**
It should not — rotation rewraps rather than re-encrypting. If it does, check
whether the key was *revoked* rather than rotated; those are different
operations.

**Secrets work over REST and not from the CLI.**
Expected. The CLI subtree is a stub.

**Something is missing from the whole KMS surface.**
It is almost certainly missing upstream, in the stack's key management, not
here. This repository is service and transport code with no `pkg/kms` at all.

---

## One thing to be aware of

Every `KeyManagementService` gRPC method requires a `kms` scope, and every
`kms_*`, `secret_*` and `dek_*` MCP tool requires the scope of the gRPC method
it mirrors. A token without that scope is refused with `PermissionDenied`, on
MCP as on gRPC. The scope of each tool is in [api.md](api.md) §2–§4 and §6.

---

## Where to go next

- [cli.md](cli.md) — what works, what does not
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — what this repository owns (very little)
- [`docs/ca/`](../ca/) · [`docs/tenant/`](../tenant/) ·
  [`docs/registry/`](../registry/) · [`docs/secrets/`](../secrets/)
