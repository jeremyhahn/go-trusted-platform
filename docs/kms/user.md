# Key Management — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
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

### 1. A large part of `platformctl kms` is not implemented

36 of the CLI's 107 verb declarations return "not yet implemented":

- **the whole `kms secrets` subtree** — store, get, list, delete, rotate,
  versions, rollback, status, policy, prefix, watch
- **`kms datakey`** — generate, wrapped, rewrap
- **`kms key export`, `import`, `versions`, `status`, `unwrap`, `test-backend`**

They exist in `--help`, parse flags and then refuse with a typed error.

**The REST API is ahead of the CLI**: secrets and DEK management are fully
routed under `/api/v1/kms/secrets` and `/api/v1/kms/deks`. Use REST for those.

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
platformctl kms key generate tenant-a-dek
platformctl kms key get   tenant-a-dek --output json
platformctl kms key list
platformctl kms key rotate tenant-a-dek
platformctl kms key delete old-key
```

**Rotate on a schedule.** Rotation rewraps to a new key version; it does not
re-encrypt your data, so it is cheap. There is no reason to leave a key
unrotated for years.

---

## Encrypting, signing and the hash/HMAC distinction

```bash
platformctl kms crypto encrypt --key tenant-a-dek ...
platformctl kms crypto decrypt --key tenant-a-dek ...
platformctl kms crypto sign    --key signing-key ...
platformctl kms crypto verify  --key signing-key ...
platformctl kms hmac generate  --key mac-key ...
platformctl kms hmac verify    --key mac-key ...
platformctl kms hash ...
platformctl kms random ...
platformctl kms algorithms
```

**`kms hash` is unkeyed. `kms hmac` is keyed.** A hash proves a message has not
changed by accident. An HMAC proves it came from someone holding the key. If you
reach for `hash` where you needed `hmac`, you have an authentication check that
authenticates nothing — and it will look like it works.

---

## AEAD safety limits — check these

```bash
platformctl kms safety check
platformctl kms safety report
platformctl kms safety get  tenant-a-dek
platformctl kms safety set  tenant-a-dek ...
```

AES-GCM has a limit on how many times one key may be used before nonce reuse
becomes probable. Crossing it is not a slow degradation — it is a break in the
encryption's guarantees.

**`kms safety` exists only on the CLI.** There is no API for it, so this cannot
be monitored programmatically today. Until that changes, running
`kms safety check` on a schedule against each daemon is the only way to see a
key approaching its limit. If a crypto operation starts returning 429, that may
be the limit rather than backpressure — rotate the key.

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
It is one of the 36 stub declarations. Check [cli.md](cli.md) §4 for the list and
whether REST has it.

**Everything returns 503.**
The KMS is not wired into the daemon.

**A crypto operation returns 429.**
Not necessarily backpressure. It can be the key's AEAD safety limit. Run
`kms safety get <key-id>` and rotate if it is close.

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

Every `KeyManagementService` gRPC method requires a `kms` scope. **No KMS MCP
tool requires anything** beyond a valid token — including `kms_decrypt`,
`kms_sign`, `kms_generate_key`, `kms_delete_key`, `kms_generate_data_key` and
`secret_get`.

That is the highest-severity instance of the MCP authorization map's
default-allow behaviour on the platform: an MCP client with a valid token can
decrypt and sign with any key. Recorded in [api.md](api.md) §6 and raised for
the owner.

---

## Where to go next

- [cli.md](cli.md) — what works, what does not
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — what this repository owns (very little)
- [`docs/ca/`](../ca/) · [`docs/tenant/`](../tenant/) ·
  [`docs/registry/`](../registry/) · [`docs/secrets/`](../secrets/)
