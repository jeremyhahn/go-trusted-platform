# Key Management — API

> **Status: NORMATIVE** · Scope: KMS routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.KMS` carries the service in-process.

gRPC: `KeyManagementService`, 23 RPCs (`pkg/api/grpc/proto/kms.proto`).
REST: base path `/api/v1/kms` (`pkg/webservice/v1/rest/kms/router.go`).
QUIC: key management `0xC0`–`0xCF`, crypto `0xD0`–`0xDA`, DEK `0xF0`–`0xF5`,
plus a **KMS extended category opcode `0xCD`**.
MCP: 20 `kms_*` tools and 6 `secret_*` tools.

---

## 2. Key lifecycle

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate key | `POST /api/v1/kms/keys` | `GenerateKey` | `0xC0`–`0xCF` | `kms_generate_key` (`kms:write`) | ✅ |
| Import key | `POST /api/v1/kms/keys/import` | `ImportKey` | as above | `MISSING — docs/13 G7` | ✅ |
| List keys | `GET /api/v1/kms/keys` | `ListKeys` | as above | `kms_list_keys` (`kms:read`) | ✅ |
| Get key | `GET /api/v1/kms/keys/{name}` | `GetKey` | as above | `kms_get_key` (`kms:read`) | ✅ |
| Delete key | `DELETE /api/v1/kms/keys/{name}` | `DeleteKey` | as above | `kms_delete_key` (`kms:delete`) | ✅ |
| Rotate key | `POST /api/v1/kms/keys/{name}/rotate` | `RotateKey` | as above | `kms_rotate_key` (`kms:write`) | ✅ |
| Revoke key | `POST /api/v1/kms/keys/{name}/revoke` | `MISSING — docs/13 G7` | as above | `kms_revoke_key` (`kms:write`) | — |
| Update key status | `PUT /api/v1/kms/keys/{name}/status` | `UpdateKeyStatus` | as above | `MISSING — docs/13 G7` | ✅ |
| List key versions | `GET /api/v1/kms/keys/{name}/versions` | `GetKeyVersions` | as above | `MISSING — docs/13 G7` | ✅ |
| Export key | `MISSING — docs/13 G7` | `ExportKey` | as above | `kms_export_public_key` (`kms:read`) | ✅ |
| Get key metadata | `GET /api/v1/kms/keys/{name}/metadata` | `MISSING — docs/13 G7` | as above | `kms_get_key_metadata` (`kms:read`) | — |
| Update key metadata | `PUT /api/v1/kms/keys/{name}/metadata` | `MISSING — docs/13 G7` | as above | `kms_update_key_metadata` (`kms:write`) | — |
| Get key policy | `GET /api/v1/kms/keys/{name}/policy` | `MISSING — docs/13 G7` | as above | `kms_get_key_policy` (`kms:read`) | — |
| Set key policy | `PUT /api/v1/kms/keys/{name}/policy` | `MISSING — docs/13 G7` | as above | `kms_set_key_policy` (`kms:write`) | — |
| List algorithms | `GET /api/v1/kms/algorithms` | `MISSING — docs/13 G7` | as above | `kms_supported_algorithms` (`kms:read`) | — |
| Backend status | `GET /api/v1/kms/backend/status` | `BackendStatus` | as above | `kms_backend_status` (`kms:read`) | ✅ |

**`ExportKey` exists on gRPC and has no REST route.** The MCP tool is
`kms_export_public_key` — note the name: public key only. The gRPC RPC is
`ExportKey` without that qualifier, which is a naming difference worth checking
before assuming what crosses the boundary.

Key **metadata and policy** are REST and MCP only — no gRPC RPC.

`POST /api/v1/kms/keys` reads a flat body: `name`, `algorithm` as a name
(`AES-256-GCM`, `CHACHA20-POLY1305`, `RSA-2048`, `RSA-4096`, `ECDSA-P256`,
`ECDSA-P384`, `ED25519`; underscores are accepted for dashes) and `usage` as
names (`ENCRYPT`, `DECRYPT`, `SIGN`, `VERIFY`, `WRAP`, `UNWRAP`). It answers
`key_id`, `version` and `algorithm` under the same names. The SDK REST client
(`sdk/go/transport/rest/kms_keys.go`) flattens the gRPC `key_spec` onto those
fields and decodes the reply into `key` and `metadata`. It refuses an algorithm
or usage outside those lists as InvalidArgument before sending, because the
route would answer 400.

---

## 3. Cryptographic operations

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Encrypt | `POST /api/v1/kms/encrypt/{name}` | `Encrypt` | `0xD0`–`0xDA` | `kms_encrypt` (`kms:write`) | ✅ |
| Decrypt | `POST /api/v1/kms/decrypt/{name}` | `Decrypt` | as above | `kms_decrypt` (`kms:read`) | ✅ |
| Batch encrypt | `MISSING — docs/13 G7` | `BatchEncrypt` | as above | `MISSING — docs/13 G7` | ✅ |
| Batch decrypt | `MISSING — docs/13 G7` | `BatchDecrypt` | as above | `MISSING — docs/13 G7` | ✅ |
| Rewrap | `MISSING — docs/13 G7` | `Rewrap` | as above | `MISSING — docs/13 G7` | ✅ |
| Sign | `POST /api/v1/kms/sign/{name}` | `Sign` | as above | `kms_sign` (`kms:write`) | ✅ |
| Verify | `POST /api/v1/kms/verify/{name}` | `Verify` | as above | `kms_verify` (`kms:read`) | ✅ |
| Hash | `POST /api/v1/kms/hash` | `Hash` | as above | `MISSING — docs/13 G7` | ✅ |
| HMAC | `POST /api/v1/kms/hmac/{name}` | `HMAC` | as above | `MISSING — docs/13 G7` | ✅ |
| Verify HMAC | `POST /api/v1/kms/hmac/{name}/verify` | `VerifyHMAC` | as above | `MISSING — docs/13 G7` | ✅ |
| Generate random | `POST /api/v1/kms/random` | `GenerateRandom` | as above | `kms_random` (`kms:read`) | ✅ |

`Hash` takes no key name in its path — it is unkeyed. `HMAC` does. Do not treat
them as interchangeable: an unkeyed digest where an HMAC is required is a real
authentication failure.

**REST Decrypt refuses a named key version.** The body's `version` field is
accepted only as 0 or absent; any other value answers 400. The go-quicbaas
SDK's `crypto.DecryptRequest` (v0.12.0-alpha) has no version field, so the
route cannot decrypt under the version a caller names, and it refuses rather
than decrypting under whichever version the service picks.

**Batch encrypt/decrypt and rewrap are gRPC-only.** Rewrap is the operation that
makes key rotation cheap, and it is unreachable from REST and MCP.

---

## 4. Data encryption keys and secrets

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate data key | `POST /api/v1/kms/data-keys` | `GenerateDataKey` | `0xF0`–`0xF5` | `kms_generate_data_key` (`kms:write`) | ✅ |
| Generate wrapped data key | `POST /api/v1/kms/data-keys/wrapped` | `GenerateWrappedDataKey` | as above | `kms_generate_wrapped_data_key` (`kms:write`) | ✅ |
| Create DEK | `POST /api/v1/kms/deks` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| List DEKs | `GET /api/v1/kms/deks` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Get DEK | `GET /api/v1/kms/deks/{path}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| DEK status | `GET /api/v1/kms/deks/{path}/status` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rotate DEK | `POST /api/v1/kms/deks/{path}/rotate` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Delete DEK | `DELETE /api/v1/kms/deks/{path}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |

| Secrets capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Store secret | `POST /api/v1/kms/secrets` | `MISSING — docs/13 G7` | secrets category `0xCE` | `secret_store` (`secrets:write`) | — |
| List secrets | `GET /api/v1/kms/secrets` | `MISSING — docs/13 G7` | as above | `secret_list` (`secrets:list`) | — |
| Get secret | `GET /api/v1/kms/secrets/{name}` | `MISSING — docs/13 G7` | as above | `secret_get` (`secrets:read`) | — |
| Delete secret | `DELETE /api/v1/kms/secrets/{name}` | `MISSING — docs/13 G7` | as above | `secret_delete` (`secrets:delete`) | — |
| Get secret version | `GET /api/v1/kms/secrets/{name}/versions/{version}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| List secret versions | `GET /api/v1/kms/secrets/{name}/versions` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rotate secret | `POST /api/v1/kms/secrets/{name}/rotate` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rollback secret | `POST /api/v1/kms/secrets/{name}/rollback` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Update secret status | `PUT /api/v1/kms/secrets/{name}/status` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Get rotation policy | `GET /api/v1/kms/secrets/{name}/policy` | `MISSING — docs/13 G7` | as above | `secret_get_rotation_policy` (`secrets:read`) | — |
| Set rotation policy | `PUT /api/v1/kms/secrets/{name}/policy` | `MISSING — docs/13 G7` | as above | `secret_set_rotation_policy` (`secrets:write`) | — |

**Secrets and DEK management have no gRPC service at all.** They are REST, QUIC
and (partially) MCP. That means the SDK's typed gRPC path cannot reach them, and
an embedded-mode consumer cannot use them.

**The CLI cannot reach them either** — the entire `platformctl kms secrets`
and `kms dek` subtrees are stubs that return typed
`ErrSecretsNotImplemented` / `ErrDEKNotImplemented` errors. See
[engineering.md](engineering.md) §2 and [cli.md](cli.md) §7–§8. (`kms crypto
datakey`, which mints a wrapped DEK, does work.)

**Generating a data key and creating a DEK are different operations.**
`/data-keys` mints a key under the KEK named by `key_id` (`wrapping_key_id` on
`/data-keys/wrapped`) and returns it without storing anything: the plaintext and
the KEK-encrypted copy, or only the encrypted copy from the wrapped route.
`/deks` stores a named DEK at `path` and returns its version, never key
material.

`key_size` is in bits on every transport (gRPC, Unix, REST, QUIC and the CLI's
`--key-size`). `algorithm` (`key_algorithm` on the wrapped route) is a proto
`KMSKeyAlgorithm` name; REST also takes it without the `KMS_KEY_ALGORITHM_`
prefix. A data key is AES-128, AES-192, AES-256 or ChaCha20-Poly1305. A named
algorithm fixes the size, and a non-zero `key_size` must match it. With no
algorithm, `key_size` picks the AES variant (128, 192 or 256), and 0 means 256.
The MCP tools take no `key_size`; their `algorithm` (`aes-128-gcm` …
`chacha20-poly1305`, default `aes-256-gcm`) sets the size.

REST mints only 256-bit keys (AES-256 or ChaCha20-Poly1305). The quicbaas SDK
crypto client it calls (`GenerateDataKey` / `GenerateWrappedDataKey` in
`go-quicbaas/sdk/go/client/crypto`, v0.12.0-alpha) sends neither size nor
algorithm, so REST answers 400 rather than return a key of another size.

The SDK REST client sends the algorithm by its proto name
(`KMS_KEY_ALGORITHM_AES_256`), never by its enum number, and omits it when it is
unspecified. It refuses two requests before sending them, as InvalidArgument: a
value outside the `KMSKeyAlgorithm` enum, and a `wrapping_algorithm` on the
wrapped route. The route takes no wrapping algorithm — the KEK's own applies —
and would otherwise ignore the choice; QUIC refuses it too.

The data-key and DEK routes answer 400 for a missing key name or a malformed
body, and 404 for an unknown KEK. The data-key routes also answer 400 for a
`key_size` the algorithm does not mint or an algorithm that is not a data-key
cipher.

`{path:.+}` on the DEK routes is a catch-all because DEK paths contain slashes.
Note the ordering: `/deks/{path}/status` and `/deks/{path}/rotate` are registered
**before** the bare `/deks/{path}`, so the suffixes are not swallowed.

---

## 5. AEAD safety limits have no surface at all

AEAD safety limits have **no gRPC RPC, no REST route, no QUIC opcode and no MCP
tool** (grepped 2026-08-18). The CLI's `kms key safety` group is compiled only
under a build tag the shipped binary does not use, and does not compile under it
([cli.md](cli.md) §10).

These limits guard against AES-GCM nonce reuse under a single key — a
catastrophic rather than gradual failure. There is currently **no programmatic
way to check whether a fleet's keys are approaching their invocation limit**;
no shipped CLI can do it either. Raised as an owner
question in the migration report.

---

## 6. Authorization

**`KeyManagementService` is in the gRPC scope catalog** with all 23 methods
mapped — resource `kms`, actions `read`/`write`/`delete`. Complete coverage.

**Every `kms_*` and `secret_*` MCP tool carries the scope of the gRPC method it
mirrors (#304)**, shown beside each tool in the tables above. The `kms_*`
scopes are those of `KeyManagementService` and the `quicbaas.kms.v1`
`KeyManagement` and `Crypto` services; the `secret_*` scopes are those of
`quicbaas.kms.v1.SecretsManagement` (`pkg/api/grpc/method_permissions.go`).
A caller without the scope is refused with `PermissionDenied` before the
handler runs.

`kms_decrypt` and `kms_generate_data_key` answer plaintext key material and
`secret_get` answers the secret, so each reaches only a holder of its scope.
No handler logs the material.

### REST is gated on the `admin` role (#165)

`/api/v1/kms/**` — keys, DEKs, data keys, secrets, and the crypto operations
that use them (`encrypt`, `decrypt`, `sign`, `hmac`) — requires an authenticated
caller holding `admin`. Reads are gated with the writes: a key's metadata,
policy and version list, and the secret inventory, are all disclosure.

Until #165 the whole surface answered callers with no token at all. The gate
is `v1Router.gated(common.ROLE_ADMIN)` in `pkg/webservice/v1/router.go`;
[`docs/auth/architecture.md`](../auth/architecture.md) §6c has the mechanism
and [`docs/api/rest-routers.md`](../api/rest-routers.md) the router-level
picture. The REST gate is role-based; the gRPC and MCP positions are the scope
catalogs above.

---

## 7. Status and error mapping

| QUIC byte | Name | REST | KMS cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed key name, ciphertext or algorithm |
| `0x02` | `StatusNotFound` | 404 | Unknown key, DEK or secret |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | Backend failure |
| `0x06` | `StatusAlreadyExists` | 409 | Key name in use |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `kms:*` scope, or key policy denied |
| `0x08` | `StatusResourceExhausted` | 429 | **AEAD safety limit reached** |
| `0x0A` | `StatusUnavailable` | 503 | KMS not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | The unimplemented CLI/service areas in [engineering.md](engineering.md) §2 |

**429 from a crypto operation is not backpressure.** It can mean the key has
reached its AEAD invocation limit, at which point continuing would risk nonce
reuse. Rotate the key.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB) — relevant for batch
operations and large ciphertexts.

### MCP answers in the gRPC classes (#304)

An MCP tool fails with the gRPC code its gRPC method would answer for the same
input. `pkg/api/daemon/kms_mcp_grpc_parity_test.go` holds both transports to
it, per group, against one in-memory SDK fake.

| Input | gRPC | MCP |
|---|---|---|
| Missing `key_id`, `secret_id`, plaintext, ciphertext, message, signature or data | `InvalidArgument` — the `quicbaas.kms.v1` adapters check before calling the SDK | `InvalidArgument` |
| Unknown key (`kms_get_key`, `kms_get_key_metadata`, `kms_get_key_policy`) | `NotFound` | `NotFound` |
| Unknown secret (`secret_get`, `secret_get_rotation_policy`) | `NotFound` | `NotFound` |
| Encrypt, decrypt or data key under an unknown key | `Internal` | `Internal` |

The read methods answer any SDK failure as `NotFound` on both transports. The
data-key comparison is against `platform.v1` `GenerateDataKey`, since
`quicbaas.kms.v1` has no data-key method.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
unimplemented CLI areas are stubs awaiting implementation, not deprecations.
