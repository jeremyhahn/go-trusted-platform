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
| Generate key | `POST /api/v1/kms/keys` | `GenerateKey` | `0xC0`–`0xCF` | `kms_generate_key` | ✅ |
| Import key | `POST /api/v1/kms/keys/import` | `ImportKey` | as above | `MISSING — docs/13 G7` | ✅ |
| List keys | `GET /api/v1/kms/keys` | `ListKeys` | as above | `kms_list_keys` | ✅ |
| Get key | `GET /api/v1/kms/keys/{name}` | `GetKey` | as above | `kms_get_key` | ✅ |
| Delete key | `DELETE /api/v1/kms/keys/{name}` | `DeleteKey` | as above | `kms_delete_key` | ✅ |
| Rotate key | `POST /api/v1/kms/keys/{name}/rotate` | `RotateKey` | as above | `kms_rotate_key` | ✅ |
| Revoke key | `POST /api/v1/kms/keys/{name}/revoke` | `MISSING — docs/13 G7` | as above | `kms_revoke_key` | — |
| Update key status | `PUT /api/v1/kms/keys/{name}/status` | `UpdateKeyStatus` | as above | `MISSING — docs/13 G7` | ✅ |
| List key versions | `GET /api/v1/kms/keys/{name}/versions` | `GetKeyVersions` | as above | `MISSING — docs/13 G7` | ✅ |
| Export key | `MISSING — docs/13 G7` | `ExportKey` | as above | `kms_export_public_key` | ✅ |
| Get key metadata | `GET /api/v1/kms/keys/{name}/metadata` | `MISSING — docs/13 G7` | as above | `kms_get_key_metadata` | — |
| Update key metadata | `PUT /api/v1/kms/keys/{name}/metadata` | `MISSING — docs/13 G7` | as above | `kms_update_key_metadata` | — |
| Get key policy | `GET /api/v1/kms/keys/{name}/policy` | `MISSING — docs/13 G7` | as above | `kms_get_key_policy` | — |
| Set key policy | `PUT /api/v1/kms/keys/{name}/policy` | `MISSING — docs/13 G7` | as above | `kms_set_key_policy` | — |
| List algorithms | `GET /api/v1/kms/algorithms` | `MISSING — docs/13 G7` | as above | `kms_supported_algorithms` | — |
| Backend status | `GET /api/v1/kms/backend/status` | `BackendStatus` | as above | `kms_backend_status` | ✅ |

**`ExportKey` exists on gRPC and has no REST route.** The MCP tool is
`kms_export_public_key` — note the name: public key only. The gRPC RPC is
`ExportKey` without that qualifier, which is a naming difference worth checking
before assuming what crosses the boundary.

Key **metadata and policy** are REST and MCP only — no gRPC RPC.

---

## 3. Cryptographic operations

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Encrypt | `POST /api/v1/kms/encrypt/{name}` | `Encrypt` | `0xD0`–`0xDA` | `kms_encrypt` | ✅ |
| Decrypt | `POST /api/v1/kms/decrypt/{name}` | `Decrypt` | as above | `kms_decrypt` | ✅ |
| Batch encrypt | `MISSING — docs/13 G7` | `BatchEncrypt` | as above | `MISSING — docs/13 G7` | ✅ |
| Batch decrypt | `MISSING — docs/13 G7` | `BatchDecrypt` | as above | `MISSING — docs/13 G7` | ✅ |
| Rewrap | `MISSING — docs/13 G7` | `Rewrap` | as above | `MISSING — docs/13 G7` | ✅ |
| Sign | `POST /api/v1/kms/sign/{name}` | `Sign` | as above | `kms_sign` | ✅ |
| Verify | `POST /api/v1/kms/verify/{name}` | `Verify` | as above | `kms_verify` | ✅ |
| Hash | `POST /api/v1/kms/hash` | `Hash` | as above | `MISSING — docs/13 G7` | ✅ |
| HMAC | `POST /api/v1/kms/hmac/{name}` | `HMAC` | as above | `MISSING — docs/13 G7` | ✅ |
| Verify HMAC | `POST /api/v1/kms/hmac/{name}/verify` | `VerifyHMAC` | as above | `MISSING — docs/13 G7` | ✅ |
| Generate random | `POST /api/v1/kms/random` | `GenerateRandom` | as above | `kms_random` | ✅ |

`Hash` takes no key name in its path — it is unkeyed. `HMAC` does. Do not treat
them as interchangeable: an unkeyed digest where an HMAC is required is a real
authentication failure.

**Batch encrypt/decrypt and rewrap are gRPC-only.** Rewrap is the operation that
makes key rotation cheap, and it is unreachable from REST and MCP.

---

## 4. Data encryption keys and secrets

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create DEK | `POST /api/v1/kms/deks` | `GenerateDataKey` | `0xF0`–`0xF5` | `kms_generate_data_key` | ✅ |
| Generate wrapped DEK | `MISSING — docs/13 G7` | `GenerateWrappedDataKey` | as above | `kms_generate_wrapped_data_key` | ✅ |
| List DEKs | `GET /api/v1/kms/deks` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Get DEK | `GET /api/v1/kms/deks/{path}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| DEK status | `GET /api/v1/kms/deks/{path}/status` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rotate DEK | `POST /api/v1/kms/deks/{path}/rotate` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Delete DEK | `DELETE /api/v1/kms/deks/{path}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |

| Secrets capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Store secret | `POST /api/v1/kms/secrets` | `MISSING — docs/13 G7` | secrets category `0xCE` | `secret_store` | — |
| List secrets | `GET /api/v1/kms/secrets` | `MISSING — docs/13 G7` | as above | `secret_list` | — |
| Get secret | `GET /api/v1/kms/secrets/{name}` | `MISSING — docs/13 G7` | as above | `secret_get` | — |
| Delete secret | `DELETE /api/v1/kms/secrets/{name}` | `MISSING — docs/13 G7` | as above | `secret_delete` | — |
| Get secret version | `GET /api/v1/kms/secrets/{name}/versions/{version}` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| List secret versions | `GET /api/v1/kms/secrets/{name}/versions` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rotate secret | `POST /api/v1/kms/secrets/{name}/rotate` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Rollback secret | `POST /api/v1/kms/secrets/{name}/rollback` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Update secret status | `PUT /api/v1/kms/secrets/{name}/status` | `MISSING — docs/13 G7` | as above | `MISSING — docs/13 G7` | — |
| Get rotation policy | `GET /api/v1/kms/secrets/{name}/policy` | `MISSING — docs/13 G7` | as above | `secret_get_rotation_policy` | — |
| Set rotation policy | `PUT /api/v1/kms/secrets/{name}/policy` | `MISSING — docs/13 G7` | as above | `secret_set_rotation_policy` | — |

**Secrets and DEK management have no gRPC service at all.** They are REST, QUIC
and (partially) MCP. That means the SDK's typed gRPC path cannot reach them, and
an embedded-mode consumer cannot use them.

**The CLI cannot reach them either** — the entire `platformctl kms secrets`
and `kms dek` subtrees are stubs that return typed
`ErrSecretsNotImplemented` / `ErrDEKNotImplemented` errors. See
[engineering.md](engineering.md) §2 and [cli.md](cli.md) §7–§8. (`kms crypto
datakey`, which mints a wrapped DEK, does work.)

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

**None of the 20 `kms_*` or 6 `secret_*` MCP tools is in the MCP authorization
map.** Of 449 declared tool names, 71 carry a permission; no KMS tool is among
them, and `AuthorizeTool` allows a tool absent from the map once the token
validates.

So `Decrypt` over gRPC requires a `kms` scope, while `kms_decrypt` over MCP
requires nothing beyond a valid token — as do `kms_sign`, `kms_generate_key`,
`kms_delete_key`, `kms_generate_data_key` and `secret_get`. **This is the
highest-severity instance of the map's default-allow behaviour** in the whole
platform. Raised as an owner question in the migration report.

### REST is gated on the `admin` role (#165)

`/api/v1/kms/**` — keys, DEKs, secrets, and the crypto operations that use
them (`encrypt`, `decrypt`, `sign`, `hmac`) — requires an authenticated
caller holding `admin`. Reads are gated with the writes: a key's metadata,
policy and version list, and the secret inventory, are all disclosure.

Until #165 the whole surface answered callers with no token at all. The gate
is `v1Router.gated(common.ROLE_ADMIN)` in `pkg/webservice/v1/router.go`;
[`docs/auth/architecture.md`](../auth/architecture.md) §6c has the mechanism
and [`docs/api/rest-routers.md`](../api/rest-routers.md) the router-level
picture. **This does not change the gRPC or MCP positions above** — the MCP
default-allow finding stands exactly as written.

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

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
unimplemented CLI areas are stubs awaiting implementation, not deprecations.
