# Key Management — API

> **Status: NORMATIVE** · Scope: KMS routes on every transport · Last verified: 2026-10-16
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.KMS` carries the service in-process.

gRPC: `KeyManagementService`, 23 RPCs (`pkg/api/grpc/proto/kms.proto`). The
daemon also serves the go-quicbaas `quicbaas.kms.v1` services `KeyManagement`,
`SecretsManagement`, `Crypto` and `DEKManagement` on the same TCP and Unix
listeners (`KMSService.RegisterGRPCServices`, `pkg/api/daemon/kms_service.go`).
A gRPC cell written `Service.Method` names one of those.
REST: base path `/api/v1/kms`. The webservice router
(`pkg/webservice/v1/rest/kms/router.go`) serves the routes keyed by name; the
daemon REST server (`RESTServer.SetKMSHandlers`, `pkg/api/rest/kms_handlers.go`)
serves export, the batch operations and rewrap.
QUIC: key management `0xC0`–`0xCF`, crypto `0xD0`–`0xDA`, plus a **KMS
extended category opcode `0xCD`** whose subs `0x08`–`0x0D` are the DEK calls.
The `OpDEK*` bytes `0xF0`–`0xF5` are reserved and unserved.
MCP: 29 `kms_*` tools, 11 `secret_*` tools and 6 `dek_*` tools.

---

## 2. Key lifecycle

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate key | `POST /api/v1/kms/keys` | `GenerateKey` | `0xC0`–`0xCF` | `kms_generate_key` (`kms:write`) | ✅ |
| Import key | `POST /api/v1/kms/keys/import` | `ImportKey` | as above | `kms_import_key` (`kms:write`) | ✅ |
| List keys | `GET /api/v1/kms/keys` | `ListKeys` | as above | `kms_list_keys` (`kms:read`) | ✅ |
| Get key | `GET /api/v1/kms/keys/{name}` | `GetKey` | as above | `kms_get_key` (`kms:read`) | ✅ |
| Delete key | `DELETE /api/v1/kms/keys/{name}` | `DeleteKey` | as above | `kms_delete_key` (`kms:delete`) | ✅ |
| Rotate key | `POST /api/v1/kms/keys/{name}/rotate` | `RotateKey` | as above | `kms_rotate_key` (`kms:write`) | ✅ |
| Revoke key | `POST /api/v1/kms/keys/{name}/revoke` | `KeyManagement.RevokeKey` | as above | `kms_revoke_key` (`kms:write`) | — |
| Update key status | `PUT /api/v1/kms/keys/{name}/status` | `UpdateKeyStatus` | as above | `kms_update_key_status` (`kms:write`) | ✅ |
| List key versions | `GET /api/v1/kms/keys/{name}/versions` | `GetKeyVersions` | as above | `kms_list_key_versions` (`kms:read`) | ✅ |
| Export key | `GET /api/v1/kms/keys/{id}/export` (daemon) | `ExportKey` | as above | `kms_export_public_key` (`kms:read`) | ✅ |
| Get key metadata | `GET /api/v1/kms/keys/{name}/metadata` | `KeyManagement.GetKeyMetadata` | as above | `kms_get_key_metadata` (`kms:read`) | — |
| Update key metadata | `PUT /api/v1/kms/keys/{name}/metadata` | `KeyManagement.UpdateKeyMetadata` | as above | `kms_update_key_metadata` (`kms:write`) | — |
| Get key policy | `GET /api/v1/kms/keys/{name}/policy` | `KeyManagement.GetKeyPolicy` | as above | `kms_get_key_policy` (`kms:read`) | — |
| Set key policy | `PUT /api/v1/kms/keys/{name}/policy` | `KeyManagement.SetKeyPolicy` | as above | `kms_set_key_policy` (`kms:write`) | — |
| List algorithms | `GET /api/v1/kms/algorithms` | `KeyManagement.GetSupportedAlgorithms` | as above | `kms_supported_algorithms` (`kms:read`) | — |
| Backend status | `GET /api/v1/kms/backend/status` | `BackendStatus` | as above | `kms_backend_status` (`kms:read`) | ✅ |

**REST export takes its options as query values:** `wrapping_key_id`,
`wrapping_algorithm` and `format` as their proto enum numbers, and `version`.
A value that is not a number answers 400; an absent one leaves the default. The
reply carries `format` and `wrapping_algorithm` as numbers and
`wrapped_material` as base64. The MCP tool is `kms_export_public_key` — note
the name: public key only. The gRPC RPC is `ExportKey` without that qualifier,
which is a naming difference worth checking before assuming what crosses the
boundary.

Key **revocation, metadata, policy and the algorithm list** have no RPC on the
platform `KeyManagementService`; gRPC serves them through
`quicbaas.kms.v1.KeyManagement`.

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
| Batch encrypt | `POST /api/v1/kms/batch-encrypt` (daemon) | `BatchEncrypt` | as above | `kms_batch_encrypt` (`kms:write`) | ✅ |
| Batch decrypt | `POST /api/v1/kms/batch-decrypt` (daemon) | `BatchDecrypt` | as above | `kms_batch_decrypt` (`kms:read`) | ✅ |
| Rewrap | `POST /api/v1/kms/rewrap` (daemon) | `Rewrap` | as above | `kms_rewrap` (`kms:write`) | ✅ |
| Sign | `POST /api/v1/kms/sign/{name}` | `Sign` | as above | `kms_sign` (`kms:write`) | ✅ |
| Verify | `POST /api/v1/kms/verify/{name}` | `Verify` | as above | `kms_verify` (`kms:read`) | ✅ |
| Hash | `POST /api/v1/kms/hash` | `Hash` | as above | `kms_hash` (`kms:read`) | ✅ |
| HMAC | `POST /api/v1/kms/hmac/{name}` | `HMAC` | as above | `kms_hmac` (`kms:write`) | ✅ |
| Verify HMAC | `POST /api/v1/kms/hmac/{name}/verify` | `VerifyHMAC` | as above | `kms_verify_hmac` (`kms:read`) | ✅ |
| Generate random | `POST /api/v1/kms/random` | `GenerateRandom` | as above | `kms_random` (`kms:read`) | ✅ |

`Hash` takes no key name in its path — it is unkeyed. `HMAC` does. Do not treat
them as interchangeable: an unkeyed digest where an HMAC is required is a real
authentication failure.

**REST Decrypt refuses a named key version.** The body's `version` field is
accepted only as 0 or absent; any other value answers 400. The go-quicbaas
SDK's `crypto.DecryptRequest` (v0.12.0-alpha) has no version field, so the
route cannot decrypt under the version a caller names, and it refuses rather
than decrypting under whichever version the service picks.

**REST, MCP and gRPC batch and rewrap call the same daemon methods.** Rewrap
is the operation that makes key rotation cheap. A REST batch item and its
result carry `item_id`, so a caller matches results to items; an item that
failed has `error` set. REST rewrap names `source_key_id` and
`destination_key_id`. When they are the same key, it is the gRPC `Rewrap`; the
SDK REST client sends the proto's one `key_id` as both. When they differ, the
daemon decrypts under the source and encrypts under the destination.

**Rewrap refuses a source key version.** Every transport answers
InvalidArgument (`ErrKMSRewrapSourceVersionUnsupported`) when
`source_version` (REST `source_key_version`, same key) is non-zero. The go-quicbaas SDK's `RewrapRequest` has no
source version field, so the daemon cannot decrypt under the version a caller
names, and it refuses rather than rewrapping under whichever version the
service picks — the same rule as REST Decrypt above.

MCP `kms_hash` takes `data` (base64) and `algorithm` (the platform
`HashAlgorithm` number: 0 or 2 = SHA-256, 3 = SHA-384, 4 = SHA-512; SHA-1 is
InvalidArgument). `kms_hmac` and `kms_verify_hmac` take `key_id`, `message`
(base64) and `hash_algorithm`; `kms_verify_hmac` also takes `hmac` and an
optional `key_version`. `kms_rewrap` takes `key_id`, `ciphertext`, optional
`context` and `nonce`, and `source_version` (absent or 0).

MCP `kms_import_key` takes `key_material` (base64), `key_spec` (an object with
the `KMSKeySpec` fields: `algorithm` and `usage` as the platform enum numbers,
`key_size`, `exportable`, `deletion_protection`), and optional `name`,
`description`, `wrapping_key_id` and `tags`. `kms_update_key_status` takes
`key_id`, `status` (the platform `KeyStatus` number) and an optional `version`;
it answers the new state as `key_status`, as gRPC does. `kms_list_key_versions`
takes `key_id`, `limit` and `cursor`. `kms_batch_encrypt` and
`kms_batch_decrypt` take `key_id` and `items`, 1 to 100 objects with `item_id`,
`plaintext` or `ciphertext` (base64), and optional `context` and `nonce`; a
decrypt item also takes `key_version`. A batch answers a per-item `status`
(`success`, `message`), so one bad item does not fail the call, while an
unknown key fails it whole. Each answer has the layout of the platform.v1 reply
(`kms_import_key` answers the new key under `key`), so the SDK MCP adapter
(`sdk/go/transport/mcp`) decodes it into the gRPC response.

---

## 4. Data encryption keys and secrets

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate data key | `POST /api/v1/kms/data-keys` | `GenerateDataKey` | `0xD9` | `kms_generate_data_key` (`kms:write`) | ✅ |
| Generate wrapped data key | `POST /api/v1/kms/data-keys/wrapped` | `GenerateWrappedDataKey` | `0xDA` | `kms_generate_wrapped_data_key` (`kms:write`) | ✅ |
| Create DEK | `POST /api/v1/kms/deks` | `DEKManagement.CreateDEK` | KMS extended category `0xCD`, sub `0x08` | `dek_create` (`kms:write`) | — |
| List DEKs | `GET /api/v1/kms/deks` | `DEKManagement.ListDEKs` | sub `0x09` | `dek_list` (`kms:read`) | — |
| Get DEK | `GET /api/v1/kms/deks/{path}` | `DEKManagement.GetDEK` | sub `0x0A` | `dek_get` (`kms:read`) | — |
| DEK status | `GET /api/v1/kms/deks/{path}/status` | `DEKManagement.GetDEKStatus` | sub `0x0B` | `dek_status` (`kms:read`) | — |
| Rotate DEK | `POST /api/v1/kms/deks/{path}/rotate` | `DEKManagement.RotateDEK` | sub `0x0C` | `dek_rotate` (`kms:write`) | — |
| Delete DEK | `DELETE /api/v1/kms/deks/{path}` | `DEKManagement.DeleteDEK` | sub `0x0D` | `dek_delete` (`kms:delete`) | — |

| Secrets capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Store secret | `POST /api/v1/kms/secrets` | `SecretsManagement.StoreSecret` | secrets category `0xCE`, sub `0x01` | `secret_store` (`secrets:write`) | — |
| List secrets | `GET /api/v1/kms/secrets` | `SecretsManagement.ListSecrets` | sub `0x03` | `secret_list` (`secrets:list`) | — |
| Get secret | `GET /api/v1/kms/secrets/{name}` | `SecretsManagement.GetSecret` | sub `0x02` | `secret_get` (`secrets:read`) | — |
| Delete secret | `DELETE /api/v1/kms/secrets/{name}` | `SecretsManagement.DeleteSecret` | sub `0x04` | `secret_delete` (`secrets:delete`) | — |
| Get secret version | `GET /api/v1/kms/secrets/{name}/versions/{version}` | `SecretsManagement.GetSecretVersion` | sub `0x07` | `secret_get_version` (`secrets:read`) | — |
| List secret versions | `GET /api/v1/kms/secrets/{name}/versions` | `SecretsManagement.ListSecretVersions` | sub `0x08` | `secret_list_versions` (`secrets:list`) | — |
| Rotate secret | `POST /api/v1/kms/secrets/{name}/rotate` | `SecretsManagement.RotateSecret` | sub `0x09` | `secret_rotate` (`secrets:write`) | — |
| Rollback secret | `POST /api/v1/kms/secrets/{name}/rollback` | `SecretsManagement.RollbackSecret` | sub `0x0A` | `secret_rollback` (`secrets:write`) | — |
| Update secret status | `PUT /api/v1/kms/secrets/{name}/status` | `SecretsManagement.UpdateSecretStatus` | sub `0x0B` | `secret_update_status` (`secrets:write`) | — |
| Get rotation policy | `GET /api/v1/kms/secrets/{name}/policy` | `SecretsManagement.GetRotationPolicy` | sub `0x06` | `secret_get_rotation_policy` (`secrets:read`) | — |
| Set rotation policy | `PUT /api/v1/kms/secrets/{name}/policy` | `SecretsManagement.SetRotationPolicy` | sub `0x05` | `secret_set_rotation_policy` (`secrets:write`) | — |

**gRPC DEK and REST DEK are one store.** `DEKManagement` calls the same SDK DEK
client (`Security().DEK()`) as the `/deks` routes, so a DEK created on one
transport is read, rotated and deleted on the other. The gRPC secret version,
rotate, rollback and status RPCs call the SDK secrets client the secret routes
call; the matching MCP tools call the daemon's secrets service
(`Security().Secrets()`), the one `secret_get` and `secret_store` use.

**QUIC DEK subs `0x08`–`0x0D` carry the quicbaas.kms.v1 messages.** Their
payload after the sub-opcode byte is the `DEKManagement` request message and
the reply is its response message. The QUIC handler
(`pkg/api/daemon/quic_dek.go`) calls the `DEKServerAdapter` method the gRPC RPC
calls, so all three transports share one DEK store and answer the same codes.
The SDK's QUIC adapter routes the six full method names to `0xCD`
(`sdk/go/transport/quic/aab_dek.go`), so `pb.NewDEKManagementClient` over its
connection works unchanged. Create and rotate need `kms:write`; list, get and
status need `kms:read`; delete needs `kms:delete` — the gRPC method scopes. A
daemon without a DEK service answers Unavailable.

**MCP `dek_*` tools call the same `DEKServerAdapter`**
(`pkg/api/daemon/mcp_dek.go`) under the same scopes, and each answers the
`DEKManagement` response message as JSON. `dek_create` takes `path`, and
optionally `algorithm` (the quicbaas.kms.v1 `KeyAlgorithm` number),
`description`, `max_operations`, `max_bytes`, `warning_percent` and `tags`.
`dek_list` takes `prefix`, `recursive`, `limit` and `cursor`. `dek_get` and
`dek_status` take `path`; `dek_rotate` takes `path` and `background`;
`dek_delete` takes `path`, `force` and `migrate_to`. A missing path is
InvalidArgument before the adapter runs.

**QUIC secrets subs `0x07`–`0x0B` carry the quicbaas.kms.v1 messages.** Their
payload after the sub-opcode byte is the `SecretsManagement` request message
itself and the reply is its response message, and the QUIC handler calls the
same `SecretsServerAdapter` method the gRPC RPC calls, so codes match on both
transports. The SDK's QUIC adapter routes those five full method names to
`0xCE`, so `pb.NewSecretsManagementClient` over its connection works unchanged.
Subs `0x01`–`0x06` take platform wire structs and are not routed by method name.
Every secrets sub needs the scope in its row's MCP cell, the one its gRPC method
needs; the two list subs, `0x03` and `0x08`, need `secrets:list`.

**An embedded daemon cannot serve secret versions, rotate, rollback or
status.** Seam: go-quicbaas embedded Secrets `GetVersion`, `ListVersions`,
`Rotate`, `Rollback` and `UpdateStatus`. The pinned SDK's embedded dispatcher
(`sdk/go/transport/embedded/transport.go` `unaryHandlers`, v0.12.0-alpha)
registers only `Store`, `Get`, `List`, `Delete` and `Ensure` for
`quicbaas.Secrets`, so on an embedded daemon every transport's route for the
other five reaches the SDK and answers its unknown-method error; its service
also refuses a `deleted` status. A daemon on a remote quicbaas transport
serves them.

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

**Every `kms_*`, `secret_*` and `dek_*` MCP tool carries the scope of the gRPC
method it mirrors (#304)**, shown beside each tool in the tables above. The
`kms_*` scopes are those of `KeyManagementService` and the `quicbaas.kms.v1`
`KeyManagement` and `Crypto` services; the `secret_*` scopes are those of
`quicbaas.kms.v1.SecretsManagement` and the `dek_*` scopes those of
`quicbaas.kms.v1.DEKManagement` (`pkg/api/grpc/method_permissions.go`).
A caller without the scope is refused with `PermissionDenied` before the
handler runs.

`kms_decrypt` and `kms_generate_data_key` answer plaintext key material and
`secret_get` and `secret_get_version` answer the secret, so each reaches only a
holder of its scope.
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

Every transport answers an error with its **class**, a gRPC status code named
by one shared classifier, `pkg/api/errclass` (#304). It reads the error's type,
never its message, and tries in order: a gRPC status anywhere in the chain
(including typed errors with a `GRPCStatus` method), then the QuicBaaS SDK
error code (`sdkerrors.Code`), then a database error's own `HTTPStatus`. An
error that names no class is `Internal`. The gRPC adapters still log every
error before answering it.

| Class (gRPC / Unix) | REST | QUIC byte | MCP JSON-RPC | KMS cause |
|---|---|---|---|---|
| `OK` | 200 | `0x00` `StatusOK` | result | — |
| `InvalidArgument` | 400 | `0x09` `StatusInvalidArgument` | `-32602` InvalidParams | Missing field, bad key spec or algorithm, ciphertext the key did not seal, empty or oversize batch |
| `Unauthenticated` | 401 | `0x03` `StatusUnauthorized` | `-32001` AuthenticationRequired | Token invalid |
| `PermissionDenied` | 403 | `0x07` `StatusPermissionDenied` | `-32003` PermissionDenied | Missing `kms:*` scope, key policy denied, key disabled, pending deletion or not exportable |
| `NotFound` | 404 | `0x02` `StatusNotFound` | `-32005` NotFound | Unknown key, DEK or secret |
| `AlreadyExists` | 409 | `0x06` `StatusAlreadyExists` | `-32006` AlreadyExists | Key name in use |
| `Aborted` | 409 | `0x06` `StatusAlreadyExists` | `-32603` InternalError | SDK conflict |
| `FailedPrecondition` | 412 | `0x0C` `StatusFailedPrecondition` | `-32007` FailedPrecondition | Barrier or service not initialized |
| `ResourceExhausted` | 429 | `0x08` `StatusResourceExhausted` | `-32603` InternalError | **AEAD safety limit reached**, rate limited |
| `Unimplemented` | 501 | `0x0B` `StatusNotImplemented` | `-32603` InternalError | The unimplemented CLI/service areas in [engineering.md](engineering.md) §2 |
| `Unavailable` | 503 | `0x0A` `StatusUnavailable` | `-32004` ServiceUnavailable | KMS not wired into the daemon, barrier sealed, SDK connection lost |
| `DeadlineExceeded` | 504 | `0x05` `StatusTimeout` | `-32603` InternalError | SDK timeout |
| `Internal` | 500 | `0x04` `StatusInternalError` | `-32603` InternalError | Any error that names no class |

QUIC answers `0x01` `StatusInvalidRequest` only for a payload it cannot decode;
a decoded request with a missing field is `0x09`. MCP has no JSON-RPC code for
`Aborted`, `ResourceExhausted`, `Unimplemented` or `DeadlineExceeded`, so
those classes reach an MCP client as `InternalError`.

**429 from a crypto operation is not backpressure.** It can mean the key has
reached its AEAD invocation limit, at which point continuing would risk nonce
reuse. Rotate the key.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB) — relevant for batch
operations and large ciphertexts.

### Per call

| Calls | Classes they answer |
|---|---|
| Key lifecycle (generate, import, get, metadata, list, update, enable, disable, delete, schedule/cancel deletion, rotate, policy) | The backend's class; `InvalidArgument` for a missing key ID or spec, an unsupported value, filter or cursor |
| Crypto (encrypt, decrypt, sign, verify, MAC, data key, re-encrypt) | The backend's class; `InvalidArgument` for a missing input or a ciphertext the key did not seal |
| Batch (REST) | `InvalidArgument` for an empty or oversize batch; 207 Multi-Status when some items fail (`pkg/api/rest/kms_handlers.go` `writeKMSError`) |
| Secrets (`secret_*`, secret routes, `SecretsManagement`) | `InvalidArgument` for a missing ID, a rotate without data, a rollback without a target version or an unspecified status (MCP also for a status other than `enabled`, `disabled` or `deleted`); MCP answers a rotate, rollback or status failure with the SDK error's own class; gRPC and QUIC still answer store, list, rotate, rollback and status failures `Internal` and read failures (secret, version, version list) `NotFound`, whatever the cause |
| DEK (`DEKManagement`, DEK routes) | gRPC: `InvalidArgument` for a missing path; create, list, rotate and delete failures `Internal`, get and status failures `NotFound`, whatever the cause; the REST 400/404 rules are in §4 |
| Rotation policy | Update failures `Internal`, get failures `NotFound`, whatever the cause |

### MCP answers in the gRPC classes (#304)

An MCP tool fails with the gRPC code its gRPC method would answer for the same
input. `pkg/api/daemon/kms_mcp_grpc_parity_test.go` holds both transports to
it, per group, against one in-memory SDK fake.

| Input | gRPC | MCP |
|---|---|---|
| Missing `key_id`, `secret_id`, plaintext, ciphertext, message, signature or data | `InvalidArgument` — the `quicbaas.kms.v1` adapters check before calling the SDK | `InvalidArgument` |
| Unknown key (`kms_get_key`, `kms_get_key_metadata`, `kms_get_key_policy`) | `NotFound` | `NotFound` |
| Unknown secret (`secret_get`, `secret_get_rotation_policy`, `secret_get_version`, `secret_list_versions`) | `NotFound` | `NotFound` |
| Encrypt, decrypt or data key under an unknown key | `NotFound` | `NotFound` |
| Decrypt a ciphertext the key did not seal | `InvalidArgument` | `InvalidArgument` |
| HMAC or rewrap under an unknown key | `NotFound` | `NotFound` |
| Key status, key versions or batch under an unknown key | `NotFound` | `NotFound` |
| Import without `key_material` or `key_spec`; batch without `items` or over 100 | `InvalidArgument` | `InvalidArgument` |
| Hash with SHA-1 or an unknown algorithm | `InvalidArgument` | `InvalidArgument` |
| Rewrap with a non-zero `source_version` (§3) | `InvalidArgument` | `InvalidArgument` |

The key read methods keep the backend's class on both transports: an unknown
key is `NotFound`, an unavailable backend `Unavailable`, an unclassed failure
`Internal`. The data-key comparison is against `platform.v1`
`GenerateDataKey`, since `quicbaas.kms.v1` has no data-key method.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
unimplemented CLI areas are stubs awaiting implementation, not deprecations.
