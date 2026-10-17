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
| Revoke key | `POST /api/v1/kms/keys/{name}/revoke` | `KeyManagement.RevokeKey` | as above | `kms_revoke_key` (`kms:write`) | — |
| Update key status | `PUT /api/v1/kms/keys/{name}/status` | `UpdateKeyStatus` | as above | `MISSING — docs/13 G7` | ✅ |
| List key versions | `GET /api/v1/kms/keys/{name}/versions` | `GetKeyVersions` | as above | `MISSING — docs/13 G7` | ✅ |
| Export key | `MISSING — docs/13 G7` | `ExportKey` | as above | `kms_export_public_key` (`kms:read`) | ✅ |
| Get key metadata | `GET /api/v1/kms/keys/{name}/metadata` | `KeyManagement.GetKeyMetadata` | as above | `kms_get_key_metadata` (`kms:read`) | — |
| Update key metadata | `PUT /api/v1/kms/keys/{name}/metadata` | `KeyManagement.UpdateKeyMetadata` | as above | `kms_update_key_metadata` (`kms:write`) | — |
| Get key policy | `GET /api/v1/kms/keys/{name}/policy` | `KeyManagement.GetKeyPolicy` | as above | `kms_get_key_policy` (`kms:read`) | — |
| Set key policy | `PUT /api/v1/kms/keys/{name}/policy` | `KeyManagement.SetKeyPolicy` | as above | `kms_set_key_policy` (`kms:write`) | — |
| List algorithms | `GET /api/v1/kms/algorithms` | `KeyManagement.GetSupportedAlgorithms` | as above | `kms_supported_algorithms` (`kms:read`) | — |
| Backend status | `GET /api/v1/kms/backend/status` | `BackendStatus` | as above | `kms_backend_status` (`kms:read`) | ✅ |

**`ExportKey` exists on gRPC and has no REST route.** The MCP tool is
`kms_export_public_key` — note the name: public key only. The gRPC RPC is
`ExportKey` without that qualifier, which is a naming difference worth checking
before assuming what crosses the boundary.

Key **revocation, metadata, policy and the algorithm list** have no RPC on the
platform `KeyManagementService`; gRPC serves them through
`quicbaas.kms.v1.KeyManagement`.

`GenerateKey` on every transport: the request's `name` is the key ID.
`key_spec.exportable` and `key_spec.deletion_protection` are set at generation;
a delete of a deletion-protected key is refused with FailedPrecondition.
`description` and `tags` are recorded as key metadata right after the generate,
and the reply's `metadata` is what the KMS recorded, read back, never an echo
of the request. `owner` cannot be set: the SDK `GenerateKeyRequest` and
`UpdateKeyMetadataRequest` have no owner field (go-quicbaas
`sdk/go@v0.12.0-alpha` `client/kms/client.go:100` and `:431`), so the reply
carries the owner the KMS recorded. A key whose metadata cannot be recorded
fails the request with the metadata error's class; the key itself exists.

That holds in the system scope: a caller of the platform system tenant, or an
unbound caller. A caller of any other tenant generates in that tenant's key
scope, where the reply's `metadata` is only what the generate response carries
(key ID, algorithm, version, `exportable`, `deletion_protection`) and no
metadata call is made. A tenant-scope request carrying `description` or `tags`
is refused with `FailedPrecondition` on every transport before any key is
generated. SDK gap (go-quicbaas `v0.12.0-alpha`): `GenerateKey` stores a
tenant key as `tenant/<tenant>/<name>` (`pkg/service/kms.go:446`), but
`GetKeyMetadata` (`:1266`) and `UpdateKeyMetadata` (`:1302`) look the name up
unscoped, so they miss the key or reach a same-named system key; and the
tenant setter they read, `iam.ContextWithTenant`, is not re-exported under
`quicbaas/sdk/go` (`sdk/go/transport.ContextWithTenant` sets a different key).

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
| Generate data key | `POST /api/v1/kms/data-keys` | `GenerateDataKey` | `0xD9` | `kms_generate_data_key` (`kms:write`) | ✅ |
| Generate wrapped data key | `POST /api/v1/kms/data-keys/wrapped` | `GenerateWrappedDataKey` | `0xDA` | `kms_generate_wrapped_data_key` (`kms:write`) | ✅ |
| Create DEK | `POST /api/v1/kms/deks` | `DEKManagement.CreateDEK` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| List DEKs | `GET /api/v1/kms/deks` | `DEKManagement.ListDEKs` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get DEK | `GET /api/v1/kms/deks/{path}` | `DEKManagement.GetDEK` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| DEK status | `GET /api/v1/kms/deks/{path}/status` | `DEKManagement.GetDEKStatus` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Rotate DEK | `POST /api/v1/kms/deks/{path}/rotate` | `DEKManagement.RotateDEK` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Delete DEK | `DELETE /api/v1/kms/deks/{path}` | `DEKManagement.DeleteDEK` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |

| Secrets capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Store secret | `POST /api/v1/kms/secrets` | `SecretsManagement.StoreSecret` | secrets category `0xCE`, sub `0x01` | `secret_store` (`secrets:write`) | — |
| List secrets | `GET /api/v1/kms/secrets` | `SecretsManagement.ListSecrets` | sub `0x03` | `secret_list` (`secrets:list`) | — |
| Get secret | `GET /api/v1/kms/secrets/{name}` | `SecretsManagement.GetSecret` | sub `0x02` | `secret_get` (`secrets:read`) | — |
| Delete secret | `DELETE /api/v1/kms/secrets/{name}` | `SecretsManagement.DeleteSecret` | sub `0x04` | `secret_delete` (`secrets:delete`) | — |
| Get secret version | `GET /api/v1/kms/secrets/{name}/versions/{version}` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| List secret versions | `GET /api/v1/kms/secrets/{name}/versions` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Rotate secret | `POST /api/v1/kms/secrets/{name}/rotate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Rollback secret | `POST /api/v1/kms/secrets/{name}/rollback` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Update secret status | `PUT /api/v1/kms/secrets/{name}/status` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get rotation policy | `GET /api/v1/kms/secrets/{name}/policy` | `SecretsManagement.GetRotationPolicy` | sub `0x06` | `secret_get_rotation_policy` (`secrets:read`) | — |
| Set rotation policy | `PUT /api/v1/kms/secrets/{name}/policy` | `SecretsManagement.SetRotationPolicy` | sub `0x05` | `secret_set_rotation_policy` (`secrets:write`) | — |

**gRPC DEK and REST DEK are one store.** `DEKManagement` calls the same SDK DEK
client (`Security().DEK()`) as the `/deks` routes, so a DEK created on one
transport is read, rotated and deleted on the other.

**Secret versions, rotate, rollback and status are not served on gRPC or MCP.**
Seam: go-quicbaas embedded Secrets `GetVersion`, `ListVersions`, `Rotate`,
`Rollback` and `UpdateStatus`. The pinned SDK's embedded dispatcher
(`sdk/go/transport/embedded/transport.go` `unaryHandlers`) registers only
`Store`, `Get`, `List`, `Delete` and `Ensure` for `quicbaas.Secrets`, so an
embedded daemon answers the other five with an unknown-method error; its
service also refuses a `deleted` status. The REST routes in the table reach the
same SDK client and fail the same way on an embedded daemon.

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
| Secrets (`secret_*`, secret routes, `SecretsManagement`) | `InvalidArgument` for a missing ID; gRPC and QUIC still answer store and list failures `Internal` and read failures `NotFound`, whatever the cause |
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
| Unknown secret (`secret_get`, `secret_get_rotation_policy`) | `NotFound` | `NotFound` |
| Encrypt, decrypt or data key under an unknown key | `NotFound` | `NotFound` |
| Decrypt a ciphertext the key did not seal | `InvalidArgument` | `InvalidArgument` |

The key read methods keep the backend's class on both transports: an unknown
key is `NotFound`, an unavailable backend `Unavailable`, an unclassed failure
`Internal`. The data-key comparison is against `platform.v1`
`GenerateDataKey`, since `quicbaas.kms.v1` has no data-key method.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
unimplemented CLI areas are stubs awaiting implementation, not deprecations.
