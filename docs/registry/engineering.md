# Trusted Registry — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/registry/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> This is the file an implementing agent works from. Design and boundaries are
> in [architecture.md](architecture.md); the transport matrix is in
> [api.md](api.md).

---

## 1. Exported surface

Every identifier below was grepped in this repository before it was written
down. Where a previous document named something that does not exist, the
correction is noted inline.

### The interface

`pkg/registry/registry.go:29` — `TrustedRegistry`:

```go
type TrustedRegistry interface {
	Push(ctx context.Context, ref string, image *Image, opts PushOptions) error
	Pull(ctx context.Context, ref string, opts PullOptions) (*Image, error)
	Delete(ctx context.Context, ref string) error
	List(ctx context.Context, opts RegistryListOptions) ([]*ImageManifest, error)
	VerifyClient(ctx context.Context, attestation *AttestationEvidence) error
	EncryptImage(ctx context.Context, ref string, keyID string) error
	DecryptImage(ctx context.Context, ref string) (*Image, error)
}
```

> **Correction (2026-08-18).** An earlier draft of `architecture.md` gave
> `List(ctx, opts ListOptions) ([]ImageManifest, error)` and passed `image
> Image` by value. Both are wrong: the option type is **`RegistryListOptions`**,
> not `ListOptions` (which is a different type belonging to other packages), and
> images cross the boundary as **pointers**. An agent that built against the old
> signature would not compile.

`*Registry` (`pkg/registry/registry.go`) is the single implementation and adds
three methods beyond the interface:

| Method | Line | Purpose |
|---|---|---|
| `Close() error` | `registry.go:758` | Releases storage and KMS handles |
| `GetSession(clientID string) (*RegistrySessionView, bool)` | `registry.go:796` | Read-only view of a cached attestation session |
| `InvalidateSession(clientID string)` | `registry.go:812` | Forces the next request from that client to re-attest |

`GetSession` returns a **`*RegistrySessionView`**, not the `*RegistrySession`
the session manager holds. The view exists so callers cannot mutate live
session state; do not widen it to return the session itself.

### Constructors and functional options

| Constructor | File | Notes |
|---|---|---|
| `NewRegistry(config RegistryConfig, logger *slog.Logger, opts ...RegistryOption) (*Registry, error)` | `registry.go` | The only supported way to build a registry |
| `NewRegistryAuthHandler(...)` | `auth.go` | Attestation gate in front of every request |
| `NewSessionManager(quicBaaS QuicBaaSClient, sessionDuration time.Duration) *SessionManager` | `auth.go` | Session cache; duration comes from `cache_session_duration` |
| `NewImageEncryptor(kms KMSClient, opts ...EncryptorOption) (*ImageEncryptor, error)` | `encryption.go` | Per-layer DEK envelope encryption |
| `NewQuicBaaSStorage(client QuicBaaSStorageClient, opts ...StorageOption) (*QuicBaaSStorage, error)` | `storage.go` | The production blob backend |
| `NewFileStorageClient(root string) (*FileStorageClient, error)` | `file_storage.go` | Local filesystem backend for development and tests |
| `NewLocalKMSClient(root string) (*LocalKMSClient, error)` | `local_kms.go` | Single-node KMS. **Reached by the shipped daemon** — see the correction below |
| `NewGRPCAdapter(r *Registry) *GRPCAdapter` | `grpc_adapter.go` | Bridges `*Registry` to the generated `RegistryService` server |

The four option types — `RegistryOption`, `EncryptorOption`, `StorageOption`
and the auth handler's — follow the portfolio functional-option convention:
each is a `func(*T) error` applied in order by its constructor.

### Seams for substitution

Three interfaces exist purely so the registry can be driven without hardware or
a live backend. They are the fault-injection points:

- `Attestor` — supplies and verifies attestation evidence. Test doubles return
  canned `*AttestationEvidence`.
- `KMSClient` — key wrap/unwrap. `LocalKMSClient` satisfies it on disk.
- `QuicBaaSStorageClient` / `FileStorageClient` — blob persistence.

---

## 2. Invariants

1. **Attestation is the only authentication method.** When
   `attestation.require_attestation` is true, `VerifyClient` runs before any
   read or write path and a failure aborts the request. There is no password,
   token, or bearer-credential fallback, and none may be added: an alternative
   credential path would defeat the entire point of the feature.
2. **A cached session never outlives its configured window.** Sessions are keyed
   by client ID and expire after `cache_session_duration`. Expiry is checked on
   read, not by a sweeper, so a clock jump backwards extends a session and a
   clock jump forwards ends it — the platform requires synchronised time
   (see [`docs/ntp/`](../ntp/)).
3. **A quote older than `quote_max_age` is rejected** even if its signature and
   PCRs are valid. Replay resistance comes from the nonce
   (`nonce_validity_duration`) and freshness comes from this bound; both must
   hold.
4. **Digests are verified on the way in and on the way out.** A blob whose
   computed digest does not match its descriptor produces `ErrDigestMismatch`
   and is never written to storage nor returned to a client.
5. **Encryption is per layer, not per image.** Each layer carries its own DEK
   (`EncryptedLayerMeta`); the DEKs are wrapped by a KMS key. Rotating the KMS
   key rewraps DEKs and does not re-encrypt layer bytes.
6. **`EncryptImage` is in-place and requires the image to already exist.**
   Calling it on an absent reference is `ErrImageNotFound`, not an implicit
   push.
7. **Concurrency is bounded by configuration, not by the caller.**
   `max_concurrent_pulls` and `max_concurrent_pushes` gate the corresponding
   paths; exceeding them blocks rather than failing.

---

## 3. Error semantics

`pkg/registry/errors.go` declares typed errors, not `fmt.Errorf` strings. The
ones a caller must handle by type:

| Type | Returned when | Fails closed |
|---|---|---|
| `ErrAttestationRequired` | Evidence absent and attestation is required | yes |
| `ErrAttestationFailed` | Evidence present but verification failed | yes |
| `ErrPCRMismatch` | A required PCR does not match `required_pcrs` | yes |
| `ErrInvalidQuote` | Quote malformed, unsigned, or past `quote_max_age` | yes |
| `ErrAIKNotAllowed` | AIK fingerprint not in `allowed_aiks` | yes |
| `ErrPolicyEvaluationFailed` | The OPA attestation policy could not be evaluated | yes |
| `ErrAccessDenied` | Attestation succeeded, authorization did not | yes |
| `ErrInvalidSession` | Session expired, unknown, or invalidated | yes |
| `ErrImageNotFound` / `ErrManifestNotFound` / `ErrBlobNotFound` | Reference resolves to nothing | n/a |
| `ErrImageExists` / `ErrImageAlreadyExists` | Push would overwrite without `--overwrite` | n/a |
| `ErrDigestMismatch` | Computed digest differs from the descriptor | yes |
| `ErrInvalidDigest` / `ErrInvalidImageRef` / `ErrInvalidManifest` | Malformed input | yes |
| `ErrImageEmpty` | Push carried no layers | yes |
| `ErrEncryptionNotConfigured` | `--encrypt` with no encryption backend | yes |
| `ErrEncryptionFailed` / `ErrDecryptionFailed` | Crypto operation failed | yes |
| `ErrKeyNotFound` / `ErrKeyNotFoundLocal` / `ErrKeyCreationFailed` / `ErrKeyWrapFailed` / `ErrKeyUnwrapFailed` | KMS path failures | yes |
| `ErrInvalidConfig` | Rejected at construction, before the listener opens | yes |
| `ErrNilClient` / `ErrNilContext` | Programming errors caught at the boundary | yes |
| `ErrOperationTimeout` | `read_timeout` / `write_timeout` / storage `request_timeout` elapsed | yes |

**Every failure in the attestation and crypto columns fails closed.** There is
no path on which a verification error yields a served image. When you add a
branch to `VerifyClient` or to the encryption envelope, the default arm must
deny.

**Crossing the transport boundary.** The gRPC adapter maps these to status
codes; REST maps them to the structured error envelope in
`pkg/webservice/v1/response`. A registry service that is not wired into the
daemon returns **HTTP 503 with a structured "not configured" envelope** on
every route — that is deliberate (`pkg/webservice/v1/rest/registry/router.go:44`),
so an operator can tell "disabled" from "broken". MCP tools return
`ErrRegistryNotConfigured` for the same case rather than "unknown tool".

---

## 4. Configuration

`RegistryConfig` (`pkg/registry/config.go:22`). YAML keys are the struct tags;
they are the contract, not the Go field names.

| Key | Type | Meaning |
|---|---|---|
| `listen_addr` | string | Registry listener, e.g. `":5000"` |
| `read_timeout`, `write_timeout`, `idle_timeout` | duration | HTTP server bounds |
| `max_concurrent_pulls`, `max_concurrent_pushes` | int | Per-direction concurrency gate |
| `tls.enabled` | bool | TLS on the registry listener |
| `tls.cert_file`, `tls.key_file`, `tls.ca_file` | path | Server cert, key, and the CA used to verify clients |
| `tls.client_auth` | `tls.ClientAuthType` | Client-certificate policy |
| `tls.min_version`, `tls.cipher_suites` | uint16 / []uint16 | Constrained by FIPS mode when enabled |
| `attestation.require_attestation` | bool | **The gate.** False disables the feature's whole premise; only ever set it false in a development sandbox |
| `attestation.required_pcrs` | map[int][]byte | Golden PCR policy a client must match |
| `attestation.allowed_aiks` | []string | AIK fingerprint allowlist; empty accepts any valid AIK |
| `attestation.attestation_policy` | path | OPA policy evaluated for the attestation decision |
| `attestation.nonce_validity_duration` | duration | Replay window for the challenge nonce |
| `attestation.quote_max_age` | duration | Freshness bound on the TPM quote |
| `attestation.cache_session_duration` | duration | How long a verified client skips re-attestation |
| `storage.addr` | string | Backend address |
| `storage.namespace` | string | Namespace for registry blobs |
| `storage.encrypted` | bool | Encrypt blobs at rest |
| `storage.key_id` | string | Key used for at-rest blob encryption |
| `storage.connection_timeout`, `storage.request_timeout` | duration | Backend bounds |
| `storage.max_retries`, `storage.retry_backoff` | int / duration | Retry ladder |
| `encryption.quicbaas_addr` | string | Key-management endpoint |
| `encryption.key_namespace` | string | Namespace for image encryption keys |
| `encryption.algorithm` | string | e.g. `AES-256-GCM` |

`StorageConfig`'s doc comment states that the stack's object-storage service is
**the only supported storage backend** for the trusted registry.
`FileStorageClient` and `LocalKMSClient` are not a supported production
*configuration* and must not be documented as one.

### FIPS: both AES-GCM call sites, and an envelope that never shipped (#209)

`pkg/registry` seals bytes in two places. `cipher.NewGCM` — the explicit-nonce
constructor — is refused outright under `GODEBUG=fips140=only`, so both moved to
`cipher.NewGCMWithRandomNonce`, which generates the nonce itself and carries it
inside the ciphertext. Both now produce the same framing:

```
nonce (12) || ciphertext || tag (16)
```

| site | before | after |
|---|---|---|
| `local_kms.go` `Encrypt`/`Decrypt` | `nonce \|\| ciphertext \|\| tag`, assembled by hand | identical bytes, assembled by the cipher |
| `encryption.go` `encryptContent`/`decryptContent` | nonce in a separate `nonce` field of the envelope | nonce inside the ciphertext; envelope **v2** |

`LocalKMSClient` already prepended a 12-byte nonce, which is exactly what
`NewGCMWithRandomNonce` emits, so **the swap changed no stored bytes**. That is
asserted by a checked-in vector in `TestLocalKMS_WireFormatUnchanged` rather
than argued from the standard library's documentation — the vector is a literal
because recomputing it would need the very API a FIPS build refuses, which would
have forced the test to skip in exactly the build whose compatibility it exists
to prove.

**Both sites call `pkg/crypto/aesgcm` since #248.** `encryptContent`,
`decryptContent` and `LocalKMSClient.Encrypt`/`Decrypt` hold no cipher of their
own: they call `aesgcm.Seal`/`Open`, which produce the same framing, so no stored
byte changed — `TestLocalKMS_WireFormatUnchanged` now opens its pre-#209 vector
through `aesgcm.Open`. `registry.NonceSize` and `TagSize` are the package's
constants. A blob shorter than nonce + tag is refused with
`aesgcm.ErrCiphertextTooShort` (inside `ErrDecryptionFailed` on the layer path)
before any decryption is attempted.

**The envelope changed format, and there is deliberately no migration.** The
nonce field is gone and `encryptedLayerEnvelopeVersion` is `2`; there is no v1
decoder and no refusal path beyond the version check that already existed.

That is not an oversight, and it is worth stating plainly because the absence of
a migration looks exactly like one. **No registry had been deployed when the
format changed** (owner ruling, 2026-09-03), so no v1 envelope has ever existed
outside a test. "A FIPS build cannot read v1" is therefore not a compatibility
risk that was accepted — it is a property of a format that never shipped.

The version was bumped rather than v1 being redefined in place, for one
concrete reason: `decodeEncryptedLayer` already rejected unknown versions, so
the bump cost one constant and added **no new branch**. Had v1 kept its number,
a v1 blob meeting the v2 reader would have had its first 12 bytes of ciphertext
mistaken for a nonce and surfaced as a decryption failure — which reads as key
trouble or corruption. It now names the version instead.
`TestDecodeEncryptedLayer_RejectsRetiredVersion` pins that, and is a diagnosis
path rather than a migration.

**Correction (2026-09-03, #209): "not supported" is not the same as "not
reached", and this section previously implied it was.** `LocalKMSClient` is
wired by `pkg/daemon/commands/registry_init.go` (`registryDistBackend`, called
from `serve.go`), so the shipped daemon does construct it: it backs the
image-encryption pipeline with keys under `<PlatformDir>/registry/keys`, which
operators are told to back up. Until the XKMS-backed `KMSClient` lands it is
what actually wraps per-layer DEKs on a running node.

The distinction matters for triage. A defect in `LocalKMSClient` is a defect an
operator can hit, not a test-only concern — #209 found its AES-GCM broken under
`GODEBUG=fips140=only` with **no test covering it at all**, so the FIPS nightly
showed five red packages while this one failed silently.

---

## 5. Persistence

- **Blobs** live in the configured storage namespace, addressed by digest.
- **Manifests** are `ImageManifest` documents; an encrypted image additionally
  carries `EncryptedImage` / `EncryptedLayer` / `EncryptedLayerMeta` describing
  the per-layer DEK envelope.
- **Compatibility rule:** an unencrypted manifest must remain readable after
  encryption is enabled, and an encrypted manifest must remain readable after
  the KMS key rotates. Both are consequences of §2.5 — rotation rewraps DEKs
  and leaves layer bytes untouched.

---

## 6. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/registry/*_test.go` | Digest handling, envelope encryption, session expiry, error mapping |
| Integration | `test/integration/registry/` | End-to-end push/pull against a running daemon |
| Transport parity | see [api.md](api.md) | REST, gRPC, MCP, Unix, embedded |

**Known gap — record, do not paper over.** This repository has **no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the parity
requirement in `conventions/feature-docs.md` §4 — every `cli.md` verb has a
`CommandDefinition` in the integration parity suite — is **unmet repo-wide**,
not only here. It is listed as an owner question in the migration report rather
than silently satisfied.

Fault-injection seams are the three interfaces in §1: substitute `Attestor` to
force `ErrAttestationFailed`, `KMSClient` to force `ErrKeyUnwrapFailed`, and the
storage client to force `ErrBlobNotFound` and `ErrOperationTimeout`.

---

## 7. Observability

- The registry takes an `*slog.Logger` at construction; every denial logs the
  client ID and the deciding error type. **Attestation evidence and quotes are
  not logged** — they are attestation material, and a log is not a trust store.
- REST responses go through `pkg/webservice/v1/response`, so status codes and
  error envelopes are uniform with the rest of the platform.
- `platformctl registry status --metrics` surfaces the operational counters;
  `--attestation` and `--encryption` print the effective policy, which is the
  fastest way to confirm a deployed gate is actually on.

---

## 8. Related

- [architecture.md](architecture.md) — design, boundaries, rejected alternatives
- [api.md](api.md) — the capability × transport matrix
- [cli.md](cli.md) — `platformctl registry`
- [user.md](user.md) — task-oriented usage
- The pre-migration configuration.md is deleted; §4 holds the configuration
  reference
