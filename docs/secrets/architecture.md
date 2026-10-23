# Configuration Secret Resolution — Architecture

> **Status: NORMATIVE** · Scope: `pkg/config/secrets/`, `pkg/bootstrap/`, `pkg/app/secrets*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

A platform node's configuration file names a dozen credentials: TPM
authorization values, CA key passwords, BMC account passwords, switch SSH
passwords, web-service key passwords. Every one of them has to reach the process
before it initialises anything — the TPM hierarchy auth is needed before
`InitTPM`, the CA key password before CA init.

Putting those values in the file means the file cannot be version-controlled,
cannot be templated, and cannot be shipped in an installer image. Fetching them
all by hand at boot means every service grows its own credential-loading code.

## 2. The shape chosen

**A configuration value may be a URI instead of a literal.** At bootstrap, a
single reflective walk over the in-memory config struct replaces every secret
URI with its resolved plaintext, in place, before any service reads it.

```
platform.yaml                 resolution                    in-memory config
+--------------------+      +------------------+      +--------------------+
| bmc:               |      | ResolverRegistry |      | bmc:               |
|   password:        | ---> |  kms://          | ---> |   password: <bytes>|
|     "kms://..."    |      |  idevid://       |      |                    |
| tpm:               |      |  file://         |      | tpm:               |
|   srk-auth:        | ---> |  dynamic://      | ---> |   srk-auth: <bytes>|
|     "idevid://..." |      |  xkms://         |      |                    |
+--------------------+      +------------------+      +--------------------+
                                     |
                              ConfigProcessor
                              (fail-closed)
```

Three properties define the design:

1. **Scheme-routed.** The URI scheme selects the resolver. Adding a source means
   adding a resolver, not touching the walker.
2. **Fail-closed, always.** `ProcessSecrets` constructs the processor with
   `quicbaassecret.WithFailClosed()` unconditionally. Any URI that cannot be
   resolved aborts startup. A raw `kms://...` string is never handed downstream
   as if it were a password.
3. **The SPI is not ours.** The resolver interface, the registry and the config
   walker are `go-quicbaas/sdk/go/secret` types. This repository contributes
   *resolvers*, plus the platform-specific glue that builds the registry.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **A platform-wide AES-256-GCM config-encryption scheme** | Shipped once and **removed**. One wrapping key shared by every node means compromising it exposes every secret on every node. Replaced by `kms://` (per tenant/node keyspace) and `idevid://` (per device). |
| **Leave an unresolved URI as a literal string** | It reaches the TPM as a `TPM2B_AUTH` and fails with `TPM_RC_SIZE`, or reaches the BMC as a password and fails as an auth error — both cryptic, both after partial initialisation. `WithFailClosed` turns it into one clear startup refusal. |
| **Resolve lazily, at first use** | Then a bad reference surfaces during an operation instead of at boot, and every consumer needs resolution logic. One walk, once, before anything starts. |
| **Write our own resolver registry and config walker** | go-qrdb owns that SPI and go-quicbaas exports it. `pkg/bootstrap/secrets.go` says so outright: *"Secret resolution and config walking are delegated to the unified qrdb-SDK ResolverRegistry / ConfigProcessor."* An earlier local `SecretManager` was removed — see §8. |
| **Silently skip `kms://` when the KMS is unreachable** | `kmsNotAvailableResolver` exists precisely to prevent that: in standalone mode with `local-kms: true`, every `kms://` URI resolves to `ErrSecretsServiceNotAvailableButKMSRequired`. Loud failure over quiet literal. |
| **Enable `file://` by default** | It reads plaintext secret bytes off local disk. It is opt-in (`secrets.file`), off by default, and documented as an airgap/dev/recovery escape hatch only. |
| **Base64-decode or trim `file://` contents** | The operator controls the exact on-disk representation. The file's bytes *are* the secret. An empty file is `ErrFileEmpty`, not an empty secret. |
| **Rotate `idevid://` values in place** | The blob is RSA-OAEP-encrypted to a `FixedTPM` IDevID key. There is no rotation; changing the value means re-provisioning the node. That is the cost of binding a secret to one chip. |

## 3. Component boundaries

| Piece | Location | Owner |
|---|---|---|
| **`SecretResolver` interface, `SecretValue`, `ResolverRegistry`, `ConfigProcessor`, `ProcessResult`, `WithFailClosed`** | `go-quicbaas/sdk/go/secret` | **not this repo** |
| **`kms://`, `remote-kms://`, `credential://`, autogen resolvers; `EnsureSecret` semantics** | go-qrdb, composed by go-quicbaas; obtained via `sdkClient.Security().SecretResolver()` | **not this repo** |
| **The secret store itself** | go-quicbaas `SecretsService`, reached through `App.Secrets()` — [`docs/kms/`](../kms/) | **not this repo** |
| URI scheme and strategy constants, `IsSecretURI`, `ExpandShortKMSPath` | `pkg/bootstrap/secrets.go` | this repo |
| `idevid://` resolver | `pkg/config/secrets/idevid_resolver.go` | this repo |
| `file://` resolver | `pkg/config/secrets/file_resolver.go` | this repo |
| `dynamic://` resolver | `pkg/app/secrets_resolvers.go` | this repo |
| `xkms://` resolver | `pkg/app/secrets_resolvers.go` | this repo |
| Registry assembly, `SecretsConfig`, `ProcessSecrets` | `pkg/app/secrets.go` | this repo |
| TPM-backed decrypter for `idevid://` | `pkg/app/secrets.go` (`tpmDecrypter`, `getIDevIDDecrypter`) | this repo |
| Atomic config-file rewriting and backup | `pkg/bootstrap/config_writer.go` | this repo |
| `platformctl bootstrap secrets` | `pkg/cli/commands/bootstrap/secrets*.go` | this repo |
| **IDevID key material and RSA decryption** | The node's TPM via go-xkms — [`docs/tpm/`](../tpm/) | **not this repo** |

The §R capability rows touched are the *"Re-export frontage of the composed
stack"* row (the KMS half) and *"Zero-touch provisioning"* (secrets delivered to
a node during provisioning). The SDK edge consumed is
`go-quicbaas/sdk/go/secret` plus `sdkClient.Security()`.

## 4. Data flow

### Bootstrap

`pkg/app/app.go`, in order:

1. `initStores()` — the `SecretsService` must exist before `kms://` can resolve.
2. `ProvisionSecureBootKeys(ctx)` — Secure Boot PK/KEK/DB material is created
   first, because those `kms://` references carry no `?ensure=true` (they are
   keypairs and certificates, not random bytes) and nothing else would create
   them; the fail-closed walk below would otherwise abort with "secret not
   found".
3. **If `SecretsConfig != nil && SecretsConfig.Enabled`:**
   `ProcessSecrets(ctx, cfg)`:
   - `SetupSecretResolvers` builds the registry (§5).
   - `quicbaassecret.NewConfigProcessor(registry, WithFailClosed())`.
   - `processor.Process(ctx, app)` walks the `*App` struct reflectively and
     replaces secret-URI string fields in place.
   - On failure, every unresolved field and every resolution error is logged
     individually before returning — so the operator learns *which* of dozens
     of `kms://` references blocked startup, not just that one did.
4. Startup aborts if any field failed.
5. `initBarrier`, `initSDN`, TPM initialisation, CA init — all now reading
   plaintext.

Ordering is the design: the PINs used for TPM hierarchy auth must be stable
before `ParsePINs()` / `InitTPM()`.

### Registry assembly (`SetupSecretResolvers`)

```
QuicBaaS SDK client present?
├── yes → base registry = sdkClient.Security().SecretResolver()
│          (already carries credential://, kms://, remote-kms://, autogen)
└── no  → base registry = quicbaassecret.NewResolverRegistry()
           └── if cfg.LocalKMS: register kmsNotAvailableResolver
                                (every kms:// URI fails closed)

then, additively:
  cfg.Encrypted       → secrets.NewIDevIDResolver(tpmDecrypter, logger)
  cfg.File            → secrets.NewFileResolver(logger)
  cfg.DynamicSecrets  → NewDynamicSecretsResolver(sdkClient.Security().DynamicSecrets(), logger)
  cfg.XKMS            → NewXKMSSecretsResolver(&xkmsKMSClientAdapter{...}, logger)
```

Every one of the four additive registrations **logs a warning and skips** when
its dependency is missing — an IDevID decrypter that cannot be built, a nil
DynamicSecrets client, a nil KMS client. **A skipped resolver is not a silent
pass**: the URI it would have handled then has no resolver, and the fail-closed
processor rejects it at walk time. The warning is the early signal; the startup
abort is the enforcement.

### Migration (operator-driven, CLI only)

`platformctl bootstrap secrets migrate` is a **separate, text-level** pipeline
that does not use the registry at all:

1. Read the YAML file as bytes; regex- and indentation-scan for URIs.
2. Resolve `env://` and `file://` **only** (§6.4).
3. Encrypt each value to the KMS via `kmsClient.EncryptDomain`.
4. `ConfigWriter.Backup()`, then `UpdateSecretReferences` rewrites the YAML
   nodes to `kms://config/<dotted.path>` atomically (temp file → sync →
   rename), restoring from backup if the update fails.
5. Verify, then print a summary.

### What crosses a boundary

| Crossing | What crosses |
|---|---|
| Config file → memory | A URI (not a secret) |
| Node → go-quicbaas secret store | `kms://` path; the resolved bytes come back |
| Node → provisioning server | `remote-kms://` fetch over mTLS |
| Ciphertext → TPM | `idevid://` blob in, plaintext out; the private key never leaves the chip |
| Local disk → memory | `file://` — plaintext already on disk |
| Node → go-quicbaas DynamicSecrets | `dynamic://` role name; a leased credential comes back as JSON |

## 5. Trust boundaries

1. **A config file containing only URIs is not a secret.** That is the point —
   it can be templated, committed and shipped. **A config file containing a
   `file://` reference is still not a secret; the file it points at is.**

2. **`kms://` fails closed, by two mechanisms.** With a QuicBaaS client, an
   unresolvable path errors from the real resolver. Without one and with
   `local-kms: true`, `kmsNotAvailableResolver` returns
   `ErrSecretsServiceNotAvailableButKMSRequired` for every `kms://` URI. Its
   entire reason for existing is that *"the raw URI string is never passed
   downstream as a literal password or auth value."*

3. **`idevid://` is bound to one TPM.** RSA-OAEP/SHA-256 to the node's IDevID
   certificate; the private key is `FixedTPM`. A blob copied to another node is
   undecryptable. There is no rotation — changing the value means
   re-provisioning.

4. **`file://` is plaintext on disk and is opt-in for that reason.** Off by
   default (`SecretsConfig.File` zero value). **Never enable it on a node that
   can reach a KMS.** The resolver's own doc comment says so.

5. **`dynamic://` returns a whole credential document, not a password.** The
   resolved value is JSON containing the credential ID, type, data map, lease ID
   and expiry. A config field assigned a `dynamic://` URI receives that JSON —
   which is almost never what a password field wants. Treat it as a structured
   value.

6. **`xkms://` returns key *metadata*, not key material, on its fallback path.**
   `resolveViaGetKey` marshals the whole `GetKeyResponse` to JSON and returns
   that as the secret value. Only `resolveViaUnseal` returns real plaintext, and
   only when the backend reports `CanSeal`. See §6 — today's adapter never
   reports `CanSeal`.

7. **TPM authorization values are capped at 32 bytes.** A `TPM2B_AUTH` is at most
   `sizeof(TPMU_HA)` — one digest, 32 bytes on a SHA-256 TPM. Every config field
   whose value becomes a TPM auth value must use `enc=raw`, not `enc=base64`
   (which yields 43 characters for `len=32` and is rejected with `TPM_RC_SIZE`).
   The trigger is `platform-policy: true`, **not** `store:` — a software-stored
   key with `platform-policy: true` still has its password sealed into a TPM
   keyed-hash object. Fields that are not TPM auth values keep `enc=base64`.

8. **Short `kms://` paths are namespaced at resolution time.**
   `ExpandShortKMSPath` rewrites anything not starting with `tenants/` to
   `tenants/{tenant}/nodes/{node}/secrets/{path}`. **Config files must not embed
   `tenants/…/nodes/…` literals** — doing so pins a node's secrets to another
   node's keyspace. With an empty tenant or node id the path is returned
   unchanged, which is a quieter failure than it deserves.

9. **Migration touches your config file.** `secrets migrate` rewrites it in
   place. It backs up first unless `--no-backup`, and restores on failure. Run
   `--dry-run` before the real thing.

10. **`--raw` and `--show-secrets` print plaintext.** Both CLI flags exist for
    debugging and both defeat the masking that is otherwise on by default.

11. **`ProcessSecrets` logs field *paths*, never values.** Do not add value
    logging to that path.

## 6. What this feature deliberately does not do

- **It does not store secrets.** The store is go-quicbaas's `SecretsService`;
  see [`docs/kms/`](../kms/).
- **It does not implement `kms://`, `remote-kms://`, `credential://` or
  autogen.** Those resolvers come from the go-quicbaas registry.
- **It does not implement the config walker or the registry.** Both are
  `go-quicbaas/sdk/go/secret` types.
- **It does not rotate anything.** Rotation is a KMS operation
  ([`docs/kms/`](../kms/)); `idevid://` has none at all.
- **It does not resolve secrets at runtime.** One reflective walk at bootstrap.
  A config reload does not re-resolve.
- **It does not expose any API.** No REST route, no gRPC service, no QUIC
  opcode, no MCP tool. [api.md](api.md).
- **It does not resolve `kms://`, `remote-kms://`, `idevid://`, `file://`,
  `dynamic://` or `xkms://` from `platformctl bootstrap secrets resolve` or
  `verify`.** Those two verbs resolve `env://` and nothing else. See
  [cli.md](cli.md) §6.

## 7. Known non-functional paths

Recorded because a doc that omits them makes the feature look finished.

| Path | State (verified 2026-08-18) |
|---|---|
| `xkms://` | The adapter wired in `SetupSecretResolvers` is `xkmsKMSClientAdapter`, whose `CanSeal` always returns `false`, and whose `Unseal` and `GetKey` both return `ErrXKMSNotAvailable`. **Enabling `secrets.xkms` today registers a resolver that cannot resolve anything.** The `XKMSSecretsResolver` itself is complete; the adapter behind it is a placeholder with `kms interface{}` as its only field. |
| `platformctl bootstrap secrets resolve kms://...` | Returns `ErrSecretsNotImplemented` — *"secrets service is not yet implemented in the platform KMS"*. Only `env://` resolves. |
| `platformctl bootstrap secrets resolve idevid://...` / `remote-kms://...` | `ErrResolverNotAvailable` — the CLI has no TPM decrypter and no remote client. |
| `platformctl bootstrap secrets` scheme detection | `detectScheme` knows `kms://`, `remote-kms://`, `env://`, `idevid://` only. `file://` is handled by an extra `detectSchemeWithFile` in the migrate path; `dynamic://` and `xkms://` are unknown to the CLI entirely and report `unknown or missing scheme`. |
| `isResolverAvailable` | Hard-codes `true` for `kms`, `env`, `autogen`, `remote-kms`, `encrypted` and `false` otherwise. Its own comment: *"In a real implementation, this would check the resolver registry."* `secrets status` availability output is therefore advisory, not measured. |

## 8. Corrections against the code

Recorded per `conventions/feature-docs.md` §7 — the code wins, and the document
is fixed to the canonical name.

| Stale statement | Where | Reality (2026-08-18) |
|---|---|---|
| `bootstrap.NewResolverRegistry(logger)`, `bootstrap.NewSecretManager(...)`, `SecretManager`, `MigrationResult` | deleted legacy `docs/secrets/README.md` | **None of these exist.** `pkg/bootstrap/secrets.go` holds only scheme/strategy constants, `SecretStructTag`, `IsSecretURI` and `ExpandShortKMSPath`. The registry is `quicbaassecret.ResolverRegistry`; the walker is `quicbaassecret.ConfigProcessor`; the result type is `quicbaassecret.ProcessResult{Resolved int, Unresolved []string, Errors []error}`. |
| `SecretResolver.Resolve(ctx, uri) ([]byte, error)` | deleted legacy `docs/secrets/README.md` | The SPI returns `(*quicbaassecret.SecretValue, error)`. |
| `secrets: auto-generate / migrate-to-kms / update-config-file` | deleted legacy `docs/secrets/README.md`, and shipped config templates | **`SecretsConfig` defines no such fields.** Its seven keys are `enabled`, `local-kms`, `remote-kms`, `encrypted`, `file`, `dynamic-secrets`, `xkms`. The three stale keys are parsed as unknown and ignored. Generation is expressed per-URI as `?ensure=true`, not as a global switch. |
| Resolver table listing `AutoGenResolver` / `autogen://` and `EnvResolver` / `env://` as platform schemes | deleted legacy `docs/secrets/README.md` | Both come from the go-quicbaas registry. Neither `autogen://` nor `credential://` appears in this repo's `IsSecretURI`, so a config walk driven by that helper does not classify them as secret URIs. `env://` *is* in `IsSecretURI` but has no resolver in this repository. |
| `ConfigWriter` documented only as part of `SecretManager` | deleted legacy `docs/secrets/README.md` | `pkg/bootstrap/config_writer.go` is real and is used by `secrets migrate`: `NewConfigWriter`, `Path`, `Backup`, `Restore`, `UpdateSecretReferences`, `DryRun`, atomic write. |
| `secrets.enabled: true` shown as the normal case | deleted legacy `docs/secrets/README.md` | `DefaultSecretsConfig()` returns `Enabled: false`. Resolution is opt-in; the config templates opt in. |

## 9. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/kms/`](../kms/) — the secret store the `kms://` scheme reads
- [`docs/tpm/`](../tpm/) — IDevID and TPM authorization values
- [`docs/provisioning/`](../provisioning/) — how secrets reach a node being installed
- [`docs/bootstrap/`](../bootstrap/) — the wider bootstrap sequence
