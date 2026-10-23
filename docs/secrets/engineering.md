# Configuration Secret Resolution — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/config/secrets/`, `pkg/bootstrap/`, `pkg/app/secrets*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Package layout

| Path | Holds |
|---|---|
| `pkg/bootstrap/secrets.go` | Scheme and strategy constants, `SecretStructTag`, `IsSecretURI`, `ExpandShortKMSPath` |
| `pkg/bootstrap/secret_fields.go` | `PlaintextSecretFields` — the `secret:"true"` walk that finds tagged fields holding literals; the diskless image build refuses a platform config it reports |
| `pkg/bootstrap/config_writer.go` | `SecretUpdate`, `ConfigWriter` and its atomic YAML rewriting |
| `pkg/config/secrets/idevid_resolver.go` | `IDevIDResolver` |
| `pkg/config/secrets/file_resolver.go` | `FileResolver` |
| `pkg/config/secrets/errors.go` | Ten typed errors shared by both resolvers |
| `pkg/app/secrets.go` | `SecretsConfig`, `SetupSecretResolvers`, `ProcessSecrets`, `tpmDecrypter`, `kmsNotAvailableResolver`, `xkmsKMSClientAdapter` |
| `pkg/app/secrets_resolvers.go` | `DynamicSecretsResolver`, `XKMSSecretsResolver`, `XKMSClient` |
| `pkg/app/secrets_errors.go` | Twenty-one typed errors |
| `pkg/cli/commands/bootstrap/secrets*.go` | The four CLI verbs and their helpers |

**`pkg/bootstrap` is not a resolution engine.** Its package comment states the
contract: *"Package bootstrap provides secret-URI scheme constants and path
utilities used during platform bootstrap. Secret resolution and config walking
are delegated to the unified qrdb-SDK ResolverRegistry / ConfigProcessor."*

## 2. The SPI

Defined in `go-quicbaas/sdk/go/secret`, imported here as `quicbaassecret`. This
repository implements against it and does not own it.

```go
type SecretResolver interface {
    Scheme() string
    CanResolve(raw string) bool
    Resolve(ctx context.Context, raw string) (*SecretValue, error)
}
```

Supporting types used by this repository:

| Symbol | Used for |
|---|---|
| `quicbaassecret.SecretValue` | Resolver return value |
| `quicbaassecret.NewSecretValue(uri, data, strategy)` | Constructing one |
| `quicbaassecret.StrategyLiteral` | The strategy every local resolver reports |
| `quicbaassecret.ResolverRegistry`, `NewResolverRegistry()`, `.Register(r)` | The scheme→resolver map |
| `quicbaassecret.NewConfigProcessor(registry, opts...)`, `.Process(ctx, v)` | The reflective config walk |
| `quicbaassecret.WithFailClosed()` | Always applied |
| `quicbaassecret.ProcessResult{Resolved int; Unresolved []string; Errors []error}` | Walk outcome |

Every local resolver carries a compile-time assertion, e.g.
`var _ quicbaassecret.SecretResolver = (*FileResolver)(nil)`.

## 3. Scheme and strategy constants

`pkg/bootstrap/secrets.go`:

```go
const (
    SchemeKMS        = "kms://"
    SchemeRemoteKMS  = "remote-kms://"
    SchemeEnv        = "env://"
    SchemeIDevID     = "idevid://"
    SchemeFile       = "file://"
    SchemeDynamic    = "dynamic://"
    SchemeXKMS       = "xkms://"
    SchemeCredential = "credential://"
    SchemeAutoGen    = "autogen://"
)

const (
    StrategyKMS, StrategyRemoteKMS, StrategyEnv, StrategyIDevID,
    StrategyFile, StrategyDynamic, StrategyXKMS,
    StrategyLiteral, StrategyPlainText = "kms", "remote-kms", "env", "idevid",
    "file", "dynamic", "xkms", "literal", "plaintext"
)

const SecretStructTag = "secret"

func IsSecretURI(s string) bool
func ExpandShortKMSPath(path, tenantID, nodeID string) string
```

Two things to note:

- **`IsSecretURI` covers all nine schemes**, including `credential://` and
  `autogen://`, which only the go-quicbaas registry resolves. Its consumer,
  `PlaintextSecretFields`, treats any of them as a reference, not a literal.
- **`ExpandShortKMSPath` returns the path unchanged when `tenantID` or `nodeID`
  is empty**, rather than erroring. A short path resolved with an empty tenant
  therefore reaches the store un-namespaced.

Note also that the resolver packages define their own scheme constants with
*different values*: `secrets.SchemeIDevID == "idevid"` (no `://`) alongside
`secrets.SchemeURIPrefix == "idevid://"` and `secrets.SchemePrefix == "idevid:"`;
`secrets.SchemeFile == "file"` alongside `secrets.SchemeFileURIPrefix ==
"file://"`; and `bootstrap` CLI helper `SchemeFile == "file://"`. **Three
symbols named `SchemeFile`/`SchemeIDevID` in three packages with two different
value conventions.** Grep the package before using one.

## 4. Resolvers implemented here

### `IDevIDResolver` — `pkg/config/secrets/idevid_resolver.go`

```go
const (
    SchemeIDevID    = "idevid"
    SchemePrefix    = "idevid:"
    SchemeURIPrefix = "idevid://"
)

type IDevIDResolver struct { /* decrypter crypto.Decrypter; logger *slog.Logger */ }
func NewIDevIDResolver(decrypter crypto.Decrypter, logger *slog.Logger) *IDevIDResolver
func (r *IDevIDResolver) Scheme() string      // "idevid"
func (r *IDevIDResolver) CanResolve(raw string) bool
func (r *IDevIDResolver) Resolve(ctx context.Context, raw string) (*quicbaassecret.SecretValue, error)
```

- Accepts **both** `idevid:<b64>` and `idevid://<b64>`, case-insensitively.
- Tries standard **and** URL-safe base64 automatically.
- RSA-OAEP with SHA-256 via the injected `crypto.Decrypter`.
- Checks the context for cancellation before and after decryption.
- Nil decrypter ⇒ `ErrDecrypterRequired`.

The decrypter in production is `app.tpmDecrypter`, which calls
`tpm.RSADecrypt(handle, name, ciphertext)` on the IDevID key attributes. Its
`Public()` returns `tpm.IDevID()`, and `Decrypt` **ignores the `rand` and
`opts` arguments** — the TPM supplies randomness and the padding is always
RSA-OAEP/SHA-256.

### `FileResolver` — `pkg/config/secrets/file_resolver.go`

```go
const (
    SchemeFile          = "file"
    SchemeFileURIPrefix = "file://"
)

type FileResolver struct { /* logger *slog.Logger */ }
func NewFileResolver(logger *slog.Logger) *FileResolver
func (r *FileResolver) Scheme() string      // "file"
func (r *FileResolver) CanResolve(raw string) bool
func (r *FileResolver) Resolve(ctx context.Context, raw string) (*quicbaassecret.SecretValue, error)
```

- `file:///absolute/path` — the path is `raw[len("file://"):]`, so
  `file:///run/secrets/x` yields `/run/secrets/x`.
- **Read verbatim.** No base64 decoding, no trimming. A trailing newline is part
  of the secret.
- Empty file ⇒ `ErrFileEmpty`. Unreadable ⇒ `ErrFileReadFailed`.
- Safe for concurrent use.

### `DynamicSecretsResolver` — `pkg/app/secrets_resolvers.go`

```go
type DynamicSecretsResolver struct { /* client quicbaassdk.DynamicSecretsClient; logger *slog.Logger */ }
func NewDynamicSecretsResolver(client quicbaassdk.DynamicSecretsClient, logger *slog.Logger) *DynamicSecretsResolver
```

- URI: `dynamic://role-name[/ttl]`, e.g. `dynamic://database-readonly/1h`.
- TTL parsed with `time.ParseDuration`; must be positive.
- Calls `client.GenerateCredential(ctx, &GenerateCredentialRequest{RoleName, TTL})`.
- **Returns `json.Marshal(resp.Credential)` as the secret value** — a document,
  not a bare password.
- Nil client ⇒ `ErrDynamicSecretsNotAvailable`.

### `XKMSSecretsResolver` — `pkg/app/secrets_resolvers.go`

```go
type XKMSClient interface {
    CanSeal(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error)
    Unseal(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error)
    GetKey(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error)
}

type XKMSSecretsResolver struct { /* client XKMSClient; logger *slog.Logger */ }
func NewXKMSSecretsResolver(client XKMSClient, logger *slog.Logger) *XKMSSecretsResolver
```

- URI: `xkms://backend/key-id`; both segments required.
- `CanSeal` true ⇒ `resolveViaUnseal` ⇒ `resp.Plaintext` is the secret.
- `CanSeal` false **or erroring** ⇒ `resolveViaGetKey` ⇒
  `json.Marshal(GetKeyResponse)` is the secret — metadata, not key material.
- Empty plaintext or nil response ⇒ `bootstrap.ErrSecretNotFound{Path: backend + "/" + keyID}`.

**The adapter wired in production makes this resolver inert.**
`xkmsKMSClientAdapter` (`pkg/app/secrets.go`) has `CanSeal` returning
`{CanSeal: false}`, and `Unseal` and `GetKey` both returning
`ErrXKMSNotAvailable`. Its only field is `kms interface{}`. Treat `xkms://` as
not yet functional ([architecture.md](architecture.md) §7).

### `kmsNotAvailableResolver` — `pkg/app/secrets.go`

Unexported, registered only in standalone mode when `cfg.LocalKMS` is set.
`Scheme() == "kms"`, `CanResolve` matches `kms://` case-insensitively, and
`Resolve` **always** returns `ErrSecretsServiceNotAvailableButKMSRequired{URICount: 1}`.
It exists so a `kms://` URI cannot fall through to a literal.

## 5. Registry and processing

```go
func (app *App) SetupSecretResolvers(ctx context.Context, cfg *SecretsConfig) (*quicbaassecret.ResolverRegistry, error)
func (app *App) ProcessSecrets(ctx context.Context, cfg *SecretsConfig) (*quicbaassecret.ProcessResult, error)
func (app *App) Secrets() baasservice.SecretsService
func (app *App) CryptoService() baasservice.CryptoService
```

`SetupSecretResolvers`:
- nil `cfg` ⇒ `ErrNilSecretsConfig`.
- Base registry from `sdkClient.Security().SecretResolver()` when available;
  otherwise a fresh `NewResolverRegistry()` plus the fail-closed KMS stub.
- Additive registration per §4, each guarded and each logging a warning on a
  missing dependency rather than failing.
- **Never returns an error for a missing dependency** — only for nil config.

`ProcessSecrets`:
- nil `cfg` ⇒ `ErrNilSecretsConfig`.
- `!cfg.Enabled` ⇒ `(&ProcessResult{}, nil)` — a no-op success.
- `WithFailClosed()` is **unconditional**.
- On processor error: logs each `result.Unresolved` field name and each
  `result.Errors` entry, then a summary, then returns
  `(result, ErrProcessSecrets{Cause: err})`. **The result is returned alongside
  the error** so the caller can inspect diagnostics.
- On success: logs `resolved` / `unresolved` / `errors` counts and returns
  `(result, nil)`.

`App.Secrets()` and `App.CryptoService()` return nil (with a debug log) when the
datastore backend is not QuicBaaS or the sub-service is disabled.

## 6. Invariants

1. **Resolution is fail-closed, always.** `WithFailClosed()` is not
   configurable. A URI with no resolver, or whose resolver errors, aborts
   startup.
2. **Resolution happens once, at bootstrap, before services start.** After
   `ProcessSecrets` the config struct holds plaintext. Nothing re-resolves.
3. **Ordering is load-bearing**: `initStores()` → `ProvisionSecureBootKeys()` →
   `ProcessSecrets()` → barrier / SDN / `ParsePINs()` / `InitTPM()` / CA init.
   Secure Boot key material is provisioned first because its `kms://` refs carry
   no `?ensure=true` and nothing else creates them.
4. **`cfg.Enabled == false` leaves URIs in place as literal strings.** That is a
   valid configuration only if nothing downstream consumes them as credentials.
5. **A skipped resolver is not a permissive resolver.** Warnings at registry
   assembly become hard failures at walk time.
6. **`file://` bytes are verbatim.** Byte-for-byte, including any trailing
   newline.
7. **`idevid://` cannot be rotated.** The blob is bound to a `FixedTPM` key.
8. **Resolvers are safe for concurrent use.** None holds mutable state.
9. **`ConfigWriter` writes atomically**: temp file in the same directory →
   `Sync` → `Rename`.

## 7. Configuration

```go
type SecretsConfig struct {
    Enabled        bool `yaml:"enabled"`
    LocalKMS       bool `yaml:"local-kms"`
    RemoteKMS      bool `yaml:"remote-kms"`
    Encrypted      bool `yaml:"encrypted"`
    File           bool `yaml:"file"`
    DynamicSecrets bool `yaml:"dynamic-secrets"`
    XKMS           bool `yaml:"xkms"`
}
```

Reached as `App.SecretsConfig`, YAML key `secrets` (`omitempty`), mapstructure
`secrets`.

| Key | Type | `DefaultSecretsConfig()` | Enables |
|---|---|---|---|
| `enabled` | bool | **`false`** | The whole walk |
| `local-kms` | bool | `true` | `kms://` (or the fail-closed stub in standalone mode) |
| `remote-kms` | bool | `false` | `remote-kms://` |
| `encrypted` | bool | `true` | `idevid://` |
| `file` | bool | `false` | `file://` |
| `dynamic-secrets` | bool | `false` | `dynamic://` |
| `xkms` | bool | `false` | `xkms://` (see §4 — inert today) |

**Precedence:** these are plain config-file values; there is no environment
override and no CLI flag for any of them. Verified 2026-08-18.

**Keys that do not exist**, despite appearing in shipped config templates and
in the legacy README: `auto-generate`, `migrate-to-kms`, `update-config-file`.
They are ignored. Generation is per-URI (`?ensure=true`); migration is the
`platformctl bootstrap secrets migrate` verb; config rewriting is that verb's
step 4.

### Query parameters on `kms://`

`?ensure=true&len=N&enc=base64|hex|numeric|raw` are interpreted by the
go-quicbaas resolver's `EnsureSecret`, **not by code in this repository**
(grepped 2026-08-18: no `ensure=` parsing here). Their documented semantics:
`ensure=true` opts into generate-on-first-boot / stable-thereafter; `len` is
bytes for `base64`/`hex`/`raw` and digits for `numeric`; `base64` is
`RawURLEncoding`, so `len=32` yields a **43-character** value and `hex` yields
64. Changing `len` or `enc` on an already-generated secret returns
`ErrSecretSpecMismatch` rather than regenerating.

**Use `enc=raw` for anything that becomes a TPM authorization value** —
`webservice(s)[*].key.password`, `acme.client.account.key.password`,
`tpm.platform-srk.srk-auth`,
`certificate-authority.identity[*].keystores.tpm2.srk-auth`. The trigger is
`platform-policy: true`, not `store:`.

## 8. Error semantics

### `pkg/config/secrets` (both resolvers)

`ErrDecrypterRequired`, `ErrInvalidSecretFormat{Raw, Reason}`,
`ErrBase64DecodeFailed{Reason}`, `ErrDecryptionFailed{Reason}`,
`ErrContextCanceled{Reason}`, `ErrContextDeadlineExceeded{Reason}`,
`ErrEmptyCiphertext`, `ErrUnsupportedKeyType{KeyType}`,
`ErrInvalidFileURI{Raw, Reason}`, `ErrFileReadFailed{Path, Cause}` (unwraps),
`ErrFileEmpty{Path}`.

### `pkg/app`

`ErrNilSecretsConfig`, `ErrSetupSecretResolvers{Cause}` (unwraps),
`ErrSecretsServiceNotAvailableButKMSRequired{URICount}`,
`ErrProcessSecrets{Cause}` (unwraps), `ErrTPMNotAvailable`,
`ErrIDevIDNotConfigured`, `ErrPlatformKSNotAvailable`,
`ErrGetIDevIDAttrs{Cause}`, `ErrGetDecrypter{Cause}`,
`ErrContextCanceled{Cause}`, `ErrKMSNotAvailable`, `ErrInvalidKMSURI`,
`ErrKMSGetFailed`, `ErrKMSStoreFailed`, `ErrSecretsServiceNotAvailable`,
`ErrSecretsGetFailed`, `ErrSecretsStoreFailed`,
`ErrDynamicSecretsNotAvailable`, `ErrInvalidDynamicURI{URI, Reason}`,
`ErrDynamicSecretGenerateFailed{RoleName, Cause}`, `ErrXKMSNotAvailable`,
`ErrInvalidXKMSURI{URI, Reason}`, `ErrXKMSUnsealFailed{Backend, KeyID, Cause}`,
`ErrXKMSGetKeyFailed{Backend, KeyID, Cause}`.

### CLI (`pkg/cli/commands/bootstrap/errors.go`)

`ErrConfigPathRequired`, `ErrConfigFileReadFailed{Path, Err}`,
`ErrSecretURIRequired`, `ErrInvalidSecretURI{URI, Reason}`,
`ErrSecretResolutionFailed{URI, Err}`, `ErrMigrationFailed{Err}`,
`ErrSecretVerificationFailed{FailedCount, TotalCount}`,
`ErrBackupCreationFailed{Path, Err}`, `ErrConfigUpdateFailed{Path, Err}`,
`ErrResolverNotAvailable{Scheme}`, `ErrKMSClientRequired`,
`ErrSecretsNotImplemented`, `ErrEnvVarNotSet{Name}`,
`ErrFileReadFailed{Path, Err}`, `ErrAlreadyKMSManaged{Path}`,
`ErrKMSStoreFailed{Path, ...}`.

### Fail-closed paths

- The config walk (`WithFailClosed`, unconditional).
- `kms://` with no reachable secrets service
  (`ErrSecretsServiceNotAvailableButKMSRequired`).
- `file://` on an empty or unreadable file.
- `idevid://` with no decrypter, bad base64, or failed decryption.
- `dynamic://` with a nil client, empty role, or unparsable/non-positive TTL.
- `xkms://` with a nil client or a malformed URI.
- Startup: `app.go` returns a `WrappedError{Msg: "bootstrap secret resolution"}`
  and refuses to start when the walk fails, and a `MessageError` naming the
  count when `result.Errors` is non-empty.

### Fail-open paths

- **`cfg.Enabled == false`** — URIs stay as literal strings. This is the
  default (`DefaultSecretsConfig`).
- **`ExpandShortKMSPath` with an empty tenant or node id** returns the path
  unchanged instead of erroring.
- **`xkms://` fallback to `GetKey`** returns metadata JSON as if it were a
  secret. A field assigned that value gets a document, not a credential.

## 9. Persistence

This feature persists nothing of its own. Two files it touches:

- **The config file**, only via `platformctl bootstrap secrets migrate`.
  `ConfigWriter.Backup()` writes a sibling backup and returns its path;
  `UpdateSecretReferences([]SecretUpdate{Path, KMSReference, OriginalValue})`
  rewrites YAML nodes by dotted path (`applyUpdate` / `navigateToNode`);
  `atomicWrite` does temp → sync → rename; `Restore(backupPath)` rolls back.
  `DryRun(updates)` returns what would change without writing.
- **Files named by `file://`** are read, never written.

Migration maps a dotted config path to a KMS path as
`config/<path with '.'→'/', '['→'/', ']' removed>`, e.g.
`kms.backends.tpm2.srk-auth` → `config/kms/backends/tpm2/srk-auth`.

## 10. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit — resolvers | `pkg/config/secrets/{idevid,file}_resolver_test.go` | Both URI forms, both base64 alphabets, context cancellation, empty/unreadable files, nil decrypter |
| Unit — errors | `pkg/config/secrets/errors_test.go` | Every message and unwrap |
| Unit — registry | `pkg/app/secrets_test.go`, `secrets_resolvers_test.go`, `app_test.go` | `DefaultSecretsConfig`, nil-config guards, per-flag registration, `dynamic://` and `xkms://` paths, `ProcessSecrets` enabled/disabled |
| Unit — writer | `pkg/bootstrap/config_writer_test.go` | Backup, restore, dry run, atomic write, path navigation |
| CLI | **none** — there is no `secrets*_test.go` under `pkg/cli/commands/bootstrap/` (globbed 2026-08-18). The four verbs, their flag binding, `detectScheme`, `maskSecretURI` and `maskValue` are untested. |

Fault-injection seams:
- `quicbaassecret.SecretResolver` — register a failing resolver.
- `crypto.Decrypter` — substitute for `IDevIDResolver` without a TPM.
- `XKMSClient` — three methods, trivial to fake; this is the seam the production
  adapter currently stubs out.
- `quicbaassdk.DynamicSecretsClient` — for `dynamic://`.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, including the four
`bootstrap secrets` verbs.

## 11. Observability

| Event | Level | Source |
|---|---|---|
| `processing secrets in configuration` | info | `ProcessSecrets` |
| `secrets processing complete` + `resolved`/`unresolved`/`errors` counts | info | `ProcessSecrets` |
| `secret reference unresolved` + `field` | **error, one per field** | `ProcessSecrets` failure path |
| `secret resolution error` + `error` | error | `ProcessSecrets` failure path |
| `secrets processing failed` + counts | error | `ProcessSecrets` failure path |
| `kms:// resolver requested but QuicBaaS not available; kms:// URIs will fail-closed` | warn | standalone registry assembly |
| `idevid resolver enabled but IDevID decrypter not available` / `... IDevID is not configured` | warn | registry assembly |
| `dynamic-secrets resolver enabled but ...` / `xkms resolver enabled but ...` | warn | registry assembly |
| `using quicbaas unified secret resolver registry` / `built standalone secret resolver registry` / `registered <x> resolver` | debug | registry assembly |
| `file secret read failed` + `path` | error | `FileResolver` |
| `resolved file secret` / `resolved secret via XKMS unseal` / `... GetKey` / `generated dynamic credential` + `length` | debug | resolvers |

The per-field `secret reference unresolved` logging exists because the
fail-closed sentinel is generic: without it an operator sees only *"unresolved
secret reference remains"* with no way to tell which of dozens of `kms://`
references blocked startup.

**Field paths and byte lengths are logged. Values never are.** Keep it that way.
There are **no metrics** for resolution counts, latency or failures.

## 12. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- Legacy in this folder, still useful:
  `config-secret-schemes.md` (scheme reference, accurate). The legacy
  `bootstrap-secrets.md`, `provisioning-secrets.md` and `README.md` are
  deleted; these five files hold their content, and
  [architecture.md](architecture.md) §8 lists what they got wrong.
- [`docs/kms/`](../kms/) · [`docs/tpm/`](../tpm/) · [`docs/provisioning/`](../provisioning/) · [`docs/bootstrap/`](../bootstrap/)
