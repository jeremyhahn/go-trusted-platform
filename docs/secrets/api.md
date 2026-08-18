# Configuration Secret Resolution — API

> **Status: NORMATIVE** · Scope: `pkg/config/secrets/`, `pkg/bootstrap/`, `pkg/app/secrets*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. This feature has no remote API

Secret resolution is a **bootstrap-internal** operation. It runs once inside
`platformd`, before services start, against the process's own in-memory
configuration struct. There is no `SecretResolutionService` on gRPC, no
`/api/v1/secrets/*` route group, no QUIC opcode, and no MCP tool. Verified
2026-08-18.

Two reasons, both deliberate:

1. **The operand is this process's config.** A remote caller has nothing
   meaningful to point it at.
2. **The output is plaintext credentials.** An endpoint that resolves an
   arbitrary URI and returns the result is an oracle. The one place that shape
   exists — `platformctl bootstrap secrets resolve` — is local, masks by
   default, and can only resolve `env://` ([cli.md](cli.md) §6).

The **secret store** the `kms://` scheme reads does have a full API. It is
go-quicbaas's, re-exported by this repository as the KMS surface, and documented
in [`docs/kms/api.md`](../kms/api.md) — not here.

---

## 2. Capabilities

| Capability | Embedded (Go) | Unix | gRPC | REST | QUIC | MCP |
|---|---|---|---|---|---|---|
| Build a resolver registry | `App.SetupSecretResolvers(ctx, *SecretsConfig)` | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design |
| Resolve all secret URIs in the running config | `App.ProcessSecrets(ctx, *SecretsConfig)` | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design | `MISSING` — by design |
| Resolve a single URI | `registry.Resolve` / a resolver's `Resolve(ctx, raw)` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Classify a string as a secret URI | `bootstrap.IsSecretURI(s)` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Expand a short `kms://` path | `bootstrap.ExpandShortKMSPath(path, tenantID, nodeID)` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Back up / rewrite / restore a config file | `bootstrap.ConfigWriter` (`Backup`, `UpdateSecretReferences`, `DryRun`, `Restore`) | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Migrate config secrets into the KMS | `MISSING` — CLI only | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| Report secret-resolution status for a config file | `MISSING` — CLI only | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| **Store / fetch / rotate a secret** | not this feature | not this feature | not this feature | not this feature | not this feature | not this feature |

**`MISSING` — by design** is not a `docs/13` gap. Exposing config-secret
resolution over a transport would create a credential oracle; the absence is the
control. If a future requirement needs remote visibility, the right shape is a
*status* endpoint that reports field paths and resolution outcomes without
values — which does not exist today either.

**not this feature**: the secret store's CRUD lives on the KMS surface
([`docs/kms/api.md`](../kms/api.md)) and on the platform-wide QUIC
`OpSecretsCategory` (`0xCE`) documented in
[`docs/daemon/api.md`](../daemon/api.md) §4.

---

## 3. The SPI, for implementers

The one interface a new secret source must satisfy. It is a **go-quicbaas
type** (`go-quicbaas/sdk/go/secret`), not ours:

```go
type SecretResolver interface {
    Scheme() string
    CanResolve(raw string) bool
    Resolve(ctx context.Context, raw string) (*SecretValue, error)
}
```

Contract for an implementation in this repository:

| Requirement | Why |
|---|---|
| `Scheme()` returns the bare scheme name (`"file"`, `"idevid"`), not the `://` form | Matches the existing resolvers; the registry keys on it |
| `CanResolve` is case-insensitive and returns `false` for `""` | Config values arrive with whatever casing the operator typed |
| `Resolve` checks `ctx` before doing work | Config walks can be long; callers abort them |
| `Resolve` returns a typed error, never a partial value | The processor is fail-closed and needs a definite outcome |
| `Resolve` returns `quicbaassecret.NewSecretValue(uri, data, quicbaassecret.StrategyLiteral)` | The strategy every local resolver reports |
| Safe for concurrent use | The walk may parallelise |
| A compile-time assertion `var _ quicbaassecret.SecretResolver = (*T)(nil)` | Catches signature drift at build time |
| Never log the resolved value | Log the URI, the path, and the byte length |

Register it in `App.SetupSecretResolvers` behind a `SecretsConfig` flag, and
**skip registration with a warning when its dependency is absent** — never
register a resolver that silently returns nothing, because the fail-closed
processor is what turns a missing resolver into a visible startup failure.

---

## 4. Recognised schemes

| Scheme | Resolver | Owner |
|---|---|---|
| `kms://` | go-quicbaas registry, or `kmsNotAvailableResolver` (fail-closed stub) in standalone mode | go-quicbaas / this repo |
| `remote-kms://` | go-quicbaas registry | go-quicbaas |
| `env://` | go-quicbaas registry (constant declared here; **no resolver in this repo**) | go-quicbaas |
| `idevid://`, `idevid:` | `secrets.IDevIDResolver` | this repo |
| `file://` | `secrets.FileResolver` | this repo |
| `dynamic://` | `app.DynamicSecretsResolver` | this repo |
| `xkms://` | `app.XKMSSecretsResolver` — **inert today**, see [architecture.md](architecture.md) §7 | this repo |
| `autogen://` | go-quicbaas registry — **not in `bootstrap.IsSecretURI`** | go-quicbaas |
| `credential://` | go-quicbaas registry — **not in `bootstrap.IsSecretURI`** | go-quicbaas |

---

## 5. Error mapping

Because there is no transport, there is no status-code mapping. Resolution
errors surface as **startup failure**:

| Failure | Surface |
|---|---|
| nil `SecretsConfig` | `ErrNilSecretsConfig` from `SetupSecretResolvers` / `ProcessSecrets` |
| Registry assembly failed | `ErrSetupSecretResolvers{Cause}` |
| Any URI unresolved (fail-closed) | `ErrProcessSecrets{Cause}`, plus a populated `*ProcessResult` |
| `kms://` with no reachable secrets service | `ErrSecretsServiceNotAvailableButKMSRequired{URICount}` |
| Startup, from `pkg/app/app.go` | `WrappedError{Msg: "bootstrap secret resolution", Err: ...}`, or a `MessageError` naming the failed-field count |

The full typed-error inventory is in [engineering.md](engineering.md) §8.

---

## 6. Versioning and deprecation

There is no wire format to version. The one **removed** mechanism, recorded so
nobody reintroduces it: the platform-wide AES-256-GCM config-encryption scheme,
which used a single wrapping key shared by every node. Its blast radius was
every secret on every node. Use `kms://` or `idevid://`.

---

## 7. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/kms/api.md`](../kms/api.md) — the secret store's actual API
- [`docs/daemon/api.md`](../daemon/api.md) — transports and the `0xCE` secrets category
