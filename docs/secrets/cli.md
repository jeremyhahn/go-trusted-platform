# Configuration Secret Resolution — CLI

> **Status: NORMATIVE** · Scope: `pkg/cli/commands/bootstrap/secrets*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and flag below was read out of `pkg/cli/commands/bootstrap/` on
> 2026-08-18.

---

## 1. Command group

```
platformctl bootstrap secrets    Manage bootstrap secrets
```

Four verbs: `migrate`, `status`, `verify`, `resolve`.

**Runtime resolution has no CLI.** The bootstrap walk happens inside `platformd`
when `secrets.enabled` is true. These four verbs are operator tooling *around*
that walk: they inspect a config file, migrate values into the KMS, and let you
test a single URI.

### Global flags

The `platformctl` persistent flags (`pkg/cli/commands/root.go`) apply.
Precedence is **flag > environment > config file > built-in default**.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**`--config` and the verbs' own `--config` are different flags.** `migrate`,
`status` and `verify` each declare a local `--config` marking the *file to
operate on*, and each marks it required. Cobra resolves the local flag first.

**Which verbs work without a server.** `migrate` needs a reachable daemon — it
builds a KMS client (`kmssvc.NewClientFromGRPC(base.Client().KMS())`) to encrypt
values. `status` is a pure text scan of a file. `resolve` and `verify` construct
a base command (and therefore a client) but only actually resolve `env://`
(§6).

---

## 2. `platformctl bootstrap secrets status`

Show what secret URIs a configuration file contains, and whether a resolver is
expected to be available for each.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--config` | string | `""` | **yes** | Path to the configuration file |
| `--show-uris` | bool | `false` | no | Show masked secret URIs |

```bash
platformctl bootstrap secrets status --config /etc/trusted-platform/config.yaml
platformctl bootstrap secrets status --config /etc/trusted-platform/config.yaml --show-uris
```

`--show-uris` prints **masked** URIs: the scheme plus the first two path
segments, then `/***` (e.g. `kms://tenants/acme/***`). Nothing prints a
resolved value.

**Availability is asserted, not measured.** `isResolverAvailable` hard-codes
`true` for `kms`, `env`, `autogen`, `remote-kms` and `encrypted`, `false`
otherwise, with the comment *"In a real implementation, this would check the
resolver registry."* Read the column as "this scheme is known", not "this node
can resolve it".

---

## 3. `platformctl bootstrap secrets verify`

Check that the secrets in a configuration file can be resolved.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--config` | string | `""` | **yes** | Path to the configuration file |
| `--dry-run` | bool | `false` | no | Check resolver availability without resolving |
| `--fail-fast` | bool | `false` | no | Stop verification on the first failure |
| `--show-secrets` | bool | `false` | no | Show resolved secret values |

```bash
platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml
platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml --dry-run
platformctl bootstrap secrets verify --config /etc/trusted-platform/config.yaml --fail-fast
```

**`--show-secrets` prints plaintext to your terminal.** It exists for
debugging. Do not use it on a shared or recorded session.

**A clean `verify` does not mean the node will boot.** See §6 — this verb
resolves `env://` only.

---

## 4. `platformctl bootstrap secrets resolve <uri>`

Resolve one secret URI and print the result. Exactly one positional argument
(`cobra.ExactArgs(1)`).

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--masked` | bool | `true` | no | Mask the resolved value |
| `--raw` | bool | `false` | no | Show the full resolved value |

`--raw` wins: the value is masked only when `masked && !raw`.

```bash
platformctl bootstrap secrets resolve "env://DATABASE_PASSWORD"
platformctl bootstrap secrets resolve "env://DATABASE_PASSWORD" --raw
```

Text output prints `URI` (masked), `Scheme`, `Length` in bytes, and `Value`,
plus a hint to use `--raw`. `--output json` / `--output yaml` emit
`{uri, scheme, resolved, value, length, masked}`.

**Masking keeps the first two and last two characters** for values longer than
four (`ab****yz`); four or fewer become `****`; empty becomes `(empty)`. That
leaks a little — enough to spot a transcription error, and more than nothing.

Failure modes:

| Situation | Error |
|---|---|
| Empty URI | `ErrSecretURIRequired` |
| Scheme not one of `kms://`, `remote-kms://`, `env://`, `idevid://` | `ErrInvalidSecretURI` — *"unknown or missing scheme (expected kms://, env://, remote-kms://, or idevid://)"* |
| Scheme known but not in the availability list | `ErrResolverNotAvailable{Scheme}` |
| Resolution failed | `ErrSecretResolutionFailed{URI (masked), Err}` |

---

## 5. `platformctl bootstrap secrets migrate`

Move secrets out of environment variables and files into the KMS, and rewrite
the configuration file to `kms://` references.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--config` | string | `""` | **yes** | Path to the configuration file |
| `--dry-run` | bool | `false` | no | Preview changes without modifying files |
| `--no-backup` | bool | `false` | no | Skip creating a backup of the original configuration |
| `--force` | bool | `false` | no | Continue even if some secrets fail to resolve or store |
| `--key-id` | string | `config-secrets` | no | KMS key ID used to encrypt migrated secrets |

```bash
# Always do this first.
platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --dry-run

# Then the real thing, with a backup.
platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml

# Under a specific KMS key.
platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --key-id platform-config
```

### What it does, in order

1. **Scan** the YAML text for `kms://`, `remote-kms://`, `env://`, `idevid://`
   (regex plus an indentation-aware nested scan), then separately for `file://`.
2. **Resolve** each — `env://` and `file://` only; see §6.
3. **Store** each resolved value with `kmsClient.EncryptDomain(ctx, keyID,
   value, []byte(kmsPath), nil)`.
4. **Back up** the config file unless `--no-backup`.
5. **Rewrite** the YAML nodes to `kms://config/<dotted.path.with.slashes>`,
   atomically. **If the rewrite fails and a backup exists, it is restored.**
6. **Verify** by re-encrypting a probe value under each new path.
7. **Summarise**: total, resolved, stored, verified, skipped-already-KMS,
   failed, plus the backup path.

`kms.backends.tpm2.srk-auth` becomes `kms://config/kms/backends/tpm2/srk-auth`.

Already-`kms://` entries are skipped and reported as `SKIP (already
KMS-managed)`.

Without `--force`, a resolution failure aborts before anything is written, and a
store failure aborts before the config is rewritten. **`--force` continues past
both.** Verification failures always surface as `ErrSecretVerificationFailed`
at the end, `--force` or not.

**Step 7's verification does not prove your secret round-trips.** It encrypts
the literal string `verification-test` under each new path to confirm the key is
usable. It does not decrypt what you stored.

---

## 6. What these verbs can actually resolve

This is the thing to know before trusting a green `verify`.

| Scheme | `resolve` / `verify` | `migrate` |
|---|---|---|
| `env://` | **resolves** | **resolves** |
| `file://` | not a recognised scheme (`unknown or missing scheme`) | **resolves** |
| `kms://` | `ErrSecretsNotImplemented` | skipped — already KMS-managed |
| `remote-kms://` | `ErrResolverNotAvailable` | `ErrResolverNotAvailable` |
| `idevid://` | `ErrResolverNotAvailable` | `ErrResolverNotAvailable` |
| `dynamic://` | unknown scheme | unknown scheme |
| `xkms://` | unknown scheme | unknown scheme |

The `kms://` message is explicit about the intent:

```
secrets service is not yet implemented in the platform KMS; use env:// for
environment variables or kms://...?ensure=true for persistent auto-generation
```

`remote-kms://` and `idevid://` cannot work from the CLI: one needs a remote
client, the other needs the node's TPM.

**`platformd` resolves all seven schemes** through the go-quicbaas registry at
bootstrap ([engineering.md](engineering.md) §4–5). The CLI's resolution path is
a separate, much smaller implementation. Do not read one as a proxy for the
other.

---

## 7. Exit codes and output

`0` on success, non-zero on failure, with the typed error rendered.
`--output json` / `--output yaml` are honoured by `resolve`, by `migrate
--dry-run`, and by the migrate summary; `table` is the default and its columns
are not a stable interface. Parse JSON.

---

## 8. Recorded gaps

1. **The CLI resolvers are a parallel, smaller implementation** than the one
   `platformd` uses, and they disagree about which schemes exist. Recorded, not
   resolved here.
2. **`isResolverAvailable` is hard-coded**, by its own admission.
3. **No tests.** There is no `secrets*_test.go` under
   `pkg/cli/commands/bootstrap/` (globbed 2026-08-18).
4. **CLI parity suite.** Every verb here should have a matching
   `CommandDefinition`. **This repository defines no `CommandDefinition` type**
   (grepped repo-wide, 2026-08-18), so the requirement is unmet repo-wide.

---

## 9. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/cli.md`](../daemon/cli.md) §2 — the persistent flag set
- [`docs/kms/cli.md`](../kms/cli.md) — the KMS verbs migration writes into
