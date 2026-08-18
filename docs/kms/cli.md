# Key Management — CLI

> **Status: NORMATIVE** · Scope: `platformctl kms` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/kms/` on 2026-08-18.

---

## 1. Read this before anything else

`platformctl kms` declares **107 `Use:` entries**, and **36 of those
declarations across eight non-test files carry "(not yet implemented)"**. The
commands exist, parse their flags, and then return a typed error.

Section 4 lists exactly which. Do not assume a verb works because it appears in
`--help`.

---

## 2. Command group

```
platformctl kms
    key         Manage cryptographic keys
    crypto      Cryptographic operations
    hmac        HMAC operations
    datakey     Data encryption key operations         [NOT IMPLEMENTED]
    secrets     Secrets management operations          [NOT IMPLEMENTED]
    safety      Manage AEAD safety limits
    hash        Compute a cryptographic hash
    random      Generate random bytes
    algorithms  List supported algorithms
```

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

---

## 3. What works

### `kms key`

| Verb | Argument | Status |
|---|---|---|
| `generate` | `<key-id>` | works |
| `get` | `<key-id>` | works |
| `list` | — | works |
| `delete` | `<key-id>` | works |
| `rotate` | `<key-id>` | works |
| `export` | `<key-id>` | **not implemented** |

```bash
platformctl kms key generate tenant-a-dek
platformctl kms key list --output json
platformctl kms key rotate tenant-a-dek
```

**Rotation rewraps; it does not re-encrypt your data.** That is why it is cheap
and why you should do it on a schedule.

### `kms crypto`

Encrypt, decrypt, sign, verify and the `rewrap` verb ("re-encrypt data with
latest key version").

### `kms hmac`

`generate` and `verify`.

**`kms hash` is unkeyed; `kms hmac` is keyed.** If you need to prove a message
came from someone holding a key, you need `hmac`. A hash proves only integrity
against accidental change.

### `kms hash`, `kms random`, `kms algorithms`

Compute a hash, generate random bytes, list supported algorithms. All work.

### `kms safety` — and nothing else can do this

| Verb | Argument | Purpose |
|---|---|---|
| `set` | `<key-id>` | Set AEAD safety limits for a key |
| `get` | `<key-id>` | Get AEAD safety stats |
| `clear` | `<key-id>` | Clear custom limits |
| `check` | — | Check for keys approaching their limits |
| `report` | — | Comprehensive safety report |

**This subtree exists only on the CLI.** There is no gRPC RPC, REST route, QUIC
opcode or MCP tool for AEAD safety limits.

AES-GCM has a bound on how many times a key may be used before nonce reuse
becomes probable, and crossing it is a break rather than a degradation. `check`
and `report` are the only way to see how close a fleet is:

```bash
platformctl kms safety check
platformctl kms safety report
platformctl kms safety get tenant-a-dek
```

Because there is no API equivalent, this cannot currently be monitored
programmatically — recorded in [api.md](api.md) §5.

---

## 4. What does not work

Eight non-test files return typed "not implemented" errors. The commands parse
and refuse.

| Command path | Error type |
|---|---|
| `kms secrets store\|get\|list\|delete\|rotate\|version\|versions\|rollback\|status` | `ErrSecretsNotImplemented` |
| `kms secrets policy get\|set` | `ErrSecretsNotImplemented` |
| `kms secrets prefix list`, `kms secrets watch` | `ErrSecretsNotImplemented` |
| `kms datakey generate\|wrapped\|rewrap` | `ErrDEKNotImplemented` |
| `kms key export` | `ErrKeyExportNotImplemented` |
| `kms key import` | `ErrKeyImportNotImplemented` |
| `kms key versions` | `ErrKeyVersionsNotImplemented` |
| `kms key status` | `ErrKeyStatusNotImplemented` |
| `kms key unwrap` | `ErrKeyUnwrapNotImplemented` |
| `kms key test-backend` | `ErrBackendTestNotImplemented` |

`ErrSecretsNotImplemented.Error()` reads *"secrets management is not yet
implemented in the platform KMS service"*. The command's own long help suggests
using `kms crypto encrypt` / `decrypt` to manage encrypted secrets by hand in the
meantime.

### The API is ahead of the CLI here

**REST does have the secrets surface** — `POST /api/v1/kms/secrets`,
`GET /api/v1/kms/secrets/{name}`, versions, rotate, rollback, status and
rotation policy are all registered
(`pkg/webservice/v1/rest/kms/router.go`). Likewise DEK management is on REST and
QUIC.

So the workaround is not "wait for the feature" — it is "use REST":

```bash
curl -s -X POST https://platform.example.com/api/v1/kms/secrets \
     -d '{"name":"api-token","value":"..."}'
curl -s https://platform.example.com/api/v1/kms/secrets/api-token
```

---

## 5. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18).

For KMS the requirement would be actively misleading if satisfied naively: 36 of
the 107 verb declarations are stubs, and a parity suite that asserted they exist
would be asserting the wrong thing. The stubs do have their own tests, which
assert the refusal — that is the correct shape and it is what stops them
silently half-working.

Raised as an owner question in the migration report.
