# Trusted Registry — CLI

> **Status: NORMATIVE** · Scope: `platformctl registry` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Every verb and every flag below was read out of `pkg/cli/commands/registry/`
> on 2026-08-18.

---

## 1. Command group

```
platformctl registry    Trusted Registry operations
```

Seven verbs: `list`, `push`, `pull`, `inspect`, `delete`, `status`, and the
group itself.

### Global flags

These are `platformctl` persistent flags (`pkg/cli/commands/root.go:125`) and
apply to every verb below. Precedence is **flag > environment > config file >
built-in default**.

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

**`-v` is always `--verbose`.** `registry pull --verify` has no short form.
Prefer the long forms in scripts.

**Which verbs work without a server.** All seven are client verbs: they need a
reachable `platformd` on the selected transport. `--transport embedded` runs the
services in-process and is the only way to use them with no daemon listening.

---

## 2. `platformctl registry list`

List images in the registry.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--repository` | `-r` | string | `""` | Filter by repository name |
| `--prefix` | `-p` | string | `""` | Filter by repository or tag prefix |
| `--limit` | `-l` | int32 | `50` | Maximum number of images to return |
| `--cursor` | | string | `""` | Pagination cursor for the next page |
| `--sort-by` | | string | `name` | Sort field: `name`, `size`, `created`, `pushed` |
| `--sort-desc` | | bool | `false` | Reverse sort order |
| `--show-encrypted` | | bool | `true` | Include encrypted images in the result set |

```bash
platformctl registry list --repository library/alpine --sort-by pushed --sort-desc
```

`--repository` names one repository exactly and is applied by the registry.
`--prefix` and `--show-encrypted` are applied client-side to the page the
registry returned, because the list request on the wire has no field for them:
`--prefix` matches the start of the reference, or of the tag when
`--repository` is set, and `--show-encrypted=false` drops images whose manifest
carries `org.letstrust.registry.encrypted: "true"`. `Total Count` drops by the
number of images filtered out of the page. `ENCRYPTED` and `SIGNED` are read
from the stored manifest's `org.letstrust.registry.encrypted` and
`org.letstrust.registry.signature` annotations. Each image's `DIGEST` is the
SHA-256 of the manifest bytes `GET /v2/<name>/manifests/<tag>` serves, the same
digest on every transport.

---

## 3. `platformctl registry push <image-reference>`

Push an image to the registry. Reads the image from `--input` or stdin.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--encrypt` | `-e` | bool | `false` | Encrypt image layers before storage |
| `--key-id` | `-k` | string | `""` | Encryption key ID — **required with `--encrypt`** |
| `--sign` | `-s` | bool | `false` | Sign the image manifest |
| `--signing-key-id` | | string | `""` | Key used for manifest signing; defaults to `registry-default-signer`. A key ID the registry does not hold yet is created on first use |
| `--overwrite` | | bool | `false` | Replace an existing tag with the same name |
| `--input` | `-i` | string | `""` | Input file path; reads stdin when unset |

```bash
platformctl registry push registry.example.com/apps/api:1.4.2 \
    --input ./api-1.4.2.tar --encrypt --key-id apps-api-dek --sign
```

Without `--overwrite`, pushing over an existing tag fails with
`ErrImageExists` / HTTP 409.

Each push flag reaches the registry as a push-metadata annotation
(`sdk/go/services/registry`): `encrypt`, `key-id`, `sign`, `signing-key-id` and
`overwrite`; the REST push carries the same options as the
`X-Trusted-Platform-Encrypt`, `-Key-Id`, `-Sign`, `-Signing-Key-Id` and
`-Overwrite` headers. The `Encrypted` and `Key ID` the command prints are read
from the manifest the registry stored, not echoed from the flags. A registry
with no manifest signer refuses `--sign` with `ErrSigningNotConfigured` rather
than store the image unsigned. The daemon's registry signs with ECDSA P-256
keys held in a PKCS#8 key store under `<PlatformDir>/registry/signing-keys`;
the signature, key ID and algorithm (`ECDSA-P256-SHA256`) are stored as the
`org.letstrust.registry.signature`, `.signing-key-id` and
`.signature-algorithm` manifest annotations. Signature annotations a client
sends are dropped. The signature covers the reference, schema, media type,
config, layers and every other annotation. Every pull of a signed manifest
verifies it and fails with `ErrSignatureInvalid` if it does not match.

---

## 4. `platformctl registry pull <image-reference>`

Pull an image. Writes to `--output` or stdout.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--decrypt` | `-d` | bool | `false` | Decrypt encrypted image layers |
| `--verify` | | bool | `false` | Refuse an image whose manifest carries no signature |
| `--platform` | `-p` | string | `""` | Target platform, e.g. `linux/amd64` |
| `--output` | `-o` | string | `""` | Output file path; writes stdout when unset |

```bash
platformctl registry pull registry.example.com/apps/api:1.4.2 \
    --decrypt --verify --platform linux/amd64 --output ./api.tar
```

`--verify` is opt-in, not the default. In an environment where image
provenance matters, pass it — or pull through tooling that always does.

The registry verifies the signature of every signed manifest on every pull,
with or without `--verify` (§3), so a signed image that reaches the client has
a signature that matched. Every pull also rehashes each layer and the config
against the digests the manifest names, so blob bytes replaced in storage fail
the pull with `ErrDigestMismatch`. `--verify` adds the other half: it refuses an image
whose pulled manifest carries no `org.letstrust.registry.signature`
annotation, failing with `ErrImageNotSigned` before any image byte is written.
The check is made client-side because the pull request on the wire
(`PullRequest` in `pkg/api/grpc/proto/registry.proto`) has no field to ask the
server for it.

---

## 5. `platformctl registry inspect <image-reference>`

Inspect an image manifest.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--layers` | bool | `false` | Show detailed layer information |
| `--signature` | bool | `false` | Show signature details |
| `--encryption` | bool | `false` | Show encryption details |
| `--raw` | bool | `false` | Print the unmodified manifest JSON document |

```bash
platformctl registry inspect registry.example.com/apps/api:1.4.2 --layers --encryption
```

`--raw` bypasses the rendering path entirely — use it when you need the exact
bytes the registry stored, for example to compare digests by hand.

---

## 6. `platformctl registry delete <image-reference>`

Delete an image from the registry.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--force` | `-f` | bool | `false` | Skip the confirmation prompt |
| `--dry-run` | | bool | `false` | Show what would be deleted without deleting |
| `--keep-untagged` | | bool | `false` | Remove the tag but retain the underlying image manifest |

```bash
platformctl registry delete registry.example.com/apps/api:1.4.1 --dry-run
platformctl registry delete registry.example.com/apps/api:1.4.1 --force --keep-untagged
```

Run `--dry-run` first on anything shared. `--keep-untagged` is the safe form:
it detaches the tag and leaves the manifest addressable by digest.

There is no flag for layers: every delete reclaims the layer and config blobs
that no surviving manifest references, and keeps the ones another image still
uses.

---

## 7. `platformctl registry status`

Show registry status.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--metrics` | bool | `false` | Show performance metrics |
| `--storage` | bool | `false` | Show detailed storage information |
| `--attestation` | bool | `false` | Show attestation configuration |
| `--encryption` | bool | `false` | Show encryption configuration |

```bash
platformctl registry status --attestation --encryption
```

`--attestation` is the fastest way to confirm that a deployed registry actually
has its gate on — it prints the effective `require_attestation`, the golden PCR
set, the AIK allowlist and the quote freshness bound.

With `-o json` (or `yaml`) the output is one object under a `status` key:
`healthy`, `version`, `endpoint`, `uptime_seconds`, and the nested `storage`
(`backend`, `healthy`, `used_bytes`, `total_bytes`, `image_count`,
`layer_count`, `blob_count`), `attestation` (`enabled`, `required`,
`policy_healthy`, ...), `encryption` (`enabled`, ...) and, with `--metrics`,
`metrics` objects. A section the server does not report is `null`.

---

## 8. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on
failure, with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface.

---

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so that
requirement is unmet — repo-wide, not only for the registry. It is raised as an
owner question in the migration report rather than quietly marked satisfied.
