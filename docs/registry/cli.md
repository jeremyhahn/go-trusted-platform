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
| `--limit` | `-l` | int | `50` | Maximum number of images to return |
| `--cursor` | | string | `""` | Pagination cursor for the next page |
| `--sort-by` | | string | `name` | Sort field: `name`, `size`, `created`, `pushed` |
| `--sort-desc` | | bool | `false` | Reverse sort order |
| `--show-encrypted` | | bool | `true` | Include encrypted images in the result set |

```bash
platformctl registry list --repository library/alpine --sort-by pushed --sort-desc
```

---

## 3. `platformctl registry push <image-reference>`

Push an image to the registry. Reads the image from `--input` or stdin.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--encrypt` | `-e` | bool | `false` | Encrypt image layers before storage |
| `--key-id` | `-k` | string | `""` | Encryption key ID — **required with `--encrypt`** |
| `--sign` | `-s` | bool | `false` | Sign the image manifest |
| `--signing-key-id` | | string | `""` | Key used for manifest signing; defaults to the tenant signer |
| `--overwrite` | | bool | `false` | Replace an existing tag with the same name |
| `--input` | `-i` | string | `""` | Input file path; reads stdin when unset |

```bash
platformctl registry push registry.example.com/apps/api:1.4.2 \
    --input ./api-1.4.2.tar --encrypt --key-id apps-api-dek --sign
```

Without `--overwrite`, pushing over an existing tag fails with
`ErrImageExists` / HTTP 409.

---

## 4. `platformctl registry pull <image-reference>`

Pull an image. Writes to `--output` or stdout.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--decrypt` | `-d` | bool | `false` | Decrypt encrypted image layers |
| `--verify` | | bool | `false` | Verify the image signature |
| `--platform` | `-p` | string | `""` | Target platform, e.g. `linux/amd64` |
| `--output` | `-o` | string | `""` | Output file path; writes stdout when unset |

```bash
platformctl registry pull registry.example.com/apps/api:1.4.2 \
    --decrypt --verify --platform linux/amd64 --output ./api.tar
```

`--verify` is opt-in, not the default. In an environment where image
provenance matters, pass it — or pull through tooling that always does.

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

With `--output json` the document is `{"manifest": {...}}`, snake_case
throughout: `reference`, `digest`, `media_type`, `schema_version`, `os`,
`architecture`, `config`, `layers`, `annotations`, `signature`, `encryption`,
`created_at` and `pushed_at` (RFC 3339). `os` and `architecture` are the
image's platform and are omitted when the registry has none recorded.

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
