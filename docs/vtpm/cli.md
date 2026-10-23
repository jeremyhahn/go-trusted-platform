# Virtual TPM — CLI

> **Status: NORMATIVE** · Scope: `platformctl vtpm` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/vtpm/` on 2026-08-18.

---

## 1. Command group

```
platformctl vtpm             vTPM bundle management operations
platformctl vtpm template    Manage vTPM templates
platformctl vtpm pcr         PCR (Platform Configuration Register) operations
```

**Almost every verb takes `--bundle-id`, not a positional argument** — the
exceptions are `info`, `delete`, `export` and `import`, which take a positional
`[bundle-id]` or `[archive-path]`. Mixing the two up is the most common mistake
here.

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

**`vtpm export` rebinds `-o` to `--output` as a *file path*** while the root
binds `-o` to `--output` as a *format*. Cobra resolves the local flag first, so
inside `vtpm export`, `-o` means the archive path. Use long forms.

---

## 2. Bundles

| Verb | Argument | Purpose |
|---|---|---|
| `create` | `--bundle-id` | Create a **pre-assigned** vTPM bundle |
| `clone` | `--template` | Clone a bundle from a template |
| `list` | — | List bundles |
| `info` | `[bundle-id]` | Bundle information |
| `delete` | `[bundle-id]` | Delete a bundle |
| `export` | `[bundle-id]` | Export to an archive |
| `import` | `[archive-path]` | Import from an archive |
| `start` / `stop` / `is-running` | `--bundle-id` | swtpm daemon lifecycle |

**`create`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--bundle-id` | string | | Bundle ID (**required**) |
| `--hostname` | string | | Hostname for the VM (**required**) |
| `--secure-boot` | bool | **`true`** | Generate and enroll Secure Boot keys |
| `--ek-algorithm` | string | `RSA` | `RSA` or `ECC`, any case; anything else is rejected |
| `--template-id` | string | | Template to use as a base |
| `--label` | string array | | `key=value`, repeatable |

**`--secure-boot` defaults to `true`** here — unlike `compute create`, where
`--secure-boot` defaults to false. Secure Boot key enrollment happens at bundle
generation and is part of the vTPM's initial state; it is not applied later.

**`--hostname` is required** because a bundle is bound to a host — that is what
"pre-assigned" means.

**`clone`**: `--template` (required), `--hostname` (required), `--label`.

**`list`**: `--mode` filters by `template` or `pre-assigned`.

**`delete`**: `--force` / `-f` skips the confirmation prompt.

**`export`**: `--output` / `-o` (default `bundle-{id}.vtpm.tar.gz`),
`--overwrite`.

```bash
platformctl vtpm create --bundle-id web-01-tpm --hostname web-01 --ek-algorithm ECC
platformctl vtpm list --mode pre-assigned
platformctl vtpm start --bundle-id web-01-tpm
platformctl vtpm is-running --bundle-id web-01-tpm
platformctl vtpm export web-01-tpm --output ./web-01-tpm.tar.gz
```

---

## 3. `platformctl vtpm template`

| Verb | Argument | Flags |
|---|---|---|
| `create` | — | `--id` (required), `--description`, `--secure-boot` (default **`true`**), `--ek-algorithm` (default `RSA`) |
| `list` | — | — |
| `delete` | `[template-id]` | `--force` / `-f` |

A template is a specification; a bundle is an instance. `vtpm clone --template`
turns one into the other.

```bash
platformctl vtpm template create --id uefi-sb-ecc \
    --description "UEFI Secure Boot, ECC EK" --ek-algorithm ECC
platformctl vtpm clone --template uefi-sb-ecc --hostname web-02
```

---

## 4. Runtime operations

| Verb | Flags |
|---|---|
| `quote` | `--bundle-id` (required), `--nonce` hex (**required**), `--pcrs` comma-separated (**required**) |
| `seal` | `--bundle-id` (required), `--data` base64 (required), `--pcrs`, `--auth-value` |
| `unseal` | `--bundle-id` (required), `--sealed-data` base64 (required), `--auth-value` |
| `pcr extend` | `--bundle-id` (required), `--data` hex (required) |
| `pcr read` | `--bundle-id` (required) |

**`quote --nonce` is required and not generated.** Unlike
`platformctl container attest`, which generates one, `vtpm quote` makes you
supply it. A quote without a fresh nonce proves nothing about *when*, so supply
one you generated or one a verifier gave you — never a constant.

**Encoding differs between verbs.** `seal --data` is base64, `pcr extend --data`
is hex, `quote --nonce` is hex, `unseal --sealed-data` is base64. Read the flag
before encoding.

**`--pcrs` on `seal` binds the sealed blob to those PCRs.** Data sealed to PCRs
unseals only while those PCR values still match — that is the point, and it is
also why an unseal that worked yesterday can fail after a firmware update.

**`--auth-value` must match between seal and unseal.** It is a secret; the
warning about shell history applies.

```bash
platformctl vtpm quote --bundle-id web-01-tpm \
    --nonce 9f86d081884c7d659a2feaa0c55ad015 --pcrs 0,1,7
platformctl vtpm seal --bundle-id web-01-tpm --data "$(base64 -w0 secret.bin)" --pcrs 0,7
platformctl vtpm pcr read --bundle-id web-01-tpm
```

---

## 5. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Validate a bundle | REST, gRPC, QUIC, MCP |
| Bundle path / TPM socket path / NVRAM path | REST, gRPC, QUIC, MCP |
| Verify a quote | **QUIC only** |
| Get vTPM state, EK, AK; create AK; get random | **QUIC only** |
| Get or clone a template by id | REST, gRPC, QUIC, MCP (`template get` is not a CLI verb) |

---

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
