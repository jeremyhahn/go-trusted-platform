# Key Management — CLI

> **Status: NORMATIVE** · Scope: `platformctl kms` · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/kms/` and the `--help` of a `platformctl` built
> with the shipped tag set (`make -s print-build-tags`) on 2026-10-11.

---

## 1. Read this before anything else

- **Many verbs are declared but not implemented.** They parse their arguments
  and flags, then exit 1 with a typed error, without contacting a server. §8 is
  the complete list, regenerated from the code. Do not assume a verb works
  because it appears in `--help`.
- **`crypto verify` and `crypto hmac verify` exit 1 when verification fails**,
  after printing the verdict (`valid: false`, or the FAILED line in table
  output). A script can trust the exit code.
- **There is no `kms safety`, `kms hmac`, `kms hash`, `kms random`, `kms
  datakey` or `kms algorithms`.** The hash, HMAC, random and data-key verbs
  live under `kms crypto`; `algorithms` lives under `kms key`. The AEAD safety
  subtree is not in any build (§10).

---

## 2. Command tree

```
platformctl kms
    status                                  works
    key
        generate <key-id>                   works
        get <key-id>                        works
        list                                works
        delete <key-id>                     works
        rotate <key-id>                     works
        revoke <key-id>                     works
        csr <key-id>                        works
        algorithms                          works
        metadata get <key-id>               works
        metadata update <key-id>            works
        policy get <key-id>                 works
        policy set <key-id>                 works
        versions <key-id>                   works
        status enable <key-id>              works
        status disable <key-id>             works
        import <key-id>                     not implemented
        export <key-id>                     not implemented
        unwrap                              not implemented
        backend-test                        not implemented
    crypto
        encrypt | decrypt | rewrap          works
        sign | verify                       works
        hmac generate | hmac verify         works
        hash | random                       works
        datakey generate | datakey wrapped  works
        batch encrypt | batch decrypt       works
    dek
        create | get | list | delete | rotate | status
        set-default | set-safety | clear-safety          not implemented
    secrets
        store | get | list | delete | rotate | version | versions
        rollback | status enable | status disable
        policy get | policy set | prefix list            works
        watch                                            SDK gap (typed refusal)
```

`kms`, `key`, `crypto`, `dek`, `secrets` and every nested group (`metadata`,
`policy`, `status`, `hmac`, `datakey`, `batch`, `secrets policy`, `secrets
prefix`) only print help. An unknown verb under a group prints the group's help
and exits 0.

---

## 3. Global flags, transports and exit codes

`platformctl` persistent flags (`pkg/cli/commands/root.go`), precedence
**flag > environment > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | `$HOME/.platformctl/config.yaml` | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

`--transport` takes `unix`, `grpc`, `rest`, `quic`, `mcp` or `embedded`. Every
implemented verb opens an SDK client and fails with exit 1 when no daemon is
reachable — including `crypto hash` and `crypto random`, which run server-side.
No implemented verb works offline. The not-implemented verbs never open a
client.

**Two connections.** Most verbs call platformd's `KeyManagementService` on the
`--transport` connection (`Client.KMS()`). The verbs that platform service has
no RPC for open the CLI's quicbaas client (`Client.QuicBaaS()`) instead: `kms
status`, `key algorithms`, `key csr` (its public key; the signature goes
through platformd), `key policy`, `key metadata` and `key revoke`.
`--transport` does not select that connection. Its address and transport
follow the rules in [barrier cli.md §2](../barrier/cli.md#2-where-the-verbs-go):
a local context dials `/run/quicbaas.sock` unless `quicbaas_addr` or
`PLATFORMCTL_QUICBAAS_ADDR` says otherwise. Under embedded quicbaas (the daemon
default) there is no quicbaasd and nothing serves that socket; platformd serves
the `quicbaas.kms.v1` services on its own TCP and Unix listeners
([api.md §1](api.md#1-the-six-transports)). The quicbaas SDK requires TLS on
every transport, its Unix one included, and platformd's Unix socket is plaintext
gRPC authenticated by peer credentials, so the two cannot meet there. Point
`quicbaas_addr` at platformd's TCP gRPC listener with `quicbaas_transport: grpc`
and give the context the TLS files that verify it (`quicbaas_ca_cert`, and for
mTLS `quicbaas_client_cert` and `quicbaas_client_key`).

**Output format.** `--output` selects `table`, `json` or `yaml`. Verbs that
declare their own `-o, --output` (an output *file*) shadow it: on `crypto
encrypt`, `decrypt`, `rewrap`, `sign`, `hash`, `random`, `hmac generate`,
`datakey generate` and `datakey wrapped`, select the format with
`PLATFORMCTL_OUTPUT` instead.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Success, `--help`, an unknown verb under a group, or a `verify` / `hmac verify` that passed |
| 1 | Any error: a failed `verify` / `hmac verify` (`ErrVerificationFailed`), wrong argument count, missing required flag, invalid flag value, typed "not implemented" refusal, connection failure, server error |

---

## 4. `kms status`

Show the KMS backend's status, health and capabilities. No arguments, no local
flags.

```bash
platformctl kms status --output json
```

---

## 5. `kms key`

### `key generate <key-id>`

Generate a key.

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--algorithm` | `-a` | string | `aes-256` | no |
| `--purpose` | `-p` | string, comma-separated | `encrypt` | no |
| `--exportable` | `-e` | bool | `false` | no |
| `--deletion-protection` | | bool | `false` | no |
| `--name` | `-n` | string | | no |
| `--description` | `-d` | string | | no |
| `--owner` | | string | | no |

`<key-id>` travels as the generate request's `name` and becomes the key's ID
(`api.md` §2). `--name` is a display name, not the ID: the generate request
has no display-name field, so set it with `key metadata update <key-id> --name`.

Algorithms: `aes-128`, `aes-192`, `aes-256`, `chacha20-poly1305`, `rsa-2048`,
`rsa-3072`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`,
`dilithium2`, `dilithium3`, `dilithium5`, `hmac-sha256`, `hmac-sha384`,
`hmac-sha512`. Purposes: `encrypt`, `decrypt`, `sign`, `verify`, `wrap`,
`unwrap`, `derive`, `hmac`.

```bash
platformctl kms key generate tenant-a-kek --algorithm aes-256 --purpose encrypt,decrypt
platformctl kms key generate release-signer -a ecdsa-p384 -p sign,verify --deletion-protection
```

### `key get <key-id>`

Show one key's details.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--version` | | uint64 | `0` (latest) |

```bash
platformctl kms key get tenant-a-kek -o json
```

### `key list`

| Flag | Short | Type | Default |
|---|---|---|---|
| `--limit` | `-l` | int32 | `50` |
| `--cursor` | | string | |

```bash
platformctl kms key list --limit 100 --output json
```

### `key delete <key-id>`

Keys enter pending deletion for `--pending-days` before removal.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--pending-days` | `-p` | int32 | `7` |
| `--force` | `-f` | bool | `false` — delete immediately, skipping the window |

```bash
platformctl kms key delete old-kek --pending-days 30
```

### `key rotate <key-id>`

Create a new key version. Rotation does not re-encrypt existing ciphertext; use
`crypto rewrap` for that.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--retain-old` | `-r` | bool | `true` |

```bash
platformctl kms key rotate tenant-a-kek
```

### `key revoke <key-id>`

Mark a key compromised and unusable for every operation.

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--reason` | `-r` | string | | yes — checked before connecting; exit 1 when empty |

```bash
platformctl kms key revoke tenant-a-kek --reason "key material exposed in incident review"
```

### `key csr <key-id>`

Write a PEM certificate signing request for an asymmetric key: the public key as
the KMS reports it, the key ID as the subject common name, and a signature the
KMS makes — the private key never leaves the KMS. Building the request checks
the KMS's signature against the public key it reported, so a mismatch fails
here, not at the CA.

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--out` | | path | stdout | no |

Certify it with `platformctl ca sign-csr` (`docs/ca/cli.md`), which only the
platform admin may run and which issues a code-signing certificate; the CA
stores the certificate under the key ID, which is where KMS signers
(`kms://<key-id>`) look it up.

```bash
sudo platformctl kms key csr rpi/fleet --out fleet.csr
sudo platformctl ca sign-csr fleet.csr --out fleet.pem
```

### `key algorithms`

List the algorithms the current backend supports. No local flags.

```bash
platformctl kms key algorithms --output json
```

### `key metadata get <key-id>`

Show name, description and tags, never key material. No local flags.

```bash
platformctl kms key metadata get tenant-a-kek
```

### `key metadata update <key-id>`

| Flag | Short | Type | Default |
|---|---|---|---|
| `--name` | `-n` | string | |
| `--description` | `-d` | string | |
| `--tag` | `-t` | string array, `key=value`, repeatable | |
| `--remove-tag` | | string array, repeatable | |

```bash
platformctl kms key metadata update tenant-a-kek --name "Tenant A KEK" --tag env=prod --remove-tag temp
```

### `key policy get <key-id>`

Show the key's access policy. No local flags.

```bash
platformctl kms key policy get tenant-a-kek
```

### `key policy set <key-id>`

Replace the key's access policy. No flag has a short form.

| Flag | Type | Default |
|---|---|---|
| `--operation` | string array, repeatable: `encrypt`, `decrypt`, `sign`, `verify`, `wrap-key`, `derive-key` | none |
| `--allow-principal` | string array, e.g. `user:alice`, `role:admin` | none |
| `--deny-principal` | string array | none |
| `--expires-in` | string, e.g. `24h`, `7d` | none |
| `--rotation-required` | bool | `false` |
| `--max-usage` | uint64 | `0` |
| `--require-mfa` | bool | `false` |

```bash
platformctl kms key policy set tenant-a-kek --operation encrypt --operation decrypt \
    --allow-principal role:admin
```

### `key versions <key-id>`

List one page of the key's versions.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--limit` | `-l` | int32 | `50` |
| `--cursor` | | string | first page |

`--output json` prints `key_id`, `versions`, `has_more` and `next_cursor`; pass
`next_cursor` to `--cursor` while `has_more` is true. Each version carries
`version`, `algorithm` and `status` (the protobuf enum names, e.g.
`KMS_KEY_ALGORITHM_AES_256`, `KEY_STATUS_ENABLED`), `created_at` and
`disabled_at` (Unix seconds, `0` when never disabled).

```bash
platformctl kms key versions tenant-a-kek --output json
```

### `key status enable <key-id>` and `key status disable <key-id>`

Enable or disable the key, or one version of it. A disabled key or version
refuses every cryptographic operation until it is enabled again.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--version` | | uint64 | `0` — every version |

`--output json` prints `key_id`, `version`, `status` (e.g.
`KEY_STATUS_DISABLED`) and `updated_at` (Unix seconds).

```bash
platformctl kms key status disable tenant-a-kek --version 1
platformctl kms key status enable tenant-a-kek
```

### Not implemented under `kms key`

Each exits 1 with the error shown, after argument and flag parsing.

| Verb | Flags declared (type, default) | Error |
|---|---|---|
| `import <key-id>` | `-a/--algorithm` (`aes-256-gcm`), `-p/--purpose` (`encrypt`), `-e/--exportable`, `--deletion-protection`, `-n/--name`, `-d/--description`, `--wrapping-key`, `-f/--key-file`, `-m/--material` (base64) | `ErrKeyImportNotImplemented` |
| `export <key-id>` | `--wrapping-key`, `--wrapping-algorithm` (`aes-kw`), `--format` (`raw`; `jwk`, `pem`), `--version` (`0`), `--output-file` | `ErrKeyExportNotImplemented` |
| `unwrap` | `--key-id`, `--wrapping-key`, `--wrapping-algorithm` (`aes-kw`), `-a/--algorithm`, `-n/--name`, `-d/--description`, `-f/--input-file`, `-m/--material` | `ErrKeyUnwrapNotImplemented` |
| `backend-test` | none | `ErrBackendTestNotImplemented` |

The help text marks `--wrapping-key`, `--key-id` and `--algorithm` "required"
on these verbs; nothing enforces it.

---

## 6. `kms crypto`

Every verb here runs server-side; key material never reaches the client.
`--key-id` is enforced as required wherever it appears (exit 1 when missing).
Input is read from `--input` or, when it is absent, from stdin.

### `crypto encrypt`

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--output` | `-o` | path | stdout | no |
| `--context` | | string (AAD) | | no |
| `--nonce` | | base64 | generated | no |
| `--base64` | | bool | `true` | no |

```bash
platformctl kms crypto encrypt --key-id tenant-a-kek --input backup.tar --output backup.tar.enc --context "tenant=a"
```

### `crypto decrypt`

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--output` | `-o` | path | stdout | no |
| `--context` | | string (AAD used at encryption) | | no |
| `--nonce` | | base64 | | no |
| `--key-version` | | uint64 | `0` = auto-detect | no |
| `--base64-input` | | bool | `true` | no |

```bash
platformctl kms crypto decrypt --key-id tenant-a-kek --input backup.tar.enc --output backup.tar --context "tenant=a"
```

### `crypto rewrap`

Decrypt with the original key version and re-encrypt with the latest, without
exposing plaintext. This is what makes a rotation reach existing ciphertext.

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--output` | `-o` | path | stdout | no |
| `--context` | | string (AAD) | | no |
| `--nonce` | | base64 | | no |
| `--source-version` | | uint64 | `0` = auto-detect | no |
| `--base64-input` | | bool | `true` | no |
| `--base64` | | bool | `true` | no |

```bash
platformctl kms crypto rewrap --key-id tenant-a-kek --input backup.tar.enc --output backup.tar.v2.enc
```

### `crypto sign`

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--output` | `-o` | path (signature) | stdout | no |
| `--hash` | | string | `sha256` | no |
| `--base64` | | bool | `true` | no |

Hashes: `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384`, `sha3-512`,
`blake2b-256`, `blake2b-512`.

```bash
platformctl kms crypto sign --key-id release-signer --input release.tar.gz --output release.sig --hash sha384
```

### `crypto verify`

One of `--signature` or `--signature-file` is needed (exit 1 when neither;
`--signature` wins when both are set). A signature file is decoded as base64 when it parses, raw otherwise.
**A failed verification prints the verdict and exits 1** with
`ErrVerificationFailed` (§3).

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path (message) | stdin | no |
| `--signature` | | base64 | | one of |
| `--signature-file` | | path | | one of |
| `--hash` | | string | `sha256` | no |
| `--key-version` | | uint64 | `0` = auto-detect | no |

```bash
platformctl kms crypto verify --key-id release-signer --input release.tar.gz --signature-file release.sig --hash sha384 -o json
```

### `crypto hmac generate`

Requires an HMAC key (`hmac-sha256|384|512`).

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--output` | `-o` | path | stdout | no |
| `--hash` | | string | `sha256` | no |
| `--base64` | | bool | `true` | no |

```bash
platformctl kms crypto hmac generate --key-id webhook-mac --input payload.json --output payload.mac
```

### `crypto hmac verify`

One of `--hmac` or `--hmac-file` is needed. **A failed verification prints the
verdict and exits 1** with `ErrVerificationFailed` (§3).

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--hmac` | | base64 | | one of |
| `--hmac-file` | | path | | one of |
| `--hash` | | string | `sha256` | no |
| `--key-version` | | uint64 | `0` | no |

```bash
platformctl kms crypto hmac verify --key-id webhook-mac --input payload.json --hmac-file payload.mac -o json
```

### `crypto hash`

Unkeyed: it proves integrity against accidental change, never origin. Use
`hmac` for that.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--input` | `-i` | path | stdin |
| `--output` | `-o` | path | stdout |
| `--algorithm` | | string | `sha256` (same set as `sign`) |
| `--format` | | `hex` \| `base64` | `hex` |

```bash
platformctl kms crypto hash --input release.tar.gz --algorithm sha3-256
```

### `crypto random`

Random bytes from the backend's CSPRNG.

| Flag | Short | Type | Default |
|---|---|---|---|
| `--bytes` | | int32 | `32` |
| `--output` | `-o` | path | stdout |
| `--format` | | `base64` \| `hex` \| `raw` | `base64` |

```bash
platformctl kms crypto random --bytes 64 --format raw --output seed.bin
```

### `crypto datakey generate` and `crypto datakey wrapped`

Envelope encryption: mint a data-encryption key wrapped by `--key-id` (the KEK).
`generate` returns the plaintext DEK and its wrapped form; `wrapped` returns
only the wrapped form. Both declare the same flags.

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--algorithm` | | string | `aes-256` | no |
| `--key-size` | | int32 (bits) | `256` | no |
| `--context` | | string (AAD) | | no |
| `--output` | `-o` | path (wrapped key) | stdout | no |

```bash
platformctl kms crypto datakey generate --key-id tenant-a-kek --context "purpose=backup"
platformctl kms crypto datakey wrapped --key-id tenant-a-kek --output tenant-a-dek.wrapped
```

### `crypto batch encrypt` and `crypto batch decrypt`

Many items under one key in one request. Input is a JSON array, from `--input`
or stdin:

- encrypt: `[{"plaintext": "...", "context": "...", "nonce": "<base64>", "item_id": "..."}]`
  — only `plaintext` required
- decrypt: `[{"ciphertext": "<base64>", "context": "...", "nonce": "<base64>", "key_version": 0, "item_id": "..."}]`
  — only `ciphertext` required

| Flag | Short | Type | Default | Required |
|---|---|---|---|---|
| `--key-id` | | string | | yes |
| `--input` | `-i` | path | stdin | no |
| `--json` | | bool | `true` — **accepted and ignored**; input is always parsed as JSON | no |

These verbs have no local `--output`, so the global `-o json` applies.

```bash
platformctl kms crypto batch encrypt --key-id tenant-a-kek --input items.json -o json
```

---

## 7. `kms dek` (not implemented) and `kms secrets`

### `kms dek` — not implemented

Every `dek` leaf exits 1 with `ErrDEKNotImplemented` after parsing. Arguments
are enforced (exit 1 on the wrong count). The `dek` help points at `kms crypto
datakey`, which works.

| Verb | Arguments | Flags declared (type, default) |
|---|---|---|
| `dek create` | `<path>` | none |
| `dek get` | `<path>` | none |
| `dek list` | — | `--prefix`, `--recursive` (bool), `--limit` (int32, `100`), `--cursor` |
| `dek delete` | `<path>` | `--force` (bool) |
| `dek rotate` | `<path>` | none |
| `dek status` | `<path>` | none |
| `dek set-default` | `<path> <version>` | none |
| `dek set-safety` | `<path>` | `--max-operations` (uint64, `0`), `--max-bytes` (uint64, `0`), `--warn-percent` (int32, `80`) |
| `dek clear-safety` | `<path>` | `--force` (bool) |

The help shows `[path]`, but the argument is required.

### `kms secrets`

Every verb calls the go-quicbaas SDK secrets client
(`quicbaas.SDK().Security().Secrets()`) through the same platformd connection
the `key` and `crypto` verbs use. `store` writes the value and description into
the secret's data map under `value` and `description` and the tags as its
metadata, exactly as `POST /api/v1/kms/secrets` does, so the CLI and REST read
each other's secrets. Each verb prints JSON or YAML with `-o json|yaml`;
`value` is base64 there.

`get` (and `prefix list --include-data`) returns the bytes that were stored.
The go-quicbaas Secrets client JSON-encodes the data map, so a stored value
comes back from the SDK as its base64 text; the CLI and `GET
/api/v1/kms/secrets/{name}` decode it in one shared place
(`common.DecodeSecretValue`). A stored value that is not base64 text exits 1
with `ErrSecretOperationFailed` wrapping `ErrMalformedSecretValue`.

| Verb | Arguments | Flags (type, default) | SDK call | JSON output |
|---|---|---|---|---|
| `secrets store` | `<name>` | `--value` (required), `--base64` (bool: `--value` is base64), `--description`, `--tag key=value` (repeatable) | `Store` | `name`, `version` |
| `secrets get` | `<name>` | `--version` (int, `0` = current) | `Get` | `name`, `version`, `value`, `description`, `metadata`, `created_at` |
| `secrets list` | — | `--prefix`, `--limit` (int, `100`; `0` = all) | `List` | `prefix`, `secrets` (names), `has_more` |
| `secrets delete` | `<name>` | none | `Delete` | `name`, `deleted` |
| `secrets rotate` | `<name>` | `--value` (required), `--base64` (bool) | `Rotate` | `name`, `old_version`, `new_version` |
| `secrets version` | `<name> <version>` | none | `GetVersion` | as `get`, plus `created_by` |
| `secrets versions` | `<name>` | none | `ListVersions` | `name`, `versions` (no values) |
| `secrets rollback` | `<name> <version>` | none | `Rollback` | `name`, `new_version` |
| `secrets status enable`, `secrets status disable` | `<name>` | none | `UpdateStatus` | `name`, `status` |
| `secrets policy get` | `<name>` | none | `GetRotationPolicy` | `name`, `enabled`, `interval_seconds`, `next_rotation`, `retain_versions`, `rotation_lambda` |
| `secrets policy set` | `<name>` | `--enabled` (bool, `true`), `--interval` (duration), `--retain-versions` (int), `--rotation-lambda` | `SetRotationPolicy` | as `policy get` |
| `secrets prefix list` | `<prefix>` | `--include-data` (bool: also `Get` each secret) | `List` (+ `Get`) | as `list`, plus `data` |
| `secrets watch` | `<name>` | none | **none — SDK gap** | exits 1 with `ErrSecretsSDKGap` naming `SecretsClient.Watch` |

`<version>` must be a positive integer (`ErrInvalidSecretVersion`, exit 1,
before any connection). The SDK `List` returns every name at once, so `list`
has no `--cursor`: `--limit` caps what is printed and `has_more` reports the
rest. The SDK `Delete` removes a secret with all its versions; there is no soft
delete and no `--force`. A client error exits 1 with `ErrSecretOperationFailed`
naming the operation and the secret.

**Server coverage.** The pinned go-quicbaas embedded transport serves
`Store`, `Get`, `List` and `Delete` only. Against an embedded platformd,
`rotate`, `version`, `versions`, `rollback`, `status` and `policy` exit 1 with
`embedded: unknown method: quicbaas.Secrets.*` until go-quicbaas #1619 lands.

```bash
platformctl kms secrets store api-token --value "s3cret" --tag env=prod -o json
platformctl kms secrets get api-token -o json
```

---

## 8. The not-implemented list, regenerated

A verb is not implemented when its `RunE` returns one of the package's
`*NotImplemented` error types. Regenerate the list with:

```bash
grep -rn --include='*.go' --exclude='*_test.go' 'NotImplemented{}' pkg/cli/commands/kms/
```

On 2026-10-21 that names exactly these leaves (`kms secrets watch` is not a
stub: it refuses with `ErrSecretsSDKGap`, an SDK gap, §7):

| Error | Verbs |
|---|---|
| `ErrDEKNotImplemented` | every `kms dek` leaf (§7) |
| `ErrKeyImportNotImplemented` | `kms key import` |
| `ErrKeyExportNotImplemented` | `kms key export` |
| `ErrKeyUnwrapNotImplemented` | `kms key unwrap` |
| `ErrBackendTestNotImplemented` | `kms key backend-test` |

Counting the string `(not yet implemented)` instead overcounts: it also appears
in the `Short` text of the `dek` group and in test files.

---

## 9. No local flag reuses a global shorthand

`platformctl` declares `-c` (`--config`), `-o` (`--output`) and `-v`
(`--verbose`) as persistent shorthands. A verb whose local flag takes one of
those letters under another name makes pflag panic when cobra merges the flag
sets, so the verb crashes on every call, `--help` included. These flags are
therefore long-form only:

| Verb | Flag |
|---|---|
| `kms key get` | `--version` |
| `kms key export` | `--version`, `--output-file` |
| `kms key policy set` | `--operation` |
| `kms key status enable`, `kms key status disable` | `--version` |

`TestCommandTreeHasNoFlagClashes` (`pkg/cli/commands/flag_tree_test.go`) walks
the whole `platformctl` tree and fails on any such collision.

A local flag that redeclares a global flag's *name* (the `-o, --output` file
flag of the `crypto` verbs, §3) shadows it instead and does not crash.

---

## 10. AEAD safety limits: not in any build

`pkg/cli/commands/kms/key_safety.go` declares a `kms key safety` group (`set
<key-id>` with `--max-operations`, `--max-bytes`, `--warning-percent`; `get
<key-id>`; `clear <key-id>`; `check`; `report`). It compiles only under the
`key_safety` build tag, which the shipped tag set does not include, and under
that tag it does not compile: the SDK client has no `SetKeySafety` /
`GetKeySafety`. The default build links `key_safety_stub.go`, which registers
nothing.

So no shipped `platformctl` has AEAD safety commands, and no API transport has
them either ([api.md](api.md) §5). Nothing on the platform today reports a key
approaching its AES-GCM usage bound.

---

## 11. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository.**

For the not-implemented verbs the requirement would be misleading if satisfied
naively: a parity suite that asserted they exist would be asserting the wrong
thing. Their unit tests assert the refusal, which is the correct shape and what
stops them silently half-working.
