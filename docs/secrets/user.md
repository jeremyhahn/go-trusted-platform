# Configuration Secret Resolution — Using It

> **Status: NORMATIVE** · Scope: `pkg/config/secrets/`, `pkg/bootstrap/`, `pkg/app/secrets*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

Your platform configuration file can name a secret instead of containing it:

```yaml
bmc:
  password: "kms://bmc/password?ensure=true&len=32&enc=base64"

tpm:
  platform-srk:
    srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"
```

At boot the platform replaces each of those strings with the real value, in
memory, before anything uses it. The file on disk never contains a credential,
so it can be templated, committed, and shipped inside an installer image.

---

## Turn it on

```yaml
secrets:
  enabled: true       # off by default — nothing resolves without this
  local-kms: true     # kms://
  encrypted: true     # idevid://
  file: false         # file://  — leave off unless you know why
  remote-kms: false   # remote-kms://
  dynamic-secrets: false
  xkms: false
```

Those seven keys are the whole surface. **If you have `auto-generate`,
`migrate-to-kms` or `update-config-file` in your config, delete them** — they
are not real keys, they are silently ignored, and some shipped templates still
carry them.

---

## Choosing a scheme

| Use | When |
|---|---|
| `kms://` | Almost everything. Shared service credentials, generated auth values, anything you might rotate. |
| `idevid://` | A per-node credential that must never work on another machine — TPM owner auth, a per-node unlock key. |
| `file://` | Only when no KMS is reachable: airgap install media, a recovery shell, local development. |
| `remote-kms://` | Fetching from a provisioning server during install. |
| `dynamic://` | A short-lived, leased credential generated on demand. |
| `xkms://` | **Not yet.** See the last section. |

### `kms://` — the default

```yaml
# Generate on first boot, return the same bytes on every boot after.
password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"

# Reference a secret something else created.
ssh-password: "kms://switches/core-01/ssh-password"
```

- `ensure=true` — create it the first time, return it thereafter.
- `len=N` — bytes for `base64`/`hex`/`raw`, digits for `numeric`.
- `enc=` — `base64` (URL-safe, unpadded: `len=32` → **43 characters**), `hex`
  (`len=32` → 64 characters), `numeric`, or `raw` (the `len` bytes verbatim).

**Changing `len` or `enc` after the secret exists is a breaking change.** You
get `ErrSecretSpecMismatch`, not a regenerated secret. Delete the KMS path first,
or deploy onto a clean secret store.

**Short paths are namespaced for you.** `kms://bmc/password` becomes
`tenants/{tenant}/nodes/{node}/secrets/bmc/password` at resolution time. **Do
not write `tenants/…/nodes/…` in a config file** — you will pin this node's
secrets to some other node's keyspace.

### The one rule that bites people: `enc=raw` for TPM auth values

A TPM authorization value is capped at one digest — **32 bytes** on a SHA-256
TPM. `len=32&enc=base64` produces 43 characters, overflows the cap, and the TPM
rejects the operation with `TPM_RC_SIZE`.

Use `?ensure=true&len=32&enc=raw` for every field whose value becomes a TPM auth
value:

| Field | Why |
|---|---|
| `webservice(s)[*].key.password` | `tpm-policy: platform` seals it into a TPM keyed-hash object |
| `acme.client.account.key.password` | same, plus the `TPM2_Create` auth when `store: tpm2` |
| `tpm.platform-srk.srk-auth` | Platform SRK authorization value |
| `certificate-authority.identity[*].keystores.tpm2.srk-auth` | CA TPM keystore SRK auth |

**The trigger is `tpm-policy: platform`, not `store:`.** A key with
`store: software` and `tpm-policy: platform` still gets sealed, so the cap
still applies.

Everything else keeps `enc=base64` — notably every
`certificate-authority.identity[*].keys[*].password` (a PKCS#8 encryption
password) and `bmc.password` (an IPMI/Redfish credential that must stay
printable ASCII).

### `idevid://` — bound to one machine

```yaml
tpm:
  srk-auth: "idevid://BQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk..."
```

Encrypted with RSA-OAEP/SHA-256 to that node's IDevID certificate. Only that
node's TPM can decrypt it — the private key never leaves the chip.

Produce a value:

```bash
openssl pkeyutl -encrypt \
  -pubin -inkey <(openssl x509 -in node-idevidcert.pem -pubkey -noout) \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -in secret.txt | base64 -w0
```

Both `idevid://<blob>` and `idevid:<blob>` are accepted, and both standard and
URL-safe base64 work.

**There is no rotation.** Changing the value means re-provisioning the node.
That is the price of binding a secret to one chip.

### `file://` — the escape hatch

```yaml
secrets:
  enabled: true
  file: true            # opt-in; off by default

bmc:
  password: "file:///run/secrets/bmc-password"
```

The file's bytes **are** the secret: no base64 decoding, no trimming. A trailing
newline is part of the value — `printf` rather than `echo` when you create one.

An empty file is an error. A missing or unreadable file is an error.

**Never enable `file:` on a node that can reach a KMS.** The secret sits in
plaintext on disk.

### `dynamic://` — leased credentials

```yaml
db:
  credential: "dynamic://database-readonly/1h"
```

`dynamic://role-name[/ttl]`. The TTL is a Go duration (`1h`, `30m`, `24h`) and
must be positive; omit it to use the role's default.

**The resolved value is a JSON document**, not a password: credential ID, type,
a data map, the lease ID, and expiry timestamps. A plain password field will get
that JSON. Assign it to a field that expects a structured credential.

---

## Inspect a config file

```bash
platformctl bootstrap secrets status --config /etc/trusted-platform/config.yaml --show-uris
```

`--show-uris` prints **masked** URIs — scheme plus two path segments, then
`/***`. Nothing prints a value.

---

## Move existing secrets into the KMS

If you have `env://` or `file://` references and want them KMS-managed:

```bash
# Look first.
platformctl bootstrap secrets migrate \
    --config /etc/trusted-platform/config.yaml --dry-run

# Then do it. A backup is taken unless you pass --no-backup.
platformctl bootstrap secrets migrate \
    --config /etc/trusted-platform/config.yaml
```

This **rewrites your configuration file**: each migrated value becomes
`kms://config/<dotted/path>`. On a rewrite failure the backup is restored
automatically. `--no-backup` removes that safety net; do not use it on a
production file.

`--force` continues past failures. Without it, a resolution failure aborts
before anything is written.

---

## Test a single URI

```bash
platformctl bootstrap secrets resolve "env://DATABASE_PASSWORD"
platformctl bootstrap secrets resolve "env://DATABASE_PASSWORD" --raw
```

`--raw` prints the plaintext. Do not use it on a shared or recorded terminal.

**This verb only resolves `env://`.** `kms://` returns *"secrets service is not
yet implemented in the platform KMS"*; `remote-kms://` and `idevid://` return
*"resolver not available"*; `file://`, `dynamic://` and `xkms://` are not
recognised at all. `platformd` resolves all of them at boot — the CLI is a much
smaller, separate implementation. A clean `verify` is not a boot guarantee.

---

## Troubleshooting

**The daemon refuses to start with "bootstrap secret resolution".**
Working as intended: one or more URIs could not be resolved, and the platform
would rather refuse than pass a literal `kms://...` string to the TPM as a
password. **The log names each failed field** — look for
`secret reference unresolved` lines with a `field` value.

**"secrets service not available but KMS required".**
The config uses `kms://` and there is no reachable secrets service. On a
standalone node with `local-kms: true` this is the fail-closed stub doing its
job. Either make the KMS reachable, or switch those fields to a scheme this node
can resolve.

**`TPM_RC_SIZE` from a TPM operation.**
A TPM auth value is longer than 32 bytes. You almost certainly have
`enc=base64` where you need `enc=raw`. See the rule above.

**"secret not found" for a Secure Boot key on first boot.**
Secure Boot PK/KEK/DB references are keypairs and certificates, not random
bytes, so they carry no `?ensure=true` and nothing generates them implicitly.
They are provisioned in a step that runs *before* the secret walk. If that step
did not run, the walk correctly reports them missing.

**`ErrSecretSpecMismatch`.**
You changed `len` or `enc` on a secret that already exists. Delete the KMS path
first, or deploy onto a clean secret store.

**A `file://` secret is rejected as empty.**
The file is zero bytes. Note also that a file created with `echo` has a trailing
newline that becomes part of the secret — use `printf '%s'`.

**An `idevid://` value stopped working after you moved the disk.**
It was encrypted to the old machine's TPM. It cannot decrypt anywhere else.
Re-provision.

**A secret resolves but the value is JSON you did not expect.**
Either `dynamic://` (which returns a credential document) or `xkms://` on its
fallback path (which returns key metadata). Neither is a bare password.

**Warnings at startup like "idevid resolver enabled but IDevID is not
configured".**
The resolver was requested and its dependency is missing, so it was skipped. If
any config field uses that scheme, the walk will fail shortly afterwards. The
warning is the early signal; the startup refusal is the enforcement.

---

## One thing to be aware of

**`xkms://` does not work yet.** The resolver is written, but the client adapter
wired behind it reports "cannot seal" and returns "not available" for both of
its retrieval paths. Enabling `secrets.xkms: true` registers a resolver that
cannot resolve anything, and any `xkms://` URI in your config will fail the
walk and stop the daemon. Use `kms://` or `idevid://`.
[architecture.md](architecture.md) §7.

---

## Where to go next

- [cli.md](cli.md) — the four `bootstrap secrets` verbs, and exactly what they can resolve
- [architecture.md](architecture.md) — trust boundaries, fail-closed and fail-open paths
- `config-secret-schemes.md` in this folder — the scheme reference in full
- [`docs/kms/`](../kms/) — where `kms://` values actually live
- [`docs/provisioning/`](../provisioning/) — getting secrets onto a node during install
