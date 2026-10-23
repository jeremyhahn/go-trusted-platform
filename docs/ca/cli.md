# Certificate Authority — CLI

> **Status: NORMATIVE** · Scope: `platformctl ca`, `platformctl acme` · Last verified: 2026-10-18
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/ca/` and `pkg/cli/commands/acme/` on 2026-10-18.

Replaces `docs/man/ca/*.md`, removed in 3ddd4fa19 (`git show 3ddd4fa19^:<path>`).

---

## 1. Two command groups

```
platformctl ca      Certificate Authority operations
platformctl acme    ACME certificate management
```

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:134`), precedence
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

`ca bundle` rebinds `-o` to `--output` as a **file path**, and `ca crl export`
rebinds `--output` the same way. Use long forms.

---

## 2. `platformctl ca`

| Verb | Positional | Purpose |
|---|---|---|
| `init` | — | Initialise the Certificate Authority |
| `info` | — | CA information |
| `issue` | `[cn] [store] [algorithm]` | Issue a certificate for a newly generated key |
| `sign-csr` | `[csr-file]` | Certify the key that signed a CSR |
| `certificate` | `[serial]` | Retrieve a certificate by serial |
| `list` | — | List issued certificates |
| `renew` | `<serial>` | Renew an existing certificate |
| `revoke` | `[serial]` | Revoke an issued certificate |
| `verify` | `[cert-path]` | Verify a certificate |
| `bundle` | — | Print or save the CA bundle (PEM) |
| `export-bundle` | — | The same command as `bundle`, under its other name |
| `crl` | — | Show the CRL; `crl export` writes it to a file |
| `install-ca-certificates` | — | Install CA certificates into the system trust store |
| `uninstall-ca-certificates` | — | Remove them |

### `ca info`

Prints whether the CA is initialised, its common name, whether it is an
intermediate, the default key algorithm and validity, the root and intermediate
certificates, and the configured key stores.

### `ca init`

`--force` / `-f` — force re-initialisation even if the CA already exists.

**This destroys and replaces a CA.** Every certificate the old CA issued becomes
unverifiable against the new one. `--force` is not a retry flag.

### `ca issue`

Positional: `[cn] [store] [algorithm]`.

**`ca issue` always generates a new key** in `[store]` and certifies it. It
cannot certify a key that already exists — use `ca sign-csr` for that.

`[store]` is one of `pkcs8` / `software` (also the default when empty),
`tpm` / `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `quantum`,
`frost`. **Any other name is rejected** with `unknown key store type`; it never
falls back to a software key. In particular `kms` is not a store name.

`[algorithm]` is case-insensitive: `RSA-2048`, `RSA-3072`, `RSA-4096`,
`ECDSA-P256` (or `EC-P256`), `ECDSA-P384` (or `EC-P384`), `ED25519`. Anything
else, bare `rsa` or `ecdsa` included, is refused with `invalid key algorithm`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--key-size` | int | `0` | Accepted and ignored: the size comes from `[algorithm]` |
| `--valid-days` | int | `365` | Validity period in days |
| `--sans-dns` | string | | SAN DNS names, comma-separated |
| `--sans-ips` | string | | SAN IPs, comma-separated |
| `--sans-email` | string | | SAN emails, comma-separated |
| `--key-usage` | string | | Comma-separated: `digitalSignature`, `keyEncipherment`, … |
| `--ext-key-usage` | string | | Comma-separated: `serverAuth`, `clientAuth`, … |

Note the flag names here are `--sans-dns` / `--sans-ips` / `--sans-email` taking
**comma-separated strings**, while `acme renew` uses `--sans-dns` /
`--sans-ip` / `--sans-email` as **repeatable string arrays**. Singular `--sans-ip`
in one group, plural `--sans-ips` in the other, and different types. Check which
group you are in.

### `ca sign-csr [csr-file]`

Certifies an existing KMS key for **code signing** from a PEM PKCS#10 request
the KMS signed. No key is generated, and the private key never reaches the
CA — this is how a KMS- or HSM-held key gets its certificate, paired with
`platformctl kms key csr`.

The CA refuses the CSR unless:

- its subject is one common name and nothing else — no `O`, `OU` or other
  attribute, and no SANs;
- that common name is the ID of a key the platform KMS holds, and the CSR's
  public key is that key's.

The certificate's usages are fixed: key usage `digitalSignature`, extended key
usage `codeSigning` only. There are no usage flags.

**Only the platform admin may run it**: root on the platformd host (over the
Unix socket, or with `--transport embedded`, which hosts platformd inside
platformctl), or a caller whose platform token grants `ca:sign-csr`.
`certs:generate` does not grant it. See `api.md` §4.

The desktop GUI offers the same operation as `CABinding.SignCSR`: it makes
the same SDK call, is held to the same rule, and returns the object
`--output json` prints ([docs/daemon/cli.md](../daemon/cli.md) §8).

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--valid-days` | int | `365` | Validity period in days |
| `--out` | string | | Write the certificate PEM here instead of stdout |

With `--output json|yaml` it prints the same result object as `ca issue`.

```bash
sudo platformctl kms key csr rpi/fleet --out fleet.csr
sudo platformctl ca sign-csr fleet.csr --out fleet.pem
```

### `ca certificate [serial]`

`--pem` displays PEM; `--der` includes the DER encoding.

### `ca renew <serial>`

`--days` (default `365`), `--force` (renew even when not near expiry).

### `ca revoke [serial]`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--reason` | string | `unspecified` | `unspecified`, `key-compromise`, `ca-compromise`, `superseded`, `cessation`, `hold` |
| `--delete-keys` | bool | `false` | Delete the associated key pair |

**Set `--reason` honestly.** It lands in the CRL and is what a relying party
uses to decide how to treat the revocation. `key-compromise` and `ca-compromise`
mean something specific.

**`--delete-keys` is irreversible** and separate from revocation: revoking marks
the certificate, deleting removes the key.

### `ca verify [cert-path]`

`--crl` (default **`true`**) checks against the CRL; `--expiry` (default
**`true`**) checks expiration. Both default on — pass `--crl=false` to skip.

### `ca list`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--status` | | string | `all` | `valid`, `revoked`, `expired`, `all` |
| `--issuer` | | string | | Filter by issuer common name |
| `--page` | `-p` | uint32 | `1` | Page number |
| `--page-size` | `-s` | uint32 | `50` | Certificates per page |

### `ca bundle`

`--output` / `-o` file path; `--intermediates` (default **`true`**).

### `ca crl`

Prints the CRL. `--entries` (default `false`) adds each revoked certificate.

`ca crl export` writes the CRL in **DER** to `--output`, which is **required**.
It takes no other flag.

### `ca install-ca-certificates` / `ca uninstall-ca-certificates`

`--include-intermediates` (bool, default `true`) adds the intermediate
certificates to the root.

Both verbs are daemon RPCs (`CAService/InstallCACertificates`,
`CAService/UninstallCACertificates`, permission `trust:write`), so they would
change the trust store of the host platformd runs on, not the caller's. **No
platformd CA service implements either RPC today**
(`pkg/api/daemon/ca_grpc_service.go:55`, `pkg/api/grpc/ca_service.go:127`), so
both fail. To trust the CA on the local host, write the bundle yourself:

```bash
platformctl ca bundle | sudo tee /usr/local/share/ca-certificates/platform.crt
sudo update-ca-certificates
```

```bash
platformctl ca info
platformctl ca issue web-01.example.com pkcs8 RSA-2048 --valid-days 90 \
    --sans-dns web-01.example.com,web.example.com --ext-key-usage serverAuth
platformctl ca list --status valid
platformctl ca revoke 0A1B2C3D --reason superseded
platformctl ca bundle --output ./ca-bundle.pem
platformctl ca crl --entries
platformctl ca crl export --output ./ca.crl
```

---

## 3. `platformctl acme`

| Verb | Positional | Purpose |
|---|---|---|
| `register` | — | Register a new ACME account |
| `renew` | — | Request or renew a certificate |
| `download` | `<certificate-url>` | Download a certificate from the ACME server |
| `rotate-key` | — | Rotate the ACME account key |

### `acme register`

`--email` (string) is the only flag: the account contact.

### `acme renew`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--directory` | string | a local `.../api/v1/acme/directory` URL | ACME server directory URL |
| `--ca-cert` | string | `ca-bundle.pem` | ACME server root certificate |
| `--email` | string | | Account email |
| `--authz` | string | `dns` | `dns`, `ip`, `permanent-identifier` |
| `--challenge` | string | `http-01` | `http-01`, `dns-01`, `endorse-01`, `device-01`, `device-attest-01` |
| `--cn` | string | | Subject common name |
| `--organization`, `--organizational-unit`, `--country`, `--province`, `--locality`, `--street-address`, `--postal-code` | string | | Subject fields |
| `--sans-dns`, `--sans-email`, `--sans-ip` | string array | | SANs, **repeatable** |

**`--challenge` is where device enrollment happens.** `endorse-01`,
`device-01` and `device-attest-01` are the TPM-based challenge types — they let
a device prove what it is rather than proving control of a name. `--authz
permanent-identifier` is the authorization type that pairs with them.

**The `--directory` default points at a local development address.** In any real
deployment, pass the platform's ACME directory URL explicitly.

`acme download` and `acme rotate-key` take no flags.

```bash
platformctl acme register --email ops@example.com

platformctl acme renew --directory https://ca.example.com/api/v1/acme/directory \
    --cn web-01.example.com --challenge dns-01 \
    --sans-dns web-01.example.com --sans-dns web.example.com

platformctl acme rotate-key
```

---

## 4. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Get the bootstrap bundle / root / intermediate directly | REST `/api/v1/ca/bootstrap`, `/ca/root`, `/ca/intermediate` |
| Renew or verify over REST | `POST /api/v1/ca/certificates/{serial}/renew`, `POST /api/v1/ca/certificates/verify` (`pkg/api/rest/ca_handlers.go:509`, `:516`) |

---

## 5. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository**, so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
