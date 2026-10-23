# TPM Sealing Operations

> **Status: REFERENCE** · Last verified: 2026-10-15
> Sealing and unsealing data to platform state.

This document describes the TPM sealing and unsealing capabilities for protecting
sensitive data bound to specific platform states.

## Sealing Overview

TPM sealing encrypts data such that it can only be decrypted when the TPM is in a
specific state, typically defined by PCR values. This binds secrets to boot integrity.

```
┌───────────────────────────────────────────────────────────────────┐
│                      Sealing/Unsealing Flow                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  SEAL OPERATION                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                                                             │  │
│  │   Secret Data          Current PCR State                    │  │
│  │   ┌─────────┐          ┌────────────────┐                   │  │
│  │   │ "pass"  │          │ PCR[7] = 0x... │                   │  │
│  │   └─────────┘          │ PCR[8] = 0x... │                   │  │
│  │        │               └───────┬────────┘                   │  │
│  │        │                       │                            │  │
│  │        ▼                       ▼                            │  │
│  │   ┌────┴──────────────────────┴────┐                        │  │
│  │   │          TPM Seal              │                        │  │
│  │   │   (Create keyed hash object)   │                        │  │
│  │   └──────────────┬─────────────────┘                        │  │
│  │                  │                                          │  │
│  │                  ▼                                          │  │
│  │   ┌──────────────┴─────────────────┐                        │  │
│  │   │   Sealed Blob (encrypted)      │                        │  │
│  │   │   • Public key                 │                        │  │
│  │   │   • Private key (wrapped)      │                        │  │
│  │   │   • Policy digest              │                        │  │
│  │   └──────────────┬─────────────────┘                        │  │
│  │                  │                                          │  │
│  │                  ▼                                          │  │
│  │        Store to Key Store                                   │  │
│  │                                                             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  UNSEAL OPERATION                                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                                                             │  │
│  │   Sealed Blob          Current PCR State                    │  │
│  │   ┌─────────┐          ┌────────────────┐                   │  │
│  │   │ [enc]   │          │ PCR[7] = 0x... │                   │  │
│  │   └─────────┘          │ PCR[8] = 0x... │                   │  │
│  │        │               └───────┬────────┘                   │  │
│  │        │                       │                            │  │
│  │        ▼                       ▼                            │  │
│  │   ┌────┴───────────────────────┴───┐                        │  │
│  │   │         TPM Unseal             │                        │  │
│  │   │   (Policy session + auth)      │                        │  │
│  │   └───────────────┬────────────────┘                        │  │
│  │                   │                                         │  │
│  │        ┌──────────┴──────────┐                              │  │
│  │        │                     │                              │  │
│  │        ▼                     ▼                              │  │
│  │   PCR Match              PCR Mismatch                       │  │
│  │   ┌─────────┐            ┌─────────────┐                    │  │
│  │   │ "pass"  │            │ AUTH_FAIL   │                    │  │
│  │   └─────────┘            └─────────────┘                    │  │
│  │                                                             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Seal Operation

### Command Line

`platformctl tpm seal` (`pkg/cli/commands/tpm/seal.go`) takes the secret in
`--data`; it reads no positional arguments and no stdin. It calls the daemon's
`TPMService.Seal` RPC.

```bash
# Seal with password auth only (no PCR binding: omit --pcrs)
platformctl tpm seal --cn my-secret --data "sensitive-data" --password "$PW"

# Seal to PCRs 7 and 9 of the sha256 bank
platformctl tpm seal --cn my-secret --data "sensitive-data" --pcrs 7,9

```

### Seal Options

| Option            | Description                                    | Default      |
|-------------------|------------------------------------------------|--------------|
| `--cn`            | Common name of the sealed object (required)    | -            |
| `--data`          | Data to seal                                   | (empty)      |
| `--password`      | Sealed object password                         | (empty)      |
| `--parent`        | Parent key handle                              | 0x81000001   |
| `--parent-password`| Parent key authorization                      | (empty)      |
| `--pcrs`          | PCR indices to bind the sealed object to       | (none)       |
| `--pcr-bank`      | `sha1`, `sha256`, `sha384` or `sha512`         | sha256       |
| `--overwrite`     | Overwrite existing sealed object               | false        |

The daemon always seals under the SSRK (`buildSealOptions`,
`pkg/api/daemon/tpm_grpc_service.go`): it does not read `--parent`,
`--parent-password` or `--overwrite` from the request. Empty data is refused
with `InvalidArgument`.

### gRPC Seal Request

```go
request := &platformv1.SealRequest{
    Data:       []byte("sensitive-data"),
    Cn:         "my-secret",
    Password:   "optional-key-password",
    PcrIndices: []uint32{7, 9},
    PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
}

response, err := client.Seal(ctx, request)
// response.Status     - success and "sealed <key id>"
// response.SealedData - length-prefixed TPM2B_PUBLIC + TPM2B_PRIVATE
// response.PublicKey and response.PrivateKey are not set
```

## Unseal Operation

### Command Line

```bash
# Unseal (requires the PCR state the object was sealed to)
platformctl tpm unseal --cn my-secret

# Unseal a password-protected object
platformctl tpm unseal --cn my-secret --password "$PW"
```

In the default table output the command prints the unsealed data as is, so it
can be redirected to a file; `-o json` and `-o yaml` wrap it with `success`
and `cn` (`pkg/cli/commands/tpm/unseal.go`).

### Unseal Options

| Option            | Description                                    | Default      |
|-------------------|------------------------------------------------|--------------|
| `--cn`            | Common name of the sealed object (required)    | -            |
| `--password`      | Sealed object password                         | (empty)      |
| `--parent`        | Parent key handle                              | 0x81000001   |
| `--parent-password`| Parent key authorization                      | (empty)      |
| `--pcrs`          | PCR indices                                    | (none)       |
| `--pcr-bank`      | PCR bank                                       | sha256       |

The daemon looks the object up by CN and reads only `cn` and `password` from
the request; the PCR selection is the one recorded at seal time.

### gRPC Unseal Request

```go
request := &platformv1.UnsealRequest{
    Cn:       "my-secret",
    Password: "optional-key-password",
}

response, err := client.Unseal(ctx, request)
// response.Data - Unsealed plaintext data (the daemon sets no Status)
```

## PCR Policies

`tpm seal` applies no default PCR policy: without `--pcrs` the object is
protected by its password alone. With `--pcrs` the object gets a PCR policy on
the chosen bank; when a `--password` is also set, the policy requires it too.

There is no `tpm.seal_policy` configuration key. The PCR lists the platform
does configure are:

| Key | Shipped value | Used for |
|-----|---------------|----------|
| `seal-pcrs` | `[0, 7, 9]` | LUKS key sealing by the installer and initrd |
| `tpm.golden-pcrs` | `[7, 9]` | Platform policy |

(Values from `configs/platform/templates/single-node/default.yaml`.)

## Data Protection Use Cases

### LUKS Disk Encryption

The LUKS volume key is sealed to `seal-pcrs` by the installer and unsealed by
the initrd; that path does not use `platformctl tpm seal`. See
[LUKS](../luks/user.md) and [Installer](../installer/user.md).

### Secret Management

```bash
# Seal database credentials
platformctl tpm seal --cn db-credentials --data "postgres://user:pass@localhost/db"

# Seal a generated encryption key
platformctl tpm seal --cn encryption-key --data "$(openssl rand -base64 32)"
```

### TLS Private Key Protection

```bash
# Seal TLS private key
platformctl tpm seal --cn tls-private-key --data "$(cat server.key)"

# Unseal for use
platformctl tpm unseal --cn tls-private-key > /run/secrets/server.key
```

## Sealed Object Storage

The sealed object (TPM2B_PUBLIC and TPM2B_PRIVATE) is kept by the TPM keystore
under its CN, protected by the SSRK and, when set, the PCR policy. Unseal
finds it by CN alone.

## Compound Authorization

With both `--pcrs` and `--password`, the seal carries the password on the
object and on its PCR policy, so unseal needs the PCR state and the password
(`buildSealOptions`). There is no PCR-or-password recovery branch.

## Error Handling

| Error                    | Cause                          | Resolution             |
|--------------------------|--------------------------------|------------------------|
| TPM_RC_POLICY_FAIL       | PCR values changed             | Re-seal after update   |
| TPM_RC_AUTH_FAIL         | Wrong password                 | Correct password       |
| TPM_RC_HANDLE            | Parent key not found           | Check key provisioning |
| TPM_RC_LOCKOUT           | Too many auth failures         | Wait for lockout reset |

The daemon answers `Unavailable` when it has no TPM and `InvalidArgument` for
empty seal data or an empty unseal CN.

## Re-sealing After an Update

There is no `tpm reseal` command and no recovery-key flag. To move a secret to
a new PCR state, unseal it while the old state still holds, then seal it again
after the update. The daemon ignores `--overwrite`, so seal under a new CN if
the old object is still in the keystore:

```bash
platformctl tpm unseal --cn my-secret > /run/my-secret
# ... update, reboot ...
platformctl tpm seal --cn my-secret-v2 --data "$(cat /run/my-secret)" --pcrs 7,9
rm /run/my-secret
```

## Related Documentation

- [README](README.md) - TPM module overview
- [Architecture](architecture.md) - Key hierarchy and PCR configuration
- [Attestation](attestation.md) - PCR-based attestation
- [PCRs](pcrs.md) - Platform Configuration Register reference
- [Security](security.md) - Security considerations and CVEs
- [Configuration](configuration.md) - TPM configuration options
- [API Reference](api-reference.md) - gRPC seal/unseal API
- [CLI Usage](cli-usage.md) - Command-line examples

## References

- [TCG TPM 2.0 Library - Part 3: Commands](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)
- [Disk Encryption with TPM](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)
- [LUKS TPM2 Integration](https://github.com/salrashid123/tpm2/blob/master/luks/README.md)
