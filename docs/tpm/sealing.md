# TPM Sealing Operations

This document describes the TPM sealing and unsealing capabilities for protecting
sensitive data bound to specific platform states.

## Sealing Overview

TPM sealing encrypts data such that it can only be decrypted when the TPM is in a
specific state, typically defined by PCR values. This binds secrets to boot integrity.

> **Status: PCR-bound sealing is unavailable.** The gRPC, Unix, REST, MCP and
> vTPM seal surfaces refuse any request that names PCRs
> (`common.ErrPCRBoundSealUnavailable`, `FailedPrecondition` on gRPC). They will accept it once go-quicbaas re-exports
> the TPM PolicyPCR primitives (go-quicbaas #1171). Today a sealed object is
> protected by its password alone. The PCR flow below describes the design, not
> current behaviour. The contract is in [engineering.md](engineering.md) §6, and
> it wins wherever this page disagrees.

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

```bash
# Seal secret to current PCR state
platformctl tpm seal my-secret "sensitive-data"

# Seal with specific parent key
platformctl tpm seal my-secret "data" --parent 0x81000002

# Seal with password protection
platformctl tpm seal my-secret "data" --password "keypass"

# Seal from stdin
echo "sensitive-data" | platformctl tpm seal my-secret

# Seal with password auth only (no PCR binding: omit --pcrs)
platformctl tpm seal --cn my-secret --data "data" --password "$PW"
```

### Seal Options

| Option            | Description                                    | Default      |
|-------------------|------------------------------------------------|--------------|
| `--parent`        | Parent key handle (SRK)                        | 0x81000002   |
| `--parent-password`| Parent key authorization                      | (empty)      |
| `--password`      | Sealed object password                         | (empty)      |
| `--pcrs`          | PCR indices to bind to — refused until go-quicbaas #1171 | (none) |
| `--pcr-bank`      | PCR bank for `--pcrs`                          | sha256       |
| `--overwrite`     | Overwrite existing sealed object               | false        |

### gRPC Seal Request

```go
request := &platformv1.SealRequest{
    Data:           []byte("sensitive-data"),
    Cn:             "my-secret",
    ParentHandle:   0x81000002,
    ParentPassword: "",
    Password:       "key-password",
    Overwrite:      false,
    // PcrIndices is refused with FailedPrecondition until go-quicbaas #1171.
}

response, err := client.Seal(ctx, request)
// response.Status     - Operation status
// response.SealedData - Encrypted blob
// response.PublicKey  - Public portion
// response.PrivateKey - Wrapped private portion
```

## Unseal Operation

### Command Line

```bash
# Unseal secret (requires matching PCR state)
platformctl tpm unseal my-secret

# Unseal with password
platformctl tpm unseal my-secret --password "keypass"

# Unseal with specific parent
platformctl tpm unseal my-secret --parent 0x81000002
```

### Unseal Options

| Option            | Description                                    | Default      |
|-------------------|------------------------------------------------|--------------|
| `--parent`        | Parent key handle                              | 0x81000002   |
| `--parent-password`| Parent key authorization                      | (empty)      |
| `--password`      | Sealed object password                         | (empty)      |

### gRPC Unseal Request

```go
request := &platformv1.UnsealRequest{
    Cn:             "my-secret",
    ParentHandle:   0x81000002,
    ParentPassword: "",
    Password:       "optional-key-password",
    PcrIndices:     []uint32{7, 8, 9},
    PcrBank:        platformv1.PCRBank_PCR_BANK_SHA256,
}

response, err := client.Unseal(ctx, request)
// response.Status - Operation status
// response.Data   - Unsealed plaintext data
```

## PCR Policies

### Default Platform Policy

The platform configures a default PCR policy for sealed objects:

```
┌───────────────────────────────────────────────────────────────────┐
│                       Platform PCR Policy                         │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Firmware Integrity (PCRs 0-3, 7)                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ PCR 0: Core UEFI code                                       │  │
│  │ PCR 1: UEFI configuration                                   │  │
│  │ PCR 2: Option ROM code                                      │  │
│  │ PCR 3: Option ROM data                                      │  │
│  │ PCR 7: Secure Boot state                                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Boot Integrity (PCRs 8-9)                                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ PCR 8: Kernel command line                                  │  │
│  │ PCR 9: Kernel and initrd                                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  UKI Integrity (PCR 11)                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ PCR 11: Unified Kernel Image components                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Policy Configuration

```yaml
tpm:
  seal_policy:
    # Default policy for all sealed objects
    default:
      pcr_bank: SHA256
      pcrs: [7, 8, 9, 11]

    # Named policy for specific use cases
    firmware_only:
      pcr_bank: SHA256
      pcrs: [0, 1, 2, 3, 7]

    # LUKS encryption policy
    luks:
      pcr_bank: SHA256
      pcrs: [7, 11]
      require_password: true
```

## Data Protection Use Cases

### LUKS Disk Encryption

```
┌───────────────────────────────────────────────────────────────────┐
│                       LUKS Key Sealing                            │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Installation (First Boot):                                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Generate LUKS master key                                 │  │
│  │ 2. Seal key to TPM with PCR policy                          │  │
│  │ 3. Store sealed blob in LUKS token slot                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Subsequent Boots:                                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. initrd loads sealed blob from LUKS header                │  │
│  │ 2. Unseal using TPM (requires matching PCRs)                │  │
│  │ 3. Unlock LUKS volume with unsealed key                     │  │
│  │ 4. Continue boot                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Recovery (PCR mismatch):                                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Unseal fails due to PCR change                           │  │
│  │ 2. Prompt for recovery password                             │  │
│  │ 3. User enters recovery password                            │  │
│  │ 4. Re-seal key to new PCR state (if authorized)             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Secret Management

```bash
# Seal database credentials
platformctl tpm seal db-credentials "postgres://user:pass@localhost/db"

# Seal API keys
platformctl tpm seal api-key "sk_live_..."

# Seal encryption keys
openssl rand -base64 32 | platformctl tpm seal encryption-key
```

### TLS Private Key Protection

```bash
# Seal TLS private key
cat server.key | platformctl tpm seal tls-private-key

# Unseal for use
platformctl tpm unseal tls-private-key > /run/secrets/server.key
```

## Sealed Object Storage

```
┌───────────────────────────────────────────────────────────────────┐
│                      Sealed Object Storage                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Key Store Path: ${platform-dir}/keys/tpm/                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ my-secret.pub    - Public portion (TPM2B_PUBLIC)            │  │
│  │ my-secret.priv   - Private portion (wrapped, TPM2B_PRIVATE) │  │
│  │ my-secret.policy - Policy digest                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  The sealed data is stored encrypted in the private portion,      │
│  protected by the parent key (SRK) and the PCR policy.            │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Compound Authorization

Sealed objects can require multiple authorization factors:

```
┌───────────────────────────────────────────────────────────────────┐
│                     Compound Authorization                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Policy: PCR + Password                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Start policy session                                     │  │
│  │ 2. TPM2_PolicyPCR (bind to PCR values)                      │  │
│  │ 3. TPM2_PolicyAuthValue (require password)                  │  │
│  │ 4. Unseal with combined policy                              │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Policy: PCR OR Password (recovery)                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Branch A: TPM2_PolicyPCR                                    │  │
│  │ Branch B: TPM2_PolicyAuthValue                              │  │
│  │ TPM2_PolicyOR (either branch satisfies)                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Error Handling

| Error                    | Cause                          | Resolution             |
|--------------------------|--------------------------------|------------------------|
| TPM_RC_POLICY_FAIL       | PCR values changed             | Re-seal after update   |
| TPM_RC_AUTH_FAIL         | Wrong password                 | Correct password       |
| TPM_RC_HANDLE            | Parent key not found           | Check key provisioning |
| TPM_RC_NV_UNAVAILABLE    | Sealed object not found        | Verify CN exists       |
| TPM_RC_LOCKOUT           | Too many auth failures         | Wait for lockout reset |

## Recovery Procedures

### PCR Change Recovery

```bash
# 1. Boot with recovery key (bypasses TPM)
# 2. Authenticate with SO PIN
# 3. Re-seal to new PCR state
platformctl tpm unseal my-secret --recovery-key "..." > /tmp/secret
platformctl tpm seal my-secret "$(cat /tmp/secret)" --overwrite
rm /tmp/secret
```

### Re-sealing After Update

```bash
# After kernel update, re-seal objects to new PCR state
platformctl tpm reseal my-secret --so-pin
```

## Performance

| Operation        | Size    | Typical Latency |
|------------------|---------|-----------------|
| Seal 128 bytes   | 128B    | 50-200ms        |
| Seal 1KB         | 1KB     | 100-300ms       |
| Unseal 128 bytes | 128B    | 50-200ms        |
| Policy creation  | -       | 10-50ms         |

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
