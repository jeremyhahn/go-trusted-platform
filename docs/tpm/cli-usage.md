# TPM CLI Usage

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `platformctl tpm` commands, by example. The command tree is
> [cli.md](cli.md).

This document gives worked examples of TPM operations with `platformctl`. The
commands live in `pkg/cli/commands/tpm/` and call the daemon's `TPMService`.

## Command Overview

```
platformctl tpm <command> [options]

Commands:
  info        Get TPM device information
  status      Show TPM provisioning status (keys, certificates, hierarchies)
  provision   Provision the TPM with required keys
  clear       Clear the TPM
  ek          Endorsement Key operations (create, info, certificate, delete)
  srk         Storage Root Key operations (create, info, delete)
  iak         IAK operations
  idevid      IDevID operations
  seal        Seal data to the TPM
  unseal      Unseal data from the TPM
  eventlog    Get the TPM event log
  nvram       NVRAM operations (define, write, read, delete)
  enroll      Enroll the device using the ACME enroll-01 challenge
  certify     Certify a persistent key with the attestation key
```

`install`, `destroy`, `policy`, `extend`, `xkms`, `flush` and `device` are also
registered (`pkg/cli/commands/tpm/tpm.go`); see [cli.md](cli.md).

## TPM Information

```bash
# TPM information as reported by the daemon
platformctl tpm info

# JSON output: {"info": "...", "is_simulator": false}
platformctl tpm info -o json

# Keys, certificates and hierarchies
platformctl tpm status
```

## TPM Provisioning

```bash
# Create the EK, SRK and AK
platformctl tpm provision

# With hierarchy passwords
platformctl tpm provision --owner-password "$OWNER_PW" --endorsement-password "$EH_PW"
```

| Option                   | Description                    | Default |
|--------------------------|--------------------------------|---------|
| `--create-ek`            | Create the EK                  | true    |
| `--create-srk`           | Create the SRK                 | true    |
| `--create-ak`            | Create the AK                  | true    |
| `--owner-password`       | Owner hierarchy password       | (empty) |
| `--endorsement-password` | Endorsement hierarchy password | (empty) |

## Endorsement Key Operations

```bash
# EK information (default handle 0x81010001)
platformctl tpm ek info

# EK certificate
platformctl tpm ek certificate
platformctl tpm ek certificate -o json

# Create an EK: RSA-2048 (default), RSA-3072, ECDSA-P256 or ECDSA-P384
platformctl tpm ek create --algorithm ECDSA-P384
```

## Storage Root Key Operations

```bash
# SRK information (default handle 0x81000001)
platformctl tpm srk info
platformctl tpm srk info -o json

# Create an SRK under the EK at 0x81010001
platformctl tpm srk create --algorithm RSA-2048
```

## Seal and Unseal

`seal` takes the secret in `--data`; it reads no positional arguments and no
stdin. Objects are named by `--cn`.

```bash
# Seal with a password
platformctl tpm seal --cn my-secret --data "sensitive-data" --password "$PW"

# Seal to PCRs 7 and 9 (sha256 bank)
platformctl tpm seal --cn my-secret --data "sensitive-data" --pcrs 7,9

# Seal a file's contents
platformctl tpm seal --cn tls-private-key --data "$(cat server.key)"

# Unseal: table output prints the data as is
platformctl tpm unseal --cn my-secret > secret.txt
platformctl tpm unseal --cn my-secret --password "$PW"
```

The options are in [Sealing](sealing.md#seal-options). The daemon always seals
under the SSRK and does not act on `--parent`, `--parent-password` or
`--overwrite`. There is no `seal list` command.

## Event Log

```bash
# Text (default)
platformctl tpm eventlog

# JSON or raw binary
platformctl tpm eventlog --format json
platformctl tpm eventlog --format binary > binary_bios_measurements
```

## Clear TPM

```bash
# Clear the TPM (requires owner authorization; --confirm is required)
platformctl tpm clear --owner-password "$OWNER_PW" --confirm

# Clear through UEFI PPI (bypasses DA lockout, reboots)
platformctl tpm clear --force --confirm
```

**Warning:** Clearing the TPM removes all keys and sealed data permanently.

## Global Options

The `platformctl` root flags (`pkg/cli/commands/root.go`) apply to every TPM
command:

| Option          | Short | Description                          | Env |
|-----------------|-------|--------------------------------------|-----|
| `--config`      | `-c`  | Config file path                     | `PLATFORMCTL_CONFIG` |
| `--context`     |       | Named context                        | `PLATFORMCTL_CONTEXT` |
| `--transport`   |       | Transport override                   | `PLATFORMCTL_TRANSPORT` |
| `--server`      |       | Server address override              | `PLATFORMCTL_SERVER` |
| `--server-name` |       | TLS server name override             | `PLATFORMCTL_SERVER_NAME` |
| `--output`      | `-o`  | Output format (default `table`)      | `PLATFORMCTL_OUTPUT` |
| `--verbose`     | `-v`  | Verbose output                       | |
| `--no-color`    |       | Disable colored output               | `NO_COLOR` |

There are no TPM-wide PIN or password flags; each command takes its own.

## Examples

### Provision and Seal Database Credentials

```bash
# 1. Provision TPM
platformctl tpm provision

# 2. Verify provisioning
platformctl tpm status
platformctl tpm ek info
platformctl tpm srk info

# 3. Seal database credentials
platformctl tpm seal --cn db-credentials --data "postgres://user:pass@localhost/db"

# 4. Unseal for use
DB_URL=$(platformctl tpm unseal --cn db-credentials)
```

### Seal a TLS Private Key

```bash
openssl ecparam -genkey -name prime256v1 -noout -out server.key
platformctl tpm seal --cn tls-private-key --data "$(cat server.key)"

# Later, unseal for use
platformctl tpm unseal --cn tls-private-key > /run/secrets/server.key
chmod 600 /run/secrets/server.key
```

### PCR Values

`platformctl tpm` has no PCR read or quote command. Read PCRs with the
`TPMService.GetPCRs` RPC and quote with `TPMService.Quote`
([Attestation](attestation.md)); `platformctl tpm eventlog` shows the
measurements behind them.

## Error Messages

| Error                  | Cause                    | Solution                     |
|------------------------|--------------------------|------------------------------|
| "TPM service not available" | Daemon has no TPM   | Check `tpm.device` and the device node |
| Authorization failure  | Wrong password           | Correct credentials          |
| Policy failure         | PCR state changed        | Re-seal after update         |
| Lockout                | Too many auth failures   | Wait or clear lockout        |

## Related Documentation

- [README](README.md) - TPM module overview
- [Architecture](architecture.md) - TPM key hierarchy
- [Sealing](sealing.md) - Detailed sealing documentation
- [Attestation](attestation.md) - Quote operations
- [API Reference](api-reference.md) - gRPC API

## See Also

- `platformctl --help` - General CLI help
- `platformctl tpm --help` - TPM command help
- `platformctl tpm seal --help` - Seal command help
