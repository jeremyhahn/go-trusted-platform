# TPM CLI Usage

This document provides the command-line reference for TPM operations
using platformctl.

## Command Overview

```
platformctl tpm <command> [options]

Commands:
  info        Display TPM information
  provision   Provision TPM keys
  clear       Clear TPM (factory reset)
  ek          Endorsement Key operations
  srk         Storage Root Key operations
  seal        Seal data to TPM
  unseal      Unseal data from TPM
  eventlog    Display TPM event log
```

## TPM Information

### Display TPM Info

```bash
# Basic TPM information
platformctl tpm info

# Output:
# TPM Information
# Manufacturer: Infineon
# Vendor ID:    IFX
# Family:       2.0
# Revision:     1.38
# Firmware:     7.85
# FIPS 140-2:   true
```

### Detailed Information

```bash
# Verbose output with capabilities
platformctl tpm info -v

# JSON output
platformctl tpm info -o json
```

**JSON Output Example:**
```json
{
  "version": "2.0",
  "manufacturer": {
    "name": "Infineon",
    "id": "IFX",
    "firmware": "7.85"
  },
  "capabilities": {
    "algorithms": ["RSA", "ECC", "AES", "SHA256", "SHA384"],
    "pcrBanks": ["SHA256", "SHA384"],
    "maxNvramSize": 2048
  },
  "fipsMode": true,
  "isSimulator": false
}
```

## TPM Provisioning

### Full Provision

```bash
# Provision TPM with all standard keys
platformctl tpm provision --so-pin

# With explicit passwords
platformctl tpm provision --raw-so-pin "owner-password"
```

### Provision Options

| Option           | Description                              |
|------------------|------------------------------------------|
| `--so-pin`       | Prompt for Security Officer PIN         |
| `--raw-so-pin`   | Provide SO PIN directly (automation)    |
| `--hierarchy-auth`| Hierarchy authorization password        |

## Endorsement Key Operations

### View EK

```bash
# Display EK information
platformctl tpm ek show

# Output:
# Endorsement Key (EK)
# Handle:     0x81010001
# Algorithm:  RSA-2048
# Public Key: [base64 encoded]
```

### Export EK Certificate

```bash
# Export EK certificate (PEM)
platformctl tpm ek cert > ek.crt

# Export in DER format
platformctl tpm ek cert --format der > ek.der
```

### Create EK

```bash
# Create RSA EK
platformctl tpm ek create --algorithm rsa2048

# Create ECC EK
platformctl tpm ek create --algorithm eccp384
```

## Storage Root Key Operations

### View SRK

```bash
# Display SRK information
platformctl tpm srk show

# Output:
# Storage Root Key (SRK)
# Handle:     0x81000002
# Algorithm:  RSA-2048
# Parent:     0x81010001 (EK)
```

### SRK Options

```bash
# Show with public key details
platformctl tpm srk show -v

# JSON output
platformctl tpm srk show -o json
```

## Seal Operations

### Basic Seal

```bash
# Seal a secret string
platformctl tpm seal my-secret "sensitive-data"

# Seal from file
cat secret.txt | platformctl tpm seal my-secret

# Seal with echo
echo -n "password123" | platformctl tpm seal db-password
```

### Seal Options

```bash
# Seal with password protection
platformctl tpm seal my-secret "data" --password "keypass"

# Seal without PCR policy (password only)
platformctl tpm seal my-secret "data" --policy=false --password "required"

# Seal to specific parent
platformctl tpm seal my-secret "data" --parent 0x81000002

# Overwrite existing
platformctl tpm seal my-secret "new-data" --overwrite
```

### Seal Command Options

| Option              | Description                      | Default      |
|---------------------|----------------------------------|--------------|
| `--parent, -p`      | Parent key handle                | 0x81000002   |
| `--parent-password` | Parent key password              | (empty)      |
| `--parent-policy`   | Use PCR policy for parent        | true         |
| `--password`        | Sealed object password           | (empty)      |
| `--policy`          | Attach PCR policy                | true         |
| `--overwrite`       | Overwrite if exists              | false        |

## Unseal Operations

### Basic Unseal

```bash
# Unseal a secret
platformctl tpm unseal my-secret

# Output directly to stdout
platformctl tpm unseal my-secret

# Pipe to file
platformctl tpm unseal my-secret > secret.txt
```

### Unseal Options

```bash
# Unseal with password
platformctl tpm unseal my-secret --password "keypass"

# Unseal from specific parent
platformctl tpm unseal my-secret --parent 0x81000002
```

### Unseal Command Options

| Option              | Description                      | Default      |
|---------------------|----------------------------------|--------------|
| `--parent, -p`      | Parent key handle                | 0x81000002   |
| `--parent-password` | Parent key password              | (empty)      |
| `--password`        | Sealed object password           | (empty)      |

## Event Log Operations

### View Event Log

```bash
# Display event log summary
platformctl tpm eventlog

# Detailed output
platformctl tpm eventlog -v

# JSON format
platformctl tpm eventlog -o json
```

### Event Log Output

```
PCR[0]: EV_S_CRTM_VERSION - UEFI Platform Firmware
PCR[0]: EV_EFI_PLATFORM_FIRMWARE_BLOB - Firmware code
PCR[7]: EV_EFI_VARIABLE_DRIVER_CONFIG - SecureBoot
PCR[7]: EV_EFI_VARIABLE_AUTHORITY - db certificate
PCR[8]: EV_IPL - GRUB command line
PCR[9]: EV_IPL - Linux kernel
```

## Clear TPM

### Factory Reset

```bash
# Clear TPM (requires owner auth)
platformctl tpm clear --so-pin --confirm

# With explicit password
platformctl tpm clear --raw-so-pin "owner-password" --confirm
```

**Warning:** Clearing the TPM removes all keys and sealed data permanently.

## Global Options

These options are available for all TPM commands:

| Option            | Short | Description                       |
|-------------------|-------|-----------------------------------|
| `--debug`         | `-d`  | Enable debug output               |
| `--output`        | `-o`  | Output format (table, json, yaml) |
| `--verbose`       | `-v`  | Verbose output                    |
| `--config`        | `-c`  | Config file path                  |
| `--platform-dir`  |       | Platform data directory           |
| `--so-pin`        |       | Prompt for SO PIN                 |
| `--pin`           |       | Prompt for user PIN               |
| `--raw-so-pin`    |       | SO PIN (automation)               |
| `--raw-pin`       |       | User PIN (automation)             |

## Examples

### Example: Provision and Seal Database Credentials

```bash
# 1. Provision TPM
platformctl tpm provision --so-pin

# 2. Verify provisioning
platformctl tpm info
platformctl tpm ek show
platformctl tpm srk show

# 3. Seal database credentials
platformctl tpm seal db-credentials "postgres://user:pass@localhost/db"

# 4. Verify sealed object exists
platformctl tpm seal list

# 5. Unseal for use
DB_URL=$(platformctl tpm unseal db-credentials)
echo "Connecting to: $DB_URL"
```

### Example: Seal TLS Private Key

```bash
# Generate TLS key
openssl ecparam -genkey -name prime256v1 -noout -out server.key

# Seal the private key
cat server.key | platformctl tpm seal tls-private-key

# Later, unseal for use
platformctl tpm unseal tls-private-key > /run/secrets/server.key
chmod 600 /run/secrets/server.key
```

### Example: Automation Script

```bash
#!/bin/bash
set -e

# Provision TPM (non-interactive)
platformctl tpm provision --raw-so-pin "${TPM_OWNER_PASSWORD}"

# Seal secrets
platformctl tpm seal api-key "${API_KEY}" --raw-so-pin "${TPM_OWNER_PASSWORD}"
platformctl tpm seal db-pass "${DB_PASSWORD}" --raw-so-pin "${TPM_OWNER_PASSWORD}"

echo "Secrets sealed to TPM"
```

### Example: View PCR Values

```bash
# Note: Use platformctl platform or direct TPM tools
# PCR values shown in event log context
platformctl tpm eventlog -v

# Or via attestation quote
platformctl platform quote --pcrs 0,7,8,9
```

## Error Messages

| Error                           | Cause                    | Solution                  |
|---------------------------------|--------------------------|---------------------------|
| "TPM not found"                 | No TPM device            | Check /dev/tpmrm0 exists  |
| "authorization failed"          | Wrong password/PIN       | Correct credentials       |
| "object not found"              | Sealed object missing    | Check CN exists           |
| "policy failed"                 | PCR state changed        | Re-seal after update      |
| "TPM in lockout"                | Too many auth failures   | Wait or clear lockout     |

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
