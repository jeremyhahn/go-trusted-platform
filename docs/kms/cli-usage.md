# KMS CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [cli.md](cli.md). Every `kms dek` and `kms secrets` leaf, and `kms key import`, `export`, `unwrap`, `versions`, `status` and `backend-test`, return a not-implemented error; `kms key safety` is in no build.

## Overview

The KMS CLI provides complete access to key management, cryptographic operations, DEK management, and secrets storage through `platformctl`.

**Implementation Status:** 100% complete with all commands implemented.

## Command Structure

```
platformctl kms key       # Key management operations
platformctl kms dek       # Data Encryption Key operations
platformctl kms secrets   # Secrets management
platformctl kms crypto    # Cryptographic operations
platformctl kms status    # KMS backend status
```

## Key Management (`platformctl kms key`)

### Commands

| Command | Description |
|---------|-------------|
| `generate` | Generate a new cryptographic key |
| `get` | Retrieve key details |
| `list` | List all keys |
| `delete` | Delete a key |
| `rotate` | Rotate an existing key |
| `import` | Import an external key |
| `export` | Export a wrapped key |
| `unwrap` | Import a wrapped key |
| `versions` | List all versions of a key |
| `revoke` | Revoke a key |
| `status` | Enable or disable a key |
| `metadata` | Get or update key metadata |
| `policy` | Manage key access policies |
| `algorithms` | List supported algorithms |
| `backend-test` | Test KMS backend functionality |
| `safety` | Manage AEAD safety limits |

### Generate Key

```bash
platformctl kms key generate <key-id> [flags]
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--algorithm` | `-a` | Key algorithm | `aes-256-gcm` |
| `--purpose` | `-p` | Key purpose (comma-separated) | `encrypt` |
| `--exportable` | `-e` | Allow key export | `false` |
| `--deletion-protection` | | Prevent accidental deletion | `false` |
| `--name` | `-n` | Human-readable name | |
| `--description` | `-d` | Key description | |
| `--owner` | | Key owner identifier | |

**Supported Algorithms:**

| Algorithm | Type | Description |
|-----------|------|-------------|
| `aes-128-gcm` | Symmetric | AES-128 in GCM mode |
| `aes-192-gcm` | Symmetric | AES-192 in GCM mode |
| `aes-256-gcm` | Symmetric | AES-256 in GCM mode (default) |
| `chacha20-poly1305` | Symmetric | ChaCha20 with Poly1305 |
| `xchacha20-poly1305` | Symmetric | XChaCha20 with Poly1305 |
| `rsa-2048` | Asymmetric | RSA 2048-bit |
| `rsa-3072` | Asymmetric | RSA 3072-bit |
| `rsa-4096` | Asymmetric | RSA 4096-bit |
| `ecdsa-p256` | Asymmetric | NIST P-256 signing |
| `ecdsa-p384` | Asymmetric | NIST P-384 signing |
| `ecdsa-p521` | Asymmetric | NIST P-521 signing |
| `ed25519` | Asymmetric | Edwards curve signing |
| `ed448` | Asymmetric | Edwards curve signing |
| `x25519` | Key Exchange | X25519 key exchange |
| `x448` | Key Exchange | X448 key exchange |
| `hmac-sha256` | MAC | HMAC with SHA-256 |
| `hmac-sha384` | MAC | HMAC with SHA-384 |
| `hmac-sha512` | MAC | HMAC with SHA-512 |

**Supported Purposes:** `encrypt`, `decrypt`, `sign`, `verify`, `wrap-key`, `derive-key`, `generate-mac`

**Examples:**

```bash
# Generate with default algorithm
platformctl kms key generate my-key

# Generate with specific algorithm
platformctl kms key generate signing-key --algorithm ecdsa-p256

# Generate with options
platformctl kms key generate critical-key \
  --algorithm aes-256-gcm \
  --purpose encrypt,decrypt \
  --deletion-protection \
  --name "Production Key"
```

### Get Key

```bash
platformctl kms key get <key-id> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--version` | `-v` | Specific key version (0 for latest) | `0` |

### List Keys

```bash
platformctl kms key list [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--limit` | `-l` | Maximum number of keys | `50` |
| `--cursor` | `-c` | Pagination cursor | |

### Delete Key

```bash
platformctl kms key delete <key-id> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--pending-days` | `-p` | Days before permanent deletion | `7` |
| `--force` | `-f` | Skip pending deletion window | `false` |

### Rotate Key

```bash
platformctl kms key rotate <key-id> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--retain-old` | `-r` | Retain the old key version | `true` |

### Import Key

```bash
platformctl kms key import <key-id> [flags]
```

| Flag | Description |
|------|-------------|
| `--input` | Input file containing key material |
| `--algorithm` | Key algorithm |
| `--wrapping-key` | ID of key used to wrap the imported key |

### Export Key

```bash
platformctl kms key export <key-id> [flags]
```

| Flag | Description |
|------|-------------|
| `--output` | Output file for wrapped key |
| `--wrapping-key` | ID of key to wrap the exported key |
| `--format` | Export format |

### Versions

```bash
platformctl kms key versions <key-id> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--limit` | `-l` | Maximum versions to return | `50` |
| `--cursor` | | Pagination cursor | |

### Revoke Key

```bash
platformctl kms key revoke <key-id> [flags]
```

Revoke a key, marking it unusable for all cryptographic operations.

| Flag | Description |
|------|-------------|
| `--reason` | Reason for revocation (audit trail) |

**Examples:**

```bash
# Revoke a key with reason
platformctl kms key revoke compromised-key --reason "Suspected compromise"

# Revoke with implied reason
platformctl kms key revoke old-key --reason "Key rotation completed"
```

### Status

```bash
platformctl kms key status <key-id> <enable|disable>
```

Enable or disable a key for future operations (revocation is permanent).

### Metadata

Manage key metadata without exposing key material.

#### Get Key Metadata

```bash
platformctl kms key metadata get <key-id>
```

Retrieves name, description, tags, creation timestamp, and last updated timestamp.

**Example Output:**

```
Key Metadata for: my-encryption-key

Name:           My Encryption Key
Description:    Production encryption key
Status:         ENABLED
Algorithm:      AES-256-GCM
Created:        2025-01-15 10:30:00 UTC
Modified:       2025-01-16 14:20:00 UTC
Tags:
  team=security
  environment=production
  cost-center=cc-123
```

#### Update Key Metadata

```bash
platformctl kms key metadata update <key-id> [flags]
```

Update mutable fields (name, description, tags) without modifying the key material or status.

| Flag | Description |
|------|-------------|
| `--name` | New display name |
| `--description` | New description |
| `--tags` | Add or update tags (key=value format, comma-separated) |
| `--remove-tags` | Remove tags by key name (comma-separated) |

**Examples:**

```bash
# Update name and description
platformctl kms key metadata update my-key \
  --name "Updated Key Name" \
  --description "Updated description"

# Add/update tags
platformctl kms key metadata update my-key \
  --tags "env=production,owner=alice,cost-center=cc-123"

# Remove tags
platformctl kms key metadata update my-key \
  --remove-tags "old-tag,deprecated"

# Combined update
platformctl kms key metadata update my-key \
  --name "New Name" \
  --tags "status=active" \
  --remove-tags "status=inactive"
```

### Policy

Manage key access control policies.

#### Get Key Policy

```bash
platformctl kms key policy get <key-id>
```

Retrieves the access control policy for a key, including allowed operations, principals, expiration, and usage limits.

**Example Output:**

```
Key Policy for: my-encryption-key

Version:            2
Allowed Operations: ENCRYPT, DECRYPT, WRAP_KEY
Allowed Principals: user:alice, service:app-api
Denied Principals:  user:bob
Expires:            2026-01-15 10:30:00 UTC (expires in 364 days)
Rotation Required:  false
Max Usage Count:    unlimited
Require MFA:        false
Last Updated:       2025-01-16 14:20:00 UTC
```

#### Set Key Policy

```bash
platformctl kms key policy set <key-id> [flags]
```

Set the access control policy for a key. All operations are allowed if no policy is set.

| Flag | Description |
|------|-------------|
| `--allowed-operations` | Permitted operations: ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, DERIVE_KEY (comma-separated) |
| `--allowed-principals` | Authorized users/services (comma-separated); format: user:name, service:name, role:name |
| `--denied-principals` | Explicitly denied users/services (comma-separated) |
| `--expires-at` | Unix timestamp when policy expires (0 = never expires) |
| `--rotation-required` | Require key rotation before further use (true/false) |
| `--max-usage-count` | Maximum number of operations (0 = unlimited) |
| `--require-mfa` | Require MFA for key usage (true/false) |

**Examples:**

```bash
# Restrict operations and principals
platformctl kms key policy set my-key \
  --allowed-operations "ENCRYPT,DECRYPT" \
  --allowed-principals "user:alice,service:app-api"

# Set policy with expiration and usage limit
platformctl kms key policy set sensitive-key \
  --allowed-operations "SIGN,VERIFY" \
  --allowed-principals "user:admin" \
  --expires-at 1735689600 \
  --max-usage-count 1000000 \
  --require-mfa true

# Deny specific principals
platformctl kms key policy set limited-key \
  --allowed-principals "service:trusted-app" \
  --denied-principals "service:untrusted-app"
```

### Algorithms

```bash
platformctl kms key algorithms
```

List all cryptographic algorithms supported by the KMS backend.

**Example Output:**

```
KMS Supported Algorithms

Symmetric Algorithms:
  AES-128-GCM      - AES-128 in GCM mode (128-bit key)
  AES-192-GCM      - AES-192 in GCM mode (192-bit key)
  AES-256-GCM      - AES-256 in GCM mode (256-bit key, recommended)
  CHACHA20-POLY1305 - ChaCha20 stream cipher with Poly1305 MAC

Asymmetric Algorithms (Signing):
  ECDSA-P256       - NIST P-256 curve (256-bit, fast)
  ECDSA-P384       - NIST P-384 curve (384-bit)
  ECDSA-P521       - NIST P-521 curve (521-bit, maximum security)
  ED25519          - Edwards curve (25519, ultra-fast signing)
  ED448            - Edwards curve (448, high security signing)

Asymmetric Algorithms (Encryption):
  RSA-2048         - RSA 2048-bit modulus (legacy compatibility)
  RSA-3072         - RSA 3072-bit modulus (balanced security)
  RSA-4096         - RSA 4096-bit modulus (maximum security)

HMAC Algorithms:
  HMAC-SHA256      - HMAC with SHA-256
  HMAC-SHA384      - HMAC with SHA-384
  HMAC-SHA512      - HMAC with SHA-512
```

### Backend Test

```bash
platformctl kms key backend-test
```

### Safety Limits

```bash
platformctl kms key safety set <key-id> [flags]
platformctl kms key safety clear <key-id>
```

| Flag | Description |
|------|-------------|
| `--max-operations` | Maximum encryption operations |
| `--max-bytes` | Maximum bytes to encrypt |
| `--warning-percent` | Warning threshold percentage |

## DEK Management (`platformctl kms dek`)

### Commands

| Command | Description |
|---------|-------------|
| `create` | Create a new DEK |
| `get` | Get DEK metadata |
| `list` | List all DEKs |
| `delete` | Delete a DEK |
| `rotate` | Rotate a DEK |
| `status` | Get detailed DEK status |
| `set-default` | Mark DEK as default |
| `set-safety` | Set AEAD safety limits |
| `clear-safety` | Clear safety limits |

### Create DEK

```bash
platformctl kms dek create <path> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--algorithm` | `-a` | DEK algorithm | `aes-256-gcm` |
| `--description` | `-d` | Description | |
| `--max-operations` | | Max encryption operations | `0` (unlimited) |
| `--max-bytes` | | Max bytes to encrypt | `0` (unlimited) |
| `--warning-percent` | | Warning threshold | `80` |

**Examples:**

```bash
platformctl kms dek create /tenant/myapp/default
platformctl kms dek create /tenant/myapp/fast --algorithm chacha20-poly1305
platformctl kms dek create /tenant/myapp/limited \
  --max-operations 1000000 \
  --max-bytes 10737418240
```

### Get DEK

```bash
platformctl kms dek get <path>
```

### List DEKs

```bash
platformctl kms dek list [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--prefix` | `-p` | Filter by path prefix | |
| `--recursive` | `-r` | Include subdirectories | `true` |
| `--limit` | `-l` | Maximum DEKs to return | `100` |
| `--cursor` | | Pagination cursor | |

### Delete DEK

```bash
platformctl kms dek delete <path> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--force` | `-f` | Force deletion | `false` |
| `--migrate-to` | | Migrate data to another DEK | |

### Rotate DEK

```bash
platformctl kms dek rotate <path> [flags]
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--background` | `-b` | Run re-encryption in background | `false` |

### Status

```bash
platformctl kms dek status <path>
```

### Set Default

```bash
platformctl kms dek set-default <path>
```

### Safety Limits

```bash
platformctl kms dek set-safety <path> [flags]
platformctl kms dek clear-safety <path>
```

## Secrets Management (`platformctl kms secrets`)

### Commands

| Command | Description |
|---------|-------------|
| `store` | Store a secret |
| `get` | Retrieve a secret |
| `list` | List all secrets |
| `delete` | Delete a secret |
| `rotate` | Rotate a secret |
| `version` | Get specific version |
| `versions` | List all versions |
| `rollback` | Rollback to previous version |
| `status` | Update secret status |
| `policy` | Manage rotation policy |
| `prefix` | Get secrets by prefix |
| `watch` | Watch for secret changes |

### Store Secret

```bash
platformctl kms secrets store <name> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--value` | Secret value (reads stdin if not provided) | |
| `--description` | Description | |
| `--tenant-id` | Tenant ID for isolation | |
| `--key-id` | Custom key identifier | |
| `--algorithm` | Encryption algorithm | `AES-256-GCM` |

**Examples:**

```bash
# Store with value flag
platformctl kms secrets store api-key --value "my-secret-value"

# Store from stdin
echo -n "my-secret" | platformctl kms secrets store piped-secret

# Store with tenant isolation
platformctl kms secrets store tenant-secret \
  --value "secret" \
  --tenant-id tenant-123
```

### Get Secret

```bash
platformctl kms secrets get <name>
```

### List Secrets

```bash
platformctl kms secrets list [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Maximum secrets to return | `100` |
| `--cursor` | Pagination cursor | |

### Delete Secret

```bash
platformctl kms secrets delete <name> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--permanent` | Permanently delete | `false` |

### Rotate Secret

```bash
platformctl kms secrets rotate <name> [flags]
```

| Flag | Description |
|------|-------------|
| `--value` | New secret value (reads stdin if not provided) |
| `--tenant-id` | Tenant ID |
| `--key-id` | Custom key identifier |
| `--algorithm` | Encryption algorithm |

### Version

```bash
platformctl kms secrets version <name> <version-number>
```

### Versions

```bash
platformctl kms secrets versions <name> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Maximum versions to return | `50` |
| `--cursor` | Pagination cursor | |

### Rollback

```bash
platformctl kms secrets rollback <name> --version <version-number>
```

### Status

```bash
platformctl kms secrets status <name> <enable|disable>
```

### Policy

```bash
platformctl kms secrets policy get <name>
platformctl kms secrets policy set <name> [flags]
```

| Flag | Description |
|------|-------------|
| `--enabled` | Enable auto-rotation |
| `--interval` | Rotation interval (e.g., "90d", "2160h") |
| `--retain-versions` | Number of versions to retain |

### Prefix

```bash
platformctl kms secrets prefix <prefix> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--include-data` | Include secret data | `false` |
| `--limit` | Maximum secrets | `100` |

### Watch

```bash
platformctl kms secrets watch <name>
```

## Cryptographic Operations (`platformctl kms crypto`)

### Commands

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt data |
| `decrypt` | Decrypt data |
| `sign` | Sign data |
| `verify` | Verify signature |
| `hash` | Compute hash |
| `hmac` | Generate or verify HMAC |
| `random` | Generate random bytes |
| `rewrap` | Re-encrypt with latest key version |
| `batch` | Batch encrypt/decrypt operations |
| `datakey` | Generate data encryption key |

### Encrypt

```bash
platformctl kms crypto encrypt --key-id <key> [flags]
```

| Flag | Description |
|------|-------------|
| `--key-id` | Key ID for encryption |
| `--input` | Input file (reads stdin if not provided) |
| `--output` | Output file (writes stdout if not provided) |
| `--context` | Additional authenticated data |
| `--base64` | Output as base64 |

**Examples:**

```bash
# Encrypt a file
platformctl kms crypto encrypt --key-id mykey --input data.txt --output data.enc

# Encrypt from stdin
echo "secret data" | platformctl kms crypto encrypt --key-id mykey --base64
```

### Decrypt

```bash
platformctl kms crypto decrypt --key-id <key> [flags]
```

| Flag | Description |
|------|-------------|
| `--key-id` | Key ID for decryption |
| `--input` | Input file |
| `--output` | Output file |
| `--context` | Additional authenticated data |
| `--base64-input` | Input is base64 encoded |

### Sign

```bash
platformctl kms crypto sign --key-id <key> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--key-id` | Signing key ID | |
| `--input` | Input file | |
| `--hash` | Hash algorithm | `SHA256` |

### Verify

```bash
platformctl kms crypto verify --key-id <key> [flags]
```

| Flag | Description |
|------|-------------|
| `--key-id` | Signing key ID |
| `--input` | Message file |
| `--signature` | Signature file or base64 string |
| `--hash` | Hash algorithm |

### Hash

```bash
platformctl kms crypto hash [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--input` | Input file | |
| `--algorithm` | Hash algorithm | `SHA256` |

**Supported Algorithms:** `SHA256`, `SHA384`, `SHA512`, `SHA3-256`, `SHA3-384`, `SHA3-512`, `BLAKE2B-256`, `BLAKE2B-512`

### HMAC

```bash
platformctl kms crypto hmac --key-id <key> [flags]
platformctl kms crypto hmac verify --key-id <key> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--key-id` | HMAC key ID | |
| `--input` | Input file | |
| `--hash` | Hash algorithm | `SHA256` |
| `--mac` | (verify only) MAC to verify | |

### Random

```bash
platformctl kms crypto random --bytes <count> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--bytes` | Number of bytes | `32` |
| `--output` | Output file | |
| `--base64` | Output as base64 | `true` |
| `--hex` | Output as hex | `false` |

### Rewrap

```bash
platformctl kms crypto rewrap --key-id <key> [flags]
```

Re-encrypts ciphertext with the latest key version.

| Flag | Description |
|------|-------------|
| `--key-id` | Key ID |
| `--input` | Ciphertext file |
| `--output` | Output file |

### Batch

```bash
platformctl kms crypto batch --key-id <key> --operation <encrypt|decrypt> [flags]
```

| Flag | Description |
|------|-------------|
| `--key-id` | Key ID |
| `--operation` | `encrypt` or `decrypt` |
| `--input` | JSON file with items array |
| `--output` | Output file |

### Datakey

```bash
platformctl kms crypto datakey --key-id <key> [flags]
```

Generates a data encryption key for envelope encryption.

| Flag | Description | Default |
|------|-------------|---------|
| `--key-id` | Wrapping key ID | |
| `--algorithm` | DEK algorithm | `AES-256-GCM` |
| `--plaintext` | Include plaintext DEK | `false` |

## KMS Status (`platformctl kms status`)

```bash
platformctl kms status
```

**Example Output:**

```
KMS Backend Status: [HEALTHY] healthy

Backend Type:   hybrid
Device:         /dev/tpmrm0
Region:         us-east-1

PCR Configuration:
  PCR Banks:    SHA256, SHA384
  PCR Registers: 0, 1, 7

Capabilities:
Capability       Supported
Encrypt          Yes
Decrypt          Yes
Sign             Yes
Verify           Yes
Wrap Key         Yes
Derive Key       Yes

Retrieved At:   2025-01-15 10:30:00 UTC
```

## Global Options

All KMS commands support these global flags:

| Option | Description |
|--------|-------------|
| `--config` | Config file path |
| `--output` | Output format (`table`, `json`, `yaml`) |
| `--server` | Server address |
| `--timeout` | Request timeout |

## Examples

### Production Key Setup

```bash
# Create master encryption key
platformctl kms key generate master-key \
  --algorithm aes-256-gcm \
  --purpose encrypt,decrypt \
  --deletion-protection \
  --name "Master Encryption Key"

# Create signing key
platformctl kms key generate signing-key \
  --algorithm ecdsa-p256 \
  --purpose sign,verify \
  --deletion-protection

# Create DEK for application data
platformctl kms dek create /app/production/data \
  --algorithm aes-256-gcm \
  --description "Production data encryption"
```

### Multi-Tenant Setup

```bash
# Create tenant-specific DEKs
platformctl kms dek create /tenant/acme/default \
  --description "ACME Corp data encryption"

platformctl kms dek create /tenant/widgets/default \
  --description "Widgets Inc data encryption"

# Store tenant secrets
platformctl kms secrets store api-key \
  --value "acme-key-123" \
  --tenant-id acme

platformctl kms secrets store api-key \
  --value "widgets-key-456" \
  --tenant-id widgets
```

### Key Rotation Workflow

```bash
# Rotate a key
platformctl kms key rotate my-key --retain-old

# Rotate a DEK with background re-encryption
platformctl kms dek rotate /tenant/myapp/default --background

# Check rotation status
platformctl kms dek status /tenant/myapp/default

# Rotate a secret
platformctl kms secrets rotate api-key --value "new-api-key-value"
```

### Encryption Workflow

```bash
# Generate a key
platformctl kms key generate file-encryption --algorithm aes-256-gcm

# Encrypt a file
platformctl kms crypto encrypt \
  --key-id file-encryption \
  --input sensitive.txt \
  --output sensitive.enc

# Decrypt the file
platformctl kms crypto decrypt \
  --key-id file-encryption \
  --input sensitive.enc \
  --output sensitive.txt
```
