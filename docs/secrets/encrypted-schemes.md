# Encrypted URI Schemes: `encrypted://` and `idevid://`

This document describes the two encryption schemes available for storing secrets in configuration files. Both provide secure storage of sensitive values without exposing plaintext credentials.

## Overview

| Scheme | Encryption | Key Location | Use Case | Multi-Node |
|--------|-----------|--------------|----------|-----------|
| `encrypted://` | AES-256-GCM | Platform KMS | Shared secrets | Yes (all nodes) |
| `idevid://` | RSA-OAEP | Node's TPM/XKMS | Per-node secrets | No (single node) |

## encrypted:// Scheme

Platform-wide encryption using AES-256-GCM.

### Features

- **Encryption**: AES-256-GCM with AEAD authentication
- **Key storage**: Platform KMS (QuicBaaS)
- **Scope**: All nodes in the platform cluster
- **Decryption**: Automatic at config load time
- **Rotation**: Supported via key re-encryption

### Format

```yaml
# Standard URI format
field: "encrypted://base64-encoded-ciphertext"

# Shorthand format
field: "encrypted:base64-encoded-ciphertext"
```

### Key Management

The encryption key is configured in the platform setup:

```go
config.EncryptionKey = "kms://config/encryption/aes-256-gcm"
```

The key reference points to a KMS-managed AES-256 key.

### Creating Encrypted Values

Using `platformctl`:

```bash
# Encrypt a secret
platformctl encrypt --scheme encrypted "my-database-password"

# Output:
# encrypted://BgMFBQcKDQkQEgIDAQABBAIDAQABBAP...
```

Using Go API:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"

// Create an EncryptedResolver with decryption capability
decryptFn := func(ctx context.Context, ct []byte) ([]byte, error) {
    return kms.DecryptAESGCM(ctx, keyID, ct)
}
resolver := secrets.NewEncryptedResolver(decryptFn, logger)

// Encrypt a value (requires encryptor interface)
ciphertext, err := kms.EncryptAESGCM(ctx, keyID, []byte("secret"))
b64 := base64.StdEncoding.EncodeToString(ciphertext)
// URI: "encrypted://" + b64
```

### Configuration Example

```yaml
switches:
  - name: core-switch
    vendor: cisco-nexus
    mgmt-ip: 10.0.1.50
    ssh_user: admin
    ssh_password: "encrypted://BgMFBQcKDQkQEgIDAQABBAIDAQABBAP..."

database:
  host: postgres.example.com
  username: platformd
  password: "encrypted://XYZ789abc..."

ldap:
  url: ldap://ldap.example.com
  bind_dn: "cn=admin,dc=example,dc=com"
  bind_password: "encrypted://qwertyuiopASDFGH..."
```

### Decryption at Runtime

Configuration loader automatically decrypts `encrypted://` values:

```go
config, err := app.LoadConfig("config.yaml", logger)
// All encrypted:// values are automatically resolved
// config.Switches[0].SSHPassword = "admin-password" (plaintext in memory)
```

### Advantages

- ✅ Single platform key encrypts all node secrets
- ✅ Credentials shareable across all cluster nodes
- ✅ Key rotation supported
- ✅ Safe to store in version control (encrypted values)
- ✅ No TPM required for decryption

### Limitations

- ❌ Platform key compromise exposes all secrets
- ❌ Not suitable for per-node sensitive data
- ❌ All nodes have equal access to all secrets

### Security Considerations

**Key Storage:**
- Key must be protected in KMS
- KMS access should be ACL-restricted
- Consider key rotation schedule

**Value Security:**
- Encrypted values are safe in Git/version control
- Plaintext values in config files are decrypted at load time
- Runtime environment should protect plaintext values

## idevid:// Scheme

Per-node encryption using RSA-OAEP with the node's IDevID certificate.

### Features

- **Encryption**: RSA-OAEP with SHA-256
- **Key storage**: Node's TPM or XKMS
- **Scope**: Single node only
- **Decryption**: Requires node's IDevID private key
- **Rotation**: Not supported (requires re-provisioning)

### Format

```yaml
# Standard URI format
field: "idevid://base64-encoded-ciphertext"

# Shorthand format
field: "idevid:base64-encoded-ciphertext"
```

### Key Management

IDevID keys are provisioned during node bootstrap:

```go
// During node provisioning
idevidKey, err := tpm.GenerateKey(tpm.HandleIDevID)
if err != nil {
    return err
}

// Private key stored in TPM, never exported
// Public key in IDevID certificate
```

### Creating Encrypted Values

Using `platformctl`:

```bash
# Encrypt for specific node
platformctl encrypt --scheme idevid --node-id "lab-node-1" "my-secret"

# Output (node-specific):
# idevid://BQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk...
```

Using Go API:

```go
import (
    "crypto/rsa"
    "crypto/rand"
    "github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
)

// Encrypt with IDevID public key from certificate
publicKey := idevidCert.PublicKey.(*rsa.PublicKey)

ciphertext, err := rsa.EncryptOAEP(
    sha256.New(),
    rand.Reader,
    publicKey,
    []byte("secret"),
    nil,
)
b64 := base64.StdEncoding.EncodeToString(ciphertext)
// URI: "idevid://" + b64
```

### Configuration Example

```yaml
# Node lab-node-1 specific secrets
nodeid: "lab-node-1"

# Device-specific key encrypted to this node's IDevID
device:
  unlock_key: "idevid://BQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk..."
  cert_pin: "idevid://FxYVFBMSEREQDw4NDAwLCgoJCAcGBQQDAgE..."

# TPM configuration per-node
tpm:
  srk_auth: "idevid://node-specific-srk-auth-encrypted..."
```

### Decryption at Runtime

Configuration loader decrypts `idevid://` values using node's IDevID key:

```go
config, err := app.LoadConfig("config.yaml", logger)
// Requires IDevID private key from TPM
// Only works on the node it was encrypted for
```

### Advantages

- ✅ Per-node encryption (only that node can decrypt)
- ✅ IDevID key bound to specific TPM (FixedTPM attribute)
- ✅ Suitable for node-specific credentials
- ✅ Keys cannot be exported from TPM

### Limitations

- ❌ Cannot be decrypted on other nodes
- ❌ Requires TPM with IDevID key provisioned
- ❌ No key rotation (re-provisioning required)
- ❌ More operational complexity

### Security Considerations

**Key Protection:**
- IDevID private key never leaves TPM
- Hardware TPM provides maximum protection
- Key binding to specific chip via FixedTPM

**Value Security:**
- Encrypted values are safe in version control
- Decryption only possible on provisioned node
- Lost node = lost secrets (no recovery option)

**Backup Strategy:**
- No backup recovery available
- Secrets must be re-provisioned if node is rebuilt
- Consider backup node with shared `encrypted://` secrets

## Choosing Between Schemes

Use `encrypted://` for:
- Shared database passwords
- API keys for external services
- Credentials used by multiple nodes
- Values that need to be rotatable

Use `idevid://` for:
- Node-specific device credentials
- TPM owner authentication
- Per-node unlock keys
- Secrets that should not be transferable

## Using Both Schemes

Combine both in the same configuration:

```yaml
# Shared platform secrets (encrypted://)
database:
  password: "encrypted://platform-key-encrypted-value"

# Node-specific secrets (idevid://)
device:
  unlock_key: "idevid://node-specific-encrypted-value"

# Provisioned at each node
provisioning:
  # This is resolved per-node (its own IDevID key)
  credential: "idevid://unique-per-node-value"
```

## CLI Usage

### Encrypt with platformctl

```bash
# Platform key encryption (all nodes)
platformctl encrypt --scheme encrypted "shared-secret"

# IDevID encryption (specific node)
platformctl encrypt --scheme idevid --node-id "lab-node-1" "node-secret"

# Save to file for sharing
platformctl encrypt --scheme encrypted "password" > encrypted-secret.txt
```

### Decrypt (for testing only)

```bash
# Manually decrypt for troubleshooting
platformctl decrypt "encrypted://BgMFBQ..." --scheme encrypted

# IDevID decryption (node must be available)
platformctl decrypt "idevid://BQECAw..." --scheme idevid --node-id "lab-node-1"
```

## Error Handling

### "failed to decrypt encrypted:// value"

**Possible causes:**
- KMS key not available
- Wrong encryption key configured
- Corrupted ciphertext (bad base64)

**Resolution:**
1. Verify `config.encryption_key` setting
2. Verify KMS connectivity
3. Re-encrypt with correct key: `platformctl encrypt --scheme encrypted "secret"`

### "failed to decrypt idevid:// value"

**Possible causes:**
- TPM not accessible
- IDevID key not provisioned
- Wrong node ID
- Encrypted on different node

**Resolution:**
1. Verify TPM is accessible
2. Verify IDevID key exists: `tpm2_nvlist`
3. Ensure config is on correct node
4. Use `encrypted://` scheme as fallback for testing

### "invalid ciphertext"

**Possible causes:**
- Truncated base64 value
- Corrupted during copy/paste
- Wrong scheme used

**Resolution:**
1. Re-encrypt: `platformctl encrypt "secret"`
2. Update config with new value
3. Verify URL format matches: `encrypted://` or `idevid://`

## Migration from Plaintext

### Step 1: Identify Secrets

Find plaintext values in config:

```yaml
ssh_password: "my-password"  # Plaintext - needs encryption
api_key: "sk_live_xyz"       # Plaintext - needs encryption
```

### Step 2: Encrypt Each Value

```bash
$ platformctl encrypt --scheme encrypted "my-password"
encrypted://BgMFBQcKDQkQEgIDAQABBAIDAQABBAP...
```

### Step 3: Update Configuration

```yaml
ssh_password: "encrypted://BgMFBQcKDQkQEgIDAQABBAIDAQABBAP..."
api_key: "encrypted://XYZ789abc..."
```

### Step 4: Restart Platform

```bash
systemctl restart platformd
```

### Step 5: Verify

```bash
# Check that encrypted values are properly resolved
platformd --config config.yaml --dry-run

# Or use verification command
platformctl secrets verify --config config.yaml
```

## See Also

- [Secrets Framework](./README.md) - Overview of secrets system
- [Bootstrap Secrets](./bootstrap-secrets.md) - Secret migration during bootstrap
- [IDevID Design](../tpm/device-identity-design.md) - Device identity architecture
- [Configuration Guide](../configuration.md) - Full config file reference
