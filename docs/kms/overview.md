# Key Management Service (KMS)

The KMS package provides unified key management for the Trusted Platform, supporting both software-based keys (QuicBaaS) and hardware-backed keys (TPM).

## Architecture

The KMS is designed around a flexible architecture that supports multiple backends:

```
                    ┌──────────────────┐
                    │   KeyManager     │
                    │    Interface     │
                    └────────┬─────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
    ┌───────▼────────┐              ┌─────────▼────────┐
    │   QuicBaaS     │              │     Hybrid       │
    │   KeyManager   │              │     Manager      │
    └───────┬────────┘              └─────────┬────────┘
            │                                 │
            │                        ┌────────┴────────┐
            │                        │                 │
    ┌───────▼────────┐      ┌────────▼────────┐  ┌─────▼──────┐
    │   QuicBaaS     │      │   QuicBaaS      │  │    TPM     │
    │    Storage     │      │    Storage      │  │   Backend  │
    └────────────────┘      └─────────────────┘  └────────────┘
```

## Backends

### QuicBaaS Backend

QuicBaaS provides distributed, replicated key storage with ACID guarantees.

**Features:**
- Memory backend for testing
- Local file-based storage for single-node deployments
- Distributed storage for production clusters
- In-memory caching for performance
- Full algorithm support (AES, RSA, ECDSA, EdDSA)

**Configuration:**

Key stores for CA operations are configured under `certificate-authority.identity[].keystores`:

```yaml
certificate-authority:
  identity:
    - keystores:
        software:
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
```

### Hybrid Backend

The hybrid backend seamlessly integrates software (QuicBaaS) and TPM key management.

**Features:**
- Automatic backend selection based on key requirements
- TPM hardware protection for sensitive keys
- Software backend for high-performance operations
- Transparent routing between backends
- Graceful fallback when TPM unavailable

**Configuration:**

TPM-backed keys are configured by specifying `store: tpm2` and configuring the TPM keystore:

```yaml
tpm:
  device: /dev/tpmrm0
  keystore:
    srk-handle: 0x81000002
    srk-auth: 123456
    platform-policy: true

certificate-authority:
  identity:
    - keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: 123456
          platform-policy: true
      keys:
        # Software-backed key
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
        # TPM-backed key
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: 123456
          platform-policy: true
```

## Usage Examples

### Accessing KMS via Platform Application

The KMS is accessed through the platform SDK's unified interface:

```go
package main

import (
    "context"

    quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func main() {
    // Initialize platform SDK
    ctx := context.Background()
    client, err := platform.NewClient(ctx,
        platform.WithGRPCAddr("localhost:10443"),
    )
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Access KMS service through gRPC
    kms := client.Connection()
    kmsClient := quicbaassdk.NewKMSClient(kms)

    // Generate a key
    key, err := kmsClient.GenerateKey(ctx, &quicbaassdk.GenerateKeyRequest{
        Name:      "my-key",
        Algorithm: "AES-256-GCM",
    })
    if err != nil {
        panic(err)
    }

    // Encrypt data
    encrypted, err := kmsClient.Encrypt(ctx, &quicbaassdk.EncryptRequest{
        KeyID:     key.ID,
        Plaintext: []byte("sensitive data"),
    })
    if err != nil {
        panic(err)
    }

    // Decrypt data
    decrypted, err := kmsClient.Decrypt(ctx, &quicbaassdk.DecryptRequest{
        KeyID:      key.ID,
        Ciphertext: encrypted.Ciphertext,
    })
    if err != nil {
        panic(err)
    }
}
```

### CLI Usage

The `platformctl` CLI provides full KMS functionality:

```bash
# Generate keys
platformctl kms key generate my-encryption-key --algorithm AES-256-GCM
platformctl kms key generate my-signing-key --algorithm ECDSA-P256

# Encrypt/decrypt
platformctl kms crypto encrypt --key my-encryption-key --data "secret"
platformctl kms crypto decrypt --key my-encryption-key --ciphertext "<base64>"

# Manage secrets
platformctl kms secrets store api-key --value "sk-1234567890"
platformctl kms secrets get api-key

# DEK management
platformctl kms dek create /tenant/myapp/default --algorithm AES-256-GCM
platformctl kms dek rotate /tenant/myapp/default
```

### REST API Usage

```bash
# Generate a key
curl -X POST https://localhost:8443/api/v1/kms/keys \
  -H "Content-Type: application/json" \
  -d '{"key_spec": {"algorithm": "AES-256-GCM"}, "name": "my-key"}'

# Encrypt data
curl -X POST https://localhost:8443/api/v1/kms/encrypt/my-key \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "c2VjcmV0IGRhdGE="}'  # base64 encoded
```

## Supported Algorithms

### Symmetric Algorithms

| Algorithm | Key Size | Description |
|-----------|----------|-------------|
| AES256-GCM | 256-bit | AES in Galois/Counter Mode (recommended) |
| AES192-GCM | 192-bit | AES in Galois/Counter Mode |
| AES128-GCM | 128-bit | AES in Galois/Counter Mode |

### Asymmetric Algorithms (ECDSA)

| Algorithm | Curve | Description |
|-----------|-------|-------------|
| ECDSA-P256 | P-256 | NIST P-256 curve (recommended) |
| ECDSA-P384 | P-384 | NIST P-384 curve |
| ECDSA-P521 | P-521 | NIST P-521 curve |

### Asymmetric Algorithms (RSA)

| Algorithm | Key Size | Description |
|-----------|----------|-------------|
| RSA-2048 | 2048-bit | RSA with 2048-bit modulus |
| RSA-3072 | 3072-bit | RSA with 3072-bit modulus |
| RSA-4096 | 4096-bit | RSA with 4096-bit modulus (recommended) |

### Asymmetric Algorithms (EdDSA)

| Algorithm | Description | TPM Support |
|-----------|-------------|-------------|
| Ed25519 | Edwards-curve Digital Signature | Software only |

## Key Locations

Keys can be stored in different security domains:

| Location | Security | Performance | Exportable |
|----------|----------|-------------|------------|
| Software | Medium | High | Yes |
| TPM | High | Medium | No |
| HSM | Very High | Medium | No* |

*Depends on HSM configuration

## Configuration Options

KMS configuration is handled through the platform configuration file and QuicBaaS settings. Key configuration options include:

### Key Algorithm

Set the algorithm when generating keys via CLI or API:

```bash
platformctl kms key generate my-key --algorithm AES-256-GCM
platformctl kms key generate signing-key --algorithm ECDSA-P256
```

### Key Protection

Keys can be stored in different backends:
- `software` - QuicBaaS encrypted storage (default)
- `tpm2` - TPM 2.0 hardware-protected
- `pkcs11` - HSM via PKCS#11

Configure in platform config under `certificate-authority.identity[].keys[].store`.

### Deletion Protection

Enable deletion protection to prevent accidental key deletion:

```bash
platformctl kms key generate critical-key --deletion-protection
```

## Error Handling

The KMS API returns standard HTTP status codes and error types:

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized |
| 403 | Forbidden (key disabled, revoked, or policy violation) |
| 404 | Key/secret not found |
| 503 | Backend unavailable |

### Error Types

- `ErrKeyNotFound` - Key does not exist
- `ErrKeyAlreadyExists` - Key ID already in use
- `ErrKeyDisabled` - Key is disabled
- `ErrKeyCompromised` - Key is revoked/compromised
- `ErrVersionNotFound` - Key version does not exist
- `ErrInvalidInput` - Invalid parameter
- `ErrDeletionProtected` - Key has deletion protection
- `ErrStorageUnavailable` - Backend unavailable
- `ErrUnsupportedAlgorithm` - Algorithm not supported
- `ErrPolicyViolation` - Policy check failed

## Performance Considerations

### Software Keys

**Advantages:**
- High throughput for bulk operations
- Low latency for symmetric encryption
- Full algorithm support
- Easy backup and replication

**Trade-offs:**
- Keys stored in software (encrypted at rest)
- Exportable (can be copied)
- Software-based protection

### TPM Keys

**Advantages:**
- Hardware protection against extraction
- Platform binding (sealed to PCRs)
- Attestation capabilities
- Non-exportable keys

**Trade-offs:**
- Lower throughput due to hardware limitations
- Algorithm restrictions (no Ed25519)
- Single-device binding

## Security Model

### Defense in Depth

1. **Key Material Protection:**
   - Encryption at rest in QuicBaaS
   - Hardware protection in TPM
   - Secure key derivation
   - Optional caching with TTL

2. **Access Control:**
   - Authentication required for operations
   - Authorization checks per operation
   - Audit logging of all operations

3. **Key Lifecycle:**
   - Secure generation with hardware RNG
   - Rotation support
   - Revocation capabilities
   - Secure deletion (zeroing memory)

## Testing

### Unit Tests

Unit tests cover the REST API handlers, CLI command logic, and service layer:

```bash
# Run REST API tests
go test ./pkg/webservice/v1/rest/kms/...

# Run CLI tests
go test ./pkg/cli/commands/kms/...
```

**Coverage:**
- REST API: 99.9%
- CLI testable functions: 100%

### Integration Tests

Multi-protocol integration tests verify all 29 KMS operations across 6 protocols:

```bash
# Run in devcontainer
make integration-test-kms
```

**Test Coverage:**
- CLI adapter - 29 operations
- REST adapter - 29 operations
- gRPC adapter - 29 operations
- QUIC adapter - 29 operations
- MCP adapter - 29 operations
- Unix socket adapter - 29 operations

**Total: 174 test executions**

## Integration

The KMS integrates with other platform components:

- **Certificate Authority:** Key storage for CA operations
- **ACME Server:** Key management for certificate lifecycle
- **Web Services:** TLS key management
- **Data Encryption:** Key storage for encrypted data

## Future Enhancements

- HSM backend support (PKCS#11)
- Key rotation automation
- Key escrow and recovery
- Multi-party computation
- Threshold cryptography
- Cloud KMS integration (AWS, Azure, GCP)

## References

- [QuicBaaS Documentation](https://github.com/jeremyhahn/go-quicbaas)
- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [go-xkms Package](https://github.com/jeremyhahn/go-xkms)
