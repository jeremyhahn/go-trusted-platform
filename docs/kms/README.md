# Trusted Platform Key Management Service

Unified key management with multi-backend support, hardware security integration, and QuicBaaS distributed storage.

## Overview

The Trusted Platform KMS provides centralized key management for all cryptographic operations. It wraps QuicBaaS's KMSService with platform-specific functionality including TPM hardware security, HSM integration, and multi-backend routing.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Backend** | Software, TPM2, PKCS#11, AWS KMS, Azure Key Vault, GCP Cloud KMS |
| **QuicBaaS Integration** | Distributed, replicated key storage with ACID guarantees |
| **TPM Hardware Security** | Hardware-bound keys with PCR-sealed policies |
| **Key Hierarchy** | Master Key -> DEK -> User Keys -> Data encryption |
| **Key Versioning** | Multiple versions with automatic rotation |
| **Policy Management** | Per-key access control and usage policies |
| **AEAD Safety** | Usage tracking per NIST SP 800-38D limits |
| **Hybrid Mode** | Seamless software + TPM backend routing |

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        Trusted Platform KMS                               │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   platformd wraps QuicBaaS KMSService     Multi-backend routing           │
│    with TPM/HSM hardware integration      Automatic fallback support      │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Backend Selection:                                                      │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────┐   │
│   │  Software   │    │    TPM2     │    │   PKCS#11   │    │  Cloud   │   │
│   │  (QuicBaaS) │    │  Hardware   │    │    HSM      │    │   KMS    │   │
│   └─────────────┘    └─────────────┘    └─────────────┘    └──────────┘   │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Key Location Hierarchy:                                                 │
│                                                                           │
│   Software       High throughput, full algorithm support                  │
│   TPM            Hardware-bound, platform attestation                     │
│   HSM            FIPS 140-2/3 compliance, high security                   │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Key Operations:                                                         │
│                                                                           │
│   Generate   Create new keys with algorithm and location                  │
│   Import     Bring Your Own Key (BYOK) support                            │
│   Export     Key wrapping for secure transport                            │
│   Rotate     Version-based rotation with retention                        │
│   Revoke     Mark compromised with audit trail                            │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Key Management Configuration

Key management in the Trusted Platform is configured through the Certificate Authority and TPM sections. There is no standalone top-level `kms:` section.

#### Certificate Authority Key Stores

Configure key stores for CA operations under `certificate-authority.identity[].keystores`:

```yaml
certificate-authority:
  identity:
    - keystores:
        software:
          platform-policy: true
        pkcs11:
          library: /usr/lib/softhsm/libsofthsm2.so
          config: trusted-data/etc/softhsm.conf
          slot: 0
          label: SoftHSM
          pin: 123456
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: 123456
          platform-policy: true
```

#### CA Key Definitions

Define keys under `certificate-authority.identity[].keys`:

```yaml
certificate-authority:
  identity:
    - keys:
        # PKCS #8 RSA
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
          debug: true

        # TPM 2.0 ECDSA
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: 123456
          platform-policy: true
          debug: true

        # PKCS #8 Ed25519
        - algorithm: Ed25519
          ecc:
            curve: P-256
          signature-algorithm: Ed25519
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
          debug: true
```

#### TPM Keystore Configuration

Configure the TPM keystore under `tpm.keystore`:

```yaml
tpm:
  device: /dev/tpmrm0
  keystore:
    srk-handle: 0x81000002
    srk-auth: 123456
    platform-policy: true
```

#### Web Service Keys

Configure web service keys under `webservices[].key`:

```yaml
webservices:
  - name: public
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: software
      password: 123456
      platform-policy: true
      debug: true
```

### Generate a Key

```bash
# Generate AES-256-GCM key (software backend)
platformctl kms key generate my-encryption-key

# Generate with specific algorithm
platformctl kms key generate signing-key --algorithm ECDSA-P256

# Generate TPM-backed key (hybrid backend)
platformctl kms key generate secure-key --location tpm
```

### List Keys

```bash
# List all keys
platformctl kms key list

# List keys with filter
platformctl kms key list --algorithm AES-256-GCM --status enabled
```

### Encrypt/Decrypt

```bash
# Encrypt data
platformctl kms encrypt my-encryption-key --data "sensitive data"

# Decrypt data
platformctl kms decrypt my-encryption-key --data "<ciphertext>"
```

### Rotate Key

```bash
# Rotate key (creates new version)
platformctl kms key rotate my-encryption-key
```

## Key Types and Algorithms

### Symmetric Algorithms

| Algorithm | Key Size | Use Case | TPM Support |
|-----------|----------|----------|-------------|
| `AES-128-GCM` | 128-bit | Fast encryption | Yes |
| `AES-192-GCM` | 192-bit | Balanced security | Yes |
| `AES-256-GCM` | 256-bit | Strong encryption (recommended) | Yes |
| `CHACHA20-POLY1305` | 256-bit | Modern stream cipher | Software only |

### Asymmetric Algorithms (Signing)

| Algorithm | Curve/Size | Use Case | TPM Support |
|-----------|------------|----------|-------------|
| `ECDSA-P256` | P-256 | NIST compliance (recommended) | Yes |
| `ECDSA-P384` | P-384 | Higher security | Yes |
| `ECDSA-P521` | P-521 | Maximum security | Software only |
| `ED25519` | Curve25519 | Fast signing | Software only |
| `ED448` | Curve448 | High security signing | Software only |

### Asymmetric Algorithms (RSA)

| Algorithm | Key Size | Use Case | TPM Support |
|-----------|----------|----------|-------------|
| `RSA-2048` | 2048-bit | Legacy compatibility | Yes |
| `RSA-3072` | 3072-bit | Balanced security | Yes |
| `RSA-4096` | 4096-bit | Maximum security | Yes |

### HMAC Algorithms

| Algorithm | Hash | Use Case |
|-----------|------|----------|
| `HMAC-SHA256` | SHA-256 | Message authentication |
| `HMAC-SHA384` | SHA-384 | Higher security |
| `HMAC-SHA512` | SHA-512 | Maximum security |

## Backend Support

| Backend | Description | Hardware | Use Case |
|---------|-------------|----------|----------|
| `memory` | In-memory storage | No | Testing only |
| `local` | File-based QuicBaaS | No | Single-node deployments |
| `hybrid` | Software + TPM | Yes | Production with hardware security |
| `tpm2` | TPM 2.0 sealed keys | Yes | Hardware-bound keys |
| `pkcs11` | HSM via PKCS#11 | Yes | FIPS compliance |
| `awskms` | AWS Key Management Service | Cloud | AWS deployments |
| `azurekv` | Azure Key Vault | Cloud | Azure deployments |
| `gcpkms` | GCP Cloud KMS | Cloud | GCP deployments |

## Key Locations

| Location | Security | Performance | Exportable | Platform Binding |
|----------|----------|-------------|------------|------------------|
| Software | Medium | High | Yes | No |
| TPM | High | Medium | No | Yes (PCR sealed) |
| HSM | Very High | Medium | Configurable | Device-specific |
| Cloud | High | Variable | Configurable | Provider-specific |

## Configuration

Key management is configured through several platform configuration sections:

```yaml
# TPM Configuration (including keystore)
tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: false
  entropy: false
  hash: SHA-256
  keystore:
    srk-handle: 0x81000002
    srk-auth: 123456
    platform-policy: true

# Certificate Authority with Key Stores and Keys
certificate-authority:
  platform-ca: 1
  identity:
    - keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: 123456
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: 123456
          platform-policy: true

# Web Service Keys
webservices:
  - name: public
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: software
      password: 123456
      platform-policy: true
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Key hierarchy and backend integration |
| [Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | API overview and navigation |
| [REST API Reference](api-reference-rest.md) | REST endpoint documentation (new lifecycle operations) |
| [QUIC API Reference](api-reference-quic.md) | QUIC opcode documentation (extended + secrets categories) |
| [MCP API Reference](api-reference-mcp.md) | MCP tools documentation (32 tools) |
| [CLI Usage](cli-usage.md) | Command-line interface with new key lifecycle commands |
| [Roadmap](ROADMAP.md) | Development roadmap and progress tracker |

## Integration

The KMS integrates with other platform components:

- **Certificate Authority** - Key storage for CA operations
- **ACME Server** - Key management for certificate lifecycle
- **Web Services** - TLS key management
- **Data Encryption** - Key storage for encrypted data
- **TPM Operations** - Hardware-backed key sealing

## Related Documentation

| Document | Description |
|----------|-------------|
| [KMS Overview](overview.md) | Deep-dive into KMS architecture, backends, and usage examples |
| [YubiKey Integration](yubikey.md) | YubiKey PIV slots, PKCS#11 mappings, and OTP configuration |

## See Also

- [QuicBaaS KMS Documentation](https://github.com/jeremyhahn/go-quicbaas/tree/main/docs/kms)
- [TPM Documentation](../tpm/README.md)
- [Security Overview](../architecture/reference.md)
