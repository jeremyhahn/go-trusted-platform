# Provisioning Secrets

This document describes how secrets are provisioned to nodes in go-trusted-platform.

## Overview

The provisioning server provides secrets to nodes during activation using a secure, zero-trust approach. Secrets never travel in plaintext over the network. Instead, they are either:

1. **Encrypted to the node's IDevID certificate** - Only the target node can decrypt
2. **Fetched from a remote KMS** - Authenticated via mTLS with IDevID
3. **Auto-generated on first boot** - Created locally with cryptographic randomness

After resolution, secrets are migrated to the node's local KMS for unified access.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Provisioning   │     │   Node Boot     │     │   Local KMS     │
│     Server      │────>│  Secret Resolve │────>│   (QuicBaaS)    │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
   Encrypt to IDevID      Decrypt via TPM         Unified Access
   Store in Profile       Resolve URIs            kms:// references
```

## Provisioning Strategies

### remote-kms://

Fetches secrets from the provisioning server's KMS over mTLS.

```yaml
# Node configuration
kms:
  backends:
    tpm2:
      srk-auth: "remote-kms://secrets/node-001/srk-auth"
```

The node authenticates to the provisioning server using its IDevID certificate. The server verifies the certificate CN matches the requested secret path.

**URI Format:** `remote-kms://path/to/secret`

### encrypted:

Secrets pre-encrypted to the node's IDevID public key.

```yaml
# Node configuration (encrypted blob)
kms:
  backends:
    tpm2:
      srk-auth: "encrypted://SGVsbG8gV29ybGQhIFRoaXMgaXMgYW4gZW5jcnlwdGVkIHNlY3JldA=="
```

The provisioning server encrypts each secret using the node's IDevID certificate before including it in the device profile. Only the target node can decrypt via its TPM-backed IDevID private key.

**URI Format:** `encrypted://base64-encoded-ciphertext`

### autogen://

Generates random secrets on first boot.

```yaml
# Node configuration (auto-generate)
kms:
  backends:
    tpm2:
      srk-auth: "autogen://32/base64"
```

**URI Format:** `autogen://length/encoding`

| Parameter | Description | Options |
|-----------|-------------|---------|
| `length` | Bytes of randomness | 16, 32, 64, etc. |
| `encoding` | Output format | `base64`, `hex`, `raw` |

**Examples:**
- `autogen://32/base64` - 32 random bytes, base64 encoded
- `autogen://16/hex` - 16 random bytes, hex encoded
- `autogen://64` - 64 raw bytes

## IDevID Encryption

### How Encryption Works

Secrets are encrypted using RSA-OAEP with SHA-256 to the node's IDevID public key:

1. Provisioning server retrieves node's IDevID certificate from enrollment records
2. Extracts RSA public key from certificate
3. Encrypts secret using RSA-OAEP (SHA-256)
4. Base64-encodes ciphertext
5. Includes encrypted blob in device profile

### Decryption via TPM

The node decrypts using its TPM-backed IDevID private key:

1. Node receives encrypted secret in device profile
2. Secret resolver detects `encrypted://` prefix
3. Decodes base64 ciphertext
4. Calls TPM decrypt via IDevID key handle
5. Returns plaintext for migration to local KMS

### Encryption Command

Encrypt a secret to a node's IDevID certificate:

```bash
# Using openssl
openssl pkeyutl -encrypt \
  -pubin -inkey <(openssl x509 -in node-idevidcert.pem -pubkey -noout) \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -in secret.txt | base64 -w0

# Using platformctl
platformctl secrets encrypt \
  --cert /path/to/node-idevidcert.pem \
  --input "my-secret-value"
```

The output can be used directly as an `encrypted://` value in configuration.

## Remote KMS

### Setting Up Provisioning Server

Configure the provisioning server to serve secrets over mTLS:

```yaml
# Provisioning server config
api:
  tls:
    enabled: true
    client-auth: require-and-verify
    ca-file: /etc/trusted-platform/ca/ca.pem
    cert-file: /etc/trusted-platform/certs/server.pem
    key-file: /etc/trusted-platform/certs/server-key.pem

kms:
  enabled: true
  backends:
    quicbaas:
      enabled: true
      path: /var/lib/trusted-platform/kms
```

### mTLS Authentication

Nodes authenticate using their IDevID certificates:

1. Node presents IDevID certificate during TLS handshake
2. Server verifies certificate chain to trusted CA
3. Server extracts node identity from certificate CN
4. Server authorizes secret access based on node identity

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | HTTPS | REST API (mTLS) |
| 9443 | gRPC | High-performance access |

Ensure firewall allows provisioning VLAN (typically VLAN 998) to reach these ports.

## Activation Flow

The complete secret provisioning flow during node activation:

```
1. Node boots on provisioning network (VLAN 998)
                    │
                    ▼
2. Node requests device profile via mTLS
   POST /api/v1/device/activate
   (IDevID certificate authentication)
                    │
                    ▼
3. Provisioning server returns profile with secrets:
   - encrypted:// blobs (pre-encrypted to IDevID)
   - remote-kms:// references (fetch on-demand)
   - autogen:// directives (generate locally)
                    │
                    ▼
4. Node resolves each secret:
   - encrypted:// → TPM decrypt via IDevID
   - remote-kms:// → mTLS fetch from server
   - autogen:// → Generate with crypto/rand
                    │
                    ▼
5. Resolved secrets migrated to local KMS
   - Stored as kms://config/... paths
   - Config updated with kms:// references
                    │
                    ▼
6. Node transitions to production network
   - All secrets now local in QuicBaaS KMS
   - No further provisioning server access required
```

## Configuration Examples

### Provisioning Server Config

```yaml
# /etc/trusted-platform/provisioning-server.yaml
api:
  listen: ":8443"
  tls:
    enabled: true
    client-auth: require-and-verify
    ca-file: /etc/trusted-platform/ca/ca.pem

# Device profiles with encrypted secrets
devices:
  - serial: "NODE-001"
    secrets:
      srk-auth: "encrypted://SGVsbG8gV29ybGQh..."
      pin: "encrypted://U2VjcmV0IFBJTg==..."
```

### Node Config with remote-kms References

```yaml
# /etc/trusted-platform/node.yaml
secrets:
  enabled: true
  remote-kms: true
  migrate-to-kms: true

kms:
  backends:
    tpm2:
      srk-auth: "remote-kms://secrets/node-001/srk-auth"
      owner-auth: "remote-kms://secrets/node-001/owner-auth"
```

### Node Config with Encrypted Blobs

```yaml
# /etc/trusted-platform/node.yaml
secrets:
  enabled: true
  encrypted: true
  migrate-to-kms: true

kms:
  backends:
    tpm2:
      srk-auth: "encrypted://SGVsbG8gV29ybGQhIFRoaXMgaXMg..."
      owner-auth: "encrypted://VGhpcyBpcyBhbm90aGVyIGVuY3J5..."
```

### Mixed Strategy Config

```yaml
# /etc/trusted-platform/node.yaml
secrets:
  enabled: true
  auto-generate: true
  encrypted: true
  remote-kms: true
  migrate-to-kms: true
  update-config-file: true

kms:
  backends:
    tpm2:
      # Pre-provisioned encrypted secret
      srk-auth: "encrypted://SGVsbG8gV29ybGQh..."
      # Fetch from provisioning server
      owner-auth: "remote-kms://secrets/node-001/owner-auth"
      # Generate on first boot
      lockout-auth: "autogen://32/base64"
```

## Security Model

### TPM-Backed Decryption

- IDevID private key never leaves the TPM
- Decrypt operations happen inside TPM hardware
- Key is bound to the specific TPM chip (FixedTPM attribute)
- No software can extract the private key

### No Plaintext Secrets in Transit

| Strategy | Encryption in Transit | Encryption at Rest |
|----------|----------------------|-------------------|
| `encrypted://` | RSA-OAEP to IDevID | Base64 in config |
| `remote-kms://` | mTLS (TLS 1.2+) | KMS encryption |
| `autogen://` | N/A (local only) | Local KMS |

### Certificate-Based Authentication

- All network operations use mTLS with IDevID certificates
- Server verifies certificate chain to trusted CA
- Node identity derived from certificate CN/serial
- No shared secrets or pre-shared keys

### Post-Migration Security

After secrets are migrated to local KMS:

1. Original `encrypted://` values can be removed from config
2. Config updated with `kms://` references
3. Secrets protected by QuicBaaS encryption
4. Access controlled by local KMS policies

## Related Documentation

- [Bootstrap Secrets](bootstrap-secrets.md) - Secret migration during bootstrap
- [Device Provisioning](../provisioning/README.md) - Device enrollment workflow
- [Provisioning Client](../provisioning/client.md) - mTLS client implementation
- [TPM Configuration](../tpm/configuration.md) - TPM key and handle setup
- [IDevID Design](../tpm/device-identity-design.md) - Device identity architecture
