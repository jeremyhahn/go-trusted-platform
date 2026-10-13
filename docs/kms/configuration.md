# KMS Configuration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [engineering.md](engineering.md) §6. The platform config has no top-level `keystores:` block and no cloud-backend sections; platformd reads `tpm.platform-srk:` (`tpm.keystore:` is only a firstboot fallback); nothing reads `KMS_SRK_AUTH` or `PKCS11_PIN`; cloud backends are built in with `WITH_*` variables ([build-tags.md](../configuration/build-tags.md)), not `go build -tags`.

## Overview

Key management in the Trusted Platform is configured through several configuration sections rather than a standalone `kms:` block. Keys are managed through:

- `certificate-authority.identity[].keystores:` - Key store backends (software, pkcs11, tpm2)
- `certificate-authority.identity[].keys:` - Individual key definitions
- `tpm.keystore:` - TPM-specific keystore settings
- `webservices[].key:` - Web service TLS keys

## Key Store Configuration

### Software Key Store

Software-based key storage with platform policy support:

```yaml
certificate-authority:
  identity:
    - keystores:
        software:
          platform-policy: true
```

### TPM2 Key Store

Hardware-backed key storage using TPM 2.0:

```yaml
certificate-authority:
  identity:
    - keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: 123456
          platform-policy: true
```

### PKCS#11 Key Store (HSM)

HSM integration via PKCS#11:

```yaml
certificate-authority:
  identity:
    - keystores:
        pkcs11:
          library: /usr/lib/softhsm/libsofthsm2.so
          config: trusted-data/etc/softhsm.conf
          slot: 0
          label: SoftHSM
          pin: 123456
          platform-policy: true
```

## TPM Configuration

TPM settings are configured in the main TPM section:

```yaml
tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true
  entropy: true
  hash: SHA-256

  # Storage Root Key
  ssrk:
    handle: 0x81000001
    hierarchy-auth: ""
    password: ""
    platform-policy: true
    rsa:
      size: 2048

  # TPM Keystore configuration
  keystore:
    srk-handle: 0x81000002
    srk-auth: "${KMS_SRK_AUTH}"
    platform-policy: true
```

## Key Definition Configuration

Keys are defined under `certificate-authority.identity[].keys`:

```yaml
certificate-authority:
  identity:
    - keys:
        # RSA Key (Software Store)
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: true
          debug: true

        # ECDSA Key (TPM Store)
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: 123456
          platform-policy: true
          debug: true

        # Ed25519 Key (Software Store)
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

### Key Definition Fields

| Field | Description | Values |
|-------|-------------|--------|
| `algorithm` | Key algorithm | `RSA`, `ECDSA`, `Ed25519` |
| `rsa.size` | RSA key size | `2048`, `3072`, `4096` |
| `ecc.curve` | ECC curve | `P-256`, `P-384`, `P-521` |
| `signature-algorithm` | Signature algorithm | `SHA256-RSA`, `ECDSA-SHA256`, `Ed25519` |
| `hash` | Hash algorithm | `SHA-256`, `SHA-384`, `SHA-512` |
| `store` | Key store backend | `software`, `tpm2`, `pkcs11` |
| `password` | Key password | string |
| `platform-policy` | Enable platform policy | `true`, `false` |
| `debug` | Enable debug logging | `true`, `false` |

## Web Service Key Configuration

Web service TLS keys are configured under `webservices[].key`:

```yaml
webservices:
  - name: public
    port: 8080
    tls-port: 8443
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
    certificate:
      subject:
        cn: server.example.com
        organization: ACME Corporation
      sans:
        dns:
          - server.example.com
          - www.server.example.com
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KMS_SRK_AUTH` | TPM SRK authorization password | - |
| `PKCS11_PIN` | PKCS#11 token PIN | - |

## Complete Example

### Development Configuration

```yaml
# config.dev.yaml
debug: true
debug-secrets: true
platform-dir: trusted-data

tpm:
  device: /dev/tpmrm0
  simulator: true
  keystore:
    srk-handle: 0x81000002
    srk-auth: 123456
    platform-policy: false

certificate-authority:
  platform-ca: 1
  identity:
    - keystore-type: software
      keystores:
        software:
          platform-policy: false
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software
          password: 123456
          platform-policy: false
          debug: true
```

### Production Configuration (Software Only)

```yaml
# config.prod.yaml
debug: false
platform-dir: /var/lib/trusted-platform

certificate-authority:
  platform-ca: 1
  identity:
    - keystore-type: software
      keystores:
        software:
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: ${CA_KEY_PASSWORD}
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software
          password: ${CA_KEY_PASSWORD}
          platform-policy: true

webservices:
  - name: public
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: software
      password: ${WEBSERVICE_KEY_PASSWORD}
      platform-policy: true
```

### Production Configuration (with TPM)

```yaml
# config.prod-secure.yaml
debug: false
platform-dir: /var/lib/trusted-platform
pin-seal-policy: true

tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true
  entropy: true
  hash: SHA-256
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048
  ssrk:
    handle: 0x81000001
    platform-policy: true
    rsa:
      size: 2048
  keystore:
    srk-handle: 0x81000002
    srk-auth: ${KMS_SRK_AUTH}
    platform-policy: true

certificate-authority:
  platform-ca: 1
  identity:
    - keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: ${KMS_SRK_AUTH}
          platform-policy: true
      keys:
        # Software-backed RSA key
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: ${CA_KEY_PASSWORD}
          platform-policy: true
        # TPM-backed ECDSA key
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: ${CA_KEY_PASSWORD}
          platform-policy: true

webservices:
  - name: public
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: tpm2
      password: ${WEBSERVICE_KEY_PASSWORD}
      platform-policy: true
```

### High-Security Configuration (TPM + PCR Binding)

```yaml
# config.high-security.yaml
debug: false
platform-dir: /var/lib/trusted-platform
pin-seal-policy: true

tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true
  entropy: true
  hash: SHA-256

  # Bind to specific PCRs for boot chain validation
  golden-pcrs: [0, 7, 9]
  platform-pcr: 23
  platform-pcr-bank: sha256

  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048
  ssrk:
    handle: 0x81000001
    platform-policy: true
    rsa:
      size: 2048
  keystore:
    srk-handle: 0x81000002
    srk-auth: ${KMS_SRK_AUTH}
    platform-policy: true

certificate-authority:
  platform-ca: 1
  quantum-safe: true
  identity:
    - keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: ${KMS_SRK_AUTH}
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: ${CA_KEY_PASSWORD}
          platform-policy: true
```

## Validation

The configuration is validated at startup:

| Field | Validation |
|-------|------------|
| `tpm.device` | Device path must exist and be accessible |
| `tpm.keystore.srk-handle` | Must be a valid TPM handle |
| `certificate-authority.identity[].keys[].algorithm` | Must be RSA, ECDSA, or Ed25519 |
| `certificate-authority.identity[].keys[].store` | Must be software, tpm2, or pkcs11 |
| `webservices[].key.algorithm` | Must be a supported algorithm |

## Troubleshooting

### Common Issues

**TPM backend failing:**
```
Check: tpm.device path is correct (/dev/tpmrm0)
Check: TPM is not in use by another process
Check: User has permission to access TPM device
Check: tpm.keystore.srk-handle is valid
```

**Key generation failing:**
```
Check: Algorithm is supported by the specified store
Check: store field matches a configured keystore (software, tpm2, pkcs11)
Check: Required keystore is configured under certificate-authority.identity[].keystores
```

**PKCS#11 HSM issues:**
```
Check: pkcs11.library path points to valid PKCS#11 library
Check: pkcs11.slot number is correct
Check: pkcs11.pin is correct
```

**Certificate Authority key issues:**
```
Check: certificate-authority.identity[].keys[] has valid algorithm
Check: store value matches a configured keystore
Check: password is provided for protected keys
```

## Cloud Backend Configuration

go-trusted-platform supports cloud-based key management services for enterprise deployments. These backends require specific build tags to be enabled.

### AWS KMS

Build with: `go build -tags awskms`

```yaml
keystores:
  default-backend: awskms
  awskms:
    enabled: true
    region: us-east-1
    access-key-id: AKIAIOSFODNN7EXAMPLE
    secret-access-key: ${AWS_SECRET_ACCESS_KEY}
    session-token: ${AWS_SESSION_TOKEN}  # Optional, for temporary credentials
    endpoint: ""  # Optional, for LocalStack testing
    default-key-id: alias/my-platform-key
```

**Configuration Fields:**

| Field | Description | Required |
|-------|-------------|----------|
| `region` | AWS region (e.g., `us-east-1`) | Yes |
| `access-key-id` | AWS access key ID | No (uses IAM role if not set) |
| `secret-access-key` | AWS secret access key | No (uses IAM role if not set) |
| `session-token` | Session token for temporary credentials | No |
| `endpoint` | Custom KMS endpoint (for LocalStack) | No |
| `default-key-id` | Default KMS key ID/ARN/alias | No |

### GCP Cloud KMS

Build with: `go build -tags gcpkms`

```yaml
keystores:
  default-backend: gcpkms
  gcpkms:
    enabled: true
    project-id: my-gcp-project
    location-id: us-east1
    key-ring-id: my-keyring
    credentials-file: /path/to/service-account.json
```

**Configuration Fields:**

| Field | Description | Required |
|-------|-------------|----------|
| `project-id` | GCP project ID | Yes |
| `location-id` | GCP location (e.g., `us-east1`, `global`) | Yes |
| `key-ring-id` | KMS key ring identifier | Yes |
| `credentials-file` | Path to service account JSON | No (uses ADC if not set) |

### Azure Key Vault

Build with: `go build -tags azurekv`

```yaml
keystores:
  default-backend: azurekv
  azurekv:
    enabled: true
    vault-url: https://myvault.vault.azure.net/
    tenant-id: ${AZURE_TENANT_ID}
    client-id: ${AZURE_CLIENT_ID}
    client-secret: ${AZURE_CLIENT_SECRET}
    use-managed-identity: false
```

**Configuration Fields:**

| Field | Description | Required |
|-------|-------------|----------|
| `vault-url` | Azure Key Vault URL | Yes |
| `tenant-id` | Azure AD tenant ID | No (uses Managed Identity if not set) |
| `client-id` | Azure AD application (client) ID | No |
| `client-secret` | Service principal client secret | No |
| `use-managed-identity` | Use Azure Managed Identity | No |

### HashiCorp Vault

Build with: `go build -tags vault`

```yaml
keystores:
  default-backend: vault
  vault:
    enabled: true
    address: https://vault.example.com:8200
    token: ${VAULT_TOKEN}
    namespace: admin  # Enterprise only
    transit-path: transit
    tls-ca-file: /path/to/ca.crt
    tls-skip-verify: false
```

**Configuration Fields:**

| Field | Description | Required |
|-------|-------------|----------|
| `address` | Vault server address | Yes |
| `token` | Vault authentication token | Yes |
| `namespace` | Vault namespace (Enterprise) | No |
| `transit-path` | Transit secrets engine path | No (default: `transit`) |
| `tls-ca-file` | CA certificate for TLS | No |
| `tls-skip-verify` | Skip TLS verification (insecure) | No |

## Multi-Backend Configuration

go-trusted-platform supports multiple backends simultaneously, allowing different keys to use different backends based on security requirements:

```yaml
keystores:
  default-backend: software

  software:
    enabled: true
    key-dir: /var/lib/trusted-platform/keys/software
    cert-dir: /var/lib/trusted-platform/certs/software

  tpm2:
    enabled: true
    srk-handle: 0x81000001
    srk-auth: ${TPM_SRK_AUTH}
    platform-policy: true

  awskms:
    enabled: true
    region: us-east-1
    default-key-id: alias/high-security-keys

certificate-authority:
  identity:
    - keys:
        # Development keys in software
        - algorithm: ECDSA
          store: software

        # Production CA key in TPM
        - algorithm: RSA
          store: tpm2

        # High-security signing key in AWS KMS
        - algorithm: ECDSA
          store: awskms
```

### Backend Selection

Keys specify their backend using the `store` field:

| Store Value | Backend | Build Tag |
|-------------|---------|-----------|
| `software` | File-based PKCS#8 | None |
| `tpm2` | TPM 2.0 | None |
| `pkcs11` | PKCS#11 HSM | `pkcs11` |
| `awskms` | AWS KMS | `awskms` |
| `gcpkms` | GCP Cloud KMS | `gcpkms` |
| `azurekv` | Azure Key Vault | `azurekv` |
| `vault` | HashiCorp Vault | `vault` |

## Build Tags

To include cloud backend support, compile with the appropriate build tags:

```bash
# Single backend
go build -tags awskms ./cmd/platformd

# Multiple backends
go build -tags "awskms gcpkms azurekv vault" ./cmd/platformd

# All backends including PKCS#11
go build -tags "pkcs11 awskms gcpkms azurekv vault" ./cmd/platformd
```
