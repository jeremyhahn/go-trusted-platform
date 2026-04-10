# Trusted Registry Configuration

## Overview

This document provides the complete configuration reference for the Trusted Registry.

## RegistryConfig Structure

```go
// RegistryConfig for trusted registry
type RegistryConfig struct {
    // Enable/disable registry
    Enabled bool `yaml:"enabled"`

    // Listen address
    ListenAddr string `yaml:"listen-addr"`

    // TLS configuration (required)
    TLS TLSConfig `yaml:"tls"`

    // Attestation requirements for clients
    Attestation RegistryAttestationConfig `yaml:"attestation"`

    // Storage backend (QuicBaaS)
    Storage StorageConfig `yaml:"storage"`

    // Encryption via QuicBaaS
    Encryption EncryptionConfig `yaml:"encryption"`

    // Session settings
    Session SessionConfig `yaml:"session"`

    // Logging
    Logging LoggingConfig `yaml:"logging"`
}
```

## TLS Configuration

TLS is required for all registry connections.

```yaml
registry:
  tls:
    cert-file: /etc/platformd/certs/registry.crt
    key-file: /etc/platformd/certs/registry.key
    ca-file: /etc/platformd/certs/ca.crt
    client-auth: require  # require, request, none
    min-version: "1.3"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cert-file` | string | required | TLS certificate file |
| `key-file` | string | required | TLS private key file |
| `ca-file` | string | optional | CA certificate for client verification |
| `client-auth` | string | `require` | Client certificate requirement |
| `min-version` | string | `1.3` | Minimum TLS version |

## Attestation Configuration

```yaml
registry:
  attestation:
    require-attestation: true
    required-pcrs: [0, 1, 2, 7, 14]
    allowed-aiks:
      - "sha256:abc123..."
      - "sha256:def456..."
    attestation-policy: "registry.access"
    evidence-header: "X-Attestation-Evidence"
    max-quote-age: 5m
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `require-attestation` | bool | `true` | Require TPM attestation for access |
| `required-pcrs` | []int | `[0,1,2,7,14]` | PCR registers that must be included in quote |
| `allowed-aiks` | []string | optional | Restrict access to specific AIK fingerprints |
| `attestation-policy` | string | `registry.access` | OPA policy path for access decisions |
| `evidence-header` | string | `X-Attestation-Evidence` | HTTP header containing attestation evidence |
| `max-quote-age` | duration | `5m` | Maximum age of TPM quote |

### PCR Requirements

| PCR | Purpose | Recommended |
|-----|---------|-------------|
| 0 | BIOS/UEFI firmware | Yes |
| 1 | BIOS/UEFI configuration | Yes |
| 2 | Option ROMs | Yes |
| 7 | Secure Boot state | Yes |
| 14 | Workload measurements | Yes |

## Storage Configuration

```yaml
registry:
  storage:
    addr: "localhost:9000"
    namespace: "registry-blobs"
    encrypted: true
    key-id: "registry-storage-key"
    connection-timeout: 10s
    request-timeout: 30s
    max-connections: 100
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string | required | QuicBaaS server address |
| `namespace` | string | `registry-blobs` | Namespace for blob storage |
| `encrypted` | bool | `true` | Encrypt blobs at rest |
| `key-id` | string | optional | Storage encryption key ID |
| `connection-timeout` | duration | `10s` | Connection timeout |
| `request-timeout` | duration | `30s` | Request timeout |
| `max-connections` | int | `100` | Maximum connection pool size |

## Encryption Configuration

```yaml
registry:
  encryption:
    quicbaas-addr: "localhost:9000"
    key-namespace: "container-images"
    algorithm: "AES-256-GCM"
    encrypt-by-default: true
    key-rotation-interval: 720h
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `quicbaas-addr` | string | required | QuicBaaS address for key management |
| `key-namespace` | string | `container-images` | Namespace for encryption keys |
| `algorithm` | string | `AES-256-GCM` | Encryption algorithm |
| `encrypt-by-default` | bool | `true` | Encrypt all images by default |
| `key-rotation-interval` | duration | `720h` | KEK rotation interval |

### Supported Algorithms

| Algorithm | Key Size | Description |
|-----------|----------|-------------|
| `AES-256-GCM` | 256 bits | Default, recommended |
| `AES-128-GCM` | 128 bits | Faster, less secure |
| `ChaCha20-Poly1305` | 256 bits | Alternative to AES |

## Session Configuration

```yaml
registry:
  session:
    token-ttl: 1h
    max-sessions: 10000
    cleanup-interval: 5m
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `token-ttl` | duration | `1h` | Session token lifetime |
| `max-sessions` | int | `10000` | Maximum concurrent sessions |
| `cleanup-interval` | duration | `5m` | Expired session cleanup interval |

## Logging Configuration

```yaml
registry:
  logging:
    level: info
    format: json
    access-log: true
    audit-log: true
    audit-log-path: /var/log/platformd/registry-audit.log
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `info` | Log level (debug, info, warn, error) |
| `format` | string | `json` | Log format (json, text) |
| `access-log` | bool | `true` | Enable access logging |
| `audit-log` | bool | `true` | Enable audit logging |
| `audit-log-path` | string | optional | Separate audit log file |

## Complete Example

```yaml
registry:
  enabled: true
  listen-addr: ":5000"

  tls:
    cert-file: /etc/platformd/certs/registry.crt
    key-file: /etc/platformd/certs/registry.key
    ca-file: /etc/platformd/certs/ca.crt
    client-auth: require
    min-version: "1.3"

  attestation:
    require-attestation: true
    required-pcrs: [0, 1, 2, 7, 14]
    attestation-policy: "registry.access"
    evidence-header: "X-Attestation-Evidence"
    max-quote-age: 5m

  storage:
    addr: "quicbaas.platform.local:9000"
    namespace: "registry-blobs"
    encrypted: true
    key-id: "registry-storage-key"
    connection-timeout: 10s
    request-timeout: 30s
    max-connections: 100

  encryption:
    quicbaas-addr: "quicbaas.platform.local:9000"
    key-namespace: "container-images"
    algorithm: "AES-256-GCM"
    encrypt-by-default: true
    key-rotation-interval: 720h

  session:
    token-ttl: 1h
    max-sessions: 10000
    cleanup-interval: 5m

  logging:
    level: info
    format: json
    access-log: true
    audit-log: true
    audit-log-path: /var/log/platformd/registry-audit.log
```

## Device Profile Integration

The registry can be configured per-device profile:

```yaml
device_profile:
  name: "secure-compute-node"

  registry:
    trusted_registry: "registry.platform.local:5000"

    attestation:
      enabled: true
      required_pcrs: [0, 1, 2, 7, 14]

    encryption:
      enabled: true
      quicbaas_addr: "quicbaas.platform.local:9000"
      key_namespace: "container-images"
      encrypt_by_default: true

  containers:
    - name: "secure-app"
      image: "registry.platform.local:5000/secure-app:v1"
```

## OPA Access Policy

Example OPA policy for registry access control:

```rego
# registry_access.rego
package registry.access

default allow = false

# Allow if attestation is valid and PCRs match golden values
allow {
    input.quote_verified == true
    pcr_values_match
    aik_trusted
}

# Check PCR values against golden values
pcr_values_match {
    golden := data.golden_pcrs[input.aik]
    input.pcrs[0] == golden[0]
    input.pcrs[1] == golden[1]
    input.pcrs[2] == golden[2]
    input.pcrs[7] == golden[7]
}

# Verify AIK is in trusted list
aik_trusted {
    data.trusted_aiks[input.aik]
}

# Restrict certain images to specific AIKs
allow {
    input.quote_verified == true
    pcr_values_match
    image_allowed
}

image_allowed {
    not startswith(input.requested, "/v2/restricted/")
}

image_allowed {
    startswith(input.requested, "/v2/restricted/")
    data.restricted_access[input.aik]
}
```

## Environment Variables

Configuration can be overridden via environment variables:

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `REGISTRY_LISTEN_ADDR` | `registry.listen-addr` | Listen address |
| `REGISTRY_TLS_CERT` | `registry.tls.cert-file` | TLS certificate |
| `REGISTRY_TLS_KEY` | `registry.tls.key-file` | TLS private key |
| `REGISTRY_QUICBAAS_ADDR` | `registry.storage.addr` | QuicBaaS address |
| `REGISTRY_KEY_NAMESPACE` | `registry.encryption.key-namespace` | Key namespace |

## See Also

- [Architecture](architecture.md)
- [Registry README](README.md)
- [QuicBaaS Configuration](../quicbaas/configuration.md)
- [Attestation Configuration](../attestation/configuration.md)
