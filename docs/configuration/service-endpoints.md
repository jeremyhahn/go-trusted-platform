# Service Endpoints Configuration

This document describes how to configure service endpoints in go-trusted-platform, including backend definitions, transport modes, TLS configuration, and secrets resolution.

## Overview

go-trusted-platform supports flexible service deployment where each service can run:

- **Embedded**: In-process within the platformd daemon (default)
- **Remote**: Connected to a dedicated cluster endpoint

Service mode is **inferred from configuration** - no explicit `mode:` field required:

- If `backend:` is specified, the service uses **remote mode**
- If `backend:` is NOT specified, the service uses **embedded mode** (default)

## Backend Definitions

Backends define reusable remote endpoint configurations. Define backends once and reference them across multiple services.

```yaml
backends:
  # QuicBaaS cluster for data services
  quicbaas-cluster:
    address: "quicbaas.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/quicbaas/ca
      client_cert: kms://platform/backends/quicbaas/cert
      client_key: kms://platform/backends/quicbaas/key

  # Dedicated KMS cluster
  kms-cluster:
    address: "kms.cluster.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/kms/ca
      client_cert: kms://platform/backends/kms/cert
      client_key: kms://platform/backends/kms/key

  # Certificate Authority cluster
  ca-cluster:
    address: "ca.internal:8443"
    transport: rest
    tls:
      ca_cert: kms://platform/backends/ca/ca
      client_cert: kms://platform/backends/ca/cert
      client_key: kms://platform/backends/ca/key
```

### Backend Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `address` | Yes | Host:port of the remote service |
| `transport` | Yes | Protocol: `grpc`, `rest`, `quic`, `unix` |
| `tls.ca_cert` | No | CA certificate for server verification |
| `tls.client_cert` | No | Client certificate for mTLS |
| `tls.client_key` | No | Client private key for mTLS |

## Transport Modes

| Transport | Port | Use Case |
|-----------|------|----------|
| Embedded | - | Default, in-process (single-node) |
| Unix Socket | /run/platformd.sock | Local IPC, CLI tools |
| gRPC | 10443 | High-performance remote |
| REST | 8443 | Web clients, external systems |
| QUIC | 9444 | Low-latency, mobile clients |
| MCP | 9445 | AI/LLM integration |

## Per-Service Configuration

Reference backends in service configuration to enable remote mode:

```yaml
services:
  # Remote services (backend specified)
  kms:     { backend: kms-cluster }
  secrets: { backend: quicbaas-cluster }
  iam:     { backend: quicbaas-cluster }
  ca:      { backend: ca-cluster }

  # Embedded services (no backend = embedded)
  vector:  { index_type: hnsw, dimensions: 1536 }
  data:    { wal_enabled: true }
```

## TLS Configuration

### Server TLS

Configure TLS for the platformd server:

```yaml
webservice:
  tls-port: 8443
  key:
    algorithm: ECDSA
    ecc:
      curve: P-256
    signature-algorithm: ECDSA-SHA256
    hash: SHA-256
    store: tpm2         # software, pkcs11, or tpm2
    password: auto      # auto-generate on first boot
    platform-policy: true
  certificate:
    subject:
      cn: server.example.com
      organization: My Organization
    sans:
      dns:
        - server.example.com
        - www.server.example.com
```

### Client TLS (mTLS)

Configure client certificates for connecting to remote backends:

```yaml
backends:
  secure-backend:
    address: "backend.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/secure/ca
      client_cert: kms://platform/backends/secure/cert
      client_key: kms://platform/backends/secure/key
      # Optional: specify min TLS version
      min_version: "1.3"
      # Optional: specify allowed cipher suites
      cipher_suites:
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

## Secrets Resolution

**Never store secrets directly in configuration files.** Use go-quicbaas's secrets resolution:

| Scheme | Description | Example |
|--------|-------------|---------|
| `kms://` | Local KMS lookup | `kms://platform/backends/kms/ca` |
| `remote-kms://` | Remote KMS lookup | `remote-kms://kms.internal:10443/path` |
| `auto` | Auto-generate on first boot | `password: auto` |

### Examples

```yaml
# Local KMS secret reference
backends:
  quicbaas:
    tls:
      ca_cert: kms://platform/backends/quicbaas/ca
      client_cert: kms://platform/backends/quicbaas/cert
      client_key: kms://platform/backends/quicbaas/key

# Remote KMS secret reference
backends:
  external:
    tls:
      ca_cert: remote-kms://kms.external.com:10443/certs/external-ca
      client_cert: remote-kms://kms.external.com:10443/certs/client-cert
      client_key: remote-kms://kms.external.com:10443/keys/client-key

# Auto-generate password
tpm:
  keystore:
    srk-auth: auto  # Auto-generated on first boot
```

## Configuration Examples

### Minimal Development Configuration

Single-node development setup with all services embedded:

```yaml
debug: true
platform-dir: trusted-data
config-dir: trusted-data/etc
log-dir: trusted-data/log
domain: localhost

tpm:
  simulator: true
  device: /dev/tpmrm0

quicbaas:
  storage-backend: pebble
  data-dir: trusted-data/quicbaas

certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true
  identity:
    - keystores:
        software:
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          store: software
          password: 123456
      valid: 10
      subject:
        cn: dev-ca.localhost

webservice:
  port: 8080
  tls-port: 8443

argon2:
  memory: 1
  iterations: 1
  parallelism: 1
```

### Single Backend Configuration

Route all services to one QuicBaaS cluster:

```yaml
platform-dir: /var/lib/trusted-platform
domain: app.example.com

backends:
  quicbaas-primary:
    address: "quicbaas.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/quicbaas/ca
      client_cert: kms://platform/backends/quicbaas/cert
      client_key: kms://platform/backends/quicbaas/key

services:
  kms:        { backend: quicbaas-primary }
  secrets:    { backend: quicbaas-primary }
  iam:        { backend: quicbaas-primary }
  vector:     { backend: quicbaas-primary }
  timeseries: { backend: quicbaas-primary }

tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true

certificate-authority:
  platform-ca: 1
  identity:
    - keystores:
        tpm2:
          srk-handle: 0x81000003
          platform-policy: true
      keys:
        - algorithm: ECDSA
          store: tpm2
      subject:
        cn: ca.app.example.com

webservice:
  tls-port: 8443
  key:
    store: tpm2
```

### Production Mixed-Mode Configuration

Some services embedded, some remote for production deployments:

```yaml
platform-dir: /var/lib/trusted-platform
domain: prod.example.com
pin-seal-policy: true

backends:
  # Dedicated KMS cluster for sensitive operations
  kms-cluster:
    address: "kms.prod.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/kms/ca
      client_cert: kms://platform/backends/kms/cert
      client_key: kms://platform/backends/kms/key

  # Dedicated IAM cluster
  iam-cluster:
    address: "iam.prod.internal:10443"
    transport: grpc
    tls:
      ca_cert: kms://platform/backends/iam/ca
      client_cert: kms://platform/backends/iam/cert
      client_key: kms://platform/backends/iam/key

  # Certificate Authority cluster
  ca-cluster:
    address: "ca.prod.internal:8443"
    transport: rest
    tls:
      ca_cert: kms://platform/backends/ca/ca
      client_cert: kms://platform/backends/ca/cert
      client_key: kms://platform/backends/ca/key

services:
  # Remote services (high security, dedicated clusters)
  kms:     { backend: kms-cluster }
  secrets: { backend: kms-cluster }
  iam:     { backend: iam-cluster }
  ca:      { backend: ca-cluster }

  # Embedded services (local performance optimization)
  vector:     { index_type: hnsw, dimensions: 1536 }
  data:       { wal_enabled: true }
  timeseries: { retention: 90d }

tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true
  entropy: true

quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  cache-size: 67108864
  consistency-level: linearizable
  # SPIFFE trust domain for the embedded server's IAM. REQUIRED for qrdb
  # first-boot to issue the admin certificate and with it create the
  # system tenant, built-in roles and platform admin — without it the IAM
  # bootstrap fails on every boot and tenant-scoped surfaces (WebAuthn
  # ceremonies, operating-tenant adoption) never work.
  spiffe-trust-domain: trusted-platform.internal

webservice:
  tls-port: 8443
  key:
    algorithm: ECDSA
    store: tpm2
    platform-policy: true
  certificate:
    acme:
      challenge: http-01
      cross-sign:
        directory: https://acme-v02.api.letsencrypt.org/directory

argon2:
  memory: 65536
  iterations: 3
  parallelism: 2
```

## Environment Variable Substitution

Configuration files support environment variable substitution:

```yaml
domain: ${DOMAIN}
network:
  interfaces:
    - name: eth0
      address: ${PRIVATE_IPv4}
dns:
  public:
    zone:
      records:
        a:
          - name: "@"
            value: ${PUBLIC_IPv4}
```

## Related Documentation

- [Build Tags Reference](build-tags.md) - Control feature compilation
- [Deployment Modes](../operations/deployment-modes.md) - Standalone, cluster, and mixed deployments
- [SDK Integration](../architecture/sdk-integration.md) - Multi-transport architecture
