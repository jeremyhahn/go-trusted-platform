# CA Configuration

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `certificate-authority:` configuration block (`trustedca.CAConfig`, re-exported from the stack).

This document provides the complete configuration reference for the
Certificate Authority component.

## Configuration File

The CA configuration is part of the main platform configuration file:

```yaml
# /etc/trusted-platform/config.yaml

certificate-authority:
  # Index of the issuing CA in the identity array (0 = root, 1 = first intermediate)
  platform-ca: 1

  # Auto-import issuing CA certificate to system trust store
  auto-import-issuing-ca: true

  # Use system certificate pool for validation
  system-cert-pool: false

  # Default certificate validity in days
  default-validity: 365

  # Default Common Name for IDevID certificates
  default-idevid-cn: default-device-id

  # Include localhost in Subject Alternative Names
  sans-include-localhost: true

  # Require password for private key operations
  require-password: true

  # Enable quantum-safe cryptographic algorithms
  quantum-safe: true

  # CA hierarchy defined as array of identity configurations
  identity:
    - # Root Certificate Authority (index 0)
      key-algorithm: RSA
      key-size: 2048
      keystore-type: software       # software, tpm2, pkcs11
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "123456"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "123456"
          platform-policy: true
      valid: 50                     # Validity in years
      subject:
        cn: root-ca.example.com
        organization: Example Corp
        country: US
        province: State
        locality: City
        address: 123 Example Street
        postal-code: "12345"
      sans:
        dns:
          - root-ca.example.com
        email:
          - admin@example.com

    - # Intermediate Certificate Authority (index 1)
      key-algorithm: RSA
      key-size: 2048
      keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "123456"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "123456"
          platform-policy: true
      valid: 10
      subject:
        cn: ca01.example.com
        organization: Example Corp
        country: US
        province: State
        locality: City
        address: 123 Example Street
        postal-code: "12345"
      sans:
        dns:
          - ca01.example.com
          - ca.example.com
        email:
          - admin@example.com
```

## Identity Configuration

Each CA in the hierarchy is configured as an entry in the `identity` array.

### Subject Configuration

| Field        | Type   | Description                      | Required |
|--------------|--------|----------------------------------|----------|
| cn           | string | Common Name                      | Yes      |
| organization | string | Organization (O)                 | Yes      |
| country      | string | Country (C) - 2-letter code      | Yes      |
| province     | string | State/Province (ST)              | No       |
| locality     | string | Locality/City (L)                | No       |
| address      | string | Street Address                   | No       |
| postal-code  | string | Postal Code                      | No       |

### Key Configuration

Each CA identity supports multiple keys for different algorithms and storage backends:

```yaml
identity:
  - # CA Identity Configuration
    key-algorithm: RSA              # Default algorithm: RSA, ECDSA, Ed25519
    key-size: 2048                  # Default key size for RSA
    keystore-type: software         # Default keystore: software, tpm2, pkcs11

    # Configure available keystores
    keystores:
      software:
        platform-policy: true       # Use platform security policy

      tpm2:
        srk-handle: 0x81000001      # Storage Root Key handle
        srk-auth: "123456"          # SRK authorization value
        platform-policy: true

      pkcs11:
        library: /usr/lib/softhsm/libsofthsm2.so
        config: /etc/softhsm.conf
        slot: 0
        label: SoftHSM
        pin: "123456"
        platform-policy: true

    # Define keys for this CA (supports multiple algorithms/stores)
    keys:
      # PKCS#8 RSA with PSS padding
      - algorithm: RSA
        rsa:
          size: 2048
        signature-algorithm: SHA256-RSA
        hash: SHA-256
        store: software             # software, tpm2, pkcs11
        password: "123456"
        platform-policy: true
        debug: true

      # TPM 2.0 RSA
      - algorithm: RSA
        rsa:
          size: 2048
        signature-algorithm: SHA256-RSA
        hash: SHA-256
        store: tpm2
        password: "123456"
        platform-policy: true

      # PKCS#8 ECDSA
      - algorithm: ECDSA
        ecc:
          curve: P-256              # P-256, P-384, P-521
        signature-algorithm: ECDSA-SHA256
        hash: SHA-256
        store: software
        password: "123456"
        platform-policy: true

      # TPM 2.0 ECDSA
      - algorithm: ECDSA
        ecc:
          curve: P-256
        signature-algorithm: ECDSA-SHA256
        hash: SHA-256
        store: tpm2
        password: "123456"
        platform-policy: true

      # PKCS#8 Ed25519
      - algorithm: Ed25519
        ecc:
          curve: P-256
        signature-algorithm: Ed25519
        hash: SHA-256
        store: software
        password: "123456"
        platform-policy: true

    valid: 50                       # Certificate validity in years
    subject:
      cn: root-ca.example.com
      organization: Example Corp
      country: US
      province: State
      locality: City
      address: 123 Example Street
      postal-code: "12345"
    sans:
      dns:
        - root-ca.example.com
      email:
        - admin@example.com
```

## Intermediate CA Configuration

Intermediate CAs are additional entries in the `identity` array after the root CA:

```yaml
certificate-authority:
  platform-ca: 1                    # Use index 1 (first intermediate) for issuing
  identity:
    - # Root CA (index 0) - see above

    - # Intermediate CA (index 1)
      key-algorithm: RSA
      key-size: 2048
      keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "123456"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "123456"
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: "123456"
          platform-policy: true
      valid: 10
      subject:
        cn: ca01.example.com
        organization: Example Corp
        country: US
        province: State
        locality: City
        address: 123 Example Street
        postal-code: "12345"
      sans:
        dns:
          - ca01.example.com
          - ca.example.com
        email:
          - admin@example.com
```

## ACME Server Configuration

ACME is configured per webservice in the `webservices` array:

```yaml
webservices:
  - name: public
    home: /var/lib/trusted-platform/public_html
    port: 8080
    tls-port: 8443
    index: index.html

    acme:
      enabled: true
      directory: https://server.example.com/api/v1/acme/directory
      terms-of-service: /tos.html
      challenges:
        - enroll-01           # TPM attestation for IDevID
        - device-attest-01    # Device attestation
        - dns-01              # DNS TXT record validation
        - endorse-01          # EK certificate installation
        - http-01             # Standard HTTP validation
        - http-8080           # HTTP on port 8080
        - http-8081           # HTTP on port 8081
        - enroll-8080         # Enrollment on port 8080
        - enroll-8081         # Enrollment on port 8081

    jwt:
      expiration: 60      # Token expiration in minutes (1 hour default)
      issuer: trusted-platform

    webauthn:
      display-name: Trusted Platform
      id: localhost
      origins:
        - https://server.example.com
        - https://localhost
        - http://localhost:8080

    cors:
      allowed-origins:
        - https://server.example.com
        - https://localhost
      allowed-methods:
        - GET
        - POST
        - PUT
        - DELETE
        - OPTIONS
      allowed-headers:
        - "*"
      allow-credentials: true

    # TLS key configuration
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: software
      password: "123456"
      platform-policy: true

    # TLS certificate configuration
    certificate:
      acme:
        challenge: http-01    # Challenge type for auto-renewal
        renew: 15             # Renew when N days remain
      subject:
        cn: server.example.com
        organization: Example Corp
        country: US
        province: State
        locality: City
        address: 123 Example Street
        postal-code: "12345"
      sans:
        dns:
          - server.example.com
          - www.server.example.com
        email:
          - admin@example.com
```

## Revocation Configuration

### CRL Configuration

```yaml
revocation:
  crl:
    enabled: true
    # CRL validity period
    validity_hours: 24
    # Next update offset
    next_update_hours: 12
    # Maximum entries per CRL
    max_entries: 10000
    # Distribution points
    distribution_points:
      - http://crl.example.com/ca.crl
      - ldap://ldap.example.com/cn=CA,o=Example
    # Storage
    storage:
      type: filesystem
      path: /var/lib/trusted-platform/ca/crl
```

### OCSP Configuration

```yaml
revocation:
  ocsp:
    enabled: true
    # OCSP responder URL
    responder_url: http://ocsp.example.com
    # Response validity
    this_update_offset: -5m
    next_update_offset: 24h
    # Responder certificate
    responder_cert:
      cn: "OCSP Responder"
      key:
        algorithm: ecdsa
        curve: P-256
        store: tpm
```

## Certificate Policy Configuration

```yaml
policy:
  # Maximum certificate validity
  max_validity_days: 365
  min_validity_days: 1

  # CSR requirements
  require_csr: true
  validate_csr_signature: true

  # Allowed algorithms
  allowed_key_types:
    - RSA-2048
    - RSA-3072
    - RSA-4096
    - ECDSA-P256
    - ECDSA-P384
    - Ed25519

  # Minimum RSA key size
  min_rsa_key_size: 2048

  # Subject validation
  subject:
    require_organization: true
    require_country: true
    allowed_countries:
      - US
      - CA
      - GB

  # SAN validation
  san:
    allow_ip_addresses: true
    allow_wildcards: true
    max_dns_names: 100
    max_ip_addresses: 10
    domain_whitelist:
      - "*.example.com"
      - "*.internal.example.com"
    domain_blacklist:
      - "*.test.com"

  # Key usage restrictions
  key_usage:
    server_auth:
      allowed: true
      max_validity_days: 365
    client_auth:
      allowed: true
      max_validity_days: 365
    code_signing:
      allowed: true
      require_approval: true
      max_validity_days: 365
```

## Database Configuration

```yaml
ca:
  database:
    driver: postgres
    dsn: "postgres://user:pass@localhost:5432/ca?sslmode=verify-full"

    # Connection pool
    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime: 5m

    # TLS
    tls:
      enabled: true
      ca_file: /etc/trusted-platform/ca/db-ca.crt
      cert_file: /etc/trusted-platform/ca/db-client.crt
      key_file: /etc/trusted-platform/ca/db-client.key
```

## Environment Variables

Configuration values can use environment variable substitution:

| Variable              | Description                          |
|-----------------------|--------------------------------------|
| ${CA_KEY_PASSWORD}    | Password for software key storage    |
| ${PKCS11_PIN}         | PKCS#11 token PIN                    |
| ${TPM_OWNER_AUTH}     | TPM owner authorization              |
| ${ACME_DATABASE_DSN}  | ACME account database connection     |
| ${CA_DATABASE_DSN}    | Certificate database connection      |

## Example Configurations

### Minimal Development Configuration

```yaml
certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true
  system-cert-pool: false
  default-validity: 365
  require-password: true

  identity:
    - # Root CA
      key-algorithm: ECDSA
      key-size: 256
      keystore-type: software
      keystores:
        software:
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software
          password: "dev-password"
          platform-policy: true
      valid: 5
      subject:
        cn: dev-root-ca.local
        organization: Development
        country: US
      sans:
        dns:
          - dev-root-ca.local

    - # Intermediate CA
      key-algorithm: ECDSA
      key-size: 256
      keystore-type: software
      keystores:
        software:
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: software
          password: "dev-password"
          platform-policy: true
      valid: 2
      subject:
        cn: dev-ca.local
        organization: Development
        country: US
      sans:
        dns:
          - dev-ca.local
```

### Production TPM Configuration

```yaml
certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true
  system-cert-pool: false
  default-validity: 365
  require-password: true
  quantum-safe: true

  identity:
    - # Root CA with TPM-backed keys
      key-algorithm: RSA
      key-size: 4096
      keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "${TPM_SRK_AUTH}"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA384-RSA
          hash: SHA-384
          store: tpm2
          password: "${CA_KEY_PASSWORD}"
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-384
          signature-algorithm: ECDSA-SHA384
          hash: SHA-384
          store: tpm2
          password: "${CA_KEY_PASSWORD}"
          platform-policy: true
      valid: 20
      subject:
        cn: root-ca.enterprise.com
        organization: Enterprise Corp
        country: US
        province: California
        locality: San Francisco
      sans:
        dns:
          - root-ca.enterprise.com
        email:
          - security@enterprise.com

    - # Intermediate CA
      key-algorithm: RSA
      key-size: 4096
      keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "${TPM_SRK_AUTH}"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: tpm2
          password: "${CA_KEY_PASSWORD}"
          platform-policy: true
      valid: 10
      subject:
        cn: ca.enterprise.com
        organization: Enterprise Corp
        country: US
        province: California
        locality: San Francisco
      sans:
        dns:
          - ca.enterprise.com
          - issuing-ca.enterprise.com
        email:
          - security@enterprise.com
```

## Configuration Validation

There is no `platformctl ca validate-config` and `ca init` has no `--dry-run`.
`platformctl ca init` initializes the CA from the loaded configuration
(`--force` re-initializes); see [cli.md](cli.md).

## Related Documentation

- [README](README.md) - CA overview
- [Architecture](architecture.md) - CA design
- [ACME](acme.md) - ACME server configuration
- [API Reference](api-reference.md) - API documentation
- [CLI Usage](cli-usage.md) - Command-line reference
