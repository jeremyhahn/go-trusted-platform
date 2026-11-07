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
  selected-ca: 1

  # Upstream field; platformd does NOT forward it (see note below)
  default-validity-days: 365

  # Add localhost and 127.0.0.1 to every issued certificate (development)
  include-localhost-sans: true

  # Refuse a software-backed CA key with an empty password. Read but not yet
  # enforced: platformd does not pass it to the SDK CA until go-xkms #1768 is
  # released, because the pinned go-xkms drops the CA key password when it
  # rebuilds the identity (#833).
  require-key-password: true

  # Upstream field; platformd IGNORES it (see note below)
  home-dir: /var/lib/trusted-platform/ca

  # CA hierarchy defined as array of identity configurations
  identity:
    - # Root Certificate Authority (index 0)
      keystore-type: software       # software, tpm2, pkcs11
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
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
      keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/issuing/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "kms://ca/issuing/keys/0/password?ensure=true&len=32&enc=base64"
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

Two fields of the upstream `CAConfig` schema have no effect in platformd today:

- `default-validity-days` is decoded but not forwarded. `App.LoadCA`
  (`pkg/app/app.go:3259`) and `App.InitCA` (`pkg/app/app.go:3347`) build
  `quicbaasca.Params` from `Identity` and the three store factories only
  (`App.caParams`), so
  `quicbaasca.NewCA` never sees the value and the CA keeps its built-in
  365-day default whatever is configured.

- `home-dir` is ignored. `App.InitCA` overwrites it with `platform-dir`, and
  both `InitCA` and `LoadCA` build the CA stores with `NewCAStoreFactory`
  (`pkg/app/ca_factory.go`). Do not point backup tooling at `home-dir`.

### Backing up CA state

CA state is split between `platform-dir` and the QuicBaaS data directory.
Back up both, because neither one alone can restore the CA:

| CA data | Stored through | Default location (embedded QuicBaaS) |
|---------|----------------|--------------------------------------|
| Certificates (`x509` partition), CRLs and revocation records | SDK ObjectStorage (`CreateCertStore`, `CreateObjectStore`, `pkg/app/ca_factory.go`). Here `<platform-dir>/ca/<issuing CN>` is only a key prefix inside the SDK | The `default` local object backend at `<quicbaas.data-dir>/objectstorage/` (`pkg/storage/quicbaas/config.go`, `ToQuicBaaSConfig`) |
| CA signing keys (software keystore) | The go-xkms `software` backend. `App.initStores` registers it, on file storage, before QuicBaaS starts (`pkg/app/app.go:1655-1704`). `ServiceInitialize` runs only once, so the embedded QuicBaaS KMS and `App.initXKMSService` (`pkg/app/app.go:156`) reuse that backend | **`<platform-dir>/ca/<issuing CN>/`** on the platformd host. The issuing CN is `identity[selected-ca]`, or `identity[1]` when `selected-ca` is 0 and more than one identity is configured (`pkg/app/app.go:1662-1668`) |

`quicbaas.data-dir` is configured on its own, separately from
`platform-dir` (default `trusted-data/quicbaas`, `pkg/app/app.go`). To back
up a CA:

1. Stop platformd, or take the backup from a consistent snapshot of the
   file system, so object storage, the key store and the KV store agree.
2. Back up the software keystore directory `<platform-dir>/ca/<issuing CN>/`.
   It holds the CA private keys. Without it, the certificates in `data-dir`
   cannot sign anything.
3. Back up the whole `quicbaas.data-dir` and, when it is set outside it,
   `quicbaas.wal-dir`. Back up the directory as a unit: the CA keystore
   reads its certificates from the object store (`CreateKeyStore`).
4. If a CA key uses a hardware or cloud KMS backend (TPM 2.0, PKCS#11, cloud
   KMS) instead of software, that private key is in neither directory. Back
   it up with that backend's own tools.
5. A remote transport (`quicbaas.transport` other than `embedded`) keeps the
   object store and the KMS operations on the QuicBaaS server. In that case,
   back up that server's data directory and KMS backend as well as
   `<platform-dir>/ca/<issuing CN>/` on the platformd host.

## Identity Configuration

Each CA in the hierarchy is configured as an entry in the `identity` array.

### Subject Configuration

| Field        | Type   | Description                      | Required |
|--------------|--------|----------------------------------|----------|
| cn           | string | Common Name                      | Yes      |
| organization | string | Organization (O)                 | Yes      |
| organizational-unit | string | Organizational Unit (OU)  | No       |
| country      | string | Country (C) - 2-letter code      | Yes      |
| province     | string | State/Province (ST)              | No       |
| locality     | string | Locality/City (L)                | No       |
| address      | string | Street Address                   | No       |
| postal-code  | string | Postal Code                      | No       |

### Subject Alternative Names

`sans` takes `dns`, `ips`, `email` and `uris` (string lists) and
`hardware-module` (the RFC 4108 hardware module name for TPM/HSM device
identities).

### Key Configuration

Each CA identity supports multiple keys for different algorithms and storage backends:

```yaml
identity:
  - # CA Identity Configuration
    keystore-type: software         # Default keystore: software, tpm2, pkcs11

    # Configure available keystores
    keystores:
      software:
        platform-policy: true       # Use platform security policy
        password: "kms://ca/root/software/password"  # fallback for keys with no password

      tpm2:
        srk-handle: 0x81000001      # Storage Root Key handle
        srk-auth: "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=raw"  # SRK authorization value
        platform-policy: true

      pkcs11:
        module: /usr/lib/softhsm/libsofthsm2.so
        slot: 0
        pin: "kms://ca/root/pkcs11/pin"  # set when the token was initialised

    # Define keys for this CA (supports multiple algorithms/stores)
    keys:
      # PKCS#8 RSA with PSS padding
      - algorithm: RSA
        rsa:
          size: 2048
        signature-algorithm: SHA256-RSA
        hash: SHA-256
        store: software             # software, tpm2, pkcs11
        password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
        platform-policy: true
        debug: true

      # TPM 2.0 RSA
      - algorithm: RSA
        rsa:
          size: 2048
        signature-algorithm: SHA256-RSA
        hash: SHA-256
        store: tpm2
        password: "kms://ca/root/keys/1/password?ensure=true&len=32&enc=base64"
        platform-policy: true

      # PKCS#8 ECDSA
      - algorithm: ECDSA
        ecc:
          curve: P-256              # P-256, P-384, P-521
        signature-algorithm: ECDSA-SHA256
        hash: SHA-256
        store: software
        password: "kms://ca/root/keys/2/password?ensure=true&len=32&enc=base64"
        platform-policy: true

      # TPM 2.0 ECDSA
      - algorithm: ECDSA
        ecc:
          curve: P-256
        signature-algorithm: ECDSA-SHA256
        hash: SHA-256
        store: tpm2
        password: "kms://ca/root/keys/3/password?ensure=true&len=32&enc=base64"
        platform-policy: true

      # PKCS#8 Ed25519
      - algorithm: Ed25519
        ecc:
          curve: P-256
        signature-algorithm: Ed25519
        hash: SHA-256
        store: software
        password: "kms://ca/root/keys/4/password?ensure=true&len=32&enc=base64"
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
  selected-ca: 1                    # Use index 1 (first intermediate) for issuing
  identity:
    - # Root CA (index 0) - see above

    - # Intermediate CA (index 1)
      keystore-type: software
      keystores:
        software:
          platform-policy: true
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/issuing/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 2048
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: software
          password: "kms://ca/issuing/keys/0/password?ensure=true&len=32&enc=base64"
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: "kms://ca/issuing/keys/1/password?ensure=true&len=32&enc=base64"
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
      password: "kms://webservices/0/key/password?ensure=true&len=32&enc=raw"
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

## Revocation and Extensions

There is no `revocation:`, `policy:` or `ca.database` block. Revocation
pointers and policy OIDs are set per identity:

| Key | Type | Meaning |
|-----|------|---------|
| `crl-distribution-points` | list | CRL URLs written into issued certificates |
| `crl-validity-days` | int | Validity of a generated CRL (default 7) |
| `ocsp-servers` | list | OCSP responder URLs written into issued certificates (AIA) |
| `issuing-certificate-urls` | list | Issuer certificate URLs (AIA) |
| `policy-identifiers` | list | Certificate policy OIDs |
| `max-path-length`, `max-path-length-zero` | int, bool | Path length constraint |
| `parent-ca` | string | CN of the parent CA, for an intermediate |

Certificates and revocation records are kept in the platform certificate store,
not a database ([architecture.md](architecture.md) §Persistence).

## Secrets

platformd does not expand environment variables in `config.yaml`. Passwords,
PINs and SRK authorization values are `kms://` references resolved through the
platform KMS (`?ensure=true` generates the value on first use).

## Example Configurations

### Minimal Development Configuration

```yaml
certificate-authority:
  selected-ca: 1
  default-validity-days: 365
  require-key-password: true

  identity:
    - # Root CA
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
          password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
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
          password: "kms://ca/issuing/keys/0/password?ensure=true&len=32&enc=base64"
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
  selected-ca: 1
  default-validity-days: 365
  require-key-password: true

  identity:
    - # Root CA with TPM-backed keys
      keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA384-RSA
          hash: SHA-384
          store: tpm2
          password: "kms://ca/keys/0/password?ensure=true&len=32&enc=base64"
          platform-policy: true
        - algorithm: ECDSA
          ecc:
            curve: P-384
          signature-algorithm: ECDSA-SHA384
          hash: SHA-384
          store: tpm2
          password: "kms://ca/keys/1/password?ensure=true&len=32&enc=base64"
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
      keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: tpm2
          password: "kms://ca/keys/2/password?ensure=true&len=32&enc=base64"
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

- [Architecture](architecture.md) - CA design
- [ACME](acme.md) - ACME server configuration
- [API Reference](api.md) - API documentation
- [CLI Usage](cli.md) - Command-line reference
