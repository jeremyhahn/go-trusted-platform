# Certificate Authority

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md).

The Certificate Authority (CA) provides a full-featured, TPM and Attestation-aware
x509 certificate management system for the go-trusted-platform.

```
┌───────────────────────────────────────────────────────────────────┐
│                      Certificate Authority                        │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │    Root CA       │  │  Intermediate CA │  │    ACME Server   │ │
│  │  (RSA/ECC/Ed)    │  │    (Issuing)     │  │   (enroll-01)    │ │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘ │
│           │                     │                     │           │
│           └─────────────────────┴─────────────────────┘           │
│                                 │                                 │
│                    ┌────────────┴────────────┐                    │
│                    │      Key Management     │                    │
│                    │   (TPM / PKCS#11 / SW)  │                    │
│                    └────────────┬────────────┘                    │
│                                 │                                 │
└───────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │    go-xkms Backend    │
                    └───────────────────────────┘
```

## Features

| Feature                    | Description                                    |
|----------------------------|------------------------------------------------|
| Multi-Algorithm Support    | RSA-2048/3072/4096, ECDSA P-256/384, Ed25519   |
| CA Hierarchy               | Root CA with multiple Intermediate CAs         |
| TPM Integration            | Hardware-backed key storage and operations     |
| PKCS#11 Support            | HSM integration for enterprise deployments     |
| ACME Server                | Automated certificate issuance (RFC 8555)      |
| Device Attestation         | enroll-01 challenge for IDevID issuance        |
| CRL/OCSP                   | Certificate revocation support                 |
| TCG Compliance             | TCG certificate attributes and OIDs            |

## Certificate Types

| Type           | Usage                              | Key Storage         |
|----------------|-----------------------------------|---------------------|
| Root CA        | Trust anchor, signs Intermediate  | HSM/TPM recommended |
| Intermediate   | Issues end-entity certificates    | TPM/PKCS#11/Software|
| TLS Server     | HTTPS server authentication       | TPM/Software        |
| TLS Client     | mTLS client authentication        | TPM/Software        |
| IDevID         | Device identity (TCG)             | TPM required        |
| IAK            | Attestation Key certificate       | TPM required        |
| Code Signing   | Binary/firmware signing           | TPM/HSM             |

## ACME Server

The integrated ACME server supports:

| Challenge Type | Description                                    |
|----------------|------------------------------------------------|
| http-01        | Standard HTTP validation (RFC 8555)            |
| dns-01         | DNS TXT record validation                      |
| enroll-01      | TPM attestation for IDevID (device-01)         |
| endorse-01     | EK certificate installation                    |

## Quick Start

### 1. Initialize CA

```bash
# Initialize the Certificate Authority
platformctl ca init

# Verify initialization
platformctl ca info
```

### 2. Issue Certificate

```bash
# Issue TLS certificate
platformctl ca issue server.example.com software rsa2048 \
  --sans-dns "server.example.com,www.example.com"
```

### 3. Install CA Bundle

```bash
# Install CA certificates to system trust store
platformctl ca install-ca-certificates

# Export CA bundle
platformctl ca bundle > ca-bundle.crt
```

## CA Hierarchy

```
┌───────────────────────────────────────────────────────────────────┐
│                         CA Hierarchy                              │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    Root CA                                  │  │
│  │  CN: Trusted Platform Root CA                               │  │
│  │  Algorithm: RSA-4096 / ECDSA P-384                          │  │
│  │  Validity: 10-20 years                                      │  │
│  │  Key Usage: keyCertSign, cRLSign                            │  │
│  └───────────────────────────┬────────────────────────────────┘  │
│                              │                                    │
│         ┌────────────────────┴────────────────────┐               │
│         │                                         │               │
│         ▼                                         ▼               │
│  ┌──────┴──────┐                           ┌──────┴──────┐       │
│  │ Intermediate│                           │ Device CA   │       │
│  │ CA (TLS)    │                           │ (IDevID)    │       │
│  └──────┬──────┘                           └──────┬──────┘       │
│         │                                         │               │
│    ┌────┴────┐                              ┌─────┴─────┐        │
│    │         │                              │           │        │
│    ▼         ▼                              ▼           ▼        │
│  ┌───┐   ┌───────┐                      ┌───────┐   ┌───────┐   │
│  │TLS│   │mTLS   │                      │IDevID │   │IAK    │   │
│  │Srv│   │Client │                      │Cert   │   │Cert   │   │
│  └───┘   └───────┘                      └───────┘   └───────┘   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Configuration

CA configuration in platform config file:

```yaml
certificate-authority:
  platform-ca: 1                    # Index of issuing CA in identity array
  auto-import-issuing-ca: true      # Auto-import issuing CA to system trust
  system-cert-pool: false           # Use system certificate pool
  default-validity: 365             # Default certificate validity (days)
  default-idevid-cn: default-device-id
  sans-include-localhost: true      # Include localhost in SANs
  require-password: true            # Require password for key operations
  quantum-safe: true                # Enable quantum-safe algorithms

  identity:
    - # Root Certificate Authority
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
          store: software           # software, tpm2, pkcs11
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

    - # Intermediate Certificate Authority
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

## Certificate Verification

```bash
# Verify certificate chain with OpenSSL
openssl verify \
  -CAfile root-ca.crt \
  -untrusted intermediate-ca.crt \
  server.crt

# Verify HTTPS server
openssl s_client \
  -connect server.example.com:443 \
  -servername server.example.com \
  | openssl x509 -noout -text
```

## Related Documentation

- [Architecture](architecture.md) - CA hierarchy and key storage
- [ACME](acme.md) - ACME server and enroll-01 challenge
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - Certificate management API
- [CLI Usage](cli-usage.md) - Command-line reference

## See Also

- [Overview](overview.md) - CA overview with OpenSSL verification commands
- [ASN.1 and DER](asn1.md) - ASN.1 encoding reference

## References

- [RFC 5280](https://tools.ietf.org/html/rfc5280) - X.509 PKI Certificate Profile
- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME Protocol
- [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf)
- [TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
