# ACME Server

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on the stack's ACME server and the `webservices[].acme` configuration; the challenge handlers are go-xkms's ([architecture.md](architecture.md)).

This document describes the ACME (Automated Certificate Management Environment)
server implementation, including the enroll-01 challenge for TPM attestation.

## ACME Overview

The platform implements an RFC 8555-compliant ACME server with extensions
for device attestation.

```
┌───────────────────────────────────────────────────────────────────┐
│                     ACME Server Architecture                      │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ACME Endpoints                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ /directory     │ Server capabilities and URLs               │  │
│  │ /new-nonce     │ Request fresh nonce                        │  │
│  │ /new-account   │ Register new account                       │  │
│  │ /new-order     │ Request certificate order                  │  │
│  │ /authz/{id}    │ Authorization object                       │  │
│  │ /challenge/{id}│ Challenge endpoint                         │  │
│  │ /order/{id}    │ Order status                               │  │
│  │ /cert/{id}     │ Download certificate                       │  │
│  │ /revoke-cert   │ Revoke certificate                         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Challenge Handlers                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │    http-01      │  │     dns-01       │  │   enroll-01      │ │
│  │  (RFC 8555)     │  │   (RFC 8555)     │  │  (TPM Attest)    │ │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘ │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Supported Challenge Types

| Challenge    | Description                      | Use Case                    |
|--------------|----------------------------------|-----------------------------|
| http-01      | HTTP validation (/.well-known/)  | Web servers                 |
| dns-01       | DNS TXT record validation        | Wildcard certs, non-HTTP    |
| enroll-01    | TPM attestation (device-01)      | IDevID issuance             |
| endorse-01   | EK certificate installation      | TPM without mfr EK cert     |

## enroll-01 Challenge Flow

The enroll-01 (device-01) challenge enables IDevID certificate issuance
with TPM attestation:

```
┌───────────────────────────────────────────────────────────────────┐
│                   enroll-01 Challenge Flow                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    ACME Client                           ACME Server              │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │  1. POST /new-order ─────────────▶                 │        │
│    │     identifiers:                   │                │        │
│    │       type: "device"               │                │        │
│    │       value: "device-serial"       │                │        │
│    │                │                   │                │        │
│    │  2. Order Created ◀────────────────                 │        │
│    │     status: "pending"              │                │        │
│    │     authorizations: [authz-url]    │                │        │
│    │                │                   │                │        │
│    │  3. GET authz-url ─────────────────▶                 │        │
│    │                │                   │                │        │
│    │  4. Authorization ◀────────────────                 │        │
│    │     challenges: [{                 │                │        │
│    │       type: "enroll-01"            │                │        │
│    │       token: "xyz..."              │                │        │
│    │     }]                             │                │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### TCG-CSR-IDEVID Submission

```
┌───────────────────────────────────────────────────────────────────┐
│                  TCG-CSR-IDEVID Submission                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    ACME Client                           ACME Server              │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │  5. Prepare TCG-CSR-IDEVID:        │                │        │
│    │     • IAK public key               │                │        │
│    │     • IDevID CSR (signed by IAK)   │                │        │
│    │     • EK certificate               │                │        │
│    │                │                   │                │        │
│    │  6. POST /.well-known/acme-challenge/{token}        │        │
│    │     Content-Type: application/jose+json             │        │
│    │     Body: TCG-CSR-IDEVID ─────────▶                 │        │
│    │                │                   │                │        │
│    │                │                   │ 7. Validate:   │        │
│    │                │                   │    • EK cert   │        │
│    │                │                   │      chain     │        │
│    │                │                   │    • IAK is    │        │
│    │                │                   │      restricted│        │
│    │                │                   │      key       │        │
│    │                │                   │    • CSR sig   │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Credential Activation

```
┌───────────────────────────────────────────────────────────────────┐
│                    Credential Activation                          │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    ACME Client                           ACME Server              │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │                │                   │ 8. MakeCredential:      │
│    │                │                   │    • Generate secret    │
│    │                │                   │    • Encrypt to EK      │
│    │                │                   │    • Bind to IAK name   │
│    │                │                   │                │        │
│    │  9. GET /.well-known/acme-activation/{token}        │        │
│    │                │                   │                │        │
│    │  10. Credential Blob ◀─────────────                 │        │
│    │      (encrypted secret)            │                │        │
│    │                │                   │                │        │
│    │  11. ActivateCredential            │                │        │
│    │      (TPM operation)               │                │        │
│    │      • Load EK                     │                │        │
│    │      • Load IAK                    │                │        │
│    │      • Decrypt secret              │                │        │
│    │                │                   │                │        │
│    │  12. POST /.well-known/acme-activation/{token}      │        │
│    │      Body: decrypted secret ───────▶                 │        │
│    │                │                   │                │        │
│    │                │                   │ 13. Verify     │        │
│    │                │                   │     secret     │        │
│    │                │                   │     matches    │        │
│    │                │                   │                │        │
│    │  14. Challenge Valid ◀─────────────                 │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Certificate Issuance

```
┌───────────────────────────────────────────────────────────────────┐
│                       IDevID Issuance                             │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    ACME Client                           ACME Server              │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │  15. POST /order/{id}/finalize     │                │        │
│    │      CSR: (same as TCG-CSR) ───────▶                 │        │
│    │                │                   │                │        │
│    │                │                   │ 16. Issue IDevID        │
│    │                │                   │     • Add TCG OIDs      │
│    │                │                   │     • Sign with CA      │
│    │                │                   │                │        │
│    │  17. Order Valid ◀─────────────────                 │        │
│    │      certificate: cert-url         │                │        │
│    │                │                   │                │        │
│    │  18. GET cert-url ─────────────────▶                 │        │
│    │                │                   │                │        │
│    │  19. IDevID Certificate ◀──────────                 │        │
│    │      (PEM format)                  │                │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## IDevID Certificate Content

```
┌───────────────────────────────────────────────────────────────────┐
│                      IDevID Certificate                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Subject:                                                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ CN = Device Serial Number                                   │  │
│  │ O  = Organization                                           │  │
│  │ serialNumber = TPM-extracted serial                         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Extensions:                                                      │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Key Usage: digitalSignature                                 │  │
│  │ Extended Key Usage: clientAuth, id-kp-cmcRA                 │  │
│  │ Subject Alt Names:                                          │  │
│  │   • otherName: hwSerialNum                                  │  │
│  │   • otherName: hwType (OID)                                 │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  TCG OIDs (2.23.133.x):                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ tcg-at-tpmManufacturer   = Infineon                         │  │
│  │ tcg-at-tpmModel          = SLB9670                          │  │
│  │ tcg-at-tpmVersion        = 7.85                             │  │
│  │ tcg-at-tpmSpecification  = 2.0                              │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Rate Limiting

| Endpoint            | Limit                      | Key                |
|---------------------|----------------------------|--------------------|
| /new-account        | 5 requests/hour            | IP address         |
| /new-nonce          | 60 requests/minute         | IP address         |
| /new-order          | 50 requests/week           | Account (JWS KID)  |
| /orders/{id}        | 5 requests/minute          | Account            |
| /authz/{id}         | 5 requests/minute          | Account            |
| /challenge/{id}     | 5 requests/minute          | Account            |
| /cert/{id}          | 10 requests/hour           | Account            |
| /revoke-cert        | 5 requests/hour            | Account            |
| /directory          | 100 requests/hour          | IP address         |

## Configuration

ACME is configured per webservice in the platform configuration:

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
        - http-01             # Standard HTTP validation (RFC 8555)
        - http-8080           # HTTP on port 8080
        - http-8081           # HTTP on port 8081
        - enroll-8080         # Enrollment on port 8080
        - enroll-8081         # Enrollment on port 8081

    jwt:
      expiration: 60      # Token expiration in minutes (1 hour default)
      issuer: trusted-platform

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

    # TLS key for this webservice
    key:
      algorithm: ECDSA
      ecc:
        curve: P-256
      signature-algorithm: ECDSA-SHA256
      hash: SHA-256
      store: software
      password: "123456"
      tpm-policy: platform

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

## Dynamic Port Configuration

The platform supports dynamic port configuration for challenges:

```
Challenge Type    Port Suffix    Example
http-01           (standard)     /.well-known/acme-challenge/
http-8080         8080           http://host:8080/.well-known/acme-challenge/
device-01         (standard)     /.well-known/acme-challenge/
device-8443       8443           https://host:8443/.well-known/acme-challenge/
```

## Cross-Signed Certificates

The ACME server supports cross-signing with public CAs:

```
┌───────────────────────────────────────────────────────────────────┐
│                   Cross-Signed Certificate                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Certificate Chain (Standard):                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. End-entity certificate (issued by Enterprise CA)         │  │
│  │ 2. Enterprise Intermediate CA                               │  │
│  │ 3. Enterprise Root CA                                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Certificate Chain (Cross-Signed):                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. End-entity certificate                                   │  │
│  │ 2. Enterprise Intermediate CA (cross-signed)                │  │
│  │ 3. Public CA (Let's Encrypt / other)                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Benefits:                                                        │
│  • Browser trust without custom CA installation                  │
│  • TCG attributes still present in certificate                   │
│  • Enterprise attestation for "trusted" clients                  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Error Responses

| Error Type              | HTTP Code | ACME Error Type              |
|-------------------------|-----------|------------------------------|
| Bad CSR                 | 400       | badCSR                       |
| Account does not exist  | 400       | accountDoesNotExist          |
| Invalid challenge       | 400       | invalidChallenge             |
| Rate limited            | 429       | rateLimited                  |
| Unauthorized            | 403       | unauthorized                 |
| Server error            | 500       | serverInternal               |

## Client Configuration

Example ACME client configuration for enroll-01:

```yaml
acme:
  client:
    directory: https://server.example.com:9443/api/v1/acme/directory
    account:
      email: hostmaster@example.com
      key:
        # TPM 2.0 ECDSA account key
        algorithm: ECDSA
        cn: acme-account
        debug: true
        hash: SHA-256
        password: "123456"
        tpm-policy: platform
        ecc:
          curve: P-256
        signature-algorithm: ECDSA-SHA256
        store: tpm2
        # Alternative: PKCS#8 RSA w/ PSS
        # algorithm: RSA
        # cn: acme-account
        # hash: SHA-256
        # password: "123456"
        # tpm-policy: platform
        # rsa:
        #   size: 2048
        # signature-algorithm: SHA256-RSA
        # store: software
      register: true
```

## Related Documentation

- [README](user.md) - CA module overview
- [Architecture](architecture.md) - CA hierarchy
- [Configuration](configuration.md) - Full configuration reference
- [TPM Attestation](../tpm/attestation.md) - Attestation details

## References

- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME Protocol
- [draft-acme-device-attest](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03) - Device Attestation
- [TCG TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
