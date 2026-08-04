# Device Identity (IDevID/IAK) Design

**Version**: 1.0
**Last Updated**: 2026-01-05
**Status**: Implementation Phase

## Overview

This document describes the architecture and implementation of TPM-based Device Identity using IDevID (Initial Device Identifier) and IAK (Initial Attestation Key) certificates per TCG specifications. Device identity provides a cryptographically-bound, manufacturer-issued identity for secure device authentication and attestation.

## References

- TCG TPM 2.0 Keys for Device Identity and Attestation
- TCG Infrastructure Working Group - Device Identifier Composition Engine
- RFC 8995 - Bootstrapping Remote Secure Key Infrastructure (BRSKI)
- IETF ACME Device Attestation (draft-acme-device-attest)

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Device Identity Flow                        |
+------------------------------------------------------------------+
|                                                                    |
|  +-------------+     +----------------+     +------------------+  |
|  |   Device    |     |   IDevID/IAK   |     |       CA         |  |
|  |   (TPM)     |     |   Service      |     |   (go-xkms CA)   |  |
|  +------+------+     +-------+--------+     +---------+--------+  |
|         |                    |                        |           |
|         |  1. Generate Keys  |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
|         |  2. Create CSR     |                        |           |
|         |<-------------------|                        |           |
|         |    (TCG Profile)   |                        |           |
|         |                    |                        |           |
|         |                    |  3. Submit CSR         |           |
|         |                    |----------------------->|           |
|         |                    |                        |           |
|         |                    |  4. Verify TPM         |           |
|         |                    |<-----------------------|           |
|         |                    |  (ActivateCredential)  |           |
|         |                    |                        |           |
|         |  5. Decrypt Secret |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
|         |                    |  6. Return Secret      |           |
|         |                    |----------------------->|           |
|         |                    |                        |           |
|         |                    |  7. Issue Certificate  |           |
|         |                    |<-----------------------|           |
|         |                    |                        |           |
|         |  8. Install Cert   |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
+------------------------------------------------------------------+
```

> **Note**: The CA above is the go-xkms CA/ACME engine, consumed by
> go-trusted-platform through the go-quicbaas SDK (`Security().ACME()` /
> `Security().Certificate()`). go-trusted-ca has been decommissioned; the
> platform never imports it directly.

## Key Types and Hierarchy

### TPM Key Hierarchy

```
Endorsement Hierarchy (EH)
|
+-- EK (Endorsement Key)
|   +-- Restricted, decrypt-only
|   +-- Unique to each TPM
|   +-- Certified by TPM manufacturer
|
+-- IDevID (Initial Device Identifier)
    +-- Sign-only, non-restricted
    +-- Certified by device manufacturer/enterprise
    +-- Used for device authentication

Owner Hierarchy (OH)
|
+-- SRK (Storage Root Key)
    +-- Parent for user keys
    +-- Sealing operations

Endorsement Hierarchy (EH) or Platform Hierarchy (PH)
|
+-- IAK (Initial Attestation Key)
    +-- Restricted signing key
    +-- Used for TPM quotes/attestation
    +-- Certified by device manufacturer/enterprise
```

### Key Properties

| Key | Algorithm | Attributes | Use Case |
|-----|-----------|------------|----------|
| IDevID | ECDSA P-256 | Sign, FixedTPM, FixedParent, SensitiveDataOrigin | Device authentication, TLS client auth |
| IAK | ECDSA P-256 | Sign, Restricted, FixedTPM, FixedParent | TPM quotes, attestation |

## TCG OID Constants

The following OIDs are defined by TCG for device identity certificates:

```
tcg OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) international-organizations(23) 133 }
tcg-at OBJECT IDENTIFIER ::= { tcg 2 }
tcg-tcpaSpecVersion OBJECT IDENTIFIER ::= { tcg-at 16 }
tcg-at-tpmManufacturer OBJECT IDENTIFIER ::= { tcg-at 1 }
tcg-at-tpmModel OBJECT IDENTIFIER ::= { tcg-at 2 }
tcg-at-tpmVersion OBJECT IDENTIFIER ::= { tcg-at 3 }
tcg-at-platformManufacturer OBJECT IDENTIFIER ::= { tcg-at 4 }
tcg-at-platformModel OBJECT IDENTIFIER ::= { tcg-at 5 }
tcg-at-platformVersion OBJECT IDENTIFIER ::= { tcg-at 6 }

OID Values:
- 2.23.133.2.1 - TPM Manufacturer
- 2.23.133.2.2 - TPM Model
- 2.23.133.2.3 - TPM Version
- 2.23.133.2.4 - Platform Manufacturer
- 2.23.133.2.5 - Platform Model
- 2.23.133.2.6 - Platform Version
- 2.23.133.2.16 - TCG Spec Version
```

## Key Generation Flow

### IDevID Generation

```go
1. Check if IDevID already exists at persistent handle
2. If not exists:
   a. Create ECC P-256 key under Endorsement Hierarchy
   b. Set attributes: Sign, FixedTPM, FixedParent, SensitiveDataOrigin
   c. Evict to persistent handle (0x81010100)
3. Export public key for CSR generation
```

### IAK Generation

```go
1. Check if IAK already exists at persistent handle
2. If not exists:
   a. Create ECC P-256 key under Endorsement Hierarchy
   b. Set attributes: Sign, Restricted, FixedTPM, FixedParent
   c. Evict to persistent handle (0x81010101)
3. Export public key for CSR generation
```

### Persistent Handle Allocation

| Handle | Key Type | Description |
|--------|----------|-------------|
| 0x81010100 | IDevID | Device identity key |
| 0x81010101 | IAK | Initial attestation key |
| 0x81010102 | LDevID | Local device identity (optional) |
| 0x81010103 | LAK | Local attestation key (optional) |

## CSR Generation with TCG Profile

### Certificate Request Structure

```
CertificationRequest ::= SEQUENCE {
    certificationRequestInfo CertificationRequestInfo,
    signatureAlgorithm AlgorithmIdentifier,
    signature BIT STRING
}

CertificationRequestInfo ::= SEQUENCE {
    version INTEGER { v1(0) },
    subject Name,
    subjectPKInfo SubjectPublicKeyInfo,
    attributes [0] Attributes
}
```

### TCG Subject Alternative Name Extension

```
SubjectAltName ::= SEQUENCE OF GeneralName
    directoryName ::= RDNSequence {
        tpmManufacturer UTF8String,
        tpmModel UTF8String,
        tpmVersion UTF8String
    }
```

### CSR Generation Steps

```go
1. Read TPM properties:
   - Manufacturer (TPM2_PT_MANUFACTURER)
   - Model/Family (TPM2_PT_VENDOR_STRING_1-4)
   - Firmware version (TPM2_PT_FIRMWARE_VERSION)

2. Read platform properties (from SMBIOS/DMI):
   - System manufacturer
   - System product name
   - System serial number

3. Build CSR:
   - Subject: CN=<serial_number>, O=<manufacturer>
   - Key Usage: Digital Signature
   - Extended Key Usage: id-kp-cmcRA (if for CMC enrollment)
   - SAN: TCG OIDs with TPM/platform info
   - Public key: IDevID public key from TPM

4. Sign CSR using IDevID key via TPM
```

## Certificate Installation Flow

### IDevID Certificate Storage

```go
1. Receive certificate from CA
2. Parse and validate certificate
3. Verify public key matches IDevID
4. Store options:
   a. TPM NVRAM (preferred for hardware TPM)
   b. Filesystem (for vTPM bundles)
5. Update manifest/metadata
```

### NVRAM Storage Locations

| NV Index | Certificate | Size |
|----------|-------------|------|
| 0x01C00100 | IDevID Certificate | 2048 bytes |
| 0x01C00101 | IAK Certificate | 2048 bytes |

## Integration with CA Module

### Certificate Profiles

The CA module must support the following certificate profiles:

1. **IDevID Profile**
   - Key Usage: Digital Signature
   - Extended Key Usage: Client Authentication
   - Subject: Device serial number
   - Validity: 10+ years (device lifetime)
   - SAN: TCG hardware attributes

2. **IAK Profile**
   - Key Usage: Digital Signature
   - Extended Key Usage: Key Encipherment, Attestation
   - Subject: Device serial number + "-ak"
   - Validity: 10+ years (device lifetime)
   - SAN: TCG hardware attributes

### CA Interface

```go
type DeviceIdentityCA interface {
    // IssueIDevIDCertificate issues an IDevID certificate.
    IssueIDevIDCertificate(ctx context.Context, csr []byte) (*x509.Certificate, error)

    // IssueIAKCertificate issues an IAK certificate.
    IssueIAKCertificate(ctx context.Context, csr []byte) (*x509.Certificate, error)

    // VerifyTPMBinding verifies the CSR is bound to a real TPM via ActivateCredential.
    VerifyTPMBinding(ctx context.Context, ekCert *x509.Certificate, akPub []byte) (*ActivateCredentialChallenge, error)

    // CompleteTPMVerification completes TPM verification with decrypted secret.
    CompleteTPMVerification(ctx context.Context, challengeID string, secret []byte) error
}
```

## ACME enroll-01 Challenge Flow (Future)

### Overview

The ACME enroll-01 challenge provides automated device identity enrollment using ACME protocol with TPM attestation.

### Flow

```
Device                          ACME Server                    CA
   |                                |                           |
   |  1. POST /newOrder            |                           |
   |  (identifiers: device-id)     |                           |
   |------------------------------->|                           |
   |                                |                           |
   |  2. 201 Created               |                           |
   |  (authorizations: [...])      |                           |
   |<------------------------------|                           |
   |                                |                           |
   |  3. POST /authz/{id}          |                           |
   |------------------------------->|                           |
   |                                |                           |
   |  4. 200 OK                    |                           |
   |  (challenges: [enroll-01])    |                           |
   |<------------------------------|                           |
   |                                |                           |
   |  5. POST /challenge           |                           |
   |  (EK cert, AK pub)            |                           |
   |------------------------------->|                           |
   |                                |  6. MakeCredential       |
   |                                |------------------------->|
   |                                |                           |
   |  7. credential blob           |  8. credential blob       |
   |<------------------------------|<--------------------------|
   |                                |                           |
   |  [TPM: ActivateCredential]    |                           |
   |                                |                           |
   |  9. POST /challenge           |                           |
   |  (decrypted secret)           |                           |
   |------------------------------->|                           |
   |                                | 10. Verify secret        |
   |                                |------------------------->|
   |                                |                           |
   | 11. POST /finalize            |                           |
   |  (CSR)                        |                           |
   |------------------------------->|                           |
   |                                | 12. Issue certificate    |
   |                                |------------------------->|
   |                                |                           |
   | 13. 200 OK                    | 14. Certificate          |
   |  (certificate URL)            |<--------------------------|
   |<------------------------------|                           |
```

### ACME Challenge Response

```json
{
  "type": "enroll-01",
  "status": "pending",
  "token": "base64-encoded-challenge-token",
  "attestation": {
    "ek_cert": "base64-encoded-ek-certificate",
    "ak_pub": "base64-encoded-ak-public-key",
    "credential_blob": "base64-encoded-make-credential-output"
  }
}
```

## Security Considerations

### Key Protection

1. IDevID and IAK keys are generated inside TPM
2. Private keys never leave the TPM
3. Keys are bound to specific TPM instance via FixedTPM attribute
4. Keys are protected by TPM hierarchy authorization

### Certificate Validation

1. CA must verify TPM binding via ActivateCredential
2. EK certificate chain must be validated to TPM manufacturer
3. Platform binding should be verified against SMBIOS data

### Storage Security

1. NVRAM storage protected by TPM authorization
2. Filesystem storage protected by file permissions
3. Certificate chain should be validated on use

## Implementation Checklist

- [ ] Define TCG OID constants
- [ ] Implement IDevIDConfig and IAKConfig types
- [ ] Implement DeviceIdentityCertificate type
- [ ] Define typed errors
- [ ] Define DeviceIdentityService interface
- [ ] Implement key generation for IDevID
- [ ] Implement key generation for IAK
- [ ] Implement CSR generation with TCG profile
- [ ] Implement certificate installation
- [ ] Implement NVRAM storage
- [ ] Integrate with CA module
- [ ] Add CLI commands (platformctl tpm idevid)
- [ ] Add multi-protocol API support
- [ ] Implement ACME enroll-01 challenge (future)
- [ ] Write unit tests
- [ ] Write integration tests

## File Structure

```
pkg/tpm/idevid/
    types.go          - Configuration and data types
    errors.go         - Typed error definitions
    interface.go      - Service interface definition
    service.go        - Service implementation
    csr.go            - CSR generation with TCG profile
    nvram.go          - NVRAM certificate storage
    oid.go            - TCG OID definitions
    service_test.go   - Unit tests
```
