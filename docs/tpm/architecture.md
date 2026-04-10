# TPM Architecture

This document describes the TPM integration architecture within the go-trusted-platform,
including the key hierarchy, PCR configuration, and integration with go-xkms.

## TPM Integration Overview

```
┌───────────────────────────────────────────────────────────────────┐
│                       Application Layer                           │
├───────────────────────────────────────────────────────────────────┤
│  platformctl  │  platformd  │  ACME Server   │  Other Services    │
└───────┬───────┴──────┬──────┴───────┬────────┴────────┬───────────┘
        │              │              │                 │
        ▼              ▼              ▼                 ▼
┌───────────────────────────────────────────────────────────────────┐
│                     Platform Service Layer                        │
├───────────────────────────────────────────────────────────────────┤
│  CA Service  │  Attestation  │  Key Mgmt  │  Sealing Service      │
└──────┬───────┴───────┬───────┴─────┬──────┴───────────┬───────────┘
       │               │             │                  │
       └───────────────┴─────────────┴──────────────────┘
                                │
┌───────────────────────────────────────────────────────────────────┐
│                     go-xkms TPM2 Backend                      │
├───────────────────────────────────────────────────────────────────┤
│   KeyStore Interface  │  TPM2 Package  │  Session Management      │
└───────────┬───────────┴───────┬────────┴───────────┬──────────────┘
            │                   │                    │
            ▼                   ▼                    ▼
┌───────────────────────────────────────────────────────────────────┐
│                       go-tpm TPMDirect API                        │
├───────────────────────────────────────────────────────────────────┤
│   TPM2 Commands  │  Handles  │  Sessions  │  Authorization        │
└─────────┬────────┴─────┬─────┴──────┬─────┴──────────┬────────────┘
          │              │            │                │
          ▼              ▼            ▼                ▼
┌───────────────────────────────────────────────────────────────────┐
│                       TPM Resource Manager                        │
├───────────────────────────────────────────────────────────────────┤
│                         /dev/tpmrm0                               │
└─────────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                     TPM 2.0 Hardware / swtpm                      │
└───────────────────────────────────────────────────────────────────┘
```

## Key Hierarchy Design

The platform implements the TCG-recommended key hierarchy:

```
┌───────────────────────────────────────────────────────────────────┐
│                       TPM Key Hierarchy                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ENDORSEMENT HIERARCHY                                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    Endorsement Seed                         │  │
│  │                    (Hardware RNG)                           │  │
│  └───────────────────────────┬────────────────────────────────┘  │
│                              │                                    │
│                              ▼                                    │
│  ┌───────────────────────────┴────────────────────────────────┐  │
│  │  Endorsement Key (EK)     Handle: 0x81010001               │  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │ Algorithm: RSA-2048 or ECC P-384                       ││  │
│  │  │ Usage: Decrypt only (privacy sensitive)                ││  │
│  │  │ Certificate: Manufacturer or CA issued                 ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  STORAGE HIERARCHY                                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    Storage Primary Seed                     │  │
│  └───────────────────────────┬────────────────────────────────┘  │
│                              │                                    │
│                              ▼                                    │
│  ┌───────────────────────────┴────────────────────────────────┐  │
│  │  Shared SRK (SSRK)        Handle: 0x81000002               │  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │ Algorithm: RSA-2048 or ECC P-256                       ││  │
│  │  │ Usage: Decrypt (key wrapping)                          ││  │
│  │  │ Policy: Platform PCR policy                            ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  └───────────────────────────┬────────────────────────────────┘  │
│                              │                                    │
│         ┌────────────────────┼────────────────────┐               │
│         │                    │                    │               │
│         ▼                    ▼                    ▼               │
│  ┌──────┴──────┐      ┌──────┴──────┐      ┌──────┴──────┐       │
│  │  AK/IAK    │      │  IDevID     │      │  Sealed     │       │
│  │  0x81010002│      │  0x81020000 │      │  Objects    │       │
│  ├─────────────┤      ├─────────────┤      ├─────────────┤       │
│  │ Signing    │      │ Signing     │      │ KeyedHash   │       │
│  │ Attestation│      │ Device ID   │      │ PCR Policy  │       │
│  └─────────────┘      └─────────────┘      └─────────────┘       │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Handle Allocation

| Handle        | Key Type                    | Purpose                    |
|---------------|-----------------------------|----------------------------|
| 0x81010001    | Endorsement Key (EK)        | Platform identity root     |
| 0x81000002    | Shared Storage Root Key     | Key hierarchy root         |
| 0x81010002    | Attestation Key (AK/IAK)    | Remote attestation signing |
| 0x81020000    | Initial Device ID (IDevID) | Device identity            |
| 0x81000100+   | Application Keys            | User/app key storage       |
| 0x01000000+   | NVRAM Indices               | Certificate/data storage   |

## PCR Configuration

Platform Configuration Registers store boot measurements:

```
┌───────────────────────────────────────────────────────────────────┐
│                      PCR Bank Configuration                       │
├─────┬─────────────────┬───────────────────────────────────────────┤
│ PCR │ Measured By     │ Contents                                  │
├─────┼─────────────────┼───────────────────────────────────────────┤
│  0  │ Firmware        │ Core UEFI code                            │
│  1  │ Firmware        │ UEFI configuration                        │
│  2  │ Firmware        │ Option ROM code                           │
│  3  │ Firmware        │ Option ROM configuration                  │
│  4  │ Firmware        │ MBR/Boot loader                           │
│  5  │ Firmware        │ GPT/Partition table                       │
│  6  │ Firmware        │ Resume from S4/S5                         │
│  7  │ Firmware        │ Secure Boot state                         │
│  8  │ GRUB            │ Kernel command line                       │
│  9  │ GRUB/Kernel     │ Kernel and initrd                         │
│ 10  │ IMA             │ Integrity Measurement Architecture        │
│ 11  │ systemd-stub    │ UKI components                            │
│ 12  │ systemd-stub    │ Kernel parameters/credentials             │
│ 13  │ systemd-stub    │ System extensions                         │
│ 14  │ shim            │ MOK certificates                          │
│ 15  │ systemd         │ Root FS encryption key                    │
└─────┴─────────────────┴───────────────────────────────────────────┘
```

### PCR Policy Configuration

```yaml
tpm:
  pcr_policy:
    # Boot integrity PCRs
    - indices: [0, 1, 2, 3, 7]
      bank: SHA256
      description: "Firmware and Secure Boot"

    # OS integrity PCRs
    - indices: [8, 9, 11]
      bank: SHA256
      description: "Kernel and boot parameters"

    # Runtime integrity PCRs
    - indices: [10]
      bank: SHA256
      description: "IMA runtime measurements"
```

## go-xkms TPM2 Backend

The platform uses go-xkms for unified key management:

```
┌───────────────────────────────────────────────────────────────────┐
│                      go-xkms Integration                      │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KeyStore Interface                                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Create()  │  Get()  │  Delete()  │  Sign()  │  Verify()   │  │
│  └───────────────────────────┬────────────────────────────────┘  │
│                              │                                    │
│                              ▼                                    │
│  ┌───────────────────────────┴────────────────────────────────┐  │
│  │                    TPM2 Backend                             │  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │  Session Management                                    ││  │
│  │  │  • HMAC sessions for authorization                     ││  │
│  │  │  • Policy sessions for PCR-based access                ││  │
│  │  │  • Encrypted sessions for parameter protection         ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │  Key Operations                                        ││  │
│  │  │  • CreatePrimary for hierarchy keys                    ││  │
│  │  │  • Create for child keys                               ││  │
│  │  │  • Load/ContextSave/ContextLoad for session mgmt       ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │  Cryptographic Operations                              ││  │
│  │  │  • Sign/Verify with loaded keys                        ││  │
│  │  │  • Encrypt/Decrypt for data protection                 ││  │
│  │  │  • Quote for attestation                               ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Key Attributes Structure

```go
type KeyAttributes struct {
    CN             string              // Common name
    KeyAlgorithm   x509.PublicKeyAlgorithm
    KeyType        KeyType             // TLS, Signing, Encryption, HMAC
    Password       Password            // Key authorization
    PlatformPolicy bool                // Use PCR policy
    StoreType      StoreType           // TPM2, PKCS11, Software
    Parent         *KeyAttributes      // Parent key reference
    TPMAttributes  *TPMAttributes      // TPM-specific attributes
}

type TPMAttributes struct {
    Handle        uint32              // Persistent handle
    HierarchyAuth Password            // Hierarchy authorization
    Hierarchy     TPMHierarchy        // Owner, Endorsement, Platform
}
```

## Session Management

```
┌───────────────────────────────────────────────────────────────────┐
│                       TPM Session Types                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  HMAC Session                                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Password-based authorization                              │  │
│  │ • Used for key operations requiring owner auth              │  │
│  │ • Session key derived from shared secret                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Policy Session                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • PCR-based authorization                                   │  │
│  │ • Required for sealed objects                               │  │
│  │ • Compound policies (PCR + password)                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Encrypted Session                                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Parameter encryption on CPU<->TPM bus                     │  │
│  │ • Protects against side-channel attacks                     │  │
│  │ • XOR or AES encryption modes                               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## NVRAM Organization

```
┌───────────────────────────────────────────────────────────────────┐
│                        TPM NVRAM Layout                           │
├───────────────────┬───────────────────────────────────────────────┤
│ Index Range       │ Purpose                                       │
├───────────────────┼───────────────────────────────────────────────┤
│ 0x01C00002        │ EK Certificate (RSA)                          │
│ 0x01C0000A        │ EK Certificate (ECC)                          │
│ 0x01C00012        │ Platform Certificate                          │
│ 0x01800000-       │ Application-defined indices                   │
│ 0x01BFFFFF        │                                               │
└───────────────────┴───────────────────────────────────────────────┘
```

## Error Handling

| TPM Error          | Platform Handling                             |
|--------------------|-----------------------------------------------|
| TPM_RC_LOCKOUT     | Retry with exponential backoff                |
| TPM_RC_AUTH_FAIL   | Log failure, increment counter                |
| TPM_RC_HANDLE      | Handle not found, check provisioning          |
| TPM_RC_NV_LOCKED   | NVRAM locked, requires platform auth          |
| TPM_RC_PCR_CHANGED | PCR state changed, re-seal required           |

## Performance Considerations

| Operation          | Typical Latency | Notes                        |
|--------------------|-----------------|------------------------------|
| RSA-2048 Sign      | 100-500ms       | Hardware dependent           |
| ECDSA P-256 Sign   | 20-100ms        | Faster than RSA              |
| Seal (128 bytes)   | 50-200ms        | Plus policy evaluation       |
| Unseal             | 50-200ms        | Plus PCR verification        |
| Quote              | 100-500ms       | Depends on PCR count         |
| GetRandom (32B)    | 5-20ms          | Hardware RNG                 |

## Related Documentation

- [README](README.md) - TPM module overview
- [Attestation](attestation.md) - Remote attestation
- [Sealing](sealing.md) - Data protection
- [PCRs](pcrs.md) - Platform Configuration Register reference
- [Security](security.md) - Security considerations and CVEs
- [Configuration](configuration.md) - TPM configuration options
- [API Reference](api-reference.md) - gRPC TPM API
