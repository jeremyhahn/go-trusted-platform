# TPM2 Module

> **Status: REFERENCE** · Last verified: 2026-10-15
> Overview of the TPM 2.0 integration. The API contract is [api.md](api.md).

The Trusted Platform Module (TPM) 2.0 integration provides hardware-backed security
operations including key management, attestation, sealing/unsealing, and cryptographic
operations for the go-trusted-platform.

```
┌───────────────────────────────────────────────────────────────────┐
│                        Trusted Platform                           │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │   Certificate    │  │    Attestation   │  │     Sealing      │ │
│  │    Authority     │  │      Service     │  │     Service      │ │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘ │
│           │                     │                     │           │
│           └─────────────────────┼─────────────────────┘           │
│                                 │                                 │
│                    ┌────────────┴────────────┐                    │
│                    │      TPM Interface      │                    │
│                    │ (go-xkms TPM2 pkg)  │                    │
│                    └────────────┬────────────┘                    │
│                                 │                                 │
└───────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │    TPM 2.0 Hardware       │
                    │    or Software TPM        │
                    └───────────────────────────┘
```

## TPM Capabilities

| Capability               | Description                                      |
|--------------------------|--------------------------------------------------|
| Key Generation           | RSA, ECDSA, Ed25519 key generation in hardware   |
| Key Storage              | Secure persistent storage in TPM NVRAM           |
| Attestation              | Quote generation and verification                |
| Sealing/Unsealing        | Data protection bound to PCR state               |
| Random Number Generation | Hardware-based cryptographic RNG                 |
| PCR Operations           | Read, extend, and policy-based access            |
| NVRAM Storage            | Define, read, write secure storage areas         |
| FIPS 140-2 Support       | Compliant cryptographic operations               |

## Platform Integration

The TPM integrates with the following platform components:

| Component             | TPM Usage                                        |
|-----------------------|--------------------------------------------------|
| Certificate Authority | EK/AK certificates, IDevID issuance              |
| Key Management        | Hardware-backed key storage and operations       |
| LUKS Encryption       | Disk encryption key sealing                      |
| Secure Boot           | PCR-based boot measurement verification          |
| Network Access        | 802.1X device authentication via IDevID          |
| ACME Server           | enroll-01 challenge attestation                  |

## Quick Start

### 1. Check TPM Availability

```bash
# View TPM information
platformctl tpm info
```

### 2. Provision TPM

```bash
# Create the EK, SRK and attestation key (each on by default)
platformctl tpm provision
```

### 3. Display Key Hierarchy

```bash
# View Endorsement Key
platformctl tpm ek info

# View Storage Root Key
platformctl tpm srk info
```

### 4. Seal Data

```bash
# Seal a secret to the current state of PCR 7
platformctl tpm seal --cn my-secret --data "sensitive data" --pcrs 7

# Unseal the secret (requires matching PCR state)
platformctl tpm unseal --cn my-secret --pcrs 7
```

## Key Hierarchy

The TPM key hierarchy follows TCG recommended guidance:

```
┌───────────────────────────────────────────────────────────────────┐
│                        TPM 2.0 Key Hierarchy                      │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────┐  Primary Seed (PS)                    │
│  │   Endorsement Seed     │  Hardware-rooted, unique per TPM      │
│  └──────────┬─────────────┘                                       │
│             │                                                     │
│             ▼                                                     │
│  ┌──────────┴─────────────┐  Endorsement Key (EK)                 │
│  │         EK             │  Handle: 0x81010001                   │
│  │   (RSA-2048/ECC-384)   │  Certified by manufacturer            │
│  └──────────┬─────────────┘                                       │
│             │                                                     │
│             ▼                                                     │
│  ┌──────────┴─────────────┐  Storage Root Key (SRK)               │
│  │        SSRK            │  Handle: 0x81000001                   │
│  │   (Shared Storage)     │  Protects all storage hierarchy keys  │
│  └──────────┬─────────────┘                                       │
│             │                                                     │
│    ┌────────┴────────┐                                            │
│    │                 │                                            │
│    ▼                 ▼                                            │
│  ┌────┐         ┌────┴────┐                                       │
│  │ AK │         │ IDevID  │  Attestation Key / Device Identity    │
│  └────┘         └─────────┘  Handle: 0x81010002 / 0x81020000      │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Supported Algorithms

| Algorithm    | Key Sizes/Curves | Use Cases                       |
|--------------|------------------|---------------------------------|
| RSA          | 2048, 3072, 4096 | EK, SRK, signing, encryption    |
| ECDSA        | P-256, P-384     | EK, AK, signing                 |
| Ed25519      | 256-bit          | Signing (via software)          |
| AES          | 128, 256         | Symmetric encryption            |
| SHA          | 256, 384, 512    | PCR banks, hashing              |

## Configuration

TPM configuration is specified in the platform configuration file (as shipped in
`configs/platform/templates/single-node/default.yaml`):

```yaml
tpm:
  device: /dev/tpmrm0           # TPM device path (use /dev/tpm0 for exclusive access)
  simulator: false              # Use software TPM (swtpm) instead of hardware
  encrypt-sessions: false       # Encrypt TPM command sessions
  entropy: false                # Use TPM as entropy source
  hash: SHA-256                 # Default hash algorithm

  # Endorsement Key (EK) - manufacturer-certified identity key
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048

  # Shared Storage Root Key (SSRK) - protects storage hierarchy
  ssrk:
    handle: 0x81000001
    platform-policy: false
    rsa:
      size: 2048

  # Initial Attestation Key (IAK) - for remote attestation
  iak:
    handle: 0x81010002
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048

  # Initial Device ID (IDevID) - device identity certificate
  idevid:
    handle: 0x81020000
    cert-handle: 0x01C90000   # currently IGNORED (see configuration.md)
    model: edge
    serial: device-serial-001
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048

  # PCR configuration
  platform-pcr: 23              # PCR for platform measurements
  platform-pcr-bank: sha256     # PCR bank to use
  golden-pcrs: [7, 9]           # PCRs for sealing (Secure Boot + kernel cmdline)

  # PlatformSRK: a different key from the SSRK
  platform-srk:
    srk-handle: 0x81000002
    srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"
    platform-policy: true       # Bind to platform PCR state
```

See [configuration.md](configuration.md) for complete TPM configuration options.

## Related Documentation

- [Overview](overview.md) - TPM introduction, tools, tutorials, and examples
- [Architecture](architecture.md) - TPM integration architecture
- [Attestation](attestation.md) - Remote attestation operations
- [Sealing](sealing.md) - Data sealing and unsealing
- [PCRs](pcrs.md) - Platform Configuration Register reference
- [Security](security.md) - Security considerations and CVEs
- [API Reference](api-reference.md) - gRPC API documentation
- [CLI Usage](cli-usage.md) - Command-line reference
- [Configuration](configuration.md) - TPM configuration options

## References

### TCG Specifications

- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [TCG TPM 2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)
- [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
- [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf)
- [TCG OID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf)
- [TCG FIPS 140-3 Guidance for TPM 2.0](https://trustedcomputinggroup.org/wp-content/uploads/TCG-FIPS-140-3-Guidance-for-TPM-2.0-Version-1.0-Revision-1_14Feb24.pdf)
- [TCG CPU-TPM Bus Protection Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG_-CPU_-TPM_Bus_Protection_Guidance_Active_Attack_Mitigations-V1-R30_PUB-1.pdf)

### NIST Standards

- [NIST SP 800-57 Key Management Recommendations](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf)

### Platform Integration

- [Linux TPM PCR Registry (UAPI Group)](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
- [OPC UA Device Onboarding](https://reference.opcfoundation.org/Onboarding/v105/docs/5.1)
- [ACME Device Attestation Draft](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03)

### Implementation Guides

- [TPM 2.0 Software Stack Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
- [Remote Attestation with tpm2-tools](https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html)
- [Disk Encryption with TPM](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)
- [TPM Remote Attestation with go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
- [TPM-based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
- [TPM Key Concepts](https://ericchiang.github.io/post/tpm-keys/)
- [LUKS TPM2 Integration](https://github.com/salrashid123/tpm2/blob/master/luks/README.md)

### Security Resources

- [Vulnerabilities in TPM 2.0 Reference Implementation (Quarkslab)](https://blog.quarkslab.com/vulnerabilities-in-the-tpm-20-reference-implementation-code.html)
- [TPM 2.0 Session and Authorization (Springer)](https://link.springer.com/chapter/10.1007/978-1-4302-6584-9_13)
