# vTPM Architecture

## Overview

The vTPM service provides virtual TPM bundle management for VM provisioning. It creates complete swtpm state with CA-issued EK certificates and optional UEFI Secure Boot keys.

## Design Goals

1. **Pre-provisioned Identity** - Bundles include EK certificates before VM deployment
2. **Template Cloning** - Rapid provisioning from base images
3. **Secure Boot Integration** - UEFI key generation and enrollment
4. **Portability** - Export/import bundles between systems
5. **Integrity** - Checksum verification of bundle contents

## Bundle Structure

```
/var/lib/trusted-platform/vtpm/
├── bundles/
│   └── {bundle-id}/
│       ├── manifest.json      # Bundle metadata
│       ├── tpm/
│       │   ├── tpm2-00.permall   # Persistent TPM state
│       │   └── swtpm.sock        # Runtime socket (when running)
│       ├── ovmf/
│       │   └── OVMF_VARS.fd      # UEFI NVRAM
│       └── secureboot/           # If Secure Boot enabled
│           ├── PK.key            # Platform Key
│           ├── PK.crt
│           ├── KEK.key           # Key Exchange Key
│           ├── KEK.crt
│           ├── DB.key            # Signature Database
│           └── DB.crt
└── templates/
    └── {template-id}/
        ├── tpm/
        │   └── tpm2-00.permall
        ├── ovmf/
        │   └── OVMF_VARS.fd
        └── secureboot/
            └── ...
```

## Bundle Modes

### Pre-Assigned Mode

Complete bundles with identity issued at creation time.

```
Create Bundle
     │
     ├─▶ Initialize swtpm
     │        │
     │        ├─▶ Create EK key pair
     │        │
     │        └─▶ Store EK certificate in NV RAM
     │
     ├─▶ Generate Secure Boot keys (if enabled)
     │        │
     │        ├─▶ Create PK, KEK, DB keys
     │        │
     │        └─▶ Enroll in OVMF NVRAM
     │
     └─▶ Create manifest with checksums
```

**Use Case:** Direct VM deployment where each VM needs immediate TPM identity.

### Template Mode

Base images without identity; EK certificate issued at clone time.

```
Create Template                Clone Template
     │                               │
     ├─▶ Initialize swtpm            ├─▶ Copy TPM state
     │   (no EK cert)                │
     │                               ├─▶ Copy OVMF NVRAM
     ├─▶ Generate Secure Boot        │
     │   keys (shared)               ├─▶ Copy Secure Boot keys
     │                               │
     └─▶ Create base state           ├─▶ Generate EK certificate
                                     │
                                     └─▶ Create manifest
```

**Use Case:** Fleet provisioning where VMs share common configuration but need unique identities.

## EK Certificate Provisioning

The service integrates with the platform CA to issue EK certificates.

### Certificate Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   vTPM       │    │  Certificate │    │   swtpm      │
│   Service    │    │   Authority  │    │   State      │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │  Initialize       │                   │
       ├───────────────────────────────────────▶
       │                   │                   │
       │  Create EK Key    │                   │
       │◀──────────────────────────────────────┤
       │                   │                   │
       │  Request Cert     │                   │
       ├──────────────────▶│                   │
       │                   │                   │
       │  Issue EK Cert    │                   │
       │◀──────────────────┤                   │
       │                   │                   │
       │  Store in NV RAM  │                   │
       ├───────────────────────────────────────▶
       │                   │                   │
```

### NV Index Locations

| Algorithm | NV Index | TCG Specification |
|-----------|----------|-------------------|
| RSA 2048 | 0x01C00002 | PC Client Platform TPM Profile |
| ECC P-256 | 0x01C0000A | PC Client Platform TPM Profile |

## Secure Boot Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                    Platform Key (PK)                            │
│                    Self-signed, top of chain                    │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ signs
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Key Exchange Key (KEK)                         │
│                  Signed by PK                                   │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ signs
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Signature Database (DB)                      │
│                    Signed by KEK                                │
│                    Signs bootloaders and kernels                │
└─────────────────────────────────────────────────────────────────┘
```

### Key Generation

```go
// Default configuration
SecureBootKeySize:      2048     // RSA key size
SecureBootValidYears:   10       // Certificate validity
SecureBootCommonName:   "Trusted Platform"
SecureBootOrganization: "Trusted Platform"
```

## Export Archive Format

Bundles are exported as gzip-compressed tar archives:

```
bundle-{id}.vtpm.tar.gz
├── manifest.json
├── tpm/
│   └── tpm2-00.permall
├── ovmf/
│   └── OVMF_VARS.fd
└── secureboot/           # If Secure Boot enabled
    ├── PK.key
    ├── PK.crt
    ├── KEK.key
    ├── KEK.crt
    ├── DB.key
    └── DB.crt
```

### Manifest Schema

```json
{
  "version": "1.0",
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mode": "pre-assigned",
  "hostname": "vm001.example.com",
  "created_at": "2025-01-15T10:30:00Z",
  "ek_certificate": {
    "subject": "CN=vm001.example.com",
    "issuer": "CN=Trusted Platform CA",
    "serial_number": "1234567890",
    "not_before": "2025-01-15T10:30:00Z",
    "not_after": "2026-01-15T10:30:00Z",
    "fingerprint": "SHA256:AB:CD:EF:..."
  },
  "ek_algorithm": "RSA",
  "ek_handle": 29360130,
  "secure_boot_enabled": true,
  "secure_boot_keys": {
    "pk_fingerprint": "SHA256:...",
    "kek_fingerprint": "SHA256:...",
    "db_fingerprint": "SHA256:...",
    "owner_guid": "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
  },
  "checksums": {
    "tpm2-00.permall": "e3b0c44298fc1c149afbf4c8996fb924...",
    "OVMF_VARS.fd": "b94d27b9934d3e08a52e52d7da7dabfa..."
  },
  "labels": {
    "environment": "production"
  }
}
```

## VM Integration

### QEMU/KVM Attachment

```bash
# Start swtpm for bundle
swtpm socket \
  --tpmstate dir=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm \
  --ctrl type=unixio,path=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm/swtpm.sock \
  --tpm2

# Start VM with vTPM
qemu-system-x86_64 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,file=/var/lib/trusted-platform/vtpm/bundles/{id}/ovmf/OVMF_VARS.fd \
  -chardev socket,id=chrtpm,path=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm/swtpm.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

### libvirt Integration

```xml
<domain type='kvm'>
  <tpm model='tpm-tis'>
    <backend type='emulator' version='2.0'>
      <source path='/var/lib/trusted-platform/vtpm/bundles/{id}/tpm'/>
    </backend>
  </tpm>
  <os firmware='efi'>
    <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.secboot.fd</loader>
    <nvram>/var/lib/trusted-platform/vtpm/bundles/{id}/ovmf/OVMF_VARS.fd</nvram>
  </os>
</domain>
```

## Dependencies

| Component | Purpose |
|-----------|---------|
| `swtpm` | Software TPM implementation |
| `swtpm_setup` | TPM initialization tool |
| `OVMF` | UEFI firmware for VMs |
| `openssl` | Key and certificate generation |
| `sbsigntool` | Secure Boot signing (optional) |

## Security Considerations

### Key Protection

- Secure Boot private keys are stored unencrypted on disk
- Access should be restricted via filesystem permissions
- Consider HSM storage for production deployments

### EK Certificate Trust

- EK certificates are signed by the platform CA
- Verifiers must trust the CA chain
- Certificate revocation requires CRL distribution

### Bundle Integrity

- All files are checksummed in manifest
- Import validates checksums before extraction
- Export includes all required files

### Template Security

- Templates share Secure Boot keys across clones
- Each clone gets unique EK certificate
- Consider key rotation for long-lived templates
