# Virtual TPM Bundle Management

Manage vTPM bundles for VM provisioning with CA-issued EK certificates and UEFI Secure Boot.

## Overview

The vTPM service provides centralized management of virtual TPM bundles for VM deployment. It creates initialized swtpm state with CA-issued Endorsement Key certificates and optional UEFI Secure Boot keys.

## Key Features

| Feature | Description |
|---------|-------------|
| **Pre-Assigned Bundles** | Complete bundles with EK certificates issued at creation |
| **Template Cloning** | Base images with identity issued at clone time |
| **Secure Boot Keys** | PK, KEK, DB key generation and NVRAM enrollment |
| **EK Certificates** | CA-issued certificates stored in TPM NV RAM |
| **Export/Import** | Portable tar.gz archives with checksums |
| **Validation** | Integrity verification of bundle contents |

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                           vTPM Service                                    │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Bundle Types:                                                           │
│   ┌─────────────────┐              ┌─────────────────┐                    │
│   │   Pre-Assigned  │              │    Template     │                    │
│   │   Complete ID   │  ──clone──▶  │   Base Image    │                    │
│   │   Ready to Use  │              │   No Identity   │                    │
│   └─────────────────┘              └─────────────────┘                    │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Bundle Contents:                                                        │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐    │
│   │  manifest   │  │    swtpm    │  │    OVMF     │  │  Secure Boot  │    │
│   │    .json    │  │    state    │  │    NVRAM    │  │     keys      │    │
│   └─────────────┘  └─────────────┘  └─────────────┘  └───────────────┘    │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   Integration:                                                            │
│                                                                           │
│   Certificate Authority ──▶ Issues EK Certificates                        │
│   UEFI Secure Boot      ──▶ Key enrollment in NVRAM                       │
│   VM Hypervisor         ──▶ Attaches bundle to VM                         │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Create a Pre-Assigned Bundle

```bash
# Create bundle with default settings (RSA EK, Secure Boot enabled)
platformd vtpm create --hostname vm001.example.com

# Create with ECC EK algorithm
platformd vtpm create --hostname vm001.example.com --ek-algorithm ECC

# Create without Secure Boot
platformd vtpm create --hostname vm001.example.com --secure-boot=false
```

### Use Templates for Cloning

```bash
# Create a template
platformd vtpm template create --id base-server

# Clone template to create new bundle
platformd vtpm clone --template base-server --hostname vm002.example.com
```

### List and Inspect Bundles

```bash
# List all bundles
platformd vtpm list

# List only templates
platformd vtpm list --mode template

# Get bundle details
platformd vtpm info <bundle-id>
```

### Export and Import

```bash
# Export bundle to archive
platformd vtpm export <bundle-id> -o bundle.vtpm.tar.gz

# Import bundle from archive
platformd vtpm import bundle.vtpm.tar.gz
```

## Bundle Modes

| Mode | Description | EK Certificate | Use Case |
|------|-------------|----------------|----------|
| `pre-assigned` | Complete bundle | Issued at creation | Direct VM deployment |
| `template` | Base image | Issued at clone time | Fleet provisioning |

## EK Algorithms

| Algorithm | Key Size | NV Index | Notes |
|-----------|----------|----------|-------|
| `RSA` | 2048-bit | 0x01C00002 | Default, widest compatibility |
| `ECC` | P-256 | 0x01C0000A | Smaller certificate size |

## Configuration

```yaml
# config.yaml
vtpm:
  base-dir: /var/lib/trusted-platform/vtpm
  ovmf-code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf-code-secure: /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf-vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  pcr-banks:
    - sha256
  secure-boot-key-size: 2048
  secure-boot-valid-years: 10
  ek-algorithm: RSA
```

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Usage](cli-usage.md) | Command-line interface |
| [API Reference](api-reference.md) | Service API documentation |
| [Architecture](architecture.md) | Design and implementation details |
| [Configuration](configuration.md) | Configuration reference |

## Integration

The vTPM service integrates with:

- **Certificate Authority** - Issues EK certificates
- **UEFI Secure Boot** - Key enrollment in OVMF NVRAM
- **VM Hypervisors** - QEMU/KVM with swtpm attachment
- **Remote Attestation** - Platform identity verification

## See Also

- [TPM Documentation](../tpm/README.md)
- [Secure Boot](../firmware/secure-boot.md)
- [Certificate Authority](../ca/)
