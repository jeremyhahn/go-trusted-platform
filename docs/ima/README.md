# Linux IMA (Integrity Measurement Architecture)

Linux IMA provides runtime file integrity monitoring by measuring files at access time and recording those measurements in PCR 10 of the TPM.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IMA Security Architecture                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────────┐ │
│  │   File Access  │───▶│  IMA Subsystem │───▶│   PCR 10 (TPM)     │ │
│  │   (exec/mmap)  │    │  (Measure/Log) │    │   Measurements     │ │
│  └────────────────┘    └───────┬────────┘    └────────────────────┘ │
│                                │                                     │
│                                ▼                                     │
│                    ┌───────────────────────┐                         │
│                    │   Event Log           │                         │
│                    │   /sys/kernel/security│                         │
│                    │   /ima/...            │                         │
│                    └───────────────────────┘                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Capabilities

| Feature | Description |
|---------|-------------|
| **File Measurement** | Hash files on access and extend to PCR 10 |
| **Signature Verification** | Verify file signatures before execution (appraise mode) |
| **Policy Engine** | Flexible rules for what to measure/appraise |
| **TPM Integration** | Extend measurements to PCR 10 for attestation |
| **Audit Logging** | Log IMA events to audit subsystem |
| **EVM Support** | Protect file metadata with extended attributes |

## Quick Start

### 1. Enable IMA in Platform Configuration

```yaml
# config.yaml
ima:
  enabled: true
  policy: tcb                # Trusted Computing Base
  hash-algorithm: sha256
  appraise-mode: log         # Log failures but allow execution
  audit-enabled: true
```

### 2. Build and Install

```bash
# Build the installer ISO with IMA enabled
make iso

# Install the platform
# IMA is enabled via kernel command line during boot
```

### 3. Verify IMA is Active

```bash
# Check IMA status
cat /sys/kernel/security/ima/policy

# View IMA measurements
cat /sys/kernel/security/ima/ascii_runtime_measurements

# Check PCR 10 value
cat /sys/class/tpm/tpm0/pcr-sha256/10
```

## Security Model

IMA integrates with the platform's measured boot chain:

```
┌────────────────────────────────────────────────────────────────────┐
│                     Measured Boot Chain                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PCR 0  ─────▶  UEFI Firmware                                       │
│  PCR 7  ─────▶  Secure Boot State                                   │
│  PCR 9  ─────▶  Kernel Command Line (includes IMA params)           │
│  PCR 10 ─────▶  IMA File Measurements  ◀──── Runtime integrity      │
│                                                                     │
│  Golden Measurement = Hash(PCR0 || PCR7 || PCR9 || PCR10)           │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

**Important:** PCR 10 changes on every boot as files are measured. It is suitable for:
- Post-boot application key sealing (once measurements complete)
- Remote attestation verification
- Runtime integrity verification

It is **NOT** suitable for:
- LUKS disk encryption key sealing (use PCR 0, 7, 9 instead)

## Policy Types

| Policy | Description | Use Case |
|--------|-------------|----------|
| `tcb` | Measures executables, libraries, kernel modules | Default for most deployments |
| `appraise_tcb` | Measures AND verifies signatures | High-security environments |
| `secure_boot` | Minimal policy for secure boot only | Lightweight deployments |
| `critical_data` | Measures critical kernel data only | Specialized use cases |

## Platform Integration

IMA measurements are used throughout the platform:

| Component | IMA Usage |
|-----------|-----------|
| **Remote Attestation** | Include PCR 10 in attestation quotes |
| **Workload Verification** | Verify container/VM integrity |
| **Intrusion Detection** | Detect unauthorized file modifications |
| **Compliance** | Maintain audit trail of executed code |

## Related Documentation

- [Configuration](configuration.md) - Complete configuration reference
- [Policies](policies.md) - Policy syntax and examples
- [TPM Integration](tpm-integration.md) - PCR 10 and attestation
- [API Reference](api-reference.md) - Go package API
- [Troubleshooting](troubleshooting.md) - Common issues and debugging

## References

- [Linux IMA Wiki](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [IMA/EVM in the Linux Kernel](https://www.kernel.org/doc/html/latest/security/IMA.html)
- [TCG PC Client Platform Firmware Profile](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/)
