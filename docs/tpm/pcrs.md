# TPM Platform Configuration Registers (PCRs)

> **Status: REFERENCE**
> PCR allocation and measurement sources, by platform.

This document provides a comprehensive reference for TPM Platform Configuration Registers (PCRs), including their allocation, measurement sources, and usage across different platforms.

## PCR Overview

Platform Configuration Registers are special TPM registers that store cryptographic measurements (hashes) of software and configuration data during the boot process. These measurements form a chain of trust that enables remote attestation and data sealing.

Key characteristics:
- PCRs can only be extended, not directly written
- Extension: `PCR[i] = Hash(PCR[i] || measurement)`
- PCRs are reset only on platform reset
- Multiple hash algorithms (banks) may be supported (SHA-1, SHA-256, SHA-384)

## Linux PCR Assignments

The following table documents PCR usage on Linux systems following the UAPI Group specification:

| PCR | Used By | From Location | Measured Objects | Log | Use Reported By |
|-----|---------|---------------|------------------|-----|-----------------|
| 0 | Firmware | UEFI Boot Component | Core system firmware executable code | UEFI TPM event log | n/a |
| 1 | Firmware | UEFI Boot Component | Core system firmware data/host platform configuration; typically contains serial and model numbers | UEFI TPM event log | n/a |
| 2 | Firmware | UEFI Boot Component | Extended or pluggable executable code; includes option ROMs on pluggable hardware | UEFI TPM event log | n/a |
| 3 | Firmware | UEFI Boot Component | Extended or pluggable firmware data; includes information about pluggable hardware | UEFI TPM event log | n/a |
| 4 | Firmware | UEFI Boot Component | Boot loader and additional drivers; binaries and extensions loaded by the boot loader | UEFI TPM event log | n/a |
| 5 | Firmware | UEFI Boot Component | GPT/Partition table | UEFI TPM event log | n/a |
| 7 | Firmware | UEFI Boot Component | SecureBoot state | UEFI TPM event log | n/a |
| 8 | grub | UEFI Boot Component | Commands and kernel command line | UEFI TPM event log | n/a |
| 9 | grub | UEFI Boot Component | All files read (including kernel image) | UEFI TPM event log | n/a |
| 9 | Linux Kernel | Kernel | All passed initrds (when the new LOAD_FILE2 initrd protocol is used) | UEFI TPM event log | n/a |
| 10 | IMA | Kernel | Protection of the IMA measurement log | IMA event log | n/a |
| 11 | systemd-stub | UEFI Stub | All components of unified kernel images (UKIs) | UEFI TPM event log | in EFI variable StubPcrKernelImage |
| 11 | systemd-pcrphase | Userspace | Boot phase strings, indicating various milestones of the boot process | Journal (for now) | n/a |
| 12 | systemd-stub | UEFI Stub | Kernel command line, system credentials and system configuration images | UEFI TPM event log | in EFI variable StubPcrKernelParameters |
| 13 | systemd-stub | UEFI Stub | All system extension images for the initrd | UEFI TPM event log | in EFI variable StubPcrInitRDSysExts |
| 14 | shim | UEFI Boot Component | "MOK" certificates and hashes | UEFI TPM event log | n/a |
| 15 | systemd-cryptsetup | Userspace | Root file system volume encryption key | Journal (for now) | n/a |
| 15 | systemd-pcrmachine | Userspace | Machine ID (/etc/machine-id) | Journal (for now) | n/a |
| 15 | systemd-pcrfs | Userspace | File system mount point, UUID, label, partition UUID label of root file system and /var/ | Journal (for now) | n/a |

## Microsoft Windows PCR Assignments

PCR usage on Windows systems differs from Linux:

| PCR | Contents |
|-----|----------|
| 0 | Core root-of-trust for measurement, EFI boot and run-time services, EFI drivers embedded in system ROM, ACPI static tables, embedded SMM code, and BIOS code |
| 1 | Platform and motherboard configuration and data. Handoff tables and EFI variables that affect system configuration |
| 2 | Option ROM code |
| 3 | Option ROM data and configuration |
| 4 | Master boot record (MBR) code or code from other boot devices |
| 5 | Master boot record (MBR) partition table. Various EFI variables and the GPT table |
| 6 | State transition and wake events |
| 7 | Computer manufacturer-specific |
| 8 | NTFS boot sector |
| 9 | NTFS boot block |
| 10 | Boot manager |
| 11 | BitLocker access control |

## Secure Boot vs Trusted Boot

Understanding the difference between these complementary security mechanisms:

**Trusted Boot (Measured Boot)**
- Uses cryptographic hashing to measure each step of the boot process
- Measurements are extended into PCRs
- Does not prevent execution of untrusted code
- Enables post-boot verification via remote attestation

**Secure Boot**
- Uses digital signatures to verify firmware and bootloaders
- Prevents execution of unsigned or improperly signed code
- Provides active protection during boot
- Typically configured alongside trusted boot

## PCR Policy Recommendations

### Boot Integrity Verification

For verifying firmware and secure boot state:

| Use Case | Recommended PCRs | Description |
|----------|------------------|-------------|
| Firmware Only | 0, 1, 2, 3, 7 | Core firmware and Secure Boot |
| Boot Chain | 0-5, 7 | Complete firmware through bootloader |
| Kernel Integrity | 7, 8, 9 | Secure Boot + kernel + initrd |
| UKI Integrity | 7, 11 | Unified Kernel Image |
| Full Integrity | 0-3, 7-9, 11 | Complete boot chain verification |

### Sealing Policies

Recommended PCR combinations for different security levels:

```yaml
# Standard security - kernel and secure boot
standard:
  pcrs: [7, 8, 9]
  description: "Secure Boot state and kernel configuration"

# High security - full boot chain
high_security:
  pcrs: [0, 1, 2, 3, 7, 8, 9, 11]
  description: "Complete boot chain from firmware to UKI"

# LUKS encryption - minimal but effective
luks:
  pcrs: [7, 11]
  description: "Secure Boot and UKI for disk encryption"
```

## Reading PCR Values

### Command Line

```bash
# Read all PCRs using tpm2-tools
tpm2_pcrread

# Read specific PCRs
tpm2_pcrread sha256:0,1,2,3,7

# Using platformctl
platformctl tpm pcr read --indices 0,1,2,3,7 --bank SHA256
```

### Programmatic Access

```go
// gRPC request to read PCRs
request := &platformv1.GetPCRsRequest{
    Indices: []uint32{0, 1, 2, 3, 7},
    Bank:    platformv1.PCRBank_PCR_BANK_SHA256,
}

response, err := client.GetPCRs(ctx, request)
for _, pcr := range response.PcrValues {
    fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Value)
}
```

## Event Log Verification

PCR values can be verified by replaying the TPM event log:

```
Event Log Location: /sys/kernel/security/tpm0/binary_bios_measurements

Verification Process:
1. Start with PCR initial value (all zeros)
2. For each event in the log:
   - Extract the digest
   - Extend: PCR[i] = Hash(PCR[i] || digest)
3. Compare computed PCR with actual TPM value
4. Values should match if log is complete and authentic
```

## Related Documentation

- [README](README.md) - TPM module overview
- [Architecture](architecture.md) - TPM key hierarchy and integration
- [Attestation](attestation.md) - Remote attestation using PCRs
- [Sealing](sealing.md) - PCR-based data protection
- [Configuration](configuration.md) - PCR policy configuration

## References

- [Linux TPM PCR Registry (UAPI Group)](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
- [Understanding UEFI Secure Boot Chain](https://laurie0131.gitbooks.io/understanding-uefi-secure-boot-chain/content/overview.html)
- [Measured Boot with TPM 2.0 in U-Boot](https://bootlin.com/blog/measured-boot-with-a-tpm-2-0-in-u-boot/)
- [Disk Encryption with TPM](https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html)
- [LUKS TPM2 Integration](https://github.com/salrashid123/tpm2/blob/master/luks/README.md)
