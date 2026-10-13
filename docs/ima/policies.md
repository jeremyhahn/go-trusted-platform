# IMA Policies

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and [user.md](user.md). Custom `monitor-paths` emit `obj_type=<path>` rules, which match SELinux types, not paths ([architecture.md §9](architecture.md)).

IMA policies define what files are measured and/or appraised.

## Policy Rule Syntax

IMA policy rules follow this format:

```
<action> <conditions>
```

### Actions

| Action | Description |
|--------|-------------|
| `measure` | Measure file and extend to PCR 10 |
| `appraise` | Verify file signature before execution |
| `audit` | Log file access to audit subsystem |
| `hash` | Calculate hash (no PCR extension) |
| `dont_measure` | Exclude from measurement |
| `dont_appraise` | Exclude from appraisal |
| `dont_audit` | Exclude from audit logging |

### Condition Keywords

| Keyword | Description | Example |
|---------|-------------|---------|
| `func=` | Function type | `func=BPRM_CHECK` |
| `mask=` | Access mask | `mask=MAY_EXEC` |
| `pcr=` | PCR to extend | `pcr=10` |
| `template=` | Template format | `template=ima-ng` |
| `fowner=` | File owner UID | `fowner=0` |
| `uid=` | Process UID | `uid=0` |
| `fsmagic=` | Filesystem magic number | `fsmagic=0x9fa0` |
| `fsuuid=` | Filesystem UUID | `fsuuid=...` |
| `obj_type=` | SELinux object type | `obj_type=bin_t` |
| `appraise_type=` | Signature type | `appraise_type=imasig` |

### Function Types

| Function | Description |
|----------|-------------|
| `BPRM_CHECK` | Binary execution (exec, execve) |
| `MMAP_CHECK` | Memory-mapped file execution |
| `FILE_CHECK` | File open/read |
| `MODULE_CHECK` | Kernel module loading |
| `FIRMWARE_CHECK` | Firmware loading |
| `KEXEC_KERNEL_CHECK` | Kexec kernel loading |
| `KEXEC_INITRAMFS_CHECK` | Kexec initramfs loading |
| `POLICY_CHECK` | IMA policy loading |
| `KEY_CHECK` | Keyring key operations |

### Access Masks

| Mask | Description |
|------|-------------|
| `MAY_READ` | Read access |
| `MAY_WRITE` | Write access |
| `MAY_EXEC` | Execute access |
| `MAY_APPEND` | Append access |

### Template Types

| Template | Description |
|----------|-------------|
| `ima-ng` | Standard template: hash + path |
| `ima-sig` | Signature template: hash + path + signature |

## Built-in Policies

### TCB (Trusted Computing Base)

Measures all executables, libraries, and kernel modules.

```
measure func=BPRM_CHECK mask=MAY_EXEC pcr=10 template=ima-ng
measure func=MMAP_CHECK mask=MAY_EXEC pcr=10 template=ima-ng
measure func=MODULE_CHECK pcr=10 template=ima-ng
measure func=FIRMWARE_CHECK pcr=10 template=ima-ng
measure func=KEXEC_KERNEL_CHECK pcr=10 template=ima-ng
measure func=KEXEC_INITRAMFS_CHECK pcr=10 template=ima-ng
```

### Appraise TCB

Measures AND verifies signatures for TCB.

```
measure func=BPRM_CHECK mask=MAY_EXEC pcr=10 template=ima-sig
appraise func=BPRM_CHECK mask=MAY_EXEC fowner=0 appraise_type=imasig
measure func=MMAP_CHECK mask=MAY_EXEC pcr=10 template=ima-sig
appraise func=MMAP_CHECK mask=MAY_EXEC fowner=0 appraise_type=imasig
measure func=MODULE_CHECK pcr=10 template=ima-sig
appraise func=MODULE_CHECK fowner=0 appraise_type=imasig
measure func=FIRMWARE_CHECK pcr=10 template=ima-sig
measure func=KEXEC_KERNEL_CHECK pcr=10 template=ima-sig
measure func=KEXEC_INITRAMFS_CHECK pcr=10 template=ima-sig
```

### Secure Boot

Minimal policy for secure boot environments.

```
measure func=KEXEC_KERNEL_CHECK pcr=10 template=ima-ng
measure func=KEXEC_INITRAMFS_CHECK pcr=10 template=ima-ng
measure func=MODULE_CHECK pcr=10 template=ima-ng
```

### Critical Data

Measures critical kernel data only.

```
measure func=CRITICAL_DATA pcr=10 template=ima-ng
```

## Noise Reduction Rules

Exclude virtual filesystems from measurement to reduce noise:

```
# Exclude pseudo-filesystems
dont_measure fsmagic=0x9fa0        # procfs
dont_measure fsmagic=0x62656572    # sysfs
dont_measure fsmagic=0x64626720    # debugfs
dont_measure fsmagic=0x01021994    # tmpfs
dont_measure fsmagic=0x858458f6    # ramfs
dont_measure fsmagic=0x73636673    # securityfs
dont_measure fsmagic=0x27e0eb     # cgroup
dont_measure fsmagic=0x63677270    # cgroup2
dont_measure fsmagic=0x19800202    # mqueue
dont_measure fsmagic=0x4d44        # msdos
```

### Common Filesystem Magic Numbers

| Magic | Filesystem |
|-------|------------|
| `0x9fa0` | procfs |
| `0x62656572` | sysfs |
| `0x64626720` | debugfs |
| `0x01021994` | tmpfs |
| `0x858458f6` | ramfs |
| `0x73636673` | securityfs |
| `0x27e0eb` | cgroup |
| `0x63677270` | cgroup2 |
| `0x19800202` | mqueue |
| `0xef53` | ext2/3/4 |
| `0x58465342` | xfs |
| `0x9123683e` | btrfs |

## Custom Monitoring Paths

Add measurement rules for specific paths:

```
# Measure reads from custom application directory
measure func=FILE_CHECK mask=MAY_READ uid=0 pcr=10 obj_type=/opt/myapp

# Measure configuration files
measure func=FILE_CHECK mask=MAY_READ pcr=10 obj_type=/etc/myapp
```

## Policy Generation

The platform generates IMA policies based on configuration:

```go
// pkg/installer/alpine.go

func (ai *alpineInstaller) generateIMAPolicy() string {
    // Generates policy based on:
    // - ima.policy setting (tcb, appraise_tcb, etc.)
    // - ima.monitor-paths (additional paths)
    // - Noise reduction rules
}
```

### Generated Policy Location

```
/etc/ima/ima-policy
```

### Loading Policy at Boot

The policy is loaded via OpenRC boot script:

```bash
# /etc/local.d/ima.start
if [ -f /sys/kernel/security/ima/policy ]; then
    cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
fi
```

## Event Log Format

IMA events are logged to `/sys/kernel/security/ima/ascii_runtime_measurements`:

### ima-ng Format

```
<PCR> <template_hash> ima-ng <algorithm>:<file_hash> <file_path>
```

Example:
```
10 abc123... ima-ng sha256:def456... /usr/bin/bash
```

### ima-sig Format

```
<PCR> <template_hash> ima-sig <algorithm>:<file_hash> <file_path> <signature>
```

Example:
```
10 abc123... ima-sig sha256:def456... /usr/bin/bash 0302...
```

## Verifying Policy

### Check Loaded Policy

```bash
cat /sys/kernel/security/ima/policy
```

### Count Measurements

```bash
wc -l /sys/kernel/security/ima/ascii_runtime_measurements
```

### View Recent Measurements

```bash
tail -20 /sys/kernel/security/ima/ascii_runtime_measurements
```

### Check Violations

```bash
cat /sys/kernel/security/ima/violations
```

## Best Practices

### Measurement vs Appraisal

| Mode | Use Case |
|------|----------|
| **Measurement only** | Audit trail, remote attestation |
| **Measurement + Log** | Testing signature infrastructure |
| **Measurement + Enforce** | Production high-security environments |

### Recommended Approach

1. Start with `policy: tcb` and `appraise-mode: log`
2. Monitor violations and tune policy
3. Once stable, switch to `appraise-mode: enforce`

### Performance Considerations

- Measure only what's necessary
- Use noise reduction rules liberally
- Consider `hash` instead of `measure` for local-only verification
- The `tcb` policy provides good security/performance balance

## Related Documentation

- [Configuration](configuration.md) - Configuration options
- [TPM Integration](tpm-integration.md) - PCR 10 measurements
- [API Reference](api-reference.md) - Go package API
