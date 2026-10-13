# IMA Troubleshooting

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [user.md](user.md). There is no `platformctl ima` command group, so `ima policy generate` does not exist ([architecture.md §9](architecture.md)).

Common issues and solutions for Linux IMA.

## Checking IMA Status

### Verify IMA is Enabled

```bash
# Check if IMA directory exists
ls /sys/kernel/security/ima/
# Should show: ascii_runtime_measurements, binary_runtime_measurements, policy, violations

# Check kernel command line for IMA parameters
cat /proc/cmdline | grep -o 'ima[^ ]*'
# Should show: ima=on ima_policy=tcb ima_hash=sha256 etc.
```

### Check Policy is Loaded

```bash
# Read current policy
cat /sys/kernel/security/ima/policy

# If empty, policy may not be loaded
# Check boot script
cat /etc/local.d/ima.start
```

### View Measurement Count

```bash
# Count measurements
wc -l /sys/kernel/security/ima/ascii_runtime_measurements

# View recent measurements
tail -20 /sys/kernel/security/ima/ascii_runtime_measurements
```

## Common Issues

### IMA Not Available

**Symptom:**
```
/sys/kernel/security/ima/: No such file or directory
```

**Causes:**
1. Kernel not compiled with IMA support
2. securityfs not mounted
3. IMA not enabled in kernel command line

**Solutions:**

1. Check kernel config:
```bash
grep CONFIG_IMA /boot/config-$(uname -r)
# Should show: CONFIG_IMA=y
```

2. Mount securityfs:
```bash
mount -t securityfs securityfs /sys/kernel/security
```

3. Verify kernel command line includes `ima=on`:
```bash
cat /proc/cmdline | grep 'ima=on'
```

### Policy Not Loading

**Symptom:**
```bash
cat /sys/kernel/security/ima/policy
# Empty output
```

**Causes:**
1. Policy file missing
2. Boot script not running
3. Invalid policy syntax

**Solutions:**

1. Check policy file exists:
```bash
ls -la /etc/ima/ima-policy
```

2. Manually load policy:
```bash
cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
```

3. Check for syntax errors:
```bash
# Test loading policy manually and check dmesg
cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
dmesg | tail -20
```

4. Enable boot script:
```bash
chmod +x /etc/local.d/ima.start
rc-update add local default
```

### PCR 10 Mismatch

**Symptom:**
```
Error: PCR value mismatch
```

**Causes:**
1. Event log modified or truncated
2. TPM not synchronized with IMA
3. Different hash algorithms

**Solutions:**

1. Verify hash algorithms match:
```bash
# Check IMA hash
cat /proc/cmdline | grep ima_hash

# Check PCR bank being read
cat /sys/class/tpm/tpm0/pcr-sha256/10
```

2. Compare computed vs actual:
```go
reader := ima.NewReader()
verifier := ima.NewVerifier()

log, _ := reader.ReadEventLog()
computed, _ := verifier.ComputePCR10(log, "sha256")
actual, _ := verifier.ReadPCR10FromTPM("sha256")

fmt.Printf("Computed: %x\n", computed)
fmt.Printf("Actual:   %x\n", actual)
```

3. Check for event log truncation:
```bash
# Event log has maximum size - older events may be lost
dmesg | grep -i ima
```

### Appraisal Failures

**Symptom:**
```
IMA: HASH_NOT_AVAILABLE: /usr/bin/myapp
```
or
```
IMA: INTEGRITY_UNKNOWN: /usr/bin/myapp
```

**Causes:**
1. File not signed
2. Signature invalid
3. Public key not loaded

**Solutions:**

1. Check appraise mode:
```bash
cat /proc/cmdline | grep ima_appraise
# If "enforce", files without valid signatures are blocked
```

2. Switch to log mode for testing:
```yaml
ima:
  appraise-mode: log  # Log failures but allow execution
```

3. Check if signing key is loaded:
```bash
keyctl list %:.ima
```

4. Sign files with evmctl:
```bash
evmctl ima_sign --key /etc/ima/signing-key.pem /usr/bin/myapp
```

### High Measurement Volume

**Symptom:**
- Large event log
- Performance degradation
- Disk space issues

**Causes:**
1. Policy too broad
2. Missing noise reduction rules
3. Monitoring unnecessary paths

**Solutions:**

1. Add noise reduction rules:
```
dont_measure fsmagic=0x9fa0      # procfs
dont_measure fsmagic=0x62656572  # sysfs
dont_measure fsmagic=0x01021994  # tmpfs
```

2. Use more specific policy:
```yaml
ima:
  policy: secure_boot  # Minimal policy
```

3. Exclude specific paths:
```
dont_measure obj_type=/tmp
dont_measure obj_type=/var/log
```

### TPM Not Available

**Symptom:**
```
Error: TPM device not available
```

**Causes:**
1. TPM not present or not enabled
2. TPM kernel modules not loaded
3. TPM device permissions

**Solutions:**

1. Check TPM device:
```bash
ls -la /dev/tpm*
ls -la /sys/class/tpm/tpm0/
```

2. Load TPM modules:
```bash
modprobe tpm_tis
modprobe tpm_crb
```

3. Check device permissions:
```bash
# Add user to tss group
usermod -a -G tss $USER
```

4. Verify TPM PCR reading:
```bash
cat /sys/class/tpm/tpm0/pcr-sha256/10
```

## Diagnostic Commands

### System Information

```bash
# Kernel version
uname -r

# IMA kernel config
zcat /proc/config.gz | grep IMA

# Kernel command line
cat /proc/cmdline

# Security filesystem contents
ls -la /sys/kernel/security/
ls -la /sys/kernel/security/ima/
```

### IMA Status

```bash
# Measurement count
wc -l /sys/kernel/security/ima/ascii_runtime_measurements

# Violation count
cat /sys/kernel/security/ima/violations

# Current policy
cat /sys/kernel/security/ima/policy

# View last 50 measurements
tail -50 /sys/kernel/security/ima/ascii_runtime_measurements
```

### TPM Status

```bash
# TPM version
cat /sys/class/tpm/tpm0/tpm_version_major

# PCR values
for pcr in 0 7 9 10; do
  echo "PCR $pcr:"
  cat /sys/class/tpm/tpm0/pcr-sha256/$pcr
done

# Available PCR banks
ls /sys/class/tpm/tpm0/ | grep pcr-
```

### Audit Logs

```bash
# IMA audit messages
ausearch -m INTEGRITY_RULE -ts today

# IMA kernel messages
dmesg | grep -i ima

# Boot messages
journalctl -b | grep -i ima
```

## Log Analysis

### Find Specific File Measurements

```bash
grep "/usr/bin/bash" /sys/kernel/security/ima/ascii_runtime_measurements
```

### Count by Template

```bash
cut -d' ' -f3 /sys/kernel/security/ima/ascii_runtime_measurements | sort | uniq -c
```

### Find Duplicate Measurements

```bash
cut -d' ' -f5 /sys/kernel/security/ima/ascii_runtime_measurements | sort | uniq -c | sort -rn | head -20
```

### Export Event Log

```bash
# Text format
cp /sys/kernel/security/ima/ascii_runtime_measurements /tmp/ima-events.txt

# Binary format
cp /sys/kernel/security/ima/binary_runtime_measurements /tmp/ima-events.bin
```

## Recovery Procedures

### Reset IMA (Requires Reboot)

IMA state cannot be reset without rebooting. PCR 10 is extended and cannot be decreased.

```bash
# Reboot to reset IMA measurements and PCR 10
reboot
```

### Rebuild Policy

```bash
# Regenerate policy from configuration
platformctl ima policy generate --output /etc/ima/ima-policy

# Reload policy (appends to existing)
cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
```

### Re-sign Files

```bash
# Re-sign all files in directory
find /usr/bin -type f -exec evmctl ima_sign --key /etc/ima/signing-key.pem {} \;
```

## Getting Help

### Collect Diagnostic Information

```bash
#!/bin/bash
# Save to ima-diagnostics.txt

echo "=== Kernel Info ===" > ima-diagnostics.txt
uname -a >> ima-diagnostics.txt
echo "" >> ima-diagnostics.txt

echo "=== Kernel Command Line ===" >> ima-diagnostics.txt
cat /proc/cmdline >> ima-diagnostics.txt
echo "" >> ima-diagnostics.txt

echo "=== IMA Files ===" >> ima-diagnostics.txt
ls -la /sys/kernel/security/ima/ >> ima-diagnostics.txt 2>&1
echo "" >> ima-diagnostics.txt

echo "=== IMA Policy ===" >> ima-diagnostics.txt
cat /sys/kernel/security/ima/policy >> ima-diagnostics.txt 2>&1
echo "" >> ima-diagnostics.txt

echo "=== Measurement Count ===" >> ima-diagnostics.txt
wc -l /sys/kernel/security/ima/ascii_runtime_measurements >> ima-diagnostics.txt 2>&1
echo "" >> ima-diagnostics.txt

echo "=== Violations ===" >> ima-diagnostics.txt
cat /sys/kernel/security/ima/violations >> ima-diagnostics.txt 2>&1
echo "" >> ima-diagnostics.txt

echo "=== TPM PCR 10 ===" >> ima-diagnostics.txt
cat /sys/class/tpm/tpm0/pcr-sha256/10 >> ima-diagnostics.txt 2>&1
echo "" >> ima-diagnostics.txt

echo "=== Last 50 Measurements ===" >> ima-diagnostics.txt
tail -50 /sys/kernel/security/ima/ascii_runtime_measurements >> ima-diagnostics.txt 2>&1

echo "Diagnostics saved to ima-diagnostics.txt"
```

## Related Documentation

- [Configuration](configuration.md) - Configuration reference
- [Policies](policies.md) - Policy syntax
- [TPM Integration](tpm-integration.md) - PCR 10 verification
- [API Reference](api-reference.md) - Go package API
