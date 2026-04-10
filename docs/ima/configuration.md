# IMA Configuration

Complete configuration reference for Linux Integrity Measurement Architecture.

## Configuration Structure

IMA is configured in the platform configuration file under the `ima:` section:

```yaml
ima:
  enabled: true
  policy: tcb
  hash-algorithm: sha256
  evm: false
  appraise-mode: log
  audit-enabled: true
  signing-key-path: ""
  public-key-path: ""
  monitor-paths: []
```

## Configuration Options

### enabled

Enable or disable IMA.

| Field | Value |
|-------|-------|
| Type | `bool` |
| Default | `false` |
| Required | Yes |

```yaml
ima:
  enabled: true
```

### policy

IMA policy type to load at boot time.

| Field | Value |
|-------|-------|
| Type | `string` |
| Default | `tcb` |
| Values | `tcb`, `appraise_tcb`, `secure_boot`, `critical_data` |

| Policy | Description |
|--------|-------------|
| `tcb` | Measures all executables, libraries, and kernel modules (Trusted Computing Base) |
| `appraise_tcb` | Measures AND appraises (verifies signatures) for TCB |
| `secure_boot` | Minimal policy for secure boot environments |
| `critical_data` | Measures critical kernel data only |

```yaml
ima:
  policy: tcb
```

### hash-algorithm

Hash algorithm for IMA measurements.

| Field | Value |
|-------|-------|
| Type | `string` |
| Default | `sha256` |
| Values | `sha256`, `sha1`, `sha512` |

**Recommendation:** Use `sha256` for best compatibility with TPM PCR banks.

```yaml
ima:
  hash-algorithm: sha256
```

### evm

Enable Extended Verification Module for file metadata protection.

| Field | Value |
|-------|-------|
| Type | `bool` |
| Default | `false` |

EVM protects file extended attributes (xattrs) including IMA signatures. When enabled, the kernel command line includes `evm=fix`.

```yaml
ima:
  evm: true
```

### appraise-mode

IMA appraisal mode for signature verification.

| Field | Value |
|-------|-------|
| Type | `string` |
| Default | `off` |
| Values | `off`, `log`, `enforce`, `fix` |

| Mode | Description |
|------|-------------|
| `off` | No appraisal (measurement only) |
| `log` | Log appraisal failures but allow execution |
| `enforce` | Block execution on appraisal failure |
| `fix` | Fix missing/invalid signatures (requires EVM key) |

```yaml
ima:
  appraise-mode: log
```

### signing-key-path

Path to IMA signing key for appraise mode.

| Field | Value |
|-------|-------|
| Type | `string` |
| Default | `""` |
| Required | Only for `appraise_tcb` policy |

```yaml
ima:
  signing-key-path: /etc/ima/signing-key.pem
```

### public-key-path

Path to IMA public key certificate for signature verification.

| Field | Value |
|-------|-------|
| Type | `string` |
| Default | `""` |
| Required | Only for signature verification |

```yaml
ima:
  public-key-path: /etc/ima/ima-public-key.pem
```

### audit-enabled

Enable logging of IMA events to the audit subsystem.

| Field | Value |
|-------|-------|
| Type | `bool` |
| Default | `false` |

When enabled, the kernel command line includes `ima_audit=1`.

```yaml
ima:
  audit-enabled: true
```

### monitor-paths

Additional files/directories to monitor beyond the default policy.

| Field | Value |
|-------|-------|
| Type | `[]string` |
| Default | `[]` |

These paths are added to the generated IMA policy for measurement.

```yaml
ima:
  monitor-paths:
    - /opt/application/bin
    - /var/lib/myapp/config
```

## Default Monitor Paths

When IMA is enabled, the following paths are monitored by default:

### System Binaries
- `/bin`, `/sbin`
- `/usr/bin`, `/usr/sbin`
- `/usr/local/bin`, `/usr/local/sbin`

### Libraries
- `/lib`, `/lib64`
- `/usr/lib`, `/usr/lib64`

### Kernel Modules
- `/lib/modules`

### Boot Files
- `/boot`

### System Configuration
- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- `/etc/sudoers`, `/etc/sudoers.d`
- `/etc/ssh/sshd_config`
- `/etc/pam.d`, `/etc/security`
- `/etc/ld.so.conf`, `/etc/ld.so.conf.d`

### Scheduled Tasks
- `/etc/crontab`
- `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly`
- `/etc/cron.weekly`, `/etc/cron.monthly`
- `/var/spool/cron`

### Init System
- `/etc/init.d`, `/etc/rc.d`
- `/etc/systemd`, `/usr/lib/systemd`

### Kernel Parameters
- `/etc/sysctl.conf`, `/etc/sysctl.d`

### Network Configuration
- `/etc/hosts`, `/etc/hosts.allow`, `/etc/hosts.deny`
- `/etc/resolv.conf`

### Package Management
- `/etc/apk`, `/etc/apt`
- `/etc/yum.repos.d`, `/etc/dnf`

## Kernel Command Line Parameters

When IMA is enabled, the installer configures the following kernel command line parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `ima=on` | Enable IMA | Always set when enabled |
| `ima_policy=<policy>` | Policy to load | `ima_policy=tcb` |
| `ima_hash=<alg>` | Hash algorithm | `ima_hash=sha256` |
| `ima_audit=1` | Enable audit logging | Set when `audit-enabled: true` |
| `ima_appraise=<mode>` | Appraise mode | `ima_appraise=log` |
| `evm=fix` | Enable EVM | Set when `evm: true` |

## Configuration Examples

### Minimal (Measurement Only)

```yaml
ima:
  enabled: true
  policy: tcb
  hash-algorithm: sha256
```

### Standard Security

```yaml
ima:
  enabled: true
  policy: tcb
  hash-algorithm: sha256
  appraise-mode: log
  audit-enabled: true
```

### High Security (Enforce Signatures)

```yaml
ima:
  enabled: true
  policy: appraise_tcb
  hash-algorithm: sha256
  evm: true
  appraise-mode: enforce
  audit-enabled: true
  signing-key-path: /etc/ima/signing-key.pem
  public-key-path: /etc/ima/ima-public-key.pem
```

### Custom Application Monitoring

```yaml
ima:
  enabled: true
  policy: tcb
  hash-algorithm: sha256
  audit-enabled: true
  monitor-paths:
    - /opt/myapp/bin
    - /opt/myapp/lib
    - /etc/myapp
    - /var/lib/myapp/config
```

## Files Created During Installation

When IMA is enabled, the installer creates:

| File | Description |
|------|-------------|
| `/etc/ima/ima-policy` | Generated IMA policy rules |
| `/etc/ima/ima.conf` | IMA configuration reference |
| `/etc/local.d/ima.start` | OpenRC boot script to load policy |

## Related Documentation

- [Policies](policies.md) - Policy syntax and rules
- [TPM Integration](tpm-integration.md) - PCR 10 measurements
- [Troubleshooting](troubleshooting.md) - Common issues
