# Compute CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [cli.md](cli.md), the `platformctl` compute command reference.

This document describes the command-line interface for compute orchestration.

## Status: 100% Complete

All CLI commands for compute orchestration are fully implemented.

## Overview

The Trusted Platform CLI (`platformd`) provides commands for managing virtual machines and containers. The compute-related commands are organized into command groups.

## Command Structure

```
platformd
    vtpm                    # Virtual TPM bundle management
        create              # Create a pre-assigned vTPM bundle
        clone               # Clone from a template
        list                # List all bundles
        info                # Show bundle details
        delete              # Delete a bundle
        export              # Export bundle for distribution
        import              # Import a bundle
        template            # Template management
            create          # Create a template
            list            # List templates

```

## Virtual TPM Commands

The `vtpm` command group manages pre-provisioned virtual TPM bundles for VM deployment.

### vtpm create

Create a pre-assigned vTPM bundle with a unique TPM identity.

```bash
platformd vtpm create --hostname vm001.example.com
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--hostname` | string | required | Hostname for the VM |
| `--output` | string | auto | Output directory for bundle |
| `--format` | string | tar.gz | Bundle format |

**Output:**
- swtpm state with EK certificate in NV RAM
- OVMF NVRAM with Secure Boot keys enrolled
- Secure Boot keys (PK, KEK, DB)

### vtpm clone

Clone a vTPM bundle from a template.

```bash
platformd vtpm clone --template base-vtpm --hostname vm002.example.com
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--template` | string | required | Template ID to clone from |
| `--hostname` | string | required | Hostname for the VM |
| `--output` | string | auto | Output directory for bundle |

### vtpm list

List all vTPM bundles.

```bash
platformd vtpm list
```

**Output:**
```
ID              HOSTNAME              CREATED              STATUS
abc123          vm001.example.com     2025-01-15T10:30:00  ready
def456          vm002.example.com     2025-01-15T11:00:00  ready
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format` | string | table | Output format (table, json, yaml) |
| `--all` | bool | false | Include templates |

### vtpm info

Show detailed information about a vTPM bundle.

```bash
platformd vtpm info abc123
```

**Output:**
```
Bundle ID:     abc123
Hostname:      vm001.example.com
Created:       2025-01-15T10:30:00Z
Status:        ready
TPM Version:   2.0
PCR Banks:     SHA-256
Secure Boot:   enabled
EK Cert:       present

Files:
  - tpm2-00.permall (TPM state)
  - OVMF_VARS.fd (NVRAM)
  - PK.auth (Platform Key)
  - KEK.auth (Key Exchange Key)
  - DB.auth (Signature Database)
```

### vtpm delete

Delete a vTPM bundle.

```bash
platformd vtpm delete abc123
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | false | Skip confirmation |

### vtpm export

Export a vTPM bundle for distribution.

```bash
platformd vtpm export abc123 -o bundle.vtpm.tar.gz
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | required | Output file path |
| `--encrypt` | bool | false | Encrypt bundle |
| `--password` | string | - | Encryption password |

### vtpm import

Import a vTPM bundle.

```bash
platformd vtpm import bundle.vtpm.tar.gz
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--decrypt` | bool | false | Decrypt bundle |
| `--password` | string | - | Decryption password |

### vtpm template create

Create a vTPM template for cloning.

```bash
platformd vtpm template create --id base-vtpm
```

**Flags:**
| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | string | required | Template identifier |
| `--description` | string | - | Template description |

Templates are base images that can be cloned. The EK certificate is issued at clone time, giving each clone a unique TPM identity while sharing the same Secure Boot keys.

## Global Flags

All commands support these global flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-d, --debug` | bool | false | Enable debug mode |
| `--debug-secrets` | bool | false | Include secrets in logs |
| `-e, --env` | string | dev | Environment (dev, staging, prod) |
| `--platform-dir` | string | ./trusted-data | Platform data directory |
| `--config-dir` | string | /etc/trusted-platform | Config directory |
| `-c, --config` | string | - | Specific config file |
| `--log-dir` | string | trusted-data/log | Log directory |
| `--ca-dir` | string | trusted-data/ca | CA data directory |
| `--setuid` | string | root | Run as user |
| `--intermediate` | int | 1 | Target CA index |
| `--so-pin` | bool | false | Prompt for SO PIN |
| `--pin` | bool | false | Prompt for PIN |
| `--raw-so-pin` | string | - | Plain-text SO PIN |
| `--raw-pin` | string | - | Plain-text PIN |

## Examples

### Create and Deploy a VM with Pre-provisioned vTPM

1. Create a vTPM bundle:
```bash
platformd vtpm create --hostname webserver.example.com
# Output: Created bundle abc123
```

2. Export the bundle:
```bash
platformd vtpm export abc123 -o webserver.vtpm.tar.gz
```

3. Deploy to target host and import:
```bash
platformd vtpm import webserver.vtpm.tar.gz
```

4. Create VM using the vTPM state:
```bash
# The VM will detect the pre-provisioned EK certificate
# and skip the endorse-01 ACME challenge during enrollment
```

### Create Template and Clone Multiple VMs

1. Create a template:
```bash
platformd vtpm template create --id base-vm \
    --description "Base VM template for web tier"
```

2. Clone for multiple VMs:
```bash
for i in 1 2 3; do
    platformd vtpm clone --template base-vm \
        --hostname web-${i}.example.com
done
```

3. List all bundles:
```bash
platformd vtpm list
# ID        HOSTNAME              CREATED              STATUS
# base-vm   (template)            2025-01-15T10:00:00  template
# abc123    web-1.example.com     2025-01-15T10:05:00  ready
# def456    web-2.example.com     2025-01-15T10:05:01  ready
# ghi789    web-3.example.com     2025-01-15T10:05:02  ready
```

## Environment Variables

CLI behavior can be modified via environment variables:

| Variable | Description |
|----------|-------------|
| TRUSTED_PLATFORM_DEBUG | Enable debug mode |
| TRUSTED_PLATFORM_ENV | Runtime environment |
| TRUSTED_PLATFORM_CONFIG | Config file path |
| TRUSTED_PLATFORM_DATA_DIR | Data directory |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Resource not found |
| 5 | Permission denied |
| 6 | Resource conflict |
| 7 | Timeout |

## See Also

- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - API documentation
- [swtpm Integration](swtpm-integration.md) - vTPM details
- [Architecture](architecture.md) - System design
