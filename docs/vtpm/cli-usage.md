# vTPM CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [cli.md](cli.md). The verbs are `platformctl vtpm`, not `platformd vtpm`; there is no `--json` flag (use the global `-o json`); `create` requires `--bundle-id`; `start`, `stop`, `is-running`, `quote`, `seal`, `unseal` and `pcr` are missing here.

## Command Structure

```
platformd vtpm create     # Create pre-assigned bundle
platformd vtpm list       # List bundles
platformd vtpm info       # Display bundle information
platformd vtpm clone      # Clone from template
platformd vtpm delete     # Delete bundle
platformd vtpm export     # Export to archive
platformd vtpm import     # Import from archive
platformd vtpm template   # Template management
```

## Bundle Management

### Create Bundle (`platformd vtpm create`)

Create a pre-assigned vTPM bundle with CA-issued EK certificate.

```bash
# Create with required hostname
platformd vtpm create --hostname vm001.example.com

# Create with ECC EK algorithm
platformd vtpm create --hostname vm001.example.com --ek-algorithm ECC

# Create without Secure Boot
platformd vtpm create --hostname vm001.example.com --secure-boot=false

# Output as JSON
platformd vtpm create --hostname vm001.example.com --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--hostname` | VM hostname (required) | - |
| `--secure-boot` | Enable Secure Boot key generation | true |
| `--ek-algorithm` | EK algorithm (RSA or ECC) | RSA |
| `--json` | Output in JSON format | false |

**Output Example:**

```
Bundle created successfully
  ID:          f47ac10b-58cc-4372-a567-0e02b2c3d479
  Hostname:    vm001.example.com
  Mode:        pre-assigned
  Secure Boot: true
  EK Algo:     RSA
  Created:     2025-01-15 10:30:00
```

### List Bundles (`platformd vtpm list`)

List all vTPM bundles with optional filtering.

```bash
# List all bundles
platformd vtpm list

# List only templates
platformd vtpm list --mode template

# List only pre-assigned bundles
platformd vtpm list --mode pre-assigned

# Output as JSON
platformd vtpm list --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--mode` | Filter by mode (template, pre-assigned) | - |
| `--json` | Output in JSON format | false |

**Output Example:**

```
ID                                    MODE          HOSTNAME                        SECURE-BOOT  CREATED
------------------------------------  ------------  ------------------------------  ----------  --------------------
f47ac10b-58cc-4372-a567-0e02b2c3d479  pre-assigned  vm001.example.com               true        2025-01-15 10:30
a1b2c3d4-e5f6-7890-abcd-ef1234567890  pre-assigned  vm002.example.com               true        2025-01-15 11:00
base-server                           template                                      true        2025-01-14 09:00
```

### Bundle Info (`platformd vtpm info`)

Display detailed information about a bundle.

```bash
# Get bundle details
platformd vtpm info f47ac10b-58cc-4372-a567-0e02b2c3d479

# Output as JSON
platformd vtpm info f47ac10b-58cc-4372-a567-0e02b2c3d479 --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output in JSON format | false |

**Output Example:**

```
Bundle Information
==================

ID:            f47ac10b-58cc-4372-a567-0e02b2c3d479
Mode:          pre-assigned
Created:       2025-01-15 10:30:00

Manifest
--------
Hostname:      vm001.example.com
Secure Boot:   true
EK Algorithm:  RSA
EK Cert FP:    SHA256:AB:CD:EF:12:34:56:78:90:...

Checksums (SHA-256)
-------------------
  tpm2-00.permall: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  OVMF_VARS.fd: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

TPM State
---------
State Dir:     /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../tpm
Permall File:  /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../tpm/tpm2-00.permall

OVMF State
----------
NVRAM File:    /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../ovmf/OVMF_VARS.fd

Secure Boot Keys
----------------
Directory:     /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot
PK Key:        /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/PK.key
PK Cert:       /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/PK.crt
KEK Key:       /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/KEK.key
KEK Cert:      /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/KEK.crt
DB Key:        /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/DB.key
DB Cert:       /var/lib/trusted-platform/vtpm/bundles/f47ac10b.../secureboot/DB.crt
```

### Delete Bundle (`platformd vtpm delete`)

Delete a bundle and all associated files.

```bash
# Delete with confirmation prompt
platformd vtpm delete f47ac10b-58cc-4372-a567-0e02b2c3d479

# Force delete without confirmation
platformd vtpm delete f47ac10b-58cc-4372-a567-0e02b2c3d479 --force
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--force` | `-f` | Skip confirmation prompt | false |

## Template Management

### Create Template (`platformd vtpm template create`)

Create a template for cloning. Templates do not have EK certificates; the certificate is issued when cloned.

```bash
# Create template with required ID
platformd vtpm template create --id base-server

# Create with specific settings
platformd vtpm template create --id secure-base --secure-boot=true --ek-algorithm RSA

# Output as JSON
platformd vtpm template create --id base-server --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--id` | Template ID (required) | - |
| `--secure-boot` | Enable Secure Boot key generation | true |
| `--ek-algorithm` | EK algorithm for clones (RSA or ECC) | RSA |
| `--json` | Output in JSON format | false |

### List Templates (`platformd vtpm template list`)

List all available templates.

```bash
# List templates
platformd vtpm template list

# Output as JSON
platformd vtpm template list --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output in JSON format | false |

**Output Example:**

```
ID                              SECURE-BOOT  EK-ALGO   CREATED
------------------------------  ----------   --------  --------------------
base-server                     true         RSA       2025-01-14 09:00
minimal-vm                      false        ECC       2025-01-13 15:30
```

### Delete Template (`platformd vtpm template delete`)

Delete a template. This does not affect bundles cloned from the template.

```bash
# Delete with confirmation
platformd vtpm template delete base-server

# Force delete
platformd vtpm template delete base-server --force
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--force` | `-f` | Skip confirmation prompt | false |

## Clone Operations

### Clone Template (`platformd vtpm clone`)

Clone a template to create a new bundle with unique identity.

```bash
# Clone template
platformd vtpm clone --template base-server --hostname vm002.example.com

# Output as JSON
platformd vtpm clone --template base-server --hostname vm002.example.com --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--template` | Template ID to clone from (required) | - |
| `--hostname` | Hostname for the new VM (required) | - |
| `--json` | Output in JSON format | false |

**What Gets Cloned:**

- Copy of template's swtpm state
- Unique EK certificate issued at clone time
- Copy of template's OVMF NVRAM
- Copy of template's Secure Boot keys

## Export/Import

### Export Bundle (`platformd vtpm export`)

Export a bundle to a portable tar.gz archive.

```bash
# Export with default filename
platformd vtpm export f47ac10b-58cc-4372-a567-0e02b2c3d479

# Export with custom filename
platformd vtpm export f47ac10b-58cc-4372-a567-0e02b2c3d479 -o vm001-bundle.vtpm.tar.gz
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output file path | bundle-{id}.vtpm.tar.gz |

**Archive Contents:**

- `manifest.json` - Metadata and checksums
- `tpm/` - swtpm state files
- `ovmf/` - OVMF NVRAM
- `secureboot/` - Secure Boot keys (if enabled)

### Import Bundle (`platformd vtpm import`)

Import a bundle from a tar.gz archive.

```bash
# Import bundle
platformd vtpm import bundle.vtpm.tar.gz

# Output as JSON
platformd vtpm import bundle.vtpm.tar.gz --json
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output in JSON format | false |

**Validation:**

- Manifest is checked for required fields
- Checksums are verified
- Bundle ID uniqueness is enforced

## Examples

### VM Fleet Provisioning

```bash
# Create a base template
platformd vtpm template create --id production-base --secure-boot=true

# Clone for each VM in the fleet
platformd vtpm clone --template production-base --hostname web-01.prod.example.com
platformd vtpm clone --template production-base --hostname web-02.prod.example.com
platformd vtpm clone --template production-base --hostname web-03.prod.example.com

# List all cloned bundles
platformd vtpm list --mode pre-assigned
```

### Bundle Distribution

```bash
# Create bundle on provisioning server
platformd vtpm create --hostname app-server.example.com

# Export for distribution
platformd vtpm export <bundle-id> -o app-server.vtpm.tar.gz

# Transfer to target host
scp app-server.vtpm.tar.gz target-host:/tmp/

# Import on target host
platformd vtpm import /tmp/app-server.vtpm.tar.gz
```

### Development Workflow

```bash
# Create bundle for development VM
platformd vtpm create --hostname dev-vm.local --secure-boot=false

# Get bundle path for QEMU
platformd vtpm info <bundle-id> --json | jq '.tpm_state.state_dir'

# Use with QEMU
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/var/lib/trusted-platform/vtpm/bundles/<id>/tpm/swtpm.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```
