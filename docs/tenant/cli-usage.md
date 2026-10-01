# Tenant CLI Reference

> Subordinate to [cli.md](cli.md), which is normative. A tenant has no VLAN
> range and no OVS bridge (retired by #708): the `vlan` and `bridge` verbs and
> the `--vlan-start` / `--vlan-end` flags no longer exist, and network
> isolation of tenants arrives with tenant VRFs.

This document provides a complete reference for managing tenants using the `platformctl` command-line interface.

## Command Overview

```
platformctl tenant <command> [options]

Commands:
  create      Create a new tenant
  list        List all tenants
  show        Show tenant details
  update      Update tenant configuration
  delete      Delete a tenant
  suspend     Suspend a tenant
  resume      Resume a suspended tenant
  quotas      Manage tenant quotas
  usage       Show tenant resource usage
  verify      Verify tenant isolation
```

## Tenant Creation

### Basic Creation

```bash
# Create a tenant with default settings
platformctl tenant create --name engineering

# Output:
# Tenant created successfully
#
# Tenant Details:
#   ID:           tenant-550e8400-e29b-41d4-a716-446655440000
#   Name:         engineering
#   Display Name: engineering
#   State:        created
#   Created:      2025-12-26T10:30:00Z
```

### Full Creation Options

```bash
# Create tenant with full configuration
platformctl tenant create \
  --name production \
  --display-name "Production Environment" \
  --description "Production workloads and services" \
  --contact-email "ops@example.com" \
  --contact-slack "#prod-alerts" \
  --max-vms 100 \
  --max-containers 500 \
  --max-vcpus 500 \
  --max-memory-gb 2048 \
  --max-disk-gb 20000 \
  --max-bridges 10 \
  --max-ports 2000 \
  --max-bandwidth-gbps 50 \
  --label environment=production \
  --label tier=critical \
  --label compliance=soc2

# Output:
# Tenant created successfully
#
# Tenant Details:
#   ID:           tenant-661f9511-f30c-52e5-b827-557766551111
#   Name:         production
#   Display Name: Production Environment
#   State:        created
#
# Compute Quotas:
#   Max VMs:         100
#   Max Containers:  500
#   Max vCPUs:       500
#   Max Memory:      2048 GB
#   Max Disk:        20000 GB
#
# Network Quotas:
#   Max Bridges:     10
#   Max Ports:       2000
#   Max Bandwidth:   50 Gbps
```

### Create from File

```bash
# Create tenant from YAML configuration
platformctl tenant create --file tenant-config.yaml

# tenant-config.yaml
# name: staging
# display_name: "Staging Environment"
# quotas:
#   compute:
#     max_vms: 25
#     max_vcpus: 100
```

### Create Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--name` | `-n` | Unique tenant name (required) |
| `--display-name` | `-d` | Human-readable display name |
| `--description` | | Tenant description |
| `--contact-email` | | Contact email address |
| `--contact-slack` | | Slack channel for notifications |
| `--max-vms` | | Maximum VM instances |
| `--max-containers` | | Maximum containers |
| `--max-vcpus` | | Maximum vCPU cores |
| `--max-memory-gb` | | Maximum memory in GB |
| `--max-disk-gb` | | Maximum disk storage in GB |
| `--max-bridges` | | Maximum OVS bridges |
| `--max-ports` | | Maximum network ports |
| `--max-bandwidth-gbps` | | Maximum bandwidth in Gbps |
| `--label` | `-l` | Label (can be specified multiple times) |
| `--file` | `-f` | Create from YAML file |

## Listing Tenants

### List All Tenants

```bash
# List all tenants
platformctl tenant list

# Output:
# NAME          ID                                      STATE     VMS       MEMORY      CREATED
# engineering   tenant-550e8400-e29b-41d4-a716-4466... active    10/50     128/512 GB  2025-12-20
# production    tenant-661f9511-f30c-52e5-b827-5577... active    85/100    2048/4096   2025-12-15
# staging       tenant-772f0622-g41d-63f6-c938-6688... suspended 0/25      0/256 GB    2025-12-22
```

### Filtered Listing

```bash
# List only active tenants
platformctl tenant list --state active

# List tenants with specific label
platformctl tenant list --label environment=production

# List with custom output format
platformctl tenant list --output json

# List with wide output (more columns)
platformctl tenant list --output wide
```

### List Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--state` | `-s` | Filter by state |
| `--label` | `-l` | Filter by label |
| `--output` | `-o` | Output format: table, wide, json, yaml |
| `--no-headers` | | Omit table headers |

## Showing Tenant Details

### Basic Show

```bash
# Show tenant by name
platformctl tenant show engineering

# Output:
# Tenant: engineering
# ==================
#
# General:
#   ID:           tenant-550e8400-e29b-41d4-a716-446655440000
#   Name:         engineering
#   Display Name: Engineering Department
#   Description:  Engineering team development environment
#   State:        active
#   Created:      2025-12-20T10:30:00Z
#   Updated:      2025-12-26T14:45:00Z
#
# Contact:
#   Email:        eng-ops@example.com
#   Slack:        #eng-platform
#
# Network:
#   Active Ports: 47
#
# Compute Quotas:
#   VMs:          10 / 50 (20%)
#   Containers:   35 / 200 (17.5%)
#   vCPUs:        40 / 200 (20%)
#   Memory:       128 / 512 GB (25%)
#   Disk:         750 / 5000 GB (15%)
#
# Network Quotas:
#   Bridges:      1 / 5 (20%)
#   Ports:        47 / 500 (9.4%)
#   Bandwidth:    2.5 / 10 Gbps (25%)
#
# Storage Quotas:
#   Volumes:      25 / 100 (25%)
#   Snapshots:    75 / 500 (15%)
#   Total:        450 / 2000 GB (22.5%)
#
# Labels:
#   environment:  development
#   cost_center:  CC-1234
```

### Show with JSON Output

```bash
# Get tenant details as JSON
platformctl tenant show engineering --output json | jq .
```

### Show Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | `-o` | Output format: text, json, yaml |

## Updating Tenants

### Update Display Name

```bash
# Update display name
platformctl tenant update engineering \
  --display-name "Engineering Department (Updated)"
```

### Update Labels

```bash
# Add or update labels
platformctl tenant update engineering \
  --label tier=standard \
  --label cost_center=CC-5678

# Remove a label
platformctl tenant update engineering \
  --remove-label old_label
```

### Update Contact

```bash
# Update contact information
platformctl tenant update engineering \
  --contact-email "new-email@example.com" \
  --contact-slack "#new-channel"
```

### Update Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--display-name` | `-d` | New display name |
| `--description` | | New description |
| `--contact-email` | | New contact email |
| `--contact-slack` | | New Slack channel |
| `--label` | `-l` | Add/update label |
| `--remove-label` | | Remove label by key |
| `--file` | `-f` | Update from YAML file |

## Deleting Tenants

### Standard Delete

```bash
# Delete tenant (fails if resources exist)
platformctl tenant delete staging

# Output:
# Error: Tenant 'staging' has active resources:
#   - 5 VMs
#   - 12 containers
#   - 8 volumes
#
# Use --force to delete tenant and all resources
```

### Force Delete

```bash
# Force delete tenant and all resources
platformctl tenant delete staging --force

# Output:
# Deleting tenant 'staging' and all resources...
#
# Resources to delete:
#   VMs:        5
#   Containers: 12
#   Volumes:    8
#   Snapshots:  25
#   Ports:      47
#
# Continue? [y/N]: y
#
# Deleting VMs...           [5/5] done
# Deleting containers...    [12/12] done
# Deleting volumes...       [8/8] done
# Deleting snapshots...     [25/25] done
# Deleting network...       done
# Deleting DEK...           done
#
# Tenant 'staging' deleted successfully
```

### Delete Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--force` | `-f` | Force delete with all resources |
| `--yes` | `-y` | Skip confirmation prompt |

## Tenant Lifecycle

### Suspend Tenant

```bash
# Suspend tenant
platformctl tenant suspend engineering \
  --reason "Scheduled maintenance" \
  --stop-resources

# Output:
# Suspending tenant 'engineering'...
#
# Stopping resources:
#   VMs:        [10/10] stopped
#   Containers: [35/35] stopped
#
# Tenant 'engineering' suspended successfully
# Reason: Scheduled maintenance
```

### Resume Tenant

```bash
# Resume tenant
platformctl tenant resume engineering \
  --start-resources

# Output:
# Resuming tenant 'engineering'...
#
# Starting resources:
#   VMs:        [10/10] started
#   Containers: [35/35] started
#
# Tenant 'engineering' resumed successfully
```

### Lifecycle Options Reference

| Option | Description |
|--------|-------------|
| `--reason` | Reason for suspension |
| `--stop-resources` | Stop all running resources on suspend |
| `--start-resources` | Start previously running resources on resume |
| `--notify` | Send notification to tenant contact |

## Quota Management

### Show Quotas

```bash
# Show current quotas
platformctl tenant quotas show engineering

# Output:
# Quotas for tenant: engineering
# ==============================
#
# Compute:
#   Resource        Used    Max     Utilization
#   VMs             10      50      20%
#   Containers      35      200     17.5%
#   vCPUs           40      200     20%
#   Memory (GB)     128     512     25%
#   Disk (GB)       750     5000    15%
#
# Network:
#   Resource        Used    Max     Utilization
#   Bridges         1       5       20%
#   Ports           47      500     9.4%
#   Bandwidth (Gbps) 2.5    10      25%
#   Flow Rules      423     10000   4.23%
#
# Storage:
#   Resource        Used    Max     Utilization
#   Volumes         25      100     25%
#   Snapshots       75      500     15%
#   Total (GB)      450     2000    22.5%
```

### Set Quotas

```bash
# Set compute quotas
platformctl tenant quotas set engineering \
  --max-vms 100 \
  --max-vcpus 400 \
  --max-memory-gb 1024

# Set network quotas
platformctl tenant quotas set engineering \
  --max-bridges 10 \
  --max-ports 1000 \
  --max-bandwidth-gbps 20

# Set storage quotas
platformctl tenant quotas set engineering \
  --max-volumes 200 \
  --max-snapshots 1000 \
  --max-total-gb 5000
```

### Quota Options Reference

| Option | Description |
|--------|-------------|
| `--max-vms` | Maximum VM instances |
| `--max-containers` | Maximum containers |
| `--max-vcpus` | Maximum vCPU cores |
| `--max-memory-gb` | Maximum memory in GB |
| `--max-disk-gb` | Maximum disk storage in GB |
| `--max-bridges` | Maximum OVS bridges |
| `--max-ports` | Maximum network ports |
| `--max-bandwidth-gbps` | Maximum bandwidth in Gbps |
| `--max-flow-rules` | Maximum OpenFlow rules |
| `--max-volumes` | Maximum storage volumes |
| `--max-snapshots` | Maximum volume snapshots |
| `--max-total-gb` | Maximum total storage in GB |

## Resource Usage

### Show Usage

```bash
# Show current usage
platformctl tenant usage engineering

# Show usage over time period
platformctl tenant usage engineering --period 24h

# Output:
# Resource Usage for tenant: engineering
# Period: 2025-12-25 15:30 - 2025-12-26 15:30 (24h)
# ================================================
#
# Compute:
#   Resource        Current     Peak        Average
#   VMs             10          12          10.5
#   vCPUs           40          48          42
#   Memory (GB)     128         160         140
#
# Network:
#   Resource        Current     Peak        Average
#   Bandwidth       2.5 Gbps    5.2 Gbps    3.1 Gbps
#   Packets/sec     125K        350K        180K
#
# Storage:
#   Resource        Current     Peak        Average
#   IOPS            5K          15K         7.5K
#   Throughput      500 MB/s    1.2 GB/s    750 MB/s
```

### Usage Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--period` | `-p` | Time period: 1h, 24h, 7d, 30d |
| `--output` | `-o` | Output format: table, json, yaml |
| `--resource` | `-r` | Filter by resource type |

## Isolation Verification

### Verify Isolation

```bash
# Verify tenant isolation
platformctl tenant verify engineering

# Output:
# Isolation Verification for tenant: engineering
# ==============================================
#
# Network Isolation:
#   [PASS] Isolation flows installed
#   [PASS] No cross-tenant ports detected
#
# Storage Isolation:
#   [PASS] Namespace exists: /var/lib/platformd/tenants/engineering
#   [PASS] Permissions correct: 0750
#   [PASS] No path traversal vulnerabilities
#
# Key Isolation:
#   [PASS] DEK exists in TPM: handle 0x81000003
#   [PASS] DEK sealed with PCR policy
#   [PASS] Key rotation within policy
#
# Policy Isolation:
#   [PASS] RBAC policies configured
#   [PASS] Audit logging enabled
#
# Result: ALL CHECKS PASSED
```

### Verify Options Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show detailed check output |
| `--fix` | | Attempt to fix issues |
| `--output` | `-o` | Output format: text, json |

## Global Options

These options apply to all tenant commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to config file |
| `--socket` | `-s` | Path to platformd socket |
| `--timeout` | `-t` | Request timeout |
| `--verbose` | `-v` | Verbose output |
| `--debug` | | Debug output |
| `--output` | `-o` | Output format |

## Examples

### Complete Tenant Lifecycle

```bash
# 1. Create tenant
platformctl tenant create \
  --name myproject \
  --display-name "My Project" \
  --max-vms 20 \
  --max-vcpus 80 \
  --max-memory-gb 256

# 2. Verify isolation
platformctl tenant verify myproject

# 3. Check quotas
platformctl tenant quotas show myproject

# 4. Increase quotas
platformctl tenant quotas set myproject \
  --max-vms 50 \
  --max-vcpus 200

# 5. Monitor usage
platformctl tenant usage myproject --period 7d

# 6. Suspend for maintenance
platformctl tenant suspend myproject \
  --reason "System upgrade" \
  --stop-resources

# 7. Resume after maintenance
platformctl tenant resume myproject \
  --start-resources

# 8. Delete when no longer needed
platformctl tenant delete myproject --force --yes
```

### Scripting with JSON Output

```bash
#!/bin/bash

# Get tenant quota utilization as JSON
quota_json=$(platformctl tenant quotas show engineering -o json)

# Extract VM utilization
vm_used=$(echo "$quota_json" | jq '.compute.used_vms')
vm_max=$(echo "$quota_json" | jq '.compute.max_vms')
vm_pct=$((vm_used * 100 / vm_max))

if [ $vm_pct -gt 80 ]; then
    echo "WARNING: VM quota at ${vm_pct}%"
    # Send alert...
fi
```

## Related Documentation

- [API Reference](api-reference.md) - REST and gRPC API
- [Configuration](configuration.md) - Configuration options
- [Isolation](isolation.md) - Isolation mechanisms
