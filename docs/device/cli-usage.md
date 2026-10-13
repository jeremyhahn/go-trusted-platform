# Device CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [cli.md](cli.md). There are no `device create` or `device update` verbs; a device is added with `device register`.

## Overview

The `platformctl device` and `platformctl profile` command groups provide management operations for device identity and profile management in go-trusted-platform.

## Device Commands

```
platformctl device <command>

Commands:
  create       Create a new device record
  get          Get device by ID
  list         List all devices
  update       Update device properties
  delete       Delete a device
  disable      Cut a device off the fabric
  enable       Re-admit a disabled device, pending re-attestation
  find-serial  Find device by serial number

Flags:
  -h, --help   Help for device commands
```

## Profile Commands

```
platformctl profile <command>

Commands:
  get      Get profile by ID
  list     List all profiles
  delete   Delete a profile
  match    Find the profile that matches a device

Flags:
  -h, --help   Help for profile commands
```

## Device Create

Create a new device record with TPM identity information.

### Usage

```bash
platformctl device create [flags]
```

### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--serial` | string | Yes | Device serial number |
| `--model` | string | Yes | Device model identifier |
| `--ek-cert` | string | No | Path to EK certificate (PEM) |
| `--attest-pub` | string | No | Path to attestation public key (PEM) |
| `--signing-pub` | string | No | Path to signing public key (PEM) |
| `--event-log` | string | No | Path to TPM event log file |
| `--hash-algo` | uint32 | No | TPM hash algorithm ID (default: 11) |

### Examples

```bash
# Create device with minimal info
platformctl device create \
  --serial "SRV-2024-001" \
  --model "TrustedServer-v2"

# Create device with TPM identity
platformctl device create \
  --serial "SRV-2024-001" \
  --model "TrustedServer-v2" \
  --ek-cert /path/to/ek.pem \
  --attest-pub /path/to/ak.pub \
  --signing-pub /path/to/sk.pub \
  --event-log /path/to/eventlog.bin

# Create from JSON
platformctl device create -f device.json
```

### Output

```
Device created successfully.

ID:         1234567890
Serial:     SRV-2024-001
Model:      TrustedServer-v2
EK Cert:    Present
Attest Key: Present
Hash Algo:  SHA-256 (11)
```

## Device Get

Retrieve a device by its ID.

### Usage

```bash
platformctl device get <id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | text | Output format (text, json, yaml) |

### Examples

```bash
# Get device in text format
platformctl device get 1234567890

# Get device in JSON format
platformctl device get 1234567890 -o json

# Get device in YAML format
platformctl device get 1234567890 -o yaml
```

### Output (Text)

```
Device Details:
  ID:          1234567890
  Serial:      SRV-2024-001
  Model:       TrustedServer-v2
  Hash Algo:   SHA-256 (11)

TPM Identity:
  EK Cert:     Present (4096 bits RSA)
  Attest Key:  Present (256 bits EC)
  Signing Key: Present (256 bits EC)
  Event Log:   Present (8192 bytes)
```

### Output (JSON)

```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "attest_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "attest_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "signing_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "hash_algo": 11
}
```

## Device List

List all registered devices with pagination.

### Usage

```bash
platformctl device list [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | table | Output format (table, json, yaml, wide) |
| `--page` | int | 1 | Page number |
| `--page-size` | int | 20 | Items per page |
| `--sort` | string | asc | Sort order (asc, desc) |

### Examples

```bash
# List devices in table format
platformctl device list

# List with pagination
platformctl device list --page 2 --page-size 50

# Wide output with more columns
platformctl device list -o wide

# JSON output
platformctl device list -o json
```

### Output (Table)

```
ID             SERIAL          MODEL                 HASH ALGO
1234567890     SRV-2024-001    TrustedServer-v2      SHA-256
1234567891     SRV-2024-002    TrustedServer-v2      SHA-256
1234567892     IOT-001         IoT-Sensor-v1         SHA-256

Page 1/5 (50 total devices)
```

### Output (Wide)

```
ID             SERIAL          MODEL               EK CERT    ATTEST KEY   HASH ALGO   CREATED
1234567890     SRV-2024-001    TrustedServer-v2    Yes        Yes          SHA-256     2024-01-15
1234567891     SRV-2024-002    TrustedServer-v2    Yes        Yes          SHA-256     2024-01-15
1234567892     IOT-001         IoT-Sensor-v1       Yes        No           SHA-256     2024-01-16
```

## Device Update

Update an existing device's properties.

### Usage

```bash
platformctl device update <id> [flags]
```

### Flags

| Flag | Type | Description |
|------|------|-------------|
| `--serial` | string | New serial number |
| `--model` | string | New model identifier |
| `--ek-cert` | string | Path to new EK certificate |
| `--attest-pub` | string | Path to new attestation key |
| `--signing-pub` | string | Path to new signing key |

### Examples

```bash
# Update serial number
platformctl device update 1234567890 --serial "SRV-2024-001-NEW"

# Update TPM keys
platformctl device update 1234567890 \
  --attest-pub /path/to/new-ak.pub \
  --signing-pub /path/to/new-sk.pub
```

### Output

```
Device updated successfully.

ID:     1234567890
Serial: SRV-2024-001-NEW
Model:  TrustedServer-v2
```

## Device Delete

Delete a device record.

### Usage

```bash
platformctl device delete <id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--yes` | bool | false | Skip confirmation prompt |

### Examples

```bash
# Delete with confirmation
platformctl device delete 1234567890

# Delete without confirmation
platformctl device delete 1234567890 --yes
```

### Output

```
Are you sure you want to delete device 1234567890? [y/N] y

Device 1234567890 deleted successfully.
```

## Device Disable / Enable

`disable` blocks the device's switch port and records it `suspended`.
`enable` re-admits a `suspended` device to the quarantine zone and requests
re-attestation; only a passing verdict restores it. Both are refused when the
daemon has no SDN policy engine or the device has no switch port
([cli.md §2.8](cli.md)).

### Usage

```bash
platformctl device disable <id> [--reason <text>]
platformctl device enable <id>
```

### Examples

```bash
platformctl device disable 1234567890 --reason "decommissioning rack 3"
platformctl device enable 1234567890 --output json
```

### Output

```
Device enabled; it stays quarantined until it re-attests
ID: 1234567890
State: quarantined
Previous State: suspended
Re-attestation Requested: true
```

## Device Find-Serial

Find a device by its serial number.

### Usage

```bash
platformctl device find-serial <serial> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | text | Output format (text, json, yaml) |

### Examples

```bash
platformctl device find-serial SRV-2024-001

platformctl device find-serial SRV-2024-001 -o json
```

### Output

```
Device found:
  ID:     1234567890
  Serial: SRV-2024-001
  Model:  TrustedServer-v2
```

## Device Profile Create / Update (EK Prestage)

`platformctl device profile create` and `platformctl device profile
update <id>` manage the pre-boot device record via the SDK device
service, including the hardware-EK prestage fields that arm EK-bound
config delivery and remote UKI signing.

### Usage

```bash
platformctl device profile create [flags]
platformctl device profile update <id> [flags]
```

### Flags

| Flag | Type | Description |
|------|------|-------------|
| `--name` | string | Profile name (required on create) |
| `--model` | string | Target device model |
| `--role` | string | Device role: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer |
| `--zone` | string | Default SDN zone |
| `--ek-serial` | string | Exact TPM EK certificate serial for boot-time identity resolution |
| `--mac` | string | Exact MAC address for non-TPM identification |
| `--ek-cert` | string | Prestaged TPM EK certificate: PEM file path or inline PEM (validated as an X.509 certificate) |
| `--config-file` | string | Device platform config (YAML or JSON) |

On update, only the supplied flags change; all other profile fields keep
their current values.

### Examples

```bash
# Create a profile with a prestaged hardware EK certificate
platformctl device profile create \
  --name node-02 \
  --role server \
  --ek-serial 1234567890 \
  --mac 00:25:90:FF:AA:02 \
  --ek-cert /path/to/ek-cert.pem \
  --config-file /path/to/platform.yaml

# Prestage the EK certificate on an existing profile
platformctl device profile update 123 --ek-cert /path/to/ek-cert.pem
```

## Device Profile Assign / Unassign

`platformctl device profile assign <profile-id>` binds a profile to a
specific device identity and marks it assigned;
`platformctl device profile unassign <profile-id>` clears the binding
(EK serial, MAC address, prestaged EK certificate, and assignment
state are all reset). The EK certificate is source-agnostic: it may
come from a swtpm-backed vTPM or a physical hardware TPM.

### Usage

```bash
platformctl device profile assign <profile-id> [flags]
platformctl device profile unassign <profile-id>
```

### Assign Flags

| Flag | Type | Description |
|------|------|-------------|
| `--device` | string | Registered device ID: derives the EK serial and EK certificate from the device record (the device must carry an EK certificate) |
| `--ek-serial` | string | TPM EK certificate serial identifying the device |
| `--mac` | string | Exact MAC address identifying the device |
| `--ek-cert` | string | Prestaged TPM EK certificate: PEM file path or inline PEM |

Explicit flags override values derived from `--device`. At least one of
`--device`, `--ek-serial`, or `--mac` is required.

### Examples

```bash
# Bind a profile to a registered device's EK
platformctl device profile assign 123 --device 42

# Bind a profile to a hardware TPM EK explicitly
platformctl device profile assign 123 \
  --ek-serial 1234567890 \
  --mac 00:25:90:FF:AA:02 \
  --ek-cert /path/to/ek-cert.pem

# Clear the binding
platformctl device profile unassign 123
```

## Profile Get, List, Delete and Match

`platformctl profile` mounts the `get`, `list`, `delete` and `match` verbs of
`platformctl device profile` — one implementation behind both trees. Create,
update, assign and unassign exist only under `device profile` (above).
[cli.md](cli.md) §3.0, §3.0a and §4 are the normative reference for their
flags, output and errors.

```bash
platformctl profile get 1
platformctl profile list --page 2 --page-size 50 --output json
platformctl profile delete 1
platformctl profile match --mac "52:54:00:aa:bb:cc"
platformctl profile match --serial "IOT-001" --model "IoT-Sensor-v1" --output json
```

A missing profile, or no profile matching the given attributes, exits
non-zero with `device profile: profile <id> not found` or
`device profile: no profile matches mac "…", serial "…", model "…"`.

## Global Flags

These flags apply to all device and profile commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | /etc/platformd/config.yaml | Configuration file path |
| `--server` | string | localhost:63001 | API server address |
| `--cert` | string | - | Client certificate path |
| `--key` | string | - | Client key path |
| `--ca` | string | - | CA certificate path |
| `-v, --verbose` | bool | false | Verbose output |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PLATFORM_CONFIG` | Configuration file path |
| `PLATFORM_SERVER` | API server address |
| `PLATFORM_CERT` | Client certificate path |
| `PLATFORM_KEY` | Client key path |
| `PLATFORM_CA` | CA certificate path |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Any failure — the error message names the cause (`cmd/platformctl/main.go`) |

## Scripting Examples

### Bulk Device Import

```bash
#!/bin/bash
set -e

# Import devices from CSV
while IFS=',' read -r serial model; do
  platformctl device create \
    --serial "$serial" \
    --model "$model"
done < devices.csv

echo "Import complete"
platformctl device list
```

### Profile Matching Script

```bash
#!/bin/bash

MAC=$1
SERIAL=$2

if [ -z "$MAC" ]; then
  echo "Usage: $0 <mac> [serial]"
  exit 2
fi

PROFILE=$(platformctl profile match --mac "$MAC" --serial "$SERIAL" -o json 2>/dev/null)

if [ $? -ne 0 ]; then
  echo "No matching profile found"
  exit 6
fi

NAME=$(echo "$PROFILE" | jq -r '.name')
echo "Device matches profile $NAME"
```

### Device Audit Script

```bash
#!/bin/bash

echo "Device Audit Report"
echo "==================="
echo

TOTAL=$(platformctl device list -o json | jq '.total_count')
echo "Total devices: $TOTAL"

# Count by model
platformctl device list -o json --page-size 1000 | \
  jq -r '.devices[] | .model' | \
  sort | uniq -c | \
  while read count model; do
    echo "  $model: $count"
  done

echo
echo "Devices without EK certificate:"
platformctl device list -o json --page-size 1000 | \
  jq -r '.devices[] | select(.ek_cert == "" or .ek_cert == null) | .serial'
```

## Related Documentation

- [API Reference](api-reference.md) - REST and gRPC API
- [Configuration](configuration.md) - Device configuration
- [Architecture](architecture.md) - Device architecture
- [Roadmap](../../ROADMAP.md) - Development roadmap
