# Device CLI Usage

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
  find-serial  Find device by serial number

Flags:
  -h, --help   Help for device commands
```

## Profile Commands

```
platformctl profile <command>

Commands:
  create   Create a new device profile
  get      Get profile by ID
  list     List all profiles
  update   Update profile properties
  delete   Delete a profile
  match    Find matching profile for device

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

## Profile Create

Create a new device profile.

### Usage

```bash
platformctl profile create [flags]
```

### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--name` | string | Yes | Profile name |
| `--model` | string | No | Target device model |
| `--role` | string | No | Device role (server, client, iot, etc.) |
| `--mac-prefix` | string | No | MAC address prefix for matching |
| `--serial-prefix` | string | No | Serial number prefix for matching |
| `--prov-vlan` | uint16 | No | Provisioning VLAN |
| `--prod-vlan` | uint16 | No | Production VLAN |
| `--quar-vlan` | uint16 | No | Quarantine VLAN |
| `-f, --file` | string | No | Load profile from JSON/YAML file |

### Examples

```bash
# Create simple profile
platformctl profile create \
  --name "Server Profile" \
  --model "TrustedServer-v2" \
  --role server \
  --mac-prefix "52:54:00" \
  --prov-vlan 998 \
  --prod-vlan 100 \
  --quar-vlan 666

# Create from file
platformctl profile create -f profile.yaml

# Create IoT profile
platformctl profile create \
  --name "IoT Sensor Profile" \
  --model "IoT-Sensor-v1" \
  --role iot \
  --serial-prefix "IOT-" \
  --prov-vlan 998 \
  --prod-vlan 200
```

### Output

```
Profile created successfully.

ID:                1
Name:              Server Profile
Model:             TrustedServer-v2
Role:              server

Match Rules:
  MAC Prefix:      52:54:00

Network Phases:
  Provisioning:    VLAN 998 (auth: none)
  Production:      VLAN 100 (auth: 802.1x)
  Quarantine:      VLAN 666 (auth: none)
```

## Profile Get

Retrieve a profile by its ID.

### Usage

```bash
platformctl profile get <id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | text | Output format (text, json, yaml) |

### Examples

```bash
platformctl profile get 1

platformctl profile get 1 -o json

platformctl profile get 1 -o yaml
```

### Output (Text)

```
Profile Details:
  ID:    1
  Name:  IoT Sensor Profile
  Model: IoT-Sensor-v1
  Role:  iot

Match Rules:
  MAC Prefix:    52:54:00
  Serial Prefix: IOT-

Provisioning Network:
  VLAN:       998
  Auth:       none
  DHCP Pool:  10.99.98.100 - 10.99.98.200
  Gateway:    10.99.98.1
  DNS:        10.99.98.1

Production Network:
  VLAN:    100
  Auth:    802.1x
  Gateway: 10.100.0.1
  DNS:     10.100.0.1, 8.8.8.8
  ACLs:    2 rules

Quarantine Network:
  VLAN:    666
  Auth:    none
  Gateway: 10.66.6.1
```

## Profile List

List all device profiles with pagination.

### Usage

```bash
platformctl profile list [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | table | Output format (table, json, yaml, wide) |
| `--page` | int | 1 | Page number |
| `--page-size` | int | 20 | Items per page |

### Examples

```bash
platformctl profile list

platformctl profile list -o wide

platformctl profile list -o json
```

### Output (Table)

```
ID    NAME                   MODEL             ROLE      PROD VLAN
1     IoT Sensor Profile     IoT-Sensor-v1     iot       100
2     Server Profile         TrustedServer-v2  server    200
3     Workstation Profile    Workstation-v1    client    300

Page 1/1 (3 total profiles)
```

### Output (Wide)

```
ID    NAME                   MODEL             ROLE      MAC PREFIX   SERIAL PREFIX   PROV VLAN   PROD VLAN   QUAR VLAN
1     IoT Sensor Profile     IoT-Sensor-v1     iot       52:54:00     IOT-            998         100         666
2     Server Profile         TrustedServer-v2  server    52:54:01     SRV-            998         200         666
3     Workstation Profile    Workstation-v1    client    52:54:02     WS-             998         300         666
```

## Profile Update

Update an existing profile's properties.

### Usage

```bash
platformctl profile update <id> [flags]
```

### Flags

| Flag | Type | Description |
|------|------|-------------|
| `--name` | string | New profile name |
| `--model` | string | New target model |
| `--role` | string | New device role |
| `--mac-prefix` | string | New MAC prefix |
| `--serial-prefix` | string | New serial prefix |
| `--prov-vlan` | uint16 | New provisioning VLAN |
| `--prod-vlan` | uint16 | New production VLAN |
| `--quar-vlan` | uint16 | New quarantine VLAN |
| `-f, --file` | string | Update from JSON/YAML file |

### Examples

```bash
# Update VLAN
platformctl profile update 1 --prod-vlan 150

# Update match rules
platformctl profile update 1 \
  --mac-prefix "52:54:01" \
  --serial-prefix "NEWSRV-"

# Update from file
platformctl profile update 1 -f updated-profile.yaml
```

### Output

```
Profile updated successfully.

ID:   1
Name: IoT Sensor Profile
```

## Profile Delete

Delete a device profile.

### Usage

```bash
platformctl profile delete <id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--yes` | bool | false | Skip confirmation prompt |

### Examples

```bash
platformctl profile delete 1

platformctl profile delete 1 --yes
```

### Output

```
Are you sure you want to delete profile 1? [y/N] y

Profile 1 deleted successfully.
```

## Profile Match

Find a matching profile for a device based on its characteristics.

### Usage

```bash
platformctl profile match [flags]
```

### Flags

| Flag | Type | Description |
|------|------|-------------|
| `--mac` | string | Device MAC address |
| `--serial` | string | Device serial number |
| `--model` | string | Device model |
| `-o, --output` | string | Output format (text, json, yaml) |

At least one of --mac, --serial, or --model is required.

### Examples

```bash
# Match by MAC address
platformctl profile match --mac "52:54:00:aa:bb:cc"

# Match by serial number
platformctl profile match --serial "IOT-001"

# Match with multiple criteria
platformctl profile match \
  --mac "52:54:00:aa:bb:cc" \
  --serial "IOT-001" \
  --model "IoT-Sensor-v1"

# JSON output
platformctl profile match --mac "52:54:00:aa:bb:cc" -o json
```

### Output

```
Matching profile found:

ID:    1
Name:  IoT Sensor Profile
Model: IoT-Sensor-v1
Role:  iot

Match Reason: MAC prefix matches (52:54:00)

Network Configuration:
  Provisioning: VLAN 998 (auth: none)
  Production:   VLAN 100 (auth: 802.1x)
  Quarantine:   VLAN 666 (auth: none)
```

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
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Connection failed |
| 4 | Authentication failed |
| 5 | Device/Profile not found |
| 6 | No matching profile |

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

VLAN=$(echo "$PROFILE" | jq -r '.provisioning_network.vlan')
echo "Device should be placed on VLAN $VLAN"
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
- [Roadmap](ROADMAP.md) - Development roadmap
