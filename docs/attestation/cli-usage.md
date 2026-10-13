# Attestation CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [cli.md](cli.md).

## Overview

The Attestation CLI provides commands for platform attestation operations, TPM management, and container image signing via the `platformctl` command-line interface. These commands enable hardware-backed trust verification, integrity measurement, and secure workload deployment.

## Command Structure

The Attestation CLI is organized into logical command groups:

```
platformctl attestation <command>   # Attestation verification and management
platformctl tpm <command>           # TPM hardware operations
platformctl image <command>         # Container image signing and verification
```

## Attestation Commands (`platformctl attestation`)

### Verify Quote

Verify a TPM quote against expected PCR values and validate the attestation chain.

```bash
# Basic verification
platformctl attestation verify --quote quote.bin

# Verify with expected PCR values
platformctl attestation verify --quote quote.bin --expected-pcrs expected.json

# Verify with custom nonce
platformctl attestation verify --quote quote.bin --nonce a1b2c3d4e5f6

# Verify against remote CA
platformctl attestation verify --quote quote.bin --ca-url https://ca.example.com

# Output verification results to file
platformctl attestation verify --quote quote.bin --output results.json
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--quote` | `-q` | Path to quote file (required) | - |
| `--expected-pcrs` | `-e` | Path to expected PCR values file | - |
| `--nonce` | `-n` | Nonce used during quote generation (hex) | - |
| `--ca-url` | | Certificate Authority URL for chain validation | - |
| `--output` | `-o` | Output file for verification results | stdout |

### Generate Manifest

Generate a comprehensive attestation manifest for a host, including hardware measurements, software inventory, and runtime state.

```bash
# Generate manifest for local host
platformctl attestation manifest

# Generate manifest for remote host
platformctl attestation manifest --host server-01.example.com

# Output to file
platformctl attestation manifest --output manifest.json

# Generate in YAML format
platformctl attestation manifest --format yaml --output manifest.yaml

# Include VM attestation data
platformctl attestation manifest --include-vms

# Include container attestation data
platformctl attestation manifest --include-containers

# Full manifest with all components
platformctl attestation manifest \
  --host server-01.example.com \
  --include-vms \
  --include-containers \
  --output full-manifest.json
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | `-h` | Target hostname (local if not specified) | localhost |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format (json, yaml) | json |
| `--include-vms` | | Include virtual machine attestation | false |
| `--include-containers` | | Include container attestation | false |

### Push Manifest

Push an attestation manifest to a remote attestation service for continuous verification and compliance monitoring.

```bash
# Push manifest to attestation service
platformctl attestation push --manifest manifest.json --target https://attest.example.com

# Push with scheduled updates
platformctl attestation push \
  --manifest manifest.json \
  --target https://attest.example.com \
  --schedule "*/15 * * * *"

# Push on PCR change detection
platformctl attestation push \
  --manifest manifest.json \
  --target https://attest.example.com \
  --on-change

# Continuous monitoring with change detection
platformctl attestation push \
  --manifest manifest.json \
  --target https://attest.example.com \
  --schedule "0 * * * *" \
  --on-change
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--manifest` | `-m` | Path to manifest file (required) | - |
| `--target` | `-t` | Target attestation service URL (required) | - |
| `--schedule` | `-s` | Cron schedule for periodic push | - |
| `--on-change` | | Push when PCR values change | false |

### Attestation Status

Display the current attestation state of the local or remote host.

```bash
# Show local attestation status
platformctl attestation status

# Show remote host attestation status
platformctl attestation status --host server-01.example.com

# Output as JSON
platformctl attestation status --output json
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | `-h` | Target hostname | localhost |
| `--output` | `-o` | Output format (table, json, yaml) | table |

**Example Output:**

```
Attestation Status: [VERIFIED] Platform Trusted

Host:              server-01.example.com
Last Attestation:  2026-01-02 10:30:00 UTC
Next Scheduled:    2026-01-02 11:00:00 UTC

TPM Information:
  Manufacturer:    STMicroelectronics
  Firmware:        7.85
  Device:          /dev/tpmrm0

PCR Status:
  Bank:            SHA256
  PCRs Measured:   0, 1, 2, 3, 4, 5, 6, 7, 8, 9
  Integrity:       VALID

Certificate Chain:
  EK Certificate:  Valid (expires 2030-01-15)
  AK Certificate:  Valid (expires 2027-01-02)
  CA Chain:        Verified
```

## TPM Commands (`platformctl tpm`)

### Generate Quote

Generate a TPM quote for specified PCR registers with optional nonce for freshness.

```bash
# Generate quote for boot-time PCRs
platformctl tpm quote --pcrs 0,1,2,7

# Generate quote with custom nonce
platformctl tpm quote --pcrs 0,1,2,7 --nonce a1b2c3d4e5f6a1b2

# Output quote to file
platformctl tpm quote --pcrs 0,1,2,7 --output quote.bin

# Generate quote in JSON format (includes PCR values)
platformctl tpm quote --pcrs 0,1,2,7 --format json --output quote.json

# Quote all runtime PCRs
platformctl tpm quote --pcrs 0,1,2,3,4,5,6,7,8,9 --output full-quote.bin
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--pcrs` | `-p` | Comma-separated list of PCR indices (required) | - |
| `--nonce` | `-n` | Nonce for quote freshness (hex string) | random |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format (binary, json) | binary |

**Common PCR Indices:**

| PCR | Measurement |
|-----|-------------|
| 0 | BIOS/UEFI firmware |
| 1 | BIOS/UEFI configuration |
| 2 | Option ROMs |
| 3 | Option ROM configuration |
| 4 | MBR/Boot loader |
| 5 | Boot loader configuration |
| 6 | Host platform state |
| 7 | Secure Boot state |
| 8-9 | OS kernel and initrd |
| 10-13 | Application measurements |
| 14 | Workload measurements |

### List PCRs

Display all PCR values from the TPM.

```bash
# List all PCRs (default SHA256 bank)
platformctl tpm pcrs

# List PCRs from specific bank
platformctl tpm pcrs --bank sha256
platformctl tpm pcrs --bank sha384
platformctl tpm pcrs --bank sha1

# Output as JSON
platformctl tpm pcrs --output json

# Show only specific PCRs
platformctl tpm pcrs --pcrs 0,1,2,7
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--bank` | `-b` | PCR bank (sha1, sha256, sha384) | sha256 |
| `--output` | `-o` | Output format (table, json, yaml) | table |
| `--pcrs` | `-p` | Filter to specific PCR indices | all |

**Example Output:**

```
PCR Bank: SHA256

PCR   Value
---   -----
0     3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
1     a4abb9e33fb1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1
2     3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
7     a4abb9e33fb1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1
...
```

### Export Event Log

Export the TCG2 event log containing all measurement events.

```bash
# Export event log to file
platformctl tpm eventlog --output eventlog.bin

# Export in JSON format (parsed events)
platformctl tpm eventlog --format json --output eventlog.json

# Export with verbose event descriptions
platformctl tpm eventlog --verbose --output eventlog.json
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output file path (required) | - |
| `--format` | `-f` | Output format (binary, json) | binary |
| `--verbose` | `-v` | Include verbose event descriptions | false |

### Extend PCR

Extend a PCR register with new measurement data. Used for tracking workload state changes.

```bash
# Extend PCR with hex data
platformctl tpm extend --pcr 14 --data a1b2c3d4e5f6

# Extend PCR with file contents
platformctl tpm extend --pcr 14 --data @/path/to/measurement.bin

# Extend with description for audit log
platformctl tpm extend --pcr 14 --data a1b2c3d4 --description "Workload v1.2.3 started"
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--pcr` | `-p` | PCR index to extend (required) | - |
| `--data` | `-d` | Data to extend (hex string or @file) (required) | - |
| `--description` | | Event description for audit log | - |

**Note:** PCR extension is irreversible until system reboot. Use PCRs 14-23 for application measurements.

## Image Commands (`platformctl image`)

### Sign Image

Sign a container image using the platform CA and TPM-backed keys.

```bash
# Sign image with default platform key
platformctl image sign --image myapp:v1.0.0

# Sign with specific key
platformctl image sign --image myapp:v1.0.0 --key signing-key-prod

# Sign with attestation binding
platformctl image sign --image myapp:v1.0.0 --bind-attestation

# Sign remote image
platformctl image sign --image registry.example.com/myapp:v1.0.0 --key signing-key

# Sign and push signature to registry
platformctl image sign --image myapp:v1.0.0 --push
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--image` | `-i` | Image name and tag (required) | - |
| `--key` | `-k` | Key ID for signing | platform-default |
| `--bind-attestation` | | Bind signature to platform attestation | false |
| `--push` | | Push signature to registry | false |

### Verify Image

Verify a container image signature against the platform CA.

```bash
# Verify image signature
platformctl image verify --image myapp:v1.0.0

# Verify with specific CA
platformctl image verify --image myapp:v1.0.0 --ca-cert /path/to/ca.pem

# Verify remote image
platformctl image verify --image registry.example.com/myapp:v1.0.0

# Verify and output details
platformctl image verify --image myapp:v1.0.0 --output json
```

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--image` | `-i` | Image name and tag (required) | - |
| `--ca-cert` | | Custom CA certificate path | platform-ca |
| `--output` | `-o` | Output format (table, json) | table |

**Example Output:**

```
Image Verification: [PASSED]

Image:           myapp:v1.0.0
Digest:          sha256:a1b2c3d4e5f6...
Signed By:       CN=Platform Signing Key, O=Example Corp
Signed At:       2026-01-02 09:15:00 UTC
Key ID:          signing-key-prod
Certificate:     Valid (expires 2027-06-15)
Attestation:     Bound (platform verified)
```

## Common Use Cases

### Device Enrollment

Complete enrollment flow for a new device joining the trusted platform.

```bash
# 1. Verify TPM is available and get initial PCR state
platformctl tpm pcrs --output json > initial-pcrs.json

# 2. Generate attestation manifest
platformctl attestation manifest \
  --include-vms \
  --include-containers \
  --output enrollment-manifest.json

# 3. Generate enrollment quote
platformctl tpm quote \
  --pcrs 0,1,2,3,4,5,6,7 \
  --nonce $(curl -s https://ca.example.com/nonce) \
  --output enrollment-quote.bin

# 4. Submit enrollment to CA
platformctl attestation push \
  --manifest enrollment-manifest.json \
  --target https://ca.example.com/enroll

# 5. Verify enrollment status
platformctl attestation status
```

### Fleet Attestation

Verify attestation state across multiple hosts in a fleet.

```bash
# Verify individual hosts
for host in server-{01..10}.example.com; do
  echo "Verifying $host..."
  platformctl attestation status --host $host --output json >> fleet-status.json
done

# Generate fleet-wide attestation report
platformctl attestation manifest --host server-01.example.com --output server-01.json
platformctl attestation manifest --host server-02.example.com --output server-02.json

# Verify all hosts against baseline PCRs
for host in server-{01..10}.example.com; do
  platformctl attestation verify \
    --quote <(ssh $host platformctl tpm quote --pcrs 0,1,2,7) \
    --expected-pcrs baseline-pcrs.json
done
```

### Container Deployment

Sign and verify workflow for secure container deployment.

```bash
# 1. Build container image
docker build -t myapp:v1.0.0 .

# 2. Sign image with platform key
platformctl image sign --image myapp:v1.0.0 --push

# 3. Push to registry
docker push registry.example.com/myapp:v1.0.0

# 4. On deployment target: verify before running
platformctl image verify --image registry.example.com/myapp:v1.0.0

# 5. Record workload in PCR
platformctl tpm extend \
  --pcr 14 \
  --data $(docker inspect --format='{{.Id}}' myapp:v1.0.0) \
  --description "Started myapp:v1.0.0"

# 6. Run verified container
docker run registry.example.com/myapp:v1.0.0
```

### Incident Response

Collect attestation evidence for security investigation.

```bash
# 1. Capture current PCR state
platformctl tpm pcrs --output json > incident-pcrs-$(date +%Y%m%d%H%M%S).json

# 2. Export full event log
platformctl tpm eventlog \
  --format json \
  --verbose \
  --output incident-eventlog-$(date +%Y%m%d%H%M%S).json

# 3. Generate comprehensive manifest
platformctl attestation manifest \
  --include-vms \
  --include-containers \
  --output incident-manifest-$(date +%Y%m%d%H%M%S).json

# 4. Generate signed quote for evidence preservation
platformctl tpm quote \
  --pcrs 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14 \
  --format json \
  --output incident-quote-$(date +%Y%m%d%H%M%S).json

# 5. Verify against known-good baseline
platformctl attestation verify \
  --quote incident-quote-*.json \
  --expected-pcrs known-good-baseline.json \
  --output verification-report.json
```

## Output Formats

All attestation commands support multiple output formats:

| Format | Description | Use Case |
|--------|-------------|----------|
| `table` | Human-readable tabular format | Interactive use, quick inspection |
| `json` | Machine-readable JSON | Automation, API integration, logging |
| `yaml` | Human-readable structured format | Configuration files, documentation |

**Example: JSON Output**

```bash
platformctl attestation status --output json
```

```json
{
  "status": "verified",
  "host": "server-01.example.com",
  "timestamp": "2026-01-02T10:30:00Z",
  "tpm": {
    "manufacturer": "STMicroelectronics",
    "firmware_version": "7.85",
    "device": "/dev/tpmrm0"
  },
  "pcr_bank": "sha256",
  "pcr_integrity": "valid",
  "certificates": {
    "ek": {"valid": true, "expires": "2030-01-15T00:00:00Z"},
    "ak": {"valid": true, "expires": "2027-01-02T00:00:00Z"}
  }
}
```

**Example: YAML Output**

```bash
platformctl attestation manifest --format yaml
```

```yaml
host: server-01.example.com
timestamp: 2026-01-02T10:30:00Z
tpm:
  manufacturer: STMicroelectronics
  firmware_version: "7.85"
pcrs:
  bank: sha256
  values:
    0: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
    1: a4abb9e33fb1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1f0f1
    7: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969
```

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | General error | Unspecified error occurred |
| 2 | Verification failed | Attestation or signature verification failed |
| 3 | TPM error | TPM hardware or communication error |
| 4 | Network error | Network communication failure |

**Example: Handling Exit Codes**

```bash
platformctl attestation verify --quote quote.bin --expected-pcrs baseline.json
exit_code=$?

case $exit_code in
  0)
    echo "Attestation verified successfully"
    ;;
  2)
    echo "ALERT: Attestation verification failed - platform may be compromised"
    # Trigger incident response
    ;;
  3)
    echo "ERROR: TPM communication error - check hardware"
    ;;
  4)
    echo "ERROR: Network error - check connectivity to CA"
    ;;
  *)
    echo "ERROR: Unexpected error (code: $exit_code)"
    ;;
esac
```

## Common Options

All attestation commands support these global flags:

| Option | Description |
|--------|-------------|
| `--config` | Configuration file path |
| `--output` | Output format (table, json, yaml) |
| `--server` | Server address for remote operations |
| `--timeout` | Request timeout duration |
| `--verbose` | Enable verbose output |
| `--quiet` | Suppress non-error output |
