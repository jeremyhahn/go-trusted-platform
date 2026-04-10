# Host Manifest

## Overview

Host manifests provide hierarchical attestation reports covering bare metal hosts, VMs, and containers in a single signed document. A host manifest captures the complete trust state of a physical server and all workloads running on it, enabling remote verifiers to assess the integrity of the entire compute stack through a single cryptographically signed artifact.

The manifest aggregates:
- Host-level TPM attestation (hardware root of trust)
- Virtual machine attestations (vTPM quotes for each VM)
- Container attestations (PCR 14 extensions for each container)
- Image signature verification results
- Policy evaluation outcomes

This hierarchical approach enables fleet-wide compliance verification, incident response evidence collection, and continuous monitoring of infrastructure trust state.

## Manifest Structure

Host manifests use a structured format that captures attestation data at each layer of the compute hierarchy. The manifest can be serialized as YAML or JSON.

### Complete Manifest Schema

```yaml
manifest:
  version: "1.0"
  generated_at: "2024-01-15T10:30:00Z"

  host:
    id: "host-001"
    fqdn: "server1.example.com"
    hardware:
      tpm_manufacturer: "Infineon"
      tpm_version: "2.0"
      tpm_ek_fingerprint: "sha256:abc123..."
      tpm_ak_fingerprint: "sha256:def456..."
      cpu_vendor: "Intel"
      cpu_model: "Xeon Platinum 8380"
      secure_boot: true
      measured_boot: true
      sev_snp: false
      tdx: true
    attestation:
      timestamp: "2024-01-15T10:30:00Z"
      nonce: "base64:..."
      quote:
        data: "base64:..."
        signature: "base64:..."
      pcrs:
        sha256:
          0: "base64:..."   # UEFI firmware
          1: "base64:..."   # UEFI configuration
          2: "base64:..."   # Option ROMs
          3: "base64:..."   # Option ROM configuration
          4: "base64:..."   # MBR/boot loader
          5: "base64:..."   # MBR configuration
          6: "base64:..."   # Platform state
          7: "base64:..."   # Secure Boot policy
          8: "base64:..."   # Kernel
          9: "base64:..."   # Initramfs
          10: "base64:..."  # IMA aggregate
          14: "base64:..."  # Workload chain (VMs + containers)
          23: "base64:..."  # Platform policy (golden measurement)
      eventlog:
        format: "TCG2"
        data: "base64:..."
        hash: "sha256:..."
      ima:
        policy_hash: "sha256:..."
        aggregate_pcr10: "base64:..."
        violations: 0
    verification:
      status: "valid"
      verified_at: "2024-01-15T10:30:01Z"
      verified_by: "ca.example.com"
      certificate: |
        -----BEGIN CERTIFICATE-----
        ... host IDevID certificate ...
        -----END CERTIFICATE-----

  workloads:
    vms:
      - id: "vm-001"
        name: "app-server"
        vtpm:
          ek_cert: "base64:..."
          ek_fingerprint: "sha256:..."
          ak_cert: "base64:..."
          ak_fingerprint: "sha256:..."
        attestation:
          timestamp: "2024-01-15T10:30:05Z"
          nonce: "base64:..."
          quote:
            data: "base64:..."
            signature: "base64:..."
        pcrs:
          sha256:
            0: "base64:..."   # VM UEFI
            7: "base64:..."   # VM Secure Boot
            8: "base64:..."   # VM kernel
            10: "base64:..."  # VM IMA
            14: "base64:..."  # VM container chain
        verification:
          status: "valid"
          certificate: |
            -----BEGIN CERTIFICATE-----
            ... VM IDevID certificate ...
            -----END CERTIFICATE-----
        containers:
          - id: "container-001"
            image: "nginx:1.25"
            image_digest: "sha256:abc123..."
            signature_verified: true
            signer: "CN=platform-signer"
            attestation:
              pcr14_extension: "sha256:..."
              ima_digest: "sha256:..."
              start_time: "2024-01-15T10:25:00Z"
            verification:
              status: "valid"
          - id: "container-002"
            image: "redis:7.2"
            image_digest: "sha256:def456..."
            signature_verified: true
            signer: "CN=platform-signer"
            attestation:
              pcr14_extension: "sha256:..."
              ima_digest: "sha256:..."
              start_time: "2024-01-15T10:26:00Z"
            verification:
              status: "valid"

      - id: "vm-002"
        name: "database-server"
        vtpm:
          ek_cert: "base64:..."
          ak_cert: "base64:..."
        # ... similar structure ...

    containers:  # Standalone containers running directly on host
      - id: "container-010"
        image: "redis:7"
        image_digest: "sha256:ghi789..."
        signature_verified: true
        signer: "CN=platform-signer"
        attestation:
          pcr14_extension: "sha256:..."
          ima_digest: "sha256:..."
          start_time: "2024-01-15T10:20:00Z"
        verification:
          status: "valid"
      - id: "container-011"
        image: "prometheus:2.48"
        image_digest: "sha256:jkl012..."
        signature_verified: true
        signer: "CN=platform-signer"
        attestation:
          pcr14_extension: "sha256:..."
          ima_digest: "sha256:..."
          start_time: "2024-01-15T10:21:00Z"
        verification:
          status: "valid"

  aggregate:
    total_vms: 5
    total_containers: 23
    all_valid: true
    host_status: "valid"
    vm_status: "valid"
    container_status: "valid"
    failure_count: 0
    final_pcr14: "sha256:..."
    last_updated: "2024-01-15T10:30:10Z"

  signature: "base64:..."
  signature_algorithm: "ECDSA-P384"
  signed_by: "host-001-ak"
```

### Key Fields

| Section | Field | Description |
|---------|-------|-------------|
| `manifest.version` | string | Manifest format version for compatibility |
| `host.hardware` | object | TPM and CPU capabilities of the physical host |
| `host.attestation.quote` | object | TPM quote with signature proving PCR state |
| `host.attestation.pcrs` | map | Current values of measured PCRs |
| `host.attestation.eventlog` | object | TCG2 event log for measurement replay |
| `workloads.vms` | array | Virtual machine attestations with nested containers |
| `workloads.containers` | array | Standalone containers running on the host |
| `aggregate` | object | Summary statistics and combined status |
| `signature` | string | Host AK signature over the entire manifest |

## Manifest Generation

### Command-Line Interface

Generate a host manifest using the `platformctl` command:

```bash
# Generate attestation manifest for the local host
platformctl attestation manifest --host $(hostname)

# Generate manifest with specific options
platformctl attestation manifest \
  --host server1.example.com \
  --include-vms \
  --include-containers \
  --sign \
  --output manifest.yaml

# Generate JSON format
platformctl attestation manifest \
  --host server1.example.com \
  --format json \
  --output manifest.json
```

### Generation Process Flow

The manifest generation follows a systematic process to collect attestation data from all layers:

```
+------------------------------------------------------------------------+
|                     Host Manifest Generator                             |
|                                                                         |
|  platformctl attestation manifest --host server1                        |
|                                                                         |
|  1. Collect host attestation (TPM quote, PCRs, event log)               |
|     - Read PCR values from TPM                                          |
|     - Generate fresh TPM quote with nonce                               |
|     - Collect TCG2 event log from firmware                              |
|     - Gather IMA measurements                                           |
|                                                                         |
|  2. Enumerate VMs via QEMU/libvirt API                                  |
|     - List all running virtual machines                                 |
|     - Identify VMs with vTPM (swtpm) attached                           |
|                                                                         |
|  3. For each VM:                                                        |
|     a. Request vTPM attestation via platformd gRPC                      |
|        - Generate VM-specific quote                                     |
|        - Collect VM PCR values                                          |
|     b. Enumerate containers via Podman API                              |
|        - List containers running in VM                                  |
|        - Collect container attestation records                          |
|     c. Verify image signatures                                          |
|                                                                         |
|  4. Enumerate standalone containers on host via Podman API              |
|     - List containers running directly on host                          |
|     - Collect PCR 14 extension values                                   |
|     - Verify container image signatures                                 |
|                                                                         |
|  5. Query CA for device profile (expected config)                       |
|     - Retrieve expected PCR values                                      |
|     - Get approved image signatures                                     |
|     - Load policy requirements                                          |
|                                                                         |
|  6. Verify running state against expected state                         |
|     - Compare PCR values with golden measurements                       |
|     - Validate all image signatures                                     |
|     - Check policy compliance                                           |
|                                                                         |
|  7. Generate hierarchical manifest                                      |
|     - Assemble all collected data                                       |
|     - Calculate aggregate statistics                                    |
|     - Determine overall status                                          |
|                                                                         |
|  8. Sign manifest with host AK                                          |
|     - Create signature over manifest content                            |
|     - Include AK certificate for verification                           |
|                                                                         |
+------------------------------------------------------------------------+
           |                    |                    |
           v                    v                    v
    +-------------+      +-------------+      +-------------+
    | Host TPM    |      | VM vTPMs    |      | CA Device   |
    | Quote/PCRs  |      | (via swtpm) |      | Profile     |
    | Event Log   |      |             |      | (expected)  |
    +-------------+      +-------------+      +-------------+
```

### Programmatic Generation

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation"

opts := &attestation.ManifestOptions{
    IncludeVMs:        true,
    IncludeContainers: true,
    PCRSelection:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 23},
    PolicyID:          "default-policy",
    SignManifest:      true,
}

manifest, err := mgr.GenerateManifest(ctx, opts)
if err != nil {
    log.Fatal(err)
}

log.Printf("Generated manifest for host %s with %d VMs and %d containers",
    manifest.Host.HostID, len(manifest.VMs), len(manifest.Containers))
```

## Manifest Verification

Remote verifiers request and validate host manifests to assess platform trust state.

### Verification Flow

```
Remote Verifier                           Host (platformd)
     |                                          |
     |  1. Request manifest                     |
     |  GET /api/v1/attestation/manifest        |
     |  X-Attestation-Nonce: {fresh-nonce}      |
     |----------------------------------------->|
     |                                          |
     |                          Generate fresh quotes (all layers)
     |                          Enumerate all workloads
     |                          Build hierarchical manifest
     |                          Sign with host AK
     |                                          |
     |  2. Return signed manifest               |
     |<-----------------------------------------|
     |                                          |
     |  3. Verify manifest signature            |
     |     - Validate AK certificate chain      |
     |     - Verify signature over manifest     |
     |                                          |
     |  4. Verify host quote                    |
     |     - Replay nonce (freshness check)     |
     |     - Check PCRs against golden values   |
     |     - Replay event log                   |
     |                                          |
     |  5. Verify VM quotes                     |
     |     - Check vTPM EK chains to host CA    |
     |     - Verify each VM quote signature     |
     |     - Compare PCRs with expected values  |
     |                                          |
     |  6. Verify container attestations        |
     |     - Check PCR 14 extension chain       |
     |     - Verify chain integrity             |
     |                                          |
     |  7. Verify image signatures              |
     |     - Check signatures against trusted   |
     |       signers                            |
     |     - Validate image digests             |
     |                                          |
     |  8. Return verification result           |
     |                                          |
```

### Verification Checklist

| Check | Description | Failure Action |
|-------|-------------|----------------|
| Manifest signature | AK signature over manifest is valid | Reject manifest |
| Nonce freshness | Nonce matches challenge, not expired | Reject (replay attack) |
| Host PCR values | PCRs match expected golden measurements | Mark host untrusted |
| Event log replay | Replayed log matches quoted PCRs | Mark host untrusted |
| vTPM EK chain | VM EK certificates chain to platform CA | Mark VM untrusted |
| VM PCR values | VM PCRs match expected values | Mark VM untrusted |
| PCR 14 chain | Container extensions form valid chain | Mark container untrusted |
| Image signatures | All images signed by trusted signers | Mark container untrusted |

### Programmatic Verification

```go
// Verify a received manifest
result, err := verifier.VerifyManifest(ctx, manifest, &VerifyOptions{
    ExpectedPCRs:   goldenPCRs,
    TrustedSigners: trustedSignerCerts,
    MaxAge:         5 * time.Minute,
})

if result.Valid {
    log.Println("Manifest verification successful")
    log.Printf("Host: %s, VMs: %d trusted, Containers: %d trusted",
        result.HostStatus, result.TrustedVMs, result.TrustedContainers)
} else {
    for _, violation := range result.Violations {
        log.Printf("Violation: %s - %s", violation.Component, violation.Reason)
    }
}
```

## Push Infrastructure

Host manifests can be automatically pushed to remote verifiers for continuous monitoring and compliance.

### Push Configuration

Configure manifest push in the platform configuration file:

```yaml
attestation:
  push:
    enabled: true
    endpoints:
      - url: https://verifier.example.com/api/v1/attestation/manifest
        name: "primary-verifier"
        interval: 5m
        timeout: 30s
        retry:
          max_attempts: 3
          backoff: 10s
        mtls:
          cert: /etc/platform/certs/host.crt
          key: /etc/platform/certs/host.key
          ca: /etc/platform/certs/ca.crt
      - url: https://backup-verifier.example.com/api/v1/attestation/manifest
        name: "backup-verifier"
        interval: 15m
        mtls:
          cert: /etc/platform/certs/host.crt
          key: /etc/platform/certs/host.key
    on_change: true       # Push immediately when workloads change
    on_boot: true         # Push manifest on host boot
    include_vms: true
    include_containers: true
    sign_manifest: true
```

### Push Triggers

| Trigger | Description |
|---------|-------------|
| Scheduled | Push at configured interval (e.g., every 5 minutes) |
| On-change | Push when workload state changes (container start/stop, VM lifecycle) |
| On-boot | Push initial manifest after host boot completes |
| On-demand | Manual push via API or CLI |

### Push Command

```bash
# Push manifest to configured endpoints
platformctl attestation manifest push

# Push to specific verifier
platformctl attestation manifest push \
  --verifier https://verifier.example.com/api/v1/attestation/manifest

# Push with fresh attestation
platformctl attestation manifest push --refresh
```

### Push API

```go
// Push manifest to remote verifier
err := mgr.PushManifest(ctx, manifest, "https://verifier.example.com/api/v1/attestation/manifest")
if err != nil {
    log.Printf("Push failed: %v", err)
}
```

## API Endpoints

The attestation API provides endpoints for manifest operations:

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/attestation/manifest | Get current host manifest |
| POST | /api/v1/attestation/manifest/push | Push manifest to remote verifier |
| GET | /api/v1/attestation/hosts | List all hosts (cluster mode) |
| GET | /api/v1/attestation/hosts/{id} | Get specific host manifest |
| POST | /api/v1/attestation/verify | Verify submitted manifest |

### Get Current Manifest

```http
GET /api/v1/attestation/manifest?include_vms=true&include_containers=true&sign=true
Authorization: Bearer {token}
X-Attestation-Nonce: {base64-encoded-nonce}
```

**Response:**

```json
{
  "manifest": {
    "version": "1.0",
    "generated_at": "2024-01-15T10:30:00Z",
    "host": {
      "id": "host-001",
      "fqdn": "server1.example.com",
      "attestation": {
        "quote": {...},
        "pcrs": {...}
      },
      "verification": {
        "status": "valid"
      }
    },
    "workloads": {
      "vms": [...],
      "containers": [...]
    },
    "aggregate": {
      "total_vms": 5,
      "total_containers": 23,
      "all_valid": true
    },
    "signature": "base64:..."
  }
}
```

### Push Manifest

```http
POST /api/v1/attestation/manifest/push
Content-Type: application/json
Authorization: Bearer {token}

{
  "verifier_url": "https://verifier.example.com/api/v1/attestation/manifest",
  "refresh": true
}
```

**Response:**

```json
{
  "accepted": true,
  "verifier_response": {
    "status": "verified",
    "timestamp": "2024-01-15T10:30:05Z",
    "verification_id": "ver-12345"
  }
}
```

### List Hosts

```http
GET /api/v1/attestation/hosts?status=valid&limit=50
Authorization: Bearer {token}
```

**Response:**

```json
{
  "hosts": [
    {
      "id": "host-001",
      "fqdn": "server1.example.com",
      "status": "valid",
      "last_attestation": "2024-01-15T10:30:00Z",
      "vm_count": 5,
      "container_count": 23
    },
    {
      "id": "host-002",
      "fqdn": "server2.example.com",
      "status": "valid",
      "last_attestation": "2024-01-15T10:29:00Z",
      "vm_count": 3,
      "container_count": 15
    }
  ],
  "total": 2
}
```

### Get Specific Host

```http
GET /api/v1/attestation/hosts/host-001
Authorization: Bearer {token}
```

**Response:**

Returns the full manifest for the specified host.

## Use Cases

### Fleet Compliance Verification

Use host manifests to verify compliance across an entire infrastructure fleet:

```bash
# Collect manifests from all hosts
for host in $(platformctl hosts list --format names); do
  platformctl attestation manifest \
    --host $host \
    --output manifests/${host}.yaml
done

# Verify all manifests against policy
platformctl policy verify \
  --manifests manifests/ \
  --policy compliance-policy.rego \
  --report compliance-report.json
```

**Compliance Checks:**
- All hosts have valid TPM attestation
- All VMs use platform-signed vTPM EK certificates
- All container images are signed by approved signers
- PCR values match approved golden measurements
- No IMA violations detected

### Incident Response Evidence

Capture forensic evidence during security incident investigation:

```bash
# Generate comprehensive manifest with full event log
platformctl attestation manifest \
  --host compromised-host.example.com \
  --include-eventlog \
  --include-ima-log \
  --output incident-evidence.yaml

# Compare against last-known-good manifest
platformctl attestation diff \
  --baseline known-good.yaml \
  --current incident-evidence.yaml \
  --output drift-report.json
```

**Evidence Collected:**
- Complete PCR state at time of incident
- Full TCG2 event log for measurement analysis
- IMA log showing all executed binaries
- Container attestation chain
- Image signature verification status

### Audit Trail Generation

Generate attestation audit trails for compliance reporting:

```bash
# Generate audit report for time period
platformctl attestation audit \
  --start 2024-01-01T00:00:00Z \
  --end 2024-01-31T23:59:59Z \
  --hosts all \
  --format csv \
  --output january-audit.csv
```

**Audit Data:**
- Attestation timestamps and status changes
- Policy evaluation results
- Workload lifecycle events
- Configuration drift detection
- Remediation actions taken

### Continuous Monitoring

Configure real-time monitoring of attestation state:

```yaml
# monitoring.yaml
attestation:
  monitoring:
    enabled: true
    interval: 1m
    alerts:
      - name: host-attestation-failed
        condition: "host.verification.status != 'valid'"
        severity: critical
        notify:
          - slack: "#security-alerts"
          - pagerduty: "attestation-oncall"
      - name: container-unsigned
        condition: "containers[*].signature_verified == false"
        severity: high
        notify:
          - slack: "#security-alerts"
      - name: pcr-drift
        condition: "host.attestation.pcrs != expected_pcrs"
        severity: critical
        notify:
          - pagerduty: "attestation-oncall"
```

**Monitoring Capabilities:**
- Real-time attestation status tracking
- Automatic alerting on trust violations
- Integration with observability platforms
- Historical trend analysis
- Anomaly detection

## Related Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System design and data flows |
| [Workload Attestation](workload-attestation.md) | Container and VM attestation details |
| [API Reference](api-reference.md) | Complete API documentation |
| [CLI Usage](cli-usage.md) | Command-line interface reference |
| [Configuration](configuration.md) | Platform configuration options |
| [Policy Engine](policy-engine.md) | OPA policy integration |
| [TPM Integration](../tpm/README.md) | TPM 2.0 operations |
| [Certificate Authority](../ca/README.md) | Device certificate management |
