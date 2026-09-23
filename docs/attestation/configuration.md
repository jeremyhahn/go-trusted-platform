# Attestation Configuration

> **STATUS: Configuration Schema Implemented (Phase M)**
>
> The attestation configuration schema is implemented in `pkg/config/attestation.go`. The configuration structure is ready for use. The attestation runtime services are planned for Phase M.
>
> Platform configuration is defined in `configs/platform/config.*.yaml` files.

## Overview

The attestation module provides remote attestation capabilities for verifying platform integrity and workload identity. Configuration options control attestor behavior, network settings, quote generation, workload attestation, manifest management, and policy enforcement.

**Key Design Decisions:**
- **WorkloadPCR (default: 14)** is separate from the Golden Measurement PCR (23) because:
  - Golden measurements are static, computed once at boot time
  - Workload measurements are dynamic, extended as containers/VMs start/stop
  - Separation ensures boot-time policy and runtime workload tracking don't interfere
- PCR 14 was chosen because:
  - PCR 16 is reserved for debug (not production-safe)
  - PCR 23 is used for platform golden measurements
  - PCR 14 is in the OS-specific range (8-15) but commonly unused by IMA

## Reporting service and caller admission (#226)

```yaml
attestation:
  reporting:
    enabled: false          # run the collector on this node (control plane)
    interval: 15m
    ttl: 30m                # must be >= interval
    collector:
      identity: internal    # webservice name whose key/cert the collector presents
      port: 9443
      timeout: 30s
      pcrs: [0, 1, 2, 3, 4, 5, 6, 7]
      ca-file: ""           # anchors for node certificates; else the platform anchor
    callers:
      strategy: reporting-servers   # reporting-servers | any-attested | allowlist
      reporting-servers: []         # replaces the derived acme.client.directory host
      allowlist: []                 # empty refuses everyone
      ca-file: ""                   # else heartbeat.ca-file, else the platform anchor
```

`enabled` does two things on a control plane: it starts the collector, and it
is the gate on the control plane registering **itself** as a device in its own
registry (#472). `collector.identity` likewise carries a second meaning — the
named webservice is both the identity the collector presents and the listener
it dials for the control plane's own quote, so its TLS port and certificate
name are what the self endpoint uses. Neither adds a key: the self endpoint is
derived from the running configuration, never configured separately.

See [engineering.md §5](engineering.md#5-configuration) for every key, its
default and its validation error, and [user.md](user.md#who-may-ask-this-node-for-a-quote)
for what the caller policy means operationally.

## Configuration File

```yaml
# config.yaml
attestation:
  # Attestor settings
  allow-attestor-self-ca: false
  allow-open-enrollment: false
  allowed-verifiers:
    - "verifier.example.com"

  # Network ports
  insecure-port: 0
  tls-port: 8443

  # Quote settings - PCRs included in attestation quotes
  quote-pcrs:
    - 0
    - 1
    - 2
    - 7
    - 14

  # Workload attestation - for containers and VMs
  workload:
    enabled: true
    pcr: 14                        # PCR index for workload chain (0-23)
    pcr-bank: sha256               # Hash algorithm (sha1, sha256, sha384, sha512)
    include-image-digest: true     # Include container image digest in measurement
    include-container-id: true     # Include container ID in measurement
    include-workload-type: true    # Include workload type (vm/container) in measurement

  # Manifest settings - attestation manifest generation and distribution
  manifest:
    include-vms: true
    include-containers: true
    push-enabled: false
    push-interval: "5m"
    push-targets: []

  # Policy engine - for attestation decisions
  policy:
    engine: "opa"                  # Policy engine (opa, rego)
    policy-dir: "/etc/trusted-platform/policies"
    default-action: "deny"         # Default action (allow, deny)
```

## Configuration Sections

### Attestor Settings

Controls the behavior of the attestor service and enrollment policies.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_attestor_self_ca` | bool | `false` | Allow self-signed CA for attestor certificates |
| `allow_open_enrollment` | bool | `false` | Allow enrollment without prior authorization |
| `allowed_verifiers` | []string | `[]` | List of allowed verifier endpoints |

**Security Considerations:**

- Setting `allow_attestor_self_ca: true` reduces security and should only be used in development
- Setting `allow_open_enrollment: true` allows any device to enroll without pre-authorization
- Production deployments should explicitly list trusted verifiers in `allowed_verifiers`

### Network Settings

Configures network ports and TLS behavior for the attestation service.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `insecure_port` | int | `0` | HTTP port (0 = disabled) |
| `tls_port` | int | `8443` | HTTPS port for secure connections |

**Port Configuration:**

- Set `insecure_port: 0` to disable unencrypted HTTP entirely
- The default TLS port `8443` avoids conflicts with standard HTTPS port 443
- TLS 1.3 is required; server certificates are always validated against the platform CA

### Quote Settings

Controls which Platform Configuration Registers (PCRs) are included in attestation quotes.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `quote_pcrs` | []int | `[0,1,2,7]` | PCRs to include in attestation quotes |

**PCR Reference:**

| PCR | Measurement |
|-----|-------------|
| 0 | BIOS/UEFI firmware |
| 1 | Platform configuration |
| 2 | Option ROMs |
| 3 | Option ROM configuration |
| 4 | MBR/Boot loader |
| 5 | Boot loader configuration |
| 6 | Power state events |
| 7 | Secure Boot policy |
| 8-15 | OS-specific measurements |
| 14 | WorkloadPCR - workload measurements (configurable) |
| 23 | Application-specific measurements |

### Workload Settings

Configures workload attestation for containers and virtual machines.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable workload attestation |
| `pcr` | int | `14` | PCR for workload measurement chain (0-23) |
| `pcr-bank` | string | `sha256` | PCR hash algorithm (sha1, sha256, sha384, sha512) |
| `include-image-digest` | bool | `true` | Include container image digest in measurement |
| `include-container-id` | bool | `true` | Include container ID in measurement |
| `include-workload-type` | bool | `true` | Include workload type (vm/container) in measurement |

**Workload Measurement Formula:**

```
digest = SHA256(workload_type || "|" || workload_id || "|" || image_digest)
PCR[14]_new = SHA256(PCR[14]_current || digest)
```

**Key Properties:**

- **Order-dependent**: Same workloads in different order = different PCR value
- **Tamper-evident**: Cannot remove/reorder workloads without detection
- **Verifiable**: Can replay chain to verify current PCR value
- **Auditable**: Complete workload lifecycle history

**PCR Selection Considerations:**

- PCR 14 is the default for workload chains (commonly unused by IMA)
- PCR 16 is reserved for debug - **never use in production**
- PCR 23 is used for platform golden measurements - don't mix with workloads
- Valid range: 0-23

### Manifest Settings

Controls attestation manifest generation and distribution.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `include_vms` | bool | `true` | Include VM attestations in manifest |
| `include_containers` | bool | `true` | Include container attestations in manifest |
| `push_enabled` | bool | `false` | Enable automatic manifest push to targets |
| `push_interval` | duration | `5m` | Interval between manifest pushes |
| `push_targets` | []string | `[]` | URLs to push manifests to |

**Manifest Distribution:**

- Manifests aggregate attestation state for fleet visibility
- Push targets can include centralized attestation servers or SIEM systems
- Push interval balances freshness against network overhead

### Policy Settings

Configures the policy engine for attestation decisions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `engine` | string | `opa` | Policy engine (currently only `opa` supported) |
| `policy_dir` | string | `/etc/trusted-platform/policies` | Directory containing policy files |
| `default_action` | string | `deny` | Default action when no policy matches |

**Policy Engine:**

- Open Policy Agent (OPA) provides flexible, declarative policy evaluation
- Policies are written in Rego language
- Default deny ensures explicit allow rules are required

## Environment Variables

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `ATTESTATION_TLS_PORT` | `attestation.tls_port` | TLS port for attestation service |
| `ATTESTATION_INSECURE_PORT` | `attestation.insecure_port` | HTTP port (0 to disable) |
| `ATTESTATION_QUOTE_PCRS` | `attestation.quote_pcrs` | PCRs for quotes (comma-separated) |
| `ATTESTATION_POLICY_DIR` | `attestation.policy.policy_dir` | Policy files directory |
| `ATTESTATION_POLICY_ENGINE` | `attestation.policy.engine` | Policy engine type |
| `ATTESTATION_ALLOW_OPEN_ENROLLMENT` | `attestation.allow_open_enrollment` | Allow open enrollment |
| `ATTESTATION_WORKLOAD_ENABLED` | `attestation.workload.enabled` | Enable workload attestation |
| `ATTESTATION_WORKLOAD_PCR` | `attestation.workload.pcr` | PCR for workload measurements |

## Configuration Resolution

```
+---------------------------------------------------------------------------+
|                       Config Resolution Order                              |
+---------------------------------------------------------------------------+
|                                                                           |
|   1. Environment Variables (highest priority)                             |
|      ATTESTATION_TLS_PORT=8443                                            |
|                                                                           |
|   2. Command Line Flags                                                   |
|      --attestation.tls_port=8443                                          |
|                                                                           |
|   3. Configuration File                                                   |
|      config.yaml: attestation.tls_port: 8443                              |
|                                                                           |
|   4. Default Values (lowest priority)                                     |
|      DefaultAttestationConfig()                                           |
|                                                                           |
+---------------------------------------------------------------------------+
```

## Configuration Examples

> **Note:** All configuration examples in this section are **PROPOSED** and represent the planned schema for the attestation feature. These configuration sections do not exist in the current platform configuration.

### Development Configuration

For local development and testing with relaxed security settings.

**PROPOSED - Not yet implemented**

```yaml
# config.dev.yaml (PROPOSED SCHEMA)
debug: true
debug-secrets: true
platform-dir: trusted-data

attestation:
  allow_attestor_self_ca: true
  allow_open_enrollment: true
  allowed_verifiers: []

  insecure_port: 8080
  tls_port: 8443

  quote_pcrs:
    - 0
    - 7

  workload:
    enabled: true
    pcr: 14
    include_image_digest: true
    include_container_id: true

  manifest:
    include_vms: true
    include_containers: true
    push_enabled: false

  policy:
    engine: "opa"
    policy_dir: "./policies"
    default_action: "allow"
```

### Production Configuration

Standard production deployment with secure defaults.

**PROPOSED - Not yet implemented**

```yaml
# config.prod.yaml (PROPOSED SCHEMA)
debug: false
platform-dir: /var/lib/trusted-platform

attestation:
  allow_attestor_self_ca: false
  allow_open_enrollment: false
  allowed_verifiers:
    - "verifier.prod.example.com"
    - "verifier-backup.prod.example.com"

  insecure_port: 0
  tls_port: 8443

  quote_pcrs:
    - 0
    - 1
    - 2
    - 7
    - 14

  workload:
    enabled: true
    pcr: 14
    include_image_digest: true
    include_container_id: true

  manifest:
    include_vms: true
    include_containers: true
    push_enabled: true
    push_interval: "5m"
    push_targets:
      - "https://attestation-hub.prod.example.com/manifests"

  policy:
    engine: "opa"
    policy_dir: "/etc/trusted-platform/policies"
    default_action: "deny"
```

### High-Security Configuration

Maximum security settings with comprehensive PCR coverage and strict policies.

**PROPOSED - Not yet implemented**

The `tpm:` section shown below uses the existing schema pattern, but the `attestation:` section is proposed.

```yaml
# config.high-security.yaml (PROPOSED SCHEMA)
debug: false
platform-dir: /var/lib/trusted-platform
pin-seal-policy: true

tpm:
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: true
  entropy: true
  hash: SHA-256
  golden-pcrs: [0, 1, 2, 3, 4, 5, 6, 7]
  platform-pcr: 23
  platform-pcr-bank: sha256

attestation:
  allow_attestor_self_ca: false
  allow_open_enrollment: false
  allowed_verifiers:
    - "verifier.secure.example.com"

  insecure_port: 0
  tls_port: 8443

  # Comprehensive PCR coverage for full boot chain verification
  quote_pcrs:
    - 0   # BIOS/UEFI
    - 1   # Platform config
    - 2   # Option ROMs
    - 3   # Option ROM config
    - 4   # Boot loader
    - 5   # Boot loader config
    - 7   # Secure Boot
    - 14  # Workload
    - 23  # Application

  workload:
    enabled: true
    pcr: 14
    include_image_digest: true
    include_container_id: true

  manifest:
    include_vms: true
    include_containers: true
    push_enabled: true
    push_interval: "1m"
    push_targets:
      - "https://siem.secure.example.com/attestation"
      - "https://compliance.secure.example.com/manifests"

  policy:
    engine: "opa"
    policy_dir: "/etc/trusted-platform/policies/strict"
    default_action: "deny"
```

### Fleet Management Configuration

Configuration for managing attestation across a large fleet of devices.

**PROPOSED - Not yet implemented**

```yaml
# config.fleet.yaml (PROPOSED SCHEMA)
debug: false
platform-dir: /var/lib/trusted-platform

attestation:
  allow_attestor_self_ca: false
  allow_open_enrollment: false
  allowed_verifiers:
    - "fleet-verifier-1.example.com"
    - "fleet-verifier-2.example.com"
    - "fleet-verifier-3.example.com"

  insecure_port: 0
  tls_port: 8443

  quote_pcrs:
    - 0
    - 1
    - 2
    - 7
    - 14

  workload:
    enabled: true
    pcr: 14
    include_image_digest: true
    include_container_id: true

  manifest:
    include_vms: true
    include_containers: true
    push_enabled: true
    push_interval: "10m"
    push_targets:
      - "https://fleet-hub.example.com/api/v1/manifests"
      - "https://monitoring.example.com/attestation/ingest"

  policy:
    engine: "opa"
    policy_dir: "/etc/trusted-platform/policies"
    default_action: "deny"
```

## Validation Rules

The configuration is validated at startup with the following rules:

| Field | Validation | Error Type |
|-------|------------|------------|
| `tls-port` | Must be 1-65535 or 0 to disable | - |
| `insecure-port` | Must be 1-65535 or 0 to disable | - |
| `quote-pcrs` | Values must be 0-23 | - |
| `workload.pcr` | Must be 0-23 | `ErrInvalidPCR` |
| `workload.pcr-bank` | Must be sha1, sha256, sha384, or sha512 | `ErrInvalidPCRBank` |
| `policy.engine` | Must be `opa` or `rego` | `ErrInvalidPolicyEngine` |
| `policy.policy-dir` | Must be set when policy engine is configured | `ErrEmptyPolicyDir` |
| `policy.default-action` | Must be `allow` or `deny` | `ErrInvalidDefaultAction` |
| `manifest.push-interval` | Must be valid Go duration (e.g., "5m", "1h") | `ErrInvalidPushInterval` |

**Typed Errors (pkg/config/attestation.go):**

```go
ErrInvalidPCR           // PCR index out of range (0-23)
ErrInvalidPCRBank       // Invalid PCR bank algorithm
ErrInvalidPolicyEngine  // Invalid policy engine type
ErrInvalidDefaultAction // Invalid default action
ErrInvalidPushInterval  // Invalid push interval duration
ErrEmptyPolicyDir       // Policy dir required when engine is set
```

**Validation Behavior:**

- Disabled sub-configurations skip validation (e.g., `workload.enabled: false`)
- Push interval validation only applies when `push-enabled: true`
- Policy directory validation only applies when `policy.engine` is set

## Troubleshooting

### Common Issues

**Attestation service not starting:**
```
Check: At least one port (tls_port or insecure_port) is non-zero
Check: TLS certificates are valid and accessible
Check: Policy directory exists and contains valid policies
```

**Quote generation failing:**
```
Check: TPM device is accessible (/dev/tpmrm0)
Check: quote_pcrs contains valid PCR indices (0-23)
Check: TPM is not in use by another process
Check: User has permission to access TPM device
```

**Enrollment rejected:**
```
Check: allow_open_enrollment is true, or device is pre-authorized
Check: Verifier endpoint is in allowed_verifiers list
Check: TLS certificates are valid and trusted
```

**Workload attestation not working:**
```
Check: workload.enabled is true
Check: workload.pcr is a valid PCR index
Check: Container runtime is accessible
Check: Sufficient permissions to read container metadata
```

**Manifest push failing:**
```
Check: push_enabled is true
Check: push_targets contains valid URLs
Check: Network connectivity to push targets
Check: TLS certificates for push targets are trusted
```

**Policy evaluation errors:**
```
Check: policy.policy_dir contains valid Rego files
Check: Policy syntax is correct (use opa check)
Check: policy.engine is set to "opa"
Check: Required policy data files are present
```

### Diagnostic Commands

**Verify TPM accessibility:**
```bash
tpm2_getcap properties-fixed
```

**Test policy evaluation:**
```bash
opa eval --data /etc/trusted-platform/policies --input input.json "data.attestation.allow"
```

**Check TLS certificate validity:**
```bash
openssl x509 -in /path/to/cert.pem -noout -dates
```

**Verify attestation service health:**
```bash
curl -k https://localhost:8443/health
```
