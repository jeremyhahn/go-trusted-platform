# Attestation Policy Engine

## Overview

The policy engine uses Open Policy Agent (OPA) to evaluate attestation data against configurable rules, enabling fine-grained access control based on hardware trust. By leveraging OPA's Rego policy language, administrators can define custom attestation requirements for hosts, virtual machines, containers, and container images without modifying application code.

The policy engine integrates directly with the attestation verification flow, receiving structured attestation evidence as input and returning allow/deny decisions with detailed reasoning. Policies can be updated at runtime through hot-reload, enabling dynamic trust management without service restarts.

## Architecture

```
+--------------------------------------------------------------------------+
|                         Policy Evaluation Flow                            |
+--------------------------------------------------------------------------+
|                                                                          |
|  Attestation Data                                                        |
|  (Quote, PCRs, Event Log, Workload Info)                                 |
|         |                                                                |
|         v                                                                |
|  +------------------+     +------------------+     +------------------+  |
|  |                  |     |                  |     |                  |  |
|  |   Input Parser   |---->|   Policy Engine  |---->|    Decision      |  |
|  |                  |     |      (OPA)       |     |   (allow/deny)   |  |
|  +------------------+     +------------------+     +------------------+  |
|                                   |                        |             |
|                                   v                        v             |
|                           +------------------+     +------------------+  |
|                           |                  |     |                  |  |
|                           |   Policy Store   |     |  Decision Log    |  |
|                           |   (Rego Files)   |     |    (Audit)       |  |
|                           +------------------+     +------------------+  |
|                                   ^                                      |
|                                   |                                      |
|                           +------------------+                           |
|                           |                  |                           |
|                           |    Policy Data   |                           |
|                           | (Expected Values)|                           |
|                           +------------------+                           |
|                                                                          |
+--------------------------------------------------------------------------+
```

### Integration with Attestation Verification

The policy engine is invoked as the final step in the attestation verification flow:

```
Attestation Request
        |
        v
+-------------------+
| Quote Verification |-----> Signature check, nonce validation
+-------------------+
        |
        v
+-------------------+
| PCR Comparison    |-----> Compare against expected values
+-------------------+
        |
        v
+-------------------+
| Event Log Replay  |-----> Verify measurement integrity
+-------------------+
        |
        v
+-------------------+
| Policy Evaluation |-----> OPA Rego rules (THIS COMPONENT)
+-------------------+
        |
        v
    Decision
```

### Policy Loading and Hot-Reload

The policy engine monitors the configured policy directory for changes and automatically reloads modified policies without requiring a service restart. This enables:

- Dynamic policy updates in production
- A/B testing of policy changes
- Rapid response to security requirements
- Zero-downtime policy deployment

## Policy Language (Rego)

Rego is a declarative policy language designed for expressing policies over complex hierarchical data structures. Key characteristics:

| Feature | Description |
|---------|-------------|
| Declarative | Policies describe what should be true, not how to check it |
| JSON-native | Works naturally with structured attestation data |
| Composable | Policies can reference other policies and data |
| Testable | Built-in testing framework for policy validation |

### How Attestation Data is Provided as Input

Attestation evidence is provided to policies as the `input` document:

```json
{
  "input": {
    "quote": {
      "valid": true,
      "nonce": "abc123...",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "pcrs": {
      "0": "sha256:3a7b...",
      "1": "sha256:8f12...",
      "7": "sha256:2c5e..."
    },
    "eventlog": {
      "valid": true,
      "events": [...]
    },
    "host": {
      "hostname": "node-01.example.com",
      "platform": "x86_64"
    }
  }
}
```

Reference values and configuration are provided through the `data` document, which is loaded from policy data files.

## Default Policies

### Host Attestation Policy

Validates bare metal host attestation evidence against expected platform measurements.

```rego
package attestation.host

default allow = false

allow {
    input.quote.valid == true
    valid_pcrs
    valid_eventlog
}

valid_pcrs {
    input.pcrs[0] == data.expected.pcrs[0]
    input.pcrs[1] == data.expected.pcrs[1]
    input.pcrs[7] == data.expected.pcrs[7]
}

valid_eventlog {
    input.eventlog.valid == true
    not contains_violation(input.eventlog.events)
}

contains_violation(events) {
    event := events[_]
    event.type in data.blocked_event_types
}

# Denial reasons for debugging
reasons[msg] {
    input.quote.valid != true
    msg := "TPM quote signature verification failed"
}

reasons[msg] {
    not valid_pcrs
    msg := "PCR values do not match expected baseline"
}

reasons[msg] {
    not valid_eventlog
    msg := "Event log contains policy violations"
}
```

### VM Attestation Policy

Validates virtual machine attestation including vTPM certificate chain and approved images.

```rego
package attestation.vm

default allow = false

allow {
    input.vtpm.ek_cert.valid == true
    input.quote.valid == true
    approved_image
}

approved_image {
    input.image.digest in data.approved_images
}

# Alternative: approve by image name pattern
approved_image {
    image_name := input.image.name
    pattern := data.approved_image_patterns[_]
    startswith(image_name, pattern)
}

# Verify vTPM is bound to trusted host
vtpm_trusted {
    input.vtpm.host_binding.valid == true
    input.vtpm.host_binding.host_ak in data.trusted_host_aks
}

reasons[msg] {
    input.vtpm.ek_cert.valid != true
    msg := "vTPM EK certificate validation failed"
}

reasons[msg] {
    not approved_image
    msg := sprintf("VM image %v not in approved list", [input.image.digest])
}
```

### Container Attestation Policy

Validates container attestation including image signatures and PCR 14 chain integrity.

```rego
package attestation.container

default allow = false

allow {
    input.image.signature_verified == true
    input.pcr14_chain.valid == true
    trusted_registry
}

trusted_registry {
    startswith(input.image.registry, "registry.example.com")
}

trusted_registry {
    registry := data.trusted_registries[_]
    startswith(input.image.registry, registry)
}

# Verify image was signed by approved signer
approved_signer {
    input.image.signer in data.approved_signers
}

# Validate PCR 14 chain matches expected workload sequence
valid_workload_chain {
    count(input.pcr14_chain.entries) > 0
    input.pcr14_chain.current == data.expected_pcr14
}

reasons[msg] {
    input.image.signature_verified != true
    msg := "Container image signature verification failed"
}

reasons[msg] {
    not trusted_registry
    msg := sprintf("Registry %v not in trusted list", [input.image.registry])
}

reasons[msg] {
    input.pcr14_chain.valid != true
    msg := "PCR 14 workload chain validation failed"
}
```

### Image Trust Policy

Validates container and VM images against signature and vulnerability requirements.

```rego
package attestation.image

default allow = false

allow {
    valid_signature
    approved_signer
    not vulnerable
}

valid_signature {
    input.signature.verified == true
    input.signature.algorithm in data.allowed_algorithms
    time.now_ns() < input.signature.expires_ns
}

approved_signer {
    input.signature.signer in data.approved_signers
}

# Check vulnerability scan results
vulnerable {
    vuln := input.vulnerabilities[_]
    vuln.severity == "CRITICAL"
}

vulnerable {
    vuln := input.vulnerabilities[_]
    vuln.severity == "HIGH"
    not vuln.id in data.accepted_vulnerabilities
}

# Additional image metadata checks
valid_metadata {
    input.created_at > data.minimum_image_date
    input.labels["maintainer"] != ""
}

reasons[msg] {
    not valid_signature
    msg := "Image signature validation failed or expired"
}

reasons[msg] {
    not approved_signer
    msg := sprintf("Signer %v not in approved list", [input.signature.signer])
}

reasons[msg] {
    vulnerable
    msg := "Image contains unacceptable vulnerabilities"
}
```

## Policy Data

Policy data provides reference values and configuration that policies evaluate against. Data is loaded separately from policies, enabling environment-specific configuration without policy changes.

### Expected PCR Values

Define expected PCR measurements for known-good platform states:

```json
{
  "expected": {
    "pcrs": {
      "0": "sha256:3a7b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
      "1": "sha256:8f12a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
      "7": "sha256:2c5ea1b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"
    }
  }
}
```

### Approved Images List

Specify which VM and container images are permitted:

```json
{
  "approved_images": [
    "sha256:abc123def456789...",
    "sha256:def456abc789012...",
    "sha256:ghi789def012345..."
  ],
  "approved_image_patterns": [
    "ubuntu-22.04-",
    "rhel-9-",
    "trusted-base-"
  ]
}
```

### Trusted Registries

Define which container registries are trusted sources:

```json
{
  "trusted_registries": [
    "registry.example.com",
    "gcr.io/trusted-project",
    "docker.io/library"
  ]
}
```

### Approved Signers

Specify which signing identities are trusted:

```json
{
  "approved_signers": [
    "CN=Platform Signing Key,O=Example Corp,C=US",
    "keyid:abc123def456...",
    "email:security@example.com"
  ],
  "allowed_algorithms": [
    "RS256",
    "RS384",
    "ES256",
    "ES384"
  ]
}
```

### Loading Data from External Sources

Policy data can be loaded from multiple sources:

| Source | Use Case |
|--------|----------|
| Local files | Static configuration, version controlled |
| HTTP endpoints | Dynamic updates from configuration service |
| Bundle server | OPA bundle protocol for atomic updates |
| Kubernetes ConfigMaps | Cloud-native deployment |

## Policy Evaluation

### Go API

Evaluate attestation evidence against policies programmatically:

```go
package main

import (
    "context"
    "log"

    "github.com/your-org/trusted-platform/pkg/policy/opa"
)

func main() {
    // Initialize policy engine
    engine, err := opa.NewEngine(opa.Config{
        PolicyDir:   "/etc/trusted-platform/policies",
        DataDir:     "/etc/trusted-platform/policy-data",
        HotReload:   true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    // Prepare attestation evidence
    attestationData := map[string]interface{}{
        "quote": map[string]interface{}{
            "valid":     true,
            "nonce":     "abc123...",
            "timestamp": "2024-01-15T10:30:00Z",
        },
        "pcrs": map[string]string{
            "0": "sha256:3a7b...",
            "1": "sha256:8f12...",
            "7": "sha256:2c5e...",
        },
        "eventlog": map[string]interface{}{
            "valid":  true,
            "events": []interface{}{},
        },
    }

    // Evaluate policy
    result, err := engine.Evaluate(ctx, "attestation.host", attestationData)
    if err != nil {
        log.Fatal(err)
    }

    if !result.Allowed {
        log.Printf("Attestation denied: %v", result.Reasons)
        // Handle denial - reject workload, alert security team, etc.
        return
    }

    log.Println("Attestation approved")
}
```

### REST API

Evaluate policies via the attestation REST API:

**Endpoint**: `POST /api/v1/attestation/policy/evaluate`

**Request**:
```json
{
  "policy": "attestation.host",
  "input": {
    "quote": {
      "valid": true,
      "nonce": "abc123...",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    "pcrs": {
      "0": "sha256:3a7b...",
      "1": "sha256:8f12...",
      "7": "sha256:2c5e..."
    },
    "eventlog": {
      "valid": true,
      "events": []
    }
  }
}
```

**Response**:
```json
{
  "allowed": true,
  "decision_id": "d7f3a2b1-c4e5-6f78-9a0b-1c2d3e4f5a6b",
  "timestamp": "2024-01-15T10:30:05Z",
  "policy": "attestation.host",
  "reasons": []
}
```

**Denial Response**:
```json
{
  "allowed": false,
  "decision_id": "e8g4b3c2-d5f6-7g89-0b1c-2d3e4f5g6h7i",
  "timestamp": "2024-01-15T10:30:05Z",
  "policy": "attestation.host",
  "reasons": [
    "PCR values do not match expected baseline",
    "PCR 7 mismatch: expected sha256:2c5e..., got sha256:9f8a..."
  ]
}
```

### Decision Logging and Auditing

All policy decisions are logged for security auditing:

```json
{
  "decision_id": "d7f3a2b1-c4e5-6f78-9a0b-1c2d3e4f5a6b",
  "timestamp": "2024-01-15T10:30:05Z",
  "policy": "attestation.host",
  "allowed": false,
  "input_hash": "sha256:abc123...",
  "reasons": ["PCR values do not match expected baseline"],
  "source_ip": "10.0.1.50",
  "request_id": "req-xyz789",
  "duration_ms": 8
}
```

Decision logs support:
- Compliance auditing
- Security incident investigation
- Policy effectiveness analysis
- Performance monitoring

## Custom Policies

### Creating Custom Policies

Create a new policy file following the package naming convention:

```rego
# /etc/trusted-platform/policies/custom/edge_device.rego
package attestation.edge_device

import future.keywords.in

default allow = false

# Edge devices have relaxed PCR requirements but strict firmware checks
allow {
    valid_firmware
    valid_identity
    recent_attestation
}

valid_firmware {
    input.firmware.version in data.approved_firmware_versions
    input.firmware.signature_verified == true
}

valid_identity {
    input.device.idevid_valid == true
    input.device.manufacturer in data.approved_manufacturers
}

recent_attestation {
    attestation_age := time.now_ns() - input.quote.timestamp_ns
    max_age := data.max_attestation_age_ns
    attestation_age < max_age
}
```

### Policy File Structure

Organize policies by attestation type:

```
/etc/trusted-platform/policies/
    attestation/
        host_attestation.rego
        vm_attestation.rego
        container_attestation.rego
        image_trust.rego
    custom/
        edge_device.rego
        high_security_zone.rego
    common/
        helpers.rego
        time_utils.rego
```

### Testing Policies

Test policies before deployment using `opa test`:

```bash
# Create test file
cat > host_attestation_test.rego << 'EOF'
package attestation.host

test_allow_valid_attestation {
    allow with input as {
        "quote": {"valid": true},
        "pcrs": {
            "0": "sha256:expected_pcr0",
            "1": "sha256:expected_pcr1",
            "7": "sha256:expected_pcr7"
        },
        "eventlog": {"valid": true, "events": []}
    } with data.expected.pcrs as {
        "0": "sha256:expected_pcr0",
        "1": "sha256:expected_pcr1",
        "7": "sha256:expected_pcr7"
    }
}

test_deny_invalid_quote {
    not allow with input as {
        "quote": {"valid": false},
        "pcrs": {},
        "eventlog": {"valid": true, "events": []}
    }
}

test_deny_pcr_mismatch {
    not allow with input as {
        "quote": {"valid": true},
        "pcrs": {
            "0": "sha256:wrong_value",
            "1": "sha256:expected_pcr1",
            "7": "sha256:expected_pcr7"
        },
        "eventlog": {"valid": true, "events": []}
    } with data.expected.pcrs as {
        "0": "sha256:expected_pcr0",
        "1": "sha256:expected_pcr1",
        "7": "sha256:expected_pcr7"
    }
}
EOF

# Run tests
opa test . -v
```

### Deploying Policies

Deploy policies through the policy directory or bundle server:

```bash
# Copy policies to policy directory (triggers hot-reload)
cp custom_policy.rego /etc/trusted-platform/policies/custom/

# Verify policy loaded
curl -X GET http://localhost:8080/api/v1/attestation/policy/list

# Test policy with sample input
curl -X POST http://localhost:8080/api/v1/attestation/policy/evaluate \
  -H "Content-Type: application/json" \
  -d @test_input.json
```

## Configuration

Configure the policy engine in the platform configuration file:

```yaml
attestation:
  policy:
    engine: "opa"
    policy_dir: "/etc/trusted-platform/policies"
    data_dir: "/etc/trusted-platform/policy-data"
    default_action: "deny"
    decision_logging: true
    hot_reload: true
    hot_reload_interval: "30s"

    # Optional: Bundle server for centralized policy management
    bundle:
      enabled: false
      url: "https://policy.example.com/bundles/attestation"
      polling_interval: "60s"

    # Performance tuning
    cache:
      enabled: true
      ttl: "5m"
      max_entries: 10000

    # Decision log configuration
    logging:
      console: true
      file: "/var/log/trusted-platform/policy-decisions.log"
      format: "json"
      include_input: false  # Set true for debugging, false for production
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `engine` | string | `opa` | Policy engine type (currently only OPA supported) |
| `policy_dir` | string | required | Directory containing Rego policy files |
| `data_dir` | string | required | Directory containing policy data files |
| `default_action` | string | `deny` | Action when no policy matches (`allow` or `deny`) |
| `decision_logging` | bool | `true` | Enable decision audit logging |
| `hot_reload` | bool | `true` | Enable automatic policy reload on file changes |
| `hot_reload_interval` | duration | `30s` | Interval to check for policy file changes |

## Troubleshooting

### Policy Evaluation Failures

**Symptom**: All attestation requests denied unexpectedly.

**Diagnosis**:
```bash
# Check policy syntax
opa check /etc/trusted-platform/policies/

# Verify policy data loaded
curl http://localhost:8080/api/v1/attestation/policy/data

# Test with trace enabled
curl -X POST http://localhost:8080/api/v1/attestation/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{"policy": "attestation.host", "input": {...}, "trace": true}'
```

**Common Causes**:
- Missing or malformed policy data files
- Policy syntax errors preventing compilation
- Incorrect input structure from attestation layer
- Policy data paths not matching policy expectations

### Debugging with Decision Logs

Enable detailed decision logging for troubleshooting:

```yaml
attestation:
  policy:
    logging:
      include_input: true  # Include full input in logs
      level: "debug"       # Enable debug-level logging
```

Review decision logs:
```bash
# View recent decisions
tail -f /var/log/trusted-platform/policy-decisions.log | jq .

# Find denied decisions
grep '"allowed":false' /var/log/trusted-platform/policy-decisions.log | jq .

# Search by decision ID
grep "d7f3a2b1-c4e5-6f78-9a0b-1c2d3e4f5a6b" /var/log/trusted-platform/policy-decisions.log
```

### Policy Testing Commands

```bash
# Validate all policies compile
opa check --bundle /etc/trusted-platform/policies/

# Run policy unit tests
opa test /etc/trusted-platform/policies/ -v

# Evaluate policy with local input file
opa eval --data /etc/trusted-platform/policies/ \
         --data /etc/trusted-platform/policy-data/ \
         --input test_input.json \
         "data.attestation.host.allow"

# Trace policy evaluation
opa eval --data /etc/trusted-platform/policies/ \
         --data /etc/trusted-platform/policy-data/ \
         --input test_input.json \
         --format pretty \
         --explain full \
         "data.attestation.host.allow"

# Profile policy performance
opa eval --data /etc/trusted-platform/policies/ \
         --input test_input.json \
         --profile \
         "data.attestation.host.allow"
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `policy not found: attestation.xyz` | Policy package not loaded | Verify policy file exists and package name matches |
| `undefined ref: data.expected.pcrs` | Missing policy data | Ensure data files are in data_dir with correct structure |
| `type error: expected string, got number` | Input type mismatch | Verify attestation layer provides correct data types |
| `compile error: rule conflict` | Duplicate rule definitions | Check for conflicting rules across policy files |

## Related Documentation

| Document | Description |
|----------|-------------|
| [Attestation Architecture](architecture.md) | System design and data flows |
| [Attestation Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | REST and gRPC APIs |
| [Workload Attestation](workload-attestation.md) | Container and VM attestation |
| [Host Manifest](host-manifest.md) | Bare metal attestation reports |
| [Implementation Plan](../feature/ATTESTATION_PLAN.md) | Technical design document |
| [OPA Documentation](https://www.openpolicyagent.org/docs/) | Official OPA documentation |
| [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/) | Rego syntax and semantics |
