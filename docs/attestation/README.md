# Attestation Module

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md).

The attestation module provides comprehensive TPM-based attestation capabilities for physical hosts, virtual machines, and containers in the go-trusted-platform.

## Overview

Attestation enables cryptographic proof of system integrity by measuring workloads into TPM PCRs and generating signed quotes that remote verifiers can validate. The module supports multi-layer attestation across heterogeneous compute environments.

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Workload      |     |       VM         |     |    Manifest      |
|   Attestation    |     |   Attestation    |     |     Builder      |
| (PCR 14 Chain)   |     |   (vTPM Quotes)  |     |  (Aggregation)   |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         v                        v                        v
+------------------------------------------------------------------+
|                        Host TPM / vTPM                            |
+------------------------------------------------------------------+
         |                        |                        |
         v                        v                        v
+------------------+     +------------------+     +------------------+
|   Chain Manager  |     |   VM Attestor    |     | Manifest Signer  |
|                  |     |   VM Verifier    |     | Manifest Verifier|
+------------------+     +------------------+     +------------------+
                                  |
                                  v
                        +------------------+
                        |   Push Client    |
                        |   Scheduler      |
                        +------------------+
```

## Components

| Component | Package | Description |
|-----------|---------|-------------|
| Workload Attestation | `pkg/attestation/workload/` | PCR 14 extension for container/VM lifecycle |
| VM Attestation | `pkg/attestation/vm/` | vTPM quote generation and verification |
| Host Manifest | `pkg/attestation/manifest/` | Attestation aggregation with Merkle trees |
| Push Infrastructure | `pkg/attestation/push/` | Remote manifest distribution |

### Workload Attestation

Tracks container and VM lifecycle events by extending PCR 14 with workload measurements. Creates an auditable chain of all workloads that have run on a system.

Key features:
- PCR 14 extension for workload measurements
- Lifecycle hooks for start/stop events
- Chain verification against TPM PCR values
- Support for containers and VMs

[Workload Attestation Documentation](workload-attestation.md)

### VM Attestation

Provides vTPM-based attestation for virtual machines. VMs generate TPM quotes signed by their AIK/AK, with identity bound to the host via EK certificate subject.

Key features:
- vTPM quote generation and verification
- EK certificate chain validation
- VM-to-host binding via certificate CN
- PCR value verification

[VM Attestation Documentation](vm-attestation.md)

### Host Manifest

Aggregates attestations from physical hosts, VMs, and containers into a single signed document with Merkle tree integrity verification.

Key features:
- Manifest building with host, VM, and container attestations
- Merkle tree construction for data integrity
- AK-based signing and verification
- Nonce-based freshness protection

[Manifest Documentation](manifest.md)

### Push Infrastructure

Distributes attestation manifests to remote verification services, policy engines, and monitoring systems.

Key features:
- HTTP/HTTPS and gRPC transports
- mTLS authentication
- Configurable retry logic with exponential backoff
- Periodic and on-change triggers

[Push Documentation](push.md)

## Quick Start

### Workload Attestation

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/workload"
    "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// Create chain manager
cm := workload.NewChainManager(
    workload.WithTPMDevice(tpmDevice),
)

// Initialize with configuration
cfg := &config.WorkloadConfig{
    Enabled: true,
    PCR:     14,
    PCRBank: "sha256",
}
cm.Initialize(ctx, cfg)

// Record container start
measurement := &workload.WorkloadMeasurement{
    WorkloadType: workload.WorkloadTypeContainer,
    WorkloadID:   "container-abc123",
    ImageDigest:  "sha256:abc123...",
}
entry, _ := cm.ExtendPCR(ctx, measurement)
```

### VM Attestation

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"

// Create attestor
attestor := vm.NewVMAttestor(
    vm.WithVTPMDevice(vtpmDevice),
)

// Initialize
cfg := &vm.AttestorConfig{
    VTPMDevicePath:       "/dev/tpmrm0",
    DefaultHashAlgorithm: vm.HashAlgorithmSHA256,
    IncludeWorkloadPCR:   true,
}
attestor.Initialize(ctx, cfg)

// Generate attestation
request := &vm.QuoteRequest{
    Nonce:         nonce,
    PCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7, 14},
    HashAlgorithm: vm.HashAlgorithmSHA256,
}
attestation, _ := attestor.GetAttestation(ctx, request)
```

### Manifest Generation

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"

// Create builder
builder := manifest.NewManifestBuilder(
    manifest.WithTPMDevice(tpmDevice),
)

cfg := &manifest.BuilderConfig{
    HostID:        "host-001",
    HashAlgorithm: manifest.HashAlgorithmSHA256,
    NonceSize:     32,
}
builder.Initialize(ctx, cfg)

// Add attestations
builder.SetHostAttestation(ctx, hostAttestation)
builder.AddVMAttestation(ctx, vmAttestation)
builder.AddContainerAttestation(ctx, containerAttestation)

// Build manifest
hostManifest, _ := builder.Build(ctx)
```

## Configuration

### YAML Configuration

```yaml
attestation:
  workload:
    enabled: true
    pcr: 14
    pcr-bank: sha256
    include-image-digest: true
    include-container-id: true
    include-workload-type: true

  manifest:
    include-vms: true
    include-containers: true
    push-enabled: true
    push-interval: "5m"
    push-targets:
      - https://verifier.example.com/attestation

  policy:
    engine: opa
    policy-dir: /etc/trusted-platform/policies
    default-action: deny
```

## PCR Allocation

| PCR | Purpose |
|-----|---------|
| 0-7 | UEFI/Secure Boot measurements |
| 8-10 | Kernel, initramfs, IMA |
| 14 | Workload identity (container/VM chain) |
| 23 | Platform policy (golden measurements) |

## Trust Hierarchy

```
Bare Metal Host (TPM 2.0)
+-- PCR 0-7: Firmware, bootloader, kernel
+-- PCR 8-10: Kernel modules, IMA
+-- PCR 23: Platform policy
    |
    +-- Virtual Machine (vTPM)
    |   +-- PCR 14: VM identity chain
    |       |
    |       +-- Container (PCR 14 extension)
    |           +-- Workload measurement
    |
    +-- Container (PCR 14 extension)
        +-- Workload measurement
```

## Security Considerations

1. **TPM Protection**: All attestation keys are stored in TPM and never exported
2. **Freshness**: Nonces prevent replay attacks
3. **Chain Validation**: EK certificates must chain to Platform CA
4. **Merkle Trees**: Provide tamper-evident integrity for manifests
5. **mTLS**: Mutual authentication for push operations

## Related Documentation

- [API Reference](api-reference.md)
- [Workload Attestation](workload-attestation.md)
- [VM Attestation](vm-attestation.md)
- [Host Manifest](manifest.md)
- [Push Infrastructure](push.md)
