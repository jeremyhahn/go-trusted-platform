# Attestation Architecture

## Overview

The Trusted Platform Attestation architecture provides hierarchical trust verification using TPM 2.0 hardware roots of trust. The system enables cryptographic proof of platform integrity through TPM quotes, event log analysis, and policy-based verification. Attestation extends from physical hosts through virtual machines to individual containers, creating a complete chain of trust for all workloads.

## System Architecture

```
+------------------------------------------------------------------------------+
|                        Trusted Platform Attestation                           |
+------------------------------------------------------------------------------+
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                      Attestation Manager                               |  |
|  |                   (pkg/attestation/manager.go)                         |  |
|  |                                                                        |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |  |    Quote      |  |    Verify     |  |   Manifest    |               |  |
|  |  |  Generator    |  |    Engine     |  |   Builder     |               |  |
|  |  |               |  |               |  |               |               |  |
|  |  | * Nonce gen   |  | * Quote check |  | * Host info   |               |  |
|  |  | * PCR select  |  | * PCR compare |  | * VM enum     |               |  |
|  |  | * AK signing  |  | * Event parse |  | * Container   |               |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |                                                                        |  |
|  |  +--------------------------------------------------------------------+|  |
|  |  |                  Workload Chain Manager                            ||  |
|  |  |               PCR 14 Extension Tracking                            ||  |
|  |  +--------------------------------------------------------------------+|  |
|  +------------------------------------------------------------------------+  |
|                                      |                                       |
|                                      | uses                                  |
|                                      v                                       |
|  +------------------------------------------------------------------------+  |
|  |                         TPM Layer                                      |  |
|  |                      (go-tpm library)                                  |  |
|  |                                                                        |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |  |    Quote      |  |     PCR       |  |   Event Log   |               |  |
|  |  |  Generation   |  |    Reading    |  |    Parser     |               |  |
|  |  |               |  |               |  |               |               |  |
|  |  | * TPM2_Quote  |  | * PCR banks   |  | * TCG2 format |               |  |
|  |  | * AK handle   |  | * SHA-256/384 |  | * Replay      |               |  |
|  |  | * Signature   |  | * Selection   |  | * Verify      |               |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  +------------------------------------------------------------------------+  |
|                                      |                                       |
|         +----------------------------+----------------------------+          |
|         |                            |                            |          |
|         v                            v                            v          |
|  +----------------+         +----------------+         +----------------+    |
|  | Certificate    |         |  Policy Engine |         | Workload Mgr   |    |
|  | Authority      |         |     (OPA)      |         |                |    |
|  |                |         |                |         |                |    |
|  | * IDevID/IAK   |         | * Rego rules   |         | * Podman       |    |
|  | * Attest store |         | * PCR policy   |         | * QEMU/libvirt |    |
|  | * ACME enroll  |         | * Evaluation   |         | * swtpm        |    |
|  +----------------+         +----------------+         +----------------+    |
|                                                                              |
+------------------------------------------------------------------------------+
                                      |
              +-----------------------+-----------------------+
              |                       |                       |
              v                       v                       v
       +-------------+         +-------------+         +-------------+
       |  platformd  |         |     CA      |         |    OPA      |
       |  (daemon)   |         |  (go-ca)    |         |  (policy)   |
       +-------------+         +-------------+         +-------------+
```

## Component Overview

### Attestation Manager

The central coordinator for all attestation operations. Orchestrates quote generation, verification workflows, and manifest creation.

Responsibilities:
- Coordinate attestation requests across components
- Manage attestation state and caching
- Route verification requests to appropriate handlers
- Aggregate results from multiple attestation sources

### TPM Interface

Hardware interaction layer using go-tpm for TPM 2.0 communication.

Capabilities:
- TPM device discovery and initialization
- Session management for authorized operations
- Error handling and retry logic
- Support for both hardware TPM and swtpm

### Quote Generator

Creates TPM quotes with cryptographic proof of platform state.

Operations:
- Generate cryptographic nonces for freshness
- Select appropriate PCR banks (SHA-256, SHA-384)
- Request TPM2_Quote with Attestation Key (AK)
- Package quote with signature and certificate chain

### Quote Verifier

Validates TPM quotes against known-good PCR values and policies.

Verification steps:
- Validate quote signature against AK certificate
- Verify nonce freshness and uniqueness
- Compare PCR values against expected baselines
- Check event log consistency with PCR values

### Event Log Analyzer

Parses and replays TCG2 event logs to verify measurement integrity.

Functions:
- Parse TCG2 event log binary format
- Replay measurements to verify PCR values
- Extract event metadata for policy evaluation
- Identify unexpected or malicious measurements

### Manifest Builder

Creates hierarchical attestation reports encompassing hosts and workloads.

Report contents:
- Host platform attestation summary
- Virtual machine attestation for each VM
- Container attestation for each container
- Cryptographic binding between layers

### Workload Chain Manager

Tracks PCR 14 extensions as workloads start and stop.

Tracking:
- Record workload lifecycle events
- Maintain extension chain integrity
- Support workload enumeration for attestation
- Provide tamper-evident workload history

### Policy Engine

OPA-based policy evaluation for attestation decisions.

Policy features:
- Rego policy language for flexible rules
- PCR value baseline comparisons
- Event log content validation
- Custom attestation requirements per workload type

## Data Model

All attestation data uses structured storage paths within the CA:

```
Attestation Storage (CA):
attestation/{akCN}/quote/data          -> TPM quote blob
attestation/{akCN}/quote/signature     -> Quote signature
attestation/{akCN}/quote/nonce         -> Challenge nonce
attestation/{akCN}/quote/timestamp     -> Quote creation time

attestation/{akCN}/eventlog/data       -> TCG2 event log binary
attestation/{akCN}/eventlog/parsed     -> Parsed event entries (JSON)
attestation/{akCN}/eventlog/hash       -> Event log integrity hash

attestation/{akCN}/pcrs/data           -> PCR values snapshot
attestation/{akCN}/pcrs/bank           -> PCR bank identifier
attestation/{akCN}/pcrs/selection      -> Selected PCR indices

Device Profiles:
profiles/{profileName}/pcrs/expected   -> Expected PCR values
profiles/{profileName}/events/allowed  -> Allowed event patterns
profiles/{profileName}/policy/rego     -> OPA policy for profile

Workload Chains:
workloads/{hostID}/chain/current       -> Current PCR 14 value
workloads/{hostID}/chain/entries       -> Extension history
workloads/{hostID}/chain/manifest      -> Active workload manifest
```

## Attestation Flows

### Device Enrollment Flow

```
Device                platformd               TPM                    CA
   |                     |                     |                     |
   | 1. Enrollment req   |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 2. Create EK        |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    EK handle        |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 3. Create AK        |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    AK handle + pub  |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 4. ACME enroll-01   |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    Challenge        |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   |                     | 5. Prove possession |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    Signed response  |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 6. Submit proof     |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    IDevID cert      |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   | 7. Enrollment done  |                     |                     |
   |<--------------------|                     |                     |
```

### Quote Verification Flow

```
Verifier             Device              TPM                 Policy Engine
   |                   |                   |                       |
   | 1. Request quote  |                   |                       |
   |   (with nonce)    |                   |                       |
   |------------------>|                   |                       |
   |                   |                   |                       |
   |                   | 2. TPM2_Quote     |                       |
   |                   |------------------>|                       |
   |                   |                   |                       |
   |                   |    Quote + sig    |                       |
   |                   |<------------------|                       |
   |                   |                   |                       |
   |                   | 3. Read event log |                       |
   |                   |------------------>|                       |
   |                   |                   |                       |
   |                   |    Event log      |                       |
   |                   |<------------------|                       |
   |                   |                   |                       |
   |    Quote bundle   |                   |                       |
   |<------------------|                   |                       |
   |                   |                   |                       |
   | 4. Verify quote signature             |                       |
   |                   |                   |                       |
   | 5. Replay event log                   |                       |
   |                   |                   |                       |
   | 6. Evaluate policy|                   |                       |
   |------------------------------------------------------>|       |
   |                   |                   |                       |
   |                   |                   |    Policy decision    |
   |<------------------------------------------------------|       |
   |                   |                   |                       |
   | 7. Return result  |                   |                       |
   |------------------>|                   |                       |
```

### Manifest Generation Flow

```
Request              Attestation Mgr          Host TPM           VM/Container
   |                       |                     |                     |
   | 1. Generate manifest  |                     |                     |
   |---------------------->|                     |                     |
   |                       |                     |                     |
   |                       | 2. Collect host     |                     |
   |                       |    attestation      |                     |
   |                       |-------------------->|                     |
   |                       |                     |                     |
   |                       |    Host quote       |                     |
   |                       |<--------------------|                     |
   |                       |                     |                     |
   |                       | 3. Enumerate VMs    |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    VM list          |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 4. For each VM:     |                     |
   |                       |    Get swtpm quote  |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    VM quotes        |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 5. Enumerate        |                     |
   |                       |    containers       |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    Container list   |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 6. Sign manifest    |                     |
   |                       |-------------------->|                     |
   |                       |                     |                     |
   |    Signed manifest    |    Signature        |                     |
   |<----------------------|<--------------------|                     |
```

### Workload Attestation Flow

```
Workload Mgr         platformd               TPM                    CA
   |                     |                     |                     |
   | 1. Container start  |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 2. Compute digest   |                     |
   |                     | H(type||id||image)  |                     |
   |                     |                     |                     |
   |                     | 3. Extend PCR 14    |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    New PCR value    |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 4. Record extension |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    Stored           |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   | 5. Start confirmed  |                     |                     |
   |<--------------------|                     |                     |
   |                     |                     |                     |
   | (Later: Container stop)                   |                     |
   |                     |                     |                     |
   | 6. Container stop   |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 7. Record stop      |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
```

## Hierarchical Trust Model

```
+---------------------------------------------+
|           Host Attestation                  |
|  TPM 2.0 (PCRs 0-10, 14, 23)               |
|                                             |
|  * Hardware root of trust                   |
|  * Platform firmware measurements           |
|  * OS boot measurements                     |
|  * Workload chain in PCR 14                 |
+-------------+---------------+---------------+
              |               |               |
              v               v               v
       +-------------+ +-------------+ +-------------+
       |    VM 1     | |    VM 2     | |    VM N     |
       |   swtpm     | |   swtpm     | |   swtpm     |
       |             | |             | |             |
       | * vTPM 2.0  | | * vTPM 2.0  | | * vTPM 2.0  |
       | * VM boot   | | * VM boot   | | * VM boot   |
       | * Guest OS  | | * Guest OS  | | * Guest OS  |
       +------+------+ +------+------+ +------+------+
              |               |               |
       +------+------+ +------+------+ +------+------+
       |  C1  |  C2  | |  C3  |  C4  | |  C5  |  C6  |
       +------+------+ +------+------+ +------+------+

Trust Propagation:
  Host TPM ---[quote]---> Verifier
       |
       +---> swtpm (VM 1) ---[quote]---> Verifier
       |          |
       |          +---> Container C1 ---[manifest]---> Verifier
       |          +---> Container C2 ---[manifest]---> Verifier
       |
       +---> swtpm (VM 2) ---[quote]---> Verifier
                  |
                  +---> Container C3 ---[manifest]---> Verifier
                  +---> Container C4 ---[manifest]---> Verifier
```

## PCR Extension Chain

Workloads are tracked through sequential PCR 14 extensions:

```
PCR 14 Extension Chain
+------------------------------------------------------------------------------+
|                                                                              |
|  Initial State (boot):                                                       |
|  PCR[14] = 0x0000...0000 (all zeros)                                        |
|                                                                              |
|  Extension 1 (Container A starts):                                           |
|  digest_1 = H("container" || "container-a-id" || "sha256:abc123...")        |
|  PCR[14] = H(PCR[14] || digest_1)                                           |
|          = 0x3a7b...c4e2                                                    |
|                                                                              |
|  Extension 2 (VM B starts):                                                  |
|  digest_2 = H("vm" || "vm-b-id" || "sha256:def456...")                      |
|  PCR[14] = H(PCR[14] || digest_2)                                           |
|          = 0x8f12...9d3a                                                    |
|                                                                              |
|  Extension 3 (Container C starts):                                           |
|  digest_3 = H("container" || "container-c-id" || "sha256:ghi789...")        |
|  PCR[14] = H(PCR[14] || digest_3)                                           |
|          = 0x2c5e...a1b7                                                    |
|                                                                              |
+------------------------------------------------------------------------------+

Chain Properties:
  * Order-dependent: Same workloads in different order = different PCR
  * Tamper-evident: Cannot remove or reorder entries
  * Verifiable: Can replay chain to verify current PCR value
  * Auditable: Complete history of workload lifecycle
```

## Security Model

### Hardware Root of Trust

| Component | Security Property |
|-----------|-------------------|
| TPM 2.0 | Tamper-resistant hardware security module |
| EK | Manufacturer-provisioned, unique identity |
| SRK | Storage hierarchy root, platform-bound |
| AK | Attestation signing key, non-migratable |

### Quote Freshness

```
Freshness Verification:
+-------------------------------------------------------------------+
|                                                                   |
|  1. Verifier generates nonce: N = random(256 bits)               |
|                                                                   |
|  2. Quote includes nonce: Quote = Sign_AK(PCRs || N)             |
|                                                                   |
|  3. Verification:                                                 |
|     - Check signature with AK public key                          |
|     - Verify N matches original challenge                         |
|     - Confirm quote timestamp within acceptable window            |
|                                                                   |
|  Protection against:                                              |
|     * Replay attacks (nonce uniqueness)                           |
|     * Stale quotes (timestamp check)                              |
|     * Quote forgery (AK signature)                                |
|                                                                   |
+-------------------------------------------------------------------+
```

### Policy-Based Verification

| Policy Type | Description |
|-------------|-------------|
| PCR Baseline | Expected PCR values for known-good state |
| Event Allowlist | Permitted measurement events |
| Workload Rules | Required attestation for workload types |
| Time Bounds | Maximum age for valid attestation |

### Tamper-Evident Event Logs

```
Event Log Integrity:
+-------------------------------------------------------------------+
|                                                                   |
|  TCG2 Event Log Format:                                           |
|  +----------------+----------------+----------------+              |
|  | Event Header   | Digest         | Event Data    |              |
|  | (PCR, type)    | (SHA-256/384)  | (variable)    |              |
|  +----------------+----------------+----------------+              |
|                                                                   |
|  Replay Verification:                                             |
|  1. Start with known-good initial PCR values                      |
|  2. For each event: PCR' = H(PCR || event_digest)                 |
|  3. Compare final PCR values with quoted values                   |
|  4. Any mismatch indicates tampering                              |
|                                                                   |
+-------------------------------------------------------------------+
```

### Hierarchical Trust Propagation

| Level | Trust Anchor | Verification Method |
|-------|--------------|---------------------|
| Host | Hardware TPM | TPM quote with EK/AK chain |
| VM | Host attestation | swtpm quote bound to host |
| Container | VM/Host attestation | PCR 14 extension chain |

## Performance Characteristics

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| Quote generation | ~100ms | TPM 2.0 hardware operation |
| Quote verification | ~50ms | Signature verification + PCR compare |
| Event log replay | ~20ms per 1000 events | Linear in event count |
| Manifest generation | ~500ms per 100 workloads | Includes enumeration overhead |
| Policy evaluation | ~10ms | OPA Rego evaluation |
| PCR extension | ~5ms | Single TPM operation |
| Nonce generation | ~1ms | Cryptographic random |

### Scaling Considerations

```
Throughput Limits:
+-------------------------------------------------------------------+
|                                                                   |
|  TPM Operations:                                                  |
|  * Hardware TPM: ~10 quotes/second (hardware bound)               |
|  * swtpm: ~100 quotes/second (software emulation)                 |
|                                                                   |
|  Verification:                                                    |
|  * Single core: ~200 verifications/second                         |
|  * Multi-core: Linear scaling with worker count                   |
|                                                                   |
|  Manifest Generation:                                             |
|  * Small deployment (<10 workloads): <100ms                       |
|  * Medium deployment (10-100 workloads): <500ms                   |
|  * Large deployment (100-1000 workloads): ~5s                     |
|                                                                   |
+-------------------------------------------------------------------+
```

## Container Attestation

Container attestation uses an event-log based approach where PCR 14 holds an aggregate hash while a measurement log tracks individual container measurements.

### Why Event-Log Based Attestation

PCR registers can only be extended, never reset (except debug PCR 16). With multiple containers starting and stopping, direct PCR-per-container allocation is impossible. The event-log approach solves this by:

- Using PCR 14 as the **aggregate** hash of all container measurements
- Maintaining a **measurement log** that tracks individual container entries
- Enabling verification by replaying the log to reconstruct the expected PCR value

This follows the TCG (Trusted Computing Group) standard approach used by measured boot.

### Container Measurement Flow

```
Container Orchestrator        Measurement Log         TPM
        |                           |                  |
        | 1. Container Create       |                  |
        |-------------------------->|                  |
        |                           |                  |
        | 2. Compute measurements   |                  |
        |   - Hash image layers     |                  |
        |   - Hash container config |                  |
        |                           |                  |
        | 3. Append log entry       |                  |
        |-------------------------->|                  |
        |                           |                  |
        |                           | 4. Extend PCR 14 |
        |                           |----------------->|
        |                           |                  |
        |                           |   New PCR value  |
        |                           |<-----------------|
        |                           |                  |
        | 5. Return with entry      |                  |
        |<--------------------------|                  |
```

### Measurement Entry Types

| Event Type | Description |
|------------|-------------|
| CREATE | Container created with image and config hashes |
| START | Container execution started |
| STOP | Container execution stopped |
| REMOVE | Container removed from system |

### Integration with Container Orchestrator

The Container Orchestrator (`pkg/compute/container/`) integrates with the attestation system through:

1. **attestation.go** - TPM PCR 14 extension operations
2. **measurement_log.go** - Per-container measurement tracking

When the orchestrator creates, starts, stops, or removes a container:
- The appropriate measurement is computed
- PCR 14 is extended with the measurement hash
- The measurement log records the entry for verification

### Verification Process

Remote verifiers can validate container attestation by:

1. Requesting a TPM quote over PCR 14
2. Receiving the measurement log alongside the quote
3. Replaying the log to compute the expected PCR 14 value
4. Comparing the computed value with the quoted value
5. Extracting individual container measurements from the log

### Benefits

| Benefit | Description |
|---------|-------------|
| Unlimited containers | Single PCR supports any number of containers |
| Individual tracking | Each container measurement recoverable from log |
| Standard approach | Follows TCG measured boot patterns |
| Audit capability | Log can be persisted and audited |
| Remote verification | Verifier can validate any container in the log |

## Related Documentation

- [TPM Integration](../tpm/README.md) - TPM 2.0 device interaction and key management
- [Certificate Authority](../ca/README.md) - IDevID/IAK certificate issuance
- [Policy Engine](../policy/README.md) - OPA-based attestation policies
- [Workload Management](../workloads/README.md) - Container and VM lifecycle
- [Workload Attestation](workload-attestation.md) - Container measurement log details
- [Security Model](../security/README.md) - Platform security architecture
- [API Reference](../api/attestation.md) - Attestation API endpoints
