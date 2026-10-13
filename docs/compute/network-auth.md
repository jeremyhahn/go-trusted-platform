# Network Authentication Service

> **Status: REFERENCE** · Last verified: 2026-10-13
> Deep dive on `pkg/compute/network`: certificate port authentication, OPA evaluation and VLAN flow rules.

## Overview

The network authentication service (`pkg/compute/network`) provides x509 certificate-based port authentication with VLAN transitions, TPM attestation integration, and OPA policy evaluation. It enables devices to securely transition from quarantine networks to production environments based on cryptographic identity and platform integrity.

## Architecture

```
                          Authentication Flow
+--------+     +----------------+     +----------------+     +----------------+
| Device |---->| mTLS with Cert |---->| Extract OIDs   |---->| TPM Attestation|
+--------+     +----------------+     +----------------+     +----------------+
                                                                     |
                                                                     v
+--------+     +----------------+     +----------------+     +----------------+
| VLAN   |<----| Install Rules  |<----| OPA Policy     |<----| Verify PCRs    |
| Change |     | (OpenFlow)     |     | Evaluation     |     +----------------+
+--------+     +----------------+     +----------------+
```

## Authentication States

| State | Description | VLAN Access |
|-------|-------------|-------------|
| `quarantine` | Initial state, restricted access | Quarantine VLAN |
| `enrolling` | Certificate enrollment in progress | Quarantine VLAN |
| `authorized` | Full network access granted | Production VLAN |
| `revoked` | Access denied, certificate or attestation failure | Quarantine VLAN |

### State Transitions

`AuthState.CanTransitionTo` allows exactly these transitions:

| From | To |
|------|----|
| `quarantine` | `enrolling`, `authorized`, `revoked` |
| `enrolling` | `authorized`, `quarantine`, `revoked` |
| `authorized` | `quarantine`, `revoked` |
| `revoked` | `quarantine` (re-enrollment) |

## Configuration

### AuthConfig

```go
config := &network.AuthConfig{
    QuarantineVLAN:          6,           // VLAN for compromised/untrusted devices
    ProductionVLAN:          11,          // Default production VLAN (OFFICE)
    BridgeName:              "br0",       // OVS bridge name
    ControllerAddress:       "tcp:127.0.0.1:6653",
    OPAEndpoint:             "http://localhost:8181",
    OPAPolicyPath:           "network/authz",
    RequireAttestation:      true,        // Require TPM attestation
    RequirePolicyEvaluation: true,        // Require OPA evaluation
    SessionTimeout:          24 * time.Hour,
    TrustedCAs:              []*x509.Certificate{caCert},
    RequiredOIDs:            []asn1.ObjectIdentifier{
        networkAccessOID,    // deployment-defined; the package ships none
        productionAccessOID,
    },
    Reattest: &network.ReattestConfig{
        Enabled:             true,
        Interval:            6 * time.Hour,
        GracePeriod:         30 * time.Minute,
        MaxFailures:         3,
        QuarantineOnFailure: true,
        AttestationTimeout:  30 * time.Second,
    },
}
```

### Creating the Service

```go
service := network.NewNetworkAuthService(
    network.WithLogger(logger),
    network.WithPolicyExtractor(extractor),
    network.WithOPAEvaluator(opaEvaluator),
    network.WithFlowManager(flowManager),
    network.WithAttestationVerifier(verifier),
)

if err := service.Initialize(ctx, config); err != nil {
    return err
}
defer service.Close()
```

## mTLS Port Authentication

Devices authenticate using x509 client certificates presented during mTLS handshake:

```go
request := &network.PortAuthRequest{
    PortID:           "eth0",
    Certificate:      clientCert,
    CertificateChain: []*x509.Certificate{intermediateCert},
    Nonce:            attestationNonce,
    ExpectedPCRs:     expectedPCRValues,
    Timeout:          30 * time.Second,
}

result, err := service.Authenticate(ctx, request)
if err != nil {
    // Handle authentication failure
    return err
}

if result.IsSuccessful() {
    fmt.Printf("Device authorized on VLAN %d\n", result.VLAN)
}
```

### Authentication Result

```go
type AuthResult struct {
    PortID              string
    State               AuthState
    VLAN                uint16
    PolicyOIDs          []asn1.ObjectIdentifier
    AttestationVerified bool
    PolicyEvaluated     bool
    PolicyDecision      bool
    FlowRulesInstalled  bool
    SessionID           string
    DeviceID            string
    ExpiresAt           time.Time
    Errors              []string
}
```

## Policy OID Extraction

The service extracts policy OIDs from x509 certificate extensions to determine access levels:

### Policy OIDs

The package defines only the standard extension OIDs (`OIDCertificatePolicies`
`2.5.29.32`, `OIDSubjectAltName` `2.5.29.17`, `OIDExtendedKeyUsage`
`2.5.29.37`). The access-granting policy OIDs belong to the deployment: they
are passed in through `AuthConfig.RequiredOIDs` and matched by the OPA policy.
The placeholder arc `1.3.6.1.4.1.99999` is forbidden in production code
(`pkg/sdn/zone/guards_test.go`); the examples below use it only as a placeholder.

### Policy Extraction

```go
extractor := network.NewPolicyExtractor(
    network.WithPolicyExtractorLogger(logger),
)

info, err := extractor.ExtractPolicyInfo(ctx, certificate)
if err != nil {
    return err
}

// Check for required OIDs
for _, oid := range info.OIDs {
    fmt.Printf("Found policy OID: %s\n", oid.String())
}

// Validate required OIDs
requiredOIDs := []asn1.ObjectIdentifier{
    networkAccessOID,
}
if err := extractor.ValidateRequiredOIDs(ctx, cert, requiredOIDs); err != nil {
    // Missing required OID
    return err
}
```

### PolicyInfo Structure

```go
type PolicyInfo struct {
    OIDs                 []asn1.ObjectIdentifier
    PolicyQualifiers     map[string]string
    CertificateSubject   string
    CertificateIssuer    string
    CertificateSerial    string
    CertificateNotBefore time.Time
    CertificateNotAfter  time.Time
    ExtendedKeyUsages    []x509.ExtKeyUsage
    KeyUsage             x509.KeyUsage
    IsCA                 bool
    DeviceID             string
}
```

## OPA Policy Evaluation

Access decisions are delegated to an Open Policy Agent server: the evaluator
POSTs `{"input": ...}` to `<OPAEndpoint>/v1/data/<OPAPolicyPath>` and reads
`allow` and `assigned_vlan` from the result. A missing result is a deny.

### OPA Input

```json
{
  "device_id": "device-12345",
  "port_id": "eth0",
  "policy_oids": ["1.3.6.1.4.1.99999.1.2", "1.3.6.1.4.1.99999.1.3"],
  "certificate_subject": "CN=device-12345,O=Example",
  "certificate_issuer": "CN=Device CA,O=Example",
  "attestation_verified": true,
  "requested_vlan": 100,
  "timestamp": "2025-01-09T10:30:00Z"
}
```

### OPA Policy Example

```rego
package network.authz

import rego.v1

default allow := false

# Allow production access for attested devices with correct OIDs
allow if {
    input.attestation_verified
    has_network_access_oid
    has_production_access_oid
}

# Assign VLAN based on policy OIDs
assigned_vlan := 100 if {
    has_production_access_oid
}

assigned_vlan := 50 if {
    has_network_access_oid
    not has_production_access_oid
}

has_network_access_oid if {
    "1.3.6.1.4.1.99999.1.2" in input.policy_oids
}

has_production_access_oid if {
    "1.3.6.1.4.1.99999.1.3" in input.policy_oids
}
```

### OPA Result

```go
type OPAResult struct {
    Allow           bool      `json:"allow"`
    AssignedVLAN    uint16    `json:"assigned_vlan,omitempty"`
    Reasons         []string  `json:"reasons,omitempty"`
    RequiredActions []string  `json:"required_actions,omitempty"`
    EvaluatedAt     time.Time `json:"evaluated_at"`
}
```

## OpenFlow Rule Management

The flow manager installs and removes OpenFlow rules for VLAN isolation:

### Flow Rule Types

| Type | Priority | Purpose |
|------|----------|---------|
| `quarantine` | `QuarantinePriority` (default 200) | Restrict traffic to enrollment services |
| `production` | `ProductionPriority` (default 300) | Full network access with VLAN tagging |
| `drop` | caller-set | Block all traffic |
| `redirect` | caller-set | Redirect to captive portal |
| `rate_limit` | caller-set | Apply rate limiting |
| `monitor` | caller-set | Mirror traffic for monitoring |

Only `InstallQuarantineRules` and `InstallProductionRules` build rules
themselves; the other types are installed through `InstallRule` with the
priority the caller sets. `DefaultPriority` defaults to 100.

### Flow Manager API

```go
flowManager := network.NewFlowManager(
    network.WithFlowManagerLogger(logger),
    network.WithFlowController(ovsController),
)

config := &network.FlowConfig{
    BridgeName:         "br0",
    ControllerAddress:  "tcp:127.0.0.1:6653",
    DefaultPriority:    100,
    QuarantinePriority: 200,
    ProductionPriority: 300,
}

if err := flowManager.Initialize(ctx, config); err != nil {
    return err
}

// Install quarantine rules (limited access)
err := flowManager.InstallQuarantineRules(ctx, "port-1", quarantineVLAN)

// Install production rules (full access)
err := flowManager.InstallProductionRules(ctx, "port-1", productionVLAN)

// Atomic VLAN transition
err := flowManager.TransitionVLAN(ctx, "port-1", quarantineVLAN, productionVLAN)

// Get current rules
rules, err := flowManager.GetRules(ctx, "port-1")

// Remove all rules for port
err := flowManager.RemoveRules(ctx, "port-1")
```

### OpenFlow Actions

| Action | Description |
|--------|-------------|
| `output` | Forward to specific port |
| `drop` | Silently drop packet |
| `set_vlan` | Set VLAN ID |
| `strip_vlan` | Remove VLAN tag |
| `set_field` | Set a header field |
| `controller` | Send to controller for inspection |
| `flood` | Send to all ports |

## VLAN Transitions

### Transition Flow

`Authenticate` moves a port by removing its rules, installing the production
rules (which also set the OVSDB port VLAN tag), and falling back to the
quarantine rules if that install fails; it then records the port state.
`Revoke` does the same with the quarantine rules.

`FlowManager.TransitionVLAN` is make-before-break instead: it installs the
rules for the new VLAN first, then removes the rules on the old VLAN, and keeps
the new rules even if a removal fails.

### Transition Structure

```go
type VLANTransition struct {
    PortID        string
    FromVLAN      uint16
    ToVLAN        uint16
    FromState     AuthState
    ToState       AuthState
    Reason        string
    Timestamp     time.Time
    TransactionID string
    Success       bool
    Error         string
}
```

## Re-attestation

Continuous compliance through periodic re-attestation:

```go
// Trigger re-attestation
result, err := service.Reattest(ctx, portID, newNonce)
if err != nil {
    // Re-attestation failed, device may be quarantined
    return err
}

// Check if port needs re-attestation
state, _ := service.GetPortState(ctx, portID)
if state.NeedsReattest(config.Reattest.Interval) {
    // Initiate re-attestation
}
```

### Failure Handling

- **Access during re-attestation**: rules are not touched while a re-attestation runs
- **Failure Count**: `PortState.FailureCount` tracks consecutive failures
- **Automatic Quarantine**: with `QuarantineOnFailure` set, the port moves to quarantine once `FailureCount` reaches `MaxFailures`

## Revocation

```go
// Revoke port access
err := service.Revoke(ctx, portID, "Certificate expired")
if err != nil {
    return err
}
// Port is now in revoked state on quarantine VLAN
```

## Error Types

| Error | Description |
|-------|-------------|
| `ErrAuthFailed` | Authentication failed |
| `ErrCertInvalid` | Certificate validation failed |
| `ErrPolicyViolation` | OPA policy denied access |
| `ErrAttestFailed` | TPM attestation failed |
| `ErrVLANFailed` | VLAN transition failed |
| `ErrOPAEvaluation` | OPA evaluation error |
| `ErrFlowRule` | OpenFlow rule error |
| `ErrOIDMissing` | Required OID not in certificate |
| `ErrPortNotFound` | Port not registered |
| `ErrStateTransition` | Invalid state transition |
| `ErrSessionExpired` | Authentication session expired |
| `ErrReattestRequired` | Re-attestation is due |
| `ErrInvalidConfig` | Invalid configuration or argument |
| `ErrContextCanceled` | Context canceled before the operation |
| `ErrServiceNotInitialized` | Service not initialized or already closed |

## Thread Safety

All operations are thread-safe:

- Service lifecycle flags are `atomic.Bool`
- Port state is held in a `sync.Map`
- Per-port rule lists are swapped with `sync.Map.CompareAndSwap`

## Related Documentation

- [802.1X Network Attachment](802.1X-network-attachment.md)
- [Compute Architecture](architecture.md)
- [PXE Provisioning](pxe-provisioning.md)
