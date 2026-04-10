# Network Authentication Service

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

```
quarantine --> enrolling --> authorized
    |              |             |
    +-------> revoked <----------+
                  |
                  v
             quarantine (re-enrollment)
```

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
        network.OIDNetworkAccess,
        network.OIDProductionAccess,
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

### Standard OIDs

| OID | Name | Purpose |
|-----|------|---------|
| `2.5.29.32` | Certificate Policies | Standard policy extension |
| `1.3.6.1.4.1.99999.1.1` | Device Attestation | Indicates TPM attestation capability |
| `1.3.6.1.4.1.99999.1.2` | Network Access | Grants basic network access |
| `1.3.6.1.4.1.99999.1.3` | Production Access | Grants production VLAN access |

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
    network.OIDNetworkAccess,
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

Access decisions are delegated to Open Policy Agent for flexible, declarative authorization:

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

default allow = false

# Allow production access for attested devices with correct OIDs
allow {
    input.attestation_verified
    has_network_access_oid
    has_production_access_oid
}

# Assign VLAN based on policy OIDs
assigned_vlan = 100 {
    has_production_access_oid
}

assigned_vlan = 50 {
    has_network_access_oid
    not has_production_access_oid
}

has_network_access_oid {
    input.policy_oids[_] == "1.3.6.1.4.1.99999.1.2"
}

has_production_access_oid {
    input.policy_oids[_] == "1.3.6.1.4.1.99999.1.3"
}
```

### OPA Result

```go
type OPAResult struct {
    Allow           bool     `json:"allow"`
    AssignedVLAN    uint16   `json:"assigned_vlan,omitempty"`
    Reasons         []string `json:"reasons,omitempty"`
    RequiredActions []string `json:"required_actions,omitempty"`
    EvaluatedAt     time.Time
}
```

## OpenFlow Rule Management

The flow manager installs and removes OpenFlow rules for VLAN isolation:

### Flow Rule Types

| Type | Priority | Purpose |
|------|----------|---------|
| `quarantine` | 200 | Restrict traffic to enrollment services |
| `production` | 300 | Full network access with VLAN tagging |
| `drop` | 100 | Block all traffic |
| `redirect` | 250 | Redirect to captive portal |
| `rate_limit` | 150 | Apply rate limiting |
| `monitor` | 50 | Mirror traffic for monitoring |

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
| `controller` | Send to controller for inspection |
| `flood` | Send to all ports |

## VLAN Transitions

### Transition Flow

1. **Remove existing rules** (if any)
2. **Install new rules** (make-before-break pattern)
3. **Update OVSDB port VLAN tag**
4. **Update state machine**
5. **Audit log transition**

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

- **Grace Period**: Network access continues during re-attestation attempt
- **Failure Count**: Track consecutive failures
- **Automatic Quarantine**: Move to quarantine after `MaxFailures` exceeded

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

## Thread Safety

All operations are thread-safe:

- Atomic state transitions using `sync/atomic`
- Lock-free port state management using `sync.Map`
- Lock-free rule list management using CAS operations

## Related Documentation

- [802.1X Network Attachment](802.1X-network-attachment.md)
- [Compute Architecture](architecture.md)
- [PXE Provisioning](pxe-provisioning.md)
