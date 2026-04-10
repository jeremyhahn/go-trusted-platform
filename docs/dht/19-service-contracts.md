# Service Contracts

This document specifies the ServiceContract system for go-trusted-platform, providing the foundational contract framework for all decentralized services on the platform.

---

## Overview

The ServiceContract system provides a unified framework for establishing, executing, and enforcing agreements between service providers and consumers on the trusted DHT network. ServiceContract is the base contract type from which all specialized service contracts derive.

### Design Principles

1. **TPM-Bound Identity** - All contract parties are identified by NodeIdentity bound to TPM IDevID
2. **Cryptographic Enforcement** - Contracts are TPM-signed by both parties for non-repudiation
3. **Escrow Protection** - Payments held in escrow until service delivery verified
4. **Decentralized Arbitration** - Disputes resolved by VRF-selected arbiter pools
5. **Extensible Hierarchy** - Base contract extended for specific service types

### Service Types

The platform supports multiple service categories, each with specialized contract terms:

| Service Type | Code | Description |
|--------------|------|-------------|
| **Agent** | `1` | AI/ML workloads, model inference, agent collaboration |
| **Compute** | `2` | Cloud hosting, VMs, containers, serverless |
| **Storage** | `3` | File storage, backup, archival, CDN |
| **E-Commerce** | `4` | Storefronts, payment processing, marketplaces |
| **Network** | `5` | Bandwidth, VPN, proxy, relay services |
| **Custom** | `255` | User-defined service types |

---

## Contract Hierarchy

The ServiceContract hierarchy enables specialized terms for each service type while maintaining a consistent base structure:

```
                         SERVICE CONTRACT HIERARCHY

                        +---------------------+
                        |   ServiceContract   |
                        |       (Base)        |
                        +---------+-----------+
                                  |
          +-----------------------+------------------------+
          |           |           |           |            |
          v           v           v           v            v
    +----------+ +----------+ +----------+ +----------+ +----------+
    |  Agent   | | Compute  | | Storage  | |ECommerce | | Network  |
    | Contract | | Contract | | Contract | | Contract | | Contract |
    +----------+ +----------+ +----------+ +----------+ +----------+
         |           |           |           |            |
         v           v           v           v            v
    +----------+ +----------+ +----------+ +----------+ +----------+
    |  Agent   | | Compute  | | Storage  | |ECommerce | | Network  |
    | Service  | | Service  | | Service  | | Service  | | Service  |
    |  Terms   | |  Terms   | |  Terms   | |  Terms   | |  Terms   |
    +----------+ +----------+ +----------+ +----------+ +----------+

    +----------------------------------------------------------------+
    |                      CustomContract                             |
    |                  (User-Defined Terms)                          |
    +----------------------------------------------------------------+
```

### Hierarchy Details

| Contract Type | Parent | Purpose |
|--------------|--------|---------|
| `ServiceContract` | - | Base contract with common fields |
| `AgentContract` | ServiceContract | AI/ML workload agreements |
| `ComputeContract` | ServiceContract | VM/container hosting agreements |
| `StorageContract` | ServiceContract | Data storage and retrieval agreements |
| `ECommerceContract` | ServiceContract | Storefront and payment agreements |
| `NetworkContract` | ServiceContract | Bandwidth and connectivity agreements |
| `CustomContract` | ServiceContract | User-defined service agreements |

---

## ServiceContract Structure

The base ServiceContract contains all fields common to service agreements:

```go
// ServiceType represents the category of service
type ServiceType uint8

const (
    ServiceTypeAgent     ServiceType = 1
    ServiceTypeCompute   ServiceType = 2
    ServiceTypeStorage   ServiceType = 3
    ServiceTypeECommerce ServiceType = 4
    ServiceTypeNetwork   ServiceType = 5
    ServiceTypeCustom    ServiceType = 255
)

// ServiceContract is the base contract type for all decentralized services
type ServiceContract struct {
    // Identity
    ContractID    [32]byte          // Unique contract identifier (SHA256)
    Version       uint8             // Contract version (for upgrades)

    // Parties (TPM-bound identities)
    Provider      NodeIdentity      // Service provider identity
    Consumer      NodeIdentity      // Service consumer identity

    // Service Definition
    ServiceType   ServiceType       // Category of service
    ServiceTerms  ServiceTerms      // Type-specific service parameters
    SLA           SLATerms          // Service level agreement

    // Client Requirements (CANONICAL)
    ClientRequirements *ClientRequirements // Provider-defined eligibility criteria

    // Economics
    PaymentTerms  PaymentTerms      // Payment structure and schedule
    Stake         StakeRequirement  // Provider/consumer stake requirements
    Penalties     PenaltyTerms      // Penalty conditions and amounts

    // Escrow Configuration
    Escrow        EscrowConfig      // Escrow account and conditions

    // Lifecycle
    StartTime     time.Time         // Contract activation time
    Duration      time.Duration     // Contract duration
    RenewalTerms  RenewalConfig     // Auto-renewal configuration

    // Dispute Resolution
    DisputeResolution DisputeConfig // Arbitration configuration

    // Cryptographic Signatures
    Signatures    ContractSignatures // TPM-signed by both parties

    // Metadata
    CreatedAt     time.Time         // Contract creation timestamp
    UpdatedAt     time.Time         // Last modification timestamp
    Status        ContractStatus    // Current contract status
}

// ClientRequirements defines eligibility criteria that consumers must meet
// SECURITY (P4-C4): Exemptions are time-limited, audited, and CANNOT bypass trust checks
type ClientRequirements struct {
    // Trust Requirements - NEVER exemptable
    MinTrustLevel     TrustLevel    // Minimum trust level (Trusted or Untrusted)
    RequireHardwareTPM bool         // Require hardware TPM attestation

    // Reputation Requirements
    MinReputation     float64       // Minimum reputation score (0.0-1.0)
    MaxViolations     uint32        // Maximum violation count allowed
    MinNetworkAge     time.Duration // Minimum time on network

    // Geographic Requirements
    AllowedRegions    []string      // Allowed geographic regions (empty = all)
    BlockedRegions    []string      // Blocked geographic regions

    // Enforcement
    EnforcementLevel  EnforcementLevel // Strict, advisory, or grace period
    GracePeriod       time.Duration    // Grace period for enforcement

    // SECURE Exemption System (P4-C4 FIX)
    // Exemptions are strictly controlled and audited
    Exemptions        *ExemptionConfig // Optional exemption configuration
}

// ExemptionConfig defines secure, auditable exemptions
// SECURITY: Exemptions NEVER bypass trust or TPM requirements
type ExemptionConfig struct {
    // Exemption list with time limits
    Exemptions        []ClientExemption

    // What CAN be exempted (reputation, age, geography only)
    AllowReputationExemption bool
    AllowAgeExemption        bool
    AllowGeographyExemption  bool

    // What can NEVER be exempted (hardcoded for security)
    // - TrustLevel checks
    // - Hardware TPM requirements
    // - Blocked regions (for compliance)

    // Audit requirements
    RequireJustification bool          // Require written reason
    MaxExemptionDuration time.Duration // Maximum exemption validity (default 30 days)
    AuditRetention       time.Duration // How long to keep audit records (default 1 year)
}

// ExemptionEntry represents a single, auditable exemption with specific scope
// SECURITY: Exemptions are granted for specific checks only, time-limited (max 30 days),
// cryptographically signed, and audited. Even with an exemption, consumer identity
// (IDevID validity) and ban status are ALWAYS verified.
type ExemptionEntry struct {
    // Identity
    ExemptionID   [32]byte  // Unique exemption identifier (SHA256)
    NodeID        [32]byte  // Who is exempted (consumer NodeID)

    // Specific Exemptions - MUST enumerate exactly what is exempted
    // SECURITY: Generic "exempt from all" is NOT allowed
    ExemptFrom    []ExemptionScope  // Specific checks being waived

    // Authorization - cryptographically bound to provider
    GrantedBy     [32]byte          // Provider NodeID who granted exemption
    GrantedBySignature []byte       // Provider's IDevID signature over exemption hash
    GrantedAt     time.Time         // When exemption was granted

    // Time Limits - exemptions MUST expire (max 30 days)
    ExpiresAt     time.Time         // REQUIRED - no indefinite exemptions
    MaxDuration   time.Duration     // Enforced maximum: 30 days (720 hours)

    // Audit Trail - required for compliance and dispute resolution
    Reason        string            // Human-readable justification (required)
    AuditTrail    []AuditEntry      // Immutable log of exemption events

    // Revocation
    Revoked           bool
    RevokedAt         *time.Time
    RevokedBy         *[32]byte
    RevocationReason  string
}

// ExemptionScope defines what specific check is being exempted
// SECURITY: Only reputation, age, and geography CAN be exempted
// Trust level, hardware TPM, banned status, and IDevID validity CANNOT be exempted
type ExemptionScope string

const (
    // Exemptable scopes (controlled by ExemptionConfig flags)
    ExemptionScopeReputation   ExemptionScope = "reputation"     // MinReputation check
    ExemptionScopeNetworkAge   ExemptionScope = "network_age"    // MinNetworkAge check
    ExemptionScopeAllowedRegion ExemptionScope = "allowed_region" // AllowedRegions check

    // NON-EXEMPTABLE (hardcoded security checks - listed for documentation)
    // ExemptionScopeTrustLevel    - NEVER exemptable
    // ExemptionScopeHardwareTPM   - NEVER exemptable
    // ExemptionScopeBlockedRegion - NEVER exemptable (compliance)
    // ExemptionScopeBanStatus     - NEVER exemptable
    // ExemptionScopeIDevIDValidity - NEVER exemptable
)

// AuditEntry records an event in the exemption audit trail
type AuditEntry struct {
    Timestamp   time.Time
    Action      string    // "granted", "used", "renewed", "revoked", "expired"
    Actor       [32]byte  // NodeID of actor
    Details     string    // Additional context
    Signature   []byte    // Signature over entry hash
}

// MaxExemptionDuration is the absolute maximum duration for any exemption
// SECURITY: Exemptions cannot exceed 30 days to ensure regular review
const MaxExemptionDuration = 30 * 24 * time.Hour // 30 days

// ValidateExemption verifies an exemption is valid and properly signed
// SECURITY: Called before granting access based on exemption
func ValidateExemption(
    entry *ExemptionEntry,
    providerCert *x509.Certificate,
    now time.Time,
) error {
    // Step 1: Check expiration
    if now.After(entry.ExpiresAt) {
        return &ErrExemptionExpired{
            ExemptionID: entry.ExemptionID,
            ExpiredAt:   entry.ExpiresAt,
        }
    }

    // Step 2: Check revocation
    if entry.Revoked {
        return &ErrExemptionRevoked{
            ExemptionID: entry.ExemptionID,
            RevokedAt:   *entry.RevokedAt,
            Reason:      entry.RevocationReason,
        }
    }

    // Step 3: Verify duration doesn't exceed maximum
    if entry.ExpiresAt.Sub(entry.GrantedAt) > MaxExemptionDuration {
        return &ErrExemptionDurationExceeded{
            ExemptionID: entry.ExemptionID,
            Duration:    entry.ExpiresAt.Sub(entry.GrantedAt),
            MaxDuration: MaxExemptionDuration,
        }
    }

    // Step 4: Verify only allowed scopes are exempted
    for _, scope := range entry.ExemptFrom {
        if !isExemptableScope(scope) {
            return &ErrNonExemptableScope{
                ExemptionID: entry.ExemptionID,
                Scope:       scope,
            }
        }
    }

    // Step 5: Verify provider signature
    exemptionHash := computeExemptionHash(entry)
    if err := verifyTPMSignature(providerCert.PublicKey, exemptionHash[:], entry.GrantedBySignature); err != nil {
        return &ErrExemptionSignatureInvalid{
            ExemptionID: entry.ExemptionID,
            Cause:       err,
        }
    }

    // Step 6: Verify reason is provided
    if len(entry.Reason) == 0 {
        return &ErrExemptionMissingReason{
            ExemptionID: entry.ExemptionID,
        }
    }

    return nil
}

// isExemptableScope returns true if the scope can be exempted
func isExemptableScope(scope ExemptionScope) bool {
    switch scope {
    case ExemptionScopeReputation, ExemptionScopeNetworkAge, ExemptionScopeAllowedRegion:
        return true
    default:
        return false
    }
}

// computeExemptionHash creates canonical hash for signature verification
func computeExemptionHash(entry *ExemptionEntry) [32]byte {
    h := sha256.New()
    h.Write(entry.ExemptionID[:])
    h.Write(entry.NodeID[:])
    for _, scope := range entry.ExemptFrom {
        h.Write([]byte(scope))
    }
    h.Write(entry.GrantedBy[:])
    binary.Write(h, binary.BigEndian, entry.GrantedAt.UnixNano())
    binary.Write(h, binary.BigEndian, entry.ExpiresAt.UnixNano())
    h.Write([]byte(entry.Reason))
    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}

// Exemption validation error types
type ErrExemptionExpired struct {
    ExemptionID [32]byte
    ExpiredAt   time.Time
}
func (e *ErrExemptionExpired) Error() string {
    return fmt.Sprintf("exemption %x expired at %v", e.ExemptionID[:8], e.ExpiredAt)
}

type ErrExemptionRevoked struct {
    ExemptionID [32]byte
    RevokedAt   time.Time
    Reason      string
}
func (e *ErrExemptionRevoked) Error() string {
    return fmt.Sprintf("exemption %x revoked at %v: %s", e.ExemptionID[:8], e.RevokedAt, e.Reason)
}

type ErrExemptionDurationExceeded struct {
    ExemptionID [32]byte
    Duration    time.Duration
    MaxDuration time.Duration
}
func (e *ErrExemptionDurationExceeded) Error() string {
    return fmt.Sprintf("exemption %x duration %v exceeds maximum %v", e.ExemptionID[:8], e.Duration, e.MaxDuration)
}

type ErrNonExemptableScope struct {
    ExemptionID [32]byte
    Scope       ExemptionScope
}
func (e *ErrNonExemptableScope) Error() string {
    return fmt.Sprintf("exemption %x contains non-exemptable scope: %s", e.ExemptionID[:8], e.Scope)
}

type ErrExemptionSignatureInvalid struct {
    ExemptionID [32]byte
    Cause       error
}
func (e *ErrExemptionSignatureInvalid) Error() string {
    return fmt.Sprintf("exemption %x signature invalid: %v", e.ExemptionID[:8], e.Cause)
}

type ErrExemptionMissingReason struct {
    ExemptionID [32]byte
}
func (e *ErrExemptionMissingReason) Error() string {
    return fmt.Sprintf("exemption %x missing required reason", e.ExemptionID[:8])
}

// CleanupExpiredExemptions removes expired exemptions from the exemption list
// SECURITY: Should be called periodically to maintain exemption hygiene
func CleanupExpiredExemptions(exemptions []ExemptionEntry, now time.Time) []ExemptionEntry {
    valid := make([]ExemptionEntry, 0, len(exemptions))
    for _, ex := range exemptions {
        if now.Before(ex.ExpiresAt) && !ex.Revoked {
            valid = append(valid, ex)
        }
        // Expired/revoked exemptions are logged to audit trail before removal
    }
    return valid
}

// Legacy alias for backward compatibility
type ClientExemption = ExemptionEntry

### Cryptographically Signed Requirements (P4-M7 Fix)

**Problem**: ClientRequirements hash is computed but NOT signed by the provider.
An attacker could modify requirements after contract creation, changing eligibility
criteria to exclude legitimate clients or include malicious ones.

**Solution**: Sign the requirements hash with provider's IDevID key, binding
requirements immutably to the contract.

```go
// SignedClientRequirements wraps requirements with cryptographic binding
// SECURITY: Requirements MUST be signed to prevent tampering
type SignedClientRequirements struct {
    // The actual requirements
    Requirements *ClientRequirements

    // Cryptographic binding
    RequirementsHash  [32]byte     // SHA256 of serialized requirements
    ProviderNodeID    [32]byte     // Provider who defined requirements
    Signature         []byte       // Provider's IDevID signature over hash
    SignedAt          time.Time    // When signature was created

    // Contract binding
    ContractID        [32]byte     // Contract these requirements belong to
    Version           uint32       // Version number for updates
}

// ComputeRequirementsHash creates canonical hash of requirements
// SECURITY: Uses deterministic serialization to ensure consistent hashing
func ComputeRequirementsHash(req *ClientRequirements) ([32]byte, error) {
    // Serialize in deterministic order
    serialized, err := req.canonicalSerialize()
    if err != nil {
        return [32]byte{}, fmt.Errorf("failed to serialize requirements: %w", err)
    }

    return sha256.Sum256(serialized), nil
}

// canonicalSerialize creates deterministic byte representation
// IMPORTANT: Field order MUST be stable for hash consistency
func (r *ClientRequirements) canonicalSerialize() ([]byte, error) {
    buf := new(bytes.Buffer)

    // Write fields in fixed order
    // Trust requirements (2 bytes)
    binary.Write(buf, binary.BigEndian, uint8(r.MinTrustLevel))
    if r.RequireHardwareTPM {
        buf.WriteByte(1)
    } else {
        buf.WriteByte(0)
    }

    // Reputation requirements
    binary.Write(buf, binary.BigEndian, math.Float64bits(r.MinReputation))
    binary.Write(buf, binary.BigEndian, r.MaxViolations)
    binary.Write(buf, binary.BigEndian, r.MinNetworkAge.Nanoseconds())

    // Geographic requirements (sorted for determinism)
    writeStringSlice(buf, sortedCopy(r.AllowedRegions))
    writeStringSlice(buf, sortedCopy(r.BlockedRegions))

    // Enforcement
    binary.Write(buf, binary.BigEndian, uint8(r.EnforcementLevel))
    binary.Write(buf, binary.BigEndian, r.GracePeriod.Nanoseconds())

    // Exemption config (if present)
    if r.Exemptions != nil {
        buf.WriteByte(1) // Has exemptions
        r.Exemptions.canonicalSerialize(buf)
    } else {
        buf.WriteByte(0) // No exemptions
    }

    return buf.Bytes(), nil
}

// SignRequirements creates a signed requirements object
// SECURITY: Must be called by provider using their IDevID key
func SignRequirements(
    ctx context.Context,
    req *ClientRequirements,
    contractID [32]byte,
    providerNodeID [32]byte,
    tpm TPMInterface,
    idevid *IDevIDKey,
) (*SignedClientRequirements, error) {

    // Step 1: Compute canonical hash
    hash, err := ComputeRequirementsHash(req)
    if err != nil {
        return nil, fmt.Errorf("failed to compute requirements hash: %w", err)
    }

    // Step 2: Create signature payload
    // Includes contract binding to prevent cross-contract replay
    payload := make([]byte, 0, 32+32+8) // hash + contractID + timestamp
    payload = append(payload, hash[:]...)
    payload = append(payload, contractID[:]...)
    timestamp := time.Now().UnixNano()
    payload = binary.BigEndian.AppendUint64(payload, uint64(timestamp))

    // Step 3: Sign with IDevID key via TPM
    signature, err := tpm.Sign(ctx, idevid.Handle(), payload)
    if err != nil {
        return nil, fmt.Errorf("failed to sign requirements: %w", err)
    }

    return &SignedClientRequirements{
        Requirements:     req,
        RequirementsHash: hash,
        ProviderNodeID:   providerNodeID,
        Signature:        signature,
        SignedAt:         time.Unix(0, timestamp),
        ContractID:       contractID,
        Version:          1,
    }, nil
}

// VerifyRequirementsSignature validates the signed requirements
// SECURITY: MUST be called before accepting any requirements
func VerifyRequirementsSignature(
    signed *SignedClientRequirements,
    providerCert *x509.Certificate,
) error {
    // Step 1: Verify certificate belongs to claimed provider
    certNodeID := ExtractNodeID(providerCert)
    if certNodeID != signed.ProviderNodeID {
        return &ErrRequirementsVerificationFailed{
            Reason: "certificate does not match provider",
        }
    }

    // Step 2: Recompute requirements hash
    computedHash, err := ComputeRequirementsHash(signed.Requirements)
    if err != nil {
        return &ErrRequirementsVerificationFailed{
            Reason: fmt.Sprintf("failed to compute hash: %v", err),
        }
    }

    // Step 3: Verify hash matches
    if computedHash != signed.RequirementsHash {
        return &ErrRequirementsVerificationFailed{
            Reason: "requirements hash mismatch - possible tampering",
        }
    }

    // Step 4: Reconstruct signature payload
    payload := make([]byte, 0, 32+32+8)
    payload = append(payload, signed.RequirementsHash[:]...)
    payload = append(payload, signed.ContractID[:]...)
    payload = binary.BigEndian.AppendUint64(payload, uint64(signed.SignedAt.UnixNano()))

    // Step 5: Verify signature
    if err := verifyTPMSignature(providerCert.PublicKey, payload, signed.Signature); err != nil {
        return &ErrRequirementsVerificationFailed{
            Reason: fmt.Sprintf("signature verification failed: %v", err),
        }
    }

    return nil
}

// UpdateRequirements creates a new version with updated requirements
// SECURITY: Old version must be kept for audit trail
func (signed *SignedClientRequirements) Update(
    ctx context.Context,
    newReq *ClientRequirements,
    tpm TPMInterface,
    idevid *IDevIDKey,
) (*SignedClientRequirements, error) {

    // Create new signed version
    updated, err := SignRequirements(ctx, newReq, signed.ContractID, signed.ProviderNodeID, tpm, idevid)
    if err != nil {
        return nil, err
    }

    // Increment version
    updated.Version = signed.Version + 1

    return updated, nil
}

// Requirements verification errors
type ErrRequirementsVerificationFailed struct {
    Reason string
}

func (e *ErrRequirementsVerificationFailed) Error() string {
    return fmt.Sprintf("requirements verification failed: %s", e.Reason)
}

// Helper functions for canonical serialization
func writeStringSlice(buf *bytes.Buffer, strings []string) {
    binary.Write(buf, binary.BigEndian, uint32(len(strings)))
    for _, s := range strings {
        binary.Write(buf, binary.BigEndian, uint32(len(s)))
        buf.WriteString(s)
    }
}

func sortedCopy(strings []string) []string {
    if len(strings) == 0 {
        return nil
    }
    sorted := make([]string, len(strings))
    copy(sorted, strings)
    sort.Strings(sorted)
    return sorted
}
```

### Requirements Integrity in Contract Lifecycle

| Stage | Requirement Integrity Check |
|-------|----------------------------|
| **Creation** | Provider signs requirements with IDevID |
| **Discovery** | Consumer verifies signature before negotiation |
| **Agreement** | Both parties confirm same requirements hash |
| **Execution** | Eligibility checks use verified requirements |
| **Dispute** | Arbiter can verify original signed requirements |
| **Audit** | Full history of signed requirement versions |

// VerifyClientEligibility checks if client meets requirements
// SECURITY (P4-C4): Even with exemptions, ALWAYS check:
// 1. Consumer identity (IDevID certificate valid and not expired)
// 2. Consumer ban status (not on network ban list)
// 3. Trust level and TPM requirements (NEVER exemptable)
func VerifyClientEligibility(
    client *NodeIdentity,
    requirements *ClientRequirements,
    signedReq *SignedClientRequirements, // REQUIRED: Signed requirements for integrity
) (*EligibilityResult, error) {
    result := &EligibilityResult{
        ClientID:  client.NodeID,
        CheckedAt: time.Now(),
    }

    // ==========================================================================
    // PHASE 1: NON-EXEMPTABLE SECURITY CHECKS
    // These checks run FIRST and can NEVER be bypassed by any exemption
    // ==========================================================================

    // Step 1.1: Verify requirements signature before applying any checks
    // SECURITY: Prevents tampering with eligibility criteria
    if signedReq != nil {
        providerCert, err := FetchProviderCertificate(signedReq.ProviderNodeID)
        if err != nil {
            return nil, &ErrRequirementsVerificationFailed{Reason: "failed to fetch provider certificate"}
        }
        if err := VerifyRequirementsSignature(signedReq, providerCert); err != nil {
            result.Eligible = false
            result.FailedChecks = append(result.FailedChecks, "requirements_signature")
            result.Message = "Requirements signature verification failed - possible tampering"
            return result, nil
        }
    }

    // Step 1.2: ALWAYS verify consumer IDevID certificate validity
    // SECURITY: This check can NEVER be exempted
    if err := VerifyIDevIDValidity(client); err != nil {
        result.Eligible = false
        result.FailedChecks = append(result.FailedChecks, "idevid_validity")
        result.Message = fmt.Sprintf("Consumer IDevID certificate invalid: %v", err)
        return result, nil
    }

    // Step 1.3: ALWAYS check consumer ban status
    // SECURITY: This check can NEVER be exempted
    if IsBanned(client.NodeID) {
        result.Eligible = false
        result.FailedChecks = append(result.FailedChecks, "ban_status")
        result.Message = "Consumer is banned from the network"
        return result, nil
    }

    // Step 1.4: Trust level check - NEVER exemptable
    if requirements.MinTrustLevel == TrustLevelTrusted && client.TrustLevel != TrustLevelTrusted {
        result.Eligible = false
        result.FailedChecks = append(result.FailedChecks, "trust_level")
        result.Message = "Service requires trusted (hardware TPM) nodes"
        return result, nil
    }

    // Step 1.5: Hardware TPM requirement - NEVER exemptable
    if requirements.RequireHardwareTPM && client.TrustLevel != TrustLevelTrusted {
        result.Eligible = false
        result.FailedChecks = append(result.FailedChecks, "hardware_tpm")
        result.Message = "Service requires hardware TPM attestation"
        return result, nil
    }

    // Step 1.6: Blocked regions check - NEVER exempted (compliance requirement)
    if len(requirements.BlockedRegions) > 0 && contains(requirements.BlockedRegions, client.Region) {
        result.Eligible = false
        result.FailedChecks = append(result.FailedChecks, "blocked_region")
        result.Message = "Client in blocked geographic region"
        return result, nil
    }

    // ==========================================================================
    // PHASE 2: EXEMPTABLE CHECKS
    // These checks can be bypassed with valid, signed, non-expired exemptions
    // ==========================================================================

    // Find valid exemption (only for exemptable requirements)
    var activeExemption *ExemptionEntry
    if requirements.Exemptions != nil {
        activeExemption = findValidExemption(client.NodeID, requirements.Exemptions)
    }

    // Helper to check if specific scope is exempted
    hasExemption := func(scope ExemptionScope) bool {
        if activeExemption == nil {
            return false
        }
        for _, s := range activeExemption.ExemptFrom {
            if s == scope {
                return true
            }
        }
        return false
    }

    // Reputation check (can be exempted if configured)
    if client.Reputation < requirements.MinReputation {
        if hasExemption(ExemptionScopeReputation) && requirements.Exemptions.AllowReputationExemption {
            result.ExemptedChecks = append(result.ExemptedChecks, "reputation")
            logExemptionUsage(activeExemption, "reputation")
        } else {
            result.Eligible = false
            result.FailedChecks = append(result.FailedChecks, "reputation")
            return result, nil
        }
    }

    // Network age check (can be exempted if configured)
    if time.Since(client.JoinedAt) < requirements.MinNetworkAge {
        if hasExemption(ExemptionScopeNetworkAge) && requirements.Exemptions.AllowAgeExemption {
            result.ExemptedChecks = append(result.ExemptedChecks, "network_age")
            logExemptionUsage(activeExemption, "network_age")
        } else {
            result.Eligible = false
            result.FailedChecks = append(result.FailedChecks, "network_age")
            return result, nil
        }
    }

    // Allowed regions check (can be exempted if configured)
    if len(requirements.AllowedRegions) > 0 && !contains(requirements.AllowedRegions, client.Region) {
        if hasExemption(ExemptionScopeAllowedRegion) && requirements.Exemptions.AllowGeographyExemption {
            result.ExemptedChecks = append(result.ExemptedChecks, "allowed_region")
            logExemptionUsage(activeExemption, "allowed_region")
        } else {
            result.Eligible = false
            result.FailedChecks = append(result.FailedChecks, "allowed_region")
            return result, nil
        }
    }

    result.Eligible = true
    return result, nil
}

// VerifyIDevIDValidity checks that consumer's IDevID certificate is valid
// SECURITY: This check can NEVER be exempted
func VerifyIDevIDValidity(client *NodeIdentity) error {
    // Fetch the IDevID certificate
    cert, err := FetchIDevIDCertificate(client.IDevIDCertHash)
    if err != nil {
        return &ErrIDevIDNotFound{Hash: client.IDevIDCertHash}
    }

    // Check certificate not expired
    now := time.Now()
    if now.After(cert.NotAfter) {
        return &ErrIDevIDExpired{
            NodeID:    client.NodeID,
            ExpiredAt: cert.NotAfter,
        }
    }

    // Check certificate not yet valid
    if now.Before(cert.NotBefore) {
        return &ErrIDevIDNotYetValid{
            NodeID:  client.NodeID,
            ValidAt: cert.NotBefore,
        }
    }

    // Verify certificate chain to trusted CA
    if err := VerifyCertificateChain(cert, client.CAPoolID); err != nil {
        return &ErrCertificateChainInvalid{Cause: err}
    }

    // Check certificate not revoked
    if IsCertificateRevoked(cert.SerialNumber) {
        return &ErrIDevIDRevoked{
            NodeID:       client.NodeID,
            SerialNumber: cert.SerialNumber.String(),
        }
    }

    return nil
}

// IsBanned checks if a node is on the network ban list
// SECURITY: This check can NEVER be exempted
func IsBanned(nodeID [32]byte) bool {
    // Check global ban list (DHT lookup)
    banEntry, err := LookupBanList(nodeID)
    if err != nil {
        // On error, fail open with warning (configurable)
        log.Warn("ban list lookup failed", "nodeID", nodeID, "error", err)
        return false
    }

    if banEntry != nil && banEntry.Active && time.Now().Before(banEntry.ExpiresAt) {
        return true
    }

    return false
}

// BanListEntry represents an entry in the network ban list
type BanListEntry struct {
    NodeID    [32]byte
    Reason    string
    BannedBy  [32]byte      // Authority that issued ban
    BannedAt  time.Time
    ExpiresAt time.Time     // Bans can be temporary
    Active    bool
    Signature []byte        // Signed by network authority
}

// IDevID validity error types
type ErrIDevIDExpired struct {
    NodeID    [32]byte
    ExpiredAt time.Time
}
func (e *ErrIDevIDExpired) Error() string {
    return fmt.Sprintf("IDevID certificate for node %x expired at %v", e.NodeID[:8], e.ExpiredAt)
}

type ErrIDevIDNotYetValid struct {
    NodeID  [32]byte
    ValidAt time.Time
}
func (e *ErrIDevIDNotYetValid) Error() string {
    return fmt.Sprintf("IDevID certificate for node %x not yet valid until %v", e.NodeID[:8], e.ValidAt)
}

type ErrIDevIDRevoked struct {
    NodeID       [32]byte
    SerialNumber string
}
func (e *ErrIDevIDRevoked) Error() string {
    return fmt.Sprintf("IDevID certificate for node %x (serial: %s) has been revoked", e.NodeID[:8], e.SerialNumber)
}

// findValidExemption returns a valid, non-expired, signed exemption for the client
// SECURITY: Validates signature and expiration before returning
func findValidExemption(clientID [32]byte, config *ExemptionConfig) *ExemptionEntry {
    now := time.Now()
    for i := range config.Exemptions {
        ex := &config.Exemptions[i]

        // Check client match
        if ex.NodeID != clientID {
            continue
        }

        // Check not revoked
        if ex.Revoked {
            continue
        }

        // Check time bounds
        if now.After(ex.ExpiresAt) {
            // Mark for cleanup - expired exemptions should be deleted
            scheduleExemptionCleanup(ex.ExemptionID)
            continue
        }
        if now.Before(ex.GrantedAt) {
            continue
        }

        // Check duration doesn't exceed maximum (30 days)
        if ex.ExpiresAt.Sub(ex.GrantedAt) > MaxExemptionDuration {
            log.Warn("exemption exceeds max duration, invalidating",
                "exemptionID", ex.ExemptionID,
                "duration", ex.ExpiresAt.Sub(ex.GrantedAt),
                "max", MaxExemptionDuration)
            continue
        }

        // Verify provider's IDevID signature over exemption
        if !verifyExemptionSignature(ex) {
            log.Warn("exemption signature verification failed",
                "exemptionID", ex.ExemptionID,
                "grantedBy", ex.GrantedBy)
            continue
        }

        // Record exemption usage in audit trail
        recordExemptionAccess(ex, now)

        return ex
    }
    return nil
}

// scheduleExemptionCleanup queues an expired exemption for deletion
// SECURITY: Expired exemptions must be cleaned up to prevent accumulation
func scheduleExemptionCleanup(exemptionID [32]byte) {
    // Queue for async cleanup - exemption records are archived before deletion
    exemptionCleanupQueue.Enqueue(exemptionID)
}

// recordExemptionAccess adds an entry to the exemption audit trail
func recordExemptionAccess(ex *ExemptionEntry, accessTime time.Time) {
    entry := AuditEntry{
        Timestamp: accessTime,
        Action:    "used",
        Actor:     ex.NodeID,
        Details:   fmt.Sprintf("exemption used for scopes: %v", ex.ExemptFrom),
    }
    ex.AuditTrail = append(ex.AuditTrail, entry)
}

// EligibilityResult contains the result of eligibility verification
type EligibilityResult struct {
    ClientID       [32]byte
    Eligible       bool
    CheckedAt      time.Time
    FailedChecks   []string  // Which checks failed
    ExemptedChecks []string  // Which checks were exempted (for audit)
    Message        string    // Human-readable explanation
}

// EnforcementLevel defines how requirement violations are handled
type EnforcementLevel uint8

const (
    EnforcementAdvisory    EnforcementLevel = 0 // Show warnings but allow access
    EnforcementStrict      EnforcementLevel = 1 // Block access if requirements not met
    EnforcementGracePeriod EnforcementLevel = 2 // Allow temporary access with grace period
)

// =============================================================================
// GEOGRAPHIC VERIFICATION (P4-H5 FIX)
// =============================================================================
// PROBLEM: Using IP geolocation for region determination is trivially spoofable
// via VPN, proxy, or Tor. This allows bypassing geographic restrictions.
//
// SOLUTION: Require TPM-attested location proof where available, with
// IP geolocation as fallback (marked with reduced confidence).

// RegionVerificationMethod defines how region was determined
type RegionVerificationMethod uint8

const (
    RegionMethodUnknown      RegionVerificationMethod = 0
    RegionMethodIPGeoLookup  RegionVerificationMethod = 1 // Spoofable - low confidence
    RegionMethodTPMLocation  RegionVerificationMethod = 2 // Hardware attested - high confidence
    RegionMethodSIMCarrier   RegionVerificationMethod = 3 // Mobile carrier - medium confidence
    RegionMethodLegalEntity  RegionVerificationMethod = 4 // Verified business registration
)

// ClientRegionProof contains verified region information
type ClientRegionProof struct {
    Region              string                    // ISO 3166-1 alpha-2 country code
    Subregion           string                    // ISO 3166-2 subdivision (optional)
    Method              RegionVerificationMethod
    Confidence          float64                   // 0.0-1.0 confidence in region
    ProofData           []byte                    // Method-specific proof
    VerifiedAt          time.Time
    ValidUntil          time.Time                 // Location proofs expire

    // TPM-specific fields (when Method == RegionMethodTPMLocation)
    TPMQuote            []byte                    // TPM quote including location claim
    LocationCertificate *x509.Certificate         // Certificate from location CA
}

// VerifyClientRegion determines client region with confidence level
// SECURITY (P4-H5): IP-only verification is marked as LOW confidence
func VerifyClientRegion(client *NodeIdentity, requiredConfidence float64) (*ClientRegionProof, error) {
    // Try TPM-attested location first (highest confidence)
    if client.HasTPMLocationCapability {
        proof, err := requestTPMLocationAttestation(client.NodeID)
        if err == nil && proof.Confidence >= requiredConfidence {
            return proof, nil
        }
    }

    // Fallback to IP geolocation (LOW confidence)
    region, err := geoIPLookup(client.LastKnownIP)
    if err != nil {
        return nil, ErrRegionVerificationFailed{Cause: err}
    }

    proof := &ClientRegionProof{
        Region:     region.CountryCode,
        Subregion:  region.SubdivisionCode,
        Method:     RegionMethodIPGeoLookup,
        Confidence: 0.3, // LOW - IP is easily spoofable
        VerifiedAt: time.Now(),
        ValidUntil: time.Now().Add(1 * time.Hour), // Short validity
    }

    // Check if confidence meets requirement
    if proof.Confidence < requiredConfidence {
        return proof, ErrInsufficientRegionConfidence{
            Required: requiredConfidence,
            Actual:   proof.Confidence,
            Method:   proof.Method,
        }
    }

    return proof, nil
}

// GeographicPolicyConfig configures geographic enforcement
type GeographicPolicyConfig struct {
    // Confidence requirements by restriction type
    BlockedRegionMinConfidence  float64 // Min confidence to enforce blocks (default: 0.3)
    AllowedRegionMinConfidence  float64 // Min confidence to verify allowed (default: 0.7)

    // High-value contracts require higher confidence
    HighValueThreshold          uint64  // Contract value threshold
    HighValueMinConfidence      float64 // Required confidence for high-value (default: 0.9)

    // Enforcement behavior
    RejectOnVerificationFailure bool    // Reject if region cannot be verified
    RequireTPMForHighValue      bool    // Require TPM location for high-value contracts
}

// Error types for geographic verification
type ErrRegionVerificationFailed struct {
    Cause error
}
func (e ErrRegionVerificationFailed) Error() string {
    return fmt.Sprintf("region verification failed: %v", e.Cause)
}

type ErrInsufficientRegionConfidence struct {
    Required float64
    Actual   float64
    Method   RegionVerificationMethod
}
func (e ErrInsufficientRegionConfidence) Error() string {
    return fmt.Sprintf("region confidence too low: required %.2f, got %.2f (method: %d)",
        e.Required, e.Actual, e.Method)
}

// =============================================================================
// GRACE PERIOD ENFORCEMENT (P4-H6 FIX)
// =============================================================================
// PROBLEM: Grace period allows indefinite noncompliance if not properly tracked.
// Clients can remain out-of-compliance forever if no enforcement action taken.
//
// SOLUTION: Track grace period state explicitly, mark RequirementsMet=false,
// and trigger enforcement action when grace expires.

// GracePeriodState tracks clients in grace period
// SECURITY: RequirementsMet is ALWAYS false during grace period
// Enforcement runs every 5 minutes to detect expired grace periods
type GracePeriodState struct {
    ClientID          [32]byte
    ContractID        [32]byte

    // Grace period timing
    EnteredAt         time.Time
    ExpiresAt         time.Time         // HARD deadline - no extensions without explicit action
    GraceDuration     time.Duration

    // Compliance status
    // CRITICAL: RequirementsMet=false is set when entering grace and
    // CANNOT be changed until compliance is restored or service terminated
    RequirementsMet   bool              // ALWAYS false during grace
    FailedChecks      []string          // Which checks triggered grace
    ComplianceStatus  ComplianceStatus
    LastCheckedAt     time.Time         // Last compliance check timestamp

    // Notifications with retry logic
    NotifiedAt        []time.Time       // When warnings were sent
    NotificationRetries map[time.Time]int // Retry count per notification
    LastNotifyError   error             // Last notification error (for diagnostics)
    EscalationCount   int               // Number of escalations

    // Enforcement tracking (for retry logic and rollback)
    EnforcementAttempts  int            // Number of enforcement attempts
    EnforcementFailures  []*EnforcementFailure // History of failed enforcements

    // Resolution
    ResolvedAt        *time.Time
    Resolution        GraceResolution
}

// ComplianceStatus indicates current compliance state
type ComplianceStatus uint8

const (
    ComplianceFullyMet      ComplianceStatus = 0 // All requirements met
    ComplianceInGrace       ComplianceStatus = 1 // Temporarily out of compliance
    ComplianceExpired       ComplianceStatus = 2 // Grace period expired, pending action
    ComplianceEnforced      ComplianceStatus = 3 // Access revoked
)

// GraceResolution defines how grace period ended
type GraceResolution string

const (
    GraceResolutionComplied   GraceResolution = "complied"   // Client became compliant
    GraceResolutionExpired    GraceResolution = "expired"    // Grace expired, access revoked
    GraceResolutionExempted   GraceResolution = "exempted"   // Exemption granted
    GraceResolutionCancelled  GraceResolution = "cancelled"  // Contract cancelled
)

// GracePeriodManager tracks all active grace periods
type GracePeriodManager struct {
    activeGrace  map[[32]byte]*GracePeriodState // keyed by ClientID+ContractID hash
    mu           sync.RWMutex
    config       *GracePeriodConfig
    stopChan     chan struct{}     // SECURITY FIX (P5-H10): For stopping background worker
    wg           sync.WaitGroup    // For graceful shutdown
}

type GracePeriodConfig struct {
    DefaultDuration        time.Duration // Default grace period (e.g., 7 days)
    MaxDuration            time.Duration // Maximum grace period (e.g., 30 days)
    NotificationIntervals  []time.Duration // When to send reminders
    AutoEnforceOnExpiry    bool            // Automatically revoke on expiry
    EnforcementCheckInterval time.Duration // SECURITY FIX (P5-H10): How often to check (default 5m)
}

// SECURITY FIX (P5-H10): Default enforcement interval
const DefaultEnforcementCheckInterval = 5 * time.Minute

// NewGracePeriodManager creates a new manager and starts background enforcement
// SECURITY FIX (P5-H10): Scheduled enforcement to prevent gaps
func NewGracePeriodManager(config *GracePeriodConfig) *GracePeriodManager {
    if config.EnforcementCheckInterval == 0 {
        config.EnforcementCheckInterval = DefaultEnforcementCheckInterval
    }

    gpm := &GracePeriodManager{
        activeGrace: make(map[[32]byte]*GracePeriodState),
        config:      config,
        stopChan:    make(chan struct{}),
    }

    // Start background enforcement worker
    gpm.wg.Add(1)
    go gpm.enforcementWorker()

    return gpm
}

// enforcementWorker runs periodic grace period enforcement checks
// SECURITY FIX (P5-H10): Ensures expired grace periods are enforced
func (gpm *GracePeriodManager) enforcementWorker() {
    defer gpm.wg.Done()

    ticker := time.NewTicker(gpm.config.EnforcementCheckInterval)
    defer ticker.Stop()

    log.Info("grace period enforcement worker started",
        "interval", gpm.config.EnforcementCheckInterval)

    for {
        select {
        case <-gpm.stopChan:
            log.Info("grace period enforcement worker stopped")
            return

        case <-ticker.C:
            // Run enforcement check
            expired := gpm.countExpiredGracePeriods()
            if expired > 0 {
                log.Info("running grace period enforcement",
                    "expiredCount", expired)
            }
            gpm.CheckGraceExpiry()
        }
    }
}

// countExpiredGracePeriods returns count of grace periods that have expired
func (gpm *GracePeriodManager) countExpiredGracePeriods() int {
    gpm.mu.RLock()
    defer gpm.mu.RUnlock()

    count := 0
    now := time.Now()
    for _, state := range gpm.activeGrace {
        if now.After(state.ExpiresAt) && state.ComplianceStatus == ComplianceInGrace {
            count++
        }
    }
    return count
}

// Stop gracefully shuts down the enforcement worker
func (gpm *GracePeriodManager) Stop() {
    close(gpm.stopChan)
    gpm.wg.Wait()
}

// EnterGracePeriod puts a client into grace period
// CRITICAL (P4-H6): Sets RequirementsMet=false and schedules enforcement
func (gpm *GracePeriodManager) EnterGracePeriod(
    clientID, contractID [32]byte,
    failedChecks []string,
    graceDuration time.Duration,
) (*GracePeriodState, error) {
    gpm.mu.Lock()
    defer gpm.mu.Unlock()

    // Enforce maximum duration
    if graceDuration > gpm.config.MaxDuration {
        graceDuration = gpm.config.MaxDuration
    }

    key := hashClientContract(clientID, contractID)
    now := time.Now()

    state := &GracePeriodState{
        ClientID:        clientID,
        ContractID:      contractID,
        EnteredAt:       now,
        ExpiresAt:       now.Add(graceDuration),
        GraceDuration:   graceDuration,
        RequirementsMet: false, // CRITICAL: Always false during grace
        FailedChecks:    failedChecks,
        ComplianceStatus: ComplianceInGrace,
        NotifiedAt:      []time.Time{now}, // Initial notification
    }

    gpm.activeGrace[key] = state

    // Schedule notifications
    for _, interval := range gpm.config.NotificationIntervals {
        scheduleNotification(state, now.Add(graceDuration-interval))
    }

    // Schedule enforcement check
    scheduleEnforcementCheck(state)

    // Store in DHT for persistence
    storeGraceState(state)

    return state, nil
}

// CheckGraceExpiry processes expired grace periods
// SECURITY FIX (P5-H6): Added retry logic with rollback on persistent failure
func (gpm *GracePeriodManager) CheckGraceExpiry() {
    gpm.mu.Lock()
    defer gpm.mu.Unlock()

    now := time.Now()

    for key, state := range gpm.activeGrace {
        if now.After(state.ExpiresAt) && state.ComplianceStatus == ComplianceInGrace {
            // Grace expired - attempt enforcement with retry
            gpm.enforceExpiredGrace(key, state, now)
        }
    }
}

// SECURITY FIX (P5-H6): Retry logic for enforcement with rollback
const (
    MaxEnforcementRetries = 3
    EnforcementRetryDelay = 5 * time.Second
)

func (gpm *GracePeriodManager) enforceExpiredGrace(
    key [32]byte,
    state *GracePeriodState,
    now time.Time,
) {
    // Track retry attempts
    state.EnforcementAttempts++

    // Mark as expired first (transitional state)
    state.ComplianceStatus = ComplianceExpired

    if !gpm.config.AutoEnforceOnExpiry {
        storeGraceState(state)
        return
    }

    // Attempt revocation with retries
    var lastErr error
    for attempt := 1; attempt <= MaxEnforcementRetries; attempt++ {
        if err := revokeContractAccess(state.ClientID, state.ContractID); err != nil {
            lastErr = err
            log.Warn("enforcement attempt failed",
                "attempt", attempt,
                "max", MaxEnforcementRetries,
                "error", err)

            if attempt < MaxEnforcementRetries {
                time.Sleep(EnforcementRetryDelay * time.Duration(attempt)) // Exponential backoff
            }
            continue
        }

        // Success
        state.ComplianceStatus = ComplianceEnforced
        state.Resolution = GraceResolutionExpired
        resolvedAt := now
        state.ResolvedAt = &resolvedAt
        storeGraceState(state)
        delete(gpm.activeGrace, key)
        return
    }

    // All retries failed - rollback to grace period with extension
    // This prevents the client from being in a broken state
    log.Error("enforcement failed after all retries, rolling back to grace",
        "client", state.ClientID,
        "contract", state.ContractID,
        "lastError", lastErr)

    // ROLLBACK: Extend grace period by 1 hour to allow manual intervention
    const GraceExtensionOnFailure = 1 * time.Hour
    state.ComplianceStatus = ComplianceInGrace
    state.ExpiresAt = now.Add(GraceExtensionOnFailure)
    state.EnforcementFailures = append(state.EnforcementFailures, &EnforcementFailure{
        AttemptedAt: now,
        Attempts:    MaxEnforcementRetries,
        LastError:   lastErr.Error(),
    })

    // Schedule retry
    scheduleEnforcementRetry(state, now.Add(GraceExtensionOnFailure))

    // Alert operators about enforcement failure
    alertEnforcementFailure(state, lastErr)

    storeGraceState(state)
}

// EnforcementFailure tracks failed enforcement attempts
type EnforcementFailure struct {
    AttemptedAt time.Time
    Attempts    int
    LastError   string
}

// IsInGracePeriod checks if client has active grace period
// Returns the state if in grace, nil if fully compliant or already enforced
func (gpm *GracePeriodManager) IsInGracePeriod(clientID, contractID [32]byte) *GracePeriodState {
    gpm.mu.RLock()
    defer gpm.mu.RUnlock()

    key := hashClientContract(clientID, contractID)
    state, exists := gpm.activeGrace[key]
    if !exists {
        return nil
    }

    if state.ComplianceStatus == ComplianceInGrace {
        return state
    }

    return nil
}

// For complete client requirements system details, see: 20-service-provider-requirements.md

// ContractStatus represents the lifecycle state of a contract
// FINAL DESIGN: Extended with additional states for comprehensive lifecycle
type ContractStatus string

const (
    ContractStatusPending                ContractStatus = "pending"                 // Contract created, awaiting signatures
    ContractStatusDraft                  ContractStatus = "draft"                   // Initial creation (legacy alias for PENDING)
    ContractStatusProposed               ContractStatus = "proposed"                // Awaiting consumer signature
    ContractStatusNegotiating            ContractStatus = "negotiating"             // Terms being negotiated
    ContractStatusAgreed                 ContractStatus = "agreed"                  // Both parties signed (legacy alias for ACTIVE pre-start)
    ContractStatusActive                 ContractStatus = "active"                  // Service being delivered
    ContractStatusSuspended              ContractStatus = "suspended"               // Temporary pause (mutual agreement or eligibility issue)
    ContractStatusPaused                 ContractStatus = "paused"                  // Service paused by provider (maintenance, max 48h)
    ContractStatusDisputed               ContractStatus = "disputed"                // Dispute filed, awaiting resolution
    ContractStatusCompleted              ContractStatus = "completed"               // Service delivered, no disputes
    ContractStatusCancelled              ContractStatus = "cancelled"               // Cancelled before completion (by agreement or breach)
    ContractStatusExpired                ContractStatus = "expired"                 // Contract period ended
    ContractStatusExpiredPendingRenewal  ContractStatus = "expired_pending_renewal" // Auto-renewal in grace period
    ContractStatusTerminatedEarly        ContractStatus = "terminated_early"        // Early termination with penalty
    ContractStatusTerminated             ContractStatus = "terminated"              // Ended before completion (legacy)
)
```

### FINAL DESIGN: Contract State Machine

The contract state machine defines all valid state transitions and their conditions:

```
                         CONTRACT STATE MACHINE

                           +-------------+
                           |   PENDING   |
                           +------+------+
                                  |
                  both sign       |       timeout or rejection
                 +----------------+----------------+
                 |                                 |
                 v                                 v
           +-----+-----+                    +------+--------+
           |  ACTIVE   |                    |  CANCELLED    |
           +-----+-----+                    +---------------+
                 |
                 |  eligibility drop
                 v
           +-----+-----+
           | SUSPENDED |--------+
           +-----+-----+        |
                 |              | grace period expired
                 | restored     v
                 |         +----+------+
                 |         | CANCELLED |
                 +-------->+           |
                           +-----------+
           +-----+-----+
           |  ACTIVE   |
           +-----+-----+
                 |
                 |  provider maintenance (max 48h)
                 v
           +-----+-----+
           |  PAUSED   |
           +-----+-----+
                 |
                 | maintenance complete
                 v
           +-----+-----+
           |  ACTIVE   |
           +-----+-----+
                 |
                 |  dispute filed
                 v
           +-----+--------+
           |  DISPUTED    |
           +-----+--------+
                 |
                 |  resolved
         +-------+--------+
         |                |
         v                v
    +----+-----+    +-----+--------+
    | COMPLETED|    |  CANCELLED   |
    +----------+    +--------------+
           +-----+-----+
           |  ACTIVE   |
           +-----+-----+
                 |
                 |  delivery confirmed
                 v
           +-----+-----+
           | COMPLETED |
           +-----------+
           +-----+-----+
           |  ACTIVE   |
           +-----+-----+
                 |
                 |  breach or mutual agreement
                 v
           +-----+-----------+
           | TERMINATED_EARLY|
           +-----------------+
           +-----+-----+
           |  ACTIVE   |
           +-----+-----+
                 |
                 |  term ended
                 v
           +-----+-----+
           | EXPIRED   |
           +-----+-----+
                 |
                 |  if auto-renew enabled
                 v
           +-----+---------------------+
           | EXPIRED_PENDING_RENEWAL   |
           +-----+---------------------+
                 |
         +-------+--------+
         |                |
         v                v
    +----+-----+    +-----+------+
    | ACTIVE   |    |  EXPIRED   |
    |(renewed) |    |(failed)    |
    +----------+    +------------+
```

#### State Transition Rules

```go
// StateTransition defines a valid state transition
type StateTransition struct {
    From       ContractStatus
    To         ContractStatus
    Condition  TransitionCondition
    Action     TransitionAction
}

// TransitionCondition defines requirements for a transition
type TransitionCondition func(*ServiceContract) error

// TransitionAction performs side effects during transition
type TransitionAction func(*ServiceContract) error

// Valid state transitions
var ValidTransitions = []StateTransition{
    // Creation flow
    {From: ContractStatusPending, To: ContractStatusActive, Condition: bothPartiesSigned},
    {From: ContractStatusPending, To: ContractStatusCancelled, Condition: timeoutOrRejection},

    // Eligibility management
    {From: ContractStatusActive, To: ContractStatusSuspended, Condition: eligibilityDropped, Action: pauseService},
    {From: ContractStatusSuspended, To: ContractStatusActive, Condition: eligibilityRestored, Action: resumeService},
    {From: ContractStatusSuspended, To: ContractStatusCancelled, Condition: gracePeriodExpired, Action: refundEscrow},

    // Provider maintenance
    {From: ContractStatusActive, To: ContractStatusPaused, Condition: providerMaintenanceRequest, Action: notifyConsumer},
    {From: ContractStatusPaused, To: ContractStatusActive, Condition: maintenanceComplete, Action: resumeService},

    // Dispute flow
    {From: ContractStatusActive, To: ContractStatusDisputed, Condition: disputeFiled, Action: initiateArbitration},
    {From: ContractStatusDisputed, To: ContractStatusCompleted, Condition: resolvedProviderFavor, Action: releaseEscrow},
    {From: ContractStatusDisputed, To: ContractStatusCancelled, Condition: resolvedConsumerFavor, Action: refundEscrow},

    // Normal completion
    {From: ContractStatusActive, To: ContractStatusCompleted, Condition: deliveryConfirmed, Action: releaseEscrow},

    // Early termination
    {From: ContractStatusActive, To: ContractStatusTerminatedEarly, Condition: breachOrMutualAgreement, Action: applyPenalty},

    // Expiration and renewal
    {From: ContractStatusActive, To: ContractStatusExpired, Condition: termEnded},
    {From: ContractStatusExpired, To: ContractStatusExpiredPendingRenewal, Condition: autoRenewEnabled},
    {From: ContractStatusExpiredPendingRenewal, To: ContractStatusActive, Condition: renewalPaid, Action: renewContract},
    {From: ContractStatusExpiredPendingRenewal, To: ContractStatusExpired, Condition: renewalFailed},
}

// IsValidTransition checks if a state transition is allowed
func IsValidTransition(from, to ContractStatus, contract *ServiceContract) error {
    for _, transition := range ValidTransitions {
        if transition.From == from && transition.To == to {
            // Check condition
            if transition.Condition != nil {
                if err := transition.Condition(contract); err != nil {
                    return ErrTransitionConditionFailed{
                        From:   from,
                        To:     to,
                        Reason: err.Error(),
                    }
                }
            }
            return nil
        }
    }

    return ErrInvalidStateTransition{
        From: from,
        To:   to,
    }
}

// TransitionTo changes contract state with validation
func (c *ServiceContract) TransitionTo(newStatus ContractStatus) error {
    // Validate transition
    if err := IsValidTransition(c.Status, newStatus, c); err != nil {
        return err
    }

    // Find transition
    for _, transition := range ValidTransitions {
        if transition.From == c.Status && transition.To == newStatus {
            // Execute action
            if transition.Action != nil {
                if err := transition.Action(c); err != nil {
                    return ErrTransitionActionFailed{
                        From:   c.Status,
                        To:     newStatus,
                        Reason: err.Error(),
                    }
                }
            }

            // Update status
            oldStatus := c.Status
            c.Status = newStatus
            c.UpdatedAt = time.Now()

            log.Info("contract state transition",
                "contractID", c.ContractID,
                "from", oldStatus,
                "to", newStatus)

            return nil
        }
    }

    return ErrInvalidStateTransition{From: c.Status, To: newStatus}
}
```

#### Condition Functions

```go
// bothPartiesSigned verifies both signatures exist
func bothPartiesSigned(c *ServiceContract) error {
    if len(c.Signatures.ProviderSignature) == 0 {
        return ErrMissingProviderSignature
    }
    if len(c.Signatures.ConsumerSignature) == 0 {
        return ErrMissingConsumerSignature
    }
    return nil
}

// eligibilityDropped checks if consumer lost eligibility
func eligibilityDropped(c *ServiceContract) error {
    client, err := GetNodeIdentity(c.Consumer.NodeID)
    if err != nil {
        return err
    }

    result, err := VerifyClientEligibility(client, c.ClientRequirements, nil)
    if err != nil || !result.Eligible {
        return nil // Condition met - eligibility dropped
    }

    return ErrConditionNotMet{Reason: "client still eligible"}
}

// eligibilityRestored checks if consumer regained eligibility
func eligibilityRestored(c *ServiceContract) error {
    client, err := GetNodeIdentity(c.Consumer.NodeID)
    if err != nil {
        return err
    }

    result, err := VerifyClientEligibility(client, c.ClientRequirements, nil)
    if err != nil || !result.Eligible {
        return ErrConditionNotMet{Reason: "client not yet eligible"}
    }

    return nil // Condition met - eligibility restored
}

// providerMaintenanceRequest checks if maintenance is within limits
func providerMaintenanceRequest(c *ServiceContract) error {
    const MaxMaintenanceDuration = 48 * time.Hour

    // Check if provider has exceeded maintenance limits
    maintenanceHistory := GetMaintenanceHistory(c.ContractID)
    if len(maintenanceHistory) > 0 {
        lastMaintenance := maintenanceHistory[len(maintenanceHistory)-1]
        if time.Since(lastMaintenance.EndTime) < 7*24*time.Hour {
            return ErrMaintenanceTooFrequent
        }
    }

    return nil
}

// deliveryConfirmed verifies delivery proof exists
func deliveryConfirmed(c *ServiceContract) error {
    if len(c.Escrow.DeliveryProof) == 0 {
        return ErrMissingDeliveryProof
    }
    return nil
}
```

---

## NodeIdentity Structure

NodeIdentity ties contract parties to their TPM-backed identity:

```go
// NodeIdentity represents a contract party bound to TPM identity
type NodeIdentity struct {
    NodeID         [32]byte  // Node identifier (SHA256 of public key)
    IDevIDCertHash [32]byte  // Hash of IDevID certificate
    PublicKey      []byte    // Ed25519 public key for signature verification
    TrustLevel     TrustLevel // Trusted or Untrusted node status

    // Certificate Chain
    IDevIDSerial   string    // IDevID certificate serial number
    CAPoolID       [32]byte  // Issuing CA pool identifier

    // Contact Information
    Endpoints      []string  // Node API endpoints
    Region         string    // Geographic region
}

// TrustLevel indicates hardware TPM verification status
type TrustLevel uint8

const (
    TrustLevelUntrusted TrustLevel = 0 // Software TPM or unverified EK
    TrustLevelTrusted   TrustLevel = 1 // Hardware TPM with whitelisted EK
)

// VerifyNodeIdentity validates the node identity chain
func VerifyNodeIdentity(identity *NodeIdentity) error {
    // 1. Verify NodeID matches public key
    expectedID := sha256.Sum256(identity.PublicKey)
    if expectedID != identity.NodeID {
        return ErrNodeIDMismatch{NodeID: identity.NodeID}
    }

    // 2. Fetch and verify IDevID certificate
    idevid, err := FetchIDevIDCertificate(identity.IDevIDCertHash)
    if err != nil {
        return ErrIDevIDNotFound{Hash: identity.IDevIDCertHash}
    }

    // 3. Verify certificate chain to DHT Privacy CA
    if err := VerifyCertificateChain(idevid, identity.CAPoolID); err != nil {
        return ErrCertificateChainInvalid{Cause: err}
    }

    // 4. Verify public key matches certificate
    if !bytes.Equal(identity.PublicKey, idevid.PublicKey) {
        return ErrPublicKeyMismatch{}
    }

    // 5. Verify trust level is accurate
    actualTrust := DetermineTrustLevel(idevid)
    if actualTrust != identity.TrustLevel {
        return ErrTrustLevelMismatch{
            Claimed: identity.TrustLevel,
            Actual:  actualTrust,
        }
    }

    return nil
}
```

### Trust Level Requirements

| Contract Role | Minimum Trust Level | Justification |
|--------------|---------------------|---------------|
| Provider (ServiceType != Custom) | Trusted | Ensures hardware TPM for accountability |
| Provider (ServiceType == Custom) | Untrusted (0.5+ reputation) | Lower bar for custom services |
| Consumer | Untrusted | Anyone can purchase services |
| Arbiter | Trusted (0.8+ reputation) | High trust for dispute resolution |

---

## ServiceTerms Interface

ServiceTerms is an interface implemented by each service type:

```go
// ServiceTerms is implemented by type-specific service term structures
type ServiceTerms interface {
    ServiceType() ServiceType
    Validate() error
    Serialize() ([]byte, error)
}
```

---

## Service-Specific Terms

### AgentServiceTerms

Terms for AI/ML agent workloads:

```go
// AgentServiceTerms defines parameters for AI agent services
type AgentServiceTerms struct {
    // Agent Capabilities
    Capabilities      []string          // Required agent capabilities
    ModelType         string            // AI model type (claude, gpt, gemini, etc.)
    ModelVersion      string            // Specific model version

    // Resource Limits
    MaxTokens         uint64            // Maximum tokens per request
    MaxRequests       uint64            // Maximum requests per period
    RatePeriod        time.Duration     // Rate limiting period

    // Task Configuration
    TaskTypes         []TaskType        // Allowed task types
    DataAccess        DataAccessLevel   // Data access permissions
    ComputeUnits      uint64            // Compute units allocated

    // Quality Requirements
    MinLatency        time.Duration     // Maximum response latency
    AccuracyThreshold float64           // Minimum accuracy requirement (0.0-1.0)

    // Collaboration
    RoomAccess        bool              // Allow chat room participation
    SubcontractAllow  bool              // Allow hiring sub-agents
}

// TaskType defines allowed agent task categories
type TaskType string

const (
    TaskTypeCodeGeneration TaskType = "code_generation"
    TaskTypeAnalysis       TaskType = "analysis"
    TaskTypeResearch       TaskType = "research"
    TaskTypeCreative       TaskType = "creative"
    TaskTypeReasoning      TaskType = "reasoning"
    TaskTypeMultimodal     TaskType = "multimodal"
)

// DataAccessLevel defines agent data permissions
type DataAccessLevel uint8

const (
    DataAccessNone       DataAccessLevel = 0 // No persistent data access
    DataAccessSession    DataAccessLevel = 1 // Session-scoped access
    DataAccessContract   DataAccessLevel = 2 // Contract-scoped access
    DataAccessHistorical DataAccessLevel = 3 // Historical data access
)

func (t *AgentServiceTerms) ServiceType() ServiceType {
    return ServiceTypeAgent
}

func (t *AgentServiceTerms) Validate() error {
    if len(t.Capabilities) == 0 {
        return ErrNoCapabilitiesSpecified
    }
    if t.MaxTokens == 0 {
        return ErrInvalidMaxTokens
    }
    if t.AccuracyThreshold < 0 || t.AccuracyThreshold > 1 {
        return ErrInvalidAccuracyThreshold
    }
    return nil
}
```

### ComputeServiceTerms

Terms for compute/hosting services:

```go
// ComputeServiceTerms defines parameters for compute services
type ComputeServiceTerms struct {
    // Compute Resources
    CPUCores          uint32            // Number of CPU cores
    MemoryGB          uint32            // Memory in gigabytes
    StorageGB         uint32            // Attached storage in gigabytes
    GPUType           string            // GPU type (if applicable)
    GPUCount          uint32            // Number of GPUs

    // Instance Configuration
    OSImage           string            // Operating system image
    SSHPublicKey      []byte            // SSH public key for access
    InitScript        string            // Initialization script (cloud-init)

    // Networking
    BandwidthMbps     uint32            // Network bandwidth in Mbps
    PublicIPv4        bool              // Allocate public IPv4
    PublicIPv6        bool              // Allocate public IPv6
    Ports             []PortConfig      // Port mappings

    // Redundancy and Availability
    Redundancy        RedundancyLevel   // Redundancy configuration
    AvailabilityZones []string          // Target availability zones
    AutoRestart       bool              // Auto-restart on failure

    // Scaling
    AutoScale         *AutoScaleConfig  // Auto-scaling configuration
}

// PortConfig defines a port mapping
type PortConfig struct {
    Protocol    string // tcp, udp
    InternalPort uint16
    ExternalPort uint16
}

// RedundancyLevel defines availability requirements
type RedundancyLevel uint8

const (
    RedundancyNone     RedundancyLevel = 0 // Single instance
    RedundancyBasic    RedundancyLevel = 1 // 2x redundancy, same region
    RedundancyStandard RedundancyLevel = 2 // 3x redundancy, multi-AZ
    RedundancyHigh     RedundancyLevel = 3 // 5x redundancy, multi-region
)

// AutoScaleConfig defines auto-scaling parameters
type AutoScaleConfig struct {
    MinInstances    uint32
    MaxInstances    uint32
    ScaleUpCPU      float64   // CPU threshold to scale up (0.0-1.0)
    ScaleDownCPU    float64   // CPU threshold to scale down (0.0-1.0)
    CooldownPeriod  time.Duration
}

func (t *ComputeServiceTerms) ServiceType() ServiceType {
    return ServiceTypeCompute
}

func (t *ComputeServiceTerms) Validate() error {
    if t.CPUCores == 0 {
        return ErrInvalidCPUCores
    }
    if t.MemoryGB == 0 {
        return ErrInvalidMemory
    }
    if t.OSImage == "" {
        return ErrNoOSImageSpecified
    }
    return nil
}
```

### GPU Compute Resources

The platform supports GPU-accelerated compute workloads through QEMU/KVM passthrough with TPM-attested GPU nodes.

#### GPU Configuration

```go
// GPUConfig defines GPU resource allocation for compute services
type GPUConfig struct {
    // GPU Hardware
    GPUType           string            // GPU model (e.g., "NVIDIA-A100", "NVIDIA-H100", "AMD-MI300X")
    GPUCount          uint32            // Number of GPUs requested
    GPUMemoryGB       uint32            // GPU memory per device (0 = full device)

    // Multi-Instance GPU (MIG) - NVIDIA only
    MIGEnabled        bool              // Enable MIG partitioning
    MIGProfile        string            // MIG profile (e.g., "1g.5gb", "2g.10gb", "3g.20gb", "7g.40gb")

    // Passthrough Configuration
    PassthroughMode   GPUPassthroughMode // Passthrough method
    VFIOGroupID       string            // VFIO IOMMU group (auto-assigned if empty)

    // Driver Requirements
    DriverVersion     string            // Minimum driver version required
    CUDAVersion       string            // Minimum CUDA version (NVIDIA)
    ROCmVersion       string            // Minimum ROCm version (AMD)
}

// GPUPassthroughMode defines how GPUs are exposed to workloads
type GPUPassthroughMode uint8

const (
    GPUPassthroughVFIO     GPUPassthroughMode = 1 // Direct VFIO passthrough (full device)
    GPUPassthroughMIG      GPUPassthroughMode = 2 // NVIDIA MIG partitioned instance
    GPUPassthroughVGPU     GPUPassthroughMode = 3 // Virtual GPU (time-sliced)
    GPUPassthroughSRIOV    GPUPassthroughMode = 4 // SR-IOV virtual function
)
```

#### Supported GPU Types

| Vendor | Model | Memory | MIG Support | Attestation |
|--------|-------|--------|-------------|-------------|
| **NVIDIA** | A100 | 40GB/80GB | Yes (7 instances) | TPM + GPU attestation |
| **NVIDIA** | H100 | 80GB | Yes (7 instances) | TPM + GPU attestation |
| **NVIDIA** | L40S | 48GB | No | TPM only |
| **NVIDIA** | A10 | 24GB | No | TPM only |
| **NVIDIA** | T4 | 16GB | No | TPM only |
| **AMD** | MI300X | 192GB | No | TPM only |
| **AMD** | MI250X | 128GB | No | TPM only |
| **Intel** | Data Center GPU Max | 48GB | No | TPM only |

#### GPU Passthrough via QEMU/KVM

GPU passthrough uses VFIO (Virtual Function I/O) to provide direct hardware access:

```go
// GPUPassthroughConfig for QEMU VM configuration
type GPUPassthroughConfig struct {
    // VFIO Configuration
    PCIAddress        string   // PCI address (e.g., "0000:41:00.0")
    IOMMUGroup        int      // IOMMU group ID
    VFIODriver        string   // VFIO driver ("vfio-pci")

    // Device Binding
    VendorID          string   // PCI vendor ID (e.g., "10de" for NVIDIA)
    DeviceID          string   // PCI device ID
    SubsystemVendorID string   // Subsystem vendor ID
    SubsystemDeviceID string   // Subsystem device ID

    // QEMU Device Arguments
    QEMUDeviceArgs    []string // Additional QEMU device arguments
}

// BuildQEMUArgs generates QEMU command-line arguments for GPU passthrough
func (g *GPUPassthroughConfig) BuildQEMUArgs() []string {
    return []string{
        "-device", fmt.Sprintf("vfio-pci,host=%s,multifunction=on", g.PCIAddress),
    }
}
```

#### GPU Pricing Model

GPU resources are priced per GPU-hour:

```go
// GPUPricing defines pricing tiers for GPU compute
type GPUPricing struct {
    // Base Rates (coins per GPU-hour)
    BaseRates map[string]uint64
}

// Default GPU Pricing (coins per GPU-hour)
var DefaultGPUPricing = GPUPricing{
    BaseRates: map[string]uint64{
        "NVIDIA-T4":       10,   // Entry-level inference
        "NVIDIA-A10":      25,   // Mid-range inference/training
        "NVIDIA-L40S":     40,   // Professional visualization + AI
        "NVIDIA-A100-40":  100,  // High-end training
        "NVIDIA-A100-80":  150,  // High-end training (80GB)
        "NVIDIA-H100":     200,  // Flagship training/inference
        "AMD-MI250X":      120,  // AMD high-end
        "AMD-MI300X":      180,  // AMD flagship
    },
}
```

#### GPU Attestation Requirements

GPU compute nodes must meet additional attestation requirements:

```go
// GPUAttestationPolicy defines attestation requirements for GPU nodes
type GPUAttestationPolicy struct {
    // Host Attestation
    RequireTPM            bool              // Host must have hardware TPM
    RequireSecureBoot     bool              // Host must have Secure Boot enabled
    RequireMeasuredBoot   bool              // Host must have measured boot chain

    // GPU-Specific Attestation
    RequireGPUAttestation bool              // Require NVIDIA GPU attestation (H100/A100)
    VerifyDriverSignature bool              // Verify GPU driver is signed
    AllowedDriverVersions []string          // Whitelist of allowed driver versions

    // PCR Requirements
    PCRPolicy             []PCRRequirement  // PCR values that must be verified
}

// PCRRequirement defines a required PCR measurement
type PCRRequirement struct {
    PCRIndex      int      // PCR index (0-23)
    Description   string   // What this PCR measures
    AllowedValues [][]byte // Allowed measurement values (any match = pass)
}

// DefaultGPUAttestationPolicy for trusted GPU compute
var DefaultGPUAttestationPolicy = GPUAttestationPolicy{
    RequireTPM:            true,
    RequireSecureBoot:     true,
    RequireMeasuredBoot:   true,
    RequireGPUAttestation: true,  // For NVIDIA H100/A100 with CC mode
    VerifyDriverSignature: true,
    PCRPolicy: []PCRRequirement{
        {PCRIndex: 0, Description: "UEFI firmware"},
        {PCRIndex: 7, Description: "Secure Boot policy"},
        {PCRIndex: 14, Description: "GPU driver measurement"},
    },
}
```

#### GPU Security and Attestation Hardening

The basic GPUAttestationPolicy above provides foundational security, but high-value workloads require additional hardening to prevent attestation bypass attacks. This section defines enhanced security controls for GPU attestation.

**GPU Attestation Requirements Table:**

| Security Level | Manufacturer Cert | Firmware Hash | Driver Sig | CC Mode | Memory Encryption | Refresh Interval |
|----------------|-------------------|---------------|------------|---------|-------------------|------------------|
| **Basic** | Required | Optional | Optional | No | No | 1 hour |
| **Standard** | Required | Required | Required | No | No | 30 minutes |
| **High** | Required | Required | Required | Required | Required | 10 minutes |
| **Maximum** | Required | Required | Required | Required | Required | 5 minutes |

```go
// GPUSecurityHardening enforces strict GPU attestation requirements
type GPUSecurityHardening struct {
    // Attestation chain requirements
    RequireGPUAttestationChain  bool   // Full chain to manufacturer CA
    RequireDriverAttestation    bool   // Signed driver verification
    RequireFirmwareAttestation  bool   // GPU firmware hash verification

    // Confidential computing requirements
    RequireCC                   bool   // NVIDIA H100 Confidential Computing
    RequireMemoryEncryption     bool   // HBM encryption enabled
    RequireSecureBoot           bool   // GPU secure boot chain

    // Runtime monitoring
    EnableNVMLMonitoring        bool   // Monitor GPU state changes
    EnableMemoryIntegrity       bool   // Detect memory tampering
    AttestationRefreshInterval  time.Duration  // Re-attest periodically
}

// GPUAttestationChain verifies full attestation from GPU to manufacturer
type GPUAttestationChain struct {
    GPUSerialNumber     string
    GPUFirmwareHash     [32]byte
    DriverSignature     []byte
    ManufacturerCert    *x509.Certificate
    AttestationReport   []byte  // NVIDIA: SPDM report, AMD: SEV report
    AttestationNonce    []byte  // Challenge-response nonce
    Timestamp           time.Time
}

// GPUAttestationError represents a GPU attestation failure
type GPUAttestationError struct {
    Code   string
    Reason string
}

func (e *GPUAttestationError) Error() string {
    return fmt.Sprintf("GPU attestation error [%s]: %s", e.Code, e.Reason)
}

// ValidateGPUAttestationChain performs comprehensive GPU attestation
func ValidateGPUAttestationChain(chain *GPUAttestationChain, policy *GPUAttestationPolicy) error {
    // Step 1: Verify manufacturer certificate
    if policy.RequireGPUAttestationChain {
        if err := verifyGPUManufacturerCert(chain.ManufacturerCert); err != nil {
            return &GPUAttestationError{
                Code:   "MANUFACTURER_CERT_INVALID",
                Reason: err.Error(),
            }
        }
    }

    // Step 2: Verify firmware hash against known-good values
    if policy.RequireFirmwareAttestation {
        if !isKnownGoodFirmware(chain.GPUFirmwareHash) {
            return &GPUAttestationError{
                Code:   "FIRMWARE_NOT_VERIFIED",
                Reason: "GPU firmware hash not in approved list",
            }
        }
    }

    // Step 3: Verify driver signature
    if policy.RequireDriverAttestation {
        if err := verifyDriverSignature(chain.DriverSignature); err != nil {
            return &GPUAttestationError{
                Code:   "DRIVER_NOT_SIGNED",
                Reason: err.Error(),
            }
        }
    }

    // Step 4: Verify attestation report freshness (prevent replay)
    reportAge := time.Since(chain.Timestamp)
    if reportAge > 5*time.Minute {
        return &GPUAttestationError{
            Code:   "ATTESTATION_STALE",
            Reason: fmt.Sprintf("attestation report is %v old", reportAge),
        }
    }

    // Step 5: Verify attestation nonce matches challenge
    if !verifyAttestationNonce(chain.AttestationNonce) {
        return &GPUAttestationError{
            Code:   "NONCE_MISMATCH",
            Reason: "attestation nonce does not match challenge",
        }
    }

    // Step 6: For NVIDIA H100 CC mode, verify confidential computing state
    if policy.RequireCC {
        if err := verifyConfidentialComputingMode(chain.AttestationReport); err != nil {
            return &GPUAttestationError{
                Code:   "CC_NOT_ENABLED",
                Reason: err.Error(),
            }
        }
    }

    return nil
}

// ContractViolation represents a GPU contract violation
type ContractViolation struct {
    Type   string
    Reason string
}

func (v *ContractViolation) Error() string {
    return fmt.Sprintf("contract violation [%s]: %s", v.Type, v.Reason)
}

// PeriodicGPUReAttestation ensures GPU state hasn't changed
func PeriodicGPUReAttestation(contract *ServiceContract, interval time.Duration) error {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            // Generate fresh nonce
            nonce := make([]byte, 32)
            rand.Read(nonce)

            // Request fresh attestation
            chain, err := requestGPUAttestation(contract.Provider, nonce)
            if err != nil {
                return &ContractViolation{
                    Type:   "GPU_ATTESTATION_FAILED",
                    Reason: err.Error(),
                }
            }

            // Validate fresh attestation
            if err := ValidateGPUAttestationChain(chain, contract.GPUConfig.AttestationPolicy); err != nil {
                return &ContractViolation{
                    Type:   "GPU_STATE_CHANGED",
                    Reason: err.Error(),
                }
            }
        }
    }
}
```

#### GPU Resource Quotas and Scheduling

```go
// GPUQuota defines resource limits for GPU allocation
type GPUQuota struct {
    MaxGPUs           uint32        // Maximum concurrent GPUs
    MaxGPUHoursDaily  uint64        // Maximum GPU-hours per day
    MaxGPUMemoryGB    uint64        // Maximum total GPU memory
    AllowedGPUTypes   []string      // Whitelist of allowed GPU types
    PriorityClass     PriorityClass // Scheduling priority
}

// PriorityClass for GPU scheduling
type PriorityClass uint8

const (
    PriorityBestEffort   PriorityClass = 0 // Preemptible, lowest cost
    PriorityStandard     PriorityClass = 1 // Normal priority
    PriorityHigh         PriorityClass = 2 // High priority, guaranteed
    PriorityReserved     PriorityClass = 3 // Reserved capacity, highest cost
)

// GPUScheduler manages GPU resource allocation
type GPUScheduler interface {
    // AllocateGPU requests GPU resources for a workload
    AllocateGPU(ctx context.Context, req *GPUAllocationRequest) (*GPUAllocation, error)

    // ReleaseGPU releases allocated GPU resources
    ReleaseGPU(ctx context.Context, allocationID string) error

    // ListAvailableGPUs returns available GPU resources
    ListAvailableGPUs(ctx context.Context, filter *GPUFilter) ([]*GPUResource, error)

    // GetGPUMetrics returns usage metrics for allocated GPUs
    GetGPUMetrics(ctx context.Context, allocationID string) (*GPUMetrics, error)
}
```

#### Example: GPU Compute Contract

```go
// Example GPU compute service contract
gpuContract := &ServiceContract{
    ServiceType: ServiceTypeCompute,
    ServiceTerms: &ComputeServiceTerms{
        CPUCores:      32,
        MemoryGB:      128,
        StorageGB:     500,
        GPUType:       "NVIDIA-H100",
        GPUCount:      4,
        OSImage:       "ubuntu-22.04-nvidia",
        BandwidthMbps: 10000,
        AutoScale: &AutoScaleConfig{
            MinInstances: 1,
            MaxInstances: 8,
        },
    },
    PaymentTerms: PaymentTerms{
        Currency:      CurrencyNative,
        PricingUnit:   PricingUnitPerGPUHour,
        BasePrice:     200, // coins per GPU-hour for H100
        PaymentPeriod: 24 * time.Hour,
    },
    ClientRequirements: &ClientRequirements{
        MinTrustLevel:   TrustLevelTrusted,
        MinReputation:   0.70,
    },
}
```

### StorageServiceTerms

Terms for storage services:

```go
// StorageServiceTerms defines parameters for storage services
type StorageServiceTerms struct {
    // Storage Capacity
    StorageQuotaGB    uint64            // Total storage quota in GB
    BandwidthQuotaGB  uint64            // Monthly bandwidth quota in GB

    // Durability and Redundancy
    ReplicationFactor uint8             // Number of replicas (1-20)
    ErasureCoding     *ErasureConfig    // Erasure coding configuration
    GeoRedundancy     bool              // Cross-region replication

    // Security
    EncryptionLevel   EncryptionLevel   // Encryption requirements
    EncryptionKeyID   [32]byte          // Customer-managed encryption key

    // Performance
    LatencySLA        time.Duration     // Maximum latency guarantee
    IOPSGuaranteed    uint32            // Guaranteed IOPS
    ThroughputMBps    uint32            // Guaranteed throughput

    // Storage Class
    StorageClass      StorageClass      // Storage tier
    AccessPattern     AccessPattern     // Expected access pattern

    // Retention
    RetentionDays     uint32            // Minimum retention period
    VersioningEnabled bool              // Keep file versions
    MaxVersions       uint32            // Maximum versions per file
}

// ErasureConfig defines erasure coding parameters
type ErasureConfig struct {
    DataShards   uint8  // Number of data shards
    ParityShards uint8  // Number of parity shards
}

// EncryptionLevel defines encryption requirements
type EncryptionLevel uint8

const (
    EncryptionNone       EncryptionLevel = 0 // No encryption (not recommended)
    EncryptionTransit    EncryptionLevel = 1 // Encryption in transit only
    EncryptionRest       EncryptionLevel = 2 // Encryption at rest only
    EncryptionFull       EncryptionLevel = 3 // Full encryption (transit + rest)
    EncryptionClientSide EncryptionLevel = 4 // Client-side encryption
)

// StorageClass defines storage tiers
type StorageClass uint8

const (
    StorageClassStandard  StorageClass = 0 // Standard storage
    StorageClassInfrequent StorageClass = 1 // Infrequent access
    StorageClassArchive   StorageClass = 2 // Archive/cold storage
    StorageClassHot       StorageClass = 3 // Hot/high-performance
)

// AccessPattern describes expected data access
type AccessPattern uint8

const (
    AccessPatternRandom     AccessPattern = 0 // Random read/write
    AccessPatternSequential AccessPattern = 1 // Sequential access
    AccessPatternAppend     AccessPattern = 2 // Append-only
    AccessPatternReadHeavy  AccessPattern = 3 // Mostly reads
    AccessPatternWriteHeavy AccessPattern = 4 // Mostly writes
)

func (t *StorageServiceTerms) ServiceType() ServiceType {
    return ServiceTypeStorage
}

func (t *StorageServiceTerms) Validate() error {
    if t.StorageQuotaGB == 0 {
        return ErrInvalidStorageQuota
    }
    if t.ReplicationFactor < 1 || t.ReplicationFactor > 20 {
        return ErrInvalidReplicationFactor
    }
    return nil
}
```

### ECommerceServiceTerms

Terms for e-commerce/storefront services:

```go
// ECommerceServiceTerms defines parameters for e-commerce services
type ECommerceServiceTerms struct {
    // Store Configuration
    StoreName         string            // Store display name
    StorefrontURL     string            // Store URL path
    StoreDescription  string            // Store description

    // Catalog
    CatalogSize       uint32            // Maximum number of products
    CategoryLimit     uint32            // Maximum categories
    VariantsPerProduct uint32           // Maximum variants per product

    // Payments
    PaymentMethods    []PaymentMethod   // Accepted payment methods
    BaseCurrency      string            // Primary currency
    MultiCurrency     bool              // Support multiple currencies

    // Fulfillment
    ShippingZones     []ShippingZone    // Shipping configuration
    DigitalDelivery   bool              // Support digital products
    DropshippingEnabled bool            // Enable dropshipping

    // Compliance
    TaxJurisdictions  []string          // Tax jurisdictions to support
    AgeRestricted     bool              // Age-restricted products
    ExportControls    bool              // Export control compliance

    // Transaction Limits
    MaxOrderValue     uint64            // Maximum order value
    MinOrderValue     uint64            // Minimum order value
    DailyTransactionLimit uint64        // Daily transaction limit
}

// PaymentMethod defines accepted payment types
type PaymentMethod uint8

const (
    PaymentMethodDHTCoin    PaymentMethod = 0 // Native DHT token
    PaymentMethodCrypto     PaymentMethod = 1 // Other cryptocurrencies
    PaymentMethodEscrow     PaymentMethod = 2 // Escrow-based payment
    PaymentMethodSubscription PaymentMethod = 3 // Recurring payments
)

// ShippingZone defines shipping region configuration
type ShippingZone struct {
    ZoneID        string
    Regions       []string
    BaseRate      uint64
    PerItemRate   uint64
    FreeThreshold uint64
    EstDaysMin    uint8
    EstDaysMax    uint8
}

func (t *ECommerceServiceTerms) ServiceType() ServiceType {
    return ServiceTypeECommerce
}

func (t *ECommerceServiceTerms) Validate() error {
    if t.StoreName == "" {
        return ErrNoStoreNameSpecified
    }
    if t.CatalogSize == 0 {
        return ErrInvalidCatalogSize
    }
    if len(t.PaymentMethods) == 0 {
        return ErrNoPaymentMethodsSpecified
    }
    return nil
}
```

### NetworkServiceTerms

Terms for network/bandwidth services:

```go
// NetworkServiceTerms defines parameters for network services
type NetworkServiceTerms struct {
    // Bandwidth
    BandwidthMbps     uint32            // Guaranteed bandwidth
    BurstBandwidthMbps uint32           // Burst bandwidth capacity
    MonthlyTransferTB float64           // Monthly transfer quota

    // Service Type
    NetworkService    NetworkServiceType // Type of network service
    Protocol          string             // Protocol (wireguard, ipsec, etc.)

    // Routing
    Regions           []string           // Service regions
    PeeringPoints     []string           // Peering exchange points
    RouteAdvertise    bool               // Advertise custom routes

    // Security
    DDoSProtection    bool               // DDoS mitigation included
    FirewallRules     []FirewallRule     // Included firewall rules
    TLSTermination    bool               // TLS termination support

    // Performance
    LatencyTarget     time.Duration      // Target latency
    PacketLossMax     float64            // Maximum packet loss (0.0-1.0)
    JitterMax         time.Duration      // Maximum jitter

    // Endpoints
    MaxConnections    uint32             // Maximum concurrent connections
    StaticIP          bool               // Static IP allocation
    IPv6Support       bool               // IPv6 support
}

// NetworkServiceType defines network service categories
type NetworkServiceType uint8

const (
    NetworkServiceVPN       NetworkServiceType = 0 // VPN service
    NetworkServiceProxy     NetworkServiceType = 1 // Proxy service
    NetworkServiceRelay     NetworkServiceType = 2 // Relay/transit service
    NetworkServiceCDN       NetworkServiceType = 3 // CDN edge service
    NetworkServiceLoadBalancer NetworkServiceType = 4 // Load balancing
)

// FirewallRule defines a firewall rule
type FirewallRule struct {
    Direction   string // inbound, outbound
    Protocol    string // tcp, udp, icmp
    PortRange   string // e.g., "80", "443", "8000-8100"
    Source      string // CIDR or any
    Destination string // CIDR or any
    Action      string // allow, deny
}

func (t *NetworkServiceTerms) ServiceType() ServiceType {
    return ServiceTypeNetwork
}

func (t *NetworkServiceTerms) Validate() error {
    if t.BandwidthMbps == 0 {
        return ErrInvalidBandwidth
    }
    if t.LatencyTarget == 0 {
        return ErrInvalidLatencyTarget
    }
    return nil
}
```

---

## Payment and Economics

### PaymentTerms Structure

```go
// PaymentTerms defines the payment structure for a contract
type PaymentTerms struct {
    // Pricing
    BasePrice         uint64            // Base price in smallest currency unit
    PricingModel      PricingModel      // How service is priced
    Currency          string            // Currency identifier

    // Payment Schedule
    PaymentFrequency  PaymentFrequency  // How often payments occur
    BillingCycle      time.Duration     // Billing cycle length

    // Prepayment
    PrepaymentRequired uint64           // Required prepayment amount
    DepositRequired    uint64           // Security deposit

    // Adjustments
    Discounts         []Discount        // Applicable discounts
    Surcharges        []Surcharge       // Additional charges

    // Settlement
    PayoutDelay       time.Duration     // Delay before provider payout
    AutoRenewalPrice  uint64            // Price for auto-renewal period
}

// PricingModel defines how the service is priced
type PricingModel uint8

const (
    PricingModelFlat       PricingModel = 0 // Flat rate
    PricingModelUsage      PricingModel = 1 // Usage-based
    PricingModelTiered     PricingModel = 2 // Tiered pricing
    PricingModelHybrid     PricingModel = 3 // Base + usage
    PricingModelAuction    PricingModel = 4 // Auction/bid-based
)

// PaymentFrequency defines payment timing
type PaymentFrequency uint8

const (
    PaymentFrequencyUpfront   PaymentFrequency = 0 // Full payment upfront
    PaymentFrequencyHourly    PaymentFrequency = 1 // Hourly billing
    PaymentFrequencyDaily     PaymentFrequency = 2 // Daily billing
    PaymentFrequencyWeekly    PaymentFrequency = 3 // Weekly billing
    PaymentFrequencyMonthly   PaymentFrequency = 4 // Monthly billing
    PaymentFrequencyMilestone PaymentFrequency = 5 // Milestone-based
)
```

### StakeRequirement Structure

```go
// StakeRequirement defines staking requirements for contract parties
type StakeRequirement struct {
    // Provider Stake
    ProviderStake     uint64            // Provider's required stake
    ProviderStakeLockDays uint16        // Days stake is locked after completion

    // Consumer Stake
    ConsumerStake     uint64            // Consumer's required stake (deposit)
    ConsumerStakeLockDays uint16        // Days stake is locked

    // Slashing Conditions
    SlashConditions   []SlashCondition  // Conditions for stake slashing
}

// SlashCondition defines when stakes are slashed
type SlashCondition struct {
    Condition         string            // Condition description
    SlashPercentage   float64           // Percentage to slash (0.0-1.0)
    Recipient         string            // Where slashed funds go (treasury, counterparty)
}
```

### PenaltyTerms Structure

```go
// PenaltyTerms defines penalty conditions
type PenaltyTerms struct {
    // SLA Violations
    UptimeViolation   PenaltyConfig     // Uptime SLA violation penalty
    LatencyViolation  PenaltyConfig     // Latency SLA violation penalty
    AvailabilityViolation PenaltyConfig // Availability violation penalty

    // Contract Breaches
    EarlyTermination  PenaltyConfig     // Early termination penalty
    NonDelivery       PenaltyConfig     // Service non-delivery penalty

    // Grace Periods
    GracePeriod       time.Duration     // Grace period before penalties apply
    MaxPenaltyCap     float64           // Maximum penalty as % of contract value
}

// PenaltyConfig defines a specific penalty
type PenaltyConfig struct {
    PercentageOfValue float64           // Penalty as % of contract value
    FixedAmount       uint64            // Fixed penalty amount
    EscalationRate    float64           // Escalation per occurrence
    MaxOccurrences    uint8             // Max occurrences before termination
}
```

---

## Escrow Configuration

```go
// EscrowConfig defines escrow parameters for the contract
type EscrowConfig struct {
    // Escrow Account
    EscrowID          [32]byte          // Escrow account identifier
    EscrowAmount      uint64            // Total escrowed amount
    Currency          string            // Escrow currency

    // Release Conditions
    ReleaseConditions []ReleaseCondition // Conditions for fund release
    PartialReleaseAllowed bool           // Allow partial releases

    // Dispute Protection (CANONICAL)
    DisputeWindow     time.Duration     // Mandatory dispute period (48h default)
    DisputeDeadline   time.Time         // Deadline for opening dispute

    // Arbitration
    ArbiterPool       []NodeIdentity    // Pre-selected arbiter candidates
    ArbiterFee        uint64            // Arbiter fee (paid from escrow)
}

// ReleaseCondition defines when escrow funds are released
type ReleaseCondition struct {
    Type              ConditionType
    Parameters        map[string]string
    Amount            uint64            // Amount released when condition met
    Satisfied         bool
    SatisfiedAt       time.Time
}

// ConditionType defines release condition types
type ConditionType uint8

const (
    ConditionDeliveryConfirmed ConditionType = 0 // Consumer confirms delivery
    ConditionTimeElapsed       ConditionType = 1 // Time-based release
    ConditionMilestoneComplete ConditionType = 2 // Milestone completion
    ConditionArbiterApproval   ConditionType = 3 // Arbiter decision
    ConditionMultiSig          ConditionType = 4 // Multi-signature release
)
```

---

## Contract Automation

The contract system provides tiered automation for escrow release and enforcement actions. Automation triggers handle objective, measurable conditions while human arbitration handles subjective disputes.

### Automation Philosophy

The platform uses a tiered enforcement model:

| Tier | Mechanism | Use Case | Coverage |
|------|-----------|----------|----------|
| **Tier 1** | Automation Triggers | Objective conditions (time, SLA metrics, signatures) | ~60% of cases |
| **Tier 2** | OPA/Rego Policies | Custom conditions with bounded execution | Complex rules |
| **Tier 3** | Human Arbitration | Subjective disputes, quality assessments | ~40% of cases |

Automation triggers execute deterministically on measurable conditions. Human judgment remains required for quality disputes, fraud detection, and subjective assessments.

### AutomationTrigger Structure

```go
// AutomationTrigger defines an automatic escrow action
type AutomationTrigger struct {
    // Trigger Identity
    TriggerID     [16]byte          // Unique trigger identifier
    Type          TriggerType       // Type of trigger
    Name          string            // Human-readable name

    // Configuration
    Config        TriggerConfig     // Type-specific configuration
    Priority      uint8             // Evaluation order (lower = first)
    Enabled       bool              // Whether trigger is active

    // Conditions
    Prerequisites []TriggerCondition // Conditions that must be met first
    Blockers      []TriggerCondition // Conditions that prevent execution

    // Actions
    Action        TriggerAction     // Action to take when triggered
    Amount        uint64            // Amount affected (0 = full escrow)
    Recipient     RecipientType     // Who receives funds

    // State
    Status        TriggerStatus     // Current trigger status
    LastEvaluated time.Time         // Last evaluation timestamp
    ExecutedAt    *time.Time        // Execution timestamp (if executed)
}

// TriggerType defines the category of automation trigger
type TriggerType uint8

const (
    // Time-Based Triggers
    TriggerTimeBasedRelease    TriggerType = 1  // Release after duration
    TriggerRefundOnTimeout     TriggerType = 2  // Refund if provider times out

    // Confirmation Triggers
    TriggerDeliveryConfirmation TriggerType = 3 // Consumer confirms receipt
    TriggerMultiSigApproval    TriggerType = 4  // N-of-M signatures

    // External Verification
    TriggerOracleAttestation   TriggerType = 5  // External oracle confirms
    TriggerProofOfService      TriggerType = 6  // Challenge-response proof

    // SLA-Based Triggers
    TriggerSLAPenalty          TriggerType = 7  // Auto-deduct for violations
    TriggerMilestoneCompletion TriggerType = 8  // Release on milestone
)

// TriggerStatus represents the current state of a trigger
type TriggerStatus uint8

const (
    TriggerStatusPending   TriggerStatus = 0 // Not yet evaluated
    TriggerStatusActive    TriggerStatus = 1 // Ready to evaluate
    TriggerStatusBlocked   TriggerStatus = 2 // Blocked by condition
    TriggerStatusExecuted  TriggerStatus = 3 // Successfully executed
    TriggerStatusExpired   TriggerStatus = 4 // Past execution window
    TriggerStatusCancelled TriggerStatus = 5 // Manually cancelled
)

// TriggerAction defines what happens when trigger fires
type TriggerAction uint8

const (
    ActionReleaseFunds     TriggerAction = 1 // Release escrow to recipient
    ActionRefundFunds      TriggerAction = 2 // Refund to consumer
    ActionDeductPenalty    TriggerAction = 3 // Deduct penalty amount
    ActionSplitFunds       TriggerAction = 4 // Split between parties
    ActionExtendContract   TriggerAction = 5 // Extend contract duration
    ActionTerminateContract TriggerAction = 6 // Terminate contract
)

// RecipientType defines who receives funds
type RecipientType uint8

const (
    RecipientProvider RecipientType = 1 // Service provider
    RecipientConsumer RecipientType = 2 // Service consumer
    RecipientSplit    RecipientType = 3 // Split per ratio
    RecipientTreasury RecipientType = 4 // Network treasury
)
```

### Trigger-Specific Configurations

Each trigger type has specialized configuration parameters:

```go
// TriggerConfig is implemented by type-specific configurations
type TriggerConfig interface {
    TriggerType() TriggerType
    Validate() error
}

// TimeBasedReleaseConfig for automatic time-based release
type TimeBasedReleaseConfig struct {
    ReleaseAfter      time.Duration  // Duration after contract start
    RequireNoDispute  bool           // Block if dispute is open
    RequireActive     bool           // Require contract to be active
    GracePeriod       time.Duration  // Additional grace period
}

func (c *TimeBasedReleaseConfig) TriggerType() TriggerType {
    return TriggerTimeBasedRelease
}

func (c *TimeBasedReleaseConfig) Validate() error {
    if c.ReleaseAfter <= 0 {
        return ErrInvalidReleaseDuration
    }
    return nil
}

// RefundOnTimeoutConfig for provider timeout refunds
type RefundOnTimeoutConfig struct {
    TimeoutDuration   time.Duration  // How long to wait for provider
    Event             TimeoutEvent   // What event is being waited for
    PartialRefund     bool           // Allow partial refund
    RefundPercentage  float64        // Percentage to refund (0.0-1.0)
}

type TimeoutEvent uint8

const (
    TimeoutEventServiceStart    TimeoutEvent = 1 // Provider didn't start service
    TimeoutEventDelivery        TimeoutEvent = 2 // Provider didn't deliver
    TimeoutEventResponse        TimeoutEvent = 3 // Provider didn't respond
    TimeoutEventMilestone       TimeoutEvent = 4 // Provider missed milestone
)

func (c *RefundOnTimeoutConfig) TriggerType() TriggerType {
    return TriggerRefundOnTimeout
}

// DeliveryConfirmationConfig for consumer confirmation
type DeliveryConfirmationConfig struct {
    RequireTPMQuote     bool           // Require fresh TPM attestation
    ConfirmationWindow  time.Duration  // Window for confirmation
    AutoReleaseOnExpiry bool           // Auto-release if no confirmation
    RequireEvidence     bool           // Require delivery evidence
}

func (c *DeliveryConfirmationConfig) TriggerType() TriggerType {
    return TriggerDeliveryConfirmation
}

// MultiSigApprovalConfig for multi-signature release
type MultiSigApprovalConfig struct {
    RequiredSignatures uint8          // Number of signatures required
    TotalSigners       uint8          // Total possible signers
    SignerNodeIDs      [][32]byte     // Authorized signer node IDs
    SignatureWindow    time.Duration  // Window for collecting signatures
    WeightedVoting     bool           // Use weighted votes
    SignerWeights      []float64      // Weight per signer (if weighted)
}

func (c *MultiSigApprovalConfig) TriggerType() TriggerType {
    return TriggerMultiSigApproval
}

// OracleAttestationConfig for external oracle verification
type OracleAttestationConfig struct {
    OracleNodeIDs      [][32]byte     // Trusted oracle node IDs
    AttestationType    OracleType     // Type of attestation
    Threshold          uint8          // Number of oracles required
    AttestationWindow  time.Duration  // Window for attestation
    DataSource         string         // External data source identifier
}

type OracleType uint8

const (
    OracleTypeShippingDelivery OracleType = 1 // Shipping/delivery confirmation
    OracleTypeUptimeMonitor    OracleType = 2 // Uptime monitoring service
    OracleTypePriceData        OracleType = 3 // Price oracle for settlements
    OracleTypeCustom           OracleType = 4 // Custom oracle type
)

func (c *OracleAttestationConfig) TriggerType() TriggerType {
    return TriggerOracleAttestation
}

// ProofOfServiceConfig for challenge-response verification
type ProofOfServiceConfig struct {
    ChallengeType       ChallengeType  // Type of challenge
    ChallengeInterval   time.Duration  // How often to challenge
    ResponseTimeout     time.Duration  // Time to respond to challenge
    FailurePenalty      uint64         // Penalty per failed challenge
    MaxConsecutiveFails uint8          // Max fails before termination
    VerifierNodeIDs     [][32]byte     // Nodes that verify responses
}

type ChallengeType uint8

const (
    ChallengeTypeStorageProof   ChallengeType = 1 // Prove data is stored
    ChallengeTypeComputeProof   ChallengeType = 2 // Prove computation
    ChallengeTypeLatencyProof   ChallengeType = 3 // Prove response time
    ChallengeTypeBandwidthProof ChallengeType = 4 // Prove bandwidth
)

func (c *ProofOfServiceConfig) TriggerType() TriggerType {
    return TriggerProofOfService
}

// SLAPenaltyConfig for automatic SLA violation penalties
type SLAPenaltyConfig struct {
    Metric            SLAMetric      // Which SLA metric
    Threshold         float64        // Threshold value
    Operator          CompareOp      // Comparison operator
    PenaltyFormula    PenaltyFormula // How to calculate penalty
    MeasurementWindow time.Duration  // Window for measurement
    CumulativePenalty bool           // Cumulative vs per-incident
    MaxPenaltyCap     float64        // Maximum penalty percentage
}

type SLAMetric uint8

const (
    MetricUptime        SLAMetric = 1 // Uptime percentage
    MetricLatency       SLAMetric = 2 // Response latency
    MetricThroughput    SLAMetric = 3 // Throughput rate
    MetricErrorRate     SLAMetric = 4 // Error rate
    MetricAvailability  SLAMetric = 5 // Availability percentage
)

type CompareOp uint8

const (
    OpLessThan      CompareOp = 1 // Actual < Threshold = violation
    OpGreaterThan   CompareOp = 2 // Actual > Threshold = violation
    OpLessOrEqual   CompareOp = 3
    OpGreaterOrEqual CompareOp = 4
)

type PenaltyFormula uint8

const (
    FormulaFixed       PenaltyFormula = 1 // Fixed amount
    FormulaPercentage  PenaltyFormula = 2 // Percentage of escrow
    FormulaProportional PenaltyFormula = 3 // Proportional to violation
    FormulaExponential PenaltyFormula = 4 // Exponential backoff
)

func (c *SLAPenaltyConfig) TriggerType() TriggerType {
    return TriggerSLAPenalty
}

// MilestoneCompletionConfig for milestone-based releases
type MilestoneCompletionConfig struct {
    Milestones        []Milestone    // Defined milestones
    RequireOrder      bool           // Must complete in order
    AllowPartial      bool           // Allow partial milestone credit
    VerificationMode  VerifyMode     // How to verify completion
}

type Milestone struct {
    MilestoneID       [16]byte
    Name              string
    Description       string
    ReleasePercentage float64        // Percentage of escrow to release
    Deadline          time.Duration  // Deadline from contract start
    Criteria          []string       // Completion criteria
}

type VerifyMode uint8

const (
    VerifyModeConsumerConfirm VerifyMode = 1 // Consumer confirms
    VerifyModeOracleAttest    VerifyMode = 2 // Oracle attests
    VerifyModeMultiSig        VerifyMode = 3 // Multi-sig approval
    VerifyModeAutomatic       VerifyMode = 4 // Automatic verification
)

func (c *MilestoneCompletionConfig) TriggerType() TriggerType {
    return TriggerMilestoneCompletion
}
```

### FINAL DESIGN: Automation Trigger Validation

To prevent ambiguous or malfunctioning triggers, all trigger configurations must include baseline values and validation:

```go
// TriggerValidationRules enforces trigger configuration requirements
type TriggerValidationRules struct {
    RequireBaselineValue     bool           // Require baseline for comparison
    RequireDataSource        bool           // Require explicit data source
    MaxFiringRate            time.Duration  // Max 1 fire per condition per hour
    RequireFallbackBehavior  bool           // What happens if data missing
}

// ValidateTriggerConfig ensures trigger is well-defined
func ValidateTriggerConfig(trigger *AutomationTrigger) error {
    // Check for ambiguous conditions
    if hasAmbiguousCondition(trigger) {
        return ErrAmbiguousTriggerCondition{
            TriggerID: trigger.TriggerID,
            Reason:    "trigger condition requires baseline value",
        }
    }

    // Enforce rapid firing prevention
    if trigger.LastEvaluated.Add(time.Hour).After(time.Now()) {
        return ErrTriggerFiringTooRapid{
            TriggerID:     trigger.TriggerID,
            LastFired:     trigger.LastEvaluated,
            MinInterval:   time.Hour,
        }
    }

    // Validate missing data handling
    if !hasMissingDataFallback(trigger) {
        return ErrMissingDataFallbackRequired{
            TriggerID: trigger.TriggerID,
        }
    }

    return nil
}

// hasAmbiguousCondition checks for conditions without baseline values
func hasAmbiguousCondition(trigger *AutomationTrigger) bool {
    switch config := trigger.Config.(type) {
    case *SLAPenaltyConfig:
        // SLA triggers MUST have baseline threshold
        if config.Threshold == 0 {
            return true
        }

    case *TimeBasedReleaseConfig:
        // Time triggers MUST have explicit duration
        if config.ReleaseAfter == 0 {
            return true
        }

    case *ProofOfServiceConfig:
        // Proof-of-service MUST have response timeout
        if config.ResponseTimeout == 0 {
            return true
        }
    }

    return false
}

// hasMissingDataFallback checks if trigger defines missing data behavior
func hasMissingDataFallback(trigger *AutomationTrigger) bool {
    // All triggers must define what happens if data source is unavailable
    for _, blocker := range trigger.Blockers {
        if blocker.Type == BlockerDataSourceUnavailable {
            return true
        }
    }
    return false
}

// TriggerFiringRateLimiter prevents rapid firing
type TriggerFiringRateLimiter struct {
    lastFired map[[16]byte]time.Time
    mu        sync.RWMutex
}

const MinTriggerInterval = 1 * time.Hour

// CanFire checks if trigger can fire based on rate limit
func (r *TriggerFiringRateLimiter) CanFire(triggerID [16]byte) bool {
    r.mu.RLock()
    defer r.mu.RUnlock()

    lastFired, exists := r.lastFired[triggerID]
    if !exists {
        return true // Never fired before
    }

    // Max 1 trigger fire per condition per hour
    return time.Since(lastFired) >= MinTriggerInterval
}

// RecordFiring records trigger execution
func (r *TriggerFiringRateLimiter) RecordFiring(triggerID [16]byte) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.lastFired[triggerID] = time.Now()
}

// MissingDataBehavior defines what happens when data is unavailable
type MissingDataBehavior uint8

const (
    MissingDataSkipTrigger   MissingDataBehavior = 1 // Skip execution, log warning
    MissingDataUseDefault    MissingDataBehavior = 2 // Use default value
    MissingDataFailContract  MissingDataBehavior = 3 // Terminate contract
    MissingDataWaitRetry     MissingDataBehavior = 4 // Wait and retry
)

// HandleMissingData processes missing data according to trigger policy
func HandleMissingData(trigger *AutomationTrigger, behavior MissingDataBehavior) error {
    switch behavior {
    case MissingDataSkipTrigger:
        log.Warn("trigger skipped due to missing data",
            "triggerID", trigger.TriggerID,
            "triggerName", trigger.Name)
        return nil

    case MissingDataUseDefault:
        // Use default value defined in trigger config
        log.Info("using default value for missing data",
            "triggerID", trigger.TriggerID)
        return nil

    case MissingDataFailContract:
        return ErrContractTerminatedDataUnavailable{
            TriggerID: trigger.TriggerID,
        }

    case MissingDataWaitRetry:
        // Schedule retry in 5 minutes
        ScheduleTriggerRetry(trigger, 5*time.Minute)
        return nil

    default:
        return ErrInvalidMissingDataBehavior{Behavior: behavior}
    }
}

// DisableTrigger allows parties to disable a trigger with mutual consent
func DisableTrigger(
    contractID [32]byte,
    triggerID [16]byte,
    providerSig []byte,
    consumerSig []byte,
) error {
    contract, err := GetContract(contractID)
    if err != nil {
        return err
    }

    // Verify both party signatures
    triggerHash := computeTriggerDisableHash(triggerID, contractID)
    if err := verifyTPMSignature(contract.Provider, triggerHash, providerSig); err != nil {
        return ErrInvalidProviderSignature{Cause: err}
    }
    if err := verifyTPMSignature(contract.Consumer, triggerHash, consumerSig); err != nil {
        return ErrInvalidConsumerSignature{Cause: err}
    }

    // Find and disable trigger
    for i := range contract.Escrow.AutomationTriggers {
        if contract.Escrow.AutomationTriggers[i].TriggerID == triggerID {
            contract.Escrow.AutomationTriggers[i].Enabled = false
            contract.Escrow.AutomationTriggers[i].Status = TriggerStatusCancelled

            log.Info("trigger disabled by mutual consent",
                "contractID", contractID,
                "triggerID", triggerID)

            return StoreContract(contract)
        }
    }

    return ErrTriggerNotFound{TriggerID: triggerID}
}
```

### FINAL DESIGN: Automated Action Appeals

Clients can appeal automated actions within 24 hours:

```go
// AutomatedActionAppeal allows disputing automated trigger execution
type AutomatedActionAppeal struct {
    AppealID         [32]byte
    ContractID       [32]byte
    TriggerID        [16]byte
    Action           TriggerAction        // Action being appealed
    Amount           uint64               // Amount affected
    Appellant        [32]byte             // Who is appealing (NodeID)
    Reason           string               // Why appeal is filed
    Evidence         []byte               // Supporting evidence
    FiledAt          time.Time
    AppealDeadline   time.Time            // 24 hours from action

    // Arbiter review
    ArbiterCommittee []NodeID
    ArbiterVotes     []ArbiterVote
    Resolution       *AppealResolution
}

const AppealWindow = 24 * time.Hour

// FileAutomatedActionAppeal creates appeal for automated action
func FileAutomatedActionAppeal(
    contractID [32]byte,
    triggerID [16]byte,
    reason string,
    evidence []byte,
) (*AutomatedActionAppeal, error) {
    contract, err := GetContract(contractID)
    if err != nil {
        return nil, err
    }

    // Find the trigger that was executed
    var trigger *AutomationTrigger
    for i := range contract.Escrow.AutomationTriggers {
        if contract.Escrow.AutomationTriggers[i].TriggerID == triggerID {
            trigger = &contract.Escrow.AutomationTriggers[i]
            break
        }
    }

    if trigger == nil {
        return nil, ErrTriggerNotFound{TriggerID: triggerID}
    }

    // Check if trigger was executed
    if trigger.Status != TriggerStatusExecuted {
        return nil, ErrTriggerNotExecuted{TriggerID: triggerID}
    }

    // Check appeal window (24 hours from execution)
    if time.Since(*trigger.ExecutedAt) > AppealWindow {
        return nil, ErrAppealWindowExpired{
            ExecutedAt: *trigger.ExecutedAt,
            FiledAt:    time.Now(),
        }
    }

    // Create appeal
    appeal := &AutomatedActionAppeal{
        AppealID:       generateAppealID(),
        ContractID:     contractID,
        TriggerID:      triggerID,
        Action:         trigger.Action,
        Amount:         trigger.Amount,
        Appellant:      contract.Consumer.NodeID, // Assume consumer for now
        Reason:         reason,
        Evidence:       evidence,
        FiledAt:        time.Now(),
        AppealDeadline: trigger.ExecutedAt.Add(AppealWindow),
    }

    // Select arbiter committee (same process as disputes)
    committee, err := SelectArbiterCommittee(contract.Escrow.EscrowID)
    if err != nil {
        return nil, err
    }
    appeal.ArbiterCommittee = committee

    // Store appeal
    if err := StoreAppeal(appeal); err != nil {
        return nil, err
    }

    // Notify arbiters
    NotifyArbiters(committee, appeal)

    log.Info("automated action appeal filed",
        "appealID", appeal.AppealID,
        "contractID", contractID,
        "triggerID", triggerID)

    return appeal, nil
}

// AppealResolution contains arbiter decision on appeal
type AppealResolution struct {
    Outcome          AppealOutcome
    Reason           string
    Compensation     uint64            // If trigger erroneous, 5% compensation
    ResolvedAt       time.Time
    ArbiterVotes     map[NodeID]*ArbiterVote
}

type AppealOutcome uint8

const (
    AppealOutcomeUpholdAction  AppealOutcome = 1 // Trigger was correct, no reversal
    AppealOutcomeReverseAction AppealOutcome = 2 // Trigger was erronous, reverse + compensate
    AppealOutcomePartialReverse AppealOutcome = 3 // Partial reversal
)

// ResolveAppeal processes arbiter votes on appeal
func ResolveAppeal(appeal *AutomatedActionAppeal) (*AppealResolution, error) {
    // Tally arbiter votes
    votes := make(map[AppealOutcome]int)
    for _, vote := range appeal.ArbiterVotes {
        outcome := vote.Decision.(AppealOutcome)
        votes[outcome]++
    }

    // Find majority outcome
    var majorityOutcome AppealOutcome
    var majorityCount int
    for outcome, count := range votes {
        if count > majorityCount {
            majorityOutcome = outcome
            majorityCount = count
        }
    }

    // Require quorum (5-of-7)
    if majorityCount < ArbiterQuorum {
        return nil, ErrNoQuorum{
            Required:  ArbiterQuorum,
            BestCount: majorityCount,
        }
    }

    resolution := &AppealResolution{
        Outcome:      majorityOutcome,
        ResolvedAt:   time.Now(),
        ArbiterVotes: make(map[NodeID]*ArbiterVote),
    }

    // Copy votes
    for _, vote := range appeal.ArbiterVotes {
        resolution.ArbiterVotes[vote.ArbiterID] = &vote
    }

    // Handle reversal
    if majorityOutcome == AppealOutcomeReverseAction {
        // Reverse automated action
        if err := ReverseAutomatedAction(appeal); err != nil {
            return nil, err
        }

        // Add 5% compensation to appellant
        contract, _ := GetContract(appeal.ContractID)
        compensation := uint64(float64(contract.Escrow.Amount) * 0.05)
        resolution.Compensation = compensation

        log.Info("automated action reversed with compensation",
            "appealID", appeal.AppealID,
            "compensation", compensation)
    }

    return resolution, nil
}

// ReverseAutomatedAction undoes a trigger execution
func ReverseAutomatedAction(appeal *AutomatedActionAppeal) error {
    contract, err := GetContract(appeal.ContractID)
    if err != nil {
        return err
    }

    switch appeal.Action {
    case ActionReleaseFunds:
        // Recall funds from provider, return to escrow
        return RecallFundsToEscrow(contract.Escrow.EscrowID, appeal.Amount)

    case ActionRefundFunds:
        // Recall refund from consumer, return to escrow
        return RecallFundsToEscrow(contract.Escrow.EscrowID, appeal.Amount)

    case ActionDeductPenalty:
        // Refund penalty to penalized party
        return RefundPenalty(contract.Escrow.EscrowID, appeal.Amount)

    default:
        return ErrActionNotReversible{Action: appeal.Action}
    }
}
```

### FINAL DESIGN: Renewal Procedures

Contracts can be configured for automatic renewal:

```go
// RenewalConfig defines contract renewal terms
type RenewalConfig struct {
    Enabled              bool
    AutoRenew            bool           // Automatic renewal
    RenewalDuration      time.Duration  // Duration of renewed term
    RenewalPrice         uint64         // Price for renewal (0 = same as original)
    PriceChangeNotice    time.Duration  // Notice period for price changes (7 days)
    RenegotiationWindow  time.Duration  // Window to renegotiate terms (14 days)
    GracePeriod          time.Duration  // Grace period after renewal failure (7 days)
    MaxRenewalAttempts   uint8          // Max retry attempts (3)
    RenewalRetryInterval time.Duration  // Time between retries (8 hours)
}

// DefaultRenewalConfig provides sensible defaults
var DefaultRenewalConfig = RenewalConfig{
    PriceChangeNotice:    7 * 24 * time.Hour,
    RenegotiationWindow:  14 * 24 * time.Hour,
    GracePeriod:          7 * 24 * time.Hour,
    MaxRenewalAttempts:   3,
    RenewalRetryInterval: 8 * time.Hour,
}

// RenewalState tracks renewal process
type RenewalState struct {
    ContractID           [32]byte
    RenewalAttempts      uint8
    LastAttemptAt        time.Time
    NextAttemptAt        time.Time
    GracePeriodEntered   bool
    GracePeriodExpiry    time.Time
    PriceChangeProposed  *PriceChangeProposal
    RenegotiationStarted bool
    ProviderEligible     bool          // Provider must be eligible at renewal
}

// PriceChangeProposal notifies consumer of price change
type PriceChangeProposal struct {
    NewPrice             uint64
    ProposedAt           time.Time
    EffectiveAt          time.Time     // 7 days notice
    ConsumerAcknowledged bool
    ConsumerSignature    []byte
}

// AttemptRenewal tries to renew contract
func AttemptRenewal(contract *ServiceContract) error {
    if !contract.RenewalTerms.Enabled || !contract.RenewalTerms.AutoRenew {
        return ErrRenewalNotEnabled{ContractID: contract.ContractID}
    }

    // Check provider eligibility
    provider, err := GetNodeIdentity(contract.Provider.NodeID)
    if err != nil {
        return err
    }

    // Provider must still be Trusted at renewal
    if provider.TrustLevel != TrustLevelTrusted {
        log.Warn("provider ineligible for renewal - contract will expire",
            "contractID", contract.ContractID,
            "providerID", provider.NodeID,
            "trustLevel", provider.TrustLevel)

        // Contract expires without renewal
        contract.Status = ContractStatusExpired
        return StoreContract(contract)
    }

    // Check for price change
    if contract.RenewalTerms.RenewalPrice != contract.PaymentTerms.Amount {
        // Price changed - require consumer acknowledgment
        if contract.renewalState.PriceChangeProposed == nil {
            // Create price change proposal
            return ProposePriceChange(contract)
        }

        // Check if consumer acknowledged
        if !contract.renewalState.PriceChangeProposed.ConsumerAcknowledged {
            return ErrPriceChangeNotAcknowledged{ContractID: contract.ContractID}
        }
    }

    // Attempt to charge renewal
    if err := ChargeRenewalPayment(contract); err != nil {
        // Renewal failed - enter retry mode
        return HandleRenewalFailure(contract, err)
    }

    // Success - renew contract
    contract.Status = ContractStatusActive
    contract.StartTime = time.Now()
    contract.Duration = contract.RenewalTerms.RenewalDuration

    log.Info("contract renewed successfully",
        "contractID", contract.ContractID,
        "newExpiry", contract.StartTime.Add(contract.Duration))

    return StoreContract(contract)
}

// ProposePriceChange notifies consumer of upcoming price change
func ProposePriceChange(contract *ServiceContract) error {
    proposal := &PriceChangeProposal{
        NewPrice:    contract.RenewalTerms.RenewalPrice,
        ProposedAt:  time.Now(),
        EffectiveAt: time.Now().Add(contract.RenewalTerms.PriceChangeNotice),
    }

    contract.renewalState.PriceChangeProposed = proposal

    // Notify consumer
    NotifyConsumer(contract.Consumer.NodeID, &PriceChangeNotification{
        ContractID:  contract.ContractID,
        OldPrice:    contract.PaymentTerms.Amount,
        NewPrice:    proposal.NewPrice,
        EffectiveAt: proposal.EffectiveAt,
        Message:     "Price will change in 7 days. Acknowledge to continue auto-renewal.",
    })

    return StoreContract(contract)
}

// HandleRenewalFailure manages failed renewal attempts
func HandleRenewalFailure(contract *ServiceContract, err error) error {
    state := &contract.renewalState
    state.RenewalAttempts++
    state.LastAttemptAt = time.Now()

    if state.RenewalAttempts >= contract.RenewalTerms.MaxRenewalAttempts {
        // All retries exhausted - enter grace period
        if !state.GracePeriodEntered {
            state.GracePeriodEntered = true
            state.GracePeriodExpiry = time.Now().Add(contract.RenewalTerms.GracePeriod)

            log.Warn("renewal failed, entering grace period",
                "contractID", contract.ContractID,
                "attempts", state.RenewalAttempts,
                "gracePeriodExpiry", state.GracePeriodExpiry)

            // Notify consumer
            NotifyConsumer(contract.Consumer.NodeID, &RenewalFailureNotification{
                ContractID:  contract.ContractID,
                Reason:      err.Error(),
                GracePeriod: contract.RenewalTerms.GracePeriod,
                ExpiresAt:   state.GracePeriodExpiry,
            })
        } else {
            // Grace period already entered, check if expired
            if time.Now().After(state.GracePeriodExpiry) {
                // Grace period expired - contract expires
                contract.Status = ContractStatusExpired
                log.Info("grace period expired, contract expired",
                    "contractID", contract.ContractID)
            }
        }
    } else {
        // Schedule retry
        state.NextAttemptAt = time.Now().Add(contract.RenewalTerms.RenewalRetryInterval)
        ScheduleRenewalRetry(contract, state.NextAttemptAt)

        log.Info("renewal retry scheduled",
            "contractID", contract.ContractID,
            "attempt", state.RenewalAttempts,
            "nextAttempt", state.NextAttemptAt)
    }

    return StoreContract(contract)
}

// ProposeRenegotiation allows either party to renegotiate terms before renewal
func ProposeRenegotiation(
    contractID [32]byte,
    proposerNodeID [32]byte,
    newTerms *ServiceContract,
) error {
    contract, err := GetContract(contractID)
    if err != nil {
        return err
    }

    // Check renegotiation window (14 days before expiry)
    timeUntilExpiry := time.Until(contract.StartTime.Add(contract.Duration))
    if timeUntilExpiry > contract.RenewalTerms.RenegotiationWindow {
        return ErrRenegotiationTooEarly{
            TimeUntilExpiry:      timeUntilExpiry,
            RenegotiationWindow:  contract.RenewalTerms.RenegotiationWindow,
        }
    }

    // Store proposed terms
    contract.renewalState.RenegotiationStarted = true

    // Notify other party
    otherParty := contract.Provider.NodeID
    if proposerNodeID == contract.Provider.NodeID {
        otherParty = contract.Consumer.NodeID
    }

    NotifyNode(otherParty, &RenegotiationNotification{
        ContractID:    contractID,
        ProposerID:    proposerNodeID,
        ProposedTerms: newTerms,
        Deadline:      contract.StartTime.Add(contract.Duration),
    })

    return StoreContract(contract)
}
```

### TriggerEngine Interface

The TriggerEngine evaluates and executes automation triggers:

```go
// TriggerEngine manages automation trigger evaluation and execution
type TriggerEngine interface {
    // Registration
    RegisterTrigger(ctx context.Context, contractID [32]byte, trigger *AutomationTrigger) error
    UnregisterTrigger(ctx context.Context, contractID [32]byte, triggerID [16]byte) error

    // Evaluation
    EvaluateTriggers(ctx context.Context, contractID [32]byte) ([]TriggerResult, error)
    EvaluateSingleTrigger(ctx context.Context, contractID [32]byte, triggerID [16]byte) (*TriggerResult, error)

    // Execution
    ExecuteTrigger(ctx context.Context, contractID [32]byte, triggerID [16]byte) (*ExecutionResult, error)

    // Queries
    GetTrigger(ctx context.Context, contractID [32]byte, triggerID [16]byte) (*AutomationTrigger, error)
    ListTriggers(ctx context.Context, contractID [32]byte) ([]*AutomationTrigger, error)
    GetTriggerHistory(ctx context.Context, contractID [32]byte) ([]*TriggerExecution, error)

    // Scheduling
    ScheduleEvaluation(ctx context.Context, contractID [32]byte, interval time.Duration) error
    CancelSchedule(ctx context.Context, contractID [32]byte) error
}

// TriggerResult represents the outcome of trigger evaluation
type TriggerResult struct {
    TriggerID      [16]byte
    TriggerType    TriggerType
    ShouldExecute  bool              // Whether trigger should fire
    Reason         string            // Reason for decision
    BlockedBy      *TriggerCondition // Blocking condition (if blocked)
    MetricValues   map[string]float64 // Measured values
    EvaluatedAt    time.Time
}

// ExecutionResult represents the outcome of trigger execution
type ExecutionResult struct {
    TriggerID      [16]byte
    Success        bool
    Action         TriggerAction
    Amount         uint64            // Amount transferred
    Recipient      RecipientType
    TransactionID  [32]byte          // Escrow transaction ID
    Error          error             // Error if failed
    ExecutedAt     time.Time
}

// TriggerExecution records trigger execution history
type TriggerExecution struct {
    ExecutionID    [16]byte
    ContractID     [32]byte
    TriggerID      [16]byte
    Result         *ExecutionResult
    TPMAttestation []byte            // TPM quote of execution
    Timestamp      time.Time
}
```

### Trigger Evaluation Flow

```
                    TRIGGER EVALUATION FLOW

Contract Created                    Contract Active
      |                                  |
      v                                  v
+-----------+                   +-----------+
|  Register   |                   |  Schedule   |
|  Triggers   |----------------->|  Evaluator  |
+-----------+                   +------+------+
                                         |
                                         v
                                  +-----------+
                                  |  Evaluate   |<-----+
                                  |  All Active |      |
                                  |  Triggers   |      |
                                  +------+------+      |
                                         |             |
                          +--------------+--------------+
                          |              |              |
                          v              v              v
                   +-----------+  +-----------+  +-----------+
                   |  Check    |  |  Check    |  |  Check    |
                   |  Time     |  |  SLA      |  |  Oracle   |
                   |  Triggers |  |  Triggers |  |  Triggers |
                   +-----+-----+  +-----+-----+  +-----+-----+
                         |              |              |
                         +--------------+--------------+
                                        v
                                 +-----------+
                                 |   Check     |
                                 | Prerequisites|
                                 |  & Blockers |
                                 +------+------+
                                        |
                         +--------------+--------------+
                         |                             |
                    Satisfied                     Not Ready
                         |                             |
                         v                             v
                  +-----------+              +-----------+
                  |   Execute   |              |   Skip &    |
                  |   Action    |              |   Reschedule|
                  +------+------+              +------+------+
                         |                             |
                         v                             |
                  +-----------+                      |
                  |  Update     |                      |
                  |  Escrow     |                      |
                  +------+------+                      |
                         |                             |
                         v                             |
                  +-----------+                      |
                  |   Record    |                      |
                  |   History   |----------------------+
                  +-----------+
```

### Default Trigger Engine Implementation

```go
// DefaultTriggerEngine implements TriggerEngine
type DefaultTriggerEngine struct {
    dht           DHT
    escrow        EscrowService
    metrics       MetricsCollector
    oracles       OracleRegistry
    scheduler     *time.Ticker
    mu            sync.RWMutex
}

// EvaluateTriggers checks all triggers for a contract
func (e *DefaultTriggerEngine) EvaluateTriggers(ctx context.Context, contractID [32]byte) ([]TriggerResult, error) {
    triggers, err := e.ListTriggers(ctx, contractID)
    if err != nil {
        return nil, ErrTriggerListFailed{Cause: err}
    }

    // Sort by priority
    sort.Slice(triggers, func(i, j int) bool {
        return triggers[i].Priority < triggers[j].Priority
    })

    results := make([]TriggerResult, 0, len(triggers))
    for _, trigger := range triggers {
        if !trigger.Enabled || trigger.Status == TriggerStatusExecuted {
            continue
        }

        result, err := e.evaluateTrigger(ctx, contractID, trigger)
        if err != nil {
            result = &TriggerResult{
                TriggerID:     trigger.TriggerID,
                TriggerType:   trigger.Type,
                ShouldExecute: false,
                Reason:        err.Error(),
                EvaluatedAt:   time.Now(),
            }
        }
        results = append(results, *result)
    }

    return results, nil
}

// evaluateTrigger evaluates a single trigger
func (e *DefaultTriggerEngine) evaluateTrigger(ctx context.Context, contractID [32]byte, trigger *AutomationTrigger) (*TriggerResult, error) {
    result := &TriggerResult{
        TriggerID:    trigger.TriggerID,
        TriggerType:  trigger.Type,
        MetricValues: make(map[string]float64),
        EvaluatedAt:  time.Now(),
    }

    // Check prerequisites
    for _, prereq := range trigger.Prerequisites {
        satisfied, err := e.checkCondition(ctx, contractID, prereq)
        if err != nil {
            return nil, err
        }
        if !satisfied {
            result.ShouldExecute = false
            result.Reason = "prerequisite not satisfied: " + prereq.Description
            return result, nil
        }
    }

    // Check blockers
    for _, blocker := range trigger.Blockers {
        blocked, err := e.checkCondition(ctx, contractID, blocker)
        if err != nil {
            return nil, err
        }
        if blocked {
            result.ShouldExecute = false
            result.Reason = "blocked by: " + blocker.Description
            result.BlockedBy = &blocker
            return result, nil
        }
    }

    // Evaluate type-specific condition
    shouldExecute, reason, metrics := e.evaluateTypeSpecific(ctx, contractID, trigger)
    result.ShouldExecute = shouldExecute
    result.Reason = reason
    result.MetricValues = metrics

    return result, nil
}

// ExecuteTrigger executes a trigger action
func (e *DefaultTriggerEngine) ExecuteTrigger(ctx context.Context, contractID [32]byte, triggerID [16]byte) (*ExecutionResult, error) {
    trigger, err := e.GetTrigger(ctx, contractID, triggerID)
    if err != nil {
        return nil, err
    }

    // Verify trigger should execute
    evalResult, err := e.EvaluateSingleTrigger(ctx, contractID, triggerID)
    if err != nil {
        return nil, err
    }
    if !evalResult.ShouldExecute {
        return nil, ErrTriggerNotReady{Reason: evalResult.Reason}
    }

    // Execute action
    result := &ExecutionResult{
        TriggerID:  triggerID,
        Action:     trigger.Action,
        Recipient:  trigger.Recipient,
        ExecutedAt: time.Now(),
    }

    amount := trigger.Amount
    if amount == 0 {
        // Full escrow amount
        contract, _ := e.getContract(ctx, contractID)
        amount = contract.Escrow.EscrowAmount
    }
    result.Amount = amount

    switch trigger.Action {
    case ActionReleaseFunds:
        txID, err := e.escrow.Release(ctx, contractID, trigger.Recipient, amount)
        result.TransactionID = txID
        result.Error = err
        result.Success = err == nil

    case ActionRefundFunds:
        txID, err := e.escrow.Refund(ctx, contractID, amount)
        result.TransactionID = txID
        result.Error = err
        result.Success = err == nil

    case ActionDeductPenalty:
        txID, err := e.escrow.DeductPenalty(ctx, contractID, amount, trigger.Recipient)
        result.TransactionID = txID
        result.Error = err
        result.Success = err == nil

    case ActionSplitFunds:
        txID, err := e.escrow.Split(ctx, contractID, evalResult.MetricValues["split_ratio"])
        result.TransactionID = txID
        result.Error = err
        result.Success = err == nil
    }

    // Update trigger status
    if result.Success {
        e.updateTriggerStatus(ctx, contractID, triggerID, TriggerStatusExecuted)
    }

    // Record execution history
    e.recordExecution(ctx, contractID, result)

    return result, nil
}
```

### Escrow Integration

The EscrowConfig is extended with automation triggers:

```go
// EscrowConfig extended with automation triggers
type EscrowConfig struct {
    // Existing fields...
    EscrowID          [32]byte
    EscrowAmount      uint64
    Currency          string
    ReleaseConditions []ReleaseCondition
    PartialReleaseAllowed bool
    DisputeWindow     time.Duration
    DisputeDeadline   time.Time
    ArbiterPool       []NodeIdentity
    ArbiterFee        uint64

    // Automation Extension
    AutomationTriggers []AutomationTrigger  // Registered automation triggers
    TriggerPrecedence  TriggerPrecedence    // How triggers interact
    EvaluationInterval time.Duration         // How often to evaluate triggers
}

// TriggerPrecedence defines how automated vs manual actions interact
type TriggerPrecedence uint8

const (
    // Manual confirmation always overrides automation
    PrecedenceManualFirst TriggerPrecedence = 1

    // First valid trigger wins (manual or automated)
    PrecedenceFirstValid TriggerPrecedence = 2

    // Automated triggers can execute but manual can override
    PrecedenceAutoWithOverride TriggerPrecedence = 3
)
```

### Automation Coverage by Service Type

| Service Type | Automatable (%) | Primary Triggers | Human Judgment Required |
|--------------|-----------------|------------------|-------------------------|
| **Agent** | 35-40% | Milestone completion, token usage | Quality assessment, accuracy disputes |
| **Compute** | 65-70% | SLA metrics, uptime, latency | Resource contention, config disputes |
| **Storage** | 80-85% | Proof of storage, bandwidth | Data integrity claims |
| **E-Commerce** | 40-45% | Shipping oracle, timeout refund | "Item not as described" |
| **Network** | 75-80% | Latency proofs, bandwidth verification | Quality of service disputes |

### What Cannot Be Automated

The following dispute types always require human arbitration:

| Category | Examples | Reason |
|----------|----------|--------|
| **Quality Disputes** | "AI output was wrong", "Code doesn't work" | Subjective assessment required |
| **Accuracy Claims** | "Data was corrupted", "Wrong results" | Evidence interpretation needed |
| **Fraud Allegations** | "Provider never intended to deliver" | Intent determination required |
| **Best Effort Assessment** | "Provider didn't try hard enough" | Judgment of effort required |
| **Contract Interpretation** | Ambiguous terms, edge cases | Legal reasoning required |
| **Novel Situations** | Unforeseen circumstances | No predefined rule exists |

---

## OPA/Rego Custom Conditions (Phase 2)

For contracts requiring custom logic beyond predefined triggers, the platform supports OPA/Rego policy conditions with bounded execution.

### Custom Condition Framework

```go
// CustomCondition defines a Rego-based condition for escrow actions
type CustomCondition struct {
    // Policy Identity
    PolicyID      [32]byte          // SHA256 hash of policy source
    Name          string            // Human-readable name
    Version       uint32            // Policy version

    // Policy Definition
    Policy        string            // Rego policy source code
    InputSchema   JSONSchema        // Required input structure
    OutputSchema  JSONSchema        // Expected output structure

    // Constraints
    MaxExecutionTime time.Duration  // Maximum evaluation time (default: 100ms)
    MaxMemory        uint64         // Maximum memory usage (default: 10MB)
    AllowedBuiltins  []string       // Allowed Rego builtins

    // Audit
    Audited       bool              // Community-audited policy
    AuditHash     [32]byte          // Hash of audited version
    AuditorIDs    [][32]byte        // Node IDs of auditors
}

// RegoConstraints defines execution limits for Rego policies
var RegoConstraints = struct {
    MaxPolicySize      int           // 4KB maximum
    MaxExecutionTime   time.Duration // 100ms timeout
    MaxMemory          uint64        // 10MB max
    ProhibitedBuiltins []string      // Blocked builtins
}{
    MaxPolicySize:    4096,
    MaxExecutionTime: 100 * time.Millisecond,
    MaxMemory:        10 * 1024 * 1024,
    ProhibitedBuiltins: []string{
        "http.send",       // No network calls
        "opa.runtime",     // No runtime introspection
        "trace",           // No debugging
    },
}
```

### Example Rego Policies

**Multi-Condition Release**:
```rego
package contract.release

default allow = false

# Release when both time elapsed AND consumer confirmed
allow {
    input.time_elapsed >= input.contract.minimum_duration
    input.consumer_confirmed == true
    not input.dispute_open
}

# Alternative: Release with multi-sig even without confirmation
allow {
    count({s | input.signatures[s].valid}) >= input.contract.required_signatures
    not input.dispute_open
}
```

**Graduated SLA Penalty**:
```rego
package contract.penalty

# Calculate penalty based on SLA violation severity
penalty_amount = amount {
    guaranteed := input.contract.sla.uptime_guaranteed
    actual := input.metrics.uptime_actual
    shortfall := guaranteed - actual

    # Tiered penalty calculation
    shortfall <= 0.01   # 1% shortfall
    amount = input.escrow_amount * 0.05  # 5% penalty

} else = amount {
    guaranteed := input.contract.sla.uptime_guaranteed
    actual := input.metrics.uptime_actual
    shortfall := guaranteed - actual

    shortfall <= 0.05   # 5% shortfall
    amount = input.escrow_amount * 0.15  # 15% penalty

} else = amount {
    # >5% shortfall = 30% penalty + potential termination
    amount = input.escrow_amount * 0.30
}
```

**Oracle Consensus**:
```rego
package contract.oracle

default delivery_confirmed = false

# Require 2-of-3 oracles to confirm delivery
delivery_confirmed {
    confirmations := {o | input.oracles[o].confirmed == true}
    count(confirmations) >= 2
}

# All oracles must report within window
oracles_valid {
    now := time.now_ns()
    window := input.contract.oracle_window_ns

    all_reported := {o |
        input.oracles[o].reported_at > 0
        (now - input.oracles[o].reported_at) < window
    }
    count(all_reported) == count(input.oracles)
}
```

### Policy Evaluation Integration

```go
// PolicyEngine evaluates Rego policies for contracts
type PolicyEngine interface {
    // Load and validate policy
    LoadPolicy(ctx context.Context, condition *CustomCondition) error
    ValidatePolicy(policy string) error

    // Evaluation
    Evaluate(ctx context.Context, policyID [32]byte, input map[string]interface{}) (*PolicyResult, error)

    // Registry
    RegisterPolicy(ctx context.Context, condition *CustomCondition) error
    GetPolicy(ctx context.Context, policyID [32]byte) (*CustomCondition, error)
}

// PolicyResult contains the outcome of policy evaluation
type PolicyResult struct {
    PolicyID      [32]byte
    Decision      bool              // Main decision (allow/deny)
    Outputs       map[string]interface{} // Additional outputs
    Bindings      map[string]interface{} // Variable bindings
    EvaluationTime time.Duration
    Error         error
}

// ContractPolicyInput provides standard input for contract policies
type ContractPolicyInput struct {
    Contract         *ServiceContract
    EscrowAmount     uint64
    TimeElapsed      time.Duration
    ConsumerConfirmed bool
    DisputeOpen      bool
    Signatures       map[string]SignatureStatus
    Metrics          map[string]float64
    Oracles          map[string]OracleReport
    Milestones       map[string]MilestoneStatus
    CustomData       map[string]interface{}
}
```

---

## SLA Terms

```go
// SLATerms defines service level agreement parameters
type SLATerms struct {
    // Availability
    UptimeGuarantee   float64           // Guaranteed uptime (0.50-0.99999)
    MaintenanceWindow time.Duration     // Allowed maintenance window

    // Performance
    ResponseTime      time.Duration     // Maximum response time
    Throughput        uint64            // Minimum throughput
    ThroughputUnit    string            // Throughput unit (requests/sec, MB/s)

    // Support
    SupportLevel      SupportLevel      // Support tier
    ResponseTimeSLA   time.Duration     // Support response time

    // Compensation
    Penalties         []SLAPenalty      // SLA violation penalties
    ServiceCredits    bool              // Offer service credits for violations
}

// SupportLevel defines support tiers
type SupportLevel uint8

const (
    SupportLevelNone     SupportLevel = 0 // No support
    SupportLevelBasic    SupportLevel = 1 // Basic (email, 48h response)
    SupportLevelStandard SupportLevel = 2 // Standard (24h response)
    SupportLevelPremium  SupportLevel = 3 // Premium (4h response)
    SupportLevel24x7     SupportLevel = 4 // 24x7 (1h response)
)

// SLAPenalty defines penalty for SLA violation
type SLAPenalty struct {
    Condition         string            // Violation condition
    Threshold         float64           // Threshold for violation
    Compensation      float64           // Compensation percentage
    CreditDays        uint16            // Service credit days
}
```

---

## Contract Signatures

```go
// ContractSignatures contains TPM-signed signatures from both parties
type ContractSignatures struct {
    // Provider Signature
    ProviderSignature []byte            // Provider's TPM-signed signature
    ProviderSignedAt  time.Time
    ProviderTPMQuote  []byte            // Fresh TPM attestation

    // Consumer Signature
    ConsumerSignature []byte            // Consumer's TPM-signed signature
    ConsumerSignedAt  time.Time
    ConsumerTPMQuote  []byte            // Fresh TPM attestation

    // Witness Signatures (optional)
    Witnesses         []WitnessSignature
}

// WitnessSignature records a third-party witness
type WitnessSignature struct {
    WitnessNodeID     [32]byte
    Signature         []byte
    SignedAt          time.Time
}

// SignContract adds a party's signature to the contract
func SignContract(contract *ServiceContract, signer *Node, role string) error {
    // Generate signing payload
    payload := GenerateSigningPayload(contract)

    // Get fresh TPM quote
    quote, err := signer.TPM.Quote(payload)
    if err != nil {
        return ErrTPMQuoteFailed{Cause: err}
    }

    // Sign with TPM-backed key
    signature, err := signer.SignWithIDevID(payload)
    if err != nil {
        return ErrSigningFailed{Cause: err}
    }

    switch role {
    case "provider":
        contract.Signatures.ProviderSignature = signature
        contract.Signatures.ProviderSignedAt = time.Now()
        contract.Signatures.ProviderTPMQuote = quote
    case "consumer":
        contract.Signatures.ConsumerSignature = signature
        contract.Signatures.ConsumerSignedAt = time.Now()
        contract.Signatures.ConsumerTPMQuote = quote
    default:
        return ErrInvalidSignerRole{Role: role}
    }

    return nil
}

// GenerateSigningPayload creates deterministic payload for signing
func GenerateSigningPayload(contract *ServiceContract) []byte {
    h := sha256.New()
    h.Write(contract.ContractID[:])
    h.Write([]byte{contract.Version})
    h.Write(contract.Provider.NodeID[:])
    h.Write(contract.Consumer.NodeID[:])
    h.Write([]byte{byte(contract.ServiceType)})

    // Include service terms hash
    termsBytes, _ := contract.ServiceTerms.Serialize()
    termsHash := sha256.Sum256(termsBytes)
    h.Write(termsHash[:])

    // Include economics
    binary.Write(h, binary.BigEndian, contract.PaymentTerms.BasePrice)
    binary.Write(h, binary.BigEndian, contract.Escrow.EscrowAmount)

    // Include timeline
    binary.Write(h, binary.BigEndian, contract.StartTime.Unix())
    binary.Write(h, binary.BigEndian, int64(contract.Duration))

    return h.Sum(nil)
}
```

---

## DHT Key Patterns

ServiceContracts are stored under multiple DHT keys for efficient retrieval:

| Purpose | Key Pattern | Description |
|---------|-------------|-------------|
| Contract by ID | `contract:{contract-id}` | Direct access by contract ID |
| Provider contracts | `contract:provider:{node-id}` | All contracts for a provider |
| Consumer contracts | `contract:consumer:{node-id}` | All contracts for a consumer |
| Contracts by type | `contract:type:{service-type}` | Contracts by service type |
| Contract escrow | `contract:escrow:{contract-id}` | Escrow account for contract |
| Service mapping | `service:{service-id}:contract:{contract-id}` | Links service to contract |
| Active contracts | `contract:active:{node-id}` | Active contracts for node |

### Key Format Examples

```go
// Contract key format
func ContractKey(contractID [32]byte) string {
    return fmt.Sprintf("contract:%x", contractID)
}

// Provider contracts index
func ProviderContractsKey(nodeID [32]byte) string {
    return fmt.Sprintf("contract:provider:%x", nodeID)
}

// Consumer contracts index
func ConsumerContractsKey(nodeID [32]byte) string {
    return fmt.Sprintf("contract:consumer:%x", nodeID)
}

// Service type index
func ContractTypeKey(serviceType ServiceType, contractID [32]byte) string {
    return fmt.Sprintf("contract:type:%d:%x", serviceType, contractID)
}

// Escrow key format
func ContractEscrowKey(contractID [32]byte) string {
    return fmt.Sprintf("contract:escrow:%x", contractID)
}

// Service-to-contract mapping
func ServiceContractKey(serviceID [32]byte, contractID [32]byte) string {
    return fmt.Sprintf("service:%x:contract:%x", serviceID, contractID)
}
```

---

## Contract Lifecycle

```
                         CONTRACT LIFECYCLE

  +------------+         +-------------+         +------------+
  |   DRAFT    |-------->| PROPOSED    |-------->| NEGOTIATING|
  | (Provider  |         | (Awaiting   |         | (Counter-  |
  |  creates)  |         |  consumer)  |         |  offers)   |
  +------------+         +-------------+         +------+-----+
                                                        |
                                                        v
  +------------+         +-------------+         +------+-----+
  | TERMINATED |<--------| DISPUTED    |<--------| AGREED     |
  | (Contract  |         | (Under      |         | (Both      |
  |  ended)    |         |  arbitration)|        |  signed)   |
  +------+-----+         +------+------+         +------+-----+
         ^                      |                       |
         |                      |                       v
  +------+-----+         +------+------+         +------+-----+
  | SUSPENDED  |<------->|  COMPLETED  |<--------| ACTIVE     |
  | (Temp.     |         | (Service    |         | (Service   |
  |  paused)   |         |  delivered) |         |  running)  |
  +------------+         +-------------+         +------------+
```

### State Transitions

| From | To | Trigger | Requirements |
|------|-----|---------|-------------|
| Draft | Proposed | Provider submits | Provider signature |
| Proposed | Negotiating | Consumer counters | Counter-offer |
| Proposed | Agreed | Consumer accepts | Consumer signature |
| Negotiating | Agreed | Terms accepted | Both signatures |
| Agreed | Active | Start time reached | Escrow funded |
| Active | Completed | Duration elapsed | Deliverables confirmed |
| Active | Disputed | Party opens dispute | Evidence submitted |
| Active | Suspended | Maintenance/issue | Either party request |
| Suspended | Active | Issue resolved | Resumption confirmation |
| Disputed | Completed | Arbiter decides | Arbiter ruling |
| Disputed | Terminated | Breach confirmed | Arbiter ruling |
| Any | Terminated | Early termination | Penalty payment |

### Lifecycle Implementation

```go
// ContractStateMachine manages contract state transitions
type ContractStateMachine struct {
    contract *ServiceContract
    dht      DHT
    escrow   EscrowService
}

// Propose transitions from Draft to Proposed
func (sm *ContractStateMachine) Propose() error {
    if sm.contract.Status != ContractStatusDraft {
        return ErrInvalidStateTransition{
            Current:  sm.contract.Status,
            Expected: ContractStatusDraft,
        }
    }

    // Verify provider signature exists
    if len(sm.contract.Signatures.ProviderSignature) == 0 {
        return ErrProviderSignatureRequired
    }

    sm.contract.Status = ContractStatusProposed
    sm.contract.UpdatedAt = time.Now()

    return sm.save()
}

// Accept transitions from Proposed to Agreed
func (sm *ContractStateMachine) Accept(consumerSig []byte, tpmQuote []byte) error {
    if sm.contract.Status != ContractStatusProposed {
        return ErrInvalidStateTransition{
            Current:  sm.contract.Status,
            Expected: ContractStatusProposed,
        }
    }

    sm.contract.Signatures.ConsumerSignature = consumerSig
    sm.contract.Signatures.ConsumerSignedAt = time.Now()
    sm.contract.Signatures.ConsumerTPMQuote = tpmQuote
    sm.contract.Status = ContractStatusAgreed
    sm.contract.UpdatedAt = time.Now()

    return sm.save()
}

// Activate transitions from Agreed to Active
func (sm *ContractStateMachine) Activate() error {
    if sm.contract.Status != ContractStatusAgreed {
        return ErrInvalidStateTransition{
            Current:  sm.contract.Status,
            Expected: ContractStatusAgreed,
        }
    }

    // Verify escrow is funded
    funded, err := sm.escrow.IsFunded(sm.contract.Escrow.EscrowID)
    if err != nil {
        return ErrEscrowCheckFailed{Cause: err}
    }
    if !funded {
        return ErrEscrowNotFunded
    }

    // Verify start time
    if time.Now().Before(sm.contract.StartTime) {
        return ErrContractNotYetActive
    }

    sm.contract.Status = ContractStatusActive
    sm.contract.UpdatedAt = time.Now()

    return sm.save()
}

// Complete transitions from Active to Completed
func (sm *ContractStateMachine) Complete() error {
    if sm.contract.Status != ContractStatusActive {
        return ErrInvalidStateTransition{
            Current:  sm.contract.Status,
            Expected: ContractStatusActive,
        }
    }

    // Release escrow to provider
    if err := sm.escrow.Release(sm.contract.Escrow.EscrowID); err != nil {
        return ErrEscrowReleaseFailed{Cause: err}
    }

    sm.contract.Status = ContractStatusCompleted
    sm.contract.UpdatedAt = time.Now()

    return sm.save()
}

// Dispute transitions from Active to Disputed
func (sm *ContractStateMachine) Dispute(reason string, evidence []byte) error {
    if sm.contract.Status != ContractStatusActive {
        return ErrInvalidStateTransition{
            Current:  sm.contract.Status,
            Expected: ContractStatusActive,
        }
    }

    // Verify within dispute window
    if time.Now().After(sm.contract.Escrow.DisputeDeadline) {
        return ErrDisputeWindowExpired
    }

    sm.contract.Status = ContractStatusDisputed
    sm.contract.UpdatedAt = time.Now()

    // Initiate arbitration
    return sm.initiateArbitration(reason, evidence)
}
```

---

## Dispute Resolution

### DisputeConfig Structure

```go
// ArbitratorType defines the type of arbitrator for dispute resolution
type ArbitratorType uint8

const (
    ArbitratorTypeHuman  ArbitratorType = 1 // Human arbiters only (VRF-selected pool)
    ArbitratorTypeAI     ArbitratorType = 2 // AI agents only (VRF-selected pool)
    ArbitratorTypeHybrid ArbitratorType = 3 // AI pre-screening with human final decision
)

// DisputeConfig defines arbitration parameters
type DisputeConfig struct {
    // Arbitrator Type Selection (CANONICAL)
    ArbitratorType    ArbitratorType    // Human, AI, or Hybrid arbitration
    AIConfig          *AIArbitratorConfig // AI-specific configuration (if AI or Hybrid)

    // Arbitration Pool
    ArbitrationPool   [][32]byte        // Candidate arbiter node IDs
    ArbiterCount      uint8             // Number of arbiters (default: 7 per E1 fix)
    ArbiterQuorum     uint8             // Votes needed for decision (default: 5)

    // Timing
    DisputeWindow     time.Duration     // Window to open dispute (48h default)
    ResolutionDeadline time.Duration    // Deadline for arbiter decision

    // Process
    EvidenceDeadline  time.Duration     // Deadline for evidence submission
    AppealAllowed     bool              // Allow appeal of decision (always true for AI)
    AppealWindow      time.Duration     // Window for appeal

    // Economics
    ArbiterFee        uint64            // Fee per arbiter
    ArbiterStake      uint64            // Required stake from each arbiter (5000 coins per E1)
    LoserPays         bool              // Losing party pays arbiter fees
}

// AIArbitratorConfig defines AI-specific arbitration settings
type AIArbitratorConfig struct {
    // Confidence Threshold
    ConfidenceThreshold float64         // Min confidence for AI decision (default: 0.85)
    AutoEscalate        bool            // Auto-escalate low-confidence to human (default: true)

    // AI Agent Selection
    RequiredCapabilities []string       // Required AI capabilities (e.g., "arbitration", "evidence_evaluation")
    MinAgentReputation   float64        // Minimum AI agent reputation (default: 0.90)
    MinAgentAge          time.Duration  // Minimum agent age (default: 30 days)

    // Appeal Settings
    AIAppealToHuman     bool            // Allow appeal from AI to human arbiters (default: true)
    HumanAppealDeadline time.Duration   // Deadline for human appeal (default: 48h)
}

// DefaultAIArbitratorConfig provides sensible defaults for AI arbitration
var DefaultAIArbitratorConfig = AIArbitratorConfig{
    ConfidenceThreshold:  0.85,
    AutoEscalate:         true,
    RequiredCapabilities: []string{"arbitration", "evidence_evaluation", "dispute_analysis"},
    MinAgentReputation:   0.90,
    MinAgentAge:          30 * 24 * time.Hour,
    AIAppealToHuman:      true,
    HumanAppealDeadline:  48 * time.Hour,
}

// For complete AI arbitration system details, see: 21-ai-arbitration-system.md
```

### Arbitration Process

```
                      DISPUTE RESOLUTION FLOW

Consumer                   Arbiters                    Provider
--------                   --------                    --------

   |                          |                           |
   | 1. Open Dispute          |                           |
   |------------------------->|                           |
   |   (reason + evidence)    |                           |
   |                          |                           |
   |                          | 2. Select 5 Arbiters      |
   |                          |   (VRF-based)             |
   |                          |                           |
   |                          | 3. Notify Parties         |
   |<-------------------------|-------------------------->|
   |                          |                           |
   | 4. Submit Evidence       |   4. Submit Evidence      |
   |------------------------->|<--------------------------|
   |   (72h deadline)         |                           |
   |                          |                           |
   |                     +----+----+                      |
   |                     |  REVIEW |                      |
   |                     | Evidence|                      |
   |                     +----+----+                      |
   |                          |                           |
   |                     +----+----+                      |
   |                     |  VOTE   |                      |
   |                     | 5-of-7  |                      |
   |                     +----+----+                      |
   |                          |                           |
   |                     +----+----+                      |
   |                     | DECISION|                      |
   |                     +---------+                      |
   |                          |                           |
   | 5. Execute Decision      |   5. Execute Decision     |
   |<-------------------------|-------------------------->|
   |   (release/refund/split) |                           |
   |                          |                           |
```

### Arbiter Selection (CANONICAL)

```go
// ArbiterEligibility defines who can serve as arbiter for contracts
type ArbiterEligibility struct {
    MinReputation     float64           // 0.80+ required
    MinUptime         float64           // 99% required
    MaxActiveDisputes int               // Maximum 10 concurrent disputes
    MinNetworkAge     time.Duration     // 90 days minimum
    NotInvolved       bool              // Cannot be contract party
}

var DefaultArbiterEligibility = ArbiterEligibility{
    MinReputation:     0.80,
    MinUptime:         0.99,
    MaxActiveDisputes: 10,
    MinNetworkAge:     90 * 24 * time.Hour,
    NotInvolved:       true,
}

// SelectArbiters uses VRF to select arbiters for a contract dispute
func SelectArbiters(contract *ServiceContract, count int) ([]NodeIdentity, error) {
    // Generate VRF seed from contract ID and dispute timestamp
    seed := GenerateArbiterSeed(contract.ContractID, time.Now())

    // Get eligible arbiters
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)

    // Filter out contract parties
    candidates = FilterOutParties(candidates, contract.Provider.NodeID, contract.Consumer.NodeID)

    if len(candidates) < count {
        return nil, ErrInsufficientArbiters{
            Required:  count,
            Available: len(candidates),
        }
    }

    // Select with VRF and diversity requirements
    return SelectWithDiversity(seed, candidates, count)
}

// GenerateArbiterSeed creates deterministic seed for arbiter selection
func GenerateArbiterSeed(contractID [32]byte, timestamp time.Time) []byte {
    h := sha256.New()
    h.Write(contractID[:])
    binary.Write(h, binary.BigEndian, timestamp.Unix())
    h.Write([]byte("contract_arbiter_selection"))
    return h.Sum(nil)
}
```

### Arbiter Selection and Anti-Collusion

Arbiter selection uses multi-layered collusion prevention with stake requirements, reputation, and behavioral analysis.

```go
// Enhanced ArbiterConfig with collusion prevention
type CollusionResistantArbiterConfig struct {
    // Increased Quorum (CANONICAL)
    ArbiterCount      uint8   // Increased to 7 (from 5)
    ArbiterQuorum     uint8   // Increased to 5 (from 3) - 71% threshold

    // Stake Requirements
    MinArbiterStake   uint64  // 10,000 coins minimum stake
    StakeAtRisk       float64 // 50% of stake at risk during dispute

    // Selection Constraints
    MaxSameRegion     uint8   // Max 2 arbiters from same region
    MaxSameVendor     uint8   // Max 2 arbiters with same TPM vendor
    MinRepSpread      float64 // Min 0.05 reputation spread
    MaxDisputes       uint8   // Max disputes in flight per arbiter

    // Behavioral Analysis
    CollisionCooldown time.Duration // Min time between same arbiter pairs
}

var DefaultCollusionResistantConfig = CollusionResistantArbiterConfig{
    ArbiterCount:      7,
    ArbiterQuorum:     5,
    MinArbiterStake:   10000,
    StakeAtRisk:       0.5,
    MaxSameRegion:     2,
    MaxSameVendor:     2,
    MinRepSpread:      0.05,
    MaxDisputes:       5,
    CollisionCooldown: 7 * 24 * time.Hour,  // 7 days
}

// SelectCollusionResistantArbiters ensures diverse, independent arbiters
func SelectCollusionResistantArbiters(contract *ServiceContract, config CollusionResistantArbiterConfig) ([]NodeIdentity, error) {
    seed := GenerateArbiterSeed(contract.ContractID, time.Now())
    candidates := GetEligibleArbiters(DefaultArbiterEligibility)

    // Filter out contract parties
    candidates = FilterOutParties(candidates, contract.Provider.NodeID, contract.Consumer.NodeID)

    // Filter by stake requirement
    candidates = FilterByMinStake(candidates, config.MinArbiterStake)

    // Apply diversity constraints during selection
    selected := make([]NodeIdentity, 0, config.ArbiterCount)
    regionCount := make(map[string]int)
    vendorCount := make(map[string]int)

    vrfOrder := VRFSortCandidates(seed, candidates)
    for _, candidate := range vrfOrder {
        if len(selected) >= int(config.ArbiterCount) {
            break
        }

        // Check region diversity
        if regionCount[candidate.Region] >= int(config.MaxSameRegion) {
            continue
        }

        // Check TPM vendor diversity
        if vendorCount[candidate.TPMVendor] >= int(config.MaxSameVendor) {
            continue
        }

        // Check collision cooldown (same pair shouldn't arbitrate together frequently)
        if hasRecentCollision(selected, candidate, config.CollisionCooldown) {
            continue
        }

        selected = append(selected, candidate)
        regionCount[candidate.Region]++
        vendorCount[candidate.TPMVendor]++
    }

    if len(selected) < int(config.ArbiterQuorum) {
        return nil, ErrInsufficientDiverseArbiters
    }

    return selected, nil
}

// DetectCollusionPatterns analyzes voting patterns for suspicious behavior
func DetectCollusionPatterns(arbiterID [32]byte) *CollusionReport {
    // Fetch arbiter's voting history
    history := GetArbiterVotingHistory(arbiterID, 90) // Last 90 days

    report := &CollusionReport{}

    // Pattern 1: Always votes with same arbiters
    covoterFreq := analyzeCovoterFrequency(history)
    for covoter, freq := range covoterFreq {
        if freq > 0.8 { // >80% agreement with same arbiter
            report.SuspiciousPairs = append(report.SuspiciousPairs, covoter)
        }
    }

    // Pattern 2: Votes against overwhelming evidence
    evidenceScore := analyzeEvidenceAlignment(history)
    if evidenceScore < 0.3 { // <30% alignment with evidence
        report.EvidenceMisalignment = true
    }

    // Pattern 3: Rapid fire votes (not reviewing evidence)
    avgReviewTime := analyzeReviewTimes(history)
    if avgReviewTime < 10*time.Minute { // <10 min average
        report.InsufficientReview = true
    }

    // Pattern 4: Votes opposite to majority too often
    minorityRate := analyzeMinorityVoteRate(history)
    if minorityRate > 0.6 { // >60% minority votes
        report.ContrarianPattern = true
    }

    return report
}

// SlashColludingArbiters penalizes detected collusion
func SlashColludingArbiters(report *CollusionReport) {
    if len(report.SuspiciousPairs) >= 2 || report.EvidenceMisalignment {
        for _, arbiterID := range report.InvolvedArbiters {
            // Freeze stake pending investigation
            FreezeArbiterStake(arbiterID)

            // Reduce reputation
            slashReputation(arbiterID, -0.3, "collusion_suspicion")

            // Suspend from arbitration pool
            SuspendFromArbitration(arbiterID, 30*24*time.Hour)
        }

        // Trigger human review for large escrows
        if report.EscrowValue > 100000 {
            TriggerManualReview(report)
        }
    }
}
```

**Economics of Collusion Prevention**:

| Escrow Value | Arbiter Count | Quorum | Bribe Cost (5x stake) | Break-Even Bribe |
|--------------|---------------|--------|----------------------|------------------|
| 10,000 coins | 7 | 5 | 250,000 coins | 2.5% of 10M |
| 100,000 coins | 9 | 6 | 300,000 coins | 3.3% of 9M |
| 1,000,000 coins | 11 | 8 | 400,000 coins | 4% of 10M |

**Key Insight**: By requiring stake > (escrow / quorum), bribery becomes unprofitable.

### Arbiter Voting

```go
// ArbiterVote represents an arbiter's decision on a contract dispute
type ArbiterVote struct {
    ContractID    [32]byte
    ArbiterID     [32]byte
    Decision      DisputeOutcome
    SplitRatio    float64             // If Split: percentage to provider
    Reasoning     string              // Required justification
    Evidence      [][32]byte          // References to evidence reviewed
    Timestamp     time.Time
    Signature     []byte              // TPM-signed vote
}

// DisputeOutcome defines possible dispute resolutions
type DisputeOutcome uint8

const (
    OutcomeProviderWins DisputeOutcome = 1 // Provider receives escrow
    OutcomeConsumerWins DisputeOutcome = 2 // Consumer receives refund
    OutcomeSplit        DisputeOutcome = 3 // Split between parties
)

// TallyContractVotes counts arbiter decisions (5-of-7 quorum per E1 fix)
func TallyContractVotes(votes []ArbiterVote, quorum int) (*DisputeResolution, error) {
    if len(votes) < quorum {
        return nil, ErrInsufficientVotes{Required: quorum, Received: len(votes)}
    }

    outcomes := make(map[DisputeOutcome]int)
    splitRatios := make([]float64, 0)

    for _, v := range votes {
        outcomes[v.Decision]++
        if v.Decision == OutcomeSplit {
            splitRatios = append(splitRatios, v.SplitRatio)
        }
    }

    // Find majority
    var majority DisputeOutcome
    var majorityCount int
    for outcome, count := range outcomes {
        if count > majorityCount {
            majority = outcome
            majorityCount = count
        }
    }

    if majorityCount < quorum {
        return nil, ErrNoQuorum{Required: quorum, BestCount: majorityCount}
    }

    resolution := &DisputeResolution{
        Outcome:    majority,
        VoteCount:  majorityCount,
        TotalVotes: len(votes),
    }

    // Use median split ratio if split decision
    if majority == OutcomeSplit && len(splitRatios) > 0 {
        sort.Float64s(splitRatios)
        resolution.SplitRatio = splitRatios[len(splitRatios)/2]
    }

    return resolution, nil
}
```

### Arbiter Incentives

| Behavior | Consequence |
|----------|-------------|
| Correct judgment (matches majority) | +0.001 reputation |
| Minority judgment | No change |
| No vote within 72 hours | -0.01 reputation |
| Evidence of bribery/collusion | -0.5 reputation + permanent ban |
| Consistent fair judgments | Priority for future selection |

### Appeal Window with Retry Logic and Atomic Transfer

Appeals provide a mechanism for parties dissatisfied with arbitration decisions to request review.
This section defines the appeal process with robust retry logic, rollback on failure, and
atomic multi-party transfers for appeal resolution.

```go
// AppealState tracks an active appeal
type AppealState struct {
    // Identity
    AppealID      [32]byte          // Unique appeal identifier
    ContractID    [32]byte          // Contract being appealed
    DisputeID     [32]byte          // Original dispute decision being appealed

    // Parties
    Appellant     [32]byte          // Party filing the appeal (consumer or provider)
    Respondent    [32]byte          // Other party
    OriginalArbiters [][32]byte     // Arbiters from original decision

    // Appeal Basis
    AppealReason  AppealReason      // Why appeal was filed
    NewEvidence   []byte            // New evidence (if applicable)
    Justification string            // Written explanation

    // Timing
    FiledAt       time.Time
    Deadline      time.Time         // Appeal window deadline
    ResolutionDeadline time.Time    // When appeal must be decided

    // Status
    Status        AppealStatus
    Decision      *AppealDecision

    // Retry and notification tracking
    NotificationAttempts []NotificationAttempt
    TransferAttempts     []TransferAttempt
}

// AppealReason defines valid reasons for appeal
type AppealReason uint8

const (
    AppealReasonNewEvidence       AppealReason = 1 // New evidence discovered
    AppealReasonProceduralError   AppealReason = 2 // Arbitration process error
    AppealReasonArbiterMisconduct AppealReason = 3 // Evidence of arbiter misconduct
    AppealReasonAILowConfidence   AppealReason = 4 // AI decision was low confidence
)

// AppealStatus tracks appeal lifecycle
type AppealStatus uint8

const (
    AppealStatusPending    AppealStatus = 1 // Awaiting review
    AppealStatusInReview   AppealStatus = 2 // Being reviewed by appeal arbiters
    AppealStatusDecided    AppealStatus = 3 // Decision made
    AppealStatusExecuting  AppealStatus = 4 // Executing transfer
    AppealStatusCompleted  AppealStatus = 5 // Fully resolved
    AppealStatusFailed     AppealStatus = 6 // Execution failed, rolled back
)

// AppealDecision contains the appeal resolution
type AppealDecision struct {
    Outcome          AppealOutcome
    NewSplitRatio    float64       // If split modified
    ArbitersVoted    [][32]byte    // Appeal arbiters who voted
    VoteBreakdown    map[[32]byte]AppealOutcome
    Reasoning        string
    DecidedAt        time.Time
    Signature        []byte        // Multi-sig from appeal arbiters
}

// AppealOutcome defines possible appeal results
type AppealOutcome uint8

const (
    AppealOutcomeUpheld     AppealOutcome = 1 // Original decision stands
    AppealOutcomeReversed   AppealOutcome = 2 // Decision reversed
    AppealOutcomeModified   AppealOutcome = 3 // Decision modified (different split)
    AppealOutcomeRemanded   AppealOutcome = 4 // Sent back for new arbitration
)

// NotificationAttempt tracks notification delivery attempts
type NotificationAttempt struct {
    Timestamp      time.Time
    Recipient      [32]byte
    NotificationType string
    Success        bool
    ErrorMessage   string
    RetryCount     int
}

// TransferAttempt tracks escrow transfer attempts
type TransferAttempt struct {
    Timestamp      time.Time
    TransferType   string        // "release", "refund", "split"
    Amount         uint64
    Recipients     [][32]byte
    Success        bool
    ErrorMessage   string
    RetryCount     int
    RolledBack     bool
}

// AppealConfig defines appeal process parameters
type AppealConfig struct {
    // Window Configuration
    AppealWindow          time.Duration // Time to file appeal (default: 48h)
    AppealResolutionDeadline time.Duration // Time to resolve appeal (default: 7 days)

    // Fee Structure
    AppealFee             uint64        // Fee to file appeal (deterrent against frivolous appeals)
    AppealFeeRefundOnWin  bool          // Refund appeal fee if appeal succeeds

    // Retry Configuration
    MaxNotificationRetries int          // Max notification attempts (default: 5)
    NotificationRetryDelay time.Duration // Delay between retries (default: 1 minute)
    MaxTransferRetries     int          // Max transfer attempts (default: 3)
    TransferRetryDelay     time.Duration // Delay between transfer retries (default: 5 seconds)

    // Arbiter Selection
    AppealArbiterCount    int           // Number of appeal arbiters (default: 5)
    ExcludeOriginalArbiters bool        // Exclude original arbiters from appeal panel
}

// DefaultAppealConfig provides sensible defaults
var DefaultAppealConfig = AppealConfig{
    AppealWindow:            48 * time.Hour,
    AppealResolutionDeadline: 7 * 24 * time.Hour,
    AppealFee:               1000, // coins
    AppealFeeRefundOnWin:    true,
    MaxNotificationRetries:  5,
    NotificationRetryDelay:  1 * time.Minute,
    MaxTransferRetries:      3,
    TransferRetryDelay:      5 * time.Second,
    AppealArbiterCount:      5,
    ExcludeOriginalArbiters: true,
}

// FileAppeal initiates an appeal with notification retry logic
func FileAppeal(
    ctx context.Context,
    contractID [32]byte,
    disputeID [32]byte,
    appellant [32]byte,
    reason AppealReason,
    justification string,
    newEvidence []byte,
    config *AppealConfig,
) (*AppealState, error) {
    // Fetch original dispute
    dispute, err := GetDispute(ctx, disputeID)
    if err != nil {
        return nil, &ErrDisputeNotFound{DisputeID: disputeID}
    }

    // Verify within appeal window
    if time.Now().After(dispute.DecidedAt.Add(config.AppealWindow)) {
        return nil, &ErrAppealWindowExpired{
            DisputeID:  disputeID,
            WindowEnd:  dispute.DecidedAt.Add(config.AppealWindow),
        }
    }

    // Verify appellant is party to dispute
    if appellant != dispute.Consumer && appellant != dispute.Provider {
        return nil, &ErrAppellantNotParty{Appellant: appellant}
    }

    // Determine respondent
    respondent := dispute.Provider
    if appellant == dispute.Provider {
        respondent = dispute.Consumer
    }

    // Create appeal state
    appeal := &AppealState{
        AppealID:         generateAppealID(contractID, disputeID),
        ContractID:       contractID,
        DisputeID:        disputeID,
        Appellant:        appellant,
        Respondent:       respondent,
        OriginalArbiters: dispute.SelectedArbiters,
        AppealReason:     reason,
        NewEvidence:      newEvidence,
        Justification:    justification,
        FiledAt:          time.Now(),
        Deadline:         time.Now().Add(config.AppealResolutionDeadline),
        Status:           AppealStatusPending,
    }

    // Notify all parties with retry logic
    if err := notifyAppealPartiesWithRetry(ctx, appeal, config); err != nil {
        // Log but don't fail - appeal is recorded, notification can be retried
        log.Warn("initial appeal notification failed, will retry",
            "appealID", appeal.AppealID,
            "error", err)
    }

    // Store appeal
    if err := StoreAppeal(ctx, appeal); err != nil {
        return nil, &ErrAppealStoreFailed{Cause: err}
    }

    return appeal, nil
}

// notifyAppealPartiesWithRetry sends notifications with exponential backoff retry
func notifyAppealPartiesWithRetry(
    ctx context.Context,
    appeal *AppealState,
    config *AppealConfig,
) error {
    parties := []struct {
        nodeID [32]byte
        role   string
    }{
        {appeal.Appellant, "appellant"},
        {appeal.Respondent, "respondent"},
    }
    // Add original arbiters
    for _, arbiter := range appeal.OriginalArbiters {
        parties = append(parties, struct {
            nodeID [32]byte
            role   string
        }{arbiter, "original_arbiter"})
    }

    var lastErr error
    for _, party := range parties {
        attempt := NotificationAttempt{
            Timestamp:        time.Now(),
            Recipient:        party.nodeID,
            NotificationType: "appeal_filed",
        }

        // Retry loop with exponential backoff
        for retry := 0; retry <= config.MaxNotificationRetries; retry++ {
            attempt.RetryCount = retry

            err := SendAppealNotification(ctx, party.nodeID, appeal, party.role)
            if err == nil {
                attempt.Success = true
                appeal.NotificationAttempts = append(appeal.NotificationAttempts, attempt)
                break
            }

            attempt.ErrorMessage = err.Error()
            lastErr = err

            if retry < config.MaxNotificationRetries {
                // Exponential backoff: delay * 2^retry
                backoff := config.NotificationRetryDelay * time.Duration(1<<uint(retry))
                time.Sleep(backoff)
            }
        }

        if !attempt.Success {
            appeal.NotificationAttempts = append(appeal.NotificationAttempts, attempt)
            log.Warn("notification failed after all retries",
                "recipient", party.nodeID,
                "role", party.role,
                "retries", config.MaxNotificationRetries)
        }
    }

    return lastErr
}

// ExecuteAppealDecision executes the appeal outcome with atomic multi-party transfer
// SECURITY: Uses atomic transfer with rollback on failure
func ExecuteAppealDecision(
    ctx context.Context,
    appeal *AppealState,
    decision *AppealDecision,
    config *AppealConfig,
) error {
    appeal.Decision = decision
    appeal.Status = AppealStatusExecuting

    // Prepare atomic transfer based on outcome
    transfer, err := prepareAppealTransfer(ctx, appeal, decision)
    if err != nil {
        appeal.Status = AppealStatusFailed
        return &ErrAppealTransferPrepareFailed{Cause: err}
    }

    // Execute with retry and rollback
    if err := executeAtomicTransferWithRetry(ctx, transfer, appeal, config); err != nil {
        appeal.Status = AppealStatusFailed
        return err
    }

    appeal.Status = AppealStatusCompleted
    return StoreAppeal(ctx, appeal)
}

// AtomicMultiPartyTransfer represents an atomic transfer across multiple parties
type AtomicMultiPartyTransfer struct {
    TransferID    [32]byte
    ContractID    [32]byte
    EscrowID      [32]byte
    TotalAmount   uint64
    Distributions []TransferDistribution
    RequiredSigs  [][32]byte    // Required signatures for authorization
    Signatures    [][]byte      // Collected signatures
    Status        TransferStatus
    CreatedAt     time.Time
}

// TransferDistribution defines a single recipient in multi-party transfer
type TransferDistribution struct {
    Recipient     [32]byte
    Amount        uint64
    Percentage    float64       // Percentage of total (for verification)
    Purpose       string        // "provider_payment", "consumer_refund", "arbiter_fee", "appeal_fee_refund"
}

// TransferStatus tracks atomic transfer state
type TransferStatus uint8

const (
    TransferStatusPending    TransferStatus = 1
    TransferStatusLocked     TransferStatus = 2 // Funds locked for transfer
    TransferStatusExecuting  TransferStatus = 3
    TransferStatusCompleted  TransferStatus = 4
    TransferStatusRolledBack TransferStatus = 5
    TransferStatusFailed     TransferStatus = 6
)

// prepareAppealTransfer creates an atomic transfer based on appeal decision
func prepareAppealTransfer(
    ctx context.Context,
    appeal *AppealState,
    decision *AppealDecision,
) (*AtomicMultiPartyTransfer, error) {
    // Fetch escrow details
    escrow, err := GetEscrow(ctx, appeal.ContractID)
    if err != nil {
        return nil, err
    }

    transfer := &AtomicMultiPartyTransfer{
        TransferID:  generateTransferID(appeal.AppealID),
        ContractID:  appeal.ContractID,
        EscrowID:    escrow.EscrowID,
        TotalAmount: escrow.Amount,
        Status:      TransferStatusPending,
        CreatedAt:   time.Now(),
    }

    switch decision.Outcome {
    case AppealOutcomeUpheld:
        // Original decision stands - no change to transfer
        return nil, nil // Transfer already executed by original dispute

    case AppealOutcomeReversed:
        // Reverse the original decision
        // If provider won originally, refund to consumer
        // If consumer won originally, release to provider
        if appeal.OriginalOutcome == OutcomeProviderWins {
            transfer.Distributions = []TransferDistribution{
                {Recipient: appeal.Respondent, Amount: escrow.Amount, Percentage: 1.0, Purpose: "consumer_refund"},
            }
        } else {
            transfer.Distributions = []TransferDistribution{
                {Recipient: appeal.Appellant, Amount: escrow.Amount, Percentage: 1.0, Purpose: "provider_payment"},
            }
        }

    case AppealOutcomeModified:
        // Split based on new ratio
        providerAmount := uint64(float64(escrow.Amount) * decision.NewSplitRatio)
        consumerAmount := escrow.Amount - providerAmount
        transfer.Distributions = []TransferDistribution{
            {Recipient: appeal.Provider, Amount: providerAmount, Percentage: decision.NewSplitRatio, Purpose: "provider_payment"},
            {Recipient: appeal.Consumer, Amount: consumerAmount, Percentage: 1 - decision.NewSplitRatio, Purpose: "consumer_refund"},
        }
    }

    // Add arbiter fees
    for _, arbiter := range decision.ArbitersVoted {
        transfer.Distributions = append(transfer.Distributions, TransferDistribution{
            Recipient: arbiter,
            Amount:    DefaultAppealConfig.AppealFee / uint64(len(decision.ArbitersVoted)),
            Purpose:   "arbiter_fee",
        })
    }

    // Refund appeal fee if appellant won
    if decision.Outcome == AppealOutcomeReversed || decision.Outcome == AppealOutcomeModified {
        if DefaultAppealConfig.AppealFeeRefundOnWin {
            transfer.Distributions = append(transfer.Distributions, TransferDistribution{
                Recipient: appeal.Appellant,
                Amount:    DefaultAppealConfig.AppealFee,
                Purpose:   "appeal_fee_refund",
            })
        }
    }

    // Require signatures from majority of appeal arbiters
    transfer.RequiredSigs = decision.ArbitersVoted

    return transfer, nil
}

// executeAtomicTransferWithRetry executes transfer with retry logic and rollback
func executeAtomicTransferWithRetry(
    ctx context.Context,
    transfer *AtomicMultiPartyTransfer,
    appeal *AppealState,
    config *AppealConfig,
) error {
    // Step 1: Lock escrow funds (prevent double-spend)
    if err := LockEscrowForTransfer(ctx, transfer.EscrowID, transfer.TransferID); err != nil {
        return &ErrEscrowLockFailed{Cause: err}
    }
    transfer.Status = TransferStatusLocked

    // Step 2: Execute with retry
    var lastErr error
    for retry := 0; retry <= config.MaxTransferRetries; retry++ {
        attempt := TransferAttempt{
            Timestamp:    time.Now(),
            TransferType: "appeal_resolution",
            Amount:       transfer.TotalAmount,
            RetryCount:   retry,
        }

        // Collect recipient IDs
        for _, dist := range transfer.Distributions {
            attempt.Recipients = append(attempt.Recipients, dist.Recipient)
        }

        // Attempt atomic transfer
        err := ExecuteAtomicTransfer(ctx, transfer)
        if err == nil {
            attempt.Success = true
            transfer.Status = TransferStatusCompleted
            appeal.TransferAttempts = append(appeal.TransferAttempts, attempt)
            return nil
        }

        lastErr = err
        attempt.ErrorMessage = err.Error()
        appeal.TransferAttempts = append(appeal.TransferAttempts, attempt)

        log.Warn("transfer attempt failed",
            "transferID", transfer.TransferID,
            "retry", retry,
            "error", err)

        if retry < config.MaxTransferRetries {
            // Exponential backoff
            backoff := config.TransferRetryDelay * time.Duration(1<<uint(retry))
            time.Sleep(backoff)
        }
    }

    // Step 3: All retries failed - ROLLBACK
    log.Error("transfer failed after all retries, initiating rollback",
        "transferID", transfer.TransferID,
        "totalAttempts", config.MaxTransferRetries+1,
        "lastError", lastErr)

    // Record rollback attempt
    rollbackAttempt := TransferAttempt{
        Timestamp:    time.Now(),
        TransferType: "rollback",
        Amount:       transfer.TotalAmount,
        RolledBack:   true,
    }

    // Unlock escrow and return to original state
    if err := UnlockEscrow(ctx, transfer.EscrowID, transfer.TransferID); err != nil {
        rollbackAttempt.Success = false
        rollbackAttempt.ErrorMessage = err.Error()
        appeal.TransferAttempts = append(appeal.TransferAttempts, rollbackAttempt)

        // Critical: Rollback failed - requires manual intervention
        AlertManualIntervention(ctx, transfer, appeal, err)
        return &ErrRollbackFailed{TransferID: transfer.TransferID, Cause: err}
    }

    rollbackAttempt.Success = true
    transfer.Status = TransferStatusRolledBack
    appeal.TransferAttempts = append(appeal.TransferAttempts, rollbackAttempt)

    // Notify parties of transfer failure and rollback
    notifyTransferRollback(ctx, appeal, lastErr)

    return &ErrAppealTransferFailed{
        TransferID: transfer.TransferID,
        Attempts:   config.MaxTransferRetries + 1,
        LastError:  lastErr,
    }
}

// ExecuteAtomicTransfer performs the actual multi-party transfer atomically
// SECURITY: All distributions succeed or none do
func ExecuteAtomicTransfer(ctx context.Context, transfer *AtomicMultiPartyTransfer) error {
    // Verify signatures
    if len(transfer.Signatures) < len(transfer.RequiredSigs)/2+1 {
        return &ErrInsufficientSignatures{
            Required: len(transfer.RequiredSigs)/2 + 1,
            Have:     len(transfer.Signatures),
        }
    }

    transfer.Status = TransferStatusExecuting

    // Begin atomic transaction
    tx, err := BeginEscrowTransaction(ctx, transfer.EscrowID)
    if err != nil {
        return err
    }
    defer tx.Rollback() // Rollback if not committed

    // Execute all distributions
    for _, dist := range transfer.Distributions {
        if err := tx.Transfer(dist.Recipient, dist.Amount); err != nil {
            return &ErrDistributionFailed{
                Recipient: dist.Recipient,
                Amount:    dist.Amount,
                Cause:     err,
            }
        }
    }

    // Verify balances
    if err := tx.VerifyBalances(); err != nil {
        return &ErrBalanceVerificationFailed{Cause: err}
    }

    // Commit atomic transaction
    return tx.Commit()
}

// Appeal error types
type ErrAppealWindowExpired struct {
    DisputeID [32]byte
    WindowEnd time.Time
}
func (e *ErrAppealWindowExpired) Error() string {
    return fmt.Sprintf("appeal window expired for dispute %x at %v", e.DisputeID[:8], e.WindowEnd)
}

type ErrAppellantNotParty struct {
    Appellant [32]byte
}
func (e *ErrAppellantNotParty) Error() string {
    return fmt.Sprintf("appellant %x is not a party to the dispute", e.Appellant[:8])
}

type ErrAppealStoreFailed struct {
    Cause error
}
func (e *ErrAppealStoreFailed) Error() string {
    return fmt.Sprintf("failed to store appeal: %v", e.Cause)
}

type ErrAppealTransferPrepareFailed struct {
    Cause error
}
func (e *ErrAppealTransferPrepareFailed) Error() string {
    return fmt.Sprintf("failed to prepare appeal transfer: %v", e.Cause)
}

type ErrAppealTransferFailed struct {
    TransferID [32]byte
    Attempts   int
    LastError  error
}
func (e *ErrAppealTransferFailed) Error() string {
    return fmt.Sprintf("appeal transfer %x failed after %d attempts: %v",
        e.TransferID[:8], e.Attempts, e.LastError)
}

type ErrEscrowLockFailed struct {
    Cause error
}
func (e *ErrEscrowLockFailed) Error() string {
    return fmt.Sprintf("failed to lock escrow: %v", e.Cause)
}

type ErrRollbackFailed struct {
    TransferID [32]byte
    Cause      error
}
func (e *ErrRollbackFailed) Error() string {
    return fmt.Sprintf("CRITICAL: rollback failed for transfer %x: %v", e.TransferID[:8], e.Cause)
}

type ErrInsufficientSignatures struct {
    Required int
    Have     int
}
func (e *ErrInsufficientSignatures) Error() string {
    return fmt.Sprintf("insufficient signatures: required %d, have %d", e.Required, e.Have)
}

type ErrDistributionFailed struct {
    Recipient [32]byte
    Amount    uint64
    Cause     error
}
func (e *ErrDistributionFailed) Error() string {
    return fmt.Sprintf("distribution to %x of %d failed: %v", e.Recipient[:8], e.Amount, e.Cause)
}

type ErrBalanceVerificationFailed struct {
    Cause error
}
func (e *ErrBalanceVerificationFailed) Error() string {
    return fmt.Sprintf("balance verification failed: %v", e.Cause)
}
```

### Appeal Process Flow

```
                        APPEAL RESOLUTION FLOW

Appellant                  Appeal Arbiters              Respondent
---------                  ---------------              ----------

   |                            |                           |
   | 1. File Appeal             |                           |
   |   (within 48h window)      |                           |
   |--------------------------->|                           |
   |                            |                           |
   |                            | 2. Select 5 Appeal        |
   |                            |    Arbiters (VRF)         |
   |                            |    (exclude original)     |
   |                            |                           |
   |                            | 3. Notify with Retry      |
   |<---------------------------|-------------------------->|
   |   (up to 5 retries)        |                           |
   |                            |                           |
   | 4. Submit New Evidence     |   4. Submit Response      |
   |--------------------------->|<--------------------------|
   |                            |                           |
   |                       +----+----+                      |
   |                       | REVIEW  |                      |
   |                       +---------+                      |
   |                            |                           |
   |                       +----+----+                      |
   |                       |  VOTE   |                      |
   |                       +---------+                      |
   |                            |                           |
   |                       +----+----+                      |
   |                       |DECISION |                      |
   |                       +---------+                      |
   |                            |                           |
   |                       +----+----+                      |
   |                       | ATOMIC  |                      |
   |                       |TRANSFER |                      |
   |                       | (retry) |                      |
   |                       +----+----+                      |
   |                            |                           |
   |                       [Success?]                       |
   |                       /         \                      |
   |                    Yes           No                    |
   |                     |             |                    |
   |                     v             v                    |
   | 5. Transfer         |        [ROLLBACK]                |
   |    Complete         |             |                    |
   |<--------------------|             |                    |
   |                     |        [Retry or]                |
   |                     |        [Manual Fix]              |
   |                     |             |                    |
```

### Appeal Outcome Distribution

| Appeal Outcome | Provider Receives | Consumer Receives | Arbiter Fees | Appeal Fee |
|----------------|-------------------|-------------------|--------------|------------|
| **Upheld** | Original decision | Original decision | From appeal fee | Forfeit to arbiters |
| **Reversed** | Opposite of original | Opposite of original | From escrow | Refunded to appellant |
| **Modified** | New split % | 100% - new split % | From appeal fee | Refunded to appellant |
| **Remanded** | Pending | Pending | Partial | Held pending |

---

## Integration with Service Discovery

ServiceContracts link to service advertisements in the marketplace:

```go
// CreateContractFromAdvertisement creates a contract from a service listing
func CreateContractFromAdvertisement(
    ad *ServiceAdvertisement,
    consumer *Node,
    duration time.Duration,
) (*ServiceContract, error) {
    // Create contract from advertisement
    contract := &ServiceContract{
        ContractID:  generateContractID(ad.ID, consumer.ID),
        Version:     1,
        Provider:    ad.NodeIdentity,
        Consumer:    consumer.ToNodeIdentity(),
        ServiceType: mapServiceType(ad.ServiceType),
        ServiceTerms: ad.ServiceTerms,
        SLA:         ad.SLA,
        PaymentTerms: PaymentTerms{
            BasePrice:    ad.Pricing.BasePrice,
            PricingModel: PricingModelFromAd(ad.Pricing),
            Currency:     ad.Pricing.Currency,
        },
        StartTime:   time.Now(),
        Duration:    duration,
        Status:      ContractStatusDraft,
        CreatedAt:   time.Now(),
    }

    // Configure escrow
    contract.Escrow = EscrowConfig{
        EscrowID:      generateEscrowID(contract.ContractID),
        EscrowAmount:  calculateEscrowAmount(ad.Pricing, duration),
        Currency:      ad.Pricing.Currency,
        DisputeWindow: 48 * time.Hour,
    }

    // Configure dispute resolution (E1 fix: 5-of-7 quorum)
    contract.DisputeResolution = DisputeConfig{
        ArbiterCount:       7,  // E1: increased from 5
        ArbiterQuorum:      5,  // E1: increased from 3 (71% threshold)
        DisputeWindow:      48 * time.Hour,
        ResolutionDeadline: 7 * 24 * time.Hour,
        EvidenceDeadline:   72 * time.Hour,
    }

    return contract, nil
}

// LinkContractToService creates DHT mapping between service and contract
func LinkContractToService(dht DHT, serviceID [32]byte, contractID [32]byte) error {
    key := ServiceContractKey(serviceID, contractID)
    value := ContractLink{
        ServiceID:  serviceID,
        ContractID: contractID,
        LinkedAt:   time.Now(),
    }

    data, err := serializeContractLink(value)
    if err != nil {
        return err
    }

    return dht.Put(context.Background(), key, data)
}
```

---

## API Reference

### Contract Service Interface

```go
// ContractService manages service contracts
type ContractService interface {
    // Contract Lifecycle
    CreateContract(ctx context.Context, contract *ServiceContract) (*ServiceContract, error)
    GetContract(ctx context.Context, contractID [32]byte) (*ServiceContract, error)
    UpdateContract(ctx context.Context, contract *ServiceContract) error
    DeleteContract(ctx context.Context, contractID [32]byte) error

    // Signing
    SignContract(ctx context.Context, contractID [32]byte, role string) error
    VerifySignatures(ctx context.Context, contractID [32]byte) error

    // State Management
    ActivateContract(ctx context.Context, contractID [32]byte) error
    SuspendContract(ctx context.Context, contractID [32]byte, reason string) error
    ResumeContract(ctx context.Context, contractID [32]byte) error
    CompleteContract(ctx context.Context, contractID [32]byte) error
    TerminateContract(ctx context.Context, contractID [32]byte, reason string) error

    // Queries
    ListProviderContracts(ctx context.Context, nodeID [32]byte) ([]*ServiceContract, error)
    ListConsumerContracts(ctx context.Context, nodeID [32]byte) ([]*ServiceContract, error)
    ListContractsByType(ctx context.Context, serviceType ServiceType) ([]*ServiceContract, error)

    // Disputes
    OpenDispute(ctx context.Context, contractID [32]byte, reason string, evidence []byte) error
    SubmitEvidence(ctx context.Context, contractID [32]byte, evidence []byte) error
    ResolveDispute(ctx context.Context, contractID [32]byte, resolution *DisputeResolution) error
}
```

---

## Error Types

```go
var (
    // Identity Errors
    ErrNodeIDMismatch           = errors.New("node ID does not match public key")
    ErrIDevIDNotFound           = errors.New("IDevID certificate not found")
    ErrCertificateChainInvalid  = errors.New("certificate chain validation failed")
    ErrPublicKeyMismatch        = errors.New("public key does not match certificate")
    ErrTrustLevelMismatch       = errors.New("trust level does not match actual")

    // Contract Errors
    ErrContractNotFound         = errors.New("contract not found")
    ErrInvalidContractState     = errors.New("invalid contract state for operation")
    ErrInvalidStateTransition   = errors.New("invalid state transition")
    ErrProviderSignatureRequired = errors.New("provider signature required")
    ErrConsumerSignatureRequired = errors.New("consumer signature required")
    ErrInvalidSignerRole        = errors.New("invalid signer role")

    // Escrow Errors
    ErrEscrowNotFunded          = errors.New("escrow not funded")
    ErrEscrowCheckFailed        = errors.New("escrow status check failed")
    ErrEscrowReleaseFailed      = errors.New("escrow release failed")

    // Dispute Errors
    ErrDisputeWindowExpired     = errors.New("dispute window has expired")
    ErrInsufficientArbiters     = errors.New("insufficient eligible arbiters")
    ErrInsufficientVotes        = errors.New("insufficient votes for quorum")
    ErrNoQuorum                 = errors.New("no quorum reached")

    // Validation Errors
    ErrNoCapabilitiesSpecified  = errors.New("no capabilities specified")
    ErrInvalidMaxTokens         = errors.New("invalid max tokens")
    ErrInvalidAccuracyThreshold = errors.New("accuracy threshold must be 0.0-1.0")
    ErrInvalidCPUCores          = errors.New("CPU cores must be > 0")
    ErrInvalidMemory            = errors.New("memory must be > 0")
    ErrNoOSImageSpecified       = errors.New("OS image not specified")
    ErrInvalidStorageQuota      = errors.New("storage quota must be > 0")
    ErrInvalidReplicationFactor = errors.New("replication factor must be 1-20")
    ErrNoStoreNameSpecified     = errors.New("store name not specified")
    ErrInvalidCatalogSize       = errors.New("catalog size must be > 0")
    ErrNoPaymentMethodsSpecified = errors.New("no payment methods specified")
    ErrInvalidBandwidth         = errors.New("bandwidth must be > 0")
    ErrInvalidLatencyTarget     = errors.New("latency target must be > 0")

    // TPM Errors
    ErrTPMQuoteFailed           = errors.New("TPM quote generation failed")
    ErrSigningFailed            = errors.New("signing operation failed")
)
```

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Contract creation latency | ~200ms |
| Signature verification | ~50ms |
| Escrow creation | ~500ms |
| DHT storage (contract) | ~150ms per hop |
| Arbiter selection (VRF) | ~100ms |
| Dispute resolution | 72h-7 days |
| Contract size (typical) | 2-5 KB |

---

## Related Documents

- [01-system-overview.md](01-system-overview.md) - System architecture overview
- [03-security-trust.md](03-security-trust.md) - Security model and TPM requirements
- [05-certificate-authority.md](05-certificate-authority.md) - IDevID certificates and PKI
- [07-currency-transactions.md](07-currency-transactions.md) - Payment and escrow system
- [13-service-discovery.md](13-service-discovery.md) - Service marketplace and advertisements
- [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) - Agent contracts

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-12-30 | Initial specification |
| 1.1 | 2026-01-08 | Added GPU compute resources and attestation |
| 1.2 | 2026-01-09 | Enhanced exemption security and requirements signing |
| 1.3 | 2026-01-10 | Added grace period enforcement and atomic transfer |
| 1.4 | 2026-01-10 | Added FINAL DESIGN elements: Contract state machine with full lifecycle states and transitions, Automation trigger validation (baseline values, rapid firing prevention, missing data handling), Automated action appeals (24h window, 5% compensation), Renewal procedures (auto-renewal, price change notice, renegotiation window, grace period with retries, provider eligibility checks) |

---

**Document Version:** 1.4
**Last Updated:** 2026-01-10
**Status:** Comprehensive Contract Lifecycle with Automation and Renewal Edge Cases
